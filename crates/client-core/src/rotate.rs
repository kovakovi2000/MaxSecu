//! Version rotation with possession-entailing carry-forward (DESIGN §12.9,
//! Phase 4). Owner-only write (D29): the file **owner** authors the next version.
//!
//! Pure and transport-agnostic. Given the owner's recovered current DEK and the
//! prior version's recipients (each with the grant chain the server served), it:
//!   1. generates a fresh `DEK'` and re-encrypts every stream under it (so a
//!      strong-revoked reader who held the *old* DEK cannot read the new
//!      version);
//!   2. forms the next recipient set by **carry-forward** (§12.9 step 2): a prior
//!      recipient is kept **only if** its grant chains to the prior author via an
//!      author or re-share edge — both *possession-entailing* (the granter
//!      actually held the DEK) — **and** it is not under an active tombstone. A
//!      server-injected row (no valid chain) or a strong-revoked user is dropped;
//!   3. re-roots every survivor under the new author with a fresh author grant,
//!      and always re-adds the owner (self) and the recovery recipient.
//!
//! Carry-forward reuses the exact §12.5 chain verifier ([`verify_grant_chain`]),
//! so download acceptance and rotation carry-forward cannot drift. The tombstone
//! set is constructible only via [`TombstoneSet::verify`] (contiguous to the
//! sink-anchored head, fail-closed on a gap, §7.6/D22), so a rotator that cannot
//! fetch the head never rotates on an unverified set (parameters §5).

use maxsecu_crypto::{Dek, EncPublicKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{Grant, Manifest};
use maxsecu_encoding::types::{Bytes32, FileType, Hash, Id, RecipientType, Suite, Timestamp};
use maxsecu_encoding::{decode, RECOVERY_ID};

use crate::download::verify_grant_chain;
use crate::error::UploadError;
use crate::identity::Identity;
use crate::limits::{CHUNK_SIZE_MAX, CHUNK_SIZE_MIN};
use crate::revocation::TombstoneSet;
use crate::upload::{seal_streams, wrap_and_grant, PlaintextStreams, SealedStreamOut, WrapOut};

/// A prior-version recipient the rotator may carry forward, with the grant chain
/// the server served for it (api.md §8.5). The `recipient_enc_pub` is the
/// recipient's **directory-verified** wrap-target key (§7.2), resolved by the
/// caller.
pub struct CarryForwardCandidate {
    pub recipient_id: Id,
    pub recipient_enc_pub: EncPublicKey,
    pub leaf_grant_bytes: Vec<u8>,
    pub leaf_grant_sig: [u8; 64],
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
}

/// Parameters for authoring the next version of a file (owner-only, D29).
pub struct RotateParams<'a> {
    /// The owner's unlocked identity — the sole writer and the new author.
    pub owner: &'a Identity,
    pub owner_id: Id,
    pub file_id: Id,
    pub file_type: FileType,
    /// The new version number — must be `prior_version + 1` (the server enforces
    /// the strict `+1` commit, §12).
    pub new_version: u64,
    pub chunk_size: u32,
    /// The recovery recipient's directory-verified `enc_pub` (always re-added).
    pub recovery_pub: EncPublicKey,
    pub created_at: Timestamp,
    /// The version being rotated away from (carry-forward grants are verified
    /// against it).
    pub prior_version: u64,
    /// The prior manifest's `dek_commit` — the recovered DEK is self-checked
    /// against it, and every carried grant must commit to it.
    pub prior_dek_commit: [u8; 32],
    /// The prior version's author id and directory-verified `sig_pub` (owner-only
    /// write ⇒ the owner, possibly at an earlier `key_version`).
    pub prior_author_id: Id,
    pub prior_author_sig_pub: [u8; 32],
}

/// The signed, encrypted record set for `POST /v1/files/{id}/versions` (api.md
/// §8.2) — like [`crate::upload::UploadBundle`] but **without** a genesis (the
/// immutable genesis is retained server-side across rotations, §11.7).
pub struct RotationBundle {
    pub file_id: Id,
    pub file_type: FileType,
    pub manifest: Manifest,
    pub manifest_sig: [u8; 64],
    pub streams: Vec<SealedStreamOut>,
    pub wraps: Vec<WrapOut>,
}

/// Why a rotation could not be built (fail-closed). Dropping an ineligible
/// carry-forward candidate is **not** an error — it is the intended §12.9 step-2
/// exclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateError {
    /// `chunk_size` outside [4 KiB, 8 MiB].
    ChunkSizeOutOfRange { chunk_size: u32 },
    /// The recovered DEK does not match the prior manifest commitment — the
    /// rotator does not actually hold the current key (§12.9 step 1).
    PriorDekMismatch,
    /// A wrap/self-check failure while building the new wraps.
    Upload(UploadError),
}

impl From<UploadError> for RotateError {
    fn from(e: UploadError) -> Self {
        RotateError::Upload(e)
    }
}

impl std::fmt::Display for RotateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotateError::ChunkSizeOutOfRange { chunk_size } => {
                write!(f, "chunk_size {chunk_size} out of range")
            }
            RotateError::PriorDekMismatch => {
                write!(f, "recovered DEK does not match the prior commitment")
            }
            RotateError::Upload(e) => write!(f, "wrap build failed: {e}"),
        }
    }
}

impl std::error::Error for RotateError {}

/// Author the next version of a file with possession-entailing carry-forward
/// (DESIGN §12.9). See the module docs for the policy.
pub fn build_next_version(
    params: &RotateParams,
    streams: &PlaintextStreams,
    prior_dek: &Dek,
    candidates: &[CarryForwardCandidate],
    tombstones: &TombstoneSet,
    granter_sig_pub: &dyn Fn(Id) -> Option<[u8; 32]>,
) -> Result<RotationBundle, RotateError> {
    if params.chunk_size < CHUNK_SIZE_MIN || params.chunk_size > CHUNK_SIZE_MAX {
        return Err(RotateError::ChunkSizeOutOfRange {
            chunk_size: params.chunk_size,
        });
    }
    // (1) Possession: the rotator must hold the current DEK (§12.9 step 1).
    if prior_dek.commit() != params.prior_dek_commit {
        return Err(RotateError::PriorDekMismatch);
    }

    // A fresh DEK' — re-encrypting under it is what denies the old key to a
    // strong-revoked reader.
    let dek = Dek::generate();
    let dek_commit = dek.commit();
    let (manifest_streams, sealed_out) =
        seal_streams(&dek, params.file_id, params.new_version, params.chunk_size, streams);

    let signer = params.owner.signing_key();
    let owner_enc_pub = EncPublicKey::from_bytes(params.owner.enc_pub_bytes());

    // Always re-add the owner (self) and the recovery recipient, then carry
    // forward each surviving prior recipient — re-rooted under the new author.
    let mut wraps = vec![
        wrap_and_grant(
            signer,
            params.file_id,
            params.new_version,
            params.owner_id,
            RecipientType::User,
            &owner_enc_pub,
            &dek,
            dek_commit,
            params.owner_id,
            params.created_at,
            Some(params.owner.enc_secret()),
        )?,
        wrap_and_grant(
            signer,
            params.file_id,
            params.new_version,
            RECOVERY_ID,
            RecipientType::Recovery,
            &params.recovery_pub,
            &dek,
            dek_commit,
            params.owner_id,
            params.created_at,
            None,
        )?,
    ];

    for c in candidates {
        // Owner/recovery are already present; skip duplicates.
        if c.recipient_id == params.owner_id || c.recipient_id == RECOVERY_ID {
            continue;
        }
        if !candidate_survives(c, params, tombstones, granter_sig_pub) {
            continue;
        }
        wraps.push(wrap_and_grant(
            signer,
            params.file_id,
            params.new_version,
            c.recipient_id,
            RecipientType::User,
            &c.recipient_enc_pub,
            &dek,
            dek_commit,
            params.owner_id,
            params.created_at,
            None,
        )?);
    }

    let manifest = Manifest {
        file_id: params.file_id,
        version: params.new_version,
        file_type: params.file_type,
        alg: Suite::V1,
        chunk_size: params.chunk_size,
        dek_commit: Bytes32(dek_commit),
        streams: manifest_streams,
        recovery_present: true,
        author_id: params.owner_id,
        created_at: params.created_at,
    };
    let manifest_sig = signer.sign_canonical(labels::MANIFEST, &manifest);

    Ok(RotationBundle {
        file_id: params.file_id,
        file_type: params.file_type,
        manifest,
        manifest_sig,
        streams: sealed_out,
        wraps,
    })
}

/// Decide whether a prior recipient is carried into the next version (§12.9 step
/// 2): its leaf grant must bind the prior file/version/DEK and name this exact
/// recipient, its chain must verify to the prior author (possession-entailing),
/// and it must not be under an active tombstone for the new version.
fn candidate_survives(
    c: &CarryForwardCandidate,
    params: &RotateParams,
    tombstones: &TombstoneSet,
    granter_sig_pub: &dyn Fn(Id) -> Option<[u8; 32]>,
) -> bool {
    // Decode + field-bind the leaf grant to the prior version's facts.
    let leaf: Grant = match decode(&c.leaf_grant_bytes) {
        Ok(g) => g,
        Err(_) => return false,
    };
    let prior_commit: Hash = Bytes32(params.prior_dek_commit);
    if leaf.file_id != params.file_id
        || leaf.file_version != params.prior_version
        || leaf.dek_commit != prior_commit
        || leaf.recipient_id != c.recipient_id
        || leaf.recipient_type != RecipientType::User
    {
        return false;
    }
    // The chain must root at the prior author via author/re-share edges only.
    if verify_grant_chain(
        &leaf,
        &c.leaf_grant_sig,
        &c.ancestor_grants,
        params.file_id,
        params.prior_version,
        prior_commit,
        params.prior_author_id,
        &params.prior_author_sig_pub,
        granter_sig_pub,
    )
    .is_err()
    {
        return false;
    }
    // Strong-revoked recipients are excluded from the next version (§11.5).
    !(tombstones.is_account_revoked(&c.recipient_id.0)
        || tombstones.is_revoked(&c.recipient_id.0, &params.file_id.0, params.new_version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_admin_core::{ControlChain, CoSign, RevokeParams};
    use maxsecu_crypto::{unwrap_dek, SigningKey, VerifyingKey};
    use maxsecu_encoding::encode;
    use maxsecu_encoding::structs::WrapContext;
    use maxsecu_encoding::types::{FileScope, StreamType};
    use maxsecu_encoding::GENESIS_HEAD;
    use crate::download::NO_GRANTERS;

    const OWNER_ID: Id = Id([0x11; 16]);
    const V_ID: Id = Id([0x33; 16]);
    const FILE_ID: Id = Id([0xF1; 16]);
    const NOW: Timestamp = Timestamp(1_719_500_000_000);

    fn plaintext() -> PlaintextStreams {
        PlaintextStreams {
            content: b"the rotating content of this file".to_vec(),
            metadata: Some(b"title=rot".to_vec()),
            thumbnail: None,
            preview: None,
        }
    }

    fn rotate_params<'a>(owner: &'a Identity, prior_dek: &Dek) -> RotateParams<'a> {
        RotateParams {
            owner,
            owner_id: OWNER_ID,
            file_id: FILE_ID,
            file_type: FileType::Blog,
            new_version: 2,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes([0xE9; 32]),
            created_at: NOW,
            prior_version: 1,
            prior_dek_commit: prior_dek.commit(),
            prior_author_id: OWNER_ID,
            prior_author_sig_pub: owner.sig_pub_bytes(),
        }
    }

    /// An author-rooted candidate `V` granted by the owner at the prior version.
    fn author_rooted_candidate(owner: &Identity, prior_dek: &Dek, v: &Identity) -> CarryForwardCandidate {
        let grant = Grant {
            file_id: FILE_ID,
            file_version: 1,
            recipient_id: V_ID,
            recipient_type: RecipientType::User,
            dek_commit: Bytes32(prior_dek.commit()),
            granted_by: OWNER_ID,
            created_at: NOW,
        };
        let sig = owner.signing_key().sign_canonical(labels::GRANT, &grant);
        CarryForwardCandidate {
            recipient_id: V_ID,
            recipient_enc_pub: EncPublicKey::from_bytes(v.enc_pub_bytes()),
            leaf_grant_bytes: encode(&grant),
            leaf_grant_sig: sig,
            ancestor_grants: vec![],
        }
    }

    fn empty_tombstones() -> TombstoneSet {
        TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap()
    }

    #[test]
    fn carries_forward_a_valid_recipient_under_a_fresh_dek() {
        let owner = Identity::generate();
        let v = Identity::generate();
        let prior_dek = Dek::generate();
        let cand = author_rooted_candidate(&owner, &prior_dek, &v);

        let bundle = build_next_version(
            &rotate_params(&owner, &prior_dek),
            &plaintext(),
            &prior_dek,
            std::slice::from_ref(&cand),
            &empty_tombstones(),
            &NO_GRANTERS,
        )
        .expect("rotation builds");

        // owner + recovery + V (carried forward).
        assert_eq!(bundle.wraps.len(), 3);
        assert_eq!(bundle.manifest.version, 2);
        assert_eq!(bundle.manifest.author_id, OWNER_ID);
        assert!(bundle.manifest.recovery_present);
        // The DEK rotated — the new commitment differs from the prior one.
        assert_ne!(bundle.manifest.dek_commit, Bytes32(prior_dek.commit()));

        // V's carried wrap opens to the *new* DEK and its grant re-roots at owner.
        let vw = bundle.wraps.iter().find(|w| w.recipient_id == V_ID).unwrap();
        assert_eq!(vw.grant.granted_by, OWNER_ID);
        assert_eq!(vw.grant.file_version, 2);
        let ctx = WrapContext { file_id: FILE_ID, version: 2, recipient_id: V_ID };
        let dek2 = unwrap_dek(v.enc_secret(), &vw.wrapped_dek, &ctx).unwrap();
        assert_eq!(Bytes32(dek2.commit()), bundle.manifest.dek_commit);
        assert_ne!(dek2.commit(), prior_dek.commit());

        // The new manifest grant verifies under the owner's key.
        let vk = VerifyingKey::from_bytes(&owner.sig_pub_bytes()).unwrap();
        assert!(vk.verify_canonical(labels::GRANT, &vw.grant, &vw.grant_sig).is_ok());
        assert!(bundle.streams.iter().any(|s| s.stream_type == StreamType::Content));
    }

    #[test]
    fn carries_forward_a_reshared_recipient_via_the_resolver() {
        // W was re-shared by R (granted_by = R), and R is author-rooted. The
        // carry-forward chain must verify R's grant under R's resolved key.
        const W_ID: Id = Id([0x44; 16]);
        let owner = Identity::generate();
        let r = Identity::generate();
        let w = Identity::generate();
        let prior_dek = Dek::generate();
        let dek_commit = Bytes32(prior_dek.commit());

        let r_grant = Grant {
            file_id: FILE_ID,
            file_version: 1,
            recipient_id: V_ID, // R's recipient id
            recipient_type: RecipientType::User,
            dek_commit,
            granted_by: OWNER_ID,
            created_at: NOW,
        };
        let r_grant_sig = owner.signing_key().sign_canonical(labels::GRANT, &r_grant);
        let w_grant = Grant {
            file_id: FILE_ID,
            file_version: 1,
            recipient_id: W_ID,
            recipient_type: RecipientType::User,
            dek_commit,
            granted_by: V_ID, // re-shared by R
            created_at: NOW,
        };
        let w_grant_sig = r.signing_key().sign_canonical(labels::GRANT, &w_grant);
        let cand = CarryForwardCandidate {
            recipient_id: W_ID,
            recipient_enc_pub: EncPublicKey::from_bytes(w.enc_pub_bytes()),
            leaf_grant_bytes: encode(&w_grant),
            leaf_grant_sig: w_grant_sig,
            ancestor_grants: vec![(encode(&r_grant), r_grant_sig)],
        };

        let r_pub = r.sig_pub_bytes();
        let resolver = move |id: Id| (id == V_ID).then_some(r_pub);
        let bundle = build_next_version(
            &rotate_params(&owner, &prior_dek),
            &plaintext(),
            &prior_dek,
            std::slice::from_ref(&cand),
            &empty_tombstones(),
            &resolver,
        )
        .unwrap();
        // owner + recovery + W (carried via the re-share edge).
        assert_eq!(bundle.wraps.len(), 3);
        let ww = bundle.wraps.iter().find(|x| x.recipient_id == W_ID).unwrap();
        assert_eq!(ww.grant.granted_by, OWNER_ID); // re-rooted under the new author
    }

    #[test]
    fn drops_a_strong_revoked_recipient() {
        let owner = Identity::generate();
        let v = Identity::generate();
        let prior_dek = Dek::generate();
        let cand = author_rooted_candidate(&owner, &prior_dek, &v);

        // Account-wide strong revoke of V (dual-controlled), anchored.
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let rec = chain
            .revoke(
                &admin,
                RevokeParams {
                    scope: FileScope::AccountWide,
                    revoked_user_id: V_ID,
                    revoked_capability: None,
                    from_version: 1,
                    issued_by: Id([1; 16]),
                    created_at: NOW,
                },
                Some(CoSign { admin_id: Id([2; 16]), key: &co }),
            )
            .unwrap();
        let tombstones = TombstoneSet::verify(std::slice::from_ref(&rec.bytes), chain.head()).unwrap();

        let bundle = build_next_version(
            &rotate_params(&owner, &prior_dek),
            &plaintext(),
            &prior_dek,
            std::slice::from_ref(&cand),
            &tombstones,
            &NO_GRANTERS,
        )
        .unwrap();
        // Only owner + recovery — V is excluded by tombstone.
        assert_eq!(bundle.wraps.len(), 2);
        assert!(bundle.wraps.iter().all(|w| w.recipient_id != V_ID));
    }

    #[test]
    fn drops_a_candidate_whose_grant_chain_does_not_verify() {
        let owner = Identity::generate();
        let v = Identity::generate();
        let prior_dek = Dek::generate();
        let mut cand = author_rooted_candidate(&owner, &prior_dek, &v);
        cand.leaf_grant_sig[0] ^= 0x01; // forged grant signature → not carried

        let bundle = build_next_version(
            &rotate_params(&owner, &prior_dek),
            &plaintext(),
            &prior_dek,
            std::slice::from_ref(&cand),
            &empty_tombstones(),
            &NO_GRANTERS,
        )
        .unwrap();
        assert_eq!(bundle.wraps.len(), 2); // owner + recovery only
    }

    #[test]
    fn refuses_when_the_recovered_dek_does_not_match_the_prior_commitment() {
        let owner = Identity::generate();
        let prior_dek = Dek::generate();
        let mut params = rotate_params(&owner, &prior_dek);
        let other = Dek::generate();
        params.prior_dek_commit = other.commit(); // claims a different prior DEK

        assert!(matches!(
            build_next_version(&params, &plaintext(), &prior_dek, &[], &empty_tombstones(), &NO_GRANTERS),
            Err(RotateError::PriorDekMismatch)
        ));
    }
}
