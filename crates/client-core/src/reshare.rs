//! Online read re-share (DESIGN §12.4b, Phase 4).
//!
//! Pure and transport-agnostic. A current recipient who already holds a file
//! version's DEK (they unwrapped it on download, §12.5) can extend **read**
//! access to another directory-verified user without any offline ceremony. This
//! module produces the new `file_key_wraps` row: the DEK re-wrapped to the
//! recipient's `enc_pub` plus a **possession-entailing** read-grant signed by
//! the granter (`granted_by = granter_id`). Because the granter actually held
//! and re-wrapped the DEK, the resulting grant is carry-forward-eligible
//! (§12.3a/§12.9).
//!
//! Re-sharing read **never** confers write (owner-only, D29).
//!
//! Two §12.4b preconditions are enforced structurally here:
//!   - **Possession.** `build_reshare` re-checks the supplied DEK against the
//!     verified manifest `dek_commit` — a granter that does not hold the real
//!     key cannot produce an openable wrap (self-validating on download, §12.5
//!     step 6).
//!   - **Tombstone / withholding resistance.** It takes a [`TombstoneSet`],
//!     which is *only* constructible by [`TombstoneSet::verify`] — a contiguous
//!     chain up to the sink-anchored head, fail-closed on a gap (§7.6/D22). It
//!     refuses to re-admit a user under an active tombstone for this
//!     file/version or account-wide (§12.4b step 2). A caller that cannot fetch
//!     the anchored head never builds a `TombstoneSet`, so the re-share cannot
//!     proceed on an unverified set (fail closed, parameters §5).

use maxsecu_crypto::{wrap_dek, Dek, EncPublicKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{Grant, WrapContext};
use maxsecu_encoding::types::{Bytes32, Id, RecipientType, Timestamp};
use maxsecu_encoding::RECOVERY_ID;

use crate::identity::Identity;
use crate::revocation::TombstoneSet;
use crate::upload::WrapOut;

/// Inputs for a single online read re-share (§12.4b). The granter's `enc_priv`
/// is not needed — the DEK has already been unwrapped on download and is passed
/// in; only the granter's **signing** key (inside `granter`) is used, to sign
/// the new grant.
pub struct ReshareParams<'a> {
    /// The re-sharing recipient — signs the new grant with their `sig` key.
    pub granter: &'a Identity,
    /// The granter's `user_id` (the grant's `granted_by`).
    pub granter_id: Id,
    pub file_id: Id,
    pub version: u64,
    /// The verified manifest's `dek_commit` — the DEK is self-checked against it.
    pub dek_commit: [u8; 32],
    /// The recipient being granted read (directory-verified by the caller, §7.2).
    pub recipient_id: Id,
    pub recipient_enc_pub: EncPublicKey,
    pub created_at: Timestamp,
}

/// Why a re-share was refused (fail-closed, §12.4b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReshareError {
    /// The supplied DEK does not match the manifest commitment — the granter
    /// does not actually hold this version's key (§12.4b step 3).
    DekCommitMismatch,
    /// The recipient is under an active tombstone for this file/version or
    /// account-wide — a strong-revoked user cannot be re-admitted (§12.4b step
    /// 2 / §11.5).
    RecipientRevoked,
    /// The recipient id is the recovery sentinel — re-share targets a *user*;
    /// the recovery recipient is (re-)added only by the author/rotation (§12.9).
    RecipientIsRecovery,
    /// The DEK could not be wrapped to the recipient's `enc_pub`.
    WrapFailed,
}

impl std::fmt::Display for ReshareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReshareError::DekCommitMismatch => {
                write!(f, "supplied DEK does not match the manifest commitment")
            }
            ReshareError::RecipientRevoked => {
                write!(f, "recipient is under an active tombstone")
            }
            ReshareError::RecipientIsRecovery => {
                write!(f, "cannot re-share to the recovery recipient")
            }
            ReshareError::WrapFailed => write!(f, "failed to wrap the DEK to the recipient"),
        }
    }
}

impl std::error::Error for ReshareError {}

/// Build one read re-share wrap+grant (§12.4b). Fail-closed: a DEK that does not
/// open to the committed value, or a recipient under an active tombstone, is
/// refused. The returned [`WrapOut`] is `POST /v1/files/{id}/wraps` (api.md
/// §10.1) — `granted_by = granter_id`, a possession-entailing grant.
pub fn build_reshare(
    params: &ReshareParams,
    dek: &Dek,
    tombstones: &TombstoneSet,
) -> Result<WrapOut, ReshareError> {
    use ReshareError::*;

    // (3) Possession: the granter must actually hold this version's DEK, or the
    // wrap it produces would not open to the committed value (§12.4b step 3).
    if dek.commit() != params.dek_commit {
        return Err(DekCommitMismatch);
    }
    // Re-share extends read to a *user*; the recovery recipient is (re-)added
    // only by the author/rotation (§12.9), never by a re-share.
    if params.recipient_id == RECOVERY_ID {
        return Err(RecipientIsRecovery);
    }
    // (2) Tombstone gate: refuse to re-admit a strong-revoked recipient, by an
    // account-wide or a per-file tombstone (§11.5). The set is contiguous to the
    // sink-anchored head by construction (only `TombstoneSet::verify` builds it).
    if tombstones.is_account_revoked(&params.recipient_id.0)
        || tombstones.is_revoked(&params.recipient_id.0, &params.file_id.0, params.version)
    {
        return Err(RecipientRevoked);
    }

    // (4) Re-wrap the DEK to the recipient's directory-verified `enc_pub`.
    let ctx = WrapContext {
        file_id: params.file_id,
        version: params.version,
        recipient_id: params.recipient_id,
    };
    let wrapped_dek = wrap_dek(&params.recipient_enc_pub, dek, &ctx).map_err(|_| WrapFailed)?;

    // (5) Issue a possession-entailing read-grant rooted at the granter.
    let grant = Grant {
        file_id: params.file_id,
        file_version: params.version,
        recipient_id: params.recipient_id,
        recipient_type: RecipientType::User,
        dek_commit: Bytes32(params.dek_commit),
        granted_by: params.granter_id,
        created_at: params.created_at,
    };
    let grant_sig = params
        .granter
        .signing_key()
        .sign_canonical(labels::GRANT, &grant);

    Ok(WrapOut {
        recipient_id: params.recipient_id,
        recipient_type: RecipientType::User,
        wrapped_dek,
        granted_by: params.granter_id,
        grant,
        grant_sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_admin_core::{ControlChain, CoSign, RevokeParams};
    use maxsecu_crypto::{generate_enc_keypair, unwrap_dek, SigningKey, VerifyingKey};
    use maxsecu_encoding::types::FileScope;
    use maxsecu_encoding::GENESIS_HEAD;

    const GRANTER_ID: Id = Id([0x11; 16]);
    const RECIPIENT_ID: Id = Id([0x33; 16]);
    const FILE_ID: Id = Id([0xF1; 16]);
    const NOW: Timestamp = Timestamp(1_719_500_000_000);

    fn empty_tombstones() -> TombstoneSet {
        TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap()
    }

    fn params<'a>(granter: &'a Identity, recipient_enc_pub: EncPublicKey, dek: &Dek) -> ReshareParams<'a> {
        ReshareParams {
            granter,
            granter_id: GRANTER_ID,
            file_id: FILE_ID,
            version: 1,
            dek_commit: dek.commit(),
            recipient_id: RECIPIENT_ID,
            recipient_enc_pub,
            created_at: NOW,
        }
    }

    #[test]
    fn reshare_produces_an_openable_wrap_and_a_possession_grant() {
        let granter = Identity::generate();
        let (recipient_sk, recipient_pk) = generate_enc_keypair();
        let dek = Dek::generate();

        let out = build_reshare(&params(&granter, recipient_pk, &dek), &dek, &empty_tombstones())
            .expect("re-share succeeds");

        // granted_by is the re-sharer; the grant is a user grant for this file.
        assert_eq!(out.granted_by, GRANTER_ID);
        assert_eq!(out.recipient_id, RECIPIENT_ID);
        assert_eq!(out.recipient_type, RecipientType::User);
        assert_eq!(out.grant.granted_by, GRANTER_ID);
        assert_eq!(out.grant.file_id, FILE_ID);
        assert_eq!(out.grant.file_version, 1);
        assert_eq!(out.grant.dek_commit, Bytes32(dek.commit()));

        // The grant signature verifies under the granter's directory sig key.
        let vk = VerifyingKey::from_bytes(&granter.sig_pub_bytes()).unwrap();
        assert!(vk
            .verify_canonical(labels::GRANT, &out.grant, &out.grant_sig)
            .is_ok());

        // The wrap actually opens to the committed DEK — self-validating access.
        let ctx = WrapContext { file_id: FILE_ID, version: 1, recipient_id: RECIPIENT_ID };
        let opened = unwrap_dek(&recipient_sk, &out.wrapped_dek, &ctx).unwrap();
        assert_eq!(opened.commit(), dek.commit());
    }

    #[test]
    fn reshare_refuses_a_dek_that_does_not_match_the_commitment() {
        let granter = Identity::generate();
        let (_sk, recipient_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let other = Dek::generate();
        let mut p = params(&granter, recipient_pk, &dek);
        p.dek_commit = other.commit(); // manifest commits to a different DEK
        assert!(matches!(
            build_reshare(&p, &dek, &empty_tombstones()),
            Err(ReshareError::DekCommitMismatch)
        ));
    }

    #[test]
    fn reshare_refuses_a_recovery_recipient() {
        let granter = Identity::generate();
        let (_sk, recipient_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let mut p = params(&granter, recipient_pk, &dek);
        p.recipient_id = RECOVERY_ID;
        assert!(matches!(
            build_reshare(&p, &dek, &empty_tombstones()),
            Err(ReshareError::RecipientIsRecovery)
        ));
    }

    #[test]
    fn reshare_refuses_an_account_revoked_recipient() {
        let granter = Identity::generate();
        let (_sk, recipient_pk) = generate_enc_keypair();
        let dek = Dek::generate();

        // An admin account-wide-revokes the recipient (dual-controlled); the
        // resulting chain head is the sink-anchored head the set verifies to.
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let rec = chain
            .revoke(
                &admin,
                RevokeParams {
                    scope: FileScope::AccountWide,
                    revoked_user_id: RECIPIENT_ID,
                    revoked_capability: None,
                    from_version: 1,
                    issued_by: Id([1; 16]),
                    created_at: NOW,
                },
                Some(CoSign { admin_id: Id([2; 16]), key: &co }),
            )
            .unwrap();
        let tombstones =
            TombstoneSet::verify(std::slice::from_ref(&rec.bytes), chain.head()).unwrap();

        assert!(matches!(
            build_reshare(&params(&granter, recipient_pk, &dek), &dek, &tombstones),
            Err(ReshareError::RecipientRevoked)
        ));
    }

    #[test]
    fn reshare_refuses_a_per_file_revoked_recipient() {
        let granter = Identity::generate();
        let (_sk, recipient_pk) = generate_enc_keypair();
        let dek = Dek::generate();

        // A single-file tombstone (no co-sign needed) from version 1 onward.
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let rec = chain
            .revoke(
                &admin,
                RevokeParams {
                    scope: FileScope::Specific(FILE_ID),
                    revoked_user_id: RECIPIENT_ID,
                    revoked_capability: None,
                    from_version: 1,
                    issued_by: Id([1; 16]),
                    created_at: NOW,
                },
                None,
            )
            .unwrap();
        let tombstones =
            TombstoneSet::verify(std::slice::from_ref(&rec.bytes), chain.head()).unwrap();

        assert!(matches!(
            build_reshare(&params(&granter, recipient_pk, &dek), &dek, &tombstones),
            Err(ReshareError::RecipientRevoked)
        ));
    }
}
