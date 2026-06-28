//! Client-side directory verification (DESIGN §7.2/§7.5) — the mandatory check
//! before a client wraps a DEK to a recipient or trusts a manifest signature.
//!
//! This module covers the **binding** half of §7.2: (2) verify the offline D5
//! signature against the *pinned* directory-signing key, (3) the clock-
//! independent rollback + TOFU key-change check against trust-on-last-use memory
//! (§7.5), and (4) the identity-validity window. The §7.6 revocation/role check
//! (step 5) layers on top via the tombstone view. A binding that fails any check
//! is treated as **absent** — fail closed.

use crate::revocation::TombstoneSet;
use maxsecu_crypto::{fingerprint, VerifyingKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::Role;
use std::collections::HashMap;

/// Trust-on-last-use memory for one user (`user_id`): the highest `key_version`
/// the client has accepted and the fingerprint of the keys at that version
/// (§7.5). The clock-independent anchor for rollback and key-change detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustRecord {
    pub key_version: u64,
    pub fingerprint: [u8; 32],
}

/// Persistent per-`user_id` trust-on-last-use store (§7.5). The client owns the
/// durable backing; the core only reads the prior record and writes an accepted
/// one. `&mut self` on write makes the single-writer discipline explicit.
pub trait TrustStore {
    fn get(&self, user_id: &[u8; 16]) -> Option<TrustRecord>;
    fn put(&mut self, user_id: [u8; 16], record: TrustRecord);
}

/// In-memory [`TrustStore`] for tests/dev (the real client persists this).
#[derive(Default)]
pub struct MemoryTrustStore {
    records: HashMap<[u8; 16], TrustRecord>,
}

impl MemoryTrustStore {
    pub fn new() -> MemoryTrustStore {
        MemoryTrustStore::default()
    }
}

impl TrustStore for MemoryTrustStore {
    fn get(&self, user_id: &[u8; 16]) -> Option<TrustRecord> {
        self.records.get(user_id).copied()
    }
    fn put(&mut self, user_id: [u8; 16], record: TrustRecord) {
        self.records.insert(user_id, record);
    }
}

/// A binding that passed §7.2 steps 2–4: its keys are usable (subject to the
/// §7.6 revocation check). `roles` is the offline-signed **ceiling** (§7.1);
/// effective roles are this minus any role-narrowing tombstone (§7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBinding {
    pub user_id: [u8; 16],
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
    pub key_version: u64,
    pub roles: Vec<Role>,
    pub fingerprint: [u8; 32],
    /// The recipient's ML-KEM-768 encapsulation key for a PQ-enrolled identity
    /// (Phase 7), or `None` for a classical binding. Carried verbatim from the
    /// D5-signed binding so a wrapper can build a hybrid recipient (P7.5). Not
    /// part of the fingerprint (§7.1).
    pub mlkem_pub: Option<[u8; 1184]>,
}

/// Why a binding was not accepted. Every variant means "treat as absent" (fail
/// closed); `KeyChanged` additionally means "block new wraps until the user
/// confirms the new fingerprint out of band" (§7.2 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The offline D5 signature did not verify under the pinned root, or a key
    /// was malformed — a forged/tampered binding (§7.2 step 2).
    BadSignature,
    /// A served `key_version` lower than the highest remembered — a rollback
    /// (§7.5). Clock-independent.
    Rollback {
        remembered_key_version: u64,
        served_key_version: u64,
    },
    /// The bound keys changed (a higher `key_version`, or — equivocation — the
    /// same version with different keys). Not silently accepted: the client must
    /// re-verify the carried `fingerprint` out of band, then
    /// [`DirectoryVerifier::accept_key_change`] (§7.2 step 3 / TOFU).
    KeyChanged { fingerprint: [u8; 32] },
    /// `now < not_before` — the identity binding is not yet valid (§7.2 step 4).
    NotYetValid,
    /// `now > not_after` — the identity binding has aged out and needs re-signing
    /// (§7.2 step 4). A long lifetime, not a revocation timer (§7.5).
    Expired,
    /// The user is under an active account-wide (`*`) tombstone (§7.2 step 5 /
    /// §7.6) — not usable as a recipient anywhere.
    Revoked,
    /// At FIRST CONTACT (no prior TOLU record), the binding was not provably
    /// included in the directory key-transparency log under a checkpoint signed
    /// by a pinned log key, or that checkpoint equivocated / rolled back (§7.4).
    /// Only produced when a [`crate::transparency::KtContext`] gate is supplied.
    NotInLog,
}

/// A recipient that passed the **full** §7.2 rule (binding steps 2–4 plus the
/// §7.6 account-wide revocation check). Its keys are usable as a wrap target and
/// its `effective_roles` (ceiling minus role-narrowing tombstones) govern any
/// capability decision (§10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRecipient {
    pub user_id: [u8; 16],
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
    pub key_version: u64,
    pub effective_roles: Vec<Role>,
    pub fingerprint: [u8; 32],
    /// The recipient's ML-KEM-768 encapsulation key (PQ, Phase 7), or `None` for
    /// a classical binding — the PQ leg of a hybrid wrap target (P7.5).
    pub mlkem_pub: Option<[u8; 1184]>,
}

/// Verifies directory bindings against the **pinned** directory-signing public
/// key (§7.3) — the trust root compiled into the client binary.
pub struct DirectoryVerifier {
    dir_pub: [u8; 32],
}

impl DirectoryVerifier {
    /// `pinned_dir_pub` is the directory-signing public key shipped in the build.
    pub fn new(pinned_dir_pub: [u8; 32]) -> DirectoryVerifier {
        DirectoryVerifier {
            dir_pub: pinned_dir_pub,
        }
    }

    /// Run §7.2 steps 2–4 over a served `binding + signature`. On success the
    /// keys are usable (pending the §7.6 revocation check) and a first-contact
    /// binding is pinned in `trust` (TOFU). Fail closed on any check.
    pub fn verify_binding(
        &self,
        binding: &DirBinding,
        signature: &[u8; 64],
        now_ms: u64,
        trust: &mut dyn TrustStore,
    ) -> Result<VerifiedBinding, VerifyError> {
        // (2) Offline signature under the pinned root. A bad/forged signature is
        // treated as absent.
        self.check_signature(binding, signature)?;

        let user_id = binding.user_id.0;
        let served_kv = binding.key_version;
        let fp = fingerprint(&binding.enc_pub.0, &binding.sig_pub.0);

        // (3) Rollback + key-change vs trust-on-last-use memory (clock-independent).
        let first_contact = match trust.get(&user_id) {
            None => true, // TOFU: first contact pins below on success.
            Some(prev) => {
                if served_kv < prev.key_version {
                    return Err(VerifyError::Rollback {
                        remembered_key_version: prev.key_version,
                        served_key_version: served_kv,
                    });
                }
                // Higher version, or same version with changed keys (equivocation)
                // ⇒ not silently accepted; block until re-confirmed out of band.
                if served_kv > prev.key_version || fp != prev.fingerprint {
                    return Err(VerifyError::KeyChanged { fingerprint: fp });
                }
                false // same version, same keys: proceed without re-pinning.
            }
        };

        // (4) Identity-validity window.
        self.check_validity(binding, now_ms)?;

        if first_contact {
            trust.put(
                user_id,
                TrustRecord {
                    key_version: served_kv,
                    fingerprint: fp,
                },
            );
        }
        Ok(self.verified(binding, fp))
    }

    /// `verify_binding` plus an OPTIONAL first-contact key-transparency gate
    /// (§7.4). When `kt` is `Some` AND this is first contact for the `user_id`
    /// (no prior TOLU record), the binding's canonical bytes must additionally be
    /// provably included in the directory KT log under a pinned, non-equivocating
    /// checkpoint ([`crate::transparency::verify_binding_in_log`]) — else
    /// [`VerifyError::NotInLog`] (fail closed). The KT gossip state is advanced
    /// only when the whole binding verification succeeds.
    ///
    /// When `kt` is `None`, behavior is IDENTICAL to [`Self::verify_binding`]
    /// (backward-compatible; the gate is opt-in).
    pub fn verify_binding_with_kt(
        &self,
        binding: &DirBinding,
        signature: &[u8; 64],
        now_ms: u64,
        trust: &mut dyn TrustStore,
        kt: Option<crate::transparency::KtContext<'_>>,
    ) -> Result<VerifiedBinding, VerifyError> {
        // The KT inclusion gate applies only at FIRST CONTACT (TOFU). After a user
        // is pinned in the directory TrustStore, §7.5 rollback/key-change rules
        // govern; re-checking KT inclusion on every fetch is not required.
        if let Some(kt) = kt {
            if trust.get(&binding.user_id.0).is_none() {
                // The KT leaf is the canonical DirBinding bytes (computed here so
                // they cannot be mismatched against the binding being verified).
                let leaf = maxsecu_encoding::encode(binding);
                crate::transparency::verify_binding_in_log(
                    &leaf,
                    kt.inclusion,
                    kt.checkpoint,
                    kt.consistency,
                    kt.log_pubs,
                    kt.store,
                )
                .map_err(|_| VerifyError::NotInLog)?;
            }
        }
        self.verify_binding(binding, signature, now_ms, trust)
    }

    /// The **full** §7.2 recipient rule: verify the binding (steps 2–4) and then
    /// confirm the user is not under an active account-wide tombstone (step 5 /
    /// §7.6), returning the usable keys plus effective roles. `tombstones` must
    /// already be proven contiguous to the anchored head (a gap fails closed at
    /// [`TombstoneSet::verify`] before this is called).
    pub fn authorize_recipient(
        &self,
        binding: &DirBinding,
        signature: &[u8; 64],
        now_ms: u64,
        trust: &mut dyn TrustStore,
        tombstones: &TombstoneSet,
    ) -> Result<AuthorizedRecipient, VerifyError> {
        let v = self.verify_binding(binding, signature, now_ms, trust)?;
        if tombstones.is_account_revoked(&v.user_id) {
            return Err(VerifyError::Revoked);
        }
        Ok(AuthorizedRecipient {
            effective_roles: tombstones.effective_roles(&v.user_id, &v.roles),
            user_id: v.user_id,
            enc_pub: v.enc_pub,
            sig_pub: v.sig_pub,
            key_version: v.key_version,
            fingerprint: v.fingerprint,
            mlkem_pub: v.mlkem_pub,
        })
    }

    /// Accept a key change the user has confirmed out of band (§7.2 step 3):
    /// re-verify the offline signature and validity, then update the pin to the
    /// new `(key_version, fingerprint)`. After this, `verify_binding` of the new
    /// binding proceeds normally.
    pub fn accept_key_change(
        &self,
        binding: &DirBinding,
        signature: &[u8; 64],
        now_ms: u64,
        trust: &mut dyn TrustStore,
    ) -> Result<VerifiedBinding, VerifyError> {
        self.check_signature(binding, signature)?;
        self.check_validity(binding, now_ms)?;
        let fp = fingerprint(&binding.enc_pub.0, &binding.sig_pub.0);
        trust.put(
            binding.user_id.0,
            TrustRecord {
                key_version: binding.key_version,
                fingerprint: fp,
            },
        );
        Ok(self.verified(binding, fp))
    }

    fn check_signature(
        &self,
        binding: &DirBinding,
        signature: &[u8; 64],
    ) -> Result<(), VerifyError> {
        VerifyingKey::from_bytes(&self.dir_pub)
            .and_then(|vk| vk.verify_canonical(labels::DIRBINDING, binding, signature))
            .map_err(|_| VerifyError::BadSignature)
    }

    fn check_validity(&self, binding: &DirBinding, now_ms: u64) -> Result<(), VerifyError> {
        if now_ms < binding.not_before.0 {
            return Err(VerifyError::NotYetValid);
        }
        if now_ms > binding.not_after.0 {
            return Err(VerifyError::Expired);
        }
        Ok(())
    }

    fn verified(&self, binding: &DirBinding, fp: [u8; 32]) -> VerifiedBinding {
        VerifiedBinding {
            user_id: binding.user_id.0,
            enc_pub: binding.enc_pub.0,
            sig_pub: binding.sig_pub.0,
            key_version: binding.key_version,
            roles: binding.roles.roles().to_vec(),
            fingerprint: fp,
            mlkem_pub: binding.mlkem_pub.map(|m| m.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::SigningKey;
    use maxsecu_encoding::types::{Bytes32, Id, RoleSet, Text, Timestamp};

    const NOW: u64 = 1_719_500_000_000;
    const YEAR_MS: u64 = 31_536_000_000;

    // The test plays the server/directory: it builds a binding and signs it with
    // a D5 key (mirroring admin-core, kept here so client-core stays independent).
    fn binding(uid: u8, enc: u8, sig: u8, key_version: u64) -> DirBinding {
        DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([uid; 16]),
            enc_pub: Bytes32([enc; 32]),
            sig_pub: Bytes32([sig; 32]),
            key_version,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(NOW - YEAR_MS),
            not_after: Timestamp(NOW + YEAR_MS),
            mlkem_pub: None,
        }
    }

    fn sign(d5: &SigningKey, b: &DirBinding) -> [u8; 64] {
        d5.sign_canonical(labels::DIRBINDING, b)
    }

    fn verifier(d5: &SigningKey) -> DirectoryVerifier {
        DirectoryVerifier::new(d5.verifying_key().to_bytes())
    }

    #[test]
    fn first_contact_verifies_and_pins() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let mut trust = MemoryTrustStore::new();
        let b = binding(1, 0xE1, 0x51, 1);
        let sig = sign(&d5, &b);

        let verified = v.verify_binding(&b, &sig, NOW, &mut trust).unwrap();
        assert_eq!(verified.enc_pub, [0xE1; 32]);
        assert_eq!(verified.sig_pub, [0x51; 32]);
        assert_eq!(verified.roles, vec![Role::User]);
        // Pinned: a second verify of the same binding still proceeds.
        assert!(v.verify_binding(&b, &sig, NOW, &mut trust).is_ok());
        assert_eq!(trust.get(&[1; 16]).unwrap().key_version, 1);
    }

    #[test]
    fn forged_binding_is_rejected_as_absent() {
        let d5 = SigningKey::generate();
        let attacker = SigningKey::generate();
        let v = verifier(&d5); // client pins the real D5…
        let b = binding(1, 0xE1, 0x51, 1);
        let sig = sign(&attacker, &b); // …but the server signed with another key.
        assert_eq!(
            v.verify_binding(&b, &sig, NOW, &mut MemoryTrustStore::new()),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn tampered_binding_is_rejected() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let b = binding(1, 0xE1, 0x51, 1);
        let sig = sign(&d5, &b);
        let mut tampered = b.clone();
        tampered.enc_pub = Bytes32([0xFF; 32]); // swap the wrap-target key
        assert_eq!(
            v.verify_binding(&tampered, &sig, NOW, &mut MemoryTrustStore::new()),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rolled_back_key_version_is_rejected() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let mut trust = MemoryTrustStore::new();
        // Pin v2…
        let b2 = binding(1, 0xE2, 0x52, 2);
        v.verify_binding(&b2, &sign(&d5, &b2), NOW, &mut trust).unwrap();
        // …then the server replays a validly-signed v1 (rollback).
        let b1 = binding(1, 0xE1, 0x51, 1);
        assert_eq!(
            v.verify_binding(&b1, &sign(&d5, &b1), NOW, &mut trust),
            Err(VerifyError::Rollback {
                remembered_key_version: 2,
                served_key_version: 1,
            })
        );
    }

    #[test]
    fn same_version_same_keys_proceeds() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let mut trust = MemoryTrustStore::new();
        let b = binding(1, 0xE1, 0x51, 1);
        let sig = sign(&d5, &b);
        v.verify_binding(&b, &sig, NOW, &mut trust).unwrap();
        assert!(v.verify_binding(&b, &sig, NOW, &mut trust).is_ok());
    }

    #[test]
    fn higher_key_version_blocks_as_key_changed_until_accepted() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let mut trust = MemoryTrustStore::new();
        let b1 = binding(1, 0xE1, 0x51, 1);
        v.verify_binding(&b1, &sign(&d5, &b1), NOW, &mut trust).unwrap();

        // A legitimately-rotated v2 is NOT silently accepted (§7.2 step 3).
        let b2 = binding(1, 0xE2, 0x52, 2);
        let sig2 = sign(&d5, &b2);
        let fp2 = fingerprint(&[0xE2; 32], &[0x52; 32]);
        assert_eq!(
            v.verify_binding(&b2, &sig2, NOW, &mut trust),
            Err(VerifyError::KeyChanged { fingerprint: fp2 })
        );

        // After out-of-band confirmation, accept and re-pin → then it proceeds.
        v.accept_key_change(&b2, &sig2, NOW, &mut trust).unwrap();
        assert!(v.verify_binding(&b2, &sig2, NOW, &mut trust).is_ok());
        assert_eq!(trust.get(&[1; 16]).unwrap().key_version, 2);
    }

    #[test]
    fn same_version_changed_keys_is_key_changed() {
        // Equivocation: same key_version, different keys — a forged binding under
        // a stolen D5. Caught as a key change (re-verify), never silently used.
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let mut trust = MemoryTrustStore::new();
        let b = binding(1, 0xE1, 0x51, 1);
        v.verify_binding(&b, &sign(&d5, &b), NOW, &mut trust).unwrap();

        let equivocal = binding(1, 0xAA, 0xBB, 1); // same version, different keys
        assert_eq!(
            v.verify_binding(&equivocal, &sign(&d5, &equivocal), NOW, &mut trust),
            Err(VerifyError::KeyChanged {
                fingerprint: fingerprint(&[0xAA; 32], &[0xBB; 32])
            })
        );
    }

    #[test]
    fn validity_window_is_enforced() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let b = binding(1, 0xE1, 0x51, 1);
        let sig = sign(&d5, &b);
        // not_before = NOW - YEAR, not_after = NOW + YEAR.
        assert_eq!(
            v.verify_binding(&b, &sig, NOW - 2 * YEAR_MS, &mut MemoryTrustStore::new()),
            Err(VerifyError::NotYetValid)
        );
        assert_eq!(
            v.verify_binding(&b, &sig, NOW + 2 * YEAR_MS, &mut MemoryTrustStore::new()),
            Err(VerifyError::Expired)
        );
    }

    #[test]
    fn verified_binding_exposes_mlkem() {
        use maxsecu_admin_core::DirectorySigner;
        let d5 = DirectorySigner::generate();
        let v = DirectoryVerifier::new(d5.public_key());

        // A PQ binding (D5-signed with an ML-KEM key) exposes mlkem_pub verbatim.
        let mlkem = maxsecu_encoding::types::MlKemPub([0x9C; 1184]);
        let pq = d5.sign_binding(&binding(1, 0xE1, 0x51, 1), Some(mlkem));
        let verified = v
            .verify_binding(&pq.binding, &pq.signature, NOW, &mut MemoryTrustStore::new())
            .unwrap();
        assert_eq!(verified.mlkem_pub, Some([0x9C; 1184]));
        // …and the PQ key carries through to the authorized recipient too.
        let none = TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap();
        let r = v
            .authorize_recipient(
                &pq.binding,
                &pq.signature,
                NOW,
                &mut MemoryTrustStore::new(),
                &none,
            )
            .unwrap();
        assert_eq!(r.mlkem_pub, Some([0x9C; 1184]));

        // A classical (non-PQ) binding yields None.
        let classical = d5.sign_binding(&binding(2, 0xE2, 0x52, 1), None);
        let verified = v
            .verify_binding(
                &classical.binding,
                &classical.signature,
                NOW,
                &mut MemoryTrustStore::new(),
            )
            .unwrap();
        assert_eq!(verified.mlkem_pub, None);
    }

    // ---- the full §7.2 recipient rule (binding + §7.6 revocation) ----

    use crate::revocation::TombstoneSet;
    use maxsecu_admin_core::{ControlChain, CoSign, RevokeParams};
    use maxsecu_encoding::GENESIS_HEAD;

    fn admin_binding(d5: &SigningKey, uid: u8) -> ([u8; 64], DirBinding) {
        let b = DirBinding {
            username: Text::new("carol").unwrap(),
            user_id: Id([uid; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User, Role::Admin]),
            not_before: Timestamp(NOW - YEAR_MS),
            not_after: Timestamp(NOW + YEAR_MS),
            mlkem_pub: None,
        };
        (sign(d5, &b), b)
    }

    fn account_revoke(scope_user: u8) -> ([Vec<u8>; 1], [u8; 32]) {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let r = chain
            .revoke(
                &admin,
                RevokeParams {
                    scope: maxsecu_encoding::types::FileScope::AccountWide,
                    revoked_user_id: Id([scope_user; 16]),
                    revoked_capability: None,
                    from_version: 1,
                    issued_by: Id([1; 16]),
                    created_at: Timestamp(NOW),
                },
                Some(CoSign { admin_id: Id([2; 16]), key: &co }),
            )
            .unwrap();
        ([r.bytes.clone()], r.head)
    }

    #[test]
    fn authorize_recipient_returns_effective_roles_when_clean() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let (sig, b) = admin_binding(&d5, 3);
        let none = TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap();

        let r = v
            .authorize_recipient(&b, &sig, NOW, &mut MemoryTrustStore::new(), &none)
            .unwrap();
        assert_eq!(r.enc_pub, [0xE1; 32]);
        assert_eq!(r.effective_roles, vec![Role::User, Role::Admin]);
    }

    #[test]
    fn authorize_recipient_rejects_an_account_revoked_user() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let (sig, b) = admin_binding(&d5, 3);
        let (recs, head) = account_revoke(3); // revoke user 3 account-wide
        let tombstones = TombstoneSet::verify(&recs, head).unwrap();

        assert_eq!(
            v.authorize_recipient(&b, &sig, NOW, &mut MemoryTrustStore::new(), &tombstones),
            Err(VerifyError::Revoked)
        );
    }

    // ---- §7.4 first-contact key-transparency gate ----

    use crate::transparency::{
        InclusionProof, KtCheckpoint, KtContext, MemoryKtCheckpointStore,
    };
    use maxsecu_crypto::merkle;
    use maxsecu_encoding::{encode, kt_checkpoint_signing_input};

    #[test]
    fn directory_first_contact_requires_kt_inclusion() {
        let d5 = SigningKey::generate();
        let v = verifier(&d5);
        let log = SigningKey::generate();
        let log_pubs = [log.verifying_key().to_bytes()];

        // A KT log whose leaves are the canonical bytes of two real bindings.
        let b_in = binding(1, 0xE1, 0x51, 1);
        let b_out = binding(2, 0xE2, 0x52, 1);
        let sig_in = sign(&d5, &b_in);
        let sig_out = sign(&d5, &b_out);
        let leaves: Vec<Vec<u8>> = vec![encode(&b_in), encode(&b_out)];
        let tree_size = leaves.len() as u64;
        let root = merkle::merkle_root(&leaves);
        let cp = KtCheckpoint {
            tree_size,
            root,
            sig: log.sign_raw(&kt_checkpoint_signing_input(tree_size, &root)),
        };
        let incl_in = InclusionProof {
            index: 0,
            tree_size,
            path: merkle::inclusion_path(0, &leaves),
        };

        // With the gate configured: a binding PROVABLY in the log is accepted.
        let mut store = MemoryKtCheckpointStore::new();
        v.verify_binding_with_kt(
            &b_in,
            &sig_in,
            NOW,
            &mut MemoryTrustStore::new(),
            Some(KtContext {
                inclusion: &incl_in,
                checkpoint: &cp,
                consistency: &[],
                log_pubs: &log_pubs,
                store: &mut store,
            }),
        )
        .expect("a logged binding passes the KT gate");

        // With the gate configured: a first-contact binding NOT in the log (proof is
        // for the wrong leaf) is rejected.
        let mut store2 = MemoryKtCheckpointStore::new();
        assert_eq!(
            v.verify_binding_with_kt(
                &b_out,
                &sig_out,
                NOW,
                &mut MemoryTrustStore::new(),
                Some(KtContext {
                    inclusion: &incl_in, // proof of b_in, but we present b_out
                    checkpoint: &cp,
                    consistency: &[],
                    log_pubs: &log_pubs,
                    store: &mut store2,
                }),
            ),
            Err(VerifyError::NotInLog)
        );

        // With NO gate configured: behavior is unchanged — b_out verifies and pins.
        let mut trust = MemoryTrustStore::new();
        assert!(v
            .verify_binding_with_kt(&b_out, &sig_out, NOW, &mut trust, None)
            .is_ok());
        assert_eq!(trust.get(&[2; 16]).unwrap().key_version, 1);
    }
}
