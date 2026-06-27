//! Client-side §7.6 revocation/role evaluation over the sink-anchored, hash-
//! chained control log (DESIGN §7.6/§11.5/§11.5a/§7.5 D22).
//!
//! The client receives the served control-log records as opaque canonical bytes
//! and an **anchored head** (in Phase 2 an injected/pinned value; the external
//! sink anchoring lands in Phase 6). [`TombstoneSet::verify`] requires the served
//! set to be a **contiguous hash chain from `GENESIS_HEAD` up to the anchored
//! head** and **fails closed on any gap or broken link** — so a malicious server
//! can neither roll back nor *withhold* a fresh tombstone. The evaluation then
//! answers: is a user under an active account-wide/`per-file` revocation, and
//! what are their effective roles (ceiling minus role-narrowing tombstones)?

use maxsecu_crypto::sha256;
use maxsecu_encoding::structs::{KeyCompromise, Reinstatement, Revocation};
use maxsecu_encoding::types::{FileScope, Role};
use maxsecu_encoding::{decode, GENESIS_HEAD};

/// The served control log was not a contiguous chain to the anchored head, or a
/// record was malformed. Every variant is fail-closed (the set is unusable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TombstoneError {
    /// The chain did not reach the anchored head — a withheld tail (D22) or a
    /// shorter set than the sink has committed.
    Gap,
    /// A record's `prev_head` did not match the running head — a dropped/forged
    /// record mid-chain.
    BrokenChain,
    /// A record's bytes were not a canonical revocation/reinstatement/
    /// key-compromise record.
    Malformed,
}

/// One decoded control-log record (the three families share one chain).
#[derive(Debug)]
enum Decoded {
    Revocation(Revocation),
    Reinstatement(Reinstatement),
    KeyCompromise(KeyCompromise),
}

impl Decoded {
    fn prev_head(&self) -> [u8; 32] {
        match self {
            Decoded::Revocation(r) => r.prev_head.0,
            Decoded::Reinstatement(r) => r.prev_head.0,
            Decoded::KeyCompromise(r) => r.prev_head.0,
        }
    }

    /// Decode by peeking the canonical `type_id` (encoding-spec §5). `decode`
    /// also enforces canonicality, so a non-canonical record is rejected.
    fn from_bytes(b: &[u8]) -> Result<Decoded, TombstoneError> {
        let id = match b {
            [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
            _ => return Err(TombstoneError::Malformed),
        };
        let m = |_| TombstoneError::Malformed;
        match id {
            0x0006 => Ok(Decoded::Revocation(decode(b).map_err(m)?)),
            0x0007 => Ok(Decoded::Reinstatement(decode(b).map_err(m)?)),
            0x0008 => Ok(Decoded::KeyCompromise(decode(b).map_err(m)?)),
            _ => Err(TombstoneError::Malformed),
        }
    }
}

/// A control-log record set proven contiguous up to the anchored head — the only
/// state §7.6 decisions may be made over (a gap fails closed before this exists).
#[derive(Debug)]
pub struct TombstoneSet {
    records: Vec<Decoded>,
}

impl TombstoneSet {
    /// Verify `records` (canonical bytes, in chain order) form a contiguous hash
    /// chain from [`GENESIS_HEAD`] up to `anchored_head`. Fail closed on a broken
    /// link (`BrokenChain`), a head that doesn't reach the anchor (`Gap`), or a
    /// malformed record (`Malformed`).
    pub fn verify(
        records: &[Vec<u8>],
        anchored_head: [u8; 32],
    ) -> Result<TombstoneSet, TombstoneError> {
        let mut head = GENESIS_HEAD.0;
        let mut decoded = Vec::with_capacity(records.len());
        for bytes in records {
            let d = Decoded::from_bytes(bytes)?;
            // Each record must chain to the running head — a dropped/forged/
            // reordered record breaks the link and fails closed (D22).
            if d.prev_head() != head {
                return Err(TombstoneError::BrokenChain);
            }
            head = sha256(bytes);
            decoded.push(d);
        }
        // The served set must reach exactly the anchored head — a shorter chain
        // (a withheld fresh tombstone) is a gap (D22), never silently accepted.
        if head != anchored_head {
            return Err(TombstoneError::Gap);
        }
        Ok(TombstoneSet { records: decoded })
    }

    /// Is `user_id` under an active account-wide (`*`) access revocation — barred
    /// as a recipient everywhere (§7.2 step 5)?
    pub fn is_account_revoked(&self, user_id: &[u8; 16]) -> bool {
        self.revocations().any(|r| {
            matches!(r.scope, FileScope::AccountWide)
                && r.revoked_user_id.0 == *user_id
                && r.revoked_capability.is_none()
                && !self.is_superseded(r)
        })
    }

    /// Is `user_id` revoked from `file_id` at `version` — by an account-wide or a
    /// per-file tombstone whose `from_version <= version`, not reinstated (§11.5)?
    pub fn is_revoked(&self, user_id: &[u8; 16], file_id: &[u8; 16], version: u64) -> bool {
        self.revocations().any(|r| {
            r.revoked_user_id.0 == *user_id
                && r.revoked_capability.is_none()
                && r.from_version <= version
                && scope_matches_file(r.scope, file_id)
                && !self.is_superseded(r)
        })
    }

    /// Effective roles = `ceiling` minus any active role-narrowing tombstone for
    /// the user (§7.6/§10.1) — the binding sets the ceiling, a tombstone narrows.
    pub fn effective_roles(&self, user_id: &[u8; 16], ceiling: &[Role]) -> Vec<Role> {
        ceiling
            .iter()
            .copied()
            .filter(|role| {
                !self.revocations().any(|r| {
                    r.revoked_user_id.0 == *user_id
                        && r.revoked_capability == Some(*role)
                        && !self.is_superseded(r)
                })
            })
            .collect()
    }

    fn revocations(&self) -> impl Iterator<Item = &Revocation> {
        self.records.iter().filter_map(|d| match d {
            Decoded::Revocation(r) => Some(r),
            _ => None,
        })
    }

    /// A revocation is superseded iff a reinstatement names it by the explicit
    /// `(scope, revoked_user, revocation_epoch)` triple (R28 — never a raw
    /// counter comparison). A *later* re-revoke (a higher epoch) is unaffected.
    fn is_superseded(&self, rev: &Revocation) -> bool {
        self.records.iter().any(|d| match d {
            Decoded::Reinstatement(r) => {
                r.scope == rev.scope
                    && r.reinstated_user_id == rev.revoked_user_id
                    && r.supersedes_epoch == rev.revocation_epoch
            }
            _ => false,
        })
    }
}

fn scope_matches_file(scope: FileScope, file_id: &[u8; 16]) -> bool {
    match scope {
        FileScope::AccountWide => true,
        FileScope::Specific(id) => id.0 == *file_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_admin_core::{ControlChain, CoSign, ReinstateParams, RevokeParams};
    use maxsecu_crypto::SigningKey;
    use maxsecu_encoding::types::{Id, Timestamp};

    const NOW: Timestamp = Timestamp(1_719_500_000_000);
    const U: u8 = 0x99;

    fn rp(scope: FileScope, user: u8, cap: Option<Role>, from_version: u64) -> RevokeParams {
        RevokeParams {
            scope,
            revoked_user_id: Id([user; 16]),
            revoked_capability: cap,
            from_version,
            issued_by: Id([1; 16]),
            created_at: NOW,
        }
    }

    fn bytes(records: &[maxsecu_admin_core::SignedControlRecord]) -> Vec<Vec<u8>> {
        records.iter().map(|r| r.bytes.clone()).collect()
    }

    #[test]
    fn empty_chain_matches_only_the_genesis_head() {
        let none: Vec<Vec<u8>> = Vec::new();
        assert!(TombstoneSet::verify(&none, GENESIS_HEAD.0).is_ok());
        assert_eq!(
            TombstoneSet::verify(&none, [9u8; 32]).unwrap_err(),
            TombstoneError::Gap
        );
    }

    #[test]
    fn contiguous_chain_to_the_anchored_head_verifies_and_evaluates() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, U, None, 1), None).unwrap();
        let r2 = chain.revoke(&admin, rp(file, 0x77, None, 1), None).unwrap();

        let set = TombstoneSet::verify(&bytes(&[r1, r2]), chain.head()).unwrap();
        assert!(set.is_revoked(&[U; 16], &[0x0A; 16], 1), "U revoked from file A");
        assert!(!set.is_revoked(&[U; 16], &[0x0B; 16], 1), "but not from another file");
    }

    #[test]
    fn broken_link_fails_closed() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, U, None, 1), None).unwrap();
        let r2 = chain.revoke(&admin, rp(file, 0x77, None, 1), None).unwrap();
        // Out of order: r2.prev_head ≠ GENESIS_HEAD ⇒ broken chain.
        let head = chain.head();
        assert_eq!(
            TombstoneSet::verify(&bytes(&[r2, r1]), head).unwrap_err(),
            TombstoneError::BrokenChain
        );
    }

    #[test]
    fn withheld_tail_is_a_gap() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, U, None, 1), None).unwrap();
        let _r2 = chain.revoke(&admin, rp(file, 0x77, None, 1), None).unwrap();
        // Server serves only r1 but the anchored head is after r2 → gap.
        assert_eq!(
            TombstoneSet::verify(&bytes(&[r1]), chain.head()).unwrap_err(),
            TombstoneError::Gap
        );
    }

    #[test]
    fn account_wide_revocation_bars_the_user_everywhere() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let r = chain
            .revoke(
                &admin,
                rp(FileScope::AccountWide, U, None, 1),
                Some(CoSign { admin_id: Id([2; 16]), key: &co }),
            )
            .unwrap();
        let set = TombstoneSet::verify(&bytes(&[r]), chain.head()).unwrap();
        assert!(set.is_account_revoked(&[U; 16]));
        assert!(!set.is_account_revoked(&[0x55; 16]));
    }

    #[test]
    fn reinstatement_clears_only_the_revocation_it_names() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let cosign = || CoSign { admin_id: Id([2; 16]), key: &co };

        // Revoke (epoch 1), then reinstate superseding epoch 1 → cleared.
        let rev1 = chain
            .revoke(&admin, rp(FileScope::AccountWide, U, None, 1), Some(cosign()))
            .unwrap();
        let rein = chain.reinstate(
            &admin,
            ReinstateParams {
                scope: FileScope::AccountWide,
                reinstated_user_id: Id([U; 16]),
                supersedes_epoch: rev1.epoch().unwrap(),
                issued_by: Id([1; 16]),
                created_at: NOW,
            },
            cosign(),
        );
        let set = TombstoneSet::verify(&bytes(&[rev1.clone(), rein.clone()]), chain.head()).unwrap();
        assert!(!set.is_account_revoked(&[U; 16]), "epoch-1 revoke is superseded");

        // A *later* re-revoke (epoch 2) is NOT cleared by the stale reinstatement.
        let rev2 = chain
            .revoke(&admin, rp(FileScope::AccountWide, U, None, 1), Some(cosign()))
            .unwrap();
        let set = TombstoneSet::verify(&bytes(&[rev1, rein, rev2]), chain.head()).unwrap();
        assert!(set.is_account_revoked(&[U; 16]), "re-revoke (epoch 2) stands");
    }

    #[test]
    fn role_narrowing_tombstone_drops_the_capability() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let r = chain
            .revoke(
                &admin,
                rp(FileScope::AccountWide, U, Some(Role::Admin), 1),
                Some(CoSign { admin_id: Id([2; 16]), key: &co }),
            )
            .unwrap();
        let set = TombstoneSet::verify(&bytes(&[r]), chain.head()).unwrap();
        // Ceiling {User, Admin} narrows to {User}; the user is NOT access-revoked.
        assert_eq!(
            set.effective_roles(&[U; 16], &[Role::User, Role::Admin]),
            vec![Role::User]
        );
        assert!(!set.is_account_revoked(&[U; 16]), "de-admin is not an access revoke");
    }

    #[test]
    fn per_file_revocation_applies_from_its_version_onward() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r = chain.revoke(&admin, rp(file, U, None, 5), None).unwrap();
        let set = TombstoneSet::verify(&bytes(&[r]), chain.head()).unwrap();
        assert!(set.is_revoked(&[U; 16], &[0x0A; 16], 5), "revoked at from_version");
        assert!(set.is_revoked(&[U; 16], &[0x0A; 16], 9), "and later versions");
        assert!(!set.is_revoked(&[U; 16], &[0x0A; 16], 4), "but not earlier versions");
    }
}
