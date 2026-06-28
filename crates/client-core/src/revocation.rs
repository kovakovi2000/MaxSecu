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

use maxsecu_crypto::{sha256, VerifyingKey};
use maxsecu_encoding::structs::{KeyCompromise, Reinstatement, Revocation};
use maxsecu_encoding::types::{FileScope, Id, Role};
use maxsecu_encoding::{decode, labels, GENESIS_HEAD};

/// The served control log was not a contiguous chain to the anchored head, a
/// record was malformed, or a record's **issuer authority** did not check out.
/// Every variant is fail-closed (the set is unusable).
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
    /// A record's `issued_by` (or `co_signed_by`) could not be resolved to a
    /// directory binding — the issuer is unknown, so its authority is unprovable.
    UnknownIssuer,
    /// The issuer (or co-signer) Ed25519 signature did not verify against the
    /// resolved binding — a forged or tampered control record (§11.5/§12.9b).
    BadAuthority,
    /// The issuer (or co-signer) did not hold the `admin` **effective** role as
    /// of the chain prefix before this record (§7.6/§10.1) — including a de-admin
    /// that took effect earlier in the chain.
    NotAdmin,
    /// A dual-controlled record (mass/`*` revoke, every reinstatement, every
    /// key-compromise) lacked a valid second-admin co-signature by a *distinct*
    /// admin (§10.1/§11.5a).
    DualControlMissing,
}

/// What the caller resolves out of band for a control-log record's issuer: the
/// admin's directory-verified Ed25519 `sig_pub`, its offline-signed role
/// *ceiling*, and the `key_version` of the binding used (informational; the
/// effective admin role is the ceiling minus prefix role-narrowing tombstones).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerInfo {
    pub sig_pub: [u8; 32],
    pub roles: Vec<Role>,
    pub key_version: u64,
}

/// One served control-log record as the wire delivers it (api.md §7.1): the
/// canonical record bytes, the issuer signature, and the optional second-admin
/// co-signature (both over the same canonical bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecordIn {
    pub bytes: Vec<u8>,
    pub sig: [u8; 64],
    pub co_sig: Option<[u8; 64]>,
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

    /// The admin `user_id` that issued (and signed) this record.
    fn issued_by(&self) -> Id {
        match self {
            Decoded::Revocation(r) => r.issued_by,
            Decoded::Reinstatement(r) => r.issued_by,
            Decoded::KeyCompromise(r) => r.issued_by,
        }
    }

    /// The second admin that co-signed, if the record names one.
    fn co_signed_by(&self) -> Option<Id> {
        match self {
            Decoded::Revocation(r) => r.co_signed_by,
            Decoded::Reinstatement(r) => Some(r.co_signed_by),
            Decoded::KeyCompromise(r) => Some(r.co_signed_by),
        }
    }

    /// Does this record require a distinct second-admin co-signature? Mass/`*`
    /// revoke, every reinstatement, every key-compromise (§10.1/§11.5a/§11.7).
    fn requires_dual_control(&self) -> bool {
        match self {
            Decoded::Revocation(r) => matches!(r.scope, FileScope::AccountWide),
            Decoded::Reinstatement(_) | Decoded::KeyCompromise(_) => true,
        }
    }

    /// Verify an Ed25519 signature over this record's canonical form under its
    /// domain label (§5). Fail-closed on a malformed key or bad signature.
    fn verify_sig(&self, pubkey: &[u8; 32], sig: &[u8; 64]) -> bool {
        let vk = match VerifyingKey::from_bytes(pubkey) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        match self {
            Decoded::Revocation(r) => vk.verify_canonical(labels::REVOCATION, r, sig).is_ok(),
            Decoded::Reinstatement(r) => vk.verify_canonical(labels::REINSTATEMENT, r, sig).is_ok(),
            Decoded::KeyCompromise(r) => vk.verify_canonical(labels::KEY_COMPROMISE, r, sig).is_ok(),
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

    /// Like [`TombstoneSet::verify`], but additionally **authenticates every
    /// record's issuer authority** (`sink-interface.md` §5 step 4): the issuer
    /// (and, where dual control is required, a *distinct* co-signer) Ed25519
    /// signature verifies against the resolved directory binding, and the
    /// issuer/co-signer holds the `admin` **effective** role as of the chain
    /// **prefix** before this record (ceiling minus prefix role-narrowing
    /// tombstones — so a de-admin earlier in the chain strips authority from a
    /// later record by the same admin). `issuer` resolves an `issued_by` to its
    /// [`IssuerInfo`]. Fail-closed on any failure. This is the authoritative
    /// constructor for §7.6 decisions against a malicious server.
    pub fn verify_authenticated(
        records: &[ControlRecordIn],
        anchored_head: [u8; 32],
        issuer: &dyn Fn(Id) -> Option<IssuerInfo>,
    ) -> Result<TombstoneSet, TombstoneError> {
        let mut head = GENESIS_HEAD.0;
        let mut decoded: Vec<Decoded> = Vec::with_capacity(records.len());
        for rec in records {
            let d = Decoded::from_bytes(&rec.bytes)?;
            if d.prev_head() != head {
                return Err(TombstoneError::BrokenChain);
            }
            authenticate_authority(&d, rec, &decoded, issuer)?;
            head = sha256(&rec.bytes);
            decoded.push(d);
        }
        if head != anchored_head {
            return Err(TombstoneError::Gap);
        }
        Ok(TombstoneSet { records: decoded })
    }

    /// Is `user_id` under an active account-wide (`*`) access revocation — barred
    /// as a recipient everywhere (§7.2 step 5)?
    pub fn is_account_revoked(&self, user_id: &[u8; 16]) -> bool {
        revocations_in(&self.records).any(|r| {
            matches!(r.scope, FileScope::AccountWide)
                && r.revoked_user_id.0 == *user_id
                && r.revoked_capability.is_none()
                && !is_superseded_in(&self.records, r)
        })
    }

    /// Is `user_id` revoked from `file_id` at `version` — by an account-wide or a
    /// per-file tombstone whose `from_version <= version`, not reinstated (§11.5)?
    pub fn is_revoked(&self, user_id: &[u8; 16], file_id: &[u8; 16], version: u64) -> bool {
        revocations_in(&self.records).any(|r| {
            r.revoked_user_id.0 == *user_id
                && r.revoked_capability.is_none()
                && r.from_version <= version
                && scope_matches_file(r.scope, file_id)
                && !is_superseded_in(&self.records, r)
        })
    }

    /// Effective roles = `ceiling` minus any active role-narrowing tombstone for
    /// the user (§7.6/§10.1) — the binding sets the ceiling, a tombstone narrows.
    pub fn effective_roles(&self, user_id: &[u8; 16], ceiling: &[Role]) -> Vec<Role> {
        effective_roles_in(&self.records, user_id, ceiling)
    }

    /// The active `key_compromise` cutoff for `(user_id, key_version)`, if any
    /// (§11.7/D28). Callers pair it with the record's **sink position** to gate a
    /// durable `genesis` signed under that key (R27) — never with `effective_from`.
    pub fn key_compromise_for(
        &self,
        user_id: &[u8; 16],
        key_version: u64,
    ) -> Option<&KeyCompromise> {
        self.records.iter().find_map(|d| match d {
            Decoded::KeyCompromise(kc)
                if kc.user_id.0 == *user_id && kc.key_version == key_version =>
            {
                Some(kc)
            }
            _ => None,
        })
    }
}

/// Authenticate one record's issuer (and co-signer) authority against the chain
/// `prefix` (records strictly before it). Pulled out so it has a single home.
fn authenticate_authority(
    d: &Decoded,
    rec: &ControlRecordIn,
    prefix: &[Decoded],
    issuer: &dyn Fn(Id) -> Option<IssuerInfo>,
) -> Result<(), TombstoneError> {
    let issued_by = d.issued_by();
    let info = issuer(issued_by).ok_or(TombstoneError::UnknownIssuer)?;
    if !d.verify_sig(&info.sig_pub, &rec.sig) {
        return Err(TombstoneError::BadAuthority);
    }
    if !prefix_is_admin(prefix, &issued_by, &info.roles) {
        return Err(TombstoneError::NotAdmin);
    }
    if d.requires_dual_control() {
        let co_id = d.co_signed_by().ok_or(TombstoneError::DualControlMissing)?;
        let co_sig = rec.co_sig.ok_or(TombstoneError::DualControlMissing)?;
        // Dual control means two *distinct* admins.
        if co_id == issued_by {
            return Err(TombstoneError::DualControlMissing);
        }
        let co_info = issuer(co_id).ok_or(TombstoneError::UnknownIssuer)?;
        if !d.verify_sig(&co_info.sig_pub, &co_sig) {
            return Err(TombstoneError::BadAuthority);
        }
        if !prefix_is_admin(prefix, &co_id, &co_info.roles) {
            return Err(TombstoneError::NotAdmin);
        }
    }
    Ok(())
}

/// Does `user_id` hold the `admin` effective role over `records` (ceiling minus
/// active role-narrowing tombstones)?
fn prefix_is_admin(records: &[Decoded], user_id: &Id, ceiling: &[Role]) -> bool {
    effective_roles_in(records, &user_id.0, ceiling).contains(&Role::Admin)
}

fn revocations_in(records: &[Decoded]) -> impl Iterator<Item = &Revocation> {
    records.iter().filter_map(|d| match d {
        Decoded::Revocation(r) => Some(r),
        _ => None,
    })
}

/// Effective roles = `ceiling` minus any active role-narrowing tombstone for the
/// user, evaluated over the given record slice (§7.6/§10.1).
fn effective_roles_in(records: &[Decoded], user_id: &[u8; 16], ceiling: &[Role]) -> Vec<Role> {
    ceiling
        .iter()
        .copied()
        .filter(|role| {
            !revocations_in(records).any(|r| {
                r.revoked_user_id.0 == *user_id
                    && r.revoked_capability == Some(*role)
                    && !is_superseded_in(records, r)
            })
        })
        .collect()
}

/// A revocation is superseded iff a reinstatement names it by the explicit
/// `(scope, revoked_user, revocation_epoch)` triple (R28 — never a raw counter
/// comparison). A *later* re-revoke (a higher epoch) is unaffected.
fn is_superseded_in(records: &[Decoded], rev: &Revocation) -> bool {
    records.iter().any(|d| match d {
        Decoded::Reinstatement(r) => {
            r.scope == rev.scope
                && r.reinstated_user_id == rev.revoked_user_id
                && r.supersedes_epoch == rev.revocation_epoch
        }
        _ => false,
    })
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
    use maxsecu_admin_core::{ControlChain, CoSign, KeyCompromiseParams, ReinstateParams, RevokeParams};
    use maxsecu_crypto::SigningKey;
    use maxsecu_encoding::types::{Bytes32, Id, Timestamp};

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

    fn admin_issuer(admin: &SigningKey, admin_id: Id) -> impl Fn(Id) -> Option<IssuerInfo> + '_ {
        let pubk = admin.verifying_key().to_bytes();
        move |id: Id| {
            (id == admin_id).then(|| IssuerInfo {
                sig_pub: pubk,
                roles: vec![Role::User, Role::Admin],
                key_version: 1,
            })
        }
    }

    fn rec_in(r: &maxsecu_admin_core::SignedControlRecord) -> ControlRecordIn {
        ControlRecordIn {
            bytes: r.bytes.clone(),
            sig: r.sig,
            co_sig: r.co_sig,
        }
    }

    const ADMIN_ID: Id = Id([1; 16]);
    const A2_ID: Id = Id([2; 16]);
    const B_ID: Id = Id([3; 16]);

    /// Resolver over several (id, sig_pub, ceiling) admins.
    fn multi_issuer(entries: Vec<(Id, [u8; 32], Vec<Role>)>) -> impl Fn(Id) -> Option<IssuerInfo> {
        move |id: Id| {
            entries.iter().find(|(i, _, _)| *i == id).map(|(_, pk, roles)| IssuerInfo {
                sig_pub: *pk,
                roles: roles.clone(),
                key_version: 1,
            })
        }
    }

    /// Hand-build a signed revocation record (bypassing `ControlChain`'s issuance
    /// rules) so the *verifier* can be tested against malformed authority.
    fn signed_revocation(
        rev: Revocation,
        signer: &SigningKey,
        co: Option<&SigningKey>,
    ) -> ([u8; 32], ControlRecordIn) {
        let bytes = maxsecu_encoding::encode(&rev);
        let sig = signer.sign_canonical(labels::REVOCATION, &rev);
        let co_sig = co.map(|k| k.sign_canonical(labels::REVOCATION, &rev));
        (sha256(&bytes), ControlRecordIn { bytes, sig, co_sig })
    }

    fn account_revoke(victim: u8, epoch: u64, prev_head: [u8; 32], cap: Option<Role>) -> Revocation {
        Revocation {
            scope: FileScope::AccountWide,
            revoked_user_id: Id([victim; 16]),
            revoked_capability: cap,
            from_version: 1,
            revocation_epoch: epoch,
            prev_head: Bytes32(prev_head),
            issued_by: ADMIN_ID,
            co_signed_by: Some(A2_ID),
            created_at: NOW,
        }
    }

    #[test]
    fn forged_issuer_signature_is_rejected() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, U, None, 1), None).unwrap();

        let mut rec = rec_in(&r1);
        rec.sig[0] ^= 0x01; // corrupt the issuer signature

        assert_eq!(
            TombstoneSet::verify_authenticated(&[rec], chain.head(), &admin_issuer(&admin, ADMIN_ID))
                .unwrap_err(),
            TombstoneError::BadAuthority
        );
    }

    #[test]
    fn authenticated_chain_verifies_and_evaluates() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, U, None, 1), None).unwrap();

        let set = TombstoneSet::verify_authenticated(
            &[rec_in(&r1)],
            chain.head(),
            &admin_issuer(&admin, ADMIN_ID),
        )
        .expect("authenticated chain verifies");
        assert!(set.is_revoked(&[U; 16], &[0x0A; 16], 1));
    }

    #[test]
    fn unknown_issuer_is_rejected() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, U, None, 1), None).unwrap();
        // Resolver knows nobody.
        let none = |_: Id| None;
        assert_eq!(
            TombstoneSet::verify_authenticated(&[rec_in(&r1)], chain.head(), &none).unwrap_err(),
            TombstoneError::UnknownIssuer
        );
    }

    #[test]
    fn non_admin_issuer_is_rejected() {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let file = FileScope::Specific(Id([0x0A; 16]));
        let r1 = chain.revoke(&admin, rp(file, U, None, 1), None).unwrap();
        // The issuer's binding carries only the User ceiling — no admin authority.
        let user_only = multi_issuer(vec![(ADMIN_ID, admin.verifying_key().to_bytes(), vec![Role::User])]);
        assert_eq!(
            TombstoneSet::verify_authenticated(&[rec_in(&r1)], chain.head(), &user_only).unwrap_err(),
            TombstoneError::NotAdmin
        );
    }

    #[test]
    fn account_wide_revoke_without_cosig_is_rejected() {
        let admin = SigningKey::generate();
        // A `*` revoke hand-forged with NO co-signature (ControlChain would refuse
        // to build this — the verifier must independently reject it).
        let (head, rec) = signed_revocation(account_revoke(U, 1, GENESIS_HEAD.0, None), &admin, None);
        let res = multi_issuer(vec![(ADMIN_ID, admin.verifying_key().to_bytes(), vec![Role::Admin])]);
        assert_eq!(
            TombstoneSet::verify_authenticated(&[rec], head, &res).unwrap_err(),
            TombstoneError::DualControlMissing
        );
    }

    #[test]
    fn cosigner_equal_to_issuer_is_rejected() {
        let admin = SigningKey::generate();
        // co_signed_by names the issuer itself, and co_sig is the issuer's own sig.
        let mut rev = account_revoke(U, 1, GENESIS_HEAD.0, None);
        rev.co_signed_by = Some(ADMIN_ID); // same as issued_by
        let (head, rec) = signed_revocation(rev, &admin, Some(&admin));
        let res = multi_issuer(vec![(ADMIN_ID, admin.verifying_key().to_bytes(), vec![Role::Admin])]);
        assert_eq!(
            TombstoneSet::verify_authenticated(&[rec], head, &res).unwrap_err(),
            TombstoneError::DualControlMissing
        );
    }

    #[test]
    fn account_wide_revoke_with_valid_dual_control_verifies() {
        let a1 = SigningKey::generate();
        let a2 = SigningKey::generate();
        let (head, rec) = signed_revocation(account_revoke(U, 1, GENESIS_HEAD.0, None), &a1, Some(&a2));
        let res = multi_issuer(vec![
            (ADMIN_ID, a1.verifying_key().to_bytes(), vec![Role::Admin]),
            (A2_ID, a2.verifying_key().to_bytes(), vec![Role::Admin]),
        ]);
        let set = TombstoneSet::verify_authenticated(&[rec], head, &res).expect("dual-controlled `*` verifies");
        assert!(set.is_account_revoked(&[U; 16]));
    }

    #[test]
    fn de_admin_earlier_in_chain_strips_later_authority() {
        // Record 0: A1+A2 de-admin B (role-narrowing `*` tombstone, dual control).
        let a1 = SigningKey::generate();
        let a2 = SigningKey::generate();
        let b = SigningKey::generate();
        let (head0, r0) =
            signed_revocation(account_revoke(3, 1, GENESIS_HEAD.0, Some(Role::Admin)), &a1, Some(&a2));
        // Record 1: B issues a per-file revoke — but B was de-admined at record 0,
        // so its effective role over the prefix is no longer admin → NotAdmin.
        let b_rev = Revocation {
            scope: FileScope::Specific(Id([0x0A; 16])),
            revoked_user_id: Id([U; 16]),
            revoked_capability: None,
            from_version: 1,
            revocation_epoch: 1,
            prev_head: Bytes32(head0),
            issued_by: B_ID,
            co_signed_by: None,
            created_at: NOW,
        };
        let (head1, r1) = signed_revocation(b_rev, &b, None);
        let res = multi_issuer(vec![
            (ADMIN_ID, a1.verifying_key().to_bytes(), vec![Role::Admin]),
            (A2_ID, a2.verifying_key().to_bytes(), vec![Role::Admin]),
            // B's binding ceiling still lists Admin, but the tombstone narrows it.
            (B_ID, b.verifying_key().to_bytes(), vec![Role::User, Role::Admin]),
        ]);
        assert_eq!(
            TombstoneSet::verify_authenticated(&[r0, r1], head1, &res).unwrap_err(),
            TombstoneError::NotAdmin
        );
    }

    #[test]
    fn key_compromise_for_finds_the_cutoff() {
        let admin = SigningKey::generate();
        let co = SigningKey::generate();
        let mut chain = ControlChain::new();
        let kc = chain.key_compromise(
            &admin,
            KeyCompromiseParams {
                user_id: Id([U; 16]),
                key_version: 3,
                effective_from: NOW,
                issued_by: ADMIN_ID,
                created_at: NOW,
            },
            CoSign { admin_id: A2_ID, key: &co },
        );
        let res = multi_issuer(vec![
            (ADMIN_ID, admin.verifying_key().to_bytes(), vec![Role::Admin]),
            (A2_ID, co.verifying_key().to_bytes(), vec![Role::Admin]),
        ]);
        let set = TombstoneSet::verify_authenticated(&[rec_in(&kc)], chain.head(), &res).unwrap();
        assert!(set.key_compromise_for(&[U; 16], 3).is_some(), "the compromised key");
        assert!(set.key_compromise_for(&[U; 16], 2).is_none(), "a different key_version");
        assert!(set.key_compromise_for(&[0x55; 16], 3).is_none(), "a different user");
    }

    #[test]
    fn reinstatement_without_cosig_is_rejected() {
        use maxsecu_encoding::structs::Reinstatement;
        let admin = SigningKey::generate();
        let rein = Reinstatement {
            scope: FileScope::AccountWide,
            reinstated_user_id: Id([U; 16]),
            supersedes_epoch: 1,
            reinstatement_epoch: 1,
            prev_head: Bytes32(GENESIS_HEAD.0),
            issued_by: ADMIN_ID,
            co_signed_by: A2_ID,
            created_at: NOW,
        };
        let bytes = maxsecu_encoding::encode(&rein);
        let sig = admin.sign_canonical(labels::REINSTATEMENT, &rein);
        // Privilege-restoring record presented with NO co-signature → rejected.
        let rec = ControlRecordIn { bytes: bytes.clone(), sig, co_sig: None };
        let res = multi_issuer(vec![(ADMIN_ID, admin.verifying_key().to_bytes(), vec![Role::Admin])]);
        assert_eq!(
            TombstoneSet::verify_authenticated(&[rec], sha256(&bytes), &res).unwrap_err(),
            TombstoneError::DualControlMissing
        );
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
