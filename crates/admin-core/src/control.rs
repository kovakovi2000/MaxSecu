//! The append-only, hash-chained control log (DESIGN §7.6/§11.5/§11.5a/§11.7).
//!
//! Revocation, reinstatement, and key-compromise records share **one** chain:
//! each record's `prev_head = SHA-256(canonical(previous record))`, the first
//! seeded from [`GENESIS_HEAD`]. [`ControlChain`] tracks the running head and
//! allocates the per-scope monotonic epochs, so a ceremony issues a contiguous,
//! correctly-linked batch the server can only append to (it can forge no record).

use crate::CeremonyError;
use maxsecu_crypto::{sha256, CryptoError, SigningKey, VerifyingKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{KeyCompromise, Reinstatement, Revocation};
use maxsecu_encoding::types::{Bytes32, FileScope, Id, Role, Timestamp};
use maxsecu_encoding::{encode, GENESIS_HEAD};
use std::collections::HashMap;

/// A second admin authorizing a dual-controlled action (§10.1): their `user_id`
/// (recorded in the signed record as `co_signed_by`) and signing key.
pub struct CoSign<'a> {
    pub admin_id: Id,
    pub key: &'a SigningKey,
}

/// Inputs for a revocation tombstone (§11.5); the chain fills `prev_head` and
/// `revocation_epoch`.
pub struct RevokeParams {
    pub scope: FileScope,
    pub revoked_user_id: Id,
    /// `Some(role)` narrows a capability (e.g. de-admin, §7.6); `None` revokes
    /// access to the scope from `from_version` onward.
    pub revoked_capability: Option<Role>,
    pub from_version: u64,
    pub issued_by: Id,
    pub created_at: Timestamp,
}

/// Inputs for a reinstatement (§11.5a). Always dual-controlled.
pub struct ReinstateParams {
    pub scope: FileScope,
    pub reinstated_user_id: Id,
    /// The `revocation_epoch` this reinstatement clears, by explicit reference
    /// (R28 — never a raw counter comparison).
    pub supersedes_epoch: u64,
    pub issued_by: Id,
    pub created_at: Timestamp,
}

/// Inputs for a signing-key-compromise cutoff (§11.7 / D28). Always dual-controlled.
pub struct KeyCompromiseParams {
    pub user_id: Id,
    pub key_version: u64,
    pub effective_from: Timestamp,
    pub issued_by: Id,
    pub created_at: Timestamp,
}

/// One of the three control-log record families (encoding-spec §4 type_ids
/// 0x0006/0x0007/0x0008), all sharing the single anchored hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRecord {
    Revocation(Revocation),
    Reinstatement(Reinstatement),
    KeyCompromise(KeyCompromise),
}

impl ControlRecord {
    fn prev_head(&self) -> [u8; 32] {
        match self {
            ControlRecord::Revocation(r) => r.prev_head.0,
            ControlRecord::Reinstatement(r) => r.prev_head.0,
            ControlRecord::KeyCompromise(r) => r.prev_head.0,
        }
    }

    fn canonical(&self) -> Vec<u8> {
        match self {
            ControlRecord::Revocation(r) => encode(r),
            ControlRecord::Reinstatement(r) => encode(r),
            ControlRecord::KeyCompromise(r) => encode(r),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            ControlRecord::Revocation(_) => labels::REVOCATION,
            ControlRecord::Reinstatement(_) => labels::REINSTATEMENT,
            ControlRecord::KeyCompromise(_) => labels::KEY_COMPROMISE,
        }
    }

    fn sign(&self, key: &SigningKey) -> [u8; 64] {
        match self {
            ControlRecord::Revocation(r) => key.sign_canonical(labels::REVOCATION, r),
            ControlRecord::Reinstatement(r) => key.sign_canonical(labels::REINSTATEMENT, r),
            ControlRecord::KeyCompromise(r) => key.sign_canonical(labels::KEY_COMPROMISE, r),
        }
    }

    fn verify_with(&self, vk: &VerifyingKey, sig: &[u8; 64]) -> Result<(), CryptoError> {
        match self {
            ControlRecord::Revocation(r) => vk.verify_canonical(labels::REVOCATION, r, sig),
            ControlRecord::Reinstatement(r) => vk.verify_canonical(labels::REINSTATEMENT, r, sig),
            ControlRecord::KeyCompromise(r) => vk.verify_canonical(labels::KEY_COMPROMISE, r, sig),
        }
    }
}

/// A signed, chain-linked control-log record: the typed record, its canonical
/// bytes (what the server stores and clients verify), the chain `head` it
/// advances to, the issuer signature, and an optional second-admin co-signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedControlRecord {
    pub record: ControlRecord,
    /// `canonical(record)` — the exact signed bytes (also what `head` hashes).
    pub bytes: Vec<u8>,
    /// `SHA-256(canonical(record))` — the new chain head after this record.
    pub head: [u8; 32],
    pub sig: [u8; 64],
    /// The second admin's signature over the same bytes, for dual-controlled
    /// records (mass/`*` revoke, every reinstatement, every key-compromise).
    pub co_sig: Option<[u8; 64]>,
}

impl SignedControlRecord {
    /// The prior chain head this record links to (`GENESIS_HEAD` for the first).
    pub fn prev_head(&self) -> [u8; 32] {
        self.record.prev_head()
    }

    /// The per-scope monotonic epoch for revocation/reinstatement; `None` for a
    /// key-compromise record (which carries no epoch).
    pub fn epoch(&self) -> Option<u64> {
        match &self.record {
            ControlRecord::Revocation(r) => Some(r.revocation_epoch),
            ControlRecord::Reinstatement(r) => Some(r.reinstatement_epoch),
            ControlRecord::KeyCompromise(_) => None,
        }
    }

    /// The domain-separation label this record was signed under.
    pub fn label(&self) -> &'static str {
        self.record.label()
    }

    /// Verify the issuer signature under an admin's public key (fail-closed).
    pub fn verify(&self, issuer_pub: &[u8; 32]) -> Result<(), CryptoError> {
        let vk = VerifyingKey::from_bytes(issuer_pub)?;
        self.record.verify_with(&vk, &self.sig)
    }

    /// Verify the second-admin co-signature. `Err` if none is present.
    pub fn verify_co_sign(&self, co_pub: &[u8; 32]) -> Result<(), CryptoError> {
        let sig = self.co_sig.ok_or(CryptoError::Signature)?;
        let vk = VerifyingKey::from_bytes(co_pub)?;
        self.record.verify_with(&vk, &sig)
    }
}

/// Builds a contiguous run of control-log records, tracking the running head and
/// per-scope epochs. Start a fresh chain with [`ControlChain::new`] or continue
/// an existing one with [`ControlChain::resume`].
pub struct ControlChain {
    head: [u8; 32],
    revoke_epochs: HashMap<Option<[u8; 16]>, u64>,
    reinstate_epochs: HashMap<Option<[u8; 16]>, u64>,
}

impl Default for ControlChain {
    fn default() -> Self {
        ControlChain::new()
    }
}

impl ControlChain {
    /// A fresh chain seeded from [`GENESIS_HEAD`] with empty epoch counters.
    pub fn new() -> ControlChain {
        ControlChain::resume(GENESIS_HEAD.0)
    }

    /// Continue an existing chain from a known head (e.g. the current anchored
    /// head at the start of a ceremony). Epoch counters start empty; supply the
    /// next epoch via the per-scope monotonic allocation as records are issued.
    pub fn resume(head: [u8; 32]) -> ControlChain {
        ControlChain {
            head,
            revoke_epochs: HashMap::new(),
            reinstate_epochs: HashMap::new(),
        }
    }

    /// The current chain head (advances after each issued record).
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// Issue a revocation tombstone. A mass/account-wide (`*`) revoke requires a
    /// co-signer (dual control, §10.1) → [`CeremonyError::DualControlRequired`]
    /// otherwise; a single-file revoke does not.
    pub fn revoke(
        &mut self,
        issuer: &SigningKey,
        params: RevokeParams,
        co_sign: Option<CoSign<'_>>,
    ) -> Result<SignedControlRecord, CeremonyError> {
        if matches!(params.scope, FileScope::AccountWide) && co_sign.is_none() {
            return Err(CeremonyError::DualControlRequired);
        }
        let epoch = next_epoch(&mut self.revoke_epochs, &params.scope);
        let record = ControlRecord::Revocation(Revocation {
            scope: params.scope,
            revoked_user_id: params.revoked_user_id,
            revoked_capability: params.revoked_capability,
            from_version: params.from_version,
            revocation_epoch: epoch,
            prev_head: Bytes32(self.head),
            issued_by: params.issued_by,
            co_signed_by: co_sign.as_ref().map(|c| c.admin_id),
            created_at: params.created_at,
        });
        Ok(self.finish(record, issuer, co_sign.map(|c| c.key)))
    }

    /// Issue a reinstatement — always dual-controlled (§11.5a).
    pub fn reinstate(
        &mut self,
        issuer: &SigningKey,
        params: ReinstateParams,
        co_sign: CoSign<'_>,
    ) -> SignedControlRecord {
        let epoch = next_epoch(&mut self.reinstate_epochs, &params.scope);
        let record = ControlRecord::Reinstatement(Reinstatement {
            scope: params.scope,
            reinstated_user_id: params.reinstated_user_id,
            supersedes_epoch: params.supersedes_epoch,
            reinstatement_epoch: epoch,
            prev_head: Bytes32(self.head),
            issued_by: params.issued_by,
            co_signed_by: co_sign.admin_id,
            created_at: params.created_at,
        });
        self.finish(record, issuer, Some(co_sign.key))
    }

    /// Issue a signing-key-compromise cutoff — always dual-controlled (§11.7/D28).
    pub fn key_compromise(
        &mut self,
        issuer: &SigningKey,
        params: KeyCompromiseParams,
        co_sign: CoSign<'_>,
    ) -> SignedControlRecord {
        let record = ControlRecord::KeyCompromise(KeyCompromise {
            user_id: params.user_id,
            key_version: params.key_version,
            effective_from: params.effective_from,
            prev_head: Bytes32(self.head),
            issued_by: params.issued_by,
            co_signed_by: co_sign.admin_id,
            created_at: params.created_at,
        });
        self.finish(record, issuer, Some(co_sign.key))
    }

    /// Canonicalize, hash into the chain head, sign (and co-sign), and advance.
    fn finish(
        &mut self,
        record: ControlRecord,
        issuer: &SigningKey,
        co_key: Option<&SigningKey>,
    ) -> SignedControlRecord {
        let bytes = record.canonical();
        let head = sha256(&bytes);
        let sig = record.sign(issuer);
        let co_sig = co_key.map(|k| record.sign(k));
        self.head = head;
        SignedControlRecord {
            record,
            bytes,
            head,
            sig,
            co_sig,
        }
    }
}

/// Allocate the next per-scope monotonic epoch (1-based), keyed on the file id or
/// the account-wide `*` (a single global counter).
fn next_epoch(epochs: &mut HashMap<Option<[u8; 16]>, u64>, scope: &FileScope) -> u64 {
    let key = match scope {
        FileScope::Specific(Id(id)) => Some(*id),
        FileScope::AccountWide => None,
    };
    let e = epochs.entry(key).or_insert(0);
    *e += 1;
    *e
}
