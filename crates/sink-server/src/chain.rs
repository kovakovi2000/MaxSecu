//! The append-only, hash-chained control-log store (DESIGN §6.1/§7.6,
//! `docs/sink-interface.md` §2).
//!
//! The sink stores the canonical control-log record bytes and tracks the running
//! head, recomputing it the SAME way clients do (`client-core::revocation`):
//! `head = SHA-256(canonical(record))`, seeded from [`GENESIS_HEAD`]. An append
//! is accepted ONLY if the record's `prev_head` equals the current head — the
//! §6.1 append-only guarantee: no rewrite, no reorder, no fork. The store can
//! therefore only grow, and its head equals exactly what a client recomputes
//! from the same records.

use maxsecu_crypto::sha256;
use maxsecu_encoding::structs::{KeyCompromise, Reinstatement, Revocation};
use maxsecu_encoding::{decode, GENESIS_HEAD};

/// The tuple the sink attests (`sink-interface.md` §2): the chain length and its
/// head. A local type (we avoid coupling the sink lib to client-core); it mirrors
/// `client-core::sink::AnchoredHead` field-for-field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredHead {
    pub chain_seq: u64,
    pub head: [u8; 32],
}

/// Why an [`ControlLogStore::append`] was refused — both fail-closed (the store
/// is unchanged).
#[derive(Debug, PartialEq, Eq)]
pub enum AppendError {
    /// The record's `prev_head` did not equal the current head — a rewrite,
    /// reorder, or fork attempt. The append-only chain admits no such record.
    NotAppending,
    /// The bytes were not a canonical revocation/reinstatement/key-compromise
    /// record, so no `prev_head` could be peeked.
    Malformed,
}

/// Peek a control-log record's `prev_head` from its canonical bytes, mirroring
/// `client-core::revocation::Decoded::from_bytes`: read the `u16 type_id`, decode
/// the matching struct (which also enforces canonicality), and pull `prev_head`.
fn peek_prev_head(bytes: &[u8]) -> Result<[u8; 32], AppendError> {
    let id = match bytes {
        [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
        _ => return Err(AppendError::Malformed),
    };
    let m = |_| AppendError::Malformed;
    let prev = match id {
        0x0006 => decode::<Revocation>(bytes).map_err(m)?.prev_head.0,
        0x0007 => decode::<Reinstatement>(bytes).map_err(m)?.prev_head.0,
        0x0008 => decode::<KeyCompromise>(bytes).map_err(m)?.prev_head.0,
        _ => return Err(AppendError::Malformed),
    };
    Ok(prev)
}

/// An append-only store of canonical control-log record bytes plus the running
/// head and chain length. Start empty with [`ControlLogStore::new`].
pub struct ControlLogStore {
    records: Vec<Vec<u8>>,
    head: [u8; 32],
    chain_seq: u64,
}

impl Default for ControlLogStore {
    fn default() -> Self {
        ControlLogStore::new()
    }
}

impl ControlLogStore {
    /// A fresh store anchored at the empty chain ([`GENESIS_HEAD`], `chain_seq 0`).
    pub fn new() -> ControlLogStore {
        ControlLogStore {
            records: Vec::new(),
            head: GENESIS_HEAD.0,
            chain_seq: 0,
        }
    }

    /// Append one canonical record. The record's `prev_head` must equal the
    /// current head (else [`AppendError::NotAppending`] — the append-only/no-
    /// rewrite/no-reorder guarantee, §6.1); undecodable bytes are
    /// [`AppendError::Malformed`]. On success the head advances exactly as a
    /// client recomputes it (`SHA-256(record)`), the length bumps, and the new
    /// [`AnchoredHead`] is returned.
    pub fn append(&mut self, record_bytes: Vec<u8>) -> Result<AnchoredHead, AppendError> {
        let prev_head = peek_prev_head(&record_bytes)?;
        if prev_head != self.head {
            return Err(AppendError::NotAppending);
        }
        self.head = sha256(&record_bytes);
        self.records.push(record_bytes);
        self.chain_seq += 1;
        Ok(self.head())
    }

    /// The current anchored head — `{chain_seq, head}`.
    pub fn head(&self) -> AnchoredHead {
        AnchoredHead {
            chain_seq: self.chain_seq,
            head: self.head,
        }
    }

    /// Records strictly after `since_seq` (1-based `chain_seq`), up to `limit`,
    /// each paired with its 1-based position — the server-facing read used to
    /// serve the tail a client is missing.
    pub fn records(&self, since_seq: u64, limit: usize) -> Vec<(u64, Vec<u8>)> {
        self.records
            .iter()
            .enumerate()
            .map(|(i, b)| (i as u64 + 1, b))
            .filter(|(seq, _)| *seq > since_seq)
            .take(limit)
            .map(|(seq, b)| (seq, b.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_admin_core::{ControlChain, RevokeParams};
    use maxsecu_encoding::types::{FileScope, Id, Timestamp};

    const NOW: Timestamp = Timestamp(1_719_500_000_000);
    const ADMIN_ID: Id = Id([1; 16]);

    fn rp(victim: u8) -> RevokeParams {
        RevokeParams {
            scope: FileScope::Specific(Id([0x0A; 16])),
            revoked_user_id: Id([victim; 16]),
            revoked_capability: None,
            from_version: 1,
            issued_by: ADMIN_ID,
            created_at: NOW,
        }
    }

    #[test]
    fn append_extends_chain_and_head() {
        // Two genuine records from a real admin-core chain.
        let mut chain = ControlChain::new();
        let admin = maxsecu_crypto::SigningKey::generate();
        let r1 = chain.revoke(&admin, rp(0x99), None).unwrap();
        let r2 = chain.revoke(&admin, rp(0x98), None).unwrap();

        let mut store = ControlLogStore::new();
        store.append(r1.bytes.clone()).unwrap();
        let head = store.append(r2.bytes.clone()).unwrap();

        assert_eq!(head.chain_seq, 2);
        // The store's head equals exactly what the chain builder computed.
        assert_eq!(head.head, chain.head());
        assert_eq!(store.head(), head);
    }

    #[test]
    fn rewrite_or_reorder_is_rejected() {
        let mut chain = ControlChain::new();
        let admin = maxsecu_crypto::SigningKey::generate();
        let r1 = chain.revoke(&admin, rp(0x99), None).unwrap();
        let r2 = chain.revoke(&admin, rp(0x98), None).unwrap();

        let mut store = ControlLogStore::new();
        // r2 chains onto r1, but the store is still at GENESIS — its prev_head
        // ≠ current head → no reorder/rewrite admitted.
        assert_eq!(store.append(r2.bytes.clone()), Err(AppendError::NotAppending));
        // r1 appends cleanly; re-appending r1 (prev_head = GENESIS) now also
        // fails — the chain only moves forward.
        store.append(r1.bytes.clone()).unwrap();
        assert_eq!(store.append(r1.bytes.clone()), Err(AppendError::NotAppending));
    }

    #[test]
    fn malformed_record_rejected() {
        let mut store = ControlLogStore::new();
        assert_eq!(store.append(vec![0xFF, 0xFF, 0x00]), Err(AppendError::Malformed));
        assert_eq!(store.append(vec![]), Err(AppendError::Malformed));
    }

    #[test]
    fn records_returns_in_order() {
        let mut chain = ControlChain::new();
        let admin = maxsecu_crypto::SigningKey::generate();
        let r1 = chain.revoke(&admin, rp(0x99), None).unwrap();
        let r2 = chain.revoke(&admin, rp(0x98), None).unwrap();

        let mut store = ControlLogStore::new();
        store.append(r1.bytes.clone()).unwrap();
        store.append(r2.bytes.clone()).unwrap();

        let all = store.records(0, 100);
        assert_eq!(all, vec![(1, r1.bytes.clone()), (2, r2.bytes.clone())]);
        // since_seq + limit window: only the tail after seq 1, capped at 1.
        assert_eq!(store.records(1, 1), vec![(2, r2.bytes.clone())]);
        assert!(store.records(2, 100).is_empty());
    }
}
