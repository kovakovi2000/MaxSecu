//! The global **sink-position** log (DESIGN §11.7/D28, `docs/sink-interface.md`
//! §4, the R27 key-compromise cutoff basis).
//!
//! A single monotonic counter (`next_pos`) is bumped by BOTH a control-log append
//! AND a file-`genesis` anchoring, so the two event kinds live in ONE ordered
//! position space. That makes "was this genesis anchored *before* or *after* that
//! `key_compromise` control record reached the sink?" decidable — the comparison
//! the R27/D28 cutoff (`client-core::download::CompromiseCheck`) makes against a
//! genesis's `genesis_sink_pos`. A backdated forgery cannot retroactively acquire
//! an earlier sink position, regardless of its attacker-chosen `created_at`.
//!
//! This mirrors `server::audit::MemoryAuditSink` field-for-field (the behavioral
//! spec): one `next_pos`, a `control_pos` vector, and a `genesis_pos` map.

use std::collections::HashMap;

/// An append-only log of global sink positions. Control appends and genesis
/// anchors both draw from the single `next_pos` counter, so their positions are
/// directly comparable. Start empty with [`PositionLog::new`].
#[derive(Default)]
pub struct PositionLog {
    /// Next global sink position (bumped on every NEW anchored event).
    next_pos: u64,
    /// Global position of each control append, indexed by `chain_seq - 1`.
    control_pos: Vec<u64>,
    /// Global position at which each file's `genesis` was anchored.
    genesis_pos: HashMap<[u8; 16], u64>,
}

impl PositionLog {
    /// A fresh log at global position 0, with no control appends or anchors.
    pub fn new() -> PositionLog {
        PositionLog::default()
    }

    /// Record a control-log append at the next global position; returns it. Called
    /// once per successful `ControlLogStore::append`, so `control_pos[chain_seq-1]`
    /// is the global position of the `chain_seq`-th appended record.
    pub fn record_control(&mut self) -> u64 {
        let pos = self.next_pos;
        self.next_pos += 1;
        self.control_pos.push(pos);
        pos
    }

    /// Anchor `file_id`'s `genesis` **idempotently**: an already-anchored file keeps
    /// its original position (no counter bump) — append-only, a genesis position
    /// never moves. Returns the existing-or-new position.
    pub fn anchor_genesis(&mut self, file_id: [u8; 16]) -> u64 {
        if let Some(&pos) = self.genesis_pos.get(&file_id) {
            return pos;
        }
        let pos = self.next_pos;
        self.next_pos += 1;
        self.genesis_pos.insert(file_id, pos);
        pos
    }

    /// The global position of the `chain_seq`-th control append (1-based), if any.
    /// Recorded now but not yet routed over HTTP: the client-side R27 cutoff
    /// comparison (a genesis position vs. its `key_compromise` control record's
    /// position) consumes this in the P7.14 capstone, which adds the read route.
    pub fn control_pos(&self, chain_seq: u64) -> Option<u64> {
        chain_seq
            .checked_sub(1)
            .and_then(|i| self.control_pos.get(i as usize).copied())
    }

    /// The global position at which `file_id`'s `genesis` was anchored, if anchored.
    pub fn genesis_pos(&self, file_id: &[u8; 16]) -> Option<u64> {
        self.genesis_pos.get(file_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_genesis_share_one_ordered_space() {
        // Mirrors `MemoryAuditSink`'s spec test: a genesis anchored AFTER a control
        // append has a strictly higher global position.
        let mut log = PositionLog::new();
        let c1 = log.record_control(); // control append #1
        let g = log.anchor_genesis([0xF1; 16]); // a file created after it

        assert_eq!(c1, 0, "first event takes position 0");
        assert_eq!(log.control_pos(1), Some(0));
        assert!(g > c1, "genesis anchored after the control append");
        assert_eq!(log.genesis_pos(&[0xF1; 16]), Some(g));
        assert!(
            log.genesis_pos(&[0x00; 16]).is_none(),
            "an un-anchored file has no position"
        );
    }

    #[test]
    fn anchoring_is_idempotent() {
        let mut log = PositionLog::new();
        let first = log.anchor_genesis([0xAB; 16]);
        // Intervening control append draws the next position …
        let _ = log.record_control();
        // … but re-anchoring the same file returns its ORIGINAL position (no bump).
        let again = log.anchor_genesis([0xAB; 16]);
        assert_eq!(first, again, "a genesis position never moves");
        // A different file gets a fresh, later position.
        let other = log.anchor_genesis([0xCD; 16]);
        assert!(other > first);
    }
}
