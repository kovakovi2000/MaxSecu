//! The external audit-sink seam for sharing-graph grant edges (DESIGN §16.5,
//! Phase 4).
//!
//! Every `granted_by → recipient` edge — authored at upload, added by a
//! re-share, or denied by a soft-revoke — is emitted here so the **authoritative**
//! grant graph lives off the untrusted app server. The §12.9b step-4 strong-
//! revoke subtree walk is computed from this append-only sink, **not** from the
//! server-served wrap rows (R25): otherwise a malicious server colluding with a
//! descendant could withhold that descendant's edge from a revoking admin while
//! still serving it to rotators/downloaders.
//!
//! This is the **seam**: the real external sink is Phase 6 (`sink-interface.md`).
//! [`MemoryAuditSink`] records edges for tests; the HTTP handlers emit through an
//! injected `Arc<dyn AuditSink>`. Emission is best-effort and infallible from the
//! caller's view — a local mirror failure must not deny a sharing operation
//! (the authoritative durability is the external sink's, §11.4).

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// What happened to a grant edge (sharing-graph audit, §16.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantAction {
    /// A wrap authored at upload/rotation (`granted_by` = the version author).
    Author,
    /// An online read re-share (§12.4b).
    Reshare,
    /// A soft-revoke denial (`granted_by` = the acting caller, §12.8).
    SoftRevoke,
}

/// One sharing-graph edge as recorded to the sink (§16.5). Version-agnostic: the
/// strong-revoke subtree walk (§12.9b) is over the per-file `granted_by` graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantEdge {
    pub file_id: [u8; 16],
    pub granted_by: [u8; 16],
    pub recipient_id: [u8; 16],
    pub action: GrantAction,
    pub at_ms: u64,
}

/// The external append-only sink seam (§16.5, `sink-interface.md`). It carries the
/// sharing-graph grant edges (`record_grant_edge`, Phase 4) and — for Phase 5 —
/// the control-log **head** the server publishes on each append (`publish_head`,
/// api.md §7.2/§6) and the **genesis anchoring** position used by the R27 cutoff
/// (`anchor_genesis`, §11.7/D28). Head/genesis emission default to no-ops so
/// existing sinks (e.g. [`NullAuditSink`]) need not change. Best-effort,
/// infallible from the caller — the durable authority is the external sink.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record_grant_edge(&self, edge: GrantEdge);
    /// Publish the new control-log head after an append (§6 of `sink-interface`).
    async fn publish_head(&self, _head: [u8; 32]) {}
    /// Anchor a file's `genesis` at its current sink position (R27/D28).
    async fn anchor_genesis(&self, _file_id: [u8; 16]) {}
}

/// In-memory sink for tests/e2e — records edges, control-head publishes, and
/// genesis anchorings, assigning each anchored event a **global monotonic sink
/// position** so the R27 cutoff can compare a genesis against a key-compromise.
#[derive(Default)]
pub struct MemoryAuditSink {
    inner: Mutex<SinkState>,
}

#[derive(Default)]
struct SinkState {
    edges: Vec<GrantEdge>,
    /// Next global sink position (incremented on every anchored event).
    next_pos: u64,
    /// The latest published head and the count of appends so far (chain_seq).
    head: Option<(u64, [u8; 32])>,
    /// Global sink position of each control append, indexed by `chain_seq - 1`.
    control_pos: Vec<u64>,
    /// Global sink position of each anchored file genesis.
    genesis_pos: HashMap<[u8; 16], u64>,
}

impl MemoryAuditSink {
    pub fn new() -> MemoryAuditSink {
        MemoryAuditSink::default()
    }

    /// A snapshot of the recorded edges, in emission order.
    pub fn edges(&self) -> Vec<GrantEdge> {
        self.inner.lock().unwrap().edges.clone()
    }

    /// The latest published `(chain_seq, head)`, or `None` if nothing published.
    pub fn latest_head(&self) -> Option<(u64, [u8; 32])> {
        self.inner.lock().unwrap().head
    }

    /// The global sink position of the `chain_seq`-th control append (1-based).
    pub fn control_pos(&self, chain_seq: u64) -> Option<u64> {
        let st = self.inner.lock().unwrap();
        chain_seq
            .checked_sub(1)
            .and_then(|i| st.control_pos.get(i as usize).copied())
    }

    /// The global sink position at which `file_id`'s genesis was anchored.
    pub fn genesis_pos(&self, file_id: &[u8; 16]) -> Option<u64> {
        self.inner.lock().unwrap().genesis_pos.get(file_id).copied()
    }
}

#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn record_grant_edge(&self, edge: GrantEdge) {
        self.inner.lock().unwrap().edges.push(edge);
    }

    async fn publish_head(&self, head: [u8; 32]) {
        let mut st = self.inner.lock().unwrap();
        let pos = st.next_pos;
        st.next_pos += 1;
        st.control_pos.push(pos);
        let chain_seq = st.control_pos.len() as u64;
        st.head = Some((chain_seq, head));
    }

    async fn anchor_genesis(&self, file_id: [u8; 16]) {
        let mut st = self.inner.lock().unwrap();
        let pos = st.next_pos;
        st.next_pos += 1;
        st.genesis_pos.insert(file_id, pos);
    }
}

/// A sink that drops every edge — for paths/states that do not inspect the audit
/// trail (the seam is still present so the wiring is not conditional).
pub struct NullAuditSink;

#[async_trait]
impl AuditSink for NullAuditSink {
    async fn record_grant_edge(&self, _edge: GrantEdge) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_sink_records_head_and_genesis_positions() {
        let s = MemoryAuditSink::new();
        s.publish_head([0xAB; 32]).await; // control append #1
        s.anchor_genesis([0xF1; 16]).await; // a file created after it

        // The latest anchored head is the published one; chain_seq counts appends.
        let (seq, head) = s.latest_head().expect("a head was published");
        assert_eq!(head, [0xAB; 32]);
        assert_eq!(seq, 1);

        // Global sink positions are comparable across event kinds: the genesis was
        // anchored AFTER the control append, so it has a higher sink position.
        let g = s.genesis_pos(&[0xF1; 16]).expect("genesis anchored");
        let c = s.control_pos(1).expect("control #1 position");
        assert!(g > c, "genesis anchored after the control append");
        assert!(s.genesis_pos(&[0x00; 16]).is_none(), "an un-anchored file has no position");
    }
}
