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

/// Sink for sharing-graph grant edges (§16.5). Best-effort, infallible from the
/// caller — the durable authority is the external sink (Phase 6).
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record_grant_edge(&self, edge: GrantEdge);
}

/// In-memory sink for tests/e2e — records every edge for inspection.
#[derive(Default)]
pub struct MemoryAuditSink {
    edges: Mutex<Vec<GrantEdge>>,
}

impl MemoryAuditSink {
    pub fn new() -> MemoryAuditSink {
        MemoryAuditSink {
            edges: Mutex::new(Vec::new()),
        }
    }

    /// A snapshot of the recorded edges, in emission order.
    pub fn edges(&self) -> Vec<GrantEdge> {
        self.edges.lock().unwrap().clone()
    }
}

#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn record_grant_edge(&self, edge: GrantEdge) {
        self.edges.lock().unwrap().push(edge);
    }
}

/// A sink that drops every edge — for paths/states that do not inspect the audit
/// trail (the seam is still present so the wiring is not conditional).
pub struct NullAuditSink;

#[async_trait]
impl AuditSink for NullAuditSink {
    async fn record_grant_edge(&self, _edge: GrantEdge) {}
}
