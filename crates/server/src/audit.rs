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
use maxsecu_crypto::sha256;
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
/// sharing-graph grant edges (`record_grant_edge`, Phase 4) and — for Phase 5/6 —
/// the **appended control-log record bytes** the server publishes on each append
/// (`publish_control_record`, api.md §7.2/§6) and the **genesis anchoring**
/// position used by the R27 cutoff (`anchor_genesis`, §11.7/D28). The real sink
/// derives the head itself (`sha256(canonical(record))`, mirroring
/// `sink-server::ControlLogStore::append`), so the seam carries the RECORD bytes,
/// not a pre-computed head. Record/genesis emission default to no-ops so existing
/// sinks (e.g. [`NullAuditSink`]) need not change. Best-effort, infallible from
/// the caller — the durable authority is the external sink, and the *fail-closed*
/// gate is the issuer-side `confirm_anchored` (client-core), not this publish.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record_grant_edge(&self, edge: GrantEdge);
    /// Publish the appended control-log record to the external sink, which
    /// re-derives the new head `sha256(canonical(record))` (§6 of `sink-interface`).
    async fn publish_control_record(&self, _record_bytes: Vec<u8>) {}
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

    async fn publish_control_record(&self, record_bytes: Vec<u8>) {
        // Mirror the real sink: the head is the record's own digest. Tracking is
        // otherwise unchanged, so the R27 accessors (`control_pos`/`latest_head`)
        // keep their meaning.
        let head = sha256(&record_bytes);
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

/// A real [`AuditSink`] that PUBLISHES each appended control-log record to the
/// independent external sink over its OWN pinned TLS identity (the sink's
/// `POST /v1/control-log/records`, `sink-interface.md` §6.1) and ANCHORS each
/// file's `genesis` at a global sink position there (`POST /v1/genesis-anchor`,
/// §4 — the R27/D28 cutoff basis, real as of P7.8). The sink derives the head
/// itself; we ship only the canonical record bytes.
///
/// Publication is **best-effort and infallible from the caller** (matching the
/// seam contract above): a publish failure never denies the admin's append at the
/// app server. The *authoritative*, fail-closed gate is the issuer-side
/// `confirm_anchored` (client-core) — a server that appended but failed to publish
/// is caught there, closing write-time withholding (§6: a server that refuses to
/// publish can only DENY, never forge or hide a revocation).
///
/// The publisher is async and runs inside the server runtime, so it does async
/// HTTP DIRECTLY (async hyper over tokio-rustls, mirroring the app server's own
/// transport) — it must NOT drive the sync `HttpSinkClient` (nested-runtime panic).
/// It reuses the SAME TLS/HTTP stack (aws-lc-rs) the app server already depends on
/// — no second TLS stack.
pub struct HttpSinkPublisher {
    addr: std::net::SocketAddr,
    server_name: String,
    tls: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
    /// The sink's coarse admin bearer secret (§6.1).
    admin_token: String,
}

impl HttpSinkPublisher {
    /// Build a publisher targeting the sink at `addr`, presenting `server_name`
    /// for TLS verification against the pinned `tls` config (which holds the
    /// sink's pinned root). `admin_token` is the bearer secret the sink requires
    /// to append. `addr`/`server_name` are split so a loopback test can dial an
    /// ephemeral port while still validating the cert's `localhost` SAN.
    pub fn new(
        addr: std::net::SocketAddr,
        server_name: impl Into<String>,
        tls: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
        admin_token: impl Into<String>,
    ) -> HttpSinkPublisher {
        HttpSinkPublisher {
            addr,
            server_name: server_name.into(),
            tls,
            admin_token: admin_token.into(),
        }
    }

    /// The shared best-effort POST dance over the sink's pinned TLS channel: TCP
    /// connect → TLS 1.3 with the pinned config → http1 handshake → POST `path`
    /// with the admin Bearer + JSON `body` → drain. Returns `Err(())` on ANY
    /// transport/HTTP failure — the caller swallows it (best-effort), so no
    /// internal detail escapes. The per-route wrappers below only build the body.
    async fn post_json(&self, path: &str, body: String) -> Result<(), ()> {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let tcp = tokio::net::TcpStream::connect(self.addr)
            .await
            .map_err(|_| ())?;
        let connector = TlsConnector::from(self.tls.clone());
        let server_name = ServerName::try_from(self.server_name.clone()).map_err(|_| ())?;
        let tls = connector.connect(server_name, tcp).await.map_err(|_| ())?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = hyper::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", self.server_name.as_str())
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.admin_token))
            .body(Full::<Bytes>::from(body))
            .map_err(|_| ())?;
        let resp = sender.send_request(req).await.map_err(|_| ())?;
        let ok = resp.status().is_success();
        // Drain so the connection task can finish cleanly.
        let _ = resp.into_body().collect().await;
        if ok {
            Ok(())
        } else {
            Err(())
        }
    }

    /// `POST /v1/control-log/records {record_b64}` (admin bearer). Best-effort,
    /// infallible from the caller (see [`Self::post_json`]).
    async fn post_record(&self, record_bytes: &[u8]) -> Result<(), ()> {
        use base64::Engine;
        let record_b64 = base64::engine::general_purpose::STANDARD.encode(record_bytes);
        let body = serde_json::json!({ "record_b64": record_b64 }).to_string();
        self.post_json("/v1/control-log/records", body).await
    }

    /// `POST /v1/genesis-anchor {file_id_b64}` (admin bearer) — anchoring
    /// `file_id`'s genesis at a global sink position (the R27/D28 cutoff basis,
    /// `sink-interface.md` §4). The sink is idempotent: re-anchoring returns the
    /// existing position. Best-effort, infallible from the caller (see
    /// [`Self::post_json`]).
    async fn post_genesis(&self, file_id: &[u8; 16]) -> Result<(), ()> {
        use base64::Engine;
        let file_id_b64 = base64::engine::general_purpose::STANDARD.encode(file_id);
        let body = serde_json::json!({ "file_id_b64": file_id_b64 }).to_string();
        self.post_json("/v1/genesis-anchor", body).await
    }
}

#[async_trait]
impl AuditSink for HttpSinkPublisher {
    /// Grant-edge publication to the real sink is out of scope here (Phase 4 seam);
    /// no-op for now.
    async fn record_grant_edge(&self, _edge: GrantEdge) {}

    async fn publish_control_record(&self, record_bytes: Vec<u8>) {
        // Best-effort: a failed publish must not deny the append. The fail-closed
        // authority is the issuer-side `confirm_anchored`.
        let _ = self.post_record(&record_bytes).await;
    }

    /// Anchor a file's `genesis` at a global sink position over the REAL sink
    /// (`POST /v1/genesis-anchor`, `sink-interface.md` §4) — the R27/D28 cutoff
    /// basis. Best-effort and infallible from the caller: a failed anchor must not
    /// deny the upload; a client that cannot establish a genesis's sink position
    /// under an active key-compromise fails closed on download (D28), so a missed
    /// anchor degrades safely. (P7.8 — was a no-op through Phase 6.)
    async fn anchor_genesis(&self, file_id: [u8; 16]) {
        let _ = self.post_genesis(&file_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_sink_records_head_and_genesis_positions() {
        let s = MemoryAuditSink::new();
        let record = vec![0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF]; // opaque control bytes
        s.publish_control_record(record.clone()).await; // control append #1
        s.anchor_genesis([0xF1; 16]).await; // a file created after it

        // The latest anchored head is the record's own digest (mirroring the real
        // sink); chain_seq counts appends.
        let (seq, head) = s.latest_head().expect("a head was published");
        assert_eq!(head, sha256(&record));
        assert_eq!(seq, 1);

        // Global sink positions are comparable across event kinds: the genesis was
        // anchored AFTER the control append, so it has a higher sink position.
        let g = s.genesis_pos(&[0xF1; 16]).expect("genesis anchored");
        let c = s.control_pos(1).expect("control #1 position");
        assert!(g > c, "genesis anchored after the control append");
        assert!(s.genesis_pos(&[0x00; 16]).is_none(), "an un-anchored file has no position");
    }
}
