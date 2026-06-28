//! axum HTTP control-log surface for the external sink (`docs/sink-interface.md`
//! §3). JSON in/out; signed record bytes ride as base64 `_b64` fields.
//!
//! The sink enforces ONLY append-only ordering (§6.1) — it never verifies record
//! signatures (clients do, §5 step 4). Each successful append re-anchors the new
//! head so [`head`] always serves the CURRENT head with BOTH anchor-proof forms
//! (custodian co-signature + RFC 6962 transparency inclusion), exactly what
//! `client-core::sink::verify_anchor_proof` accepts.
//!
//! Writes are gated by a coarse admin credential (a shared bearer secret, §6.1):
//! a compromised app server cannot rewrite/reorder the sink and cannot forge
//! admin-signed records — the worst it can do is fail to write.

use std::sync::Arc;

use axum::extract::{Json, Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::anchor::{AnchorBundle, AnchorProofParts, Anchorer};
use crate::chain::{AnchoredHead, AppendError, ControlLogStore};
use crate::position::PositionLog;

/// The sink's mutable state, behind one async mutex: the append-only record store
/// and the anchorer that re-publishes the head on every append. Cloneable (an
/// `Arc` bump) for axum.
#[derive(Clone)]
pub struct SinkState {
    inner: Arc<Mutex<Inner>>,
    /// The admin bearer secret authorizing appends (§6.1). Held behind an `Arc`
    /// so the state stays cheap to clone.
    admin_token: Arc<String>,
}

struct Inner {
    store: ControlLogStore,
    anchorer: Anchorer,
    /// The bundle for the CURRENT head — refreshed on each successful append, so a
    /// head fetch never re-derives a proof and always matches `store.head()`.
    current: AnchorBundle,
    head: AnchoredHead,
    /// Global sink positions for control appends + file-genesis anchors, drawn
    /// from ONE counter so the R27/D28 cutoff can order them (`position`).
    positions: PositionLog,
}

impl SinkState {
    /// Build the sink state over a fresh store and the given anchorer, anchoring
    /// the genesis (empty-chain) head up front so `GET …/head` works before any
    /// append. `admin_token` is the bearer secret required to append.
    pub fn new(mut anchorer: Anchorer, admin_token: impl Into<String>) -> SinkState {
        let store = ControlLogStore::new();
        let head = store.head();
        let current = anchorer.anchor(head);
        SinkState {
            inner: Arc::new(Mutex::new(Inner {
                store,
                anchorer,
                current,
                head,
                positions: PositionLog::new(),
            })),
            admin_token: Arc::new(admin_token.into()),
        }
    }
}

/// The sink control-log routes (`sink-interface.md` §3) plus the genesis-anchor
/// routes (§4, R27/D28 cutoff basis). `head`/`records`/`anchor-log` and the
/// genesis-position read are public; `POST records` and `POST genesis-anchor`
/// require the admin bearer.
pub fn router(state: SinkState) -> Router {
    Router::new()
        .route("/v1/control-log/head", get(head))
        .route(
            "/v1/control-log/records",
            get(get_records).post(post_record),
        )
        .route("/v1/control-log/anchor-log", get(anchor_log))
        .route("/v1/genesis-anchor", post(post_genesis_anchor))
        .route("/v1/genesis-anchor/{file_id}", get(get_genesis_anchor))
        .with_state(state)
}

// ---- wire shapes ----

#[derive(Serialize)]
struct TransparencyJson {
    checkpoint_sig_b64: String,
    tree_size: u64,
    root_b64: String,
    index: u64,
    path_b64: Vec<String>,
}

/// The §2 anchored head plus BOTH anchor-proof forms for the current head.
#[derive(Serialize)]
struct HeadJson {
    chain_seq: u64,
    head_b64: String,
    cosig_b64: String,
    transparency: TransparencyJson,
}

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

/// The coarse admin gate (§6.1): the request must carry `Authorization: Bearer
/// <admin_token>`. Used by every mutating route (control-log append + genesis
/// anchor) so the strip-prefix + compare lives in one place.
fn admin_ok(headers: &axum::http::HeaderMap, token: &str) -> bool {
    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        == Some(token)
}

/// Render an anchored head + its bundle into the §3.1 head JSON. The bundle MUST
/// be the one produced for exactly this head (its transparency leaf is `head`).
fn head_json(head: AnchoredHead, bundle: &AnchorBundle) -> HeadJson {
    let cosig_b64 = match &bundle.cosig {
        AnchorProofParts::CustodianCoSig { sig } => b64(sig),
        // The anchorer always populates `cosig` with the co-signature form; the
        // other arm is unreachable, but we stay total rather than panic.
        AnchorProofParts::TransparencyInclusion { .. } => String::new(),
    };
    let transparency = match &bundle.transparency {
        AnchorProofParts::TransparencyInclusion {
            checkpoint_sig,
            tree_size,
            root,
            index,
            path,
        } => TransparencyJson {
            checkpoint_sig_b64: b64(checkpoint_sig),
            tree_size: *tree_size,
            root_b64: b64(root),
            index: *index,
            path_b64: path.iter().map(|h| b64(h)).collect(),
        },
        AnchorProofParts::CustodianCoSig { .. } => TransparencyJson {
            checkpoint_sig_b64: String::new(),
            tree_size: 0,
            root_b64: String::new(),
            index: 0,
            path_b64: Vec::new(),
        },
    };
    HeadJson {
        chain_seq: head.chain_seq,
        head_b64: b64(&head.head),
        cosig_b64,
        transparency,
    }
}

// ---- GET /v1/control-log/head (§3.1) ----

/// Serve the current anchored head with both anchor-proof forms. The bytes are
/// untrusted by the client, which validates the proof via `verify_anchor_proof`.
async fn head(State(st): State<SinkState>) -> Response {
    let inner = st.inner.lock().await;
    Json(head_json(inner.head, &inner.current)).into_response()
}

// ---- GET /v1/control-log/records?since_seq=&limit= (§3.2) ----

#[derive(Deserialize)]
struct RecordsQuery {
    since_seq: Option<u64>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct RecordJson {
    chain_seq: u64,
    record_b64: String,
}

/// Serve the sink's own copy of the records after `since_seq`, capped at `limit`
/// (default 0 / 1000), so a client can verify the served set against the sink
/// directly (§3.2 — strongest mode).
async fn get_records(State(st): State<SinkState>, Query(q): Query<RecordsQuery>) -> Response {
    let since = q.since_seq.unwrap_or(0);
    let limit = q.limit.unwrap_or(1000).min(10_000);
    let inner = st.inner.lock().await;
    let out: Vec<RecordJson> = inner
        .store
        .records(since, limit)
        .into_iter()
        .map(|(chain_seq, bytes)| RecordJson {
            chain_seq,
            record_b64: b64(&bytes),
        })
        .collect();
    Json(out).into_response()
}

// ---- POST /v1/control-log/records (§6.1) ----

#[derive(Deserialize)]
struct AppendReq {
    record_b64: String,
}

/// Append one canonical control-log record (§6.1). Requires the admin bearer
/// (`Authorization: Bearer <token>`) → else `403`. The sink checks ONLY
/// append-only ordering: a non-appending write (rewrite/reorder/fork) → `409`;
/// undecodable bytes → `400`; success re-anchors and returns the new head.
async fn post_record(
    State(st): State<SinkState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AppendReq>,
) -> Response {
    // Coarse admin gate (§6.1): a constant-shape `403` for missing/bad cred.
    if !admin_ok(&headers, &st.admin_token) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(bytes) = B64.decode(req.record_b64.as_bytes()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut inner = st.inner.lock().await;
    match inner.store.append(bytes) {
        Ok(new_head) => {
            // Re-anchor on each successful append (§6 cadence) so the head fetch
            // always carries a fresh, matching proof bundle.
            let bundle = inner.anchorer.anchor(new_head);
            inner.head = new_head;
            inner.current = bundle;
            // Draw the next GLOBAL sink position so this control append is ordered
            // against genesis anchors (R27/D28 cutoff basis, `position`).
            inner.positions.record_control();
            Json(head_json(inner.head, &inner.current)).into_response()
        }
        Err(AppendError::NotAppending) => StatusCode::CONFLICT.into_response(),
        Err(AppendError::Malformed) => StatusCode::BAD_REQUEST.into_response(),
    }
}

// ---- GET /v1/control-log/anchor-log (§3.3) ----

/// Serve the full anchor history — each anchored head + both proof forms — for
/// auditor reconciliation against the cross-published medium (§3.3). Not on the
/// client hot path.
async fn anchor_log(State(st): State<SinkState>) -> Response {
    let inner = st.inner.lock().await;
    let out: Vec<HeadJson> = inner
        .anchorer
        .anchor_log()
        .iter()
        .map(|(head, bundle)| head_json(*head, bundle))
        .collect();
    Json(out).into_response()
}

// ---- genesis-anchor (R27/D28 cutoff basis, `docs/sink-interface.md` §4) ----

#[derive(Deserialize)]
struct GenesisAnchorReq {
    /// The 16-byte `file_id`, base64 (standard, padded) — matching the `_b64`
    /// wire convention of the control-log routes.
    file_id_b64: String,
}

#[derive(Serialize)]
struct GenesisPositionJson {
    /// The global sink position of this file's genesis (comparable against a
    /// control append's position — the R27 cutoff).
    position: u64,
}

/// Decode a 32-char lowercase/uppercase hex string into a 16-byte `file_id`
/// (path-safe encoding for the GET route); `None` if not exactly 32 hex digits.
fn decode_file_id_hex(s: &str) -> Option<[u8; 16]> {
    let bytes = s.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *o = (hi * 16 + lo) as u8;
    }
    Some(out)
}

// ---- POST /v1/genesis-anchor (§4) ----

/// Anchor a file's `genesis` at the next global sink position (R27/D28). Requires
/// the admin bearer (else `403`); undecodable / non-16-byte `file_id` → `400`.
/// **Idempotent and append-only**: re-anchoring an already-anchored file returns
/// its EXISTING position (no rewrite) so a genesis position never moves.
async fn post_genesis_anchor(
    State(st): State<SinkState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<GenesisAnchorReq>,
) -> Response {
    // Coarse admin gate (§6.1) — same constant-shape `403` as `post_record`.
    if !admin_ok(&headers, &st.admin_token) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(raw) = B64.decode(req.file_id_b64.as_bytes()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(file_id) = <[u8; 16]>::try_from(raw.as_slice()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut inner = st.inner.lock().await;
    let position = inner.positions.anchor_genesis(file_id);
    Json(GenesisPositionJson { position }).into_response()
}

// ---- GET /v1/genesis-anchor/{file_id_hex} (§4) ----

/// Serve the global sink position at which `file_id`'s genesis was anchored, or
/// `404` if the file is not anchored; a malformed (non-hex / wrong-length)
/// `file_id` is `400`. Public read — the position carries no secret.
async fn get_genesis_anchor(State(st): State<SinkState>, Path(file_id_hex): Path<String>) -> Response {
    let Some(file_id) = decode_file_id_hex(&file_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let inner = st.inner.lock().await;
    match inner.positions.genesis_pos(&file_id) {
        Some(position) => Json(GenesisPositionJson { position }).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use maxsecu_admin_core::{ControlChain, RevokeParams, SignedControlRecord};
    use maxsecu_crypto::SigningKey;
    use maxsecu_encoding::types::{FileScope, Id, Timestamp};
    use tower::ServiceExt; // oneshot

    const NOW: Timestamp = Timestamp(1_719_500_000_000);
    const ADMIN_ID: Id = Id([1; 16]);
    const TOKEN: &str = "sink-admin-secret";

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

    fn app() -> Router {
        let anchorer = Anchorer::new(SigningKey::generate(), SigningKey::generate());
        router(SinkState::new(anchorer, TOKEN))
    }

    /// Two genuine, validly-linked records from a real admin-core chain.
    fn two_records() -> (SignedControlRecord, SignedControlRecord) {
        let mut chain = ControlChain::new();
        let admin = SigningKey::generate();
        let r1 = chain.revoke(&admin, rp(0x99), None).unwrap();
        let r2 = chain.revoke(&admin, rp(0x98), None).unwrap();
        (r1, r2)
    }

    async fn send(router: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn post_record_req(token: Option<&str>, record_b64: &str) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri("/v1/control-log/records")
            .header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        let body = serde_json::json!({ "record_b64": record_b64 }).to_string();
        b.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn head_records_and_append_roundtrip() {
        let app = app();
        let (r1, r2) = two_records();

        // Genesis head before any append: chain_seq 0.
        let (st, head) = send(&app, get("/v1/control-log/head")).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(head["chain_seq"].as_u64().unwrap(), 0);

        // Append both records with the admin bearer.
        let (st, _) = send(&app, post_record_req(Some(TOKEN), &B64.encode(&r1.bytes))).await;
        assert_eq!(st, StatusCode::OK);
        let (st, after) = send(&app, post_record_req(Some(TOKEN), &B64.encode(&r2.bytes))).await;
        assert_eq!(st, StatusCode::OK);
        // The append response carries the new head (chain_seq 2).
        assert_eq!(after["chain_seq"].as_u64().unwrap(), 2);
        assert!(!after["cosig_b64"].as_str().unwrap().is_empty());
        assert!(!after["transparency"]["checkpoint_sig_b64"].as_str().unwrap().is_empty());

        // Head endpoint now reflects chain_seq 2.
        let (_st, head) = send(&app, get("/v1/control-log/head")).await;
        assert_eq!(head["chain_seq"].as_u64().unwrap(), 2);

        // Records endpoint serves both records in order.
        let (st, recs) = send(&app, get("/v1/control-log/records")).await;
        assert_eq!(st, StatusCode::OK);
        let arr = recs.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["chain_seq"].as_u64().unwrap(), 1);
        assert_eq!(arr[1]["chain_seq"].as_u64().unwrap(), 2);

        // since_seq window.
        let (_st, recs) = send(&app, get("/v1/control-log/records?since_seq=1&limit=10")).await;
        assert_eq!(recs.as_array().unwrap().len(), 1);

        // anchor-log records each anchored head (genesis + 2 appends = 3).
        let (st, log) = send(&app, get("/v1/control-log/anchor-log")).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(log.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn stale_append_returns_409() {
        let app = app();
        let (r1, _r2) = two_records();
        // First append of r1 (prev_head = GENESIS) succeeds.
        let (st, _) = send(&app, post_record_req(Some(TOKEN), &B64.encode(&r1.bytes))).await;
        assert_eq!(st, StatusCode::OK);
        // Re-posting r1 now has a stale prev_head → append-only rewrite rejected.
        let (st, _) = send(&app, post_record_req(Some(TOKEN), &B64.encode(&r1.bytes))).await;
        assert_eq!(st, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn malformed_append_returns_400() {
        let app = app();
        // Valid base64 but not a canonical control-log record.
        let (st, _) = send(&app, post_record_req(Some(TOKEN), &B64.encode([0xFF, 0xFF, 0x00]))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Not even base64.
        let (st, _) = send(&app, post_record_req(Some(TOKEN), "@@not-base64@@")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_cred_returns_403() {
        let app = app();
        let (r1, _r2) = two_records();
        // No bearer → 403.
        let (st, _) = send(&app, post_record_req(None, &B64.encode(&r1.bytes))).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        // Wrong bearer → 403.
        let (st, _) = send(&app, post_record_req(Some("wrong"), &B64.encode(&r1.bytes))).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    fn hex16(id: &[u8; 16]) -> String {
        id.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn post_genesis_req(token: Option<&str>, file_id_b64: &str) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri("/v1/genesis-anchor")
            .header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        let body = serde_json::json!({ "file_id_b64": file_id_b64 }).to_string();
        b.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn genesis_anchor_records_global_ordered_position() {
        let app = app();
        let f1 = [0xF1u8; 16];
        let f2 = [0xF2u8; 16];
        let (r1, _r2) = two_records();

        // An un-anchored file → 404.
        let (st, _) = send(&app, get(&format!("/v1/genesis-anchor/{}", hex16(&f1)))).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Anchor f1 (global event #0).
        let (st, body) = send(&app, post_genesis_req(Some(TOKEN), &B64.encode(f1))).await;
        assert_eq!(st, StatusCode::OK);
        let p1 = body["position"].as_u64().unwrap();

        // A control append draws the NEXT global position (between the two anchors).
        let (st, _) = send(&app, post_record_req(Some(TOKEN), &B64.encode(&r1.bytes))).await;
        assert_eq!(st, StatusCode::OK);

        // Anchor f2 AFTER the control append → strictly higher position; the
        // control append consumed exactly one position between them.
        let (st, body) = send(&app, post_genesis_req(Some(TOKEN), &B64.encode(f2))).await;
        assert_eq!(st, StatusCode::OK);
        let p2 = body["position"].as_u64().unwrap();
        assert!(p2 > p1, "genesis after control append has a higher global position");
        assert_eq!(p2, p1 + 2, "the intervening control append consumed one position");

        // GET reflects the anchored positions.
        let (st, body) = send(&app, get(&format!("/v1/genesis-anchor/{}", hex16(&f1)))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["position"].as_u64().unwrap(), p1);

        // Idempotent: re-anchoring f1 returns its ORIGINAL position (no rewrite).
        let (st, body) = send(&app, post_genesis_req(Some(TOKEN), &B64.encode(f1))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["position"].as_u64().unwrap(), p1);
    }

    #[tokio::test]
    async fn genesis_anchor_admin_gated_and_input_validated() {
        let app = app();
        let f1 = [0x0Au8; 16];
        // Missing / wrong bearer → 403 (same shape as the control route).
        let (st, _) = send(&app, post_genesis_req(None, &B64.encode(f1))).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let (st, _) = send(&app, post_genesis_req(Some("wrong"), &B64.encode(f1))).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        // Non-16-byte / undecodable file_id → 400.
        let (st, _) = send(&app, post_genesis_req(Some(TOKEN), &B64.encode([0x01, 0x02, 0x03]))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = send(&app, post_genesis_req(Some(TOKEN), "@@not-base64@@")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Malformed hex in the GET path → 400.
        let (st, _) = send(&app, get("/v1/genesis-anchor/not-hex")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
}
