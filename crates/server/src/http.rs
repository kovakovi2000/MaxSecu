//! axum HTTP control plane for auth/session (api.md §2). JSON in/out; signed
//! records ride as base64 `_b64` fields (api.md §1.3). Every handler is thin —
//! it decodes, calls the [`AuthService`](crate::auth::AuthService), and maps the
//! single `Unauthorized` to a uniform `401` (no oracle, §3).
//!
//! The per-connection **TLS exporter** is read from a request [`Extension`]
//! inserted by the transport layer (real TLS in `tls.rs`; a fixed value in
//! tests). Handlers never see the socket — only the exporter the connection
//! was bound to (api.md §1.5).

use crate::auth::AuthService;
use crate::error::{AuthError, ChallengeError, ControlAppendError, ProveError};
use crate::files::{
    parse_stage, AddWrapError, DeleteWrapError, FinalizeError, GenesisInput, ListFilter, StageError,
    StageInput, VersionSelector, WrapInput,
};
use crate::audit::{AuditSink, GrantAction, GrantEdge};
use crate::blob::BlobStore;
use crate::store::{FileView, Store};
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::Role;
use maxsecu_encoding::decode;
use axum::extract::{FromRequestParts, Json, Path, Query, State};
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The live connection's TLS exporter (RFC 5705), injected per connection.
#[derive(Clone, Copy)]
pub struct TlsExporter(pub [u8; 32]);

/// Shared handler state. Cloneable (an `Arc` bump) for axum.
pub struct AppState<S: Store> {
    pub auth: Arc<AuthService<S>>,
    /// The ciphertext-chunk tier (api.md §9 / D31). Shared across requests; the
    /// concrete impl (Memory for e2e, FS for the Postgres path) is chosen by the
    /// caller that builds the state.
    pub blobs: Arc<dyn BlobStore>,
    /// The sharing-graph audit-sink seam (§16.5). Handlers emit every
    /// `granted_by → recipient` grant edge here; the real external sink is Phase
    /// 6 (`sink-interface.md`).
    pub audit: Arc<dyn AuditSink>,
}

impl<S: Store> Clone for AppState<S> {
    fn clone(&self) -> Self {
        AppState {
            auth: self.auth.clone(),
            blobs: self.blobs.clone(),
            audit: self.audit.clone(),
        }
    }
}

/// The auth/session routes (api.md §2). The caller wraps this with the
/// per-connection `Extension<TlsExporter>` layer (TLS transport / test).
pub fn router<S: Store + 'static>(state: AppState<S>) -> Router {
    Router::new()
        .route("/v1/users", post(register::<S>))
        .route("/v1/session/challenge", post(challenge::<S>))
        .route("/v1/session/proof", post(prove::<S>))
        .route("/v1/session/logout", post(logout::<S>))
        .route("/v1/directory/by-id/{user_id}", get(directory_by_id::<S>))
        .route("/v1/directory/{username}", get(directory_by_username::<S>))
        .route(
            "/v1/revocations",
            get(get_revocations::<S>).post(post_control::<S>),
        )
        .route("/v1/reinstatements", post(post_control::<S>))
        .route("/v1/key-compromise", post(post_control::<S>))
        .route("/v1/files", get(list_files::<S>).post(create_file::<S>))
        .route("/v1/files/{file_id}", get(get_file::<S>))
        .route(
            "/v1/files/{file_id}/recipients",
            get(list_recipients::<S>),
        )
        .route(
            "/v1/files/{file_id}/wraps",
            post(add_wrap::<S>),
        )
        .route(
            "/v1/files/{file_id}/wraps/{recipient_id}",
            delete(delete_wrap::<S>),
        )
        .route("/v1/files/{file_id}/versions", post(stage_version::<S>))
        .route(
            "/v1/files/{file_id}/versions/{v}/finalize",
            post(finalize_version::<S>),
        )
        .route(
            "/v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}",
            put(put_chunk::<S>).get(get_chunk::<S>),
        )
        .with_state(state)
}

/// Uniform `429 Too Many Requests` + `Retry-After: <seconds>` for a throttled
/// request (parameters §3). The only response shape distinct from the single
/// `401` auth-failure shape (no oracle, §9.3).
fn rate_limited(retry_after_s: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(RETRY_AFTER, retry_after_s.to_string())],
    )
        .into_response()
}

/// Log a backend-fault cause **server-side only** (sanitized errors, §16.2): the
/// detail never reaches a client — the wire response is always a bare `500`.
fn log_internal(e: impl std::fmt::Display) {
    eprintln!("maxsecu: internal error: {e}");
}

/// A backend fault → bare `500`. Distinct from the uniform `401`/`429` auth
/// shapes; because a store fault is credential-independent it is not a
/// user-existence or cause oracle (§9.3 / [`crate::error::StoreError`]).
fn internal_error(e: impl std::fmt::Display) -> Response {
    log_internal(e);
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the Unix epoch")
        .as_millis() as u64
}

fn b64encode(b: &[u8]) -> String {
    B64.encode(b)
}

fn b64_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = B64.decode(s).ok()?;
    v.try_into().ok()
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

// ---- POST /v1/users — voucher-gated enrollment (api.md §5.1) ----

#[derive(Deserialize)]
struct RegisterReq {
    username: String,
    enc_pub_b64: String,
    sig_pub_b64: String,
    enrollment_voucher: String,
}

#[derive(Serialize)]
struct RegisterRes {
    user_id: String, // lowercase hex (api.md §1.4)
}

async fn register<S: Store>(
    State(st): State<AppState<S>>,
    Json(req): Json<RegisterReq>,
) -> Result<(StatusCode, Json<RegisterRes>), StatusCode> {
    let enc_pub = b64_fixed::<32>(&req.enc_pub_b64).ok_or(StatusCode::BAD_REQUEST)?;
    let sig_pub = b64_fixed::<32>(&req.sig_pub_b64).ok_or(StatusCode::BAD_REQUEST)?;
    // Voucher is the anti-spam gate (the trust gate is the in-person ceremony).
    // Consumed first so one voucher buys exactly one creation attempt.
    let voucher_hash = maxsecu_crypto::sha256(req.enrollment_voucher.as_bytes());
    match st.auth.store().consume_voucher(&voucher_hash).await {
        Ok(true) => {}                                                  // gate passed
        Ok(false) => return Err(StatusCode::FORBIDDEN),                 // invalid/used voucher
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),       // backend fault, not "bad voucher"
    }
    match st
        .auth
        .store()
        .create_user(&req.username, enc_pub, sig_pub)
        .await
    {
        Ok(Some(user_id)) => Ok((
            StatusCode::CREATED,
            Json(RegisterRes {
                user_id: hex_encode(&user_id),
            }),
        )),
        Ok(None) => Err(StatusCode::CONFLICT), // username taken
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// ---- POST /v1/session/challenge (api.md §2.1) ----

#[derive(Deserialize)]
struct ChallengeReq {
    username: String,
}

#[derive(Serialize)]
struct ChallengeRes {
    nonce_b64: String,
    server_id: String,
    expires_in_s: u64,
}

async fn challenge<S: Store>(
    State(st): State<AppState<S>>,
    Json(req): Json<ChallengeReq>,
) -> Response {
    // A well-formed challenge is returned for unknown usernames too (§9.3),
    // unless the per-account issuance cap throttles it (429, parameters §3).
    match st.auth.challenge(&req.username, now_ms()).await {
        Ok(ch) => Json(ChallengeRes {
            nonce_b64: b64encode(&ch.nonce),
            server_id: ch.server_id,
            expires_in_s: ch.expires_in_s,
        })
        .into_response(),
        Err(ChallengeError::RateLimited { retry_after_s }) => rate_limited(retry_after_s),
        Err(ChallengeError::Internal(e)) => internal_error(e),
    }
}

// ---- POST /v1/session/proof (api.md §2.2) ----

#[derive(Deserialize)]
struct ProveReq {
    username: String,
    timestamp: u64,
    proof_b64: String,
}

#[derive(Serialize)]
struct ProveRes {
    session_token: String,
    expires_in_s: u64,
}

async fn prove<S: Store>(
    State(st): State<AppState<S>>,
    Extension(exporter): Extension<TlsExporter>,
    Json(req): Json<ProveReq>,
) -> Response {
    let Some(proof) = b64_fixed::<64>(&req.proof_b64) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st
        .auth
        .prove(&req.username, req.timestamp, &proof, &exporter.0, now_ms())
        .await
    {
        Ok(token) => Json(ProveRes {
            session_token: token.to_hex(),
            expires_in_s: 3600,
        })
        .into_response(),
        // Single 401 shape for every auth-failure cause — no oracle (§3) …
        Err(ProveError::Unauthorized) => StatusCode::UNAUTHORIZED.into_response(),
        // … but a throttled attempt is the one deliberately-distinct 429 signal …
        Err(ProveError::RateLimited { retry_after_s }) => rate_limited(retry_after_s),
        // … and a backend fault is a 500 (server health, not an auth decision).
        Err(ProveError::Internal(e)) => internal_error(e),
    }
}

// ---- POST /v1/session/logout (api.md §2.4) ----

async fn logout<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
) -> StatusCode {
    match st.auth.logout(&session.token).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => {
            log_internal(e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// ---- GET /v1/directory/{username} · /v1/directory/by-id/{user_id} (api.md §6.1) ----

#[derive(Serialize)]
struct BindingRes {
    binding_b64: String,            // canonical(dirbinding)
    directory_signature_b64: String, // Ed25519 by the offline D5 key
}

/// Serve a [`StoredBinding`] as the §6.1 body, or `404` if absent. The bytes are
/// opaque — the client verifies them against the pinned root (§7.2); the server
/// is only the transport.
fn binding_response(b: Option<crate::store::StoredBinding>) -> Response {
    match b {
        Some(b) => Json(BindingRes {
            binding_b64: b64encode(&b.binding_bytes),
            directory_signature_b64: b64encode(&b.signature),
        })
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(), // unsigned/pending ⇒ not a recipient
    }
}

async fn directory_by_username<S: Store>(
    State(st): State<AppState<S>>,
    Path(username): Path<String>,
) -> Response {
    match st.auth.store().binding_by_username(&username).await {
        Ok(b) => binding_response(b),
        Err(e) => internal_error(e),
    }
}

async fn directory_by_id<S: Store>(
    State(st): State<AppState<S>>,
    Path(user_id_hex): Path<String>,
) -> Response {
    let Some(user_id) = hex_fixed::<16>(&user_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.auth.store().binding_by_user_id(&user_id).await {
        Ok(b) => binding_response(b),
        Err(e) => internal_error(e),
    }
}

// ---- Revocation control-log (api.md §7) ----

fn b64_vec(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

fn kind_str(kind: i16) -> &'static str {
    match kind {
        6 => "revocation",
        7 => "reinstatement",
        8 => "key_compromise",
        _ => "unknown",
    }
}

#[derive(Serialize)]
struct ControlRecordJson {
    kind: String,
    record_b64: String,
    sig_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    co_sig_b64: Option<String>,
    chain_head_b64: String,
}

#[derive(Serialize)]
struct RevocationsRes {
    records: Vec<ControlRecordJson>,
    next_cursor: Option<String>,
}

/// `GET /v1/revocations` — serve the whole chain in append order (api.md §7.1).
/// The client links each `prev_head` and checks the final head against the
/// sink-anchored head; the server's heads are advisory.
async fn get_revocations<S: Store>(State(st): State<AppState<S>>) -> Response {
    match st.auth.store().control_records().await {
        Ok(records) => Json(RevocationsRes {
            records: records
                .iter()
                .map(|r| ControlRecordJson {
                    kind: kind_str(r.kind).to_owned(),
                    record_b64: b64encode(&r.record_bytes),
                    sig_b64: b64encode(&r.sig),
                    co_sig_b64: r.co_sig.map(|c| b64encode(&c)),
                    chain_head_b64: b64encode(&r.head),
                })
                .collect(),
            next_cursor: None,
        })
        .into_response(),
        Err(e) => internal_error(e),
    }
}

#[derive(Deserialize)]
struct ControlReq {
    record_b64: String,
    sig_b64: String,
    co_sig_b64: Option<String>,
}

#[derive(Serialize)]
struct ChainHeadRes {
    chain_head_b64: String,
}

/// `POST /v1/revocations | /v1/reinstatements | /v1/key-compromise` — append a
/// control-log record (api.md §7.2). **Coarse** admin gate only (§10.1): the
/// authenticated caller must hold the advisory `admin` role; the record's own
/// authenticity (issuer admin-signature, dual control) is re-verified client-side.
/// The record's authenticated `kind` governs — the path is cosmetic.
async fn post_control<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Json(req): Json<ControlReq>,
) -> Response {
    match st.auth.store().user_roles(&session.user_id).await {
        Ok(roles) if roles.contains(&Role::Admin) => {}
        Ok(_) => return StatusCode::FORBIDDEN.into_response(), // not an admin
        Err(e) => return internal_error(e),
    }
    let Some(record) = b64_vec(&req.record_b64) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(sig) = b64_fixed::<64>(&req.sig_b64) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let co_sig = match req.co_sig_b64.as_deref() {
        None => None,
        Some(s) => match b64_fixed::<64>(s) {
            Some(c) => Some(c),
            None => return StatusCode::BAD_REQUEST.into_response(),
        },
    };
    match st.auth.store().append_control(record, sig, co_sig).await {
        Ok(head) => (
            StatusCode::CREATED,
            Json(ChainHeadRes {
                chain_head_b64: b64encode(&head),
            }),
        )
            .into_response(),
        Err(ControlAppendError::Conflict) => StatusCode::CONFLICT.into_response(),
        Err(ControlAppendError::Malformed) => StatusCode::BAD_REQUEST.into_response(),
        Err(ControlAppendError::Store(e)) => internal_error(e),
    }
}

// ---- Files — records (api.md §8) ----

fn file_type_code(s: &str) -> Option<i16> {
    match s {
        "video" => Some(1),
        "image" => Some(2),
        "blog" => Some(3),
        _ => None,
    }
}
fn file_type_name(c: i16) -> &'static str {
    match c {
        1 => "video",
        2 => "image",
        3 => "blog",
        _ => "unknown",
    }
}
fn stream_type_code(s: &str) -> Option<i16> {
    match s {
        "content" => Some(1),
        "metadata" => Some(2),
        "thumbnail" => Some(3),
        "preview" => Some(4),
        _ => None,
    }
}
fn stream_type_name(c: i16) -> &'static str {
    match c {
        1 => "content",
        2 => "metadata",
        3 => "thumbnail",
        4 => "preview",
        _ => "unknown",
    }
}
fn recipient_type_code(s: &str) -> Option<i16> {
    match s {
        "user" => Some(1),
        "recovery" => Some(2),
        _ => None,
    }
}

/// A wrap recipient id: the literal `"recovery"` maps to the all-zero
/// `RECOVERY_ID`; anything else is a hex-16 `user_id` (api.md §1.4).
fn recipient_id(s: &str) -> Option<[u8; 16]> {
    if s == "recovery" {
        Some([0u8; 16])
    } else {
        hex_fixed::<16>(s)
    }
}

#[derive(Deserialize)]
struct StreamReq {
    stream_type: String,
    total_bytes: u64,
    // chunk_count/chunk_size also ride here (api.md §8.1) but the manifest is
    // authoritative; the server reads framing from it, not from these.
}

#[derive(Deserialize)]
struct WrapReq {
    recipient_id: String,
    recipient_type: String,
    wrapped_dek_b64: String,
    wrap_alg: Option<u32>,
    granted_by: String,
    grant_b64: String,
    grant_sig_b64: String,
}

#[derive(Deserialize)]
struct CreateFileReq {
    file_id: String,
    file_type: String,
    genesis_b64: String,
    genesis_sig_b64: String,
    manifest_b64: String,
    manifest_sig_b64: String,
    streams: Vec<StreamReq>,
    wraps: Vec<WrapReq>,
}

#[derive(Deserialize)]
struct StageVersionReq {
    file_type: String,
    manifest_b64: String,
    manifest_sig_b64: String,
    streams: Vec<StreamReq>,
    wraps: Vec<WrapReq>,
}

#[derive(Serialize)]
struct StageRes {
    upload_token: String,
    version: u64,
}

fn build_wraps(reqs: &[WrapReq]) -> Option<Vec<WrapInput>> {
    reqs.iter()
        .map(|w| {
            Some(WrapInput {
                recipient_id: recipient_id(&w.recipient_id)?,
                recipient_type: recipient_type_code(&w.recipient_type)?,
                wrapped_dek: b64_vec(&w.wrapped_dek_b64)?,
                wrap_alg: w.wrap_alg.unwrap_or(1) as i32,
                granted_by: hex_fixed::<16>(&w.granted_by)?,
                grant_bytes: b64_vec(&w.grant_b64)?,
                grant_sig: b64_fixed::<64>(&w.grant_sig_b64)?,
            })
        })
        .collect()
}

fn build_stream_totals(reqs: &[StreamReq]) -> Option<Vec<(i16, u64)>> {
    reqs.iter()
        .map(|s| Some((stream_type_code(&s.stream_type)?, s.total_bytes)))
        .collect()
}

/// The `upload_token` scoping the chunk PUTs (api.md §8.1/§9.1). In P3.6 it
/// echoes `(file_id, version)`; P3.7 binds it to the staged blob slots.
fn upload_token(file_id: &[u8; 16], version: u64) -> String {
    format!("{}.{version}", hex_encode(file_id))
}

/// Map a stage rejection to its HTTP status (api.md §8.1: 400/413 bounds; 403
/// non-owner; 404 unknown file; 409 already finalized; 500 backend fault).
fn stage_status(e: StageError) -> Response {
    use StageError::*;
    match e {
        SizeBoundExceeded => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        NotOwner => StatusCode::FORBIDDEN.into_response(),
        NoSuchFile => StatusCode::NOT_FOUND.into_response(),
        AlreadyFinalized => StatusCode::CONFLICT.into_response(),
        Store(e) => internal_error(e),
        // Every remaining cause is a malformed/inconsistent request.
        BadManifest | BadGenesis | FileIdMismatch | ChunkSizeOutOfRange | MissingRecoveryWrap
        | VersionMismatch | GenesisRequired | GenesisUnexpected => {
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

/// `POST /v1/files` — stage version 1 of a new file (api.md §8.1).
async fn create_file<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Json(req): Json<CreateFileReq>,
) -> Response {
    let (Some(file_id), Some(file_type)) =
        (hex_fixed::<16>(&req.file_id), file_type_code(&req.file_type))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Some(manifest_bytes), Some(manifest_sig), Some(genesis_bytes), Some(genesis_sig)) = (
        b64_vec(&req.manifest_b64),
        b64_fixed::<64>(&req.manifest_sig_b64),
        b64_vec(&req.genesis_b64),
        b64_fixed::<64>(&req.genesis_sig_b64),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Some(wraps), Some(stream_totals)) =
        (build_wraps(&req.wraps), build_stream_totals(&req.streams))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let input = StageInput {
        file_id,
        caller_id: session.user_id,
        file_type_advisory: file_type,
        genesis: Some(GenesisInput {
            genesis_bytes,
            genesis_sig,
        }),
        manifest_bytes,
        manifest_sig,
        wraps,
        stream_totals,
        proposed_version: 1, // POST /v1/files is the version-1 endpoint
    };
    stage_and_respond(&st, input).await
}

/// `POST /v1/files/{file_id}/versions` — stage a rotation (api.md §8.2).
async fn stage_version<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path(file_id_hex): Path<String>,
    Json(req): Json<StageVersionReq>,
) -> Response {
    let (Some(file_id), Some(file_type)) = (
        hex_fixed::<16>(&file_id_hex),
        file_type_code(&req.file_type),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Some(manifest_bytes), Some(manifest_sig)) = (
        b64_vec(&req.manifest_b64),
        b64_fixed::<64>(&req.manifest_sig_b64),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Some(wraps), Some(stream_totals)) =
        (build_wraps(&req.wraps), build_stream_totals(&req.streams))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // The client proposes the version inside the manifest (api.md §8.2); read it
    // back so parse_stage's proposed==manifest check is consistent.
    let proposed_version = decode::<Manifest>(&manifest_bytes)
        .map(|m| m.version)
        .unwrap_or(0);
    let input = StageInput {
        file_id,
        caller_id: session.user_id,
        file_type_advisory: file_type,
        genesis: None,
        manifest_bytes,
        manifest_sig,
        wraps,
        stream_totals,
        proposed_version,
    };
    stage_and_respond(&st, input).await
}

async fn stage_and_respond<S: Store>(st: &AppState<S>, input: StageInput) -> Response {
    let file_id = input.file_id;
    let parsed = match parse_stage(input) {
        Ok(p) => p,
        Err(e) => return stage_status(e),
    };
    // Capture the authored grant edges (upload + rotation carry-forward) before
    // the parse is consumed; emit them to the sink on a successful stage (§16.5).
    let edges: Vec<([u8; 16], [u8; 16])> = parsed
        .wraps
        .iter()
        .map(|w| (w.granted_by, w.recipient_id))
        .collect();
    match st.auth.store().stage_version(parsed, now_ms()).await {
        Ok(version) => {
            let now = now_ms();
            for (granted_by, recipient_id) in edges {
                st.audit
                    .record_grant_edge(GrantEdge {
                        file_id,
                        granted_by,
                        recipient_id,
                        action: GrantAction::Author,
                        at_ms: now,
                    })
                    .await;
            }
            (
                StatusCode::CREATED,
                Json(StageRes {
                    upload_token: upload_token(&file_id, version),
                    version,
                }),
            )
                .into_response()
        }
        Err(e) => stage_status(e),
    }
}

/// `POST /v1/files/{file_id}/versions/{v}/finalize` — atomic commit (api.md §8.4).
/// Verifies every stream received exactly its `chunk_count` chunks before the
/// commit, then (on success) deletes the prior version's chunks (api.md §8.4 /
/// §12.9 — its DB streams/wraps are dropped by `finalize_version`).
async fn finalize_version<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path((file_id_hex, version)): Path<(String, u64)>,
) -> Response {
    let Some(file_id) = hex_fixed::<16>(&file_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // Completeness: each staged stream must hold exactly chunk_count chunks.
    let meta = match st.auth.store().version_meta(file_id, version).await {
        Ok(Some(m)) => m,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return internal_error(e),
    };
    for s in &meta.streams {
        match st.blobs.chunk_count(&s.blob_ref).await {
            Ok(got) if got == s.chunk_count => {}
            Ok(_) => return StatusCode::BAD_REQUEST.into_response(), // incomplete stream
            Err(e) => return internal_error(e),
        }
    }
    // Capture the prior version's blob_refs before the commit drops its DB rows.
    let prior_refs: Vec<String> = if version >= 2 {
        match st.auth.store().version_meta(file_id, version - 1).await {
            Ok(Some(m)) => m.streams.into_iter().map(|s| s.blob_ref).collect(),
            Ok(None) => Vec::new(),
            Err(e) => return internal_error(e),
        }
    } else {
        Vec::new()
    };

    match st
        .auth
        .store()
        .finalize_version(file_id, version, session.user_id, now_ms())
        .await
    {
        Ok(()) => {
            // Best-effort prior-chunk teardown; the commit already stands, so a
            // blob-delete fault is logged, not surfaced (it leaves only dead bytes).
            for r in &prior_refs {
                if let Err(e) = st.blobs.delete_stream(r).await {
                    log_internal(e);
                }
            }
            StatusCode::OK.into_response()
        }
        Err(FinalizeError::NotOwner) => StatusCode::FORBIDDEN.into_response(),
        Err(FinalizeError::NoSuchVersion) => StatusCode::NOT_FOUND.into_response(),
        Err(FinalizeError::VersionConflict { .. }) | Err(FinalizeError::AlreadyFinalized) => {
            StatusCode::CONFLICT.into_response()
        }
        Err(FinalizeError::Store(e)) => internal_error(e),
    }
}

/// Per-chunk AEAD overhead (the 128-bit GCM tag, parameters §1.2): a ciphertext
/// chunk is at most `chunk_size` plaintext + this tag.
const AEAD_TAG_LEN: u64 = 16;

/// `PUT /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}` —
/// upload one ciphertext chunk (api.md §9.1). Owner-only (D29); idempotent by
/// index; `409` once finalized; `413` over the bound.
async fn put_chunk<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path((file_id_hex, version, stream_type, index)): Path<(String, u64, String, u64)>,
    body: axum::body::Bytes,
) -> Response {
    let (Some(file_id), Some(stype)) =
        (hex_fixed::<16>(&file_id_hex), stream_type_code(&stream_type))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let meta = match st.auth.store().version_meta(file_id, version).await {
        Ok(Some(m)) => m,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return internal_error(e),
    };
    if meta.owner_id != session.user_id {
        return StatusCode::FORBIDDEN.into_response(); // only the owner writes chunks
    }
    if meta.finalized {
        return StatusCode::CONFLICT.into_response(); // immutable after finalize
    }
    let Some(slot) = meta.streams.iter().find(|s| s.stream_type == stype) else {
        return StatusCode::NOT_FOUND.into_response(); // no such stream in this version
    };
    if index >= slot.chunk_count {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response(); // index past the framing
    }
    if body.len() as u64 > slot.chunk_size as u64 + AEAD_TAG_LEN {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response(); // oversized chunk
    }
    match st.blobs.put_chunk(&slot.blob_ref, index, body.to_vec()).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => internal_error(e),
    }
}

/// `GET /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}` —
/// download one ciphertext chunk (api.md §9.2). Gated like §8.5: the owner, or a
/// recipient of a finalized version; otherwise `404` (no oracle).
async fn get_chunk<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path((file_id_hex, version, stream_type, index)): Path<(String, u64, String, u64)>,
) -> Response {
    let (Some(file_id), Some(stype)) =
        (hex_fixed::<16>(&file_id_hex), stream_type_code(&stream_type))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let meta = match st.auth.store().version_meta(file_id, version).await {
        Ok(Some(m)) => m,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return internal_error(e),
    };
    // Access: the owner always; otherwise only a recipient of a *finalized*
    // version (a wrap row exists) — exactly the §8.5 gate, reused.
    let allowed = meta.owner_id == session.user_id
        || match st
            .auth
            .store()
            .get_file(file_id, VersionSelector::Specific(version), session.user_id)
            .await
        {
            Ok(opt) => opt.is_some(),
            Err(e) => return internal_error(e),
        };
    if !allowed {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(slot) = meta.streams.iter().find(|s| s.stream_type == stype) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match st.blobs.get_chunk(&slot.blob_ref, index).await {
        Ok(Some(bytes)) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => internal_error(e),
    }
}

#[derive(Deserialize)]
struct GetFileQuery {
    version: Option<String>,
}

#[derive(Serialize)]
struct StreamOut {
    stream_type: String,
    chunk_count: u64,
    chunk_size: u32,
    blob_ref: String,
}

#[derive(Serialize)]
struct WrapOut {
    wrapped_dek_b64: String,
    grant_b64: String,
    grant_sig_b64: String,
    ancestor_grants: Vec<serde_json::Value>, // re-share chain to author (api.md §8.5)
}

#[derive(Serialize)]
struct RecoveryGrantOut {
    grant_b64: String,
    grant_sig_b64: String,
}

#[derive(Serialize)]
struct FileRes {
    version: u64,
    manifest_b64: String,
    manifest_sig_b64: String,
    genesis_b64: String,
    genesis_sig_b64: String,
    my_wrap: WrapOut,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_grant: Option<RecoveryGrantOut>,
    streams: Vec<StreamOut>,
}

fn file_view_to_res(v: FileView) -> FileRes {
    FileRes {
        version: v.version,
        manifest_b64: b64encode(&v.manifest_bytes),
        manifest_sig_b64: b64encode(&v.manifest_sig),
        genesis_b64: b64encode(&v.genesis_bytes),
        genesis_sig_b64: b64encode(&v.genesis_sig),
        my_wrap: WrapOut {
            wrapped_dek_b64: b64encode(&v.my_wrap.wrapped_dek),
            grant_b64: b64encode(&v.my_wrap.grant_bytes),
            grant_sig_b64: b64encode(&v.my_wrap.grant_sig),
            ancestor_grants: v
                .my_wrap
                .ancestor_grants
                .iter()
                .map(|(b, s)| {
                    serde_json::json!({
                        "grant_b64": b64encode(b),
                        "grant_sig_b64": b64encode(s),
                    })
                })
                .collect(),
        },
        recovery_grant: v.recovery_grant.map(|(b, s)| RecoveryGrantOut {
            grant_b64: b64encode(&b),
            grant_sig_b64: b64encode(&s),
        }),
        streams: v
            .streams
            .iter()
            .map(|s| StreamOut {
                stream_type: stream_type_name(s.stream_type).to_owned(),
                chunk_count: s.chunk_count,
                chunk_size: s.chunk_size,
                blob_ref: s.blob_ref.clone(),
            })
            .collect(),
    }
}

/// `GET /v1/files/{file_id}?version=<v|latest>` (api.md §8.5). `404` for both a
/// missing file/version and a caller with no wrap — no access oracle.
async fn get_file<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path(file_id_hex): Path<String>,
    Query(q): Query<GetFileQuery>,
) -> Response {
    let Some(file_id) = hex_fixed::<16>(&file_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let selector = match q.version.as_deref() {
        None | Some("latest") => VersionSelector::Latest,
        Some(v) => match v.parse::<u64>() {
            Ok(n) => VersionSelector::Specific(n),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        },
    };
    match st
        .auth
        .store()
        .get_file(file_id, selector, session.user_id)
        .await
    {
        Ok(Some(view)) => Json(file_view_to_res(view)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => internal_error(e),
    }
}

/// `POST /v1/files/{file_id}/wraps` — online read re-share (api.md §10.1). The
/// body is one wrap row (`granted_by` = the caller, the current wrap holder).
/// `201` on success; `400` malformed/inconsistent; `404` no such file or the
/// caller holds no wrap (no oracle); `500` backend fault. The wrap bytes are
/// inert — the recipient re-verifies the grant chain (§12.5/P4.1).
async fn add_wrap<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path(file_id_hex): Path<String>,
    Json(req): Json<WrapReq>,
) -> Response {
    let Some(file_id) = hex_fixed::<16>(&file_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(wrap) = build_wraps(std::slice::from_ref(&req)).and_then(|mut v| v.pop()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (granted_by, recipient_id) = (wrap.granted_by, wrap.recipient_id);
    match st
        .auth
        .store()
        .add_wrap(file_id, wrap, session.user_id, now_ms())
        .await
    {
        Ok(()) => {
            // §16.5: record the re-share grant edge to the (external) audit sink.
            st.audit
                .record_grant_edge(GrantEdge {
                    file_id,
                    granted_by,
                    recipient_id,
                    action: GrantAction::Reshare,
                    at_ms: now_ms(),
                })
                .await;
            StatusCode::CREATED.into_response()
        }
        Err(AddWrapError::BadRequest) => StatusCode::BAD_REQUEST.into_response(),
        Err(AddWrapError::NoAccess) => StatusCode::NOT_FOUND.into_response(),
        Err(AddWrapError::Store(e)) => internal_error(e),
    }
}

/// `DELETE /v1/files/{file_id}/wraps/{recipient_id}` — soft revoke (api.md
/// §10.2). Server-side denial only (§12.8). `204` on success; `403` if the
/// caller is neither owner nor the wrap's granter; `404` if absent; `500` fault.
async fn delete_wrap<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path((file_id_hex, recipient_hex)): Path<(String, String)>,
) -> Response {
    let Some(file_id) = hex_fixed::<16>(&file_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(recipient) = hex_fixed::<16>(&recipient_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st
        .auth
        .store()
        .delete_wrap(file_id, recipient, session.user_id)
        .await
    {
        Ok(()) => {
            // §16.5: record the soft-revoke edge (granted_by = the acting caller).
            st.audit
                .record_grant_edge(GrantEdge {
                    file_id,
                    granted_by: session.user_id,
                    recipient_id: recipient,
                    action: GrantAction::SoftRevoke,
                    at_ms: now_ms(),
                })
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(DeleteWrapError::NotAuthorized) => StatusCode::FORBIDDEN.into_response(),
        Err(DeleteWrapError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(DeleteWrapError::Store(e)) => internal_error(e),
    }
}

#[derive(Serialize)]
struct RecipientOut {
    recipient_id: String,
    granted_by: String,
    grant_b64: String,
    grant_sig_b64: String,
    ancestor_grants: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct RecipientsRes {
    recipients: Vec<RecipientOut>,
}

/// `GET /v1/files/{file_id}/recipients` — the owner reads its file's current
/// user recipients + grant chains to drive rotation carry-forward (§12.9 step
/// 2). Owner-only; `404` for a missing file or a non-owner caller (no oracle).
async fn list_recipients<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path(file_id_hex): Path<String>,
) -> Response {
    let Some(file_id) = hex_fixed::<16>(&file_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st
        .auth
        .store()
        .list_recipients(file_id, session.user_id)
        .await
    {
        Ok(Some(rs)) => {
            let recipients = rs
                .iter()
                .map(|r| RecipientOut {
                    recipient_id: hex_encode(&r.recipient_id),
                    granted_by: hex_encode(&r.granted_by),
                    grant_b64: b64encode(&r.grant_bytes),
                    grant_sig_b64: b64encode(&r.grant_sig),
                    ancestor_grants: r
                        .ancestor_grants
                        .iter()
                        .map(|(b, s)| {
                            serde_json::json!({
                                "grant_b64": b64encode(b),
                                "grant_sig_b64": b64encode(s),
                            })
                        })
                        .collect(),
                })
                .collect();
            Json(RecipientsRes { recipients }).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => internal_error(e),
    }
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(rename = "type")]
    file_type: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ListEntryRes {
    file_id: String,
    file_type: String,
    version: u64,
    updated_at: u64,
    streams: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct ListRes {
    files: Vec<ListEntryRes>,
    next_cursor: Option<String>,
}

/// `GET /v1/files?type=&limit=` — D35 listing (api.md §8.6). `file_type` +
/// small-stream structure/sizes only; never values.
async fn list_files<S: Store + 'static>(
    State(st): State<AppState<S>>,
    _session: AuthedSession,
    Query(q): Query<ListQuery>,
) -> Response {
    // An unknown type filter matches nothing rather than erroring the browse.
    let file_type = match q.file_type.as_deref() {
        None => None,
        Some(s) => match file_type_code(s) {
            Some(c) => Some(c),
            None => return Json(ListRes { files: Vec::new(), next_cursor: None }).into_response(),
        },
    };
    let limit = q.limit.unwrap_or(50).min(200);
    match st.auth.store().list_files(ListFilter { file_type, limit }).await {
        Ok(entries) => {
            let files = entries
                .iter()
                .map(|e| {
                    let mut streams = serde_json::Map::new();
                    for (st_code, size) in &e.small_streams {
                        streams.insert(
                            stream_type_name(*st_code).to_owned(),
                            serde_json::json!({ "size": size }),
                        );
                    }
                    ListEntryRes {
                        file_id: hex_encode(&e.file_id),
                        file_type: file_type_name(e.file_type).to_owned(),
                        version: e.version,
                        updated_at: e.updated_at_ms,
                        streams,
                    }
                })
                .collect();
            Json(ListRes {
                files,
                next_cursor: None,
            })
            .into_response()
        }
        Err(e) => internal_error(e),
    }
}

/// An authenticated, channel-bound session, resolved from the
/// `Authorization: MaxSecu-Session <hex>` header and validated against the live
/// connection's exporter (api.md §1.5/§2.3). Rejects with `401` on any failure.
pub struct AuthedSession {
    pub user_id: [u8; 16],
    pub token: [u8; 32],
}

impl<S: Store + 'static> FromRequestParts<AppState<S>> for AuthedSession {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<S>,
    ) -> Result<Self, StatusCode> {
        let exporter = parts
            .extensions
            .get::<TlsExporter>()
            .copied()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("MaxSecu-Session "))
            .and_then(hex_fixed::<32>)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let user_id = state
            .auth
            .validate_session(&token, &exporter.0, now_ms())
            .await
            .map_err(|e| match e {
                AuthError::Unauthorized => StatusCode::UNAUTHORIZED,
                AuthError::Internal(e) => {
                    log_internal(e);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            })?;
        Ok(AuthedSession { user_id, token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use crate::blob::MemoryBlobStore;
    use crate::store::{FaultyStore, MemoryStore, UserRecord};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use maxsecu_crypto::{generate_enc_keypair, sha256, SigningKey};
    use maxsecu_encoding::labels;
    use maxsecu_encoding::structs::AuthProofContext;
    use maxsecu_encoding::types::{Bytes32, Text, Timestamp};
    use tower::ServiceExt; // oneshot

    const EXPORTER: [u8; 32] = [0xE7; 32];

    fn app(exporter: [u8; 32]) -> (Router, SigningKey) {
        let store = MemoryStore::new();
        let sk = SigningKey::generate();
        store.add_user(
            "alice",
            UserRecord {
                user_id: [0x01; 16],
                enc_pub: [0xE1; 32],
                sig_pub: sk.verifying_key().to_bytes(),
            },
        );
        let state = AppState {
            auth: Arc::new(AuthService::new(store, AuthConfig::default())),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
        };
        let router = router(state).layer(Extension(TlsExporter(exporter)));
        (router, sk)
    }

    fn make_proof(
        sk: &SigningKey,
        server_id: &str,
        exporter: &[u8; 32],
        nonce: &[u8; 32],
        ts: u64,
    ) -> String {
        let ctx = AuthProofContext {
            server_id: Text::new(server_id).unwrap(),
            tls_exporter: Bytes32(*exporter),
            nonce: Bytes32(*nonce),
            timestamp: Timestamp(ts),
        };
        b64encode(&sk.sign_canonical(labels::AUTH, &ctx))
    }

    async fn get_json(router: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    async fn post_json(
        router: &Router,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn full_login_over_http() {
        let (router, sk) = app(EXPORTER);
        // challenge
        let (st, ch) = post_json(
            &router,
            "/v1/session/challenge",
            serde_json::json!({"username":"alice"}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let nonce = b64_fixed::<32>(ch["nonce_b64"].as_str().unwrap()).unwrap();
        let server_id = ch["server_id"].as_str().unwrap();
        // proof (bound to EXPORTER)
        let ts = 1_719_500_000_000u64;
        let proof_b64 = make_proof(&sk, server_id, &EXPORTER, &nonce, ts);
        let (st, res) = post_json(
            &router,
            "/v1/session/proof",
            serde_json::json!({"username":"alice","timestamp":ts,"proof_b64":proof_b64}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let token = res["session_token"].as_str().unwrap().to_owned();

        // authenticated logout succeeds with the channel-bound token
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/session/logout")
                    .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn relay_to_different_channel_yields_401() {
        // Server connection is bound to a DIFFERENT exporter than the proof.
        let (router, sk) = app([0x00; 32]);
        let (_st, ch) = post_json(
            &router,
            "/v1/session/challenge",
            serde_json::json!({"username":"alice"}),
        )
        .await;
        let nonce = b64_fixed::<32>(ch["nonce_b64"].as_str().unwrap()).unwrap();
        let server_id = ch["server_id"].as_str().unwrap();
        let ts = 1_719_500_000_000u64;
        // Proof built for EXPORTER, but the connection's exporter is all-zero.
        let proof_b64 = make_proof(&sk, server_id, &EXPORTER, &nonce, ts);
        let (st, _res) = post_json(
            &router,
            "/v1/session/proof",
            serde_json::json!({"username":"alice","timestamp":ts,"proof_b64":proof_b64}),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_user_gets_challenge_but_proof_401() {
        let (router, _sk) = app(EXPORTER);
        // Challenge issued for an unknown username (no oracle).
        let (st, ch) = post_json(
            &router,
            "/v1/session/challenge",
            serde_json::json!({"username":"ghost"}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(ch["nonce_b64"].as_str().is_some());
        // A bogus proof for the unknown user → 401 (same shape as any failure).
        let bogus = b64encode(&[0u8; 64]);
        let (st, _res) = post_json(
            &router,
            "/v1/session/proof",
            serde_json::json!({"username":"ghost","timestamp":1u64,"proof_b64":bogus}),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    fn app_with_vouchers(vouchers: &[&str]) -> Router {
        let store = MemoryStore::new();
        for v in vouchers {
            store.add_voucher(sha256(v.as_bytes()));
        }
        let state = AppState {
            auth: Arc::new(AuthService::new(store, AuthConfig::default())),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
        };
        router(state).layer(Extension(TlsExporter(EXPORTER)))
    }

    fn register_body(sk: &SigningKey, username: &str, voucher: &str) -> serde_json::Value {
        let (_esk, epk) = generate_enc_keypair();
        serde_json::json!({
            "username": username,
            "enc_pub_b64": b64encode(&epk.to_bytes()),
            "sig_pub_b64": b64encode(&sk.verifying_key().to_bytes()),
            "enrollment_voucher": voucher,
        })
    }

    #[tokio::test]
    async fn register_with_voucher_then_login() {
        let voucher = "in-person-code-001";
        let router = app_with_vouchers(&[voucher]);
        let sk = SigningKey::generate();
        let (st, res) = post_json(&router, "/v1/users", register_body(&sk, "bob", voucher)).await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(res["user_id"].as_str().unwrap().len(), 32); // 16 bytes hex

        // The freshly-registered user can complete a login end-to-end.
        let (_st, ch) = post_json(
            &router,
            "/v1/session/challenge",
            serde_json::json!({"username":"bob"}),
        )
        .await;
        let nonce = b64_fixed::<32>(ch["nonce_b64"].as_str().unwrap()).unwrap();
        let server_id = ch["server_id"].as_str().unwrap();
        let ts = 1_719_500_000_000u64;
        let proof_b64 = make_proof(&sk, server_id, &EXPORTER, &nonce, ts);
        let (st, res) = post_json(
            &router,
            "/v1/session/proof",
            serde_json::json!({"username":"bob","timestamp":ts,"proof_b64":proof_b64}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(res["session_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn reused_voucher_is_forbidden() {
        let voucher = "one-time-code";
        let router = app_with_vouchers(&[voucher]);
        let sk = SigningKey::generate();
        let (st1, _) = post_json(&router, "/v1/users", register_body(&sk, "bob", voucher)).await;
        assert_eq!(st1, StatusCode::CREATED);
        let (st2, _) = post_json(&router, "/v1/users", register_body(&sk, "carol", voucher)).await;
        assert_eq!(st2, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bad_voucher_is_forbidden() {
        let router = app_with_vouchers(&["real-code"]);
        let sk = SigningKey::generate();
        let (st, _) = post_json(
            &router,
            "/v1/users",
            register_body(&sk, "bob", "wrong-code"),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn duplicate_username_conflicts() {
        let router = app_with_vouchers(&["v1", "v2"]);
        let sk = SigningKey::generate();
        let (st1, _) = post_json(&router, "/v1/users", register_body(&sk, "bob", "v1")).await;
        assert_eq!(st1, StatusCode::CREATED);
        let (st2, _) = post_json(&router, "/v1/users", register_body(&sk, "bob", "v2")).await;
        assert_eq!(st2, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn challenge_issuance_cap_returns_429() {
        let (router, _sk) = app(EXPORTER);
        // 30 challenges/account/minute are allowed (parameters §3)…
        for i in 0..30 {
            let (st, _) = post_json(
                &router,
                "/v1/session/challenge",
                serde_json::json!({"username":"alice"}),
            )
            .await;
            assert_eq!(st, StatusCode::OK, "challenge #{i}");
        }
        // …the 31st within the window is throttled.
        let (st, _) = post_json(
            &router,
            "/v1/session/challenge",
            serde_json::json!({"username":"alice"}),
        )
        .await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn failed_proof_arms_backoff_then_429() {
        let (router, _sk) = app(EXPORTER);
        let bogus = b64encode(&[0u8; 64]);
        // First attempt fails 401 (no oracle) and arms the per-account backoff.
        let (st, _) = post_json(
            &router,
            "/v1/session/proof",
            serde_json::json!({"username":"alice","timestamp":1u64,"proof_b64":bogus}),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // An immediate retry (well inside the 1s backoff) is throttled 429, not 401.
        let (st, _) = post_json(
            &router,
            "/v1/session/proof",
            serde_json::json!({"username":"alice","timestamp":1u64,"proof_b64":bogus}),
        )
        .await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn directory_serves_signed_binding_byte_exactly() {
        use maxsecu_crypto::VerifyingKey;
        use maxsecu_encoding::structs::DirBinding;
        use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};
        use maxsecu_encoding::{encode, labels};

        let d5 = SigningKey::generate();
        let store = MemoryStore::new();
        let user_id = [0x01; 16];
        store.add_user(
            "alice",
            UserRecord {
                user_id,
                enc_pub: [0xE1; 32],
                sig_pub: [0x51; 32],
            },
        );
        let binding = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id(user_id),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000), // 2100-01-01
        };
        let bytes = encode(&binding);
        let sig = d5.sign_canonical(labels::DIRBINDING, &binding);
        store.put_binding(user_id, 1, bytes.clone(), sig).await.unwrap();

        let router = router(AppState {
            auth: Arc::new(AuthService::new(store, AuthConfig::default())),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
        })
        .layer(Extension(TlsExporter(EXPORTER)));

        // By username: the served bytes are byte-exact and verify under D5.
        let (st, body) = get_json(&router, "/v1/directory/alice").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(
            B64.decode(body["binding_b64"].as_str().unwrap()).unwrap(),
            bytes
        );
        let got_sig = b64_fixed::<64>(body["directory_signature_b64"].as_str().unwrap()).unwrap();
        let vk = VerifyingKey::from_bytes(&d5.verifying_key().to_bytes()).unwrap();
        assert!(vk.verify_canonical(labels::DIRBINDING, &binding, &got_sig).is_ok());

        // By id resolves the same binding.
        let (st2, body2) = get_json(
            &router,
            &format!("/v1/directory/by-id/{}", hex_encode(&user_id)),
        )
        .await;
        assert_eq!(st2, StatusCode::OK);
        assert_eq!(body2["binding_b64"], body["binding_b64"]);

        // An account with no signed binding is not a recipient → 404.
        let (st3, _) = get_json(&router, "/v1/directory/nobody").await;
        assert_eq!(st3, StatusCode::NOT_FOUND);
    }

    async fn post_json_auth(
        router: &Router,
        uri: &str,
        body: serde_json::Value,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    async fn login(router: &Router, username: &str, sk: &SigningKey) -> String {
        let (_st, ch) = post_json(
            router,
            "/v1/session/challenge",
            serde_json::json!({ "username": username }),
        )
        .await;
        let nonce = b64_fixed::<32>(ch["nonce_b64"].as_str().unwrap()).unwrap();
        let server_id = ch["server_id"].as_str().unwrap();
        let ts = 1_719_500_000_000u64;
        let proof_b64 = make_proof(sk, server_id, &EXPORTER, &nonce, ts);
        let (_st, res) = post_json(
            router,
            "/v1/session/proof",
            serde_json::json!({"username": username, "timestamp": ts, "proof_b64": proof_b64}),
        )
        .await;
        res["session_token"].as_str().unwrap().to_owned()
    }

    fn admin_app() -> (Router, SigningKey, SigningKey) {
        let (router, admin_sk, bob_sk, _audit) = admin_app_audited();
        (router, admin_sk, bob_sk)
    }

    /// Like [`admin_app`] but returns a handle to the `MemoryAuditSink` so a
    /// test can assert the grant edges the handlers emit (§16.5).
    fn admin_app_audited() -> (
        Router,
        SigningKey,
        SigningKey,
        Arc<crate::audit::MemoryAuditSink>,
    ) {
        use crate::audit::MemoryAuditSink;
        let store = MemoryStore::new();
        let admin_sk = SigningKey::generate();
        store.add_user(
            "admin",
            UserRecord {
                user_id: [0xAD; 16],
                enc_pub: [0xE1; 32],
                sig_pub: admin_sk.verifying_key().to_bytes(),
            },
        );
        store.set_roles([0xAD; 16], vec![Role::User, Role::Admin]);
        let bob_sk = SigningKey::generate();
        store.add_user(
            "bob",
            UserRecord {
                user_id: [0xB0; 16],
                enc_pub: [0xE2; 32],
                sig_pub: bob_sk.verifying_key().to_bytes(),
            },
        );
        let audit = Arc::new(MemoryAuditSink::new());
        let router = router(AppState {
            auth: Arc::new(AuthService::new(store, AuthConfig::default())),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: audit.clone(),
        })
        .layer(Extension(TlsExporter(EXPORTER)));
        (router, admin_sk, bob_sk, audit)
    }

    // Build a single-file revocation chaining to `prev_head` (server doesn't
    // verify the issuer sig — that's client-side — so a placeholder sig suffices).
    fn revocation_b64(prev_head: [u8; 32], epoch: u64, victim: u8) -> (String, String) {
        use maxsecu_encoding::structs::Revocation;
        use maxsecu_encoding::types::{Bytes32, FileScope, Id, Timestamp};
        let rec = Revocation {
            scope: FileScope::Specific(Id([0x0A; 16])),
            revoked_user_id: Id([victim; 16]),
            revoked_capability: None,
            from_version: 1,
            revocation_epoch: epoch,
            prev_head: Bytes32(prev_head),
            issued_by: Id([0xAD; 16]),
            co_signed_by: None,
            created_at: Timestamp(1_719_500_000_000),
        };
        (
            b64encode(&maxsecu_encoding::encode(&rec)),
            b64encode(&[0xCC; 64]),
        )
    }

    #[tokio::test]
    async fn control_log_append_serve_and_admin_gate() {
        let (router, admin_sk, bob_sk) = admin_app();
        let admin = login(&router, "admin", &admin_sk).await;
        let genesis = [0u8; 32];

        // Admin appends a revocation chaining to GENESIS_HEAD → 201 + new head.
        let (rec1, sig1) = revocation_b64(genesis, 1, 0x99);
        let (st, res) = post_json_auth(
            &router,
            "/v1/revocations",
            serde_json::json!({"record_b64": rec1, "sig_b64": sig1}),
            &admin,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let head1 = res["chain_head_b64"].as_str().unwrap().to_owned();

        // GET serves the record byte-exactly with its kind.
        let (st, body) = get_json(&router, "/v1/revocations").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["records"].as_array().unwrap().len(), 1);
        assert_eq!(body["records"][0]["record_b64"].as_str().unwrap(), rec1);
        assert_eq!(body["records"][0]["kind"], "revocation");

        // A second record chaining to head1 → 201.
        let (rec2, sig2) = revocation_b64(b64_fixed::<32>(&head1).unwrap(), 2, 0x98);
        let (st, _) = post_json_auth(
            &router,
            "/v1/revocations",
            serde_json::json!({"record_b64": rec2, "sig_b64": sig2}),
            &admin,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        // A stale append (prev_head = GENESIS again) → 409 Conflict.
        let (rec3, sig3) = revocation_b64(genesis, 3, 0x97);
        let (st, _) = post_json_auth(
            &router,
            "/v1/revocations",
            serde_json::json!({"record_b64": rec3, "sig_b64": sig3}),
            &admin,
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);

        // A non-admin caller is rejected by the coarse gate → 403.
        let bob = login(&router, "bob", &bob_sk).await;
        let (rec4, sig4) = revocation_b64(genesis, 1, 0x96);
        let (st, _) = post_json_auth(
            &router,
            "/v1/revocations",
            serde_json::json!({"record_b64": rec4, "sig_b64": sig4}),
            &bob,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // Malformed record bytes → 400.
        let (st, _) = post_json_auth(
            &router,
            "/v1/revocations",
            serde_json::json!({"record_b64": b64encode(&[1u8, 2, 3]), "sig_b64": b64encode(&[0xCC; 64])}),
            &admin,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn store_fault_yields_500_not_401_or_403() {
        // Over a backend that faults on every call, the HTTP layer must answer
        // 500 (server health) — NOT a swallowed 200/401/403 that hides the fault.
        let state = AppState {
            auth: Arc::new(AuthService::new(FaultyStore, AuthConfig::default())),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
        };
        let router = router(state).layer(Extension(TlsExporter(EXPORTER)));

        // challenge: insert_nonce faults → 500, not a bogus 200.
        let (st, _) = post_json(
            &router,
            "/v1/session/challenge",
            serde_json::json!({"username":"alice"}),
        )
        .await;
        assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "challenge over a faulty store");

        // register: a voucher-table fault → 500, not a misleading 403 "bad voucher".
        let sk = SigningKey::generate();
        let (_esk, epk) = generate_enc_keypair();
        let (st, _) = post_json(
            &router,
            "/v1/users",
            serde_json::json!({
                "username": "bob",
                "enc_pub_b64": b64encode(&epk.to_bytes()),
                "sig_pub_b64": b64encode(&sk.verifying_key().to_bytes()),
                "enrollment_voucher": "code",
            }),
        )
        .await;
        assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "register over a faulty store");
    }

    async fn get_json_auth(
        router: &Router,
        uri: &str,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    // Build a manifest for the file HTTP tests (sigs are placeholders — the server
    // never verifies them; the downloader does).
    fn file_manifest_b64(file: [u8; 16], version: u64, author: [u8; 16]) -> String {
        use maxsecu_encoding::structs::{Manifest, Stream};
        use maxsecu_encoding::types::{Compression, FileType, Id, StreamType, Suite};
        let m = Manifest {
            file_id: Id(file),
            version,
            file_type: FileType::Blog,
            alg: Suite::V1,
            chunk_size: 1 << 20,
            dek_commit: Bytes32([0xDC; 32]),
            streams: vec![
                Stream {
                    stream_type: StreamType::Content,
                    compression: Compression::None,
                    chunk_count: 2,
                    digest: Bytes32([0xC0; 32]),
                },
                Stream {
                    stream_type: StreamType::Metadata,
                    compression: Compression::None,
                    chunk_count: 1,
                    digest: Bytes32([0x2E; 32]),
                },
            ],
            recovery_present: true,
            author_id: Id(author),
            created_at: Timestamp(1_719_500_000_000 + version),
        };
        b64encode(&maxsecu_encoding::encode(&m))
    }

    fn file_genesis_b64(file: [u8; 16], owner: [u8; 16]) -> String {
        use maxsecu_encoding::structs::Genesis;
        use maxsecu_encoding::types::Id;
        b64encode(&maxsecu_encoding::encode(&Genesis {
            file_id: Id(file),
            owner_id: Id(owner),
            owner_key_version: 1,
            created_at: Timestamp(1_719_500_000_000),
        }))
    }

    fn file_wraps_json(owner: [u8; 16]) -> serde_json::Value {
        serde_json::json!([
            { "recipient_id": hex_encode(&owner), "recipient_type": "user",
              "wrapped_dek_b64": b64encode(&[0xA1u8; 48]), "wrap_alg": 1,
              "granted_by": hex_encode(&owner), "grant_b64": b64encode(&[0xB1u8; 8]),
              "grant_sig_b64": b64encode(&[0xC1u8; 64]) },
            { "recipient_id": "recovery", "recipient_type": "recovery",
              "wrapped_dek_b64": b64encode(&[0xA2u8; 48]), "wrap_alg": 1,
              "granted_by": hex_encode(&owner), "grant_b64": b64encode(&[0xB2u8; 8]),
              "grant_sig_b64": b64encode(&[0xC2u8; 64]) },
        ])
    }

    async fn put_chunk_auth(
        router: &Router,
        uri: &str,
        body: Vec<u8>,
        token: &str,
    ) -> StatusCode {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/octet-stream")
                    .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    async fn get_chunk_auth(router: &Router, uri: &str, token: &str) -> (StatusCode, Vec<u8>) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 21).await.unwrap();
        (status, bytes.to_vec())
    }

    fn chunk_uri(file: [u8; 16], version: u64, stream: &str, index: u64) -> String {
        format!(
            "/v1/files/{}/versions/{version}/streams/{stream}/chunks/{index}",
            hex_encode(&file)
        )
    }

    /// Upload the chunks the fixture manifest declares (content: 2, metadata: 1).
    async fn upload_declared_chunks(router: &Router, file: [u8; 16], version: u64, token: &str) {
        assert_eq!(
            put_chunk_auth(router, &chunk_uri(file, version, "content", 0), vec![0x10; 32], token).await,
            StatusCode::OK
        );
        assert_eq!(
            put_chunk_auth(router, &chunk_uri(file, version, "content", 1), vec![0x11; 32], token).await,
            StatusCode::OK
        );
        assert_eq!(
            put_chunk_auth(router, &chunk_uri(file, version, "metadata", 0), vec![0x20; 16], token).await,
            StatusCode::OK
        );
    }

    fn create_file_body(file: [u8; 16], owner: [u8; 16]) -> serde_json::Value {
        serde_json::json!({
            "file_id": hex_encode(&file),
            "file_type": "blog",
            "genesis_b64": file_genesis_b64(file, owner),
            "genesis_sig_b64": b64encode(&[0x9Au8; 64]),
            "manifest_b64": file_manifest_b64(file, 1, owner),
            "manifest_sig_b64": b64encode(&[0x9Bu8; 64]),
            "streams": [ {"stream_type":"content","chunk_count":2,"chunk_size":1048576,"total_bytes":2000000},
                         {"stream_type":"metadata","chunk_count":1,"chunk_size":1048576,"total_bytes":256} ],
            "wraps": file_wraps_json(owner),
        })
    }

    #[tokio::test]
    async fn file_upload_finalize_get_and_listing_over_http() {
        let (router, admin_sk, bob_sk) = admin_app();
        let owner = [0xADu8; 16]; // admin's user_id
        let token = login(&router, "admin", &admin_sk).await;
        let file = [0xF1u8; 16];

        // Stage v1 → 201 with version + an upload token.
        let (st, res) =
            post_json_auth(&router, "/v1/files", create_file_body(file, owner), &token).await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(res["version"].as_u64().unwrap(), 1);
        assert!(res["upload_token"].as_str().is_some());

        // Not visible until finalize.
        let (st, _) = get_json_auth(&router, &format!("/v1/files/{}", hex_encode(&file)), &token).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Upload the declared chunks, then finalize → 200.
        upload_declared_chunks(&router, file, 1, &token).await;
        let (st, _) = post_json_auth(
            &router,
            &format!("/v1/files/{}/versions/1/finalize", hex_encode(&file)),
            serde_json::json!({}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // The uploaded ciphertext chunk reads back byte-exactly.
        let (st, bytes) = get_chunk_auth(&router, &chunk_uri(file, 1, "content", 0), &token).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(bytes, vec![0x10; 32]);

        let (st, body) =
            get_json_auth(&router, &format!("/v1/files/{}?version=latest", hex_encode(&file)), &token).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["version"].as_u64().unwrap(), 1);
        assert_eq!(body["manifest_b64"].as_str().unwrap(), file_manifest_b64(file, 1, owner));
        assert!(body["my_wrap"]["wrapped_dek_b64"].as_str().is_some());
        assert!(body["recovery_grant"]["grant_b64"].as_str().is_some());
        assert_eq!(body["streams"].as_array().unwrap().len(), 2);

        // A different authenticated user holds no wrap → 404 (no access oracle),
        // for both the record and its chunks.
        let bob = login(&router, "bob", &bob_sk).await;
        let (st, _) = get_json_auth(&router, &format!("/v1/files/{}", hex_encode(&file)), &bob).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        let (st, _) = get_chunk_auth(&router, &chunk_uri(file, 1, "content", 0), &bob).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Listing shows the blog with its small (metadata) stream, not content.
        let (st, body) = get_json_auth(&router, "/v1/files?type=blog", &token).await;
        assert_eq!(st, StatusCode::OK);
        let files = body["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["file_type"], "blog");
        assert!(files[0]["streams"]["metadata"]["size"].as_u64().is_some());
        assert!(files[0]["streams"].get("content").is_none());
    }

    async fn delete_auth(router: &Router, uri: &str, token: &str) -> StatusCode {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(uri)
                    .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    fn reshare_body(recipient: [u8; 16], granted_by: [u8; 16]) -> serde_json::Value {
        serde_json::json!({
            "recipient_id": hex_encode(&recipient), "recipient_type": "user",
            "wrapped_dek_b64": b64encode(&[0xD1u8; 48]), "wrap_alg": 1,
            "granted_by": hex_encode(&granted_by), "grant_b64": b64encode(&[0xD2u8; 8]),
            "grant_sig_b64": b64encode(&[0xD3u8; 64]),
        })
    }

    /// Create + chunk + finalize a v1 blog owned by `owner` (admin's token).
    async fn create_finalize_v1(router: &Router, file: [u8; 16], owner: [u8; 16], token: &str) {
        let (st, _) = post_json_auth(router, "/v1/files", create_file_body(file, owner), token).await;
        assert_eq!(st, StatusCode::CREATED);
        upload_declared_chunks(router, file, 1, token).await;
        let (st, _) = post_json_auth(
            router,
            &format!("/v1/files/{}/versions/1/finalize", hex_encode(&file)),
            serde_json::json!({}),
            token,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn reshare_then_soft_revoke_over_http() {
        let (router, admin_sk, bob_sk) = admin_app();
        let owner = [0xADu8; 16];
        let bob_id = [0xB0u8; 16];
        let token = login(&router, "admin", &admin_sk).await;
        let file = [0xF7u8; 16];
        create_finalize_v1(&router, file, owner, &token).await;

        let bob = login(&router, "bob", &bob_sk).await;
        let wraps_uri = format!("/v1/files/{}/wraps", hex_encode(&file));

        // Bob holds no wrap → cannot re-share; indistinguishable from missing (404).
        let (st, _) = post_json_auth(&router, &wraps_uri, reshare_body([0x44; 16], bob_id), &bob).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // An inconsistent `granted_by` (not the caller) → 400.
        let (st, _) =
            post_json_auth(&router, &wraps_uri, reshare_body([0x55; 16], [0x99; 16]), &token).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Owner re-shares read to bob → 201; bob can now GET (ancestor chain empty,
        // the grant is author-rooted).
        let (st, _) = post_json_auth(&router, &wraps_uri, reshare_body(bob_id, owner), &token).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, body) =
            get_json_auth(&router, &format!("/v1/files/{}", hex_encode(&file)), &bob).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body["my_wrap"]["wrapped_dek_b64"].as_str().is_some());
        assert_eq!(body["my_wrap"]["ancestor_grants"].as_array().unwrap().len(), 0);

        // Soft-revoke: bob (neither owner nor the granter) cannot revoke his own
        // wrap → 403; the owner can → 204, and bob is then 404.
        let revoke_uri = format!("/v1/files/{}/wraps/{}", hex_encode(&file), hex_encode(&bob_id));
        assert_eq!(delete_auth(&router, &revoke_uri, &bob).await, StatusCode::FORBIDDEN);
        assert_eq!(delete_auth(&router, &revoke_uri, &token).await, StatusCode::NO_CONTENT);
        let (st, _) =
            get_json_auth(&router, &format!("/v1/files/{}", hex_encode(&file)), &bob).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn owner_lists_recipients_over_http_non_owner_404() {
        let (router, admin_sk, bob_sk) = admin_app();
        let owner = [0xADu8; 16];
        let bob_id = [0xB0u8; 16];
        let token = login(&router, "admin", &admin_sk).await;
        let file = [0xF9u8; 16];
        create_finalize_v1(&router, file, owner, &token).await;

        // Re-share to bob, then the owner enumerates recipients (owner + bob).
        let wraps_uri = format!("/v1/files/{}/wraps", hex_encode(&file));
        let (st, _) = post_json_auth(&router, &wraps_uri, reshare_body(bob_id, owner), &token).await;
        assert_eq!(st, StatusCode::CREATED);

        let recips_uri = format!("/v1/files/{}/recipients", hex_encode(&file));
        let (st, body) = get_json_auth(&router, &recips_uri, &token).await;
        assert_eq!(st, StatusCode::OK);
        let rs = body["recipients"].as_array().unwrap();
        assert_eq!(rs.len(), 2); // owner self + bob (recovery excluded)
        assert!(rs.iter().any(|r| r["recipient_id"] == hex_encode(&bob_id)));

        // bob (a recipient, not the owner) cannot enumerate → 404 (no oracle).
        let bob = login(&router, "bob", &bob_sk).await;
        let (st, _) = get_json_auth(&router, &recips_uri, &bob).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sharing_emits_grant_edges_to_the_audit_sink() {
        use crate::audit::GrantAction;
        let (router, admin_sk, bob_sk, audit) = admin_app_audited();
        let _ = &bob_sk;
        let owner = [0xADu8; 16];
        let bob_id = [0xB0u8; 16];
        let recovery = [0u8; 16];
        let token = login(&router, "admin", &admin_sk).await;
        let file = [0xF8u8; 16];
        create_finalize_v1(&router, file, owner, &token).await;

        // Author edges at upload: owner self + recovery, both granted_by = owner.
        let authored = audit.edges();
        assert!(authored.iter().any(|e| e.action == GrantAction::Author
            && e.granted_by == owner
            && e.recipient_id == owner));
        assert!(authored.iter().any(|e| e.action == GrantAction::Author
            && e.granted_by == owner
            && e.recipient_id == recovery));

        // Re-share to bob → a Reshare edge.
        let wraps_uri = format!("/v1/files/{}/wraps", hex_encode(&file));
        let (st, _) = post_json_auth(&router, &wraps_uri, reshare_body(bob_id, owner), &token).await;
        assert_eq!(st, StatusCode::CREATED);
        assert!(audit.edges().iter().any(|e| e.action == GrantAction::Reshare
            && e.file_id == file
            && e.granted_by == owner
            && e.recipient_id == bob_id));

        // Soft-revoke bob → a SoftRevoke edge (granted_by = the acting caller).
        let revoke_uri = format!("/v1/files/{}/wraps/{}", hex_encode(&file), hex_encode(&bob_id));
        assert_eq!(delete_auth(&router, &revoke_uri, &token).await, StatusCode::NO_CONTENT);
        assert!(audit.edges().iter().any(|e| e.action == GrantAction::SoftRevoke
            && e.granted_by == owner
            && e.recipient_id == bob_id));
    }

    #[tokio::test]
    async fn file_upload_redteam_status_codes() {
        let (router, admin_sk, bob_sk) = admin_app();
        let owner = [0xADu8; 16];
        let token = login(&router, "admin", &admin_sk).await;
        let file = [0xF2u8; 16];

        // A manifest authored by someone other than the caller → 403 (D29).
        let mut body = create_file_body(file, owner);
        body["manifest_b64"] = serde_json::Value::String(file_manifest_b64(file, 1, [0x22; 16]));
        let (st, _) = post_json_auth(&router, "/v1/files", body, &token).await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // Malformed manifest bytes → 400.
        let mut body = create_file_body(file, owner);
        body["manifest_b64"] = serde_json::Value::String(b64encode(&[0x00u8, 0x02, 0xFF]));
        let (st, _) = post_json_auth(&router, "/v1/files", body, &token).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Stage a real v1; finalizing before the chunks arrive → 400 (incomplete).
        let (st, _) = post_json_auth(&router, "/v1/files", create_file_body(file, owner), &token).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, _) = post_json_auth(
            &router,
            &format!("/v1/files/{}/versions/1/finalize", hex_encode(&file)),
            serde_json::json!({}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "finalize with missing chunks is incomplete");
        // Now upload the chunks and finalize → 200.
        upload_declared_chunks(&router, file, 1, &token).await;
        let (st, _) = post_json_auth(
            &router,
            &format!("/v1/files/{}/versions/1/finalize", hex_encode(&file)),
            serde_json::json!({}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        // A chunk PUT after finalize → 409 (immutable).
        assert_eq!(
            put_chunk_auth(&router, &chunk_uri(file, 1, "content", 0), vec![0x10; 32], &token).await,
            StatusCode::CONFLICT
        );
        // Stage v3 (skips v2), upload its chunks, then finalize → strict-+1 409.
        let v3 = serde_json::json!({
            "file_type": "blog",
            "manifest_b64": file_manifest_b64(file, 3, owner),
            "manifest_sig_b64": b64encode(&[0x9Bu8; 64]),
            "streams": [ {"stream_type":"content","chunk_count":2,"chunk_size":1048576,"total_bytes":2000000},
                         {"stream_type":"metadata","chunk_count":1,"chunk_size":1048576,"total_bytes":256} ],
            "wraps": file_wraps_json(owner),
        });
        let (st, _) = post_json_auth(&router, &format!("/v1/files/{}/versions", hex_encode(&file)), v3, &token).await;
        assert_eq!(st, StatusCode::CREATED);
        upload_declared_chunks(&router, file, 3, &token).await;
        let (st, _) = post_json_auth(
            &router,
            &format!("/v1/files/{}/versions/3/finalize", hex_encode(&file)),
            serde_json::json!({}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);

        // Index past the declared chunk_count → 413 (bound-check before storage).
        let file2 = [0xF3u8; 16];
        let (st, _) = post_json_auth(&router, "/v1/files", create_file_body(file2, owner), &token).await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(
            put_chunk_auth(&router, &chunk_uri(file2, 1, "content", 9), vec![0x10; 32], &token).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // A non-owner cannot upload chunks (owner-only write, D29) → 403.
        let other = login(&router, "bob", &bob_sk).await;
        assert_eq!(
            put_chunk_auth(&router, &chunk_uri(file2, 1, "content", 0), vec![0x10; 32], &other).await,
            StatusCode::FORBIDDEN
        );

        // An unauthenticated stage → 401.
        let (st, _) = post_json(&router, "/v1/files", create_file_body([0xF9; 16], owner)).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_without_token_is_401() {
        let (router, _sk) = app(EXPORTER);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/session/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
