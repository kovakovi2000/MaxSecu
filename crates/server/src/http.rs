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
    parse_stage, AddWrapError, DeleteWrapError, DiscardError, FinalizeError, GenesisInput,
    ListFilter, StageError, StageInput, VersionSelector, WrapInput,
};
use crate::audit::{AuditSink, GrantAction, GrantEdge};
use crate::blob::BlobStore;
use crate::store::{FileView, Store};
use maxsecu_encoding::labels::DIRBINDING;
use maxsecu_encoding::structs::{DirBinding, Manifest};
use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};
use maxsecu_encoding::{decode, encode};
use maxsecu_crypto::{random_array, VerifyingKey};
use axum::extract::{DefaultBodyLimit, FromRequestParts, Json, Path, Query, State};
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
    /// Operator toggle for direct client↔cold-tier links (api.md §9.4, D31).
    /// **Opt-in** — `false` means the broker endpoint returns `403
    /// direct_disabled`. A client also forces server-proxy under Tor (D34) by not
    /// calling it.
    pub direct_links_enabled: bool,
    /// Optional per-upload content size cap (operator-configured, default `None`
    /// = unlimited). When `Some(limit)`, staging a manifest whose content stream's
    /// `chunk_count × chunk_size` exceeds `limit` is rejected with `413
    /// Payload Too Large`. Other streams (metadata/thumbnail/preview) are not
    /// counted toward the quota.
    pub max_file_bytes: Option<u64>,
}

impl<S: Store> Clone for AppState<S> {
    fn clone(&self) -> Self {
        AppState {
            auth: self.auth.clone(),
            blobs: self.blobs.clone(),
            audit: self.audit.clone(),
            direct_links_enabled: self.direct_links_enabled,
            max_file_bytes: self.max_file_bytes,
        }
    }
}

/// The auth/session routes (api.md §2). The caller wraps this with the
/// per-connection `Extension<TlsExporter>` layer (TLS transport / test).
pub fn router<S: Store + 'static>(state: AppState<S>) -> Router {
    Router::new()
        .route("/v1/users", post(register::<S>))
        .route("/v1/registration-keys", post(mint_registration_key::<S>))
        .route("/v1/session/challenge", post(challenge::<S>))
        .route("/v1/session/proof", post(prove::<S>))
        .route("/v1/session/logout", post(logout::<S>))
        .route("/v1/directory", post(publish_binding::<S>))
        .route("/v1/directory/by-id/{user_id}", get(directory_by_id::<S>))
        .route("/v1/directory/{username}", get(directory_by_username::<S>))
        .route(
            "/v1/revocations",
            get(get_revocations::<S>).post(post_control::<S>),
        )
        .route("/v1/reinstatements", post(post_control::<S>))
        .route("/v1/key-compromise", post(post_control::<S>))
        .route("/v1/files", get(list_files::<S>).post(create_file::<S>))
        .route("/v1/files/{file_id}", get(get_file::<S>).delete(discard_file::<S>))
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
        .route(
            "/v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}/status",
            get(chunk_status::<S>),
        )
        .route(
            "/v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}/direct-link",
            post(direct_link::<S>),
        )
        .with_state(state)
        // Raise the body limit to 8 MiB + 64 KiB so 6 MiB ciphertext chunks (plus
        // the AEAD tag) are accepted while clearly oversized bodies are rejected.
        // Applied globally — other bodies (JSON staging requests etc.) are small,
        // so this is safe. Default axum limit is 2 MB which would block 6 MiB PUTs.
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024 + 64 * 1024))
}

/// Direct-link TTL — short-lived, scoped, read-only (parameters.md §8, api §9.4).
const DIRECT_LINK_TTL_S: u64 = 900;

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

// ---- POST /v1/users — registration-key enrollment (DESIGN §5 / §0-D5) ----

/// A server-signed enrollment binding's validity window: always-valid from the
/// epoch to 2100-01-01. Key rotation (not a short expiry) is how a compromised
/// enrollment key is retired; the transparency log (T6) is what bounds trust.
const BINDING_NOT_BEFORE_MS: u64 = 0;
const BINDING_NOT_AFTER_MS: u64 = 4_102_444_800_000; // 2100-01-01

#[derive(Deserialize)]
struct RegisterReq {
    username: String,
    enc_pub_b64: String,
    sig_pub_b64: String,
    /// The single-use registration key (plaintext); the server persists only its
    /// `sha256` and consumes it atomically. Operator- or admin-minted.
    registration_key: String,
}

#[derive(Serialize)]
struct RegisterRes {
    user_id: String, // lowercase hex (api.md §1.4)
}

/// `POST /v1/users` — registration-key-only enrollment. The server is the
/// enrollment authority AND the binding signer:
///
/// 1. validate the request (decode keys, well-formed username, signer available)
///    — all side-effect-free, so a malformed request never burns a key;
/// 2. build BOTH candidate bindings for a fresh `user_id` and SIGN them
///    server-side — pure, no store I/O (the private seed stays in the signer;
///    only signature bytes cross into the store);
/// 3. hand the whole unit of work to the ATOMIC [`enroll`]: it consumes the
///    single-use key, creates the user, resolves the one-time first-admin slot,
///    and stores the matching binding in ONE transaction. A fault leaves NO
///    partial state — no burned key, no orphan user, no dangling admin claim —
///    so a retry with the same key works. The first-ever registrant is
///    `{User, Admin}`; everyone else `{User}`.
///
/// (T6 will append the enrollment to the transparency log at the `Enrolled`
/// success point — the signed-and-stored path is the clean hook.)
///
/// [`enroll`]: crate::store::Store::enroll
async fn register<S: Store>(
    State(st): State<AppState<S>>,
    Json(req): Json<RegisterReq>,
) -> Response {
    // (1) Pure validation — no store I/O yet, so a bad request cannot burn a key.
    let (Some(enc_pub), Some(sig_pub)) = (
        b64_fixed::<32>(&req.enc_pub_b64),
        b64_fixed::<32>(&req.sig_pub_b64),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(username) = Text::new(&req.username) else {
        return StatusCode::BAD_REQUEST.into_response(); // over-long / non-canonical
    };
    // Enrollment requires the server to hold its directory-signing key; if it is
    // not configured, enrollment is disabled (checked BEFORE any store I/O).
    let Some(signer) = st.auth.dir_signer() else {
        return StatusCode::FORBIDDEN.into_response(); // enrollment signing disabled
    };

    // (2) The server assigns the id, then signs BOTH role variants for it (pure).
    // The atomic `enroll` stores exactly the one that matches its first-admin
    // decision — so the role decision and the signed binding can never diverge,
    // and signing never needs to happen inside the store (no key in the store).
    let user_id: [u8; 16] = random_array();
    let sign_for = |roles: RoleSet| -> crate::store::StoredBinding {
        let binding = DirBinding {
            username: username.clone(),
            user_id: Id(user_id),
            enc_pub: Bytes32(enc_pub),
            sig_pub: Bytes32(sig_pub),
            key_version: 1,
            roles,
            not_before: Timestamp(BINDING_NOT_BEFORE_MS),
            not_after: Timestamp(BINDING_NOT_AFTER_MS),
            mlkem_pub: None,
        };
        let signature = signer.sign_canonical(DIRBINDING, &binding);
        crate::store::StoredBinding {
            binding_bytes: encode(&binding),
            signature,
        }
    };
    let user_binding = sign_for(RoleSet::new([Role::User]));
    let admin_binding = sign_for(RoleSet::new([Role::User, Role::Admin]));

    // (3) Atomic unit of work: consume-key → create-user → claim-admin →
    // store-binding, all-or-nothing (see `Store::enroll`).
    let key_hash = maxsecu_crypto::sha256(req.registration_key.as_bytes());
    match st
        .auth
        .store()
        .enroll(
            key_hash,
            user_id,
            &req.username,
            enc_pub,
            sig_pub,
            &user_binding,
            &admin_binding,
        )
        .await
    {
        Ok(crate::store::EnrollOutcome::Enrolled { .. }) => (
            StatusCode::CREATED,
            Json(RegisterRes {
                user_id: hex_encode(&user_id),
            }),
        )
            .into_response(),
        Ok(crate::store::EnrollOutcome::KeyInvalid) => StatusCode::FORBIDDEN.into_response(),
        Ok(crate::store::EnrollOutcome::UsernameTaken) => StatusCode::CONFLICT.into_response(),
        Err(e) => internal_error(e),
    }
}

// ---- POST /v1/registration-keys — admin-minted single-use keys (§5) ----

/// Admin-minted registration-key TTL (operational admission window).
const REG_KEY_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Serialize)]
struct MintRegKeyRes {
    /// The plaintext registration key, returned ONCE (the server stores only its
    /// `sha256`). Hand it to the enrollee out of band.
    registration_key: String,
}

/// `POST /v1/registration-keys` — an admin mints a fresh strong single-use
/// registration key (§5). Admin-gated by the D5-verified [`AdminSession`].
/// Admin-minted keys are **User-role only** — only the first-ever registrant is
/// admin — which holds automatically: by the time any admin exists to mint a
/// key, a user already exists, so `claim_first_admin` returns `false` for every
/// key-minted enrollment. The server persists ONLY `sha256(key)` and returns the
/// plaintext once; the raw bytes are zeroized server-side after use.
async fn mint_registration_key<S: Store + 'static>(
    State(st): State<AppState<S>>,
    _admin: AdminSession,
) -> Response {
    // A 256-bit random key, rendered as lowercase hex for a copy-pasteable token.
    let mut raw: [u8; 32] = random_array();
    let key = hex_encode(&raw);
    {
        use zeroize::Zeroize;
        raw.zeroize(); // the hex string is the only copy handed out
    }
    let key_hash = maxsecu_crypto::sha256(key.as_bytes());
    match st
        .auth
        .store()
        .issue_registration_key(key_hash, now_ms() + REG_KEY_TTL_MS)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(MintRegKeyRes { registration_key: key }))
            .into_response(),
        Err(e) => internal_error(e),
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

// ---- POST /v1/directory — publish a D5-signed binding (§7.1) ----

#[derive(Deserialize)]
struct PublishBindingReq {
    binding_b64: String,
    directory_signature_b64: String,
}

/// `POST /v1/directory` — publish a ceremony-signed identity binding (§7.1). The
/// server verifies it against the **pinned D5 public key** (anti-pollution) and
/// stores the opaque bytes; it cannot forge a binding (it lacks D5's private key)
/// and the client re-verifies everything served. Unauthenticated by design — the
/// D5 signature is the authority, and bootstrap admins' bindings publish before
/// any admin session exists.
async fn publish_binding<S: Store>(
    State(st): State<AppState<S>>,
    Json(req): Json<PublishBindingReq>,
) -> Response {
    let Some(dir_pub) = st.auth.directory_pub() else {
        return StatusCode::FORBIDDEN.into_response(); // publishing disabled (no pinned D5)
    };
    let (Some(bytes), Some(sig)) = (
        b64_vec(&req.binding_b64),
        b64_fixed::<64>(&req.directory_signature_b64),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(binding) = maxsecu_encoding::decode::<DirBinding>(&bytes) else {
        return StatusCode::BAD_REQUEST.into_response(); // non-canonical
    };
    let verified = VerifyingKey::from_bytes(&dir_pub)
        .and_then(|vk| vk.verify_canonical(DIRBINDING, &binding, &sig))
        .is_ok();
    if !verified {
        return StatusCode::FORBIDDEN.into_response();
    }
    match st
        .auth
        .store()
        .put_binding(binding.user_id.0, binding.key_version, bytes, sig)
        .await
    {
        Ok(()) => StatusCode::CREATED.into_response(),
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
/// [`AdminSession`] extractor requires a D5-verified admin binding; the record's
/// own authenticity (issuer admin-signature, dual control) is re-verified
/// client-side. The record's authenticated `kind` governs — the path is cosmetic.
async fn post_control<S: Store + 'static>(
    State(st): State<AppState<S>>,
    _admin: AdminSession,
    Json(req): Json<ControlReq>,
) -> Response {
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
    match st.auth.store().append_control(record.clone(), sig, co_sig).await {
        Ok(head) => {
            // §6 (sink-interface): publish the appended record to the external
            // sink (which re-derives the head) so a server cannot silently swallow
            // a tombstone at write time. Best-effort; the fail-closed authority is
            // the issuer-side `confirm_anchored`.
            st.audit.publish_control_record(record).await;
            (
                StatusCode::CREATED,
                Json(ChainHeadRes {
                    chain_head_b64: b64encode(&head),
                }),
            )
                .into_response()
        }
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
    // A v1 create carries the immutable genesis; a rotation does not. The genesis
    // is anchored in the sink on success so the R27 cutoff (§11.7/D28) can compare
    // its sink position against a later key_compromise.
    let has_genesis = input.genesis.is_some();
    let parsed = match parse_stage(input) {
        Ok(p) => p,
        Err(e) => return stage_status(e),
    };
    // Optional per-upload content quota: reject if the content stream's
    // declared size (chunk_count × chunk_size) exceeds the operator cap.
    // Checked after parse so the manifest is already decoded + bound-checked.
    if let Some(limit) = st.max_file_bytes {
        if let Some(s) = parsed.streams.iter().find(|s| s.stream_type == 1) {
            let declared = (s.chunk_count).saturating_mul(s.chunk_size as u64);
            if declared > limit {
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }
        }
    }
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
            if has_genesis {
                st.audit.anchor_genesis(file_id).await;
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

#[derive(Serialize)]
struct ChunkStatusOut {
    source: &'static str,
    fetched_bytes: u64,
    total_bytes: u64,
}

/// `GET /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}/status`
/// — cache-miss progress (api.md §9.3). Same §8.5 access gate as the chunk
/// download; reports where the chunk would be served from
/// (`cache`/`cold-fetching`/`cold-ready`). `404` for missing-or-forbidden (no
/// oracle). The state is a known, accepted popularity side-channel (§15.3).
async fn chunk_status<S: Store + 'static>(
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
    // §8.5 gate: the owner always, else a recipient of this finalized version.
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
    match st.blobs.chunk_status(&slot.blob_ref, index).await {
        Ok(Some(s)) => {
            let source = match s.source {
                crate::blob::FetchSource::Cache => "cache",
                crate::blob::FetchSource::ColdFetching => "cold-fetching",
                crate::blob::FetchSource::ColdReady => "cold-ready",
            };
            Json(ChunkStatusOut {
                source,
                fetched_bytes: s.fetched_bytes,
                total_bytes: s.total_bytes,
            })
            .into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => internal_error(e),
    }
}

#[derive(Serialize)]
struct DirectLinkOut {
    url: String,
    expires_in_s: u64,
}

/// `POST /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}/direct-link`
/// — broker a short-lived scoped read-only cold-tier link (api.md §9.4, D31). The
/// operator toggle is checked **first** so an off feature returns a uniform `403
/// direct_disabled` with no access oracle. When on: the §8.5 access gate, then
/// the broker — `404` if the chunk is absent or the tier has no link capability
/// (no oracle). The tier's master token is never exposed (`server::tier`).
async fn direct_link<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path((file_id_hex, version, stream_type, index)): Path<(String, u64, String, u64)>,
) -> Response {
    if !st.direct_links_enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "code": "direct_disabled" })),
        )
            .into_response();
    }
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
    match st
        .blobs
        .broker_direct_link(&slot.blob_ref, index, DIRECT_LINK_TTL_S)
        .await
    {
        Ok(Some(link)) => Json(DirectLinkOut {
            url: link.url,
            expires_in_s: link.expires_in_s,
        })
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

/// `DELETE /v1/files/{file_id}` — discard a staged-but-never-finalized upload.
/// Owner-only; idempotent (absent-or-already-discarded staged version is success).
/// `204` on success; `404` for absent/not-owner (no oracle); `409` if a finalized
/// version exists (append-only model — cannot remove committed content, §11.7).
async fn discard_file<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
    Path(file_id_hex): Path<String>,
) -> Response {
    let Some(file_id) = hex_fixed::<16>(&file_id_hex) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.auth.store().discard_unfinalized(file_id, session.user_id).await {
        Ok(blob_refs) => {
            // Best-effort blob cleanup; the discard already committed in the store.
            for r in &blob_refs {
                if let Err(e) = st.blobs.delete_stream(r).await {
                    log_internal(e);
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(DiscardError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(DiscardError::HasFinalizedVersion) => StatusCode::CONFLICT.into_response(),
        Err(DiscardError::Store(e)) => internal_error(e),
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

/// A channel-bound session whose caller is a **D5-verified admin** (DESIGN
/// §4.2/§10.1, D-K): the session resolves to a `user_id` whose stored binding
/// verifies under the pinned D5 key, is within its validity window, and carries
/// `Role::Admin`. The server can never confer admin — authority flows only from
/// the offline directory ceremony. This is the coarse server gate; the client
/// re-verifies every control-log record's authenticity independently. Rejects
/// `401` (not a session) or `403` (authenticated but not a verified admin).
pub struct AdminSession {
    pub user_id: [u8; 16],
    #[allow(dead_code)] // mirrors AuthedSession; kept for symmetry / future use
    pub token: [u8; 32],
}

impl<S: Store + 'static> FromRequestParts<AppState<S>> for AdminSession {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<S>,
    ) -> Result<Self, StatusCode> {
        let session = AuthedSession::from_request_parts(parts, state).await?;
        let Some(dir_pub) = state.auth.directory_pub() else {
            return Err(StatusCode::FORBIDDEN); // admin authz disabled (no pinned D5)
        };
        let stored = state
            .auth
            .store()
            .binding_by_user_id(&session.user_id)
            .await
            .map_err(|e| {
                log_internal(e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or(StatusCode::FORBIDDEN)?; // no published binding ⇒ not an admin
        let binding =
            decode::<DirBinding>(&stored.binding_bytes).map_err(|_| StatusCode::FORBIDDEN)?;
        let ok = VerifyingKey::from_bytes(&dir_pub)
            .and_then(|vk| vk.verify_canonical(DIRBINDING, &binding, &stored.signature))
            .is_ok();
        if !ok {
            return Err(StatusCode::FORBIDDEN);
        }
        let now = now_ms();
        if now < binding.not_before.0 || now > binding.not_after.0 {
            return Err(StatusCode::FORBIDDEN); // outside the binding's validity window
        }
        if !binding.roles.roles().contains(&Role::Admin) {
            return Err(StatusCode::FORBIDDEN); // a valid binding, but not an admin
        }
        Ok(AdminSession {
            user_id: session.user_id,
            token: session.token,
        })
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
            direct_links_enabled: false,
            max_file_bytes: None,
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

    /// Build a router whose `AuthConfig` pins `dir_pub` as the D5 public key, over
    /// a `store` seeded by the caller (so the GET-by-username path can resolve).
    fn app_with_directory_pub(store: MemoryStore, dir_pub: [u8; 32]) -> Router {
        let state = AppState {
            auth: Arc::new(AuthService::new(
                store,
                AuthConfig::default().with_directory_pub(dir_pub),
            )),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
            direct_links_enabled: false,
            max_file_bytes: None,
        };
        router(state).layer(Extension(TlsExporter(EXPORTER)))
    }

    #[tokio::test]
    async fn publish_binding_requires_a_valid_d5_signature() {
        use maxsecu_admin_core::DirectorySigner;
        use maxsecu_encoding::encode;
        use maxsecu_encoding::structs::DirBinding;
        use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};

        let d5 = DirectorySigner::generate();
        // The GET-by-username path joins users → bindings (store.rs
        // `binding_by_username`), so seed the user row with the SAME user_id the
        // binding carries ([0x0A; 16]) for the genuine-publish GET to resolve.
        let store = MemoryStore::new();
        store.add_user(
            "alice",
            UserRecord {
                user_id: [0x0A; 16],
                enc_pub: [0xE1; 32],
                sig_pub: [0x51; 32],
            },
        );
        let app = app_with_directory_pub(store, d5.public_key());

        let b = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([0x0A; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let signed = d5.sign_binding(&b, None);

        // Forged signature → 403.
        let (st, _) = post_json(
            &app,
            "/v1/directory",
            serde_json::json!({
                "binding_b64": B64.encode(encode(&b)),
                "directory_signature_b64": B64.encode([0u8; 64]),
            }),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // Genuine D5 signature → 201, then served by GET /v1/directory/alice.
        let (st, _) = post_json(
            &app,
            "/v1/directory",
            serde_json::json!({
                "binding_b64": B64.encode(encode(&signed.binding)),
                "directory_signature_b64": B64.encode(signed.signature),
            }),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, body) = get_json(&app, "/v1/directory/alice").await;
        assert_eq!(st, StatusCode::OK);
        assert!(body["binding_b64"].as_str().is_some());
    }

    /// An enrollment app: seeds the given single-use registration keys and gives
    /// the server its directory-signing key (so `POST /v1/users` can sign the
    /// enrollment binding). Returns the router; the pinned dir pub equals the
    /// signer's public key.
    fn app_with_reg_keys(keys: &[&str]) -> Router {
        let (router, _dir_pub) = app_with_reg_keys_pub(keys);
        router
    }

    fn app_with_reg_keys_pub(keys: &[&str]) -> (Router, [u8; 32]) {
        let store = MemoryStore::new();
        for k in keys {
            store.add_reg_key(sha256(k.as_bytes()));
        }
        let signer = Arc::new(SigningKey::generate());
        let dir_pub = signer.verifying_key().to_bytes();
        let state = AppState {
            auth: Arc::new(
                AuthService::new(store, AuthConfig::default().with_directory_pub(dir_pub))
                    .with_dir_signer(signer),
            ),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
            direct_links_enabled: false,
            max_file_bytes: None,
        };
        (
            router(state).layer(Extension(TlsExporter(EXPORTER))),
            dir_pub,
        )
    }

    fn register_body(sk: &SigningKey, username: &str, key: &str) -> serde_json::Value {
        let (_esk, epk) = generate_enc_keypair();
        serde_json::json!({
            "username": username,
            "enc_pub_b64": b64encode(&epk.to_bytes()),
            "sig_pub_b64": b64encode(&sk.verifying_key().to_bytes()),
            "registration_key": key,
        })
    }

    #[tokio::test]
    async fn register_with_key_then_login() {
        let key = "reg-key-001";
        let router = app_with_reg_keys(&[key]);
        let sk = SigningKey::generate();
        let (st, res) = post_json(&router, "/v1/users", register_body(&sk, "bob", key)).await;
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
    async fn first_registrant_is_admin_second_is_user_only() {
        use maxsecu_encoding::structs::DirBinding;
        let (router, dir_pub) = app_with_reg_keys_pub(&["k1", "k2"]);

        // First registrant → the served binding carries {User, Admin} and
        // verifies under the server's directory pubkey.
        let sk1 = SigningKey::generate();
        let (st, _) = post_json(&router, "/v1/users", register_body(&sk1, "alice", "k1")).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, body) = get_json(&router, "/v1/directory/alice").await;
        assert_eq!(st, StatusCode::OK);
        let bytes = B64.decode(body["binding_b64"].as_str().unwrap()).unwrap();
        let sig = b64_fixed::<64>(body["directory_signature_b64"].as_str().unwrap()).unwrap();
        let binding = decode::<DirBinding>(&bytes).unwrap();
        let vk = VerifyingKey::from_bytes(&dir_pub).unwrap();
        assert!(vk.verify_canonical(DIRBINDING, &binding, &sig).is_ok());
        assert!(binding.roles.roles().contains(&Role::Admin), "first = admin");

        // Second registrant → {User} only.
        let sk2 = SigningKey::generate();
        let (st, _) = post_json(&router, "/v1/users", register_body(&sk2, "bob", "k2")).await;
        assert_eq!(st, StatusCode::CREATED);
        let (_st, body) = get_json(&router, "/v1/directory/bob").await;
        let bytes = B64.decode(body["binding_b64"].as_str().unwrap()).unwrap();
        let binding = decode::<DirBinding>(&bytes).unwrap();
        assert!(binding.roles.roles().contains(&Role::User));
        assert!(!binding.roles.roles().contains(&Role::Admin), "second = user only");
    }

    #[tokio::test]
    async fn enrollment_disabled_without_signer_is_403() {
        // No directory signer configured → enrollment cannot sign ⇒ disabled,
        // and the registration key is NOT consumed (checked before consume).
        let store = MemoryStore::new();
        store.add_reg_key(sha256(b"k"));
        let state = AppState {
            auth: Arc::new(AuthService::new(store, AuthConfig::default())),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
            direct_links_enabled: false,
            max_file_bytes: None,
        };
        let router = router(state).layer(Extension(TlsExporter(EXPORTER)));
        let sk = SigningKey::generate();
        let (st, _) = post_json(&router, "/v1/users", register_body(&sk, "bob", "k")).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn reused_key_is_forbidden() {
        let key = "one-time-key";
        let router = app_with_reg_keys(&[key]);
        let sk = SigningKey::generate();
        let (st1, _) = post_json(&router, "/v1/users", register_body(&sk, "bob", key)).await;
        assert_eq!(st1, StatusCode::CREATED);
        let (st2, _) = post_json(&router, "/v1/users", register_body(&sk, "carol", key)).await;
        assert_eq!(st2, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bad_key_is_forbidden() {
        let router = app_with_reg_keys(&["real-key"]);
        let sk = SigningKey::generate();
        let (st, _) = post_json(
            &router,
            "/v1/users",
            register_body(&sk, "bob", "wrong-key"),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn duplicate_username_conflicts() {
        let router = app_with_reg_keys(&["v1", "v2"]);
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
            mlkem_pub: None,
        };
        let bytes = encode(&binding);
        let sig = d5.sign_canonical(labels::DIRBINDING, &binding);
        store.put_binding(user_id, 1, bytes.clone(), sig).await.unwrap();

        let router = router(AppState {
            auth: Arc::new(AuthService::new(store, AuthConfig::default())),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
            direct_links_enabled: false,
            max_file_bytes: None,
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

    async fn admin_app() -> (Router, SigningKey, SigningKey) {
        let (router, admin_sk, bob_sk, _audit) = admin_app_audited().await;
        (router, admin_sk, bob_sk)
    }

    /// Like [`admin_app`] but returns a handle to the `MemoryAuditSink` so a
    /// test can assert the grant edges the handlers emit (§16.5).
    ///
    /// Admin authority is conferred the production way (D-K): the pinned D5 key
    /// signs a `{User, Admin}` binding for the admin, which the server verifies on
    /// every admin-gated request — the D5-verified `AdminSession` binding is the
    /// real gate. `bob` has a record but no binding, so he is a valid session yet
    /// not an admin (→ 403).
    async fn admin_app_audited() -> (
        Router,
        SigningKey,
        SigningKey,
        Arc<crate::audit::MemoryAuditSink>,
    ) {
        use crate::audit::MemoryAuditSink;
        use maxsecu_admin_core::DirectorySigner;
        use maxsecu_encoding::encode;
        use maxsecu_encoding::structs::DirBinding;
        use maxsecu_encoding::types::{Id, RoleSet};

        let d5 = DirectorySigner::generate();
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
        let admin_binding = DirBinding {
            username: Text::new("admin").unwrap(),
            user_id: Id([0xAD; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32(admin_sk.verifying_key().to_bytes()),
            key_version: 1,
            roles: RoleSet::new([Role::User, Role::Admin]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let signed = d5.sign_binding(&admin_binding, None);
        store
            .put_binding([0xAD; 16], 1, encode(&signed.binding), signed.signature)
            .await
            .unwrap();
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
            auth: Arc::new(AuthService::new(
                store,
                AuthConfig::default().with_directory_pub(d5.public_key()),
            )),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: audit.clone(),
            direct_links_enabled: false,
            max_file_bytes: None,
        })
        .layer(Extension(TlsExporter(EXPORTER)));
        (router, admin_sk, bob_sk, audit)
    }

    /// An admin-configured enrollment app: the server's directory-signing key
    /// both (a) signs a `{User, Admin}` binding for the `admin` caller (so the
    /// D5-verified [`AdminSession`] gate accepts it) and (b) backs server-side
    /// enrollment signing. Returns `(router, admin_session_token_hex)`.
    async fn admin_signer_app() -> (Router, String) {
        use maxsecu_encoding::encode;
        use maxsecu_encoding::structs::DirBinding;
        use maxsecu_encoding::types::{Id, RoleSet};

        let signer = Arc::new(SigningKey::generate());
        let dir_pub = signer.verifying_key().to_bytes();
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
        let admin_binding = DirBinding {
            username: Text::new("admin").unwrap(),
            user_id: Id([0xAD; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32(admin_sk.verifying_key().to_bytes()),
            key_version: 1,
            roles: RoleSet::new([Role::User, Role::Admin]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let admin_sig = signer.sign_canonical(DIRBINDING, &admin_binding);
        store
            .put_binding([0xAD; 16], 1, encode(&admin_binding), admin_sig)
            .await
            .unwrap();
        // Mark the admin slot already claimed: `admin` is the genesis admin, so a
        // later key-minted enrollment must NOT also become admin.
        assert!(store.claim_first_admin().await.unwrap());
        let state = AppState {
            auth: Arc::new(
                AuthService::new(store, AuthConfig::default().with_directory_pub(dir_pub))
                    .with_dir_signer(signer),
            ),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
            direct_links_enabled: false,
            max_file_bytes: None,
        };
        let app = router(state).layer(Extension(TlsExporter(EXPORTER)));
        let token = login(&app, "admin", &admin_sk).await;
        (app, token)
    }

    #[tokio::test]
    async fn mint_registration_key_is_admin_gated_and_enrolls_user_only() {
        use maxsecu_encoding::structs::DirBinding;
        let (app, admin_token) = admin_signer_app().await;

        // No token → 401 (not a session).
        let (st, _) = post_json(&app, "/v1/registration-keys", serde_json::json!({})).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // Admin → 201 with a plaintext key handed back once.
        let (st, res) =
            post_json_auth(&app, "/v1/registration-keys", serde_json::json!({}), &admin_token).await;
        assert_eq!(st, StatusCode::CREATED);
        let key = res["registration_key"].as_str().unwrap().to_owned();
        assert!(!key.is_empty());

        // The minted key enrolls exactly one user, who is User-role ONLY (only the
        // first-ever registrant — here the genesis `admin` — is admin).
        let sk = SigningKey::generate();
        let (st, _) = post_json(&app, "/v1/users", register_body(&sk, "viakey", &key)).await;
        assert_eq!(st, StatusCode::CREATED);
        let (_st, body) = get_json(&app, "/v1/directory/viakey").await;
        let bytes = B64.decode(body["binding_b64"].as_str().unwrap()).unwrap();
        let binding = decode::<DirBinding>(&bytes).unwrap();
        assert!(binding.roles.roles().contains(&Role::User));
        assert!(
            !binding.roles.roles().contains(&Role::Admin),
            "admin-minted keys are never admin"
        );

        // The minted key is single-use.
        let sk2 = SigningKey::generate();
        let (st, _) = post_json(&app, "/v1/users", register_body(&sk2, "again", &key)).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn non_admin_session_cannot_mint_or_post_control() {
        use maxsecu_admin_core::DirectorySigner;
        // A valid session with NO admin binding must be rejected (403, not 401) on
        // every admin-gated endpoint — the session is authentic, the authority is
        // not.
        let d5 = DirectorySigner::generate();
        let store = MemoryStore::new();
        let user_sk = SigningKey::generate();
        store.add_user(
            "plain",
            UserRecord {
                user_id: [0x0C; 16],
                enc_pub: [0xE3; 32],
                sig_pub: user_sk.verifying_key().to_bytes(),
            },
        );
        // No binding published for `plain` ⇒ not an admin.
        let app = app_with_directory_pub(store, d5.public_key());
        let token = login(&app, "plain", &user_sk).await;

        // Minting is admin-gated: an authentic non-admin session is refused.
        let (st, _) =
            post_json_auth(&app, "/v1/registration-keys", serde_json::json!({}), &token).await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        let (rec, sig) = revocation_b64([0u8; 32], 1, 0x96);
        let (st, _) = post_json_auth(
            &app,
            "/v1/revocations",
            serde_json::json!({"record_b64": rec, "sig_b64": sig}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    /// Like [`admin_app`] but the blob store is a [`TieredBlobStore`] over a
    /// [`MemoryColdTier`] holding `master`, with direct links **enabled** — for
    /// the §9.4 brokering path.
    ///
    /// [`TieredBlobStore`]: crate::tier::TieredBlobStore
    /// [`MemoryColdTier`]: crate::tier::MemoryColdTier
    fn admin_app_direct(master: &'static str) -> (Router, SigningKey, SigningKey) {
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
        let bob_sk = SigningKey::generate();
        store.add_user(
            "bob",
            UserRecord {
                user_id: [0xB0; 16],
                enc_pub: [0xE2; 32],
                sig_pub: bob_sk.verifying_key().to_bytes(),
            },
        );
        let cold = Arc::new(crate::tier::MemoryColdTier::with_master_token(master));
        let cache = Arc::new(MemoryBlobStore::new());
        let blobs = Arc::new(crate::tier::TieredBlobStore::new(cache, cold, 1 << 20));
        let router = router(AppState {
            auth: Arc::new(AuthService::new(store, AuthConfig::default())),
            blobs,
            audit: Arc::new(crate::audit::NullAuditSink),
            direct_links_enabled: true,
            max_file_bytes: None,
        })
        .layer(Extension(TlsExporter(EXPORTER)));
        (router, admin_sk, bob_sk)
    }

    #[tokio::test]
    async fn direct_link_brokers_scoped_url_without_master_and_gates_access() {
        let master = "PROD-MASTER-TOKEN-never-leak";
        let (router, admin_sk, bob_sk) = admin_app_direct(master);
        let token = login(&router, "admin", &admin_sk).await;
        let owner = [0xAD; 16];
        let file = [0xF7u8; 16];

        let (st, _) =
            post_json_auth(&router, "/v1/files", create_file_body(file, owner), &token).await;
        assert_eq!(st, StatusCode::CREATED);
        upload_declared_chunks(&router, file, 1, &token).await;
        let (st, _) = post_json_auth(
            &router,
            &format!("/v1/files/{}/versions/1/finalize", hex_encode(&file)),
            serde_json::json!({}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // Broker a scoped link for content chunk 0 → 200; the master token never
        // appears, and the TTL is the §8 value.
        let dl_uri = format!("{}/direct-link", chunk_uri(file, 1, "content", 0));
        let (st, body) = post_json_auth(&router, &dl_uri, serde_json::json!({}), &token).await;
        assert_eq!(st, StatusCode::OK);
        let url = body["url"].as_str().unwrap();
        assert!(!url.contains(master), "master token leaked into direct link");
        assert_eq!(body["expires_in_s"].as_u64().unwrap(), 900);

        // A non-recipient gets the uniform 404 (no access oracle).
        let bob = login(&router, "bob", &bob_sk).await;
        let (st, _) = post_json_auth(&router, &dl_uri, serde_json::json!({}), &bob).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // An absent chunk index → 404 (no oracle).
        let (st, _) = post_json_auth(
            &router,
            &format!("{}/direct-link", chunk_uri(file, 1, "content", 99)),
            serde_json::json!({}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
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
        let (router, admin_sk, bob_sk) = admin_app().await;
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
        // A dir signer is configured so enrollment reaches the (faulting) store
        // rather than short-circuiting on "enrollment disabled".
        let signer = Arc::new(SigningKey::generate());
        let dir_pub = signer.verifying_key().to_bytes();
        let state = AppState {
            auth: Arc::new(
                AuthService::new(FaultyStore, AuthConfig::default().with_directory_pub(dir_pub))
                    .with_dir_signer(signer),
            ),
            blobs: Arc::new(MemoryBlobStore::new()),
            audit: Arc::new(crate::audit::NullAuditSink),
            direct_links_enabled: false,
            max_file_bytes: None,
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

        // register: a reg-key-table fault → 500, not a misleading 403 "bad key".
        let sk = SigningKey::generate();
        let (_esk, epk) = generate_enc_keypair();
        let (st, _) = post_json(
            &router,
            "/v1/users",
            serde_json::json!({
                "username": "bob",
                "enc_pub_b64": b64encode(&epk.to_bytes()),
                "sig_pub_b64": b64encode(&sk.verifying_key().to_bytes()),
                "registration_key": "code",
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
        let (router, admin_sk, bob_sk) = admin_app().await;
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

        // Cache-miss progress (api §9.3): over a plain (non-tiered) store the
        // chunk is local, so its status is `cache`; an absent index is 404.
        let (st, body) = get_json_auth(
            &router,
            &format!("{}/status", chunk_uri(file, 1, "content", 0)),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["source"], "cache");
        assert_eq!(body["total_bytes"].as_u64().unwrap(), 32);
        let (st, _) = get_json_auth(
            &router,
            &format!("{}/status", chunk_uri(file, 1, "content", 99)),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Direct links are off by default (opt-in) → uniform 403 direct_disabled,
        // short-circuited before any access check (no oracle).
        let (st, body) = post_json_auth(
            &router,
            &format!("{}/direct-link", chunk_uri(file, 1, "content", 0)),
            serde_json::json!({}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "direct_disabled");

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
        // Status leaks no access oracle either — same uniform 404.
        let (st, _) = get_json_auth(
            &router,
            &format!("{}/status", chunk_uri(file, 1, "content", 0)),
            &bob,
        )
        .await;
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
        let (router, admin_sk, bob_sk) = admin_app().await;
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
        let (router, admin_sk, bob_sk) = admin_app().await;
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
        let (router, admin_sk, bob_sk, audit) = admin_app_audited().await;
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
    async fn sink_records_control_head_and_genesis_anchor() {
        let (router, admin_sk, _bob_sk, audit) = admin_app_audited().await;
        let owner = [0xADu8; 16];
        let token = login(&router, "admin", &admin_sk).await;

        // A control append publishes the new head to the sink (api.md §7.2/§6).
        let (rec1, sig1) = revocation_b64([0u8; 32], 1, 0x99);
        let (st, res) = post_json_auth(
            &router,
            "/v1/revocations",
            serde_json::json!({"record_b64": rec1, "sig_b64": sig1}),
            &token,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (seq, head) = audit.latest_head().expect("head published to the sink");
        assert_eq!(seq, 1);
        assert_eq!(b64encode(&head), res["chain_head_b64"].as_str().unwrap());

        // Creating a file (v1) anchors its genesis in the sink (R27/§11.7).
        let file = [0xFAu8; 16];
        assert!(audit.genesis_pos(&file).is_none(), "no genesis before create");
        create_finalize_v1(&router, file, owner, &token).await;
        assert!(audit.genesis_pos(&file).is_some(), "genesis anchored at create");
    }

    #[tokio::test]
    async fn file_upload_redteam_status_codes() {
        let (router, admin_sk, bob_sk) = admin_app().await;
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
