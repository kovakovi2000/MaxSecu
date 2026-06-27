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
use crate::error::ProveError;
use crate::store::Store;
use axum::extract::{FromRequestParts, Json, State};
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
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
}

impl<S: Store> Clone for AppState<S> {
    fn clone(&self) -> Self {
        AppState {
            auth: self.auth.clone(),
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
    if !st.auth.store().consume_voucher(&voucher_hash).await {
        return Err(StatusCode::FORBIDDEN);
    }
    match st
        .auth
        .store()
        .create_user(&req.username, enc_pub, sig_pub)
        .await
    {
        Some(user_id) => Ok((
            StatusCode::CREATED,
            Json(RegisterRes {
                user_id: hex_encode(&user_id),
            }),
        )),
        None => Err(StatusCode::CONFLICT), // username taken
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
        Err(rl) => rate_limited(rl.retry_after_s),
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
        // … but a throttled attempt is the one deliberately-distinct 429 signal.
        Err(ProveError::RateLimited { retry_after_s }) => rate_limited(retry_after_s),
    }
}

// ---- POST /v1/session/logout (api.md §2.4) ----

async fn logout<S: Store + 'static>(
    State(st): State<AppState<S>>,
    session: AuthedSession,
) -> StatusCode {
    st.auth.logout(&session.token).await;
    StatusCode::NO_CONTENT
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
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(AuthedSession { user_id, token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use crate::store::{MemoryStore, UserRecord};
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
