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
use crate::store::Store;
use axum::extract::{FromRequestParts, Json, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{request::Parts, StatusCode};
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
        .route("/v1/session/challenge", post(challenge::<S>))
        .route("/v1/session/proof", post(prove::<S>))
        .route("/v1/session/logout", post(logout::<S>))
        .with_state(state)
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
) -> Json<ChallengeRes> {
    // A well-formed challenge is returned for unknown usernames too (§9.3).
    let ch = st.auth.challenge(&req.username, now_ms()).await;
    Json(ChallengeRes {
        nonce_b64: b64encode(&ch.nonce),
        server_id: ch.server_id,
        expires_in_s: ch.expires_in_s,
    })
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
) -> Result<Json<ProveRes>, StatusCode> {
    let proof = b64_fixed::<64>(&req.proof_b64).ok_or(StatusCode::BAD_REQUEST)?;
    match st
        .auth
        .prove(&req.username, req.timestamp, &proof, &exporter.0, now_ms())
        .await
    {
        Ok(token) => Ok(Json(ProveRes {
            session_token: token.to_hex(),
            expires_in_s: 3600,
        })),
        // Single 401 shape for every cause — no oracle (§3).
        Err(_) => Err(StatusCode::UNAUTHORIZED),
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
    use maxsecu_crypto::SigningKey;
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
