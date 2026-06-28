//! Login orchestration. The transport does challenge→proof; this module builds
//! the channel-bound proof from the unlocked Identity and the live exporter.

use crate::error::UiError;
use maxsecu_client_core::auth::build_login_proof;
use maxsecu_client_core::Identity;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};

/// Build the channel-bound Ed25519 login proof (raw 64-byte signature) the
/// client base64-encodes and posts to /v1/session/proof in Task 8.
pub fn make_proof(
    id: &Identity,
    server_id: &str,
    exporter: &[u8; 32],
    nonce: &[u8; 32],
    timestamp_ms: u64,
) -> Result<[u8; 64], UiError> {
    build_login_proof(id, server_id, exporter, nonce, timestamp_ms)
        .map_err(|_| UiError::new("unauthorized", "Sign-in failed."))
}

/// The successful outcome of [`login_exchange`]: the server's self-asserted id
/// (public; safe to return to the UI), the opaque session token (kept in
/// managed state, NEVER returned to the UI), and the token lifetime.
#[derive(Debug, Clone)]
pub struct LoginOk {
    pub server_id: String,
    pub token: String,
    // Read by the Task 11 e2e and by future session-expiry / re-auth handling
    // (state.rs SessionExpired/Reauthenticating); not yet consumed by `connect`.
    #[allow(dead_code)]
    pub expires_in_s: u64,
}

/// The shared non-oracle failure: every login error (network, parse, bad
/// password match, expired challenge) collapses to one sanitized shape so the
/// UI cannot distinguish "unknown user" from "wrong key" from "stale nonce".
fn unauthorized() -> UiError {
    UiError::new("unauthorized", "Sign-in failed.")
}

/// POST a JSON body over an established hyper sender and collect the response.
async fn post_json(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    uri: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), UiError> {
    sender.ready().await.map_err(|_| unauthorized())?;
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|_| unauthorized())?;
    let resp = sender.send_request(req).await.map_err(|_| unauthorized())?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|_| unauthorized())?
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|_| unauthorized())?
    };
    Ok((status, json))
}

/// Run `/v1/session/challenge` then `/v1/session/proof` over an already-connected,
/// channel-bound hyper sender. `exporter` is this connection's RFC 5705 value;
/// challenge and proof MUST share the same connection (per-connection exporter).
/// All failures collapse to the non-oracle `unauthorized` shape.
pub async fn login_exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    id: &Identity,
    username: &str,
    host: &str,
    exporter: &[u8; 32],
    now_ms: u64,
) -> Result<LoginOk, UiError> {
    // `host` is the connect host (the cert-SAN/SNI name). The TLS SNI + pinned
    // cert (transport.rs) are the real identity check; the Host header is carried
    // through for the server's routing/vhost rather than left hardcoded.

    // 1) challenge
    let (status, ch) = post_json(
        sender,
        host,
        "/v1/session/challenge",
        serde_json::json!({ "username": username }),
    )
    .await?;
    if !status.is_success() {
        return Err(unauthorized());
    }
    let server_id = ch
        .get("server_id")
        .and_then(|v| v.as_str())
        .ok_or_else(unauthorized)?
        .to_owned();
    let nonce_b64 = ch
        .get("nonce_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(unauthorized)?;
    let nonce_vec = B64.decode(nonce_b64).map_err(|_| unauthorized())?;
    let nonce: [u8; 32] = nonce_vec.try_into().map_err(|_| unauthorized())?;

    // 2) proof — channel-bound to THIS connection's exporter + the server's id.
    let proof = make_proof(id, &server_id, exporter, &nonce, now_ms)?;
    let proof_b64 = B64.encode(proof);
    let (status, res) = post_json(
        sender,
        host,
        "/v1/session/proof",
        serde_json::json!({ "username": username, "timestamp": now_ms, "proof_b64": proof_b64 }),
    )
    .await?;
    if !status.is_success() {
        return Err(unauthorized());
    }
    let token = res
        .get("session_token")
        .and_then(|v| v.as_str())
        .ok_or_else(unauthorized)?
        .to_owned();
    let expires_in_s = res
        .get("expires_in_s")
        .and_then(|v| v.as_u64())
        .ok_or_else(unauthorized)?;

    Ok(LoginOk {
        server_id,
        token,
        expires_in_s,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::auth::verify_login_proof;

    #[test]
    fn built_proof_verifies_like_the_server_would() {
        let id = Identity::generate();
        let server_id = "maxsecu-test-1";
        let exporter = [0x42u8; 32];
        let nonce = [0x07u8; 32];
        let ts = 1_719_500_000_000u64;
        let proof = make_proof(&id, server_id, &exporter, &nonce, ts).unwrap();
        // Exactly what the server runs in api.md §2.2:
        assert!(verify_login_proof(
            &id.sig_pub_bytes(),
            server_id,
            &exporter,
            &nonce,
            ts,
            &proof
        )
        .is_ok());
    }

    #[test]
    fn proof_is_channel_bound() {
        let id = Identity::generate();
        let proof = make_proof(&id, "s", &[1u8; 32], &[2u8; 32], 1).unwrap();
        // A different exporter (relayed connection) must not verify.
        assert!(
            verify_login_proof(&id.sig_pub_bytes(), "s", &[9u8; 32], &[2u8; 32], 1, &proof)
                .is_err()
        );
    }
}
