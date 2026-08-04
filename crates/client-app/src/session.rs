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

/// Build the `POST /v1/session/challenge` body — PURE, so the wire shape is
/// testable without a network (`tests/compat.rs`). `username` is the ONLY key the
/// server's challenge handler reads; dropping/renaming it locks every existing
/// user out of login.
pub fn build_session_challenge_body(username: &str) -> serde_json::Value {
    serde_json::json!({ "username": username })
}

/// Build the `POST /v1/session/proof` body — PURE (see above). All three keys are
/// read by the server's `prove` handler: dropping any of them makes the
/// channel-bound proof unverifiable and locks every existing user out of login.
pub fn build_session_prove_body(
    username: &str,
    timestamp_ms: u64,
    proof_b64: &str,
) -> serde_json::Value {
    serde_json::json!({ "username": username, "timestamp": timestamp_ms, "proof_b64": proof_b64 })
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

/// The shared non-oracle failure: every CREDENTIAL login error (bad password
/// match, unknown user, expired/replayed nonce) collapses to one sanitized shape
/// so the UI cannot distinguish "unknown user" from "wrong key" from "stale
/// nonce".
///
/// The non-oracle rule constrains CREDENTIAL outcomes only. A dead socket and a
/// server-side throttle say nothing about anybody's credentials, so they get their
/// own honest codes ([`offline`] / [`RATE_LIMITED`]) — collapsing them in here is
/// what made a throttled account look to the user like a wrong password.
fn unauthorized() -> UiError {
    UiError::new("unauthorized", "Sign-in failed.")
}

/// A TRANSPORT fault (socket never came ready, request never left, reply never
/// arrived / was unreadable). Same code + wording the rest of the client uses
/// (`http_client.rs`) so the UI's offline handling is uniform.
fn offline(message: &str) -> UiError {
    UiError::new("offline", message)
}

/// The server's per-account anti-automation throttle (`HTTP 429`,
/// `server::ratelimit`): at most 30 challenges per account per rolling 60 s, plus
/// an exponential backoff after a failed proof. This is NOT a credential outcome
/// and NOT an oracle — `server/src/http.rs` documents 429 as the ONE response
/// shape deliberately distinct from the uniform 401, precisely so a client can
/// tell "you are going too fast" apart from "that key is wrong".
pub const RATE_LIMITED: &str = "rate_limited";

/// The throttled shape, carrying the server's `Retry-After` so the caller can wait
/// the real interval instead of reporting a credential failure — and SAYING that
/// interval in the message.
///
/// The message carries the interval because `retry_after_s` alone is machine-facing:
/// an already-shipped `ui/dist` renders `message` verbatim and knows nothing about
/// the new field, so a UI that never learns to read it would still show a bare "wait
/// a moment". Putting the number in the text the Rust side produces means every
/// build of the UI — old or new — tells the user how long. (A UI that DOES read
/// `retry_after_s` can still render its own countdown; the field is unchanged.)
fn rate_limited(retry_after_s: Option<u64>) -> UiError {
    UiError::new(RATE_LIMITED, &throttle_message(retry_after_s)).with_retry_after(retry_after_s)
}

/// The user-facing throttle sentence, naming the server's interval when it sent one.
/// Pure — unit-tested. Falls back to the interval-free wording when the server sent
/// no (or a zero) `Retry-After`, rather than inventing a number.
fn throttle_message(retry_after_s: Option<u64>) -> String {
    match retry_after_s {
        Some(1) => "The server is limiting sign-in attempts right now. Wait about 1 second and try again.".to_owned(),
        Some(s) if s > 0 => format!(
            "The server is limiting sign-in attempts right now. Wait about {s} seconds and try again."
        ),
        _ => "The server is limiting sign-in attempts right now. Wait a moment and try again."
            .to_owned(),
    }
}

/// Parse an HTTP `Retry-After` value in its delta-seconds form (what
/// `server::http::rate_limited` sends). The HTTP-date form is legal but the server
/// never emits it, so it yields `None` — the caller then falls back to its own
/// default wait rather than mis-parsing a date as a duration. Pure — unit-tested.
fn parse_retry_after(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(hyper::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// One collected login-exchange response. Carries the `Retry-After` seconds
/// alongside the status because the throttle interval lives ONLY in the headers —
/// the 429 body is empty — and dropping the headers is what left the client unable
/// to distinguish (or wait out) a throttle.
struct LoginResp {
    status: StatusCode,
    retry_after_s: Option<u64>,
    json: serde_json::Value,
}

/// POST a JSON body over an established hyper sender and collect the response.
async fn post_json(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    uri: &str,
    body: serde_json::Value,
) -> Result<LoginResp, UiError> {
    sender
        .ready()
        .await
        .map_err(|_| offline("Lost connection to the server."))?;
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|_| UiError::new("internal", "Could not build the request."))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| offline("The server did not respond."))?;
    let status = resp.status();
    let retry_after_s = parse_retry_after(resp.headers());
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|_| offline("The response was interrupted."))?
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|_| offline("The server's reply was unreadable."))?
    };
    Ok(LoginResp {
        status,
        retry_after_s,
        json,
    })
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
    let ch = post_json(
        sender,
        host,
        "/v1/session/challenge",
        build_session_challenge_body(username),
    )
    .await?;
    // The throttle BEFORE the credential collapse: a 429 means the account's
    // challenge-issuance cap is spent, not that anything is wrong with the key.
    if ch.status == StatusCode::TOO_MANY_REQUESTS {
        return Err(rate_limited(ch.retry_after_s));
    }
    if !ch.status.is_success() {
        return Err(unauthorized());
    }
    let ch = ch.json;
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
    let res = post_json(
        sender,
        host,
        "/v1/session/proof",
        build_session_prove_body(username, now_ms, &proof_b64),
    )
    .await?;
    // The proof leg has its OWN 429 (the failed-proof exponential backoff), same
    // reasoning as the challenge leg above.
    if res.status == StatusCode::TOO_MANY_REQUESTS {
        return Err(rate_limited(res.retry_after_s));
    }
    if !res.status.is_success() {
        return Err(unauthorized());
    }
    let res = res.json;
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

    /// The throttle interval lives only in the header, so parsing it is the whole
    /// difference between "wait 37 s" and a bare credential failure.
    #[test]
    fn retry_after_parses_the_delta_seconds_form() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::RETRY_AFTER, "37".parse().unwrap());
        assert_eq!(parse_retry_after(&h), Some(37));
        // Surrounding whitespace is tolerated.
        h.insert(hyper::header::RETRY_AFTER, " 5 ".parse().unwrap());
        assert_eq!(parse_retry_after(&h), Some(5));
        // Absent, or the HTTP-date form the server never sends → no interval (the
        // caller falls back to its own default wait rather than mis-reading a date).
        assert_eq!(parse_retry_after(&hyper::HeaderMap::new()), None);
        h.insert(
            hyper::header::RETRY_AFTER,
            "Wed, 21 Oct 2026 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(parse_retry_after(&h), None);
    }

    /// A throttled login must NOT wear the credential shape: it carries the
    /// distinct `rate_limited` code plus the interval, so the caller can back off
    /// and the user is not told their password is wrong.
    #[test]
    fn throttled_shape_is_distinct_from_the_credential_shape() {
        let e = rate_limited(Some(58));
        assert_eq!(e.code, RATE_LIMITED);
        assert_eq!(e.retry_after_s, Some(58));
        assert_ne!(e.code, unauthorized().code);
        assert_eq!(unauthorized().retry_after_s, None);
        // A transport fault is `offline`, not a credential failure.
        assert_eq!(offline("x").code, "offline");
    }

    /// The interval must reach the USER, not just the machine field: an
    /// already-shipped `ui/dist` renders `message` verbatim, so the number has to be
    /// in the sentence or nobody ever sees it.
    #[test]
    fn the_throttle_message_names_the_interval() {
        assert!(
            rate_limited(Some(37)).message.contains("37 seconds"),
            "the user must be told how long to wait, not just 'a moment'"
        );
        assert!(throttle_message(Some(1)).contains("1 second and"));
        assert!(!throttle_message(Some(1)).contains("1 seconds"));
        // No interval from the server ⇒ no invented number.
        for m in [throttle_message(None), throttle_message(Some(0))] {
            assert!(m.contains("Wait a moment"));
            assert!(!m.contains("seconds"));
        }
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
