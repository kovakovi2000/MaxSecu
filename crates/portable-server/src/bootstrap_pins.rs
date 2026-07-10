//! In-band pin bootstrap endpoint for the portable launcher (design
//! `2026-07-10-in-band-pin-bootstrap-design.md`, §2). Exposes the two PUBLIC
//! trust anchors — the self-signed TLS cert and the Ed25519 directory public key
//! — over `GET /v1/bootstrap/pins` so the client installer can fetch them over
//! the network instead of scp.
//!
//! **Unauthenticated by design.** Both pins are public data; the payload's
//! integrity is protected out-of-band by the fingerprint carried in the
//! operator's connection code (the client recomputes
//! `maxsecu_crypto::pin_fingerprint` and trusts the bytes only on a match). No
//! secret is served here.
//!
//! This lives in the launcher (not the generic `server` crate) so it can close
//! over the concrete pin bytes without touching `AppState<S>`.

use axum::{routing::get, Json, Router};
use base64::Engine;
use serde::Serialize;

/// JSON body of `GET /v1/bootstrap/pins`: STANDARD base64 of each raw DER pin.
#[derive(Serialize, Clone)]
struct PinsResponse {
    server_cert_b64: String,
    directory_pub_b64: String,
}

/// Build the response body from the raw DER pins (STANDARD base64, no url-safe
/// substitution). Split out so the unit test exercises the exact bytes the
/// handler emits without needing an HTTP harness.
fn encode_pins(cert_der: &[u8], dir_der: &[u8]) -> PinsResponse {
    let b64 = base64::engine::general_purpose::STANDARD;
    PinsResponse {
        server_cert_b64: b64.encode(cert_der),
        directory_pub_b64: b64.encode(dir_der),
    }
}

/// A router exposing `GET /v1/bootstrap/pins`, closing over the pin bytes.
///
/// The served bytes are exactly the `cert_der` / `dir_der` passed in (the caller
/// reads them from `client-pins/*.der`, so the response is byte-identical to
/// those files after base64 round-trip). The body is encoded once up front (it
/// is small and fixed for the process lifetime) and each request gets a clone.
pub fn router(cert_der: Vec<u8>, dir_der: Vec<u8>) -> Router {
    let body = encode_pins(&cert_der, &dir_der);
    Router::new().route(
        "/v1/bootstrap/pins",
        get(move || {
            let body = body.clone();
            async move { Json(body) }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_pins_json_base64_round_trips_to_exact_input_bytes() {
        // Distinct, non-trivial byte patterns so a swapped/garbled field is caught.
        let cert: Vec<u8> = (0u16..300).map(|n| (n % 251) as u8).collect();
        let dir: Vec<u8> = (0u16..64).map(|n| (200 - (n % 200)) as u8).collect();

        // Serialize exactly as the handler does (`Json(encode_pins(..))`).
        let json = serde_json::to_string(&encode_pins(&cert, &dir)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let cert_b64 = v["server_cert_b64"].as_str().unwrap();
        let dir_b64 = v["directory_pub_b64"].as_str().unwrap();

        let b64 = base64::engine::general_purpose::STANDARD;
        let cert_back = b64.decode(cert_b64).unwrap();
        let dir_back = b64.decode(dir_b64).unwrap();

        // The decoded base64 fields MUST equal the EXACT input bytes.
        assert_eq!(cert_back, cert, "server_cert_b64 must decode to input cert");
        assert_eq!(dir_back, dir, "directory_pub_b64 must decode to input dir");
    }
}
