//! `fetch-pins` mode (spec §4): fetch the public trust-anchor pin(s) from the
//! server over the network and trust them ONLY if they hash to the
//! operator-supplied fingerprint code. Two modes:
//!
//!   * **2-pin** (`dir_out = Some`): verify `pin_fingerprint(cert, dir)` and write
//!     BOTH `server_cert.der` + `directory_pub.der` (the post-delegation / rebuild
//!     path, where the server serves the real D5 directory pin).
//!   * **cert-only** (`dir_out = None`, offline-D5 ceremony, spec §§6,7): the
//!     server is still AWAITING delegation, so it has no directory pin yet — the D5
//!     originates on the admin PC. Verify `pin_fingerprint(cert, &[])` against the
//!     server's **cert fingerprint** (printed by `maxsecu-portable-server
//!     print-cert-fingerprint`) and write ONLY `server_cert.der`. The ceremony then
//!     writes `directory_pub.der` locally from the freshly-generated D5.
//!
//! Trust model: the pins are PUBLIC data; we need integrity, not secrecy. The
//! transport here is deliberately UNauthenticated (accept-any-cert) — a MITM can
//! only relay the genuine bytes or substitute different ones, and substituted bytes
//! cannot match the fingerprint (SHA-256 second-preimage resistance). The payload is
//! authenticated by `maxsecu_crypto::pin_fingerprint`, NOT by the TLS handshake.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use tokio_rustls::TlsConnector;

/// !!! DANGER — ACCEPT-ANY server-certificate verifier. !!!
///
/// This verifier performs NO certificate validation whatsoever: it accepts every
/// server cert and every handshake signature. That is SAFE **ONLY** in this
/// `fetch-pins` flow because the bytes we download are fingerprint-verified against
/// an out-of-band operator code IMMEDIATELY after the fetch (see
/// [`fetch_and_verify`]). It authenticates the PAYLOAD, not the transport. Do NOT
/// reuse this type anywhere that relies on the TLS handshake for authentication —
/// the real app transport pins the server cert (see `client-app::transport`).
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build an UNPINNED rustls client config (accept-any cert — see [`AcceptAnyServerCert`]).
fn unpinned_client_config() -> Result<Arc<ClientConfig>, String> {
    let cfg = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Normalize a fingerprint for comparison: uppercase, then strip every char not in
/// the RFC 4648 base32 alphabet `[A-Z2-7]` (so copy-introduced dashes/spaces/newlines
/// do not break the compare). Mirrors the spec's normalization rule.
fn normalize_fp(s: &str) -> String {
    s.to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_uppercase() || ('2'..='7').contains(c))
        .collect()
}

/// Fetch `/v1/bootstrap/pins` from `server` (dial target `ADDR:PORT`) over an
/// UNpinned TLS connection using `host` as the SNI/Host header, verify the returned
/// pin(s) against `fingerprint`, and — ONLY on a match — write the pin file(s).
///
/// `dir_out = Some(path)` selects **2-pin** mode: verify `pin_fingerprint(cert,
/// dir)` and write both files. `dir_out = None` selects **cert-only** mode (the
/// offline-D5 ceremony, server still awaiting): verify `pin_fingerprint(cert, &[])`
/// against the server's cert fingerprint and write ONLY `cert_out` — the server's
/// directory pin (if any) is ignored, because the D5 originates on the admin PC.
///
/// On ANY failure (network / TLS / HTTP / JSON / base64 / fingerprint mismatch) this
/// writes NOTHING and returns `Err`. No pin file is ever created before the
/// fingerprint match succeeds.
pub async fn fetch_and_verify(
    server: &str,
    host: &str,
    fingerprint: &str,
    cert_out: &Path,
    dir_out: Option<&Path>,
) -> Result<(), String> {
    // --- dial + unpinned TLS -------------------------------------------------
    let tcp = tokio::net::TcpStream::connect(server)
        .await
        .map_err(|e| format!("could not connect to {server}: {e}"))?;
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| format!("invalid --host value {host:?}"))?;
    let connector = TlsConnector::from(unpinned_client_config()?);
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake with {server} failed: {e}"))?;

    // --- HTTP/1.1 GET /v1/bootstrap/pins ------------------------------------
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| format!("HTTP handshake failed: {e}"))?;
    tokio::spawn(async move {
        // Drives the connection I/O; ends when the response is fully read.
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri("/v1/bootstrap/pins")
        .header(hyper::header::HOST, host)
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("build request: {e}"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("request to {server} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!(
            "server returned HTTP {status} for /v1/bootstrap/pins"
        ));
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("reading response body: {e}"))?
        .to_bytes();

    // --- parse JSON + base64-decode the cert (dir only in 2-pin mode) -------
    let json: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| format!("invalid JSON in bootstrap response: {e}"))?;
    let cert_b64 = json
        .get("server_cert_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "bootstrap response missing string field `server_cert_b64`".to_owned())?;
    let cert = base64::engine::general_purpose::STANDARD
        .decode(cert_b64)
        .map_err(|e| format!("server_cert_b64 is not valid base64: {e}"))?;

    // In 2-pin mode the directory pin is required and hashed alongside the cert;
    // in cert-only mode (ceremony, server awaiting) the fingerprint commits to the
    // cert alone (`pin_fingerprint(cert, &[])`) and any server-served dir is ignored.
    let dir: Vec<u8> = if dir_out.is_some() {
        let dir_b64 = json
            .get("directory_pub_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                "bootstrap response missing string field `directory_pub_b64`".to_owned()
            })?;
        base64::engine::general_purpose::STANDARD
            .decode(dir_b64)
            .map_err(|e| format!("directory_pub_b64 is not valid base64: {e}"))?
    } else {
        Vec::new()
    };

    // --- fingerprint gate (authenticate the PAYLOAD) ------------------------
    let computed = maxsecu_crypto::pin_fingerprint(&cert, &dir);
    if normalize_fp(&computed) != normalize_fp(fingerprint) {
        return Err(format!(
            "fingerprint MISMATCH — refusing to trust these pins. \
             expected {}, server's pins hash to {}. \
             Wrong address, wrong/stale connection code, or a man-in-the-middle. \
             Nothing was written.",
            normalize_fp(fingerprint),
            normalize_fp(&computed),
        ));
    }

    // --- match: NOW (and only now) write the pin file(s) --------------------
    std::fs::write(cert_out, &cert).map_err(|e| format!("write {}: {e}", cert_out.display()))?;
    if let Some(dir_out) = dir_out {
        std::fs::write(dir_out, &dir).map_err(|e| format!("write {}: {e}", dir_out.display()))?;
    }
    Ok(())
}
