//! e2e for the `fetch-pins` flow (design `2026-07-10-in-band-pin-bootstrap-design.md`
//! §4) exercising the REAL `maxsecu_setup::fetch::fetch_and_verify`.
//!
//! A minimal loopback TLS server (self-signed, rcgen — the `test_pki` pattern from
//! `setup_e2e.rs`) answers ANY HTTP/1 request with a hand-written
//! `200 application/json` body carrying two chosen pin blobs base64-encoded. We then:
//!   * POSITIVE — fetch with the CORRECT fingerprint: `Ok`, and both out files match
//!     the served blobs byte-for-byte;
//!   * NEGATIVE — fetch with a MUTATED fingerprint: `Err`, and NEITHER out file exists
//!     (the flow writes nothing on failure).

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

// Chosen pin blobs — distinct, non-trivial patterns so a swapped field is caught.
fn cert_blob() -> Vec<u8> {
    (0u16..300).map(|n| (n % 251) as u8).collect()
}
fn dir_blob() -> Vec<u8> {
    (0u16..64).map(|n| (200 - (n % 200)) as u8).collect()
}

/// Self-signed loopback TLS config (mirrors `setup_e2e.rs::test_pki`).
fn test_server_config() -> Arc<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    Arc::new(cfg)
}

/// Start a loopback TLS server that answers ANY HTTP/1 request with the fixed pins
/// JSON. Serves connections until the test drops (spawned, detached). Returns its
/// bound address.
async fn start_pins_server() -> std::net::SocketAddr {
    let acceptor = TlsAcceptor::from(test_server_config());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let body = format!(
        "{{\"server_cert_b64\":\"{}\",\"directory_pub_b64\":\"{}\"}}",
        B64.encode(cert_blob()),
        B64.encode(dir_blob()),
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    );

    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let acceptor = acceptor.clone();
            let response = response.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                // Read the request bytes until the blank line terminating the headers.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match tls.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });

    addr
}

fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "maxsecu-fetch-pins-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test]
async fn fetch_pins_writes_exact_bytes_on_matching_fingerprint() {
    let addr = start_pins_server().await;
    let server = addr.to_string();
    let dir = tempdir();
    let cert_out = dir.join("server_cert.der");
    let dir_out = dir.join("directory_pub.der");

    // Correct fingerprint over the served blobs.
    let fp = maxsecu_crypto::pin_fingerprint(&cert_blob(), &dir_blob());

    maxsecu_setup::fetch::fetch_and_verify(&server, "localhost", &fp, &cert_out, &dir_out)
        .await
        .expect("fetch-pins succeeds on matching fingerprint");

    assert_eq!(
        std::fs::read(&cert_out).unwrap(),
        cert_blob(),
        "written server_cert.der must byte-match the served cert blob"
    );
    assert_eq!(
        std::fs::read(&dir_out).unwrap(),
        dir_blob(),
        "written directory_pub.der must byte-match the served dir blob"
    );
}

#[tokio::test]
async fn fetch_pins_writes_nothing_on_fingerprint_mismatch() {
    let addr = start_pins_server().await;
    let server = addr.to_string();
    let dir = tempdir();
    let cert_out = dir.join("server_cert.der");
    let dir_out = dir.join("directory_pub.der");

    // Mutate one char of the correct fingerprint so verification MUST fail.
    let fp = maxsecu_crypto::pin_fingerprint(&cert_blob(), &dir_blob());
    let mut chars: Vec<char> = fp.chars().collect();
    // Flip the first char to a different base32 letter (A<->B).
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    let bad_fp: String = chars.into_iter().collect();
    assert_ne!(
        bad_fp, fp,
        "mutated fingerprint must differ from the real one"
    );

    let err =
        maxsecu_setup::fetch::fetch_and_verify(&server, "localhost", &bad_fp, &cert_out, &dir_out)
            .await
            .expect_err("fetch-pins must fail on a mismatched fingerprint");
    assert!(
        err.to_lowercase().contains("mismatch"),
        "error should mention the fingerprint mismatch, got: {err}"
    );

    // Nothing written on failure.
    assert!(!cert_out.exists(), "no server_cert.der written on mismatch");
    assert!(
        !dir_out.exists(),
        "no directory_pub.der written on mismatch"
    );
}
