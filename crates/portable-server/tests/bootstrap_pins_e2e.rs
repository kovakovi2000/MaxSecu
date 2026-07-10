//! e2e for the in-band pin bootstrap endpoint (design
//! `2026-07-10-in-band-pin-bootstrap-design.md`, §2). Stands up a REAL in-process
//! launcher via [`maxsecu_portable_server::run::prepare`], serves it over its own
//! TLS, dials `GET /v1/bootstrap/pins` with certificate verification DISABLED
//! (accept-any — safe here because we authenticate the PAYLOAD, not the transport),
//! and proves:
//!   * the base64 fields decode BYTE-IDENTICALLY to `client-pins/*.der` on disk;
//!   * `maxsecu_crypto::pin_fingerprint` over the SERVED bytes is 32 chars and
//!     equals the fingerprint over the ON-DISK pin files (served == pins).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
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

use maxsecu_portable_server::config::{LauncherConfig, Profile};
use maxsecu_portable_server::run::prepare;
use maxsecu_server::serve;

/// Accept-any TLS verifier for the test dial only. NO validation — the payload is
/// fingerprint-verified after the fetch, exactly as the real `fetch-pins` flow does.
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

fn unpinned_connector() -> TlsConnector {
    let cfg = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

fn tempdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "maxsecu-bootstrap-pins-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test]
async fn bootstrap_pins_endpoint_serves_bytes_identical_to_client_pins() {
    let data_dir = tempdir();
    let data_dir_s = data_dir.to_str().unwrap().to_owned();

    // Fresh temp data_dir, ephemeral port, Dev profile (no DATABASE_URL).
    let cfg = LauncherConfig::from_parts(|k| match k {
        "MAXSECU_DATA_DIR" => Some(data_dir_s.clone()),
        "MAXSECU_PORT" => Some("0".to_owned()),
        _ => None,
    });
    assert_eq!(cfg.profile, Profile::Dev);

    let prepared = prepare(&cfg).await.expect("prepare launcher");
    let addr = prepared.local_addr;
    tokio::spawn(serve(
        prepared.listener,
        prepared.server_config,
        prepared.router,
    ));

    // --- accept-any TLS GET /v1/bootstrap/pins ------------------------------
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = unpinned_connector()
        .connect(server_name, tcp)
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri("/v1/bootstrap/pins")
        .header(hyper::header::HOST, "localhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body = resp.into_body().collect().await.unwrap().to_bytes();

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let served_cert = B64
        .decode(json["server_cert_b64"].as_str().unwrap())
        .unwrap();
    let served_dir = B64
        .decode(json["directory_pub_b64"].as_str().unwrap())
        .unwrap();

    // --- served bytes are byte-identical to client-pins/*.der ---------------
    let disk_cert = std::fs::read(data_dir.join("client-pins").join("server_cert.der")).unwrap();
    let disk_dir = std::fs::read(data_dir.join("client-pins").join("directory_pub.der")).unwrap();
    assert_eq!(
        served_cert, disk_cert,
        "served server_cert must byte-match client-pins/server_cert.der"
    );
    assert_eq!(
        served_dir, disk_dir,
        "served directory_pub must byte-match client-pins/directory_pub.der"
    );

    // --- fingerprint: 32 chars, and served == on-disk pins ------------------
    let served_fp = maxsecu_crypto::pin_fingerprint(&served_cert, &served_dir);
    assert_eq!(served_fp.len(), 32, "fingerprint must be exactly 32 chars");
    let disk_fp = maxsecu_crypto::pin_fingerprint(&disk_cert, &disk_dir);
    assert_eq!(
        served_fp, disk_fp,
        "fingerprint over served bytes must equal fingerprint over on-disk pins"
    );
}
