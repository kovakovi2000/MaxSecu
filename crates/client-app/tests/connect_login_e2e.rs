//! Phase-1 exit gate: the REAL client-app modules drive a full connect +
//! channel-bound login against a REAL MaxSecu server over loopback TLS 1.3.
//!
//! This test deliberately reuses the production client code paths —
//! `transport::pinned_client_config`, `Transport::connect` (TLS + RFC 5705
//! exporter), and `session::{login_exchange, make_proof}` — rather than
//! reimplementing them. That reuse is the whole value of the gate: it proves the
//! shipped client can connect and authenticate, and that the proof it produces is
//! genuinely bound to its own TLS channel. No PostgreSQL: `MemoryStore` +
//! `MemoryBlobStore`, mirroring `crates/server/tests/tls_channel_binding.rs`.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::ServerConfig;

use maxsecu_client_app::session::make_proof;
use maxsecu_client_app::transport::{pinned_client_config, Transport};
use maxsecu_client_core::Identity;
use maxsecu_crypto::sha256;
use maxsecu_server::{serve, AppState, AuthConfig, AuthService, MemoryStore};

const VOUCHER: &str = "in-person-code-001";
const TS: u64 = 1_719_500_000_000;

/// A self-signed `localhost` cert: the server presents it; the client pins it.
struct TestPki {
    server_config: Arc<ServerConfig>,
    cert_der: CertificateDer<'static>,
}

fn test_pki() -> TestPki {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    TestPki {
        server_config: Arc::new(server_config),
        cert_der,
    }
}

/// Stand up the server on an ephemeral loopback port; return its address and the
/// pinned cert DER the client must trust. The auth router is backed by a
/// `MemoryStore` seeded with one enrollment voucher (no PostgreSQL).
async fn spawn_server() -> (std::net::SocketAddr, CertificateDer<'static>) {
    let pki = test_pki();

    let store = MemoryStore::new();
    store.add_voucher(sha256(VOUCHER.as_bytes()));
    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
        blobs: Arc::new(maxsecu_server::MemoryBlobStore::new()),
        audit: Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
    };
    let router = maxsecu_server::router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), router));
    (addr, pki.cert_der)
}

/// Build a `Transport` that pins `cert_der` and connects to `addr` as "localhost"
/// (the cert SAN — connecting by IP would fail the pinned verification).
fn transport_for(addr: std::net::SocketAddr, cert_der: CertificateDer<'static>) -> Transport {
    let cfg = pinned_client_config(cert_der).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    Transport::new(cfg, name, addr.to_string())
}

/// POST one JSON body over a hyper sender and return `(status, json)`, draining
/// the body so the keep-alive connection is reusable.
async fn post(
    sender: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    sender.ready().await.unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

/// Open a real pinned-TLS connection via the production `Transport`, then drive a
/// hyper http1 client over it. Returns the sender and the connection's exporter.
async fn open(transport: &Transport) -> (SendRequest<Full<Bytes>>, [u8; 32]) {
    let (tls, exporter) = transport.connect().await.unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, exporter)
}

/// Register `username` with `id`'s public keys over an established sender
/// (registration is voucher-gated, not channel-bound, so any connection works).
async fn register(sender: &mut SendRequest<Full<Bytes>>, username: &str, id: &Identity) {
    let (st, _) = post(
        sender,
        "/v1/users",
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(id.sig_pub_bytes()),
            "enrollment_voucher": VOUCHER,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over pinned TLS");
}

#[tokio::test]
async fn connect_and_login_succeeds() {
    let (addr, cert_der) = spawn_server().await;
    let transport = transport_for(addr, cert_der);
    let id = Identity::generate();

    // Register over a first real Transport connection.
    let (mut reg, _exp) = open(&transport).await;
    register(&mut reg, "alice", &id).await;

    // Fresh channel: full channel-bound login through the production session code.
    let (mut sender, exporter) = open(&transport).await;
    let login = maxsecu_client_app::session::login_exchange(
        &mut sender, &id, "alice", "localhost", &exporter, TS,
    )
    .await
    .expect("login over the bound channel");

    assert!(!login.token.is_empty(), "server minted a session token");
    assert!(
        !login.server_id.is_empty(),
        "challenge carried the real server_id"
    );
}

#[tokio::test]
async fn proof_bound_to_channel_is_rejected_on_a_foreign_connection() {
    let (addr, cert_der) = spawn_server().await;
    let transport = transport_for(addr, cert_der);
    let id = Identity::generate();

    // Register, then take a challenge over connection A (exporter_a).
    let (mut a, exporter_a) = open(&transport).await;
    register(&mut a, "carol", &id).await;
    let (st, ch) = post(
        &mut a,
        "/v1/session/challenge",
        serde_json::json!({ "username": "carol" }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let server_id = ch["server_id"].as_str().unwrap().to_owned();
    let nonce_v = B64.decode(ch["nonce_b64"].as_str().unwrap()).unwrap();
    let nonce: [u8; 32] = nonce_v.try_into().unwrap();

    // Build the proof for A's channel using the production make_proof.
    let proof = make_proof(&id, &server_id, &exporter_a, &nonce, TS).unwrap();

    // A separate channel B has a different exporter.
    let (mut b, exporter_b) = open(&transport).await;
    assert_ne!(exporter_a, exporter_b, "each TLS channel has a unique exporter");

    // Submitting A's proof over B's channel must be rejected: channel mismatch.
    let (st, _) = post(
        &mut b,
        "/v1/session/proof",
        serde_json::json!({
            "username": "carol",
            "timestamp": TS,
            "proof_b64": B64.encode(proof),
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "a proof lifted onto a foreign channel must 401"
    );
}
