//! End-to-end TLS channel-binding test (DESIGN §9.2 / api.md §1.5).
//!
//! A real `tokio-rustls` client connects over loopback TLS 1.3, extracts the
//! **same** RFC 5705 keying-material exporter the server derives per connection,
//! and runs the full control-plane flow: register → challenge → proof →
//! authenticated request. The capstone assertion is the relay check: a session
//! token minted on connection A is presented on a fresh connection B (a
//! *different* exporter) and must be rejected `401` — even though the session is
//! still valid and unrevoked on A. No DB required (uses `MemoryStore`); runs on
//! Windows and Linux alike.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use maxsecu_crypto::{generate_enc_keypair, sha256, SigningKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::AuthProofContext;
use maxsecu_encoding::types::{Bytes32, Text, Timestamp};
use maxsecu_server::{export_channel_binding, serve, AppState, AuthConfig, AuthService, MemoryStore};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

const VOUCHER: &str = "in-person-code-001";
const TS: u64 = 1_719_500_000_000;

/// A self-signed cert/key for `localhost`, plus the client roots that trust it.
struct TestPki {
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
}

fn test_pki() -> TestPki {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());

    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    TestPki {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
    }
}

/// Stand up the auth router backed by a `MemoryStore` seeded with one voucher.
fn router() -> axum::Router {
    let store = MemoryStore::new();
    store.add_voucher(sha256(VOUCHER.as_bytes()));
    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
    };
    maxsecu_server::router(state)
}

/// A live TLS connection: an HTTP/1.1 request sender plus the exporter the
/// client derived for this exact channel (matches what the server recorded).
struct Conn {
    sender: SendRequest<Full<Bytes>>,
    exporter: [u8; 32],
}

async fn connect(addr: std::net::SocketAddr, client_config: Arc<ClientConfig>) -> Conn {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();

    // Same label/len the server uses — both sides derive identical bytes (RFC 5705).
    let exporter = export_channel_binding(tls.get_ref().1).unwrap();

    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Conn { sender, exporter }
}

/// Send one POST and return `(status, json)`. Drains the body so the keep-alive
/// connection is ready for the next request.
async fn post(
    conn: &mut Conn,
    uri: &str,
    auth: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if let Some(token) = auth {
        req = req.header("authorization", format!("MaxSecu-Session {token}"));
    }
    let req = req.body(Full::new(Bytes::from(body.to_string()))).unwrap();
    let resp = conn.sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
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
    B64.encode(sk.sign_canonical(labels::AUTH, &ctx))
}

#[tokio::test]
async fn full_login_over_real_tls_then_relay_to_new_channel_is_401() {
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), router()));

    // ---- Connection A: the legitimate channel ----
    let mut a = connect(addr, pki.client_config.clone()).await;

    // register (voucher-gated; not channel-bound)
    let sk = SigningKey::generate();
    let (_esk, epk) = generate_enc_keypair();
    let (st, _res) = post(
        &mut a,
        "/v1/users",
        None,
        serde_json::json!({
            "username": "bob",
            "enc_pub_b64": B64.encode(epk.to_bytes()),
            "sig_pub_b64": B64.encode(sk.verifying_key().to_bytes()),
            "enrollment_voucher": VOUCHER,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS");

    // challenge
    let (st, ch) = post(
        &mut a,
        "/v1/session/challenge",
        None,
        serde_json::json!({"username":"bob"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let nonce_v = B64.decode(ch["nonce_b64"].as_str().unwrap()).unwrap();
    let nonce: [u8; 32] = nonce_v.try_into().unwrap();
    let server_id = ch["server_id"].as_str().unwrap().to_owned();

    // proof — bound to connection A's exporter
    let proof_b64 = make_proof(&sk, &server_id, &a.exporter, &nonce, TS);
    let (st, res) = post(
        &mut a,
        "/v1/session/proof",
        None,
        serde_json::json!({"username":"bob","timestamp":TS,"proof_b64":proof_b64}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login over the bound channel");
    let token = res["session_token"].as_str().unwrap().to_owned();

    // ---- Connection B: a DIFFERENT TLS channel (different exporter) ----
    let mut b = connect(addr, pki.client_config.clone()).await;
    assert_ne!(a.exporter, b.exporter, "each connection has a unique exporter");
    // The (still-valid, unrevoked) token replayed on B is rejected: channel mismatch.
    let (st, _) = post(&mut b, "/v1/session/logout", Some(&token), serde_json::Value::Null).await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "token lifted onto a foreign channel must 401"
    );

    // ---- Same token on connection A still works (proves the authed path) ----
    let (st, _) = post(&mut a, "/v1/session/logout", Some(&token), serde_json::Value::Null).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "authed request on the bound channel");
}
