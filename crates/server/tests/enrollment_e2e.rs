//! T4 exit-gate end-to-end test: **registration-key-only enrollment** over real
//! loopback TLS (DESIGN §5 / §0-D5, trusted-server-recovery track).
//!
//! Proves the enrollment authority now lives on the server (the bootstrap /
//! voucher / pending-approval model is gone):
//!
//! - a single-use **registration key** buys exactly one `POST /v1/users` (201);
//! - `GET /v1/directory/<user>` serves a **server-signed** binding that verifies
//!   under the server's directory-signing public key (the value clients pin);
//! - the **first** registrant is `{User, Admin}`; every later one is `{User}`;
//! - a **consumed** key cannot be reused (403);
//! - the admin-gated `POST /v1/registration-keys` mint path issues a fresh key
//!   (User-role only — admin-minted keys are never admin), and a non-admin is
//!   refused (403);
//! - the removed `POST /v1/bootstrap`, `POST /v1/vouchers`, `GET /v1/pending`
//!   routes now 404.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use maxsecu_client_core::Identity;
use maxsecu_crypto::{sha256, SigningKey, VerifyingKey};
use maxsecu_encoding::decode;
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{AuthProofContext, DirBinding};
use maxsecu_encoding::types::{Bytes32, Role, Text, Timestamp};
use maxsecu_server::{
    export_channel_binding, router, serve, AppState, AuthConfig, AuthService, MemoryBlobStore,
    MemoryStore, NullAuditSink, Store,
};

const TS: u64 = 1_719_500_000_000;
// A far-future absolute expiry so the seeded keys never TTL-expire in the test
// (mirrors the reg-key store tests' year-2100 sentinel).
const NEVER: u64 = 4_102_444_800_000;

// ---- TLS harness (loopback, self-signed; mirrors sharing_e2e.rs) ----

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

struct Conn {
    sender: SendRequest<Full<Bytes>>,
    exporter: [u8; 32],
}

async fn connect(addr: std::net::SocketAddr, client_config: Arc<ClientConfig>) -> Conn {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let exporter = export_channel_binding(tls.get_ref().1).unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Conn { sender, exporter }
}

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
    if let Some(t) = auth {
        req = req.header("authorization", format!("MaxSecu-Session {t}"));
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

async fn get(conn: &mut Conn, uri: &str) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
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

fn reg_body(username: &str, key: &str, id: &Identity) -> serde_json::Value {
    serde_json::json!({
        "username": username,
        "enc_pub_b64": B64.encode(id.enc_pub_bytes()),
        "sig_pub_b64": B64.encode(id.sig_pub_bytes()),
        "registration_key": key,
    })
}

/// Decode a `GET /v1/directory/...` body into `(DirBinding, signature)` — exactly
/// what a real client verifies against the pinned directory pubkey.
fn parse_binding(json: &serde_json::Value) -> (DirBinding, [u8; 64]) {
    let bytes = B64.decode(json["binding_b64"].as_str().unwrap()).unwrap();
    let sig: [u8; 64] = B64
        .decode(json["directory_signature_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (decode(&bytes).unwrap(), sig)
}

/// Complete a channel-bound login on `conn`, returning the session token.
async fn login(conn: &mut Conn, username: &str, id: &Identity) -> String {
    let (_st, ch) = post(
        conn,
        "/v1/session/challenge",
        None,
        serde_json::json!({ "username": username }),
    )
    .await;
    let nonce: [u8; 32] = B64
        .decode(ch["nonce_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let server_id = ch["server_id"].as_str().unwrap().to_owned();
    let ctx = AuthProofContext {
        server_id: Text::new(&server_id).unwrap(),
        tls_exporter: Bytes32(conn.exporter),
        nonce: Bytes32(nonce),
        timestamp: Timestamp(TS),
    };
    let proof = B64.encode(id.signing_key().sign_canonical(labels::AUTH, &ctx));
    let (st, res) = post(
        conn,
        "/v1/session/proof",
        None,
        serde_json::json!({"username": username, "timestamp": TS, "proof_b64": proof}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login {username}");
    res["session_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn enrollment_registration_key_only_over_real_tls() {
    // The server now holds the directory-signing key (the enrollment authority).
    // Its PUBLIC half is what clients pin and what every served binding verifies
    // under — the server signs bindings, it never leaks the private seed.
    let signer = Arc::new(SigningKey::generate());
    let dir_pub = signer.verifying_key().to_bytes();

    let store = MemoryStore::new();
    // Two single-use registration keys, operator-issued out of band (only the
    // sha256 is persisted — never the plaintext).
    store
        .issue_registration_key(sha256(b"key-one"), NEVER)
        .await
        .unwrap();
    store
        .issue_registration_key(sha256(b"key-two"), NEVER)
        .await
        .unwrap();

    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(dir_pub))
                .with_dir_signer(signer.clone()),
        ),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), router(state)));

    let mut c = connect(addr, pki.client_config.clone()).await;

    // ---- Gate 1: a valid registration key buys exactly one enrollment (201). ----
    let alice = Identity::generate();
    let (st, res) = post(&mut c, "/v1/users", None, reg_body("alice", "key-one", &alice)).await;
    assert_eq!(st, StatusCode::CREATED, "first registrant enrolls");
    assert_eq!(res["user_id"].as_str().unwrap().len(), 32); // 16 bytes hex

    // ---- Gate 2: the served binding is SERVER-signed and verifies under dir_pub. ----
    let (st, body) = get(&mut c, "/v1/directory/alice").await;
    assert_eq!(st, StatusCode::OK);
    let (ab, asig) = parse_binding(&body);
    let vk = VerifyingKey::from_bytes(&dir_pub).unwrap();
    assert!(
        vk.verify_canonical(labels::DIRBINDING, &ab, &asig).is_ok(),
        "the served binding verifies under the server's directory pubkey"
    );
    assert_eq!(ab.enc_pub.0, alice.enc_pub_bytes(), "binds the enrolled enc key");
    assert_eq!(ab.sig_pub.0, alice.sig_pub_bytes(), "binds the enrolled sig key");

    // ---- Gate 3a: the FIRST registrant is {User, Admin}. ----
    assert!(ab.roles.roles().contains(&Role::Admin), "first registrant is admin");
    assert!(ab.roles.roles().contains(&Role::User));

    // ---- Gate 3b: the SECOND registrant (second key) is {User} only. ----
    let bob = Identity::generate();
    let (st, _) = post(&mut c, "/v1/users", None, reg_body("bob", "key-two", &bob)).await;
    assert_eq!(st, StatusCode::CREATED, "second registrant enrolls");
    let (st, body) = get(&mut c, "/v1/directory/bob").await;
    assert_eq!(st, StatusCode::OK);
    let (bb, _) = parse_binding(&body);
    assert!(bb.roles.roles().contains(&Role::User));
    assert!(
        !bb.roles.roles().contains(&Role::Admin),
        "only the first registrant is admin"
    );

    // ---- Gate 4: a consumed key cannot be reused (403), and no user is created. ----
    let mallory = Identity::generate();
    let (st, _) = post(
        &mut c,
        "/v1/users",
        None,
        reg_body("mallory", "key-one", &mallory),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a consumed registration key is refused");
    let (st, _) = get(&mut c, "/v1/directory/mallory").await;
    assert_eq!(st, StatusCode::NOT_FOUND, "the refused registrant was never created");

    // ---- Gate 5: the removed enrollment routes now 404. ----
    let (st, _) = post(&mut c, "/v1/bootstrap", None, serde_json::json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "POST /v1/bootstrap removed");
    let (st, _) = post(&mut c, "/v1/vouchers", None, serde_json::json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "POST /v1/vouchers removed");
    let (st, _) = get(&mut c, "/v1/pending").await;
    assert_eq!(st, StatusCode::NOT_FOUND, "GET /v1/pending removed");

    // ---- Admin mint path: the admin mints a fresh (User-only) registration key. ----
    let admin_token = login(&mut c, "alice", &alice).await;
    let (st, res) = post(
        &mut c,
        "/v1/registration-keys",
        Some(&admin_token),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "admin mints a registration key");
    let minted = res["registration_key"].as_str().unwrap().to_owned();
    assert!(!minted.is_empty(), "the plaintext key is returned once");

    let carol = Identity::generate();
    let (st, _) = post(&mut c, "/v1/users", None, reg_body("carol", &minted, &carol)).await;
    assert_eq!(st, StatusCode::CREATED, "a minted key enrolls a user");
    let (st, body) = get(&mut c, "/v1/directory/carol").await;
    assert_eq!(st, StatusCode::OK);
    let (cb, _) = parse_binding(&body);
    assert!(
        !cb.roles.roles().contains(&Role::Admin),
        "admin-minted keys are User-role only (only the first-ever registrant is admin)"
    );

    // A minted key is single-use too.
    let dave = Identity::generate();
    let (st, _) = post(&mut c, "/v1/users", None, reg_body("dave", &minted, &dave)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a minted key is single-use");

    // ---- A non-admin session cannot mint (403, authentic but not authorized). ----
    let bob_token = login(&mut c, "bob", &bob).await;
    let (st, _) = post(
        &mut c,
        "/v1/registration-keys",
        Some(&bob_token),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a non-admin cannot mint registration keys");
}
