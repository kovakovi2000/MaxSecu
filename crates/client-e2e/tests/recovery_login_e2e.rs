//! Task 11 exit-gate end-to-end test: the **client-app recovery challenge-response
//! login** over real loopback TLS (spec §6 / §0-D6, trusted-server-recovery track).
//!
//! Unlike the server-side `recovery_login_e2e.rs` (which hand-rolls the client
//! round-trip), this drives the REAL client-app functions the two Tauri commands
//! call — `recovery_login::{load_recovery_identity, request_challenge_exchange,
//! verify_exchange}` — so it proves the shipped client can:
//!
//! - load its sealed cold recovery keyblob file (unseal with the operator
//!   passphrase, keeping the private Identity entirely in Rust),
//! - unwrap the server's challenge blob to the nonce (HYBRID + classical suites),
//! - build the channel-bound proof and log in to an ADMIN session that can
//!   `POST /v1/registration-keys` (201) over the SAME channel;
//! - and that a WRONG recovery key file, a WRONG passphrase, and a REPLAYED
//!   challenge each fail closed with no session.

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

use maxsecu_client_app::commands::recovery_login::{
    load_recovery_identity, request_challenge_exchange, verify_exchange,
};
use maxsecu_client_core::{keyblob, Identity, ARGON2_FLOOR};
use maxsecu_crypto::SigningKey;
use maxsecu_server::{
    export_channel_binding, router, serve, AppState, AuthConfig, AuthService, MemoryBlobStore,
    MemoryStore, NullAuditSink,
};

const TS: u64 = 1_719_500_000_000;
const PASSPHRASE: &str = "cold recovery passphrase 42!";

// ---- TLS harness (loopback, self-signed; mirrors recovery_login_e2e.rs) ----

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

/// Stand up a server whose admin gate is satisfiable by a recovery session (a
/// pinned directory pub + dir signer, exactly like the server-side e2e).
fn state_with_admin_gate() -> AppState<MemoryStore> {
    let signer = Arc::new(SigningKey::generate());
    let dir_pub = signer.verifying_key().to_bytes();
    AppState {
        auth: Arc::new(
            AuthService::new(MemoryStore::new(), AuthConfig::default().with_directory_pub(dir_pub))
                .with_dir_signer(signer),
        ),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    }
}

async fn start() -> (std::net::SocketAddr, Arc<ClientConfig>) {
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), router(state_with_admin_gate())));
    (addr, pki.client_config.clone())
}

/// Register the singleton recovery account from `recovery`'s PUBLIC keys. When
/// `hybrid` the ML-KEM public key is included, so the server wraps challenges as
/// Suite::V2; otherwise it is a classical (v1) account.
async fn register_recovery(c: &mut Conn, recovery: &Identity, hybrid: bool) {
    let mut body = serde_json::json!({
        "enc_pub_b64": B64.encode(recovery.enc_pub_bytes()),
        "sig_pub_b64": B64.encode(recovery.sig_pub_bytes()),
    });
    if hybrid {
        let mlkem = recovery.mlkem_pub_bytes().expect("PQ identity has ML-KEM");
        body["mlkem_pub_b64"] = serde_json::Value::String(B64.encode(&mlkem[..]));
    }
    let (st, _) = post(c, "/v1/recovery/register", None, body).await;
    assert_eq!(st, StatusCode::CREATED, "recovery account registered");
}

/// Seal `id` into a fresh temp keyblob file under `PASSPHRASE`; return the path.
fn seal_recovery_file(id: &Identity) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mxrec_key_{}.blob",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let blob = keyblob::seal(PASSPHRASE, id, ARGON2_FLOOR).unwrap();
    std::fs::write(&path, &blob).unwrap();
    path
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Full happy path over the REAL client functions, for a given suite.
async fn login_and_mint_key(hybrid: bool) {
    let (addr, client_config) = start().await;
    let mut c = connect(addr, client_config).await;

    let recovery = Identity::generate();
    register_recovery(&mut c, &recovery, hybrid).await;
    let key_file = seal_recovery_file(&recovery);

    // Load the cold recovery Identity from its sealed file (unseal in Rust).
    let id = load_recovery_identity(&key_file, PASSPHRASE).expect("unseal recovery key file");

    // Challenge → unwrap the nonce with the recovery private key (in Rust).
    let challenge = request_challenge_exchange(&mut c.sender, "localhost", &id)
        .await
        .expect("challenge unwraps to the nonce");
    assert_eq!(
        challenge.suite_is_hybrid(),
        hybrid,
        "the served suite matches the account kind"
    );

    // Verify the channel-bound proof → an ADMIN session token.
    let token = verify_exchange(&mut c.sender, "localhost", &id, &challenge, &c.exporter, TS)
        .await
        .expect("channel-bound proof logs in");
    assert!(!token.is_empty(), "server minted a recovery session token");

    // The recovery session authorizes an ADMIN action (mint a registration key).
    let (st, res) = post(
        &mut c,
        "/v1/registration-keys",
        Some(&token),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "recovery session mints a reg key");
    assert!(!res["registration_key"].as_str().unwrap().is_empty());

    // REPLAY: the same consumed challenge cannot be answered again.
    let replay = verify_exchange(&mut c.sender, "localhost", &id, &challenge, &c.exporter, TS).await;
    assert!(replay.is_err(), "a consumed challenge cannot be replayed");

    let _ = std::fs::remove_file(&key_file);
}

#[tokio::test]
async fn recovery_login_hybrid_over_real_tls() {
    login_and_mint_key(true).await;
}

#[tokio::test]
async fn recovery_login_classical_over_real_tls() {
    login_and_mint_key(false).await;
}

#[tokio::test]
async fn wrong_recovery_key_file_fails_closed() {
    let (addr, client_config) = start().await;
    let mut c = connect(addr, client_config).await;

    // The server registers the REAL recovery account (hybrid).
    let recovery = Identity::generate();
    register_recovery(&mut c, &recovery, true).await;

    // The client loads a DIFFERENT (attacker/corrupt) recovery Identity: the
    // challenge is wrapped to the real recovery pubkey, so the unwrap must fail
    // closed — no nonce, no session — with a sanitized (no-oracle) error.
    let wrong = Identity::generate();
    let key_file = seal_recovery_file(&wrong);
    let id = load_recovery_identity(&key_file, PASSPHRASE).expect("the wrong file still unseals");

    // `RecoveryChallenge` (the Ok type) intentionally has no `Debug` (it holds the
    // nonce), so extract the error via a match rather than `expect_err`.
    let err = match request_challenge_exchange(&mut c.sender, "localhost", &id).await {
        Ok(_) => panic!("a wrong recovery key must not unwrap the challenge"),
        Err(e) => e,
    };
    assert_eq!(err.code, "recovery_failed", "sanitized fail-closed code");

    let _ = std::fs::remove_file(&key_file);
}

#[tokio::test]
async fn wrong_passphrase_fails_closed() {
    let recovery = Identity::generate();
    let key_file = seal_recovery_file(&recovery);
    // A wrong passphrase cannot unseal the cold keyblob → fail closed, no Identity.
    // `Identity` (the Ok type) has no `Debug`, so match rather than `expect_err`.
    let err = match load_recovery_identity(&key_file, "not the passphrase") {
        Ok(_) => panic!("a wrong passphrase must not unseal the recovery key"),
        Err(e) => e,
    };
    assert_eq!(err.code, "unauthorized", "wrong passphrase is unauthorized");
    let _ = std::fs::remove_file(&key_file);
}
