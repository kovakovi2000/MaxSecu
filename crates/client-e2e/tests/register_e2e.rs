//! Task 12 exit-gate end-to-end test: the **client-app registration-key
//! enrollment** over real loopback TLS (spec §5, trusted-server-recovery track).
//!
//! Drives the REAL client-app function the `register_with_key` Tauri command
//! calls — `register::register_with_key_exchange` — so it proves the shipped
//! client can:
//!
//! - read the single-use registration key from the local `register.key` file,
//! - generate a fresh hybrid `Identity` entirely in Rust,
//! - enrol via `POST /v1/users` (201) with only the PUBLIC keys + the key,
//! - SEAL the new identity into the local keystore (unlockable with the
//!   passphrase afterwards), and DELETE the local `register.key` file;
//! - that the FIRST registrant lands as ADMIN and a later one as User-only;
//! - and that a SECOND run with the (now consumed) key fails CLOSED — no
//!   account, no keystore, and a sanitized error.

use std::path::{Path, PathBuf};
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

use maxsecu_client_app::commands::register::register_with_key_exchange;
use maxsecu_client_app::keystore;
use maxsecu_crypto::{sha256, SigningKey};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::Role;
use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, MemoryBlobStore, MemoryStore, NullAuditSink,
    Store,
};

// A far-future absolute expiry so seeded keys never TTL-expire in the test.
const NEVER: u64 = 4_102_444_800_000;
const PASSPHRASE: &str = "enrol passphrase battery staple 9!";

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
}

async fn connect(addr: std::net::SocketAddr, client_config: Arc<ClientConfig>) -> Conn {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Conn { sender }
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

/// Decode a `GET /v1/directory/...` body into a `DirBinding`.
fn parse_binding(json: &serde_json::Value) -> DirBinding {
    let bytes = B64.decode(json["binding_b64"].as_str().unwrap()).unwrap();
    decode(&bytes).unwrap()
}

/// Stand up a server that holds its directory-signing key (the enrollment
/// authority) and seed a set of single-use registration keys (only their
/// sha256 is persisted). Returns the bound address + client config.
async fn start_with_keys(keys: &[&str]) -> (std::net::SocketAddr, Arc<ClientConfig>) {
    let signer = Arc::new(SigningKey::generate());
    let dir_pub = signer.verifying_key().to_bytes();
    let store = MemoryStore::new();
    for k in keys {
        store
            .issue_registration_key(sha256(k.as_bytes()), NEVER)
            .await
            .unwrap();
    }
    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(dir_pub))
                .with_dir_signer(signer),
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
    (addr, pki.client_config.clone())
}

/// A fresh, empty portable app-dir with `register.key` seeded to `key`.
fn app_dir_with_key(key: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mxreg_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("register.key"), key.as_bytes()).unwrap();
    dir
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn register_key_file(dir: &Path) -> PathBuf {
    dir.join("register.key")
}

#[tokio::test]
async fn register_first_is_admin_seals_and_deletes_key() {
    let (addr, client_config) = start_with_keys(&["key-one", "key-two"]).await;

    // ---- Run 1: the FIRST registrant enrols, is sealed, and lands as ADMIN. ----
    let dir_a = app_dir_with_key("key-one");
    let mut c = connect(addr, client_config.clone()).await;
    let reg = register_with_key_exchange(&mut c.sender, "localhost", &dir_a, "alice", PASSPHRASE)
        .await
        .expect("first registrant enrols with a valid key");
    assert_eq!(reg.user_id.len(), 32, "16-byte user_id rendered as hex");
    assert_eq!(reg.username, "alice");

    // The local single-use key file was DELETED (no lingering reusable secret).
    assert!(
        !register_key_file(&dir_a).exists(),
        "register.key is destroyed after a successful enrollment"
    );

    // The new identity was SEALED into the keystore and unlocks with the passphrase.
    let sealed = keystore::unlock(&dir_a, PASSPHRASE).expect("sealed identity unlocks");

    // The served binding is the enrolled identity (the sealed key IS the enrolled
    // one), and the FIRST registrant is {User, Admin}.
    let (st, body) = get(&mut c, "/v1/directory/alice").await;
    assert_eq!(st, StatusCode::OK);
    let ab = parse_binding(&body);
    assert_eq!(
        ab.sig_pub.0,
        sealed.sig_pub_bytes(),
        "the served binding is the sealed identity"
    );
    assert!(ab.roles.roles().contains(&Role::Admin), "first registrant is admin");
    assert!(ab.roles.roles().contains(&Role::User));

    // ---- Run 2: a second registrant (second key) is User-role only. ----
    let dir_b = app_dir_with_key("key-two");
    let reg = register_with_key_exchange(&mut c.sender, "localhost", &dir_b, "bob", PASSPHRASE)
        .await
        .expect("second registrant enrols with the second key");
    assert_eq!(reg.username, "bob");
    assert!(!register_key_file(&dir_b).exists());
    keystore::unlock(&dir_b, PASSPHRASE).expect("bob's identity is sealed");
    let (st, body) = get(&mut c, "/v1/directory/bob").await;
    assert_eq!(st, StatusCode::OK);
    let bb = parse_binding(&body);
    assert!(bb.roles.roles().contains(&Role::User));
    assert!(
        !bb.roles.roles().contains(&Role::Admin),
        "only the first registrant is admin"
    );

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test]
async fn consumed_key_fails_closed() {
    let (addr, client_config) = start_with_keys(&["only-key"]).await;

    // First run consumes the key successfully.
    let dir_a = app_dir_with_key("only-key");
    let mut c = connect(addr, client_config.clone()).await;
    register_with_key_exchange(&mut c.sender, "localhost", &dir_a, "alice", PASSPHRASE)
        .await
        .expect("first enrollment succeeds");

    // Second run: a DIFFERENT device presents the SAME (now consumed) key value.
    // The server refuses (403) and the client must fail CLOSED: no account, no
    // keystore, and a sanitized error.
    let dir_b = app_dir_with_key("only-key");
    let err = match register_with_key_exchange(&mut c.sender, "localhost", &dir_b, "mallory", PASSPHRASE)
        .await
    {
        Ok(_) => panic!("a consumed registration key must not enrol"),
        Err(e) => e,
    };
    assert_eq!(err.code, "registration_failed", "sanitized fail-closed code");
    assert!(
        !keystore::exists(&dir_b),
        "no keystore is created on a refused enrollment"
    );
    // The refused account was never created server-side.
    let (st, _) = get(&mut c, "/v1/directory/mallory").await;
    assert_eq!(st, StatusCode::NOT_FOUND, "the refused registrant was never created");

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test]
async fn missing_register_key_file_is_a_clear_error() {
    let (addr, client_config) = start_with_keys(&[]).await;
    // An app-dir with NO register.key present.
    let dir = std::env::temp_dir().join(format!(
        "mxreg_none_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = connect(addr, client_config).await;
    let err = match register_with_key_exchange(&mut c.sender, "localhost", &dir, "nobody", PASSPHRASE)
        .await
    {
        Ok(_) => panic!("no register.key means no enrollment"),
        Err(e) => e,
    };
    assert_eq!(err.code, "no_registration_key");
    assert!(!keystore::exists(&dir));
    let _ = std::fs::remove_dir_all(&dir);
}
