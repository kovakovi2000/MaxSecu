//! **Task 10 exit-gate end-to-end test: trust-alarm C** — the CLIENT polices the
//! directory key-transparency (KT) log over real loopback TLS (spec §0-C/§7).
//!
//! Task 6 wires every server-signed enrollment binding into the KT log the sink
//! produces. This test drives the SHIPPED client verify path
//! (`client_app::transparency::verify_binding_transparency` + the persisted
//! `DiskKtCheckpointStore`) directly and proves:
//!
//!   1. a NORMALLY-served, logged binding verifies (inclusion + a pinned,
//!      non-equivocating checkpoint) and PROCEEDS — and the gossip store advances
//!      and PERSISTS across a re-open (cross-session split-view detectable);
//!   2. a checkpoint signed by a NON-pinned KT key (an equivocating / forged head)
//!      is BLOCKED as `server_untrusted` (fail-closed), store NOT advanced;
//!   3. a binding NOT actually in the log is BLOCKED as `server_untrusted`.
//!
//! Setup mirrors `server/tests/enrollment_transparency_e2e.rs` (app server whose
//! audit sink is a real `HttpSinkPublisher` pinned to an external sink under a
//! PINNED KT key), but drives the CLIENT verifier instead of the raw merkle prims.

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

use maxsecu_client_app::config::{client_config_for_pinned_root, SinkPins};
use maxsecu_client_app::transparency::{verify_binding_transparency, DiskKtCheckpointStore};
use maxsecu_client_core::transparency::KtCheckpointStore;
use maxsecu_client_core::Identity;
use maxsecu_crypto::{sha256, SigningKey};
use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, HttpSinkPublisher, MemoryBlobStore,
    MemoryStore, Store,
};
use maxsecu_sink_server::{router as sink_router, serve as sink_serve, Anchorer, SinkState};

const NEVER: u64 = 4_102_444_800_000;
const TOKEN: &str = "sink-admin-secret";
/// A stable seed for the directory KT log key, so the client can PIN the pubkey
/// the sink signs its checkpoints under.
const KT_SEED: [u8; 32] = [0x6C; 32];

// ---- TLS harness (loopback, self-signed; mirrors enrollment_transparency_e2e.rs) ----

struct Pki {
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    cert_der: Vec<u8>,
}

fn pki() -> Pki {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der.clone())).unwrap();
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Pki {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
        cert_der,
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

async fn post(
    conn: &mut Conn,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
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

/// The canonical `DirBinding` leaf bytes the server served for `username` — the
/// EXACT bytes it also appended to the KT log.
async fn served_leaf(conn: &mut Conn, username: &str) -> Vec<u8> {
    let (st, body) = get(conn, &format!("/v1/directory/{username}")).await;
    assert_eq!(st, StatusCode::OK, "directory serves {username}");
    B64.decode(body["binding_b64"].as_str().unwrap()).unwrap()
}

/// Build the `SinkPins` the client uses to reach the sink for KT proofs (custodian
/// / control-log transparency lists are irrelevant to the directory KT gate).
fn sink_pins(addr: std::net::SocketAddr, cert_der: &[u8]) -> SinkPins {
    SinkPins {
        addr,
        server_name: "localhost".into(),
        tls: client_config_for_pinned_root(cert_der).unwrap(),
        custodian_pubs: vec![],
        transparency_log_pubs: vec![],
    }
}

#[tokio::test]
async fn client_polices_the_directory_kt_log_over_real_tls() {
    // ---- Stand up the external sink (KT-log producer) over TLS, PINNED KT key. ----
    let sink_pki = pki();
    let kt_key = SigningKey::from_seed(&KT_SEED);
    let kt_pub = kt_key.verifying_key().to_bytes();
    let sink_state = SinkState::with_dir_log_key(
        Anchorer::new(SigningKey::generate(), SigningKey::generate()),
        TOKEN,
        kt_key,
    );
    let sink_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink_listener.local_addr().unwrap();
    tokio::spawn(sink_serve(
        sink_listener,
        sink_pki.server_config.clone(),
        sink_router(sink_state),
    ));

    // ---- App server: enrollment authority + a real HttpSinkPublisher audit sink
    // pinned to the sink, so each enrollment binding is published to the KT log. ----
    let signer = Arc::new(SigningKey::generate());
    let dir_pub = signer.verifying_key().to_bytes();
    let store = MemoryStore::new();
    store
        .issue_registration_key(sha256(b"key-one"), NEVER)
        .await
        .unwrap();
    let publisher =
        HttpSinkPublisher::new(sink_addr, "localhost", sink_pki.client_config.clone(), TOKEN);
    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(dir_pub))
                .with_dir_signer(signer),
        ),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(publisher),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    let app_pki = pki();
    let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app_listener.local_addr().unwrap();
    tokio::spawn(serve(
        app_listener,
        app_pki.server_config.clone(),
        router(state),
    ));

    let mut c = connect(app_addr, app_pki.client_config.clone()).await;

    // ---- Enroll alice; the KT log grows to one leaf. ----
    let alice = Identity::generate();
    let (st, _) = post(&mut c, "/v1/users", reg_body("alice", "key-one", &alice)).await;
    assert_eq!(st, StatusCode::CREATED, "enrollment");
    let alice_leaf = served_leaf(&mut c, "alice").await;

    // A per-test app directory holding the persisted KT gossip store, sealed under
    // a fresh client identity.
    let kt_dir = std::env::temp_dir().join(format!(
        "mxkt_{}_{}",
        std::process::id(),
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&kt_dir).unwrap();
    let identity = Identity::generate();

    // ---- (1) A logged binding under the PINNED KT key verifies and PROCEEDS,
    // and the accepted checkpoint persists across a re-open. ----
    let pins = sink_pins(sink_addr, &sink_pki.cert_der);
    let mut store = DiskKtCheckpointStore::open(&kt_dir, &identity).unwrap();
    assert!(store.latest().is_none(), "no gossip pinned yet");
    let leaf = alice_leaf.clone();
    let pin = vec![kt_pub];
    let (res, store) = tokio::task::spawn_blocking(move || {
        let r = verify_binding_transparency(&pins, &pin, &mut store, &leaf);
        (r, store)
    })
    .await
    .unwrap();
    res.expect("a logged binding under a pinned checkpoint verifies and proceeds");
    assert!(store.latest().is_some(), "the gossip store advanced (TOFU pin)");
    // Cross-session: a freshly re-opened store sees the persisted checkpoint.
    let reopened = DiskKtCheckpointStore::open(&kt_dir, &identity).unwrap();
    assert!(
        reopened.latest().is_some(),
        "the accepted checkpoint persisted across a re-open"
    );

    // ---- (2) A checkpoint signed by a NON-pinned KT key is BLOCKED (fail-closed),
    // and a fresh store is NOT advanced. ----
    let wrong_pin = vec![SigningKey::generate().verifying_key().to_bytes()];
    let pins2 = sink_pins(sink_addr, &sink_pki.cert_der);
    let leaf2 = alice_leaf.clone();
    let kt_dir2 = kt_dir.clone();
    let id2_dir = kt_dir2.join("wrong");
    std::fs::create_dir_all(&id2_dir).unwrap();
    let mut store2 = DiskKtCheckpointStore::open(&id2_dir, &identity).unwrap();
    let (res2, store2) = tokio::task::spawn_blocking(move || {
        let r = verify_binding_transparency(&pins2, &wrong_pin, &mut store2, &leaf2);
        (r, store2)
    })
    .await
    .unwrap();
    let err = res2.expect_err("a checkpoint under a non-pinned KT key must be blocked");
    assert_eq!(err.code, "server_untrusted", "trust-alarm C blocks the open");
    assert!(
        store2.latest().is_none(),
        "the equivocal checkpoint was NOT adopted"
    );

    // ---- (3) A binding NOT actually in the log is BLOCKED. ----
    let mut bogus = alice_leaf.clone();
    bogus[0] ^= 0x01; // a leaf the sink never logged
    let pins3 = sink_pins(sink_addr, &sink_pki.cert_der);
    let pin3 = vec![kt_pub];
    let bogus_dir = kt_dir.join("bogus");
    std::fs::create_dir_all(&bogus_dir).unwrap();
    let mut store3 = DiskKtCheckpointStore::open(&bogus_dir, &identity).unwrap();
    let (res3, _store3) = tokio::task::spawn_blocking(move || {
        let r = verify_binding_transparency(&pins3, &pin3, &mut store3, &bogus);
        (r, store3)
    })
    .await
    .unwrap();
    assert_eq!(
        res3.expect_err("a binding not in the log must be blocked").code,
        "server_untrusted",
        "an absent binding fails closed"
    );

    let _ = std::fs::remove_dir_all(&kt_dir);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A MALICIOUS stub sink that does NOT hold the pinned KT key: it serves a
/// checkpoint claiming `tree_size = u64::MAX` signed with garbage, and COUNTS every
/// `/v1/dir-log/inclusion` request. Runs on its own thread + current-thread runtime
/// so the (blocking) client verify can drive it without a nested-runtime panic.
/// Returns `(addr, cert_der, inclusion_hits)`.
fn spawn_hostile_sink(
    server_config: Arc<ServerConfig>,
) -> (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let hits_srv = hits.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let acceptor = acceptor.clone();
                let hits = hits_srv.clone();
                tokio::spawn(async move {
                    use hyper::service::service_fn;
                    let tls = match acceptor.accept(tcp).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let hits = hits.clone();
                        async move {
                            let path = req.uri().path().to_owned();
                            let _ = req.into_body().collect().await;
                            let body = if path == "/v1/dir-log/checkpoint" {
                                serde_json::json!({
                                    "tree_size": u64::MAX,
                                    "root_b64": B64.encode([0x11u8; 32]),
                                    "sig_b64": B64.encode([0u8; 64]), // garbage: never verifies
                                })
                                .to_string()
                            } else {
                                if path.starts_with("/v1/dir-log/inclusion") {
                                    hits.fetch_add(1, Ordering::SeqCst);
                                }
                                "{}".to_owned()
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(Full::<Bytes>::from(body))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
    });
    (rx.recv().unwrap(), hits)
}

/// A checkpoint whose signature does not verify under the pinned KT key is blocked
/// as `server_untrusted` BEFORE any index-discovery scan — so a forged
/// `tree_size = u64::MAX` cannot drive an unbounded sequence of inclusion fetches
/// (the DoS the sig-first guard closes).
#[tokio::test]
async fn forged_checkpoint_is_blocked_without_scanning() {
    let sink_pki = pki();
    let (sink_addr, hits) = spawn_hostile_sink(sink_pki.server_config.clone());

    let kt_dir = std::env::temp_dir().join(format!(
        "mxkt_hostile_{}_{}",
        std::process::id(),
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&kt_dir).unwrap();
    let identity = Identity::generate();
    let mut store = DiskKtCheckpointStore::open(&kt_dir, &identity).unwrap();

    // Pin a key the hostile sink does NOT hold (its garbage sig cannot verify).
    let pin = vec![SigningKey::generate().verifying_key().to_bytes()];
    let pins = sink_pins(sink_addr, &sink_pki.cert_der);
    let leaf = vec![0x42u8; 48];
    let (res, _store) = tokio::task::spawn_blocking(move || {
        let r = verify_binding_transparency(&pins, &pin, &mut store, &leaf);
        (r, store)
    })
    .await
    .unwrap();

    assert_eq!(
        res.expect_err("a forged checkpoint must be blocked").code,
        "server_untrusted"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the sig-first guard blocked BEFORE any inclusion fetch (no scan)"
    );

    let _ = std::fs::remove_dir_all(&kt_dir);
}
