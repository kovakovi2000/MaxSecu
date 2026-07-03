//! **T6 exit-gate end-to-end test: enrollment → key-transparency log** over real
//! loopback TLS (DESIGN §0-C/§2, trusted-server-recovery track).
//!
//! Under the Task-4 design the SERVER is the enrollment authority and signs each
//! `DirBinding` server-side. Task 6 wires that success path so every server-signed
//! enrollment binding is APPENDED to the directory key-transparency (KT) log — the
//! SAME append the Phase-7 published bindings take — and the client can fetch
//! inclusion + consistency proofs to police it.
//!
//! This test stands up:
//!   - an external `sink-server` (the KT-log producer) over TLS under a PINNED KT
//!     log key, and
//!   - an app server whose `audit` sink is a real `HttpSinkPublisher` pinned to
//!     that sink,
//! then enrolls TWO users (registration-key-only, as Task 4) and proves:
//!   1. after enrolling both, the KT log holds BOTH bindings (`tree_size == 2`);
//!   2. an INCLUSION proof for the first enrollee verifies against the served tree
//!      head with the REAL `crypto::merkle::verify_inclusion`;
//!   3. a CONSISTENCY proof between the checkpoint after enrollee #1 and the
//!      checkpoint after enrollee #2 verifies with `crypto::merkle::verify_consistency`.
//! The KT checkpoint signatures are additionally verified under the pinned KT key
//! (the same primitive `client-core::transparency` uses), so the heads are authentic.

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
use maxsecu_crypto::merkle::{verify_consistency, verify_inclusion};
use maxsecu_crypto::{sha256, SigningKey, VerifyingKey};
use maxsecu_encoding::kt_checkpoint_signing_input;
use maxsecu_server::{
    export_channel_binding, router, serve, AppState, AuthConfig, AuthService, HttpSinkPublisher,
    MemoryBlobStore, MemoryStore, Store,
};
use maxsecu_sink_server::{router as sink_router, serve as sink_serve, Anchorer, SinkState};

const NEVER: u64 = 4_102_444_800_000;
const TOKEN: &str = "sink-admin-secret";
/// A stable seed for the directory KT log key, so the test can PIN the pubkey the
/// sink signs its checkpoints under.
const KT_SEED: [u8; 32] = [0x6C; 32];

// ---- TLS harness (loopback, self-signed; mirrors enrollment_e2e.rs) ----

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
    #[allow(dead_code)]
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
/// EXACT bytes it also appended to the KT log (`binding_b64` is base64 of the
/// stored `binding_bytes`).
async fn served_leaf(conn: &mut Conn, username: &str) -> Vec<u8> {
    let (st, body) = get(conn, &format!("/v1/directory/{username}")).await;
    assert_eq!(st, StatusCode::OK, "directory serves {username}");
    B64.decode(body["binding_b64"].as_str().unwrap()).unwrap()
}

// ---- sink helpers (KT log checkpoint / inclusion / consistency over TLS) ----

async fn sink_connect(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
) -> SendRequest<Full<Bytes>> {
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
    sender
}

async fn sink_get_json(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    path: &str,
) -> serde_json::Value {
    let mut sender = sink_connect(addr, client_config).await;
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn b64_fixed<const N: usize>(v: &serde_json::Value, key: &str) -> [u8; N] {
    B64.decode(v.get(key).unwrap().as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The current signed KT checkpoint `(tree_size, root, sig)`.
async fn fetch_checkpoint(
    addr: std::net::SocketAddr,
    cc: Arc<ClientConfig>,
) -> (u64, [u8; 32], [u8; 64]) {
    let cp = sink_get_json(addr, cc, "/v1/dir-log/checkpoint").await;
    (
        cp["tree_size"].as_u64().unwrap(),
        b64_fixed::<32>(&cp, "root_b64"),
        b64_fixed::<64>(&cp, "sig_b64"),
    )
}

/// An inclusion proof `(index, tree_size, path)` for `index`.
async fn fetch_inclusion(
    addr: std::net::SocketAddr,
    cc: Arc<ClientConfig>,
    index: u64,
) -> (u64, u64, Vec<[u8; 32]>) {
    let inc = sink_get_json(addr, cc, &format!("/v1/dir-log/inclusion?index={index}")).await;
    let path = inc["path_b64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| B64.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();
    (
        inc["index"].as_u64().unwrap(),
        inc["tree_size"].as_u64().unwrap(),
        path,
    )
}

/// A consistency proof `from → current`.
async fn fetch_consistency(
    addr: std::net::SocketAddr,
    cc: Arc<ClientConfig>,
    from: u64,
) -> Vec<[u8; 32]> {
    let v = sink_get_json(addr, cc, &format!("/v1/dir-log/consistency?from={from}")).await;
    v["path_b64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| B64.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect()
}

#[tokio::test]
async fn enrollment_is_appended_to_transparency_log_over_real_tls() {
    // ---- Stand up the external sink (KT-log producer) over TLS, pinned key. ----
    let sink_pki = test_pki();
    let kt_key = SigningKey::from_seed(&KT_SEED);
    let kt_vk = VerifyingKey::from_bytes(&kt_key.verifying_key().to_bytes()).unwrap();
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

    // ---- App server: enrollment authority (dir signer) + a real HttpSinkPublisher
    // audit sink pinned to the sink, so an enrollment binding is published there. ----
    let signer = Arc::new(SigningKey::generate());
    let dir_pub = signer.verifying_key().to_bytes();
    let store = MemoryStore::new();
    store
        .issue_registration_key(sha256(b"key-one"), NEVER)
        .await
        .unwrap();
    store
        .issue_registration_key(sha256(b"key-two"), NEVER)
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
    let app_pki = test_pki();
    let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_addr = app_listener.local_addr().unwrap();
    tokio::spawn(serve(
        app_listener,
        app_pki.server_config.clone(),
        router(state),
    ));

    let mut c = connect(app_addr, app_pki.client_config.clone()).await;

    // ---- Enroll the FIRST user; the KT log grows to one leaf. ----
    let alice = Identity::generate();
    let (st, _) = post(&mut c, "/v1/users", reg_body("alice", "key-one", &alice)).await;
    assert_eq!(st, StatusCode::CREATED, "first enrollment");
    let alice_leaf = served_leaf(&mut c, "alice").await;

    // Checkpoint AFTER enrollee #1 — one leaf, and the head is authentic (signed
    // under the pinned KT key).
    let (size1, root1, sig1) = fetch_checkpoint(sink_addr, sink_pki.client_config.clone()).await;
    assert_eq!(size1, 1, "the first enrollment was appended to the KT log");
    assert!(
        kt_vk
            .verify_raw(&kt_checkpoint_signing_input(size1, &root1), &sig1)
            .is_ok(),
        "checkpoint #1 verifies under the pinned KT key"
    );

    // ---- Enroll the SECOND user; the KT log grows to two leaves. ----
    let bob = Identity::generate();
    let (st, _) = post(&mut c, "/v1/users", reg_body("bob", "key-two", &bob)).await;
    assert_eq!(st, StatusCode::CREATED, "second enrollment");
    let bob_leaf = served_leaf(&mut c, "bob").await;
    assert_ne!(alice_leaf, bob_leaf, "distinct bindings");

    // ---- (1) BOTH enrollment bindings are now in the log. ----
    let (size2, root2, sig2) = fetch_checkpoint(sink_addr, sink_pki.client_config.clone()).await;
    assert_eq!(size2, 2, "both enrollments were appended to the KT log");
    assert!(
        kt_vk
            .verify_raw(&kt_checkpoint_signing_input(size2, &root2), &sig2)
            .is_ok(),
        "checkpoint #2 verifies under the pinned KT key"
    );

    // ---- (2) INCLUSION proof for enrollee #1 verifies with the REAL merkle verify
    // against the served tree head (checkpoint #2). ----
    let (idx0, tsz0, path0) = fetch_inclusion(sink_addr, sink_pki.client_config.clone(), 0).await;
    assert_eq!(idx0, 0, "the first enrollee is leaf 0");
    assert_eq!(tsz0, size2, "inclusion is against the current head");
    assert!(
        verify_inclusion(&alice_leaf, idx0, tsz0, &path0, root2),
        "enrollee #1's binding is inclusion-provable under the served head"
    );
    // A tampered leaf must NOT verify (the proof is real, not a rubber stamp).
    let mut bad_leaf = alice_leaf.clone();
    bad_leaf[0] ^= 0x01;
    assert!(
        !verify_inclusion(&bad_leaf, idx0, tsz0, &path0, root2),
        "a tampered binding does not verify"
    );

    // Enrollee #2 also verifies at leaf 1.
    let (idx1, tsz1, path1) = fetch_inclusion(sink_addr, sink_pki.client_config.clone(), 1).await;
    assert!(
        verify_inclusion(&bob_leaf, idx1, tsz1, &path1, root2),
        "enrollee #2's binding is inclusion-provable"
    );

    // ---- (3) CONSISTENCY proof between the two tree heads verifies. ----
    let cons = fetch_consistency(sink_addr, sink_pki.client_config.clone(), size1).await;
    assert!(
        verify_consistency(size1, root1, size2, root2, &cons),
        "the head after enrollee #2 is an append-only extension of the head after #1"
    );
    // A forged later root cannot reconcile with the earlier one.
    let mut forged_root2 = root2;
    forged_root2[0] ^= 0x01;
    assert!(
        !verify_consistency(size1, root1, size2, forged_root2, &cons),
        "a forged extension is rejected"
    );
}
