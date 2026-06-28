//! End-to-end **enrollment → KT log → client-accept** test over loopback TLS
//! (`docs/sink-interface.md` §8, DESIGN §7.4) — the P7.12 KT exit gate.
//!
//! A real `sink-server` (with its directory key-transparency log) is stood up on a
//! loopback TLS 1.3 port with a pinned self-signed cert. The ceremony side signs a
//! real `DirBinding` with `admin-core`'s `DirectorySigner` (D5), publishes its
//! canonical leaf bytes to the KT log (`POST /v1/dir-log/bindings`, admin bearer),
//! then fetches the signed checkpoint + inclusion proof and runs the REAL client
//! confirm (`client-core::transparency::confirm_binding_logged`) pinned to the
//! sink's `dir_log_public()` — exactly the issuer-side confirm enrollment runs
//! before declaring the binding live. The capstone assertions are:
//!   * an ENROLLED (published) binding is inclusion-provable and client-accepted
//!     under the pinned KT key, and
//!   * a NOT-published binding fails the confirm (`KtError::NotIncluded`,
//!     fail closed), so a first-contact client would reject it.

use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use maxsecu_admin_core::DirectorySigner;
use maxsecu_client_core::transparency::{
    confirm_binding_logged, InclusionProof, KtCheckpoint, KtCheckpointStore, KtError,
    MemoryKtCheckpointStore,
};
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};
use maxsecu_sink_server::{router, serve, Anchorer, SinkState};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

const TOKEN: &str = "sink-admin-secret";

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

/// A real candidate `DirBinding` for user `uid` (the enrollee's bound keys).
fn binding(uid: u8) -> DirBinding {
    DirBinding {
        username: Text::new("alice").unwrap(),
        user_id: Id([uid; 16]),
        enc_pub: Bytes32([uid; 32]),
        sig_pub: Bytes32([uid ^ 0xFF; 32]),
        key_version: 1,
        roles: RoleSet::new([Role::User]),
        not_before: Timestamp(1_000),
        not_after: Timestamp(9_000_000_000_000),
        mlkem_pub: None,
    }
}

/// Open a fresh TLS connection to the sink and hand back an HTTP/1 sender.
async fn connect(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
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

/// POST one canonical `DirBinding` leaf to the KT log over TLS; return `(status,
/// new_index)` (index present only on 200).
async fn post_binding(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    token: &str,
    binding_bytes: &[u8],
) -> (StatusCode, Option<u64>) {
    let mut sender = connect(addr, client_config).await;
    let body = serde_json::json!({ "binding_b64": B64.encode(binding_bytes) }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/dir-log/bindings")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let index = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("index").and_then(|i| i.as_u64()));
    (status, index)
}

/// GET an arbitrary KT-log path over TLS and return the parsed JSON.
async fn get_json(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    path: &str,
) -> serde_json::Value {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
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

/// Fetch the KT checkpoint and the inclusion proof for `index` over TLS, mapped
/// into the client verifier's `KtCheckpoint` / `InclusionProof` shapes.
async fn fetch_checkpoint_and_inclusion(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    index: u64,
) -> (KtCheckpoint, InclusionProof) {
    let cp = get_json(addr, client_config.clone(), "/v1/dir-log/checkpoint").await;
    let checkpoint = KtCheckpoint {
        tree_size: cp["tree_size"].as_u64().unwrap(),
        root: b64_fixed::<32>(&cp, "root_b64"),
        sig: b64_fixed::<64>(&cp, "sig_b64"),
    };
    let inc = get_json(
        addr,
        client_config,
        &format!("/v1/dir-log/inclusion?index={index}"),
    )
    .await;
    let path = inc["path_b64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| B64.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();
    let inclusion = InclusionProof {
        index: inc["index"].as_u64().unwrap(),
        tree_size: inc["tree_size"].as_u64().unwrap(),
        path,
    };
    (checkpoint, inclusion)
}

#[tokio::test]
async fn enrolled_binding_published_to_kt_log_is_inclusion_provable_over_tls() {
    let pki = test_pki();

    // ---- 1. Stand up the sink (with its directory KT log) over loopback TLS.
    // Capture the pinned KT pubkey BEFORE moving the state into the router. ----
    let anchorer = Anchorer::new(
        maxsecu_crypto::SigningKey::generate(),
        maxsecu_crypto::SigningKey::generate(),
    );
    let state = SinkState::new(anchorer, TOKEN);
    let kt_pin = [state.dir_log_public()];
    let app = router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), app));

    // ---- 2. The ceremony signs a real DirBinding with D5 (admin-core). ----
    let d5 = DirectorySigner::generate();
    let candidate = binding(0x11);
    let signed = d5.sign_binding(&candidate, None);
    // The KT leaf is the canonical DirBinding bytes the directory publishes (§7.2);
    // it verifies under the pinned D5 root before we ever publish it (sanity).
    signed.verify(&d5.public_key()).expect("D5-signed binding verifies");
    let leaf_bytes = maxsecu_encoding::encode(&signed.binding);

    // ---- 3. Publish the signed binding to the KT log over TLS (admin-gated). ----
    let (status, index) =
        post_binding(addr, pki.client_config.clone(), TOKEN, &leaf_bytes).await;
    assert_eq!(status, StatusCode::OK);
    let index = index.expect("publish returns the new leaf index");
    assert_eq!(index, 0, "first enrolled binding lands at leaf 0");

    // ---- 4. Fetch the checkpoint + inclusion proof over the pinned channel and
    // run the REAL issuer-side confirm pinned to the sink's dir_log_public(). ----
    let (checkpoint, inclusion) =
        fetch_checkpoint_and_inclusion(addr, pki.client_config.clone(), index).await;
    let mut store = MemoryKtCheckpointStore::new();
    confirm_binding_logged(&leaf_bytes, &inclusion, &checkpoint, &kt_pin, &mut store)
        .expect("enrolled binding is inclusion-provable + client-accepted over TLS");
    // The confirmed checkpoint is pinned (TOFU) — the issuer treats enrollment done.
    assert_eq!(store.latest(), Some(checkpoint));

    // ---- 5. Fail-closed: a NOT-published binding fails the confirm. A different
    // user's binding was never POSTed, so its leaf is absent under the checkpoint
    // root — the confirm returns NotIncluded (a first-contact client would reject
    // it), even reusing the genuine, KT-signed checkpoint + an in-range proof. ----
    let unpublished = maxsecu_encoding::encode(&d5.sign_binding(&binding(0x22), None).binding);
    assert_eq!(
        confirm_binding_logged(
            &unpublished,
            &inclusion,
            &checkpoint,
            &kt_pin,
            &mut MemoryKtCheckpointStore::new(),
        ),
        Err(KtError::NotIncluded),
        "an un-enrolled binding is not inclusion-provable (fail closed)"
    );
}
