//! **Phase-7 capstone end-to-end test (DESIGN §17 Phase 7).** Demonstrates the
//! committed Phase-7 exit gates over the REAL stack/TLS, in one capstone, plus
//! the P7.8 genesis-anchor ordering add-on. (The retired T6 Shamir K-of-N
//! recovery-threshold gate is intentionally absent — recovery no longer uses
//! threshold custody.)
//!
//! 1. **PQ wrap (P7.5).** A PQ-enrolled owner + a PQ recovery binding upload a
//!    file over loopback TLS; `build_upload` emits `Suite::V2` HYBRID wraps. The
//!    owner downloads over TLS and recovers the EXACT plaintext via its hybrid
//!    secret (`enc_secret` + `mlkem_seed`). Every stored wrap is the 1168-byte
//!    hybrid wire form — assert NO classical V1 wrap is present.
//! 2. **KT split-view (P7.10/P7.12).** A `sink-server` KT log is stood up over
//!    TLS under a PINNED log key; bindings are enrolled → published → the client
//!    accepts via inclusion (and an advance via a consistency proof). A SECOND
//!    sink under the SAME KT key serves a forked checkpoint inconsistent with the
//!    gossiped one → the client returns `KtError::SplitView` (detected + rejected),
//!    and the pinned gossip state is unchanged.
//!
//! Add-on (P7.8): the real V2 upload anchors a `genesis` at a global sink
//! position; a control append + a second anchor order globally (genesis-after-
//! control ⇒ strictly higher position).

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_admin_core::{
    ControlChain, CoSign, DirectorySigner, KeyCompromiseParams, RevokeParams,
};
use maxsecu_client_core::transparency::{
    confirm_binding_logged, verify_binding_in_log, InclusionProof, KtCheckpoint, KtCheckpointStore,
    KtError, MemoryKtCheckpointStore,
};
use maxsecu_client_core::{
    build_upload, verify_and_open, CompromiseCheck, DownloadBundle, DownloadError, Identity,
    PlaintextStreams, StreamChunks, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, generate_enc_keypair, generate_mlkem_keypair, sha256, SigningKey,
    WrappedDek,
};
use maxsecu_encoding::structs::{DirBinding, Manifest};
use maxsecu_encoding::types::{
    Bytes32, FileScope, FileType, Id, MlKemPub, RecipientType, Role, RoleSet, StreamType, Suite,
    Text, Timestamp,
};
use maxsecu_encoding::{encode, labels};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuditSink, AuthConfig, AuthService, FsBlobStore,
    HttpSinkPublisher, MemoryStore, Store, UserRecord,
};
use maxsecu_sink_server::{router as sink_router, serve as sink_serve, Anchorer, SinkState};

const VOUCHER: &str = "in-person-code-p7";
const TS: u64 = 1_719_500_000_000;
const TOKEN: &str = "sink-admin-secret";
const CONTENT: &[u8] = b"PQ_TOPSECRET_PLAINTEXT_MARKER_777_hybrid_v2_must_round_trip_exactly";
/// A stable seed for the directory KT log key, so the honest sink and the fork
/// sink sign checkpoints under the SAME pinned key (the split-view setup).
const KT_SEED: [u8; 32] = [0x7C; 32];

// ---- TLS harness (mirrors file_e2e.rs / sink_publish_e2e.rs) ----

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

async fn put_raw(conn: &mut Conn, uri: &str, auth: &str, body: Vec<u8>) -> StatusCode {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    conn.sender.send_request(req).await.unwrap().status()
}

async fn get_json(conn: &mut Conn, uri: &str, auth: &str) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
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

async fn get_raw(conn: &mut Conn, uri: &str, auth: &str) -> (StatusCode, Vec<u8>) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = conn.sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes)
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn stream_name(st: StreamType) -> &'static str {
    match st {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
}

fn stream_from_name(s: &str) -> StreamType {
    match s {
        "content" => StreamType::Content,
        "metadata" => StreamType::Metadata,
        "thumbnail" => StreamType::Thumbnail,
        "preview" => StreamType::Preview,
        _ => panic!("unknown stream {s}"),
    }
}

/// Wire form of a wrap: `enc(32) ‖ ct` — the opaque bytes the server stores. For
/// a Suite::V2 wrap this is exactly the 1168-byte hybrid wire form.
fn wrap_bytes(w: &WrappedDek) -> Vec<u8> {
    let mut v = w.enc.to_vec();
    v.extend_from_slice(&w.ct);
    v
}
fn wrap_from_bytes(b: &[u8]) -> WrappedDek {
    WrappedDek {
        enc: b[..32].try_into().unwrap(),
        ct: b[32..].to_vec(),
    }
}

/// Register a PQ identity over TLS with the in-person voucher and return its
/// server-assigned user id.
async fn register(c: &mut Conn, username: &str, id: &Identity) -> [u8; 16] {
    let (st, res) = post(
        c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(id.sig_pub_bytes()),
            "registration_key": VOUCHER,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS");
    hex16(res["user_id"].as_str().unwrap())
}

/// Log in over the bound channel and return the session token.
async fn login(c: &mut Conn, username: &str, id: &Identity) -> String {
    let (_st, ch) = post(
        c,
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
    let proof = {
        use maxsecu_encoding::structs::AuthProofContext;
        let ctx = AuthProofContext {
            server_id: Text::new(&server_id).unwrap(),
            tls_exporter: Bytes32(c.exporter),
            nonce: Bytes32(nonce),
            timestamp: Timestamp(TS),
        };
        B64.encode(id.signing_key().sign_canonical(labels::AUTH, &ctx))
    };
    let (st, res) = post(
        c,
        "/v1/session/proof",
        None,
        serde_json::json!({"username": username, "timestamp": TS, "proof_b64": proof}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login over the bound channel");
    res["session_token"].as_str().unwrap().to_owned()
}

/// Stage + PUT all chunks + finalize a built upload bundle over TLS. Returns the
/// `file_id` hex.
async fn stage_upload(
    c: &mut Conn,
    token: &str,
    bundle: &maxsecu_client_core::UploadBundle,
    file_type: &str,
) -> String {
    let fid_hex = hex(&bundle.file_id.0);
    let stream_specs: Vec<serde_json::Value> = bundle
        .streams
        .iter()
        .map(|s| {
            serde_json::json!({
                "stream_type": stream_name(s.stream_type),
                "chunk_count": s.chunk_count,
                "chunk_size": s.chunk_size,
                "total_bytes": s.total_bytes,
            })
        })
        .collect();
    let wrap_alg = if matches!(bundle.manifest.alg, Suite::V2) {
        2
    } else {
        1
    };
    let wraps: Vec<serde_json::Value> = bundle
        .wraps
        .iter()
        .map(|w| {
            let is_rec = w.recipient_type == RecipientType::Recovery;
            serde_json::json!({
                "recipient_id": if is_rec { "recovery".to_owned() } else { hex(&w.recipient_id.0) },
                "recipient_type": if is_rec { "recovery" } else { "user" },
                "wrapped_dek_b64": B64.encode(wrap_bytes(&w.wrapped_dek)),
                "wrap_alg": wrap_alg,
                "granted_by": hex(&w.granted_by.0),
                "grant_b64": B64.encode(encode(&w.grant)),
                "grant_sig_b64": B64.encode(w.grant_sig),
            })
        })
        .collect();
    let body = serde_json::json!({
        "file_id": fid_hex,
        "file_type": file_type,
        "genesis_b64": B64.encode(encode(&bundle.genesis)),
        "genesis_sig_b64": B64.encode(bundle.genesis_sig),
        "manifest_b64": B64.encode(encode(&bundle.manifest)),
        "manifest_sig_b64": B64.encode(bundle.manifest_sig),
        "streams": stream_specs,
        "wraps": wraps,
    });
    let (st, _res) = post(c, "/v1/files", Some(token), body).await;
    assert_eq!(st, StatusCode::CREATED, "stage upload");
    for s in &bundle.streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            let uri = format!(
                "/v1/files/{fid_hex}/versions/1/streams/{}/chunks/{i}",
                stream_name(s.stream_type)
            );
            assert_eq!(
                put_raw(c, &uri, token, chunk.clone()).await,
                StatusCode::OK
            );
        }
    }
    let (st, _) = post(
        c,
        &format!("/v1/files/{fid_hex}/versions/1/finalize"),
        Some(token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize");
    fid_hex
}

/// GET the file records + every ciphertext chunk back and rebuild a `DownloadBundle`.
async fn fetch_download_bundle(c: &mut Conn, token: &str, fid_hex: &str) -> DownloadBundle {
    let (st, rec) = get_json(c, &format!("/v1/files/{fid_hex}?version=latest"), token).await;
    assert_eq!(st, StatusCode::OK);
    let mut dl_streams = Vec::new();
    for s in rec["streams"].as_array().unwrap() {
        let st_name = s["stream_type"].as_str().unwrap();
        let count = s["chunk_count"].as_u64().unwrap();
        let mut chunks = Vec::new();
        for i in 0..count {
            let uri = format!("/v1/files/{fid_hex}/versions/1/streams/{st_name}/chunks/{i}");
            let (cs, bytes) = get_raw(c, &uri, token).await;
            assert_eq!(cs, StatusCode::OK);
            chunks.push(bytes);
        }
        dl_streams.push(StreamChunks {
            stream_type: stream_from_name(st_name),
            chunks,
        });
    }
    let dec = |v: &serde_json::Value| B64.decode(v.as_str().unwrap()).unwrap();
    let dec64 = |v: &serde_json::Value| -> [u8; 64] { dec(v).try_into().unwrap() };
    let mw = &rec["my_wrap"];
    let rg = &rec["recovery_grant"];
    DownloadBundle {
        manifest_bytes: dec(&rec["manifest_b64"]),
        manifest_sig: dec64(&rec["manifest_sig_b64"]),
        genesis_bytes: dec(&rec["genesis_b64"]),
        genesis_sig: dec64(&rec["genesis_sig_b64"]),
        wrapped_dek: wrap_from_bytes(&dec(&mw["wrapped_dek_b64"])),
        grant_bytes: dec(&mw["grant_b64"]),
        grant_sig: dec64(&mw["grant_sig_b64"]),
        ancestor_grants: vec![],
        recovery_grant_bytes: dec(&rg["grant_b64"]),
        recovery_grant_sig: dec64(&rg["grant_sig_b64"]),
        streams: dl_streams,
    }
}

// ---- sink helpers (KT log + genesis anchor) ----

/// Open a fresh TLS connection to a sink and hand back an HTTP/1 sender.
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

/// POST one canonical `DirBinding` leaf to a sink's KT log over TLS; assert 200
/// and return the new leaf index.
async fn post_binding(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    leaf: &[u8],
) -> u64 {
    let mut sender = sink_connect(addr, client_config).await;
    let body = serde_json::json!({ "binding_b64": B64.encode(leaf) }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/dir-log/bindings")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "publish binding to KT log");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["index"]
        .as_u64()
        .unwrap()
}

/// GET an arbitrary path from a sink over TLS and return the parsed JSON.
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

/// Fetch the KT checkpoint over TLS, mapped to the client verifier's shape.
async fn fetch_checkpoint(addr: std::net::SocketAddr, cc: Arc<ClientConfig>) -> KtCheckpoint {
    let cp = sink_get_json(addr, cc, "/v1/dir-log/checkpoint").await;
    KtCheckpoint {
        tree_size: cp["tree_size"].as_u64().unwrap(),
        root: b64_fixed::<32>(&cp, "root_b64"),
        sig: b64_fixed::<64>(&cp, "sig_b64"),
    }
}

/// Fetch an inclusion proof for `index` over TLS, mapped to the client shape.
async fn fetch_inclusion(
    addr: std::net::SocketAddr,
    cc: Arc<ClientConfig>,
    index: u64,
) -> InclusionProof {
    let inc = sink_get_json(addr, cc, &format!("/v1/dir-log/inclusion?index={index}")).await;
    let path = inc["path_b64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| B64.decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();
    InclusionProof {
        index: inc["index"].as_u64().unwrap(),
        tree_size: inc["tree_size"].as_u64().unwrap(),
        path,
    }
}

/// Fetch a consistency proof `from → current` over TLS.
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

/// GET a file's recorded global genesis position over the sink's pinned channel;
/// `None` on 404.
async fn fetch_genesis_pos(
    addr: std::net::SocketAddr,
    cc: Arc<ClientConfig>,
    file_id: &[u8; 16],
) -> Option<u64> {
    let mut sender = sink_connect(addr, cc).await;
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/genesis-anchor/{}", hex(file_id)))
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    if resp.status() == StatusCode::NOT_FOUND {
        return None;
    }
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    Some(v["position"].as_u64().unwrap())
}

/// A real candidate `DirBinding` for a PQ-enrolled user (its bound hybrid keys).
fn pq_binding(username: &str, uid: u8, id: &Identity) -> DirBinding {
    DirBinding {
        username: Text::new(username).unwrap(),
        user_id: Id([uid; 16]),
        enc_pub: Bytes32(id.enc_pub_bytes()),
        sig_pub: Bytes32(id.sig_pub_bytes()),
        key_version: 1,
        roles: RoleSet::new([Role::User]),
        not_before: Timestamp(1_000),
        not_after: Timestamp(9_000_000_000_000),
        mlkem_pub: Some(MlKemPub(id.mlkem_pub_bytes().unwrap())),
    }
}

/// A filler binding (distinct keys) used to grow a KT log.
fn filler_binding(uid: u8) -> DirBinding {
    DirBinding {
        username: Text::new("filler").unwrap(),
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

#[tokio::test]
async fn phase7_exit_gates_over_real_tls() {
    // ============================================================
    // Stand up the HONEST sink (genesis anchoring + KT log) over TLS, with a
    // PINNED KT log key so the fork can sign under the same key.
    // ============================================================
    let sink_pki = test_pki();
    let kt_key = SigningKey::from_seed(&KT_SEED);
    let kt_pin = [kt_key.verifying_key().to_bytes()];
    let sink_state = SinkState::with_dir_log_key(
        Anchorer::new(SigningKey::generate(), SigningKey::generate()),
        TOKEN,
        kt_key,
    );
    assert_eq!(
        sink_state.dir_log_public(),
        kt_pin[0],
        "the sink signs KT checkpoints under the pinned key"
    );
    let sink_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink_listener.local_addr().unwrap();
    tokio::spawn(sink_serve(
        sink_listener,
        sink_pki.server_config.clone(),
        sink_router(sink_state),
    ));

    // ============================================================
    // Stand up the APP server, with a real HttpSinkPublisher pinned to the sink
    // (so a file create anchors a genesis at a real, global sink position).
    // ============================================================
    let store = MemoryStore::new();
    store.add_reg_key(sha256(VOUCHER.as_bytes()));
    let signer = Arc::new(SigningKey::generate());
    let dir_pub = signer.verifying_key().to_bytes();
    let publisher =
        HttpSinkPublisher::new(sink_addr, "localhost", sink_pki.client_config.clone(), TOKEN);
    let blob_dir =
        std::env::temp_dir().join(format!("mxp7_{}", hex(&maxsecu_crypto::random_array::<8>())));
    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(dir_pub))
                .with_dir_signer(signer),
        ),
        blobs: Arc::new(FsBlobStore::new(&blob_dir)),
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
        maxsecu_server::router(state),
    ));

    let mut c = connect(app_addr, app_pki.client_config.clone()).await;

    // A PQ-enrolled owner (Identity::generate is always PQ from P7.4).
    let owner = Identity::generate();
    assert!(owner.mlkem_pub_bytes().is_some(), "owner is PQ-enrolled");
    assert!(owner.mlkem_seed().is_some(), "owner holds its ML-KEM seed");
    let user_id = register(&mut c, "alice", &owner).await;
    let token = login(&mut c, "alice", &owner).await;

    // A PQ recovery key: an X25519 leg + an ML-KEM-768 leg (the recovery binding).
    let (_rec_x_sk, rec_x_pk) = generate_enc_keypair();
    let (_rec_mlkem_seed, rec_mlkem_pub) = generate_mlkem_keypair();

    // ============================================================
    // GATE 1 — PQ wrap: a real V2 upload over TLS, downloaded + recovered.
    // ============================================================
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let mut content = Vec::new();
    while content.len() < 4096 * 3 + 100 {
        content.extend_from_slice(CONTENT);
    }
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Blog,
        chunk_size: 4096,
        recovery_pub: rec_x_pk,
        recovery_mlkem_pub: Some(rec_mlkem_pub),
        created_at: Timestamp(TS),
    };
    let streams = PlaintextStreams {
        content: content.clone(),
        metadata: None,
        thumbnail: None,
        preview: None,
    };
    let bundle = build_upload(&params, &streams).unwrap();

    // The upload IS Suite::V2 (PQ owner + PQ recovery ⇒ hybrid wraps).
    assert!(
        matches!(bundle.manifest.alg, Suite::V2),
        "PQ owner + PQ recovery ⇒ Suite::V2 hybrid wraps"
    );
    // EVERY stored wrap is the 1168-byte hybrid wire form — NO classical V1 wrap.
    assert_eq!(bundle.wraps.len(), 2, "owner self-wrap + recovery wrap");
    for w in &bundle.wraps {
        let wire = wrap_bytes(&w.wrapped_dek);
        assert_eq!(wire.len(), 1168, "hybrid wrap is 1168 bytes (no 32+ct V1 wrap)");
        deserialize_hybrid_wrap(&wire).expect("every wrap deserializes as a hybrid wrap");
    }

    // Stage + upload + finalize over TLS (this also anchors the genesis to the sink).
    let fid_hex = stage_upload(&mut c, &token, &bundle, "blog").await;

    // Download over TLS and recover the EXACT plaintext via the hybrid secret.
    let good = fetch_download_bundle(&mut c, &token, &fid_hex).await;
    let dl_manifest: Manifest = maxsecu_encoding::decode(&good.manifest_bytes).unwrap();
    assert!(
        matches!(dl_manifest.alg, Suite::V2),
        "the served manifest is Suite::V2"
    );
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(user_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: owner.mlkem_seed(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened = verify_and_open(&ctx, &good).expect("V2 round-trips over real TLS");
    assert_eq!(opened.version, 1);
    assert!(opened.recovery_grant_ok, "recovery grant present + valid");
    let got = &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    assert_eq!(got, &content, "exact plaintext recovered via the hybrid wrap");

    // Negative control: WITHOUT the ML-KEM seed, a V2 wrap cannot be opened.
    let no_pq = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(user_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    assert!(
        verify_and_open(&no_pq, &good).is_err(),
        "a V2 wrap cannot open without the ML-KEM seed leg"
    );

    // ============================================================
    // GATE 2 — KT split-view over real TLS.
    // ============================================================
    // Enroll bindings into the HONEST sink's KT log. The app server ALREADY
    // auto-published alice's *enrollment* binding here at leaf 0 (T6 — enrollment →
    // transparency log), so the explicitly-published PQ owner binding below lands at
    // the NEXT leaf; add fillers so the tree grows (a meaningful consistency proof
    // later).
    let d5 = DirectorySigner::generate();
    let owner_binding = pq_binding("alice", 0x11, &owner);
    let owner_leaf = encode(&d5.sign_binding(&owner_binding, None).binding);
    let owner_idx = post_binding(sink_addr, sink_pki.client_config.clone(), &owner_leaf).await;
    assert_eq!(owner_idx, 1, "the enrollment binding is leaf 0; the owner binding follows");
    for u in [0x21u8, 0x22] {
        let leaf = encode(&d5.sign_binding(&filler_binding(u), None).binding);
        post_binding(sink_addr, sink_pki.client_config.clone(), &leaf).await;
    }

    // The client ACCEPTS the enrolled owner binding via inclusion under a pinned,
    // KT-signed checkpoint (TOFU on first contact).
    let cp_a = fetch_checkpoint(sink_addr, sink_pki.client_config.clone()).await;
    assert_eq!(cp_a.tree_size, 4, "enrollment binding + owner binding + 2 fillers");
    let inc0 = fetch_inclusion(sink_addr, sink_pki.client_config.clone(), owner_idx).await;
    let mut store = MemoryKtCheckpointStore::new();
    verify_binding_in_log(&owner_leaf, &inc0, &cp_a, &[], &kt_pin, &mut store)
        .expect("enrolled binding is inclusion-provable + client-accepted over TLS");
    assert_eq!(store.latest(), Some(cp_a), "first-contact checkpoint pinned");

    // The issuer-side confirm (fresh store) agrees the binding is logged.
    confirm_binding_logged(
        &owner_leaf,
        &inc0,
        &cp_a,
        &kt_pin,
        &mut MemoryKtCheckpointStore::new(),
    )
    .expect("issuer confirm: enrolled binding is logged");

    // The client also accepts a CONSISTENT advance (grow the honest log by one,
    // verify the new checkpoint against the pinned one via a consistency proof).
    let leaf3 = encode(&d5.sign_binding(&filler_binding(0x23), None).binding);
    let leaf3_idx = post_binding(sink_addr, sink_pki.client_config.clone(), &leaf3).await;
    let cp_a2 = fetch_checkpoint(sink_addr, sink_pki.client_config.clone()).await;
    assert_eq!(cp_a2.tree_size, 5);
    let inc3 = fetch_inclusion(sink_addr, sink_pki.client_config.clone(), leaf3_idx).await;
    let cons_a = fetch_consistency(sink_addr, sink_pki.client_config.clone(), cp_a.tree_size).await;
    verify_binding_in_log(&leaf3, &inc3, &cp_a2, &cons_a, &kt_pin, &mut store)
        .expect("a consistency-proven advance is accepted");
    assert_eq!(store.latest(), Some(cp_a2), "gossip advanced to the proven checkpoint");

    // ---- The FORK: a SECOND sink under the SAME KT key, with a different (larger)
    // history. Its checkpoint cannot be reconciled with the pinned one ⇒ SplitView.
    let fork_pki = test_pki();
    let fork_state = SinkState::with_dir_log_key(
        Anchorer::new(SigningKey::generate(), SigningKey::generate()),
        TOKEN,
        SigningKey::from_seed(&KT_SEED),
    );
    assert_eq!(
        fork_state.dir_log_public(),
        kt_pin[0],
        "the fork signs under the SAME pinned KT key (equivocation)"
    );
    let fork_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fork_addr = fork_listener.local_addr().unwrap();
    tokio::spawn(sink_serve(
        fork_listener,
        fork_pki.server_config.clone(),
        sink_router(fork_state),
    ));

    // Publish DIFFERENT leaves to the fork (a divergent history, larger size).
    let mut fork_leaf0 = Vec::new();
    for (i, u) in [0xB0u8, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5].into_iter().enumerate() {
        let leaf = encode(&d5.sign_binding(&filler_binding(u), None).binding);
        let idx = post_binding(fork_addr, fork_pki.client_config.clone(), &leaf).await;
        if i == 0 {
            fork_leaf0 = leaf;
            assert_eq!(idx, 0);
        }
    }
    let cp_fork = fetch_checkpoint(fork_addr, fork_pki.client_config.clone()).await;
    assert_eq!(cp_fork.tree_size, 6, "fork log has a divergent, larger history");
    let fork_inc0 = fetch_inclusion(fork_addr, fork_pki.client_config.clone(), 0).await;
    // The fork's own (internally valid) consistency proof from the gossiped size.
    let fork_cons =
        fetch_consistency(fork_addr, fork_pki.client_config.clone(), store.latest().unwrap().tree_size)
            .await;

    // The client DETECTS + REJECTS the split view: the fork's checkpoint is not a
    // consistent extension of the pinned (honest) one.
    assert_eq!(
        verify_binding_in_log(&fork_leaf0, &fork_inc0, &cp_fork, &fork_cons, &kt_pin, &mut store),
        Err(KtError::SplitView),
        "an equivocating fork checkpoint is rejected as a split view"
    );
    assert_eq!(
        store.latest(),
        Some(cp_a2),
        "the equivocal checkpoint is NOT adopted (gossip unchanged)"
    );

    // ============================================================
    // ADD-ON (P7.8) — the real V2 upload anchored a genesis at a global sink
    // position; a control append + a later anchor order globally.
    // ============================================================
    let g1 = fetch_genesis_pos(sink_addr, sink_pki.client_config.clone(), &file_id.0)
        .await
        .expect("the real V2 file create anchored a genesis to the sink");

    // A control append draws the next global position (a separate publisher pinned
    // to the SAME sink — the app server's publisher transport). The record is a
    // real, admin-signed revocation chained onto genesis so the sink's append-only
    // check accepts it (an unparseable record would be rejected, drawing no
    // position).
    let admin = SigningKey::generate();
    let rev = ControlChain::new()
        .revoke(
            &admin,
            RevokeParams {
                scope: FileScope::Specific(Id([0x0A; 16])),
                revoked_user_id: Id([0x99; 16]),
                revoked_capability: None,
                from_version: 1,
                issued_by: Id([0xA1; 16]),
                created_at: Timestamp(TS),
            },
            None,
        )
        .unwrap();
    let probe =
        HttpSinkPublisher::new(sink_addr, "localhost", sink_pki.client_config.clone(), TOKEN);
    probe.publish_control_record(rev.bytes.clone()).await;
    // A genesis anchored AFTER the control append.
    probe.anchor_genesis([0xF9; 16]).await;
    let g2 = fetch_genesis_pos(sink_addr, sink_pki.client_config.clone(), &[0xF9; 16])
        .await
        .expect("second genesis anchored");
    assert!(g2 > g1, "a genesis anchored after a control append is globally later");
    assert_eq!(
        g2,
        g1 + 2,
        "the intervening control append consumed exactly one global position"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}

/// **R27/D28 key-compromise cutoff over the REAL sink** (DESIGN §11.7, closing the
/// last Phase-7 add-on residual). Earlier the cutoff comparison sourced the
/// `key_compromise` position from `MemoryAuditSink` because the sink served no
/// control-record position route. Now the production `HttpSinkClient` reads BOTH
/// sides of the comparison — a file's genesis anchor position AND the
/// `key_compromise` control record's unified global position — from the real sink
/// over TLS (P7.16/P7.17), so the whole R27 gate runs against the real sink:
///
///   1. owner uploads `file_before` → its genesis is anchored at sink pos `a`;
///   2. an admin issues a `key_compromise(owner, kv=1)`, which the app server
///      publishes to the sink at pos `b` (`b > a`);
///   3. owner uploads `file_after` → its genesis is anchored at pos `c` (`c > b`).
///
/// A genesis whose anchored position **predates** the compromise (`a < b`) is
/// honored; one that **postdates** it (`c > b`) is a backdated forgery and is
/// rejected `GenesisAfterCompromise`, regardless of its attacker-chosen
/// `created_at` — the position cannot be retroactively lowered.
#[tokio::test]
async fn r27_cutoff_over_real_sink() {
    // ---- Stand up the external sink over loopback TLS. ----
    let sink_pki = test_pki();
    let sink_state = SinkState::new(
        Anchorer::new(SigningKey::generate(), SigningKey::generate()),
        TOKEN,
    );
    let sink_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink_listener.local_addr().unwrap();
    tokio::spawn(sink_serve(
        sink_listener,
        sink_pki.server_config.clone(),
        sink_router(sink_state),
    ));

    // ---- App server with a real HttpSinkPublisher pinned to the sink: a file
    // create anchors its genesis there, and a control append publishes there. ----
    // An admin (fixed id + Admin role) drives the coarse control-log gate; admin2
    // only co-signs offline (structural dual control), never seen by the server.
    let admin1 = Identity::generate();
    let admin2 = Identity::generate();
    let a1_id = [0xA1u8; 16];
    let a2_id = [0xA2u8; 16];
    let store = MemoryStore::new();
    store.add_reg_key(sha256(VOUCHER.as_bytes()));
    store.add_user(
        "admin1",
        UserRecord {
            user_id: a1_id,
            enc_pub: admin1.enc_pub_bytes(),
            sig_pub: admin1.sig_pub_bytes(),
        },
    );
    // Admin authority flows from a D5-signed {User, Admin} binding (D-K), verified
    // server-side by the AdminSession gate — not an advisory roles table. The
    // server IS the D5 (registration-key enrollment signs bindings): derive the
    // ceremony signer and the server's enrollment signer from ONE seed so
    // `directory_pub` matches both.
    let d5_seed: [u8; 32] = maxsecu_crypto::random_array();
    let d5 = DirectorySigner::from_seed(&d5_seed);
    let enroll_signer = Arc::new(SigningKey::from_seed(&d5_seed));
    let admin1_binding = DirBinding {
        username: Text::new("admin1").unwrap(),
        user_id: Id(a1_id),
        enc_pub: Bytes32(admin1.enc_pub_bytes()),
        sig_pub: Bytes32(admin1.sig_pub_bytes()),
        key_version: 1,
        roles: RoleSet::new([Role::User, Role::Admin]),
        not_before: Timestamp(0),
        not_after: Timestamp(4_102_444_800_000),
        mlkem_pub: None,
    };
    let signed_a1 = d5.sign_binding(&admin1_binding, None);
    store
        .put_binding(a1_id, 1, encode(&signed_a1.binding), signed_a1.signature)
        .await
        .unwrap();
    // admin1 is the genesis admin: claim the first-admin slot so the later
    // registration-key enrollment of `owner` is {User}-only.
    assert!(store.claim_first_admin().await.unwrap());

    let publisher =
        HttpSinkPublisher::new(sink_addr, "localhost", sink_pki.client_config.clone(), TOKEN);
    let blob_dir =
        std::env::temp_dir().join(format!("mxr27_{}", hex(&maxsecu_crypto::random_array::<8>())));
    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(d5.public_key()))
                .with_dir_signer(enroll_signer),
        ),
        blobs: Arc::new(FsBlobStore::new(&blob_dir)),
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
        maxsecu_server::router(state),
    ));

    let mut c = connect(app_addr, app_pki.client_config.clone()).await;
    let mut c_admin = connect(app_addr, app_pki.client_config.clone()).await;
    let owner = Identity::generate();
    let user_id = register(&mut c, "owner", &owner).await;
    let token = login(&mut c, "owner", &owner).await;
    let admin_tok = login(&mut c_admin, "admin1", &admin1).await;

    // A PQ recovery binding so the uploads are real V2 (the cutoff is suite-agnostic).
    let (_rec_x_sk, rec_x_pk) = generate_enc_keypair();
    let (_rec_mlkem_seed, rec_mlkem_pub) = generate_mlkem_keypair();
    let content = CONTENT.repeat(64);
    let streams = PlaintextStreams {
        content: content.clone(),
        metadata: None,
        thumbnail: None,
        preview: None,
    };
    let params_for = |file_id: Id| UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Blog,
        chunk_size: 4096,
        recovery_pub: rec_x_pk,
        recovery_mlkem_pub: Some(rec_mlkem_pub),
        created_at: Timestamp(TS),
    };

    // ---- (1) file_before: genesis anchored at sink pos a. ----
    let file_before = Id(maxsecu_crypto::random_array::<16>());
    let bundle_before = build_upload(&params_for(file_before), &streams).unwrap();
    let fid_before = stage_upload(&mut c, &token, &bundle_before, "blog").await;

    // ---- (2) key_compromise(owner, kv=1): app server appends it AND publishes it
    // to the sink at the next global position (b > a). ----
    let mut chain = ControlChain::new();
    let kc = chain.key_compromise(
        admin1.signing_key(),
        KeyCompromiseParams {
            user_id: Id(user_id),
            key_version: 1,
            effective_from: Timestamp(TS),
            issued_by: Id(a1_id),
            created_at: Timestamp(TS),
        },
        CoSign {
            admin_id: Id(a2_id),
            key: admin2.signing_key(),
        },
    );
    let kc_body = serde_json::json!({
        "record_b64": B64.encode(&kc.bytes),
        "sig_b64": B64.encode(kc.sig),
        "co_sig_b64": kc.co_sig.map(|cs| B64.encode(cs)),
    });
    let (st, _) = post(&mut c_admin, "/v1/key-compromise", Some(&admin_tok), kc_body).await;
    assert_eq!(st, StatusCode::CREATED, "key_compromise appended + published to sink");

    // ---- (3) file_after: genesis anchored at sink pos c (> b). ----
    let file_after = Id(maxsecu_crypto::random_array::<16>());
    let bundle_after = build_upload(&params_for(file_after), &streams).unwrap();
    let fid_after = stage_upload(&mut c, &token, &bundle_after, "blog").await;

    // ---- Read ALL THREE positions from the REAL sink via the production client. ----
    let cc = sink_pki.client_config.clone();
    let (fb, fa) = (file_before.0, file_after.0);
    let (a, b, c_pos) = tokio::task::spawn_blocking(move || {
        let sink = maxsecu_client_core::sink::HttpSinkClient::new(sink_addr, "localhost", cc);
        let a = sink.fetch_genesis_pos(&fb).unwrap().expect("file_before anchored");
        let b = sink.fetch_control_pos(1).expect("key_compromise position at the sink");
        let c = sink.fetch_genesis_pos(&fa).unwrap().expect("file_after anchored");
        (a, b, c)
    })
    .await
    .unwrap();
    assert!(
        a < b && b < c_pos,
        "one global order: genesis_before {a} < key_compromise {b} < genesis_after {c_pos}"
    );

    // The cutoff closure is assembled AFTER the fetch — had any fetch errored we
    // would refuse to build it (fail closed). It encodes the real sink position `b`.
    let owner_id = user_id;
    let cutoff = move |id: Id, kv: u64| (id.0 == owner_id && kv == 1).then_some(b);

    // file_before's genesis predates the compromise → R27 passes → full V2 download.
    let good = fetch_download_bundle(&mut c, &token, &fid_before).await;
    let mut ok_ctx = VerifyContext {
        file_id: file_before,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(user_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: owner.mlkem_seed(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: Some(CompromiseCheck {
            genesis_sink_pos: Some(a),
            cutoff: &cutoff,
        }),
    };
    assert!(
        verify_and_open(&ok_ctx, &good).is_ok(),
        "a genesis anchored before the compromise is honored"
    );

    // file_after's genesis postdates the compromise → rejected as a backdated forgery.
    let bad = fetch_download_bundle(&mut c, &token, &fid_after).await;
    ok_ctx.file_id = file_after;
    ok_ctx.compromise = Some(CompromiseCheck {
        genesis_sink_pos: Some(c_pos),
        cutoff: &cutoff,
    });
    assert_eq!(
        verify_and_open(&ok_ctx, &bad),
        Err(DownloadError::GenesisAfterCompromise),
        "a genesis anchored after the compromise is a forgery (real-sink cutoff)"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}
