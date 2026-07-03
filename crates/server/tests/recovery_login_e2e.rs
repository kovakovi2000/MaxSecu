//! T5 exit-gate end-to-end test: the **channel-bound one-time recovery login**
//! over real loopback TLS (spec §6 / §0-D6, trusted-server-recovery track).
//!
//! Proves the trusted-server recovery account can log in WITHOUT ever handing the
//! server a private key, and that the resulting session authorizes admin server
//! actions:
//!
//! - `POST /v1/recovery/register` is once-only (a second attempt → 409);
//! - `POST /v1/recovery/challenge` returns a blob that UNWRAPS with the recovery
//!   private key to a fresh 32-byte nonce (hybrid when ML-KEM is present);
//! - `POST /v1/recovery/verify` with a correct CHANNEL-BOUND proof over
//!   `(nonce, server_id, this-exporter)` → 200 + a session token that can
//!   `POST /v1/registration-keys` (an admin action) → 201;
//! - a REPLAYED challenge (verify twice) → the second is rejected (single-use);
//! - a proof built with a DIFFERENT connection's exporter → rejected (relay);
//! - a proof signed by the WRONG key → rejected;
//! - a **classical** (no ML-KEM) recovery account round-trips the wrap/unwrap and
//!   logs in too.

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

use maxsecu_crypto::{
    deserialize_hybrid_wrap, generate_enc_keypair, generate_hybrid_keypair, unwrap_dek,
    unwrap_dek_hybrid, EncSecretKey, HybridEncSecretKey, SigningKey, WrappedDek,
};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{AuthProofContext, WrapContext};
use maxsecu_encoding::types::{Bytes32, Id, Text, Timestamp};
use maxsecu_encoding::RECOVERY_ID;
use maxsecu_server::{
    export_channel_binding, router, serve, AppState, AuthConfig, AuthService, MemoryBlobStore,
    MemoryStore, NullAuditSink,
};

const TS: u64 = 1_719_500_000_000;

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
    get_auth(conn, uri, None).await
}

async fn get_auth(
    conn: &mut Conn,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost");
    if let Some(t) = auth {
        builder = builder.header("authorization", format!("MaxSecu-Session {t}"));
    }
    let req = builder.body(Full::new(Bytes::new())).unwrap();
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

fn hex16(s: &str) -> [u8; 16] {
    let v = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    v.try_into().unwrap()
}

/// The WrapContext the server binds a recovery challenge wrap to (spec §6): the
/// challenge_id as `file_id`, version 0, `recipient_id = RECOVERY_ID`. The client
/// (and this test) reconstructs it from the returned `challenge_id` to unwrap.
fn challenge_ctx(challenge_id: &[u8; 16]) -> WrapContext {
    WrapContext {
        file_id: Id(*challenge_id),
        version: 0,
        recipient_id: RECOVERY_ID,
    }
}

/// Sign the channel-bound recovery proof (mirrors client-core `build_login_proof`).
fn recovery_proof(
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

async fn start(state: AppState<MemoryStore>) -> (std::net::SocketAddr, Arc<ClientConfig>) {
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), router(state)));
    (addr, pki.client_config.clone())
}

fn state_with_admin_gate() -> AppState<MemoryStore> {
    // The recovery admin session must satisfy the SAME D5 admin gate as a real
    // admin, so the server must have a pinned directory pub configured.
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

#[tokio::test]
async fn recovery_login_hybrid_over_real_tls() {
    // The operator's cold recovery identity: X25519 + ML-KEM-768 (hybrid) enc key
    // and an Ed25519 sig key. The server only ever sees the PUBLIC halves.
    let (enc_sec, enc_pub): (HybridEncSecretKey, _) = generate_hybrid_keypair();
    let sig = SigningKey::generate();

    let state = state_with_admin_gate();
    let (addr, client_config) = start(state).await;
    let mut c = connect(addr, client_config).await;

    // ---- register the recovery account once (what maxsecu-setup calls). ----
    let reg = serde_json::json!({
        "enc_pub_b64": B64.encode(enc_pub.x25519),
        "sig_pub_b64": B64.encode(sig.verifying_key().to_bytes()),
        "mlkem_pub_b64": B64.encode(enc_pub.mlkem),
    });
    let (st, _) = post(&mut c, "/v1/recovery/register", None, reg.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "first recovery registration wins");

    // A second registration is refused (once-only).
    let (st, _) = post(&mut c, "/v1/recovery/register", None, reg).await;
    assert_eq!(st, StatusCode::CONFLICT, "recovery account is once-only (409)");

    // ---- pubkey endpoint serves the enc + mlkem the client pins against. ----
    let (st, body) = get(&mut c, "/v1/recovery/pubkey").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        B64.decode(body["enc_pub_b64"].as_str().unwrap()).unwrap(),
        enc_pub.x25519.to_vec(),
        "served recovery enc_pub matches the registered one"
    );
    assert!(body["mlkem_pub_b64"].is_string(), "hybrid account serves ML-KEM pub");

    // ---- challenge → unwrap the nonce with the recovery private key. ----
    let (st, ch) = post(&mut c, "/v1/recovery/challenge", None, serde_json::json!({})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(ch["suite"].as_str().unwrap(), "v2", "hybrid account → v2 wrap");
    let server_id = ch["server_id"].as_str().unwrap().to_owned();
    let challenge_id = hex16(ch["challenge_id"].as_str().unwrap());
    let blob = B64.decode(ch["wrapped_blob_b64"].as_str().unwrap()).unwrap();
    let wrapped = deserialize_hybrid_wrap(&blob).unwrap();
    let dek = unwrap_dek_hybrid(&enc_sec, &wrapped, &challenge_ctx(&challenge_id)).unwrap();
    let nonce: [u8; 32] = *dek.expose();

    // ---- verify a CHANNEL-BOUND proof → 200 + a session token. ----
    let proof = recovery_proof(&sig, &server_id, &c.exporter, &nonce, TS);
    let (st, res) = post(
        &mut c,
        "/v1/recovery/verify",
        None,
        serde_json::json!({ "challenge_id": ch["challenge_id"], "proof_b64": proof, "timestamp": TS }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "correct channel-bound proof logs in");
    let token = res["session_token"].as_str().unwrap().to_owned();

    // ---- the recovery session authorizes an ADMIN action (mint a reg key). ----
    let (st, res) = post(
        &mut c,
        "/v1/registration-keys",
        Some(&token),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "recovery session mints a registration key");
    assert!(!res["registration_key"].as_str().unwrap().is_empty());

    // ---- BLAST RADIUS (spec §9): the recovery session authorizes admin SERVER
    // actions ONLY. It must be refused on file/content endpoints (403) — it is not
    // a general file-read/write principal — even though it just minted a key. ----
    let (st, _) = get_auth(
        &mut c,
        "/v1/files/00000000000000000000000000000000",
        Some(&token),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "recovery session is refused on file endpoints (not a file principal)"
    );
    let (st, _) = post(
        &mut c,
        "/v1/files",
        Some(&token),
        serde_json::json!({
            "file_id": "00000000000000000000000000000000",
            "file_type": "image",
            "genesis_b64": "", "genesis_sig_b64": "",
            "manifest_b64": "", "manifest_sig_b64": "",
            "streams": [], "wraps": []
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "recovery session cannot create/write files"
    );

    // ---- REPLAY: verifying the same challenge again is rejected (single-use). ----
    let proof2 = recovery_proof(&sig, &server_id, &c.exporter, &nonce, TS);
    let (st, _) = post(
        &mut c,
        "/v1/recovery/verify",
        None,
        serde_json::json!({ "challenge_id": ch["challenge_id"], "proof_b64": proof2, "timestamp": TS }),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "a consumed challenge cannot be replayed");

    // ---- RELAY: a proof bound to a DIFFERENT exporter is rejected. ----
    let (_st, ch) = post(&mut c, "/v1/recovery/challenge", None, serde_json::json!({})).await;
    let cid = hex16(ch["challenge_id"].as_str().unwrap());
    let blob = B64.decode(ch["wrapped_blob_b64"].as_str().unwrap()).unwrap();
    let n: [u8; 32] = *unwrap_dek_hybrid(
        &enc_sec,
        &deserialize_hybrid_wrap(&blob).unwrap(),
        &challenge_ctx(&cid),
    )
    .unwrap()
    .expose();
    let wrong_channel = recovery_proof(&sig, &server_id, &[0x00; 32], &n, TS);
    let (st, _) = post(
        &mut c,
        "/v1/recovery/verify",
        None,
        serde_json::json!({ "challenge_id": ch["challenge_id"], "proof_b64": wrong_channel, "timestamp": TS }),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "a relayed (wrong-exporter) proof is rejected");

    // ---- WRONG KEY: a proof signed by a different key is rejected. ----
    let attacker = SigningKey::generate();
    let bad_key = recovery_proof(&attacker, &server_id, &c.exporter, &n, TS);
    let (st, _) = post(
        &mut c,
        "/v1/recovery/verify",
        None,
        serde_json::json!({ "challenge_id": ch["challenge_id"], "proof_b64": bad_key, "timestamp": TS }),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "a proof under the wrong key is rejected");
}

#[tokio::test]
async fn recovery_login_classical_wrap_round_trips() {
    // A classical-only recovery account (no ML-KEM): the challenge wraps with
    // X25519 HPKE and still logs in over the channel-bound proof.
    let (enc_sec, enc_pub): (EncSecretKey, _) = generate_enc_keypair();
    let sig = SigningKey::generate();

    let state = state_with_admin_gate();
    let (addr, client_config) = start(state).await;
    let mut c = connect(addr, client_config).await;

    let reg = serde_json::json!({
        "enc_pub_b64": B64.encode(enc_pub.to_bytes()),
        "sig_pub_b64": B64.encode(sig.verifying_key().to_bytes()),
        // no mlkem_pub_b64 → classical account
    });
    let (st, _) = post(&mut c, "/v1/recovery/register", None, reg).await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, ch) = post(&mut c, "/v1/recovery/challenge", None, serde_json::json!({})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(ch["suite"].as_str().unwrap(), "v1", "classical account → v1 wrap");
    let server_id = ch["server_id"].as_str().unwrap().to_owned();
    let cid = hex16(ch["challenge_id"].as_str().unwrap());
    let blob = B64.decode(ch["wrapped_blob_b64"].as_str().unwrap()).unwrap();
    // Classical blob wire form: enc(32) ‖ ct.
    let wrapped = WrappedDek {
        enc: blob[..32].try_into().unwrap(),
        ct: blob[32..].to_vec(),
    };
    let nonce: [u8; 32] = *unwrap_dek(&enc_sec, &wrapped, &challenge_ctx(&cid))
        .unwrap()
        .expose();

    let proof = recovery_proof(&sig, &server_id, &c.exporter, &nonce, TS);
    let (st, res) = post(
        &mut c,
        "/v1/recovery/verify",
        None,
        serde_json::json!({ "challenge_id": ch["challenge_id"], "proof_b64": proof, "timestamp": TS }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "classical recovery logs in");
    let token = res["session_token"].as_str().unwrap().to_owned();
    let (st, _) = post(
        &mut c,
        "/v1/registration-keys",
        Some(&token),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "classical recovery session is admin");
}
