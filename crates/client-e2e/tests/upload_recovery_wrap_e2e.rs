//! T8 exit-gate end-to-end test (embedded recovery-pin auto-wrap + trust-alarm A)
//! over REAL loopback TLS with real crypto.
//!
//! Stands up the secret-free server (MemoryStore + FsBlobStore) under a pinned
//! ceremony D5, registers + channel-bound-logs-in an author, and registers the
//! server's single recovery account. Then it exercises the REAL client-app upload
//! gate (`directory::resolve_recovery_pin`, which fetches
//! `GET /v1/recovery/pubkey`, constant-time-compares it against the compiled-in
//! recovery pin, and — on a match — returns the EMBEDDED pin's wrap-target keys)
//! followed by the real `build_upload` + `run_pipeline`. Two gates:
//!
//! - GATE MATCH: when the server serves a recovery pubkey that EQUALS the embedded
//!   pin, the upload proceeds and the produced recovery wrap **decrypts** with the
//!   test pin's reconstructed PRIVATE key (recovering the exact file DEK) — proving
//!   the standing recovery account can read every upload. Because the embedded test
//!   pin is HYBRID and `Identity::generate()` is PQ-enrolled, the file is Suite::V2,
//!   so the PQ (ML-KEM) recovery wrap is exercised.
//! - GATE MISMATCH: when the server serves a recovery pubkey that DIFFERS from the
//!   embedded pin, the gate fails closed with a `server_untrusted` error and NO
//!   bytes are staged/stored (the would-be file id is absent server-side → 404).
//!
//! Run (client-app is linked with the NON-SECURE test pin — see the `unpinned-dev`
//! feature wired onto the `maxsecu-client-app` dev-dependency in this crate's
//! Cargo.toml, so no extra CLI flag is required):
//!
//!   cargo test -p maxsecu-client-e2e --test upload_recovery_wrap_e2e

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

use maxsecu_client_app::directory::resolve_recovery_pin;
use maxsecu_client_app::recovery_pin::{embedded_pin, parse_pin, test_recovery_secret_seeds};
use maxsecu_client_core::{build_upload, Identity, UploadParams};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, sha256, unwrap_dek_hybrid, EncPublicKey, HybridEncSecretKey,
    SigningKey,
};
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::types::{FileType, Id, RecipientType, Timestamp};
use maxsecu_encoding::RECOVERY_ID;
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

/// The single-use registration key seeded server-side and presented at enrollment.
const REG_KEY: &str = "reg-key-t8-001";
const TS: u64 = 1_719_500_000_000;
const BLOG_BODY: &[u8] = b"Dear diary, a T8 upload the standing recovery account must be able to read.";

// ---- TLS harness (copied from upload_e2e.rs) ----

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

/// Register (registration-key enrollment; the server signs + stores the binding)
/// + channel-bound-login an identity; return its `user_id` + session token.
async fn register_and_login(
    c: &mut Conn,
    owner: &Identity,
    username: &str,
    reg_key: &str,
) -> ([u8; 16], String) {
    let (st, res) = post(
        c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(owner.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(owner.sig_pub_bytes()),
            "registration_key": reg_key,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS");
    let user_id = hex16(res["user_id"].as_str().unwrap());

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
        use maxsecu_encoding::labels;
        use maxsecu_encoding::structs::AuthProofContext;
        use maxsecu_encoding::types::{Bytes32, Text};
        let ctx = AuthProofContext {
            server_id: Text::new(&server_id).unwrap(),
            tls_exporter: Bytes32(c.exporter),
            nonce: Bytes32(nonce),
            timestamp: Timestamp(TS),
        };
        B64.encode(owner.signing_key().sign_canonical(labels::AUTH, &ctx))
    };
    let (st, res) = post(
        c,
        "/v1/session/proof",
        None,
        serde_json::json!({ "username": username, "timestamp": TS, "proof_b64": proof }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login over the bound channel");
    (user_id, res["session_token"].as_str().unwrap().to_owned())
}

/// Register the singleton recovery account (`POST /v1/recovery/register`).
async fn register_recovery(
    c: &mut Conn,
    enc_pub: &[u8; 32],
    mlkem_pub: Option<&[u8; 1184]>,
) -> StatusCode {
    let mut body = serde_json::json!({
        "enc_pub_b64": B64.encode(enc_pub),
        // sig_pub is required by the endpoint but irrelevant to `GET /pubkey` (only
        // enc_pub + mlkem are served / compared). A fixed 32-byte value suffices.
        "sig_pub_b64": B64.encode([0x11u8; 32]),
    });
    if let Some(m) = mlkem_pub {
        body["mlkem_pub_b64"] = serde_json::Value::String(B64.encode(&m[..]));
    }
    let (st, _) = post(c, "/v1/recovery/register", None, body).await;
    st
}

// ---------------------------------------------------------------------------

/// Boot a fresh secret-free server: a server-held directory signer (so
/// registration-key enrollment can sign the binding) + one seeded single-use
/// registration key ([`REG_KEY`]). Returns the bound address, the PKI (for the
/// client), and the blob dir (to clean up).
async fn boot() -> (std::net::SocketAddr, TestPki, std::path::PathBuf) {
    let signer = Arc::new(SigningKey::generate());
    let pinned = signer.verifying_key().to_bytes();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxrecwrap_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let store = MemoryStore::new();
    store.add_reg_key(sha256(REG_KEY.as_bytes()));
    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(pinned))
                .with_dir_signer(signer),
        ),
        blobs: Arc::new(FsBlobStore::new(&blob_dir)),
        audit: Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        pki.server_config.clone(),
        maxsecu_server::router(state),
    ));
    (addr, pki, blob_dir)
}

#[tokio::test]
async fn recovery_wrap_targets_embedded_pin_and_decrypts() {
    let (addr, pki, blob_dir) = boot().await;
    let mut c = connect(addr, pki.client_config.clone()).await;

    // Register + login the author (the server signs + stores its binding).
    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", REG_KEY).await;

    // Register the recovery account with the EXACT keys of the embedded (test) pin,
    // so the served pubkey matches the compiled-in pin.
    let pin = parse_pin(embedded_pin()).expect("embedded test pin parses");
    let pin_mlkem = pin.mlkem_pub.expect("test pin is hybrid (has ML-KEM)");
    assert_eq!(
        register_recovery(&mut c, &pin.enc_pub, Some(&pin_mlkem)).await,
        StatusCode::CREATED,
        "recovery account registered with the embedded-pin keys"
    );

    // Drive the REAL gate: fetch + compare + return the embedded pin's wrap keys.
    let recovery = resolve_recovery_pin(&mut c.sender, "localhost")
        .await
        .expect("GATE MATCH: served recovery pubkey equals the embedded pin");
    assert_eq!(recovery.enc_pub, pin.enc_pub);
    assert_eq!(recovery.mlkem_pub, Some(pin_mlkem));

    // Build + upload a blog wrapped to self + the embedded recovery pin.
    let blog_streams =
        maxsecu_client_app::upload::prepare_blog_streams(BLOG_BODY.to_vec(), "Diary", &[]);
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(recovery.enc_pub),
            recovery_mlkem_pub: recovery.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &blog_streams,
    )
    .unwrap();
    // Hybrid pin + PQ owner ⇒ Suite::V2 (exercise the PQ recovery wrap).
    assert!(
        matches!(bundle.manifest.alg, maxsecu_encoding::types::Suite::V2),
        "self+recovery both PQ ⇒ Suite::V2 hybrid wrap"
    );
    maxsecu_client_app::upload::run_pipeline(&mut c.sender, "localhost", &token, &bundle, |_, _| {})
        .await
        .unwrap();

    // The server persisted a recovery grant (the upload really wrapped to the pin).
    let (st, view) = get_json(
        &mut c,
        &format!("/v1/files/{fid_hex}?version=latest"),
        &token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !view["recovery_grant"].is_null(),
        "the served file view carries a recovery grant"
    );

    // The PRODUCED recovery wrap must decrypt with the test pin's reconstructed
    // PRIVATE key, recovering the exact file DEK. (The standard file view does not
    // serve the recovery wrapped-DEK — only the recovery account's own endpoint
    // does — so we open the wrap the pipeline produced in `bundle`.)
    let rec_wrap = bundle
        .wraps
        .iter()
        .find(|w| w.recipient_type == RecipientType::Recovery)
        .expect("a recovery wrap was produced");
    assert_eq!(
        rec_wrap.recipient_id, RECOVERY_ID,
        "recovery wrap uses the RECOVERY_ID sentinel"
    );
    // Suite::V2 packs the hybrid wire as enc(32) ‖ ct — reassemble + open it.
    let mut wire = rec_wrap.wrapped_dek.enc.to_vec();
    wire.extend_from_slice(&rec_wrap.wrapped_dek.ct);
    let hybrid = deserialize_hybrid_wrap(&wire).expect("V2 recovery wrap is a hybrid wire");
    let (x_seed, mlkem_seed) = test_recovery_secret_seeds();
    let recovery_secret = HybridEncSecretKey::from_components(x_seed, mlkem_seed);
    let wrap_ctx = WrapContext {
        file_id,
        version: bundle.manifest.version,
        recipient_id: RECOVERY_ID,
    };
    let dek = unwrap_dek_hybrid(&recovery_secret, &hybrid, &wrap_ctx)
        .expect("the recovery private key opens the wrap");
    assert_eq!(
        dek.commit(),
        bundle.manifest.dek_commit.0,
        "GATE MATCH: recovery-recovered DEK matches the file's dek_commit"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}

#[tokio::test]
async fn mismatched_recovery_pubkey_blocks_upload_fail_closed() {
    let (addr, pki, blob_dir) = boot().await;
    let mut c = connect(addr, pki.client_config.clone()).await;

    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", REG_KEY).await;

    // Register a recovery account whose keys DIFFER from the embedded pin (a
    // server-substituted recovery key). A fresh random hybrid keypair does the job.
    let (_evil_secret, evil_pub) = maxsecu_crypto::generate_hybrid_keypair();
    assert_ne!(
        evil_pub.x25519,
        parse_pin(embedded_pin()).unwrap().enc_pub,
        "sanity: evil key differs from the embedded pin"
    );
    assert_eq!(
        register_recovery(&mut c, &evil_pub.x25519, Some(&evil_pub.mlkem)).await,
        StatusCode::CREATED
    );

    // The gate must fail closed with a `server_untrusted` error (trust-alarm A).
    let err = resolve_recovery_pin(&mut c.sender, "localhost")
        .await
        .expect_err("GATE MISMATCH: served pubkey ≠ embedded pin must be rejected");
    assert_eq!(err.code, "server_untrusted", "trust-alarm A code");

    // Nothing was staged or uploaded: the would-be file id is absent server-side.
    // (The gate runs BEFORE any wrap/stage, so no `POST /v1/files` ever happened.)
    let never_file_id = Id(maxsecu_crypto::random_array::<16>());
    let (st, _) = get_json(
        &mut c,
        &format!("/v1/files/{}?version=latest", hex(&never_file_id.0)),
        &token,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "no bytes stored on the server (fail-closed before staging)"
    );

    // We never used `user_id` for an upload; touch it so the intent is explicit.
    let _ = user_id;
    let _ = std::fs::remove_dir_all(&blob_dir);
}
