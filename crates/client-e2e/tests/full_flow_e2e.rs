//! T16 holistic **full-flow capstone** for the trusted-server-recovery redesign,
//! over REAL loopback TLS with real crypto (no mocks). It composes the entire
//! trust chain the individual task e2es exercise in isolation into ONE end-to-end
//! story, and — as the crown jewel — proves the standing recovery account can
//! read an ordinary user's upload after a genuine channel-bound recovery login.
//!
//! The single hinge that makes this composable is the embedded recovery **pin**.
//! `client-e2e` bakes `--features unpinned-dev`, so the pin compiled into
//! client-app is the fixed-seed `unpinned-dev` TEST recovery keypair. Its X25519 +
//! ML-KEM seeds are public ([`test_recovery_secret_seeds`]); its private half is
//! therefore reconstructable. We register the server's singleton recovery account
//! with EXACTLY that keypair (so an upload's `resolve_recovery_pin`/`compare_served`
//! gate MATCHES the embedded pin and PROCEEDS instead of tripping trust-alarm A),
//! and the SAME reconstructed cold key both logs in over the challenge-response and
//! opens the produced recovery wrap. The pin is enc-only, so the login (which also
//! *signs*) uses a chosen signing seed alongside the fixed enc seeds — hence
//! [`Identity::from_test_seeds`].
//!
//! Two `#[tokio::test]` functions (both real, no stubs):
//!
//! * [`full_flow_setup_enroll_upload_recover`] — the CROWN JEWEL, one composed
//!   flow: bootstrap recovery (= embedded pin) → first user enrols as ADMIN →
//!   second user enrols as USER → the second (ordinary) user uploads a blog whose
//!   recovery gate MATCHES the pin and PROCEEDS → a real channel-bound recovery
//!   LOGIN yields an admin session → the recovery cold key UNWRAPS the upload's
//!   recovery wrap to the exact file DEK.
//! * [`admin_recovery_session_mints_user_role_key`] — the admin-mint arm: a
//!   recovery-login admin session MINTS a fresh registration key, and a later user
//!   who enrols with THAT minted key lands User-role only.
//!
//! Run:
//!   cargo test -p maxsecu-client-e2e --manifest-path crates/client-app/Cargo.toml \
//!       --test full_flow_e2e

use std::net::SocketAddr;
use std::path::PathBuf;
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

use maxsecu_client_app::commands::recovery_login::{request_challenge_exchange, verify_exchange};
use maxsecu_client_app::commands::register::register_with_key_exchange;
use maxsecu_client_app::directory::resolve_recovery_pin;
use maxsecu_client_app::keystore;
use maxsecu_client_app::recovery_pin::{embedded_pin, parse_pin, test_recovery_secret_seeds};
use maxsecu_client_core::{build_upload, Identity, UploadParams};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, sha256, unwrap_dek_hybrid, EncPublicKey, HybridEncSecretKey, SigningKey,
};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::{DirBinding, WrapContext};
use maxsecu_encoding::types::{FileType, Id, RecipientType, Role, Timestamp};
use maxsecu_encoding::RECOVERY_ID;
use maxsecu_server::{
    export_channel_binding, router, serve, AppState, AuthConfig, AuthService, MemoryBlobStore,
    MemoryStore, NullAuditSink, Store,
};

/// The fixed signing seed the test recovery account is given. The embedded pin is
/// enc-only (X25519 + ML-KEM); a recovery LOGIN also signs the channel-bound proof,
/// so the cold key needs a signing key we both register and hold. Any value works.
const REC_SIG_SEED: [u8; 32] = [0x5C; 32];
/// A far-future absolute expiry so seeded registration keys never TTL-expire.
const NEVER: u64 = 4_102_444_800_000;
const TS: u64 = 1_719_500_000_000;
const PASSPHRASE: &str = "capstone enrol passphrase battery 9!";
const BLOG_BODY: &[u8] = b"An ordinary user's post the standing recovery account must be able to read.";

// ---- TLS harness (loopback, self-signed; mirrors the sibling e2e suites) ----

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

async fn connect(addr: SocketAddr, client_config: Arc<ClientConfig>) -> Conn {
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

/// GET helper. The directory endpoints used here are public (`auth = None`); the
/// file-view endpoint requires the uploader's session (`auth = Some(token)`).
async fn get(conn: &mut Conn, uri: &str, auth: Option<&str>) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost");
    if let Some(t) = auth {
        req = req.header("authorization", format!("MaxSecu-Session {t}"));
    }
    let req = req.body(Full::new(Bytes::new())).unwrap();
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

/// Decode a `GET /v1/directory/...` body into a `DirBinding`.
fn parse_binding(json: &serde_json::Value) -> DirBinding {
    let bytes = B64.decode(json["binding_b64"].as_str().unwrap()).unwrap();
    decode(&bytes).unwrap()
}

/// Boot a fresh secret-free server: a server-held directory signer (so
/// registration-key enrolment + recovery challenges can be signed) + a set of
/// seeded single-use registration keys (only their sha256 is persisted).
async fn boot(reg_keys: &[&str]) -> (SocketAddr, TestPki) {
    let signer = Arc::new(SigningKey::generate());
    let pinned = signer.verifying_key().to_bytes();
    let store = MemoryStore::new();
    for k in reg_keys {
        store
            .issue_registration_key(sha256(k.as_bytes()), NEVER)
            .await
            .unwrap();
    }
    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(pinned))
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
    (addr, pki)
}

/// The recovery cold key for the WHOLE test: the `unpinned-dev` test pin's enc
/// seeds (so its enc half equals the embedded pin) plus a fixed signing seed (so it
/// can also authenticate the recovery login). This is the ONE identity that (a) is
/// registered as the server's recovery account, (b) logs in over the challenge, and
/// (c) opens the upload's recovery wrap.
fn recovery_cold_key() -> Identity {
    let (x_seed, mlkem_seed) = test_recovery_secret_seeds();
    Identity::from_test_seeds(x_seed, REC_SIG_SEED, mlkem_seed)
}

/// Register the singleton recovery account from `rec`'s PUBLIC keys (enc + sig +
/// ML-KEM). Because `rec.enc == embedded pin`, every upload's `compare_served` gate
/// will MATCH; because `rec.sig` is a real signing key we hold, the recovery login
/// proof will verify.
async fn register_recovery(c: &mut Conn, rec: &Identity) {
    let mlkem = rec.mlkem_pub_bytes().expect("test recovery account is hybrid (PQ)");
    let (st, _) = post(
        c,
        "/v1/recovery/register",
        None,
        serde_json::json!({
            "enc_pub_b64": B64.encode(rec.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(rec.sig_pub_bytes()),
            "mlkem_pub_b64": B64.encode(&mlkem[..]),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "recovery account registered");
}

/// A fresh, empty portable app-dir with `register.key` seeded to `key`.
fn app_dir_with_key(key: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mxcap_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("register.key"), key.as_bytes()).unwrap();
    dir
}

/// Channel-bound login for an already-enrolled `id` under `username`; returns the
/// session token (mirrors the normal `/session/challenge` → `/session/proof` dance).
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
        use maxsecu_encoding::labels;
        use maxsecu_encoding::structs::AuthProofContext;
        use maxsecu_encoding::types::{Bytes32, Text};
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
        serde_json::json!({ "username": username, "timestamp": TS, "proof_b64": proof }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "channel-bound login");
    res["session_token"].as_str().unwrap().to_owned()
}

// ===========================================================================
// CROWN JEWEL: setup → enrol (admin + user) → upload → recovery-login → decrypt.
// ===========================================================================

#[tokio::test]
async fn full_flow_setup_enroll_upload_recover() {
    let (addr, pki) = boot(&["cap-key-admin", "cap-key-user"]).await;
    let mut c = connect(addr, pki.client_config.clone()).await;

    // 1) Bootstrap the recovery account = the embedded (unpinned-dev) test pin.
    let rec = recovery_cold_key();
    let pin = parse_pin(embedded_pin()).expect("embedded test pin parses");
    assert_eq!(
        rec.enc_pub_bytes(),
        pin.enc_pub,
        "the recovery cold key's enc half IS the embedded pin"
    );
    assert_eq!(rec.mlkem_pub_bytes(), pin.mlkem_pub, "…including the ML-KEM half");
    register_recovery(&mut c, &rec).await;

    // 2) First user enrols → ADMIN (the server's first-registrant grant).
    let dir_admin = app_dir_with_key("cap-key-admin");
    register_with_key_exchange(&mut c.sender, "localhost", &dir_admin, "alice", PASSPHRASE)
        .await
        .expect("first registrant enrols");
    let (st, body) = get(&mut c, "/v1/directory/alice", None).await;
    assert_eq!(st, StatusCode::OK);
    let alice = parse_binding(&body);
    assert!(alice.roles.roles().contains(&Role::Admin), "first user is admin");
    assert!(alice.roles.roles().contains(&Role::User));

    // 3) Second user enrols → USER only (an ordinary poster).
    let dir_user = app_dir_with_key("cap-key-user");
    let reg_bob =
        register_with_key_exchange(&mut c.sender, "localhost", &dir_user, "bob", PASSPHRASE)
            .await
            .expect("second registrant enrols");
    let (st, body) = get(&mut c, "/v1/directory/bob", None).await;
    assert_eq!(st, StatusCode::OK);
    let bob_binding = parse_binding(&body);
    assert!(bob_binding.roles.roles().contains(&Role::User));
    assert!(
        !bob_binding.roles.roles().contains(&Role::Admin),
        "only the first registrant is admin"
    );

    // 4) The ordinary user uploads a blog. The recovery gate MATCHES the embedded
    //    pin (recovery account == pin), so the upload PROCEEDS (no alarm-A) and
    //    auto-wraps a recovery grant.
    let bob = keystore::unlock(&dir_user, PASSPHRASE).expect("bob's sealed identity unlocks");
    let bob_token = login(&mut c, "bob", &bob).await;

    let recovery = resolve_recovery_pin(&mut c.sender, "localhost")
        .await
        .expect("compare_served MATCHES the embedded pin → upload may proceed");
    assert_eq!(recovery.enc_pub, pin.enc_pub);
    assert_eq!(recovery.mlkem_pub, pin.mlkem_pub);

    let blog_streams =
        maxsecu_client_app::upload::prepare_blog_streams(BLOG_BODY.to_vec(), "Diary", &[]);
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let bundle = build_upload(
        &UploadParams {
            owner: &bob,
            owner_id: Id(hex16(&reg_bob.user_id)),
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
    assert!(
        matches!(bundle.manifest.alg, maxsecu_encoding::types::Suite::V2),
        "PQ owner + PQ recovery pin ⇒ Suite::V2 hybrid wrap"
    );
    maxsecu_client_app::upload::run_pipeline(
        &mut c.sender,
        "localhost",
        &bob_token,
        &bundle,
        |_, _| {},
        maxsecu_client_app::upload::StageFlags::default(),
    )
    .await
    .expect("the upload completes and the server accepts the recovery-wrapped file");

    // The server persisted a recovery grant (the file really wrapped to recovery).
    let (st, view) = get(
        &mut c,
        &format!("/v1/files/{fid_hex}?version=latest"),
        Some(&bob_token),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !view["recovery_grant"].is_null(),
        "the served file view carries a recovery grant"
    );

    // 5) Recovery LOGIN — the real channel-bound challenge-response with the cold
    //    key. The server wraps the challenge to the registered recovery enc pubkey
    //    (== the pin), so ONLY this cold key can unwrap it; the proof is signed with
    //    its signing key. Success ⇒ an admin recovery session token.
    let challenge = request_challenge_exchange(&mut c.sender, "localhost", &rec)
        .await
        .expect("the cold key unwraps the recovery challenge to the nonce");
    assert!(
        challenge.suite_is_hybrid(),
        "the hybrid recovery account ⇒ a Suite::V2 challenge wrap"
    );
    let admin_token = verify_exchange(&mut c.sender, "localhost", &rec, &challenge, &c.exporter, TS)
        .await
        .expect("the channel-bound proof logs the recovery account into an admin session");
    assert!(!admin_token.is_empty(), "server minted a recovery admin token");

    // 6) Recovery DECRYPTS the ordinary user's upload: unwrap the produced recovery
    //    wrap with the recovery cold PRIVATE key, recovering the exact file DEK.
    let rec_wrap = bundle
        .wraps
        .iter()
        .find(|w| w.recipient_type == RecipientType::Recovery)
        .expect("the upload produced a recovery wrap");
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
        "the recovery-recovered DEK matches the file's committed DEK"
    );

    let _ = std::fs::remove_dir_all(&dir_admin);
    let _ = std::fs::remove_dir_all(&dir_user);
}

// ===========================================================================
// ADMIN-MINT arm: a recovery-login admin session mints a user-role reg key.
// ===========================================================================

#[tokio::test]
async fn admin_recovery_session_mints_user_role_key() {
    let (addr, pki) = boot(&["cap-admin-seed"]).await;
    let mut c = connect(addr, pki.client_config.clone()).await;

    // Bootstrap recovery = the embedded pin, and enrol the first admin.
    let rec = recovery_cold_key();
    register_recovery(&mut c, &rec).await;
    let dir_admin = app_dir_with_key("cap-admin-seed");
    register_with_key_exchange(&mut c.sender, "localhost", &dir_admin, "alice", PASSPHRASE)
        .await
        .expect("first registrant enrols as admin");

    // Recovery LOGIN → an ADMIN session (the operator's cold-key path to admin).
    let challenge = request_challenge_exchange(&mut c.sender, "localhost", &rec)
        .await
        .expect("recovery challenge unwraps");
    let admin_token = verify_exchange(&mut c.sender, "localhost", &rec, &challenge, &c.exporter, TS)
        .await
        .expect("recovery admin session established");

    // The admin session MINTS a fresh single-use registration key.
    let (st, res) = post(
        &mut c,
        "/v1/registration-keys",
        Some(&admin_token),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "recovery admin session mints a reg key");
    let minted = res["registration_key"].as_str().unwrap().to_owned();
    assert!(!minted.is_empty());

    // A later user enrols with the MINTED key and lands USER-role only (alice
    // already claimed the one-time admin grant).
    let dir_user = app_dir_with_key(&minted);
    register_with_key_exchange(&mut c.sender, "localhost", &dir_user, "carol", PASSPHRASE)
        .await
        .expect("carol enrols with the admin-minted key");
    let (st, body) = get(&mut c, "/v1/directory/carol", None).await;
    assert_eq!(st, StatusCode::OK);
    let carol = parse_binding(&body);
    assert!(carol.roles.roles().contains(&Role::User));
    assert!(
        !carol.roles.roles().contains(&Role::Admin),
        "a user-role registration key never confers admin"
    );

    let _ = std::fs::remove_dir_all(&dir_admin);
    let _ = std::fs::remove_dir_all(&dir_user);
}
