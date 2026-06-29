//! Phase-2 exit gate: full bootstrap → first-admin → voucher-enroll → pending →
//! ceremony-sign (approve) → valid recipient, over REAL loopback TLS 1.3. Drives
//! the real client-app transport/session + the secret-free server + the scripted
//! offline ceremony, mirroring connect_login_e2e.rs + directory_e2e.rs.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::ServerConfig;

use maxsecu_ceremony_harness::Ceremony;
use maxsecu_client_app::session::login_exchange;
use maxsecu_client_app::transport::{pinned_client_config, Transport};
use maxsecu_client_core::{DirectoryVerifier, Identity, MemoryTrustStore, TombstoneSet};
use maxsecu_crypto::sha256;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::Role;
use maxsecu_encoding::{decode, GENESIS_HEAD};
use maxsecu_server::{serve, AppState, AuthConfig, AuthService, MemoryStore};

const BOOTSTRAP_SECRET: &str = "operator-console-secret";
const TS: u64 = 1_719_500_000_000;

/// A self-signed `localhost` cert: the server presents it; the client pins it.
struct TestPki {
    server_config: Arc<ServerConfig>,
    cert_der: CertificateDer<'static>,
}

fn test_pki() -> TestPki {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    TestPki {
        server_config: Arc::new(server_config),
        cert_der,
    }
}

/// Open a real pinned-TLS connection via the production `Transport`, then drive a
/// hyper http1 client over it. Returns the sender and the connection's exporter.
async fn open(t: &Transport) -> (SendRequest<Full<Bytes>>, [u8; 32]) {
    let (tls, exporter) = t.connect().await.unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, exporter)
}

/// POST one JSON body (optionally bearer-authed) and return `(status, json)`.
async fn post(
    s: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    s.ready().await.unwrap();
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("MaxSecu-Session {t}"));
    }
    let resp = s
        .send_request(b.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap();
    let st = resp.status();
    let by = resp.into_body().collect().await.unwrap().to_bytes();
    (
        st,
        if by.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&by).unwrap_or(serde_json::Value::Null)
        },
    )
}

/// GET (optionally bearer-authed) and return `(status, json)`.
async fn get(
    s: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    s.ready().await.unwrap();
    let mut b = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("MaxSecu-Session {t}"));
    }
    let resp = s
        .send_request(b.body(Full::new(Bytes::new())).unwrap())
        .await
        .unwrap();
    let st = resp.status();
    let by = resp.into_body().collect().await.unwrap().to_bytes();
    (
        st,
        if by.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&by).unwrap_or(serde_json::Value::Null)
        },
    )
}

/// Parse a 32-byte-hex `user_id` string (as returned by registration) to bytes.
fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[tokio::test]
async fn full_bootstrap_to_valid_recipient() {
    // Offline ceremony decides the pinned D5; the server pins its public key.
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();

    let store = MemoryStore::new();
    let cfg = AuthConfig::default()
        .with_directory_pub(pinned)
        .with_bootstrap_secret_hash(sha256(BOOTSTRAP_SECRET.as_bytes()));
    let pki = test_pki();
    let state = AppState {
        auth: Arc::new(AuthService::new(store, cfg)),
        blobs: Arc::new(maxsecu_server::MemoryBlobStore::new()),
        audit: Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        pki.server_config.clone(),
        maxsecu_server::router(state),
    ));

    let transport = Transport::new(
        pinned_client_config(pki.cert_der.clone()).unwrap(),
        ServerName::try_from("localhost").unwrap(),
        addr.to_string(),
    );

    // Bootstrap: glass-break + first-admin register (no binding yet).
    let admin_id = Identity::generate();
    let (mut c, _e) = open(&transport).await;

    let (st, gb) = post(
        &mut c,
        "/v1/bootstrap",
        serde_json::json!({
            "username": "gb-emergency",
            "enc_pub_b64": B64.encode([0xE9; 32]),
            "sig_pub_b64": B64.encode([0x59; 32]),
            "bootstrap_secret": BOOTSTRAP_SECRET,
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let gb_uid = hex16(gb["user_id"].as_str().unwrap());

    let (st, ad) = post(
        &mut c,
        "/v1/bootstrap",
        serde_json::json!({
            "username": "root",
            "enc_pub_b64": B64.encode(admin_id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(admin_id.sig_pub_bytes()),
            "bootstrap_secret": BOOTSTRAP_SECRET,
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let admin_uid = hex16(ad["user_id"].as_str().unwrap());

    // Ceremony signs BOTH bootstrap bindings with admin role, then publishes.
    for (name, uid, enc, sig) in [
        ("gb-emergency", gb_uid, [0xE9; 32], [0x59; 32]),
        (
            "root",
            admin_uid,
            admin_id.enc_pub_bytes(),
            admin_id.sig_pub_bytes(),
        ),
    ] {
        let pb = ceremony.sign_binding(name, uid, enc, sig, &[Role::User, Role::Admin], 1);
        let (st, _) = post(
            &mut c,
            "/v1/directory",
            serde_json::json!({
                "binding_b64": B64.encode(&pb.binding_bytes),
                "directory_signature_b64": B64.encode(pb.signature),
            }),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "publish {name}'s admin binding");
    }

    // Window is now closed (a published binding exists).
    let (st, _) = post(
        &mut c,
        "/v1/bootstrap",
        serde_json::json!({
            "username": "late",
            "enc_pub_b64": B64.encode([1u8; 32]),
            "sig_pub_b64": B64.encode([2u8; 32]),
            "bootstrap_secret": BOOTSTRAP_SECRET,
        }),
        None,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "bootstrap closes after the first publish"
    );

    // First admin logs in (channel-bound) over a fresh connection.
    let (mut admin_conn, exporter) = open(&transport).await;
    let login = login_exchange(
        &mut admin_conn,
        &admin_id,
        "root",
        "localhost",
        &exporter,
        TS,
    )
    .await
    .expect("admin login");
    let admin_token = login.token;

    // Admin issues a voucher; a new user enrolls (pending).
    let voucher_code = "in-person-invite-001";
    let (st, _) = post(
        &mut admin_conn,
        "/v1/vouchers",
        serde_json::json!({
            "voucher_hash_b64": B64.encode(sha256(voucher_code.as_bytes())),
        }),
        Some(&admin_token),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "admin issues a voucher");

    let user_id = Identity::generate();
    let (mut user_conn, _e) = open(&transport).await;
    let (st, ru) = post(
        &mut user_conn,
        "/v1/users",
        serde_json::json!({
            "username": "newbie",
            "enc_pub_b64": B64.encode(user_id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(user_id.sig_pub_bytes()),
            "enrollment_voucher": voucher_code,
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let newbie_uid = hex16(ru["user_id"].as_str().unwrap());

    // Pending: newbie has no binding yet.
    let (st, _) = get(&mut user_conn, "/v1/directory/newbie", None).await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "unsigned ⇒ pending ⇒ not a recipient"
    );

    // newbie appears in the admin approval queue.
    let (st, pend) = get(&mut admin_conn, "/v1/pending", Some(&admin_token)).await;
    assert_eq!(st, StatusCode::OK);
    assert!(pend["pending"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["username"] == "newbie"));

    // Approve: the ceremony signs newbie's USER binding and publishes.
    let pb = ceremony.sign_binding(
        "newbie",
        newbie_uid,
        user_id.enc_pub_bytes(),
        user_id.sig_pub_bytes(),
        &[Role::User],
        1,
    );
    let (st, _) = post(
        &mut admin_conn,
        "/v1/directory",
        serde_json::json!({
            "binding_b64": B64.encode(&pb.binding_bytes),
            "directory_signature_b64": B64.encode(pb.signature),
        }),
        Some(&admin_token),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // newbie is now a valid recipient: served binding authorizes under the PINNED D5.
    let (st, body) = get(&mut user_conn, "/v1/directory/newbie", None).await;
    assert_eq!(st, StatusCode::OK, "approved ⇒ served ⇒ recipient");
    let binding: DirBinding =
        decode(&B64.decode(body["binding_b64"].as_str().unwrap()).unwrap()).unwrap();
    let sig: [u8; 64] = B64
        .decode(body["directory_signature_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verifier = DirectoryVerifier::new(pinned);
    let none = TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap();
    let authorized = verifier
        .authorize_recipient(&binding, &sig, TS, &mut MemoryTrustStore::new(), &none)
        .expect("newbie is a valid recipient after the ceremony");
    assert_eq!(authorized.enc_pub, user_id.enc_pub_bytes());
    assert_eq!(authorized.effective_roles, vec![Role::User]);
}
