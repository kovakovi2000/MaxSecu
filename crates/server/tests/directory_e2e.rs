//! Phase 2 exit-gate end-to-end test (DESIGN §17 Phase 2, §7.2/§7.6).
//!
//! Drives the **real stack**: the offline ceremony (`admin-core`) signs bindings
//! and tombstones; the secret-free server stores them and serves them over real
//! loopback TLS; the client (`client-core`) verifies everything against the
//! pinned D5 root. Proves the four Phase-2 exit gates that are expressible over
//! the served interface:
//!
//! - a server-returned **forged** binding is rejected (pinned-root signature);
//! - an **unsigned** account is not a recipient (404 → absent);
//! - a `*`-**revoked** user is rejected via the sink-anchored tombstone set;
//! - a **withheld** tombstone (a served chain that doesn't reach the anchored head) fails closed.
//!
//! (Rollback / TOFU key-change / validity-window are the same client memory
//! logic proven in client-core's unit tests.)

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

use maxsecu_admin_core::{CoSign, ControlChain, DirectorySigner, RevokeParams};
use maxsecu_client_core::{DirectoryVerifier, MemoryTrustStore, TombstoneSet, VerifyError};
use maxsecu_crypto::SigningKey;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{Bytes32, FileScope, Id, Role, RoleSet, Text, Timestamp};
use maxsecu_encoding::{decode, encode, GENESIS_HEAD};
use maxsecu_server::{serve, AppState, AuthConfig, AuthService, MemoryStore, Store, UserRecord};

const TS: u64 = 1_719_500_000_000;

fn binding(username: &str, uid: u8, enc: u8, sig: u8, key_version: u64) -> DirBinding {
    DirBinding {
        username: Text::new(username).unwrap(),
        user_id: Id([uid; 16]),
        enc_pub: Bytes32([enc; 32]),
        sig_pub: Bytes32([sig; 32]),
        key_version,
        roles: RoleSet::new([Role::User]),
        not_before: Timestamp(0),
        not_after: Timestamp(4_102_444_800_000), // 2100
        mlkem_pub: None,
    }
}

// ---- TLS harness (loopback, self-signed; mirrors tls_channel_binding.rs) ----

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

/// Decode a `GET /v1/directory/...` body into the `(DirBinding, signature)` the
/// client verifies — exactly what a real client does with the served bytes.
fn parse_binding(json: &serde_json::Value) -> (DirBinding, [u8; 64]) {
    let bytes = B64.decode(json["binding_b64"].as_str().unwrap()).unwrap();
    let sig: [u8; 64] = B64
        .decode(json["directory_signature_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (decode(&bytes).unwrap(), sig)
}

#[tokio::test]
async fn phase2_exit_gates_over_real_tls() {
    // ---- Offline ceremony: the air-gapped D5 + an admin issuing a tombstone ----
    let d5 = DirectorySigner::generate();
    let pinned = d5.public_key(); // compiled into the client

    // alice: a genuine, fingerprint-confirmed recipient.
    let alice = binding("alice", 0x0A, 0xE1, 0x51, 1);
    let alice_signed = d5
        .sign_enrollment(
            &alice,
            &maxsecu_crypto::fingerprint(&[0xE1; 32], &[0x51; 32]),
        )
        .unwrap();

    // victim: a genuine binding, but account-wide revoked below.
    let victim = binding("victim", 0x0F, 0xE2, 0x52, 1);
    let victim_signed = d5.sign_binding(&victim, None);

    // mallory: the server tries to substitute an ATTACKER-signed binding.
    let attacker = SigningKey::generate();
    let mallory = binding("mallory", 0x11, 0xEE, 0xEE, 1);
    let mallory_forged_sig =
        attacker.sign_canonical(maxsecu_encoding::labels::DIRBINDING, &mallory);

    // A `*` tombstone revoking victim (account-wide ⇒ dual-controlled).
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    let co = SigningKey::generate();
    let rev = chain
        .revoke(
            &admin,
            RevokeParams {
                scope: FileScope::AccountWide,
                revoked_user_id: Id([0x0F; 16]),
                revoked_capability: None,
                from_version: 1,
                issued_by: Id([0xAD; 16]),
                created_at: Timestamp(TS),
            },
            Some(CoSign {
                admin_id: Id([0xC0; 16]),
                key: &co,
            }),
        )
        .unwrap();
    let anchored_head = chain.head(); // the sink would anchor this

    // A *second* tombstone the server will WITHHOLD (chain advances past it).
    let _withheld = chain
        .revoke(
            &admin,
            RevokeParams {
                scope: FileScope::AccountWide,
                revoked_user_id: Id([0x22; 16]),
                revoked_capability: None,
                from_version: 1,
                issued_by: Id([0xAD; 16]),
                created_at: Timestamp(TS),
            },
            Some(CoSign {
                admin_id: Id([0xC0; 16]),
                key: &co,
            }),
        )
        .unwrap();
    let head_with_withheld = chain.head();

    // ---- The server is loaded out of band (the ceremony publishes to it) ----
    let store = MemoryStore::new();
    for (name, uid) in [("alice", 0x0A), ("victim", 0x0F), ("mallory", 0x11)] {
        store.add_user(
            name,
            UserRecord {
                user_id: [uid; 16],
                enc_pub: [0; 32],
                sig_pub: [0; 32],
            },
        );
    }
    store
        .put_binding(
            [0x0A; 16],
            1,
            encode(&alice_signed.binding),
            alice_signed.signature,
        )
        .await
        .unwrap();
    store
        .put_binding(
            [0x0F; 16],
            1,
            encode(&victim_signed.binding),
            victim_signed.signature,
        )
        .await
        .unwrap();
    store
        .put_binding([0x11; 16], 1, encode(&mallory), mallory_forged_sig)
        .await
        .unwrap();
    // Only the FIRST tombstone is served (the second is withheld).
    store
        .append_control(rev.bytes.clone(), rev.sig, rev.co_sig)
        .await
        .unwrap();

    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
        blobs: Arc::new(maxsecu_server::MemoryBlobStore::new()),
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

    // ---- The client: pinned to the real D5, verifies everything served ----
    let mut c = connect(addr, pki.client_config.clone()).await;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();

    // Fetch + verify the served tombstone chain against the anchored head.
    let (st, revs) = get(&mut c, "/v1/revocations").await;
    assert_eq!(st, StatusCode::OK);
    let records: Vec<Vec<u8>> = revs["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| B64.decode(r["record_b64"].as_str().unwrap()).unwrap())
        .collect();
    let tombstones = TombstoneSet::verify(&records, anchored_head).expect("chain reaches anchor");

    // GATE — genuine recipient: served binding verifies and authorizes.
    let (st, body) = get(&mut c, "/v1/directory/alice").await;
    assert_eq!(st, StatusCode::OK);
    let (ab, asig) = parse_binding(&body);
    let authorized = verifier
        .authorize_recipient(&ab, &asig, TS, &mut trust, &tombstones)
        .expect("alice is a valid recipient");
    assert_eq!(authorized.enc_pub, [0xE1; 32]);

    // GATE — forged binding: the server substituted an attacker-signed binding.
    let (st, body) = get(&mut c, "/v1/directory/mallory").await;
    assert_eq!(st, StatusCode::OK);
    let (mb, msig) = parse_binding(&body);
    assert_eq!(
        verifier.verify_binding(&mb, &msig, TS, &mut trust),
        Err(VerifyError::BadSignature),
        "a binding not signed by the pinned D5 is rejected as absent"
    );

    // GATE — unsigned account: not a recipient.
    let (st, _) = get(&mut c, "/v1/directory/nobody").await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // GATE — revoked user: rejected via the sink-anchored tombstone set.
    let (st, body) = get(&mut c, "/v1/directory/victim").await;
    assert_eq!(st, StatusCode::OK);
    let (vb, vsig) = parse_binding(&body);
    assert_eq!(
        verifier.authorize_recipient(&vb, &vsig, TS, &mut MemoryTrustStore::new(), &tombstones),
        Err(VerifyError::Revoked),
        "an account-wide-revoked user is not a valid recipient"
    );

    // GATE — withheld tombstone: the served chain doesn't reach the anchored
    // head (the sink saw one more) ⇒ fail closed on the gap.
    assert_eq!(
        TombstoneSet::verify(&records, head_with_withheld).unwrap_err(),
        maxsecu_client_core::TombstoneError::Gap,
        "a withheld fresh tombstone is a gap, never silently accepted"
    );

    // Sanity: an empty served chain only matches GENESIS_HEAD (not the anchor).
    assert!(TombstoneSet::verify(&[], GENESIS_HEAD.0).is_ok());
}
