//! P6.5 end-to-end: the app server PUBLISHES each control append to the REAL,
//! independent sink, and the issuer CONFIRMS anchoring before treating the
//! revocation as effective (`docs/sink-interface.md` §6).
//!
//! Two servers are stood up over loopback TLS, each on its OWN pinned identity:
//! the app server (with `audit = HttpSinkPublisher` pinned to the sink) and an
//! in-proc `sink-server`. An admin POSTs a real, admin-signed revocation to the
//! app server; the app server async-POSTs the record bytes to the sink, which
//! re-derives the head. The capstone assertions:
//!   * after the append, the sink's `/head` reflects `chain_seq` 1 and the head
//!     `sha256(record)` (`control_append_publishes_record_to_sink`), and
//!   * the issuer-side `confirm_anchored` returns `Ok` only once the sink reflects
//!     the new head — and fails CLOSED (`NotAnchored`) before the publish lands
//!     (`issuer_confirms_anchoring`), closing write-time withholding.

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

use maxsecu_admin_core::{ControlChain, DirectorySigner, RevokeParams, SignedControlRecord};
use maxsecu_client_core::{confirm_anchored, AnchoredHead, HttpSinkClient, Identity, SinkError};
use maxsecu_crypto::{sha256, SigningKey};
use maxsecu_encoding::encode;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{Bytes32, FileScope, Id, Role, RoleSet, Text, Timestamp};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuditSink, AuthConfig, AuthService, FsBlobStore,
    HttpSinkPublisher, MemoryStore, Store, UserRecord,
};
use maxsecu_sink_server::{router as sink_router, serve as sink_serve, Anchorer, SinkState};

const TS: u64 = 1_719_500_000_000;
const TOKEN: &str = "sink-admin-secret";
const ADMIN_ID: [u8; 16] = [0xA1; 16];

// ---- TLS harness (mirrors sharing_e2e.rs) ----

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

async fn login(conn: &mut Conn, username: &str, id: &Identity) -> String {
    let (_st, ch) = post(
        conn,
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
            tls_exporter: Bytes32(conn.exporter),
            nonce: Bytes32(nonce),
            timestamp: Timestamp(TS),
        };
        B64.encode(id.signing_key().sign_canonical(labels::AUTH, &ctx))
    };
    let (st, res) = post(
        conn,
        "/v1/session/proof",
        None,
        serde_json::json!({"username": username, "timestamp": TS, "proof_b64": proof}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login {username}");
    res["session_token"].as_str().unwrap().to_owned()
}

/// POST a signed control record to the app server.
async fn post_control(
    conn: &mut Conn,
    token: &str,
    uri: &str,
    rec: &SignedControlRecord,
) -> StatusCode {
    let body = serde_json::json!({
        "record_b64": B64.encode(&rec.bytes),
        "sig_b64": B64.encode(rec.sig),
        "co_sig_b64": rec.co_sig.map(|c| B64.encode(c)),
    });
    let (st, _) = post(conn, uri, Some(token), body).await;
    st
}

/// Everything a test needs after both servers are up.
struct Booted {
    app_addr: std::net::SocketAddr,
    app_client_config: Arc<ClientConfig>,
    sink_addr: std::net::SocketAddr,
    sink_client_config: Arc<ClientConfig>,
    admin: Identity,
    custodian_pub: [u8; 32],
    log_pub: [u8; 32],
}

/// Stand up an in-proc sink and an app server whose audit sink is a real
/// `HttpSinkPublisher` pinned to that sink. The admin is added to the store
/// directly (with the Admin role) so it can POST control records after login.
async fn boot() -> Booted {
    // ---- Sink server (its own pinned identity). ----
    let sink_pki = test_pki();
    let custodian = SigningKey::generate();
    let log = SigningKey::generate();
    let custodian_pub = custodian.verifying_key().to_bytes();
    let log_pub = log.verifying_key().to_bytes();
    let anchorer = Anchorer::new(custodian, log);
    let sink_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink_listener.local_addr().unwrap();
    tokio::spawn(sink_serve(
        sink_listener,
        sink_pki.server_config.clone(),
        sink_router(SinkState::new(anchorer, TOKEN)),
    ));

    // ---- App server, publishing to the sink over its pinned channel. ----
    let store = MemoryStore::new();
    let admin = Identity::generate();
    store.add_user(
        "admin",
        UserRecord {
            user_id: ADMIN_ID,
            enc_pub: admin.enc_pub_bytes(),
            sig_pub: admin.sig_pub_bytes(),
        },
    );
    // Admin authority flows from a D5-signed {User, Admin} binding (D-K), verified
    // server-side by the AdminSession gate — not an advisory roles table.
    let d5 = DirectorySigner::generate();
    let admin_binding = DirBinding {
        username: Text::new("admin").unwrap(),
        user_id: Id(ADMIN_ID),
        enc_pub: Bytes32(admin.enc_pub_bytes()),
        sig_pub: Bytes32(admin.sig_pub_bytes()),
        key_version: 1,
        roles: RoleSet::new([Role::User, Role::Admin]),
        not_before: Timestamp(0),
        not_after: Timestamp(4_102_444_800_000),
        mlkem_pub: None,
    };
    let signed = d5.sign_binding(&admin_binding, None);
    store
        .put_binding(ADMIN_ID, 1, encode(&signed.binding), signed.signature)
        .await
        .unwrap();

    let publisher = HttpSinkPublisher::new(
        sink_addr,
        "localhost",
        sink_pki.client_config.clone(),
        TOKEN,
    );
    let blob_dir = std::env::temp_dir().join(format!(
        "mxs65_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let state = AppState {
        auth: Arc::new(AuthService::new(
            store,
            AuthConfig::default().with_directory_pub(d5.public_key()),
        )),
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

    Booted {
        app_addr,
        app_client_config: app_pki.client_config,
        sink_addr,
        sink_client_config: sink_pki.client_config,
        admin,
        custodian_pub,
        log_pub,
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// A real, single-file revocation signed by `admin` (no co-sig needed for a
/// file-scoped revoke), chained onto genesis.
fn a_revocation(admin: &Identity) -> SignedControlRecord {
    let mut chain = ControlChain::new();
    chain
        .revoke(
            admin.signing_key(),
            RevokeParams {
                scope: FileScope::Specific(Id([0x0A; 16])),
                revoked_user_id: Id([0x99; 16]),
                revoked_capability: None,
                from_version: 1,
                issued_by: Id(ADMIN_ID),
                created_at: Timestamp(TS),
            },
            None,
        )
        .unwrap()
}

/// GET the sink's recorded global position for `file_id`'s genesis over its own
/// pinned TLS channel; `None` when the sink returns `404` (file not anchored).
async fn fetch_genesis_pos(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    file_id: &[u8; 16],
) -> Option<u64> {
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
    let uri = format!("/v1/genesis-anchor/{}", hex(file_id));
    let req = Request::builder()
        .method("GET")
        .uri(uri)
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

/// P7.8: the app server anchors a file `genesis` at a REAL, global-ordered sink
/// position — the R27/D28 key-compromise cutoff basis, now over real TLS rather
/// than the in-memory `MemoryAuditSink`. Stands up an in-proc sink, pins a real
/// `HttpSinkPublisher` to it, and proves: (a) `anchor_genesis` actually records a
/// position the sink serves back, (b) control appends and genesis anchors share
/// ONE ordered position space (a genesis anchored after a control append has a
/// strictly higher position), and (c) anchoring is idempotent (append-only).
#[tokio::test]
async fn genesis_anchoring_is_real_and_globally_ordered_over_sink() {
    // ---- Stand up the sink over loopback TLS (its own pinned identity). ----
    let sink_pki = test_pki();
    let anchorer = Anchorer::new(SigningKey::generate(), SigningKey::generate());
    let sink_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink_listener.local_addr().unwrap();
    tokio::spawn(sink_serve(
        sink_listener,
        sink_pki.server_config.clone(),
        sink_router(SinkState::new(anchorer, TOKEN)),
    ));

    // A real publisher pinned to the sink's channel (the same transport the app
    // server's `AuditSink` uses).
    let publisher = HttpSinkPublisher::new(
        sink_addr,
        "localhost",
        sink_pki.client_config.clone(),
        TOKEN,
    );

    // An un-anchored file has no sink position.
    assert!(
        fetch_genesis_pos(sink_addr, sink_pki.client_config.clone(), &[0xF1; 16])
            .await
            .is_none(),
        "an un-anchored file has no genesis position"
    );

    // ---- Anchor a first genesis (global event #0) over real TLS. ----
    publisher.anchor_genesis([0xF1; 16]).await;
    let g1 = fetch_genesis_pos(sink_addr, sink_pki.client_config.clone(), &[0xF1; 16])
        .await
        .expect("first genesis anchored over the real sink");

    // ---- A control append draws the NEXT global position, BETWEEN the two genesis
    // anchors — proving control appends and genesis anchors share one ordered space.
    let rev = a_revocation(&Identity::generate());
    publisher.publish_control_record(rev.bytes.clone()).await;

    // ---- Anchor a second genesis AFTER the control append. ----
    publisher.anchor_genesis([0xF2; 16]).await;
    let g2 = fetch_genesis_pos(sink_addr, sink_pki.client_config.clone(), &[0xF2; 16])
        .await
        .expect("second genesis anchored over the real sink");

    // Global ordering (R27/D28): the genesis anchored AFTER the control append has a
    // strictly higher sink position, and the intervening control append consumed
    // exactly one global position (g1=0, control=1, g2=2) — so "genesis anchored
    // before/after a key_compromise control record" is decidable over the real sink.
    assert!(
        g2 > g1,
        "a genesis anchored after a control append has a higher global position"
    );
    assert_eq!(
        g2,
        g1 + 2,
        "the intervening control append consumed exactly one global position"
    );

    // ---- Idempotent: re-anchoring never moves a genesis's position. ----
    publisher.anchor_genesis([0xF1; 16]).await;
    let g1_again = fetch_genesis_pos(sink_addr, sink_pki.client_config.clone(), &[0xF1; 16])
        .await
        .expect("still anchored");
    assert_eq!(
        g1, g1_again,
        "re-anchoring a file is idempotent (append-only position)"
    );
}

#[tokio::test]
async fn control_append_publishes_record_to_sink() {
    let b = boot().await;
    let mut c_admin = connect(b.app_addr, b.app_client_config.clone()).await;
    let admin_tok = login(&mut c_admin, "admin", &b.admin).await;

    let rev = a_revocation(&b.admin);
    assert_eq!(
        post_control(&mut c_admin, &admin_tok, "/v1/revocations", &rev).await,
        StatusCode::CREATED
    );

    // The sink — fetched over ITS OWN pinned channel — now reflects the append.
    let sink = HttpSinkClient::new(b.sink_addr, "localhost", b.sink_client_config.clone());
    let (head, _proofs) = tokio::task::spawn_blocking(move || sink.fetch_head_all_proofs())
        .await
        .unwrap()
        .expect("sink head fetched");
    assert_eq!(head.chain_seq, 1, "sink chain advanced by the publish");
    assert_eq!(
        head.head,
        sha256(&rev.bytes),
        "sink derived head == sha256(record)"
    );
}

#[tokio::test]
async fn issuer_confirms_anchoring() {
    let b = boot().await;
    let mut c_admin = connect(b.app_addr, b.app_client_config.clone()).await;
    let admin_tok = login(&mut c_admin, "admin", &b.admin).await;

    let rev = a_revocation(&b.admin);
    let expected = AnchoredHead {
        chain_seq: 1,
        head: sha256(&rev.bytes),
    };
    let (cp, lp) = (b.custodian_pub, b.log_pub);

    // ---- BEFORE the append: the server has not published, so the sink (at
    // genesis) does NOT reflect the expected head — the issuer confirm fails
    // CLOSED. This is the write-time-withholding case.
    let sink = HttpSinkClient::new(b.sink_addr, "localhost", b.sink_client_config.clone());
    let pre = tokio::task::spawn_blocking(move || confirm_anchored(&sink, &[cp], &[lp], expected))
        .await
        .unwrap();
    assert_eq!(
        pre,
        Err(SinkError::NotAnchored),
        "unpublished head is not anchored"
    );

    // ---- Append + publish. ----
    assert_eq!(
        post_control(&mut c_admin, &admin_tok, "/v1/revocations", &rev).await,
        StatusCode::CREATED
    );

    // ---- The sink now reflects the new verified head → confirm returns Ok. ----
    let sink = HttpSinkClient::new(b.sink_addr, "localhost", b.sink_client_config.clone());
    let ok = tokio::task::spawn_blocking(move || confirm_anchored(&sink, &[cp], &[lp], expected))
        .await
        .unwrap();
    assert_eq!(ok, Ok(()), "issuer confirms the sink reflects the new head");

    // ---- A stale expected head (a different/forged target) still fails closed. ----
    let stale = AnchoredHead {
        chain_seq: 2,
        head: [0xAB; 32],
    };
    let sink = HttpSinkClient::new(b.sink_addr, "localhost", b.sink_client_config.clone());
    let bad = tokio::task::spawn_blocking(move || confirm_anchored(&sink, &[cp], &[lp], stale))
        .await
        .unwrap();
    assert_eq!(
        bad,
        Err(SinkError::NotAnchored),
        "a stale expected head is not anchored"
    );
}
