//! Phase-6 **CAPSTONE** end-to-end (DESIGN §16 / §17 Phase 6): the
//! "tamper-evident external audit demonstrated" exit gate, plus the R26
//! recovery-wrap sweep and the sanitized-error rule — all on the REAL stack over
//! loopback TLS, with the app server and the INDEPENDENT sink running as two
//! separate, pinned TLS endpoints.
//!
//! This is pure glue: every behavior already exists (P6.1 sweep, P6.3/P6.4 sink,
//! P6.5 server-publishes-to-sink + issuer `confirm_anchored`, P6.7 sanitized
//! errors, P5.1 authenticated tombstone sets). The capstone composes them once,
//! over real TLS, proving the chain end to end:
//!
//!   1. two independent endpoints stand up (app + sink, each on its own pinned
//!      identity), the app's `audit` wired to an `HttpSinkPublisher`;
//!   2. an admin revokes over TLS → the server publishes the record to the sink →
//!      the issuer `confirm_anchored` returns `Ok` (the sink reflects the head);
//!   3. a client fetches the anchored head from the SINK and the records from the
//!      APP SERVER and `verify_authenticated` succeeds (the revoked user is in
//!      the set) — two independent channels composing into one authenticated set;
//!   4. a withheld tail (an empty/short served chain) is a `Gap` against the sink
//!      head — fail closed (D22);
//!   5. an append-only rewrite (a stale `prev_head`) is rejected `409` by the
//!      sink (§6.1);
//!   6. the R26 sweep flags a recovery wrap that encrypts a DIFFERENT DEK than the
//!      manifest commits (DESIGN §16.1 / D27);
//!   7. an app-server error path stays sanitized over the wire (§16.2 — bare
//!      status, empty body, no internals).
//!
//! The TLS harness mirrors `sink_publish_e2e.rs` (P6.5); the sink raw-POST mirrors
//! `sink_e2e.rs` (P6.4); the served-records fetch + `verify_authenticated` mirror
//! `sharing_e2e.rs` (P5.9).

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

use maxsecu_admin_core::sweep::{run_sweep, RecoverySample};
use maxsecu_admin_core::{
    ControlChain, DirectorySigner, RecoveryWrapCtx, RevokeParams, SignedControlRecord,
};
use maxsecu_client_core::{
    confirm_anchored, AnchoredHead, ControlRecordIn, HttpSinkClient, Identity, IssuerInfo,
    TombstoneError, TombstoneSet,
};
use maxsecu_crypto::{generate_enc_keypair, sha256, wrap_dek, Dek, SigningKey};
use maxsecu_encoding::structs::{DirBinding, WrapContext};
use maxsecu_encoding::types::{Bytes32, FileScope, Id, Role, RoleSet, Text, Timestamp};
use maxsecu_encoding::RECOVERY_ID;
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore,
    HttpSinkPublisher, MemoryStore, Store, UserRecord,
};
use maxsecu_sink_server::{router as sink_router, serve as sink_serve, Anchorer, SinkState};

const TS: u64 = 1_719_500_000_000;
const TOKEN: &str = "sink-admin-secret";
const ADMIN_ID: [u8; 16] = [0xA1; 16];
const VICTIM_ID: [u8; 16] = [0x99; 16];
const FILE_ID: [u8; 16] = [0x0A; 16];

// ---- TLS harness (mirrors sink_publish_e2e.rs) ----

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

/// GET over the app channel returning the raw status + body bytes (used both for
/// the served control-log fetch and the sanitized-error probe).
async fn get_raw(conn: &mut Conn, uri: &str, auth: Option<&str>) -> (StatusCode, Vec<u8>) {
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
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes)
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
async fn post_control(conn: &mut Conn, token: &str, uri: &str, rec: &SignedControlRecord) -> StatusCode {
    let body = serde_json::json!({
        "record_b64": B64.encode(&rec.bytes),
        "sig_b64": B64.encode(rec.sig),
        "co_sig_b64": rec.co_sig.map(|c| B64.encode(c)),
    });
    let (st, _) = post(conn, uri, Some(token), body).await;
    st
}

/// GET the app server's served control-log chain (api.md §7.1) and rebuild the
/// opaque [`ControlRecordIn`] set the client authenticates.
async fn fetch_control(conn: &mut Conn, token: &str) -> Vec<ControlRecordIn> {
    let (st, body) = get_raw(conn, "/v1/revocations", Some(token)).await;
    assert_eq!(st, StatusCode::OK, "GET /v1/revocations");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| ControlRecordIn {
            bytes: B64.decode(r["record_b64"].as_str().unwrap()).unwrap(),
            sig: B64.decode(r["sig_b64"].as_str().unwrap()).unwrap().try_into().unwrap(),
            co_sig: r["co_sig_b64"]
                .as_str()
                .map(|s| B64.decode(s).unwrap().try_into().unwrap()),
        })
        .collect()
}

/// Raw POST of a control record to the SINK's append endpoint over its OWN pinned
/// channel (mirrors `sink_e2e.rs`). Used to drive the append-only-rewrite 409.
async fn post_sink_record(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    record_bytes: &[u8],
) -> StatusCode {
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
    let body = serde_json::json!({ "record_b64": B64.encode(record_bytes) }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/control-log/records")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    sender.send_request(req).await.unwrap().status()
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
/// `HttpSinkPublisher` pinned to that sink — two INDEPENDENT TLS endpoints, each
/// on its own pinned identity. The admin is added to the store directly (Admin
/// role) so it can POST control records after login.
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
        .put_binding(
            ADMIN_ID,
            1,
            maxsecu_encoding::encode(&signed.binding),
            signed.signature,
        )
        .await
        .unwrap();

    let publisher = HttpSinkPublisher::new(sink_addr, "localhost", sink_pki.client_config.clone(), TOKEN);
    let blob_dir =
        std::env::temp_dir().join(format!("mxs612_{}", hex(&maxsecu_crypto::random_array::<8>())));
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
                scope: FileScope::Specific(Id(FILE_ID)),
                revoked_user_id: Id(VICTIM_ID),
                revoked_capability: None,
                from_version: 1,
                issued_by: Id(ADMIN_ID),
                created_at: Timestamp(TS),
            },
            None,
        )
        .unwrap()
}

#[tokio::test]
async fn phase6_integrity_ops_exit_gates_over_real_tls() {
    // ---- GATE 1: two INDEPENDENT TLS endpoints (app + sink), audit wired. ----
    let b = boot().await;
    let mut c_admin = connect(b.app_addr, b.app_client_config.clone()).await;
    let admin_tok = login(&mut c_admin, "admin", &b.admin).await;

    // ---- GATE 2: admin revokes over TLS → the server PUBLISHES the record to the
    // sink → the issuer-side `confirm_anchored` returns Ok (the sink reflects the
    // new verified head). Before the publish, the same confirm fails CLOSED. ----
    let rev = a_revocation(&b.admin);
    let expected = AnchoredHead {
        chain_seq: 1,
        head: sha256(&rev.bytes),
    };
    let (cp, lp) = (b.custodian_pub, b.log_pub);

    // BEFORE the append: the sink (at genesis) does not reflect the head → closed.
    let sink = HttpSinkClient::new(b.sink_addr, "localhost", b.sink_client_config.clone());
    let pre = tokio::task::spawn_blocking(move || confirm_anchored(&sink, &[cp], &[lp], expected))
        .await
        .unwrap();
    assert_eq!(
        pre,
        Err(maxsecu_client_core::SinkError::NotAnchored),
        "an unpublished head is not anchored (fail closed)"
    );

    assert_eq!(
        post_control(&mut c_admin, &admin_tok, "/v1/revocations", &rev).await,
        StatusCode::CREATED,
        "admin revokes over TLS"
    );

    // AFTER the publish: the sink reflects the verified head → confirm Ok.
    let sink = HttpSinkClient::new(b.sink_addr, "localhost", b.sink_client_config.clone());
    let ok = tokio::task::spawn_blocking(move || confirm_anchored(&sink, &[cp], &[lp], expected))
        .await
        .unwrap();
    assert_eq!(ok, Ok(()), "issuer confirms the sink reflects the new head");

    // ---- GATE 3: a client fetches the anchored head from the SINK and the
    // records from the APP SERVER — two independent channels — and they compose
    // into one authenticated tombstone set marking the victim revoked. ----
    let a_pub = b.admin.sig_pub_bytes();
    let issuer = move |id: Id| {
        (id.0 == ADMIN_ID).then_some(IssuerInfo {
            sig_pub: a_pub,
            roles: vec![Role::User, Role::Admin],
            key_version: 1,
        })
    };
    let sink = HttpSinkClient::new(b.sink_addr, "localhost", b.sink_client_config.clone());
    let (head, _proofs) = tokio::task::spawn_blocking(move || sink.fetch_head_all_proofs())
        .await
        .unwrap()
        .expect("sink head fetched over its own pinned channel");
    assert_eq!(head.chain_seq, 1);
    assert_eq!(head.head, sha256(&rev.bytes), "sink head == sha256(record)");

    let served = fetch_control(&mut c_admin, &admin_tok).await;
    assert_eq!(served.len(), 1, "app server served the one record");
    let set = TombstoneSet::verify_authenticated(&served, head.head, &issuer)
        .expect("served records verify against the sink-anchored head");
    assert!(
        set.is_revoked(&VICTIM_ID, &FILE_ID, 1),
        "the revoked user is in the authenticated set"
    );

    // ---- GATE 4 (withholding, D22): a server that serves a SHORT chain (here the
    // empty prefix) against the sink head fails closed as a Gap. ----
    assert_eq!(
        TombstoneSet::verify_authenticated(&[], head.head, &issuer).unwrap_err(),
        TombstoneError::Gap,
        "a withheld tail is a Gap against the sink head"
    );

    // ---- GATE 5 (append-only, §6.1): re-posting the now-stale record to the sink
    // (its prev_head no longer matches the sink head) is rejected 409. ----
    assert_eq!(
        post_sink_record(b.sink_addr, b.sink_client_config.clone(), &rev.bytes).await,
        StatusCode::CONFLICT,
        "an append-only rewrite is rejected"
    );

    // ---- GATE 7 (§16.2): an app-server error path stays sanitized over the wire —
    // a 404 (no-oracle, unknown file) carries a bare status with an EMPTY body. ----
    let (st, body) =
        get_raw(&mut c_admin, &format!("/v1/files/{}", hex(&[0xDE; 16])), Some(&admin_tok)).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "unknown file 404s");
    assert!(
        body.is_empty(),
        "the error body must be empty (no internals leak), got: {:?}",
        String::from_utf8_lossy(&body)
    );
}

/// ---- GATE 6 (R26 / DESIGN §16.1 / D27): the offline recovery-wrap sweep flags
/// a file-version whose recovery wrap encrypts a DIFFERENT DEK than the manifest
/// commits, and ONLY that one. The sweep is the air-gapped offline check — pure,
/// no I/O — so it is proven directly (mirroring `sweep.rs`'s own test), not over
/// the wire.
#[test]
fn r26_sweep_flags_bad_recovery_wrap() {
    let (recovery_priv, recovery_pub) = generate_enc_keypair();

    // Build the wire recovery wrap `enc(32) ‖ ct` exactly as the upload path does:
    // `wrap_dek` to the recovery key under the RECOVERY_ID-bound context (§5).
    let wire = |dek: &Dek, file: Id, version: u64| -> Vec<u8> {
        let ctx = WrapContext { file_id: file, version, recipient_id: RECOVERY_ID };
        let w = wrap_dek(&recovery_pub, dek, &ctx).unwrap();
        let mut v = w.enc.to_vec();
        v.extend_from_slice(&w.ct);
        v
    };

    let good = Id([0x11; 16]);
    let bad = Id([0x22; 16]);
    let dek_good = Dek::generate();
    let dek_bad = Dek::generate(); // the version's COMMITTED key
    let other = Dek::generate(); // a DIFFERENT key the writer actually wrapped

    let samples = vec![
        // A sound version: the wrap opens to its committed DEK.
        RecoverySample {
            file_id: good,
            version: 1,
            wrap: wire(&dek_good, good, 1),
            dek_commit: dek_good.commit(),
        },
        // The malicious version: a valid wrap of `other`, but the manifest commits
        // to `dek_bad` → the wrap silently does not open to the committed key.
        RecoverySample {
            file_id: bad,
            version: 3,
            wrap: wire(&other, bad, 3),
            dek_commit: dek_bad.commit(),
        },
    ];

    let report = run_sweep(&recovery_priv, &samples);
    assert_eq!(report.checked, 2);
    assert_eq!(
        report.bad,
        vec![RecoveryWrapCtx { file_id: bad, version: 3 }],
        "the sweep flags exactly the bad recovery wrap"
    );
}
