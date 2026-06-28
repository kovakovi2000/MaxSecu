//! End-to-end sink test over loopback TLS (`docs/sink-interface.md` §3/§5).
//!
//! A real `sink-server` is stood up on a loopback TLS 1.3 port with a pinned
//! self-signed cert; the real `client-core::HttpSinkClient` fetches and verifies
//! the anchored head over the sink's OWN pinned channel — independent of the app
//! server. The capstone assertions are the two tamper checks the sink exists to
//! make real:
//!   * a server that WITHHOLDS a record is caught as a `Gap` against the sink
//!     head (fail closed, D22), and
//!   * an append-only REWRITE is rejected `409` by the sink (§6.1).

use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use maxsecu_admin_core::{ControlChain, RevokeParams, SignedControlRecord};
use maxsecu_client_core::revocation::{ControlRecordIn, IssuerInfo, TombstoneError, TombstoneSet};
use maxsecu_client_core::sink::{verify_anchor_proof, AnchorProof, HttpSinkClient};
use maxsecu_crypto::SigningKey;
use maxsecu_encoding::types::{FileScope, Id, Role, Timestamp};
use maxsecu_sink_server::{router, serve, Anchorer, SinkState};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

const NOW: Timestamp = Timestamp(1_719_500_000_000);
const ADMIN_ID: Id = Id([1; 16]);
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

fn rp(victim: u8) -> RevokeParams {
    RevokeParams {
        scope: FileScope::Specific(Id([0x0A; 16])),
        revoked_user_id: Id([victim; 16]),
        revoked_capability: None,
        from_version: 1,
        issued_by: ADMIN_ID,
        created_at: NOW,
    }
}

fn rec_in(r: &SignedControlRecord) -> ControlRecordIn {
    ControlRecordIn {
        bytes: r.bytes.clone(),
        sig: r.sig,
        co_sig: r.co_sig,
    }
}

/// POST one record to the sink over TLS and return the status.
async fn post_record(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    token: &str,
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
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    sender.send_request(req).await.unwrap().status()
}

/// GET the sink's own records and return them as `ControlRecordIn`s in order,
/// pairing the sink-served record bytes with the issuer sig/co_sig the client
/// already holds out of band (the sink does not serve sigs — clients verify, §6.1).
async fn fetch_records(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    sigs: &[SignedControlRecord],
) -> Vec<ControlRecordIn> {
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
        .uri("/v1/control-log/records")
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let rb = B64.decode(e["record_b64"].as_str().unwrap()).unwrap();
            // Match the served bytes to the locally-held sig/co_sig.
            let s = sigs.iter().find(|s| s.bytes == rb).unwrap();
            ControlRecordIn {
                bytes: rb,
                sig: s.sig,
                co_sig: s.co_sig,
            }
        })
        .collect()
}

#[tokio::test]
async fn client_fetches_verifies_and_detects_withholding_over_tls() {
    let pki = test_pki();

    // ---- 1. Stand up the sink over loopback TLS. ----
    let custodian = SigningKey::generate();
    let log = SigningKey::generate();
    let custodian_pub = custodian.verifying_key().to_bytes();
    let log_pub = log.verifying_key().to_bytes();
    let anchorer = Anchorer::new(custodian, log);
    let app = router(SinkState::new(anchorer, TOKEN));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), app));

    // ---- 2. Build 2 real control records and POST both to the sink. ----
    let admin = SigningKey::generate();
    let admin_pub = admin.verifying_key().to_bytes();
    let mut chain = ControlChain::new();
    let r1 = chain.revoke(&admin, rp(0x99), None).unwrap();
    let r2 = chain.revoke(&admin, rp(0x98), None).unwrap();

    assert_eq!(
        post_record(addr, pki.client_config.clone(), TOKEN, &r1.bytes).await,
        StatusCode::OK
    );
    assert_eq!(
        post_record(addr, pki.client_config.clone(), TOKEN, &r2.bytes).await,
        StatusCode::OK
    );

    // ---- 3. Fetch + verify the head (BOTH anchor-proof forms) over the pinned
    // channel via the real HttpSinkClient. ----
    // The SinkClient interface is sync (real callers have no ambient runtime); in
    // this `#[tokio::test]` we run the blocking fetch on a blocking thread so its
    // internal runtime is not nested inside this test's runtime.
    let sink = HttpSinkClient::new(addr, "localhost", pki.client_config.clone());
    let (head, proofs) = tokio::task::spawn_blocking(move || sink.fetch_head_all_proofs())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.chain_seq, 2);
    assert_eq!(head.head, chain.head(), "sink head == the chain's head");

    let cosig = proofs
        .iter()
        .find(|p| matches!(p, AnchorProof::CustodianCoSig { .. }))
        .unwrap();
    let transparency = proofs
        .iter()
        .find(|p| matches!(p, AnchorProof::TransparencyInclusion { .. }))
        .unwrap();
    // The custodian co-signature verifies under the pinned custodian key …
    verify_anchor_proof(&head, cosig, &[custodian_pub], &[]).expect("cosig form trusted");
    // … and the transparency-inclusion form verifies under the pinned log key.
    verify_anchor_proof(&head, transparency, &[], &[log_pub]).expect("transparency form trusted");

    // ---- 4. A server that WITHHOLDS the tail is caught as a Gap. ----
    let issuer = |id: Id| {
        (id == ADMIN_ID).then_some(IssuerInfo {
            sig_pub: admin_pub,
            roles: vec![Role::Admin],
            key_version: 1,
        })
    };
    // The full set up to the anchored head verifies …
    let full = fetch_records(addr, pki.client_config.clone(), &[r1.clone(), r2.clone()]).await;
    assert_eq!(full.len(), 2);
    TombstoneSet::verify_authenticated(&full, head.head, &issuer).expect("full set verifies");
    // … but a withheld tail (serve only r1) is a Gap against the sink head.
    let withheld = [rec_in(&r1)];
    assert_eq!(
        TombstoneSet::verify_authenticated(&withheld, head.head, &issuer).unwrap_err(),
        TombstoneError::Gap
    );

    // ---- 5. An append-only rewrite is rejected 409. ----
    // Re-posting r1 (whose prev_head is now stale) is a rewrite attempt.
    assert_eq!(
        post_record(addr, pki.client_config.clone(), TOKEN, &r1.bytes).await,
        StatusCode::CONFLICT
    );
}
