//! Offline-D5 ceremony e2e for `maxsecu-setup` (workstream W4, spec §§6,7) over
//! REAL loopback TLS (mirrors `setup_e2e.rs`'s harness), plus focused
//! library-level tests for the D5 backup/restore round-trip.
//!
//! The ceremony test stands up a **Prod-delegation** server that is AWAITING a
//! one-time bootstrap token, drives the FULL `run()` (now doing the delegation
//! BEFORE the recovery-account setup), and asserts:
//!   * the delegation was installed (`GET /v1/bootstrap/delegation` → 200) and the
//!     cert verifies against the client-minted D5 over the server's op-key;
//!   * enrollment OPENED (a user enrolls with the minted first key → 201);
//!   * the D5 custody artifacts (sealed at-rest, sealed backup, `directory_pub.der`)
//!     were written and the two seals recover the SAME D5;
//!   * the printed connection code equals `addr#pin_fingerprint(cert, d5_pub)`.
//!
//! A negative test proves a WRONG token fails closed (nothing written), and the
//! restore test proves the recovery backup rebuilds the SAME directory root.

use std::path::PathBuf;
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

use maxsecu_client_app::transport::{pinned_client_config, Transport};
use maxsecu_client_core::Identity;
use maxsecu_crypto::{sha256, verify_delegation, SigningKey};
use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, DelegationCtx, MemoryBlobStore, MemoryStore,
    NullAuditSink, NullDelegationPersist,
};
use maxsecu_setup::{run, CeremonyOpts, RestoreOpts, SetupError, SetupOpts};
use zeroize::Zeroizing;

const PW: &str = "correct horse battery staple 9!";

// ---- loopback TLS harness (self-signed; mirrors setup_e2e.rs) ----

fn test_pki() -> (Arc<ServerConfig>, CertificateDer<'static>) {
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
    (Arc::new(server_config), cert_der)
}

/// A Prod-delegation server that is AWAITING the one-time `token`: enrollment is
/// closed, the operational key is the binding signer, and there is NO pinned
/// directory pub yet (the D5 originates on the admin PC / this test's `run`).
/// Returns the state and the server's operational public key.
fn prod_awaiting_state(token: &str) -> (AppState<MemoryStore>, [u8; 32]) {
    let op = Arc::new(SigningKey::generate());
    let op_pub = op.verifying_key().to_bytes();
    let ctx = Arc::new(DelegationCtx::prod(
        op_pub,
        None,
        Some(sha256(token.as_bytes())),
        Arc::new(NullDelegationPersist),
    ));
    let state = AppState {
        auth: Arc::new(
            AuthService::new(MemoryStore::new(), AuthConfig::default())
                .with_dir_signer(op)
                .with_delegation(ctx),
        ),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    (state, op_pub)
}

async fn start(token: &str) -> (std::net::SocketAddr, CertificateDer<'static>, [u8; 32]) {
    let (server_config, cert_der) = test_pki();
    let (state, op_pub) = prod_awaiting_state(token);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, server_config, router(state)));
    (addr, cert_der, op_pub)
}

fn transport_to(addr: std::net::SocketAddr, cert: CertificateDer<'static>) -> Transport {
    Transport::new(
        pinned_client_config(cert).unwrap(),
        ServerName::try_from("localhost").unwrap(),
        addr.to_string(),
    )
}

// ---- HTTP helpers over the pinned Transport ----

async fn open(t: &Transport) -> SendRequest<Full<Bytes>> {
    let (tls, _exporter) = t.connect().await.expect("pinned TLS connect");
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("http1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

async fn get(s: &mut SendRequest<Full<Bytes>>, uri: &str) -> (StatusCode, serde_json::Value) {
    s.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = s.send_request(req).await.unwrap();
    let st = resp.status();
    let by = resp.into_body().collect().await.unwrap().to_bytes();
    (st, parse_json(&by))
}

async fn post(
    s: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    s.ready().await.unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = s.send_request(req).await.unwrap();
    let st = resp.status();
    let by = resp.into_body().collect().await.unwrap().to_bytes();
    (st, parse_json(&by))
}

fn parse_json(by: &[u8]) -> serde_json::Value {
    if by.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(by).unwrap_or(serde_json::Value::Null)
    }
}

fn tempdir() -> PathBuf {
    // A random suffix — Windows `SystemTime` is too coarse to keep parallel tests
    // from colliding on a timestamp-only name.
    let rand: String = maxsecu_crypto::random_array::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let p = std::env::temp_dir().join(format!("maxsecu-d5-ceremony-{}-{rand}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn ceremony_opts(
    dir: &std::path::Path,
    cert: &CertificateDer<'static>,
    addr: &str,
    token: &str,
) -> CeremonyOpts {
    CeremonyOpts {
        token: Zeroizing::new(token.to_owned()),
        server_cert: cert.to_vec(),
        connect_addr: addr.to_owned(),
        d5_out: dir.join("d5_key.blob"),
        d5_recovery_out: dir.join("d5_recovery.blob"),
        dir_pub_out: dir.join("directory_pub.der"),
    }
}

// ---- the ceremony happy path ----

#[tokio::test]
async fn ceremony_installs_delegation_opens_enrollment_and_mints_connection_code() {
    let token = "one-time-bootstrap-token-abc123";
    let (addr, cert, op_pub) = start(token).await;
    let transport = transport_to(addr, cert.clone());
    let dir = tempdir();
    let cer = ceremony_opts(&dir, &cert, &addr.to_string(), token);

    let opts = SetupOpts {
        host: "localhost".to_owned(),
        out: dir.join("recovery_key.blob"),
        pin_out: dir.join("recovery_pin.bin"),
        first_key_out: dir.join("register.key"),
        passphrase: Zeroizing::new(PW.to_owned()),
        ceremony: Some(cer),
    };

    // Enrollment is CLOSED before the ceremony (awaiting delegation).
    {
        let mut c = open(&transport).await;
        let (st, _) = get(&mut c, "/v1/bootstrap/delegation").await;
        assert_eq!(st, StatusCode::NOT_FOUND, "awaiting ⇒ no delegation doc");
    }

    let report = run(&transport, &opts)
        .await
        .expect("ceremony + setup succeeds");
    let cr = report.ceremony.as_ref().expect("ceremony report present");

    // --- delegation installed + verifies against the client-minted D5 over op_pub.
    let mut c = open(&transport).await;
    let (st, doc) = get(&mut c, "/v1/bootstrap/delegation").await;
    assert_eq!(st, StatusCode::OK, "delegation now served");
    let served_dir: [u8; 32] = B64
        .decode(doc["directory_pub_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(served_dir, cr.d5_pub, "server pinned OUR generated D5");
    let served_cert = B64
        .decode(doc["delegation_cert_b64"].as_str().unwrap())
        .unwrap();
    let extracted_op = verify_delegation(&cr.d5_pub, &served_cert, now_secs())
        .expect("delegation verifies against the pinned D5 and window");
    assert_eq!(extracted_op, op_pub, "cert authorizes the server's op-key");

    // --- directory_pub.der written locally == the D5 pub.
    assert_eq!(
        std::fs::read(&cr.dir_pub_out).unwrap(),
        cr.d5_pub.to_vec(),
        "directory_pub.der is the raw D5 public key"
    );

    // --- both D5 seals recover the SAME seed → the SAME public key.
    let at_rest = std::fs::read(&cr.d5_out).unwrap();
    let backup = std::fs::read(&cr.d5_recovery_out).unwrap();
    let seed_a = maxsecu_client_core::seedblob::unseal_seed(PW, &at_rest).unwrap();
    let seed_b = maxsecu_client_core::seedblob::unseal_seed(PW, &backup).unwrap();
    assert_eq!(*seed_a, *seed_b, "at-rest + backup seal the same D5 seed");
    assert_eq!(
        SigningKey::from_seed(&seed_a).verifying_key().to_bytes(),
        cr.d5_pub,
        "the sealed seed re-derives the pinned D5 pub"
    );
    // Fresh salt/nonce per seal → the two blobs are NOT byte-identical.
    assert_ne!(at_rest, backup, "each seal uses a fresh salt/nonce");

    // --- connection code == addr#pin_fingerprint(cert, d5_pub) (the inversion).
    let expected_code = format!(
        "{}#{}",
        addr,
        maxsecu_crypto::pin_fingerprint(&cert.to_vec(), &cr.d5_pub)
    );
    assert_eq!(cr.connection_code, expected_code);

    // --- enrollment OPENED: the minted first key enrolls a user (201).
    let first_key = std::fs::read_to_string(&opts.first_key_out).unwrap();
    let user = Identity::generate();
    let (st, res) = post(
        &mut c,
        "/v1/users",
        serde_json::json!({
            "username": "first-admin",
            "enc_pub_b64": B64.encode(user.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(user.sig_pub_bytes()),
            "registration_key": first_key.trim(),
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "delegation opened enrollment: {res}"
    );
}

// ---- negative: a wrong token fails closed, nothing written ----

#[tokio::test]
async fn ceremony_wrong_token_fails_closed_and_writes_nothing() {
    let (addr, cert, _op_pub) = start("the-real-token").await;
    let transport = transport_to(addr, cert.clone());
    let dir = tempdir();
    let cer = ceremony_opts(&dir, &cert, &addr.to_string(), "WRONG-TOKEN");

    let opts = SetupOpts {
        host: "localhost".to_owned(),
        out: dir.join("recovery_key.blob"),
        pin_out: dir.join("recovery_pin.bin"),
        first_key_out: dir.join("register.key"),
        passphrase: Zeroizing::new(PW.to_owned()),
        ceremony: Some(cer),
    };

    let err = run(&transport, &opts)
        .await
        .expect_err("wrong token must fail");
    assert!(matches!(err, SetupError::DelegationBadToken), "got {err:?}");
    // Fail closed: NOTHING written (neither recovery nor D5 artifacts), and the
    // recovery account was never registered (the ceremony precedes it).
    for p in [
        &opts.out,
        &opts.pin_out,
        &opts.first_key_out,
        &dir.join("d5_key.blob"),
        &dir.join("d5_recovery.blob"),
        &dir.join("directory_pub.der"),
    ] {
        assert!(!p.exists(), "nothing written on bad token: {}", p.display());
    }
}

// ---- backup → restore rebuilds the SAME directory root ----

#[test]
fn restore_from_backup_yields_same_d5_and_connection_code() {
    // Simulate a completed ceremony's backup: seal a known D5 seed under the
    // recovery passphrase, exactly as `run` writes `d5_recovery.blob`.
    let d5 = SigningKey::generate();
    let d5_pub = d5.verifying_key().to_bytes();
    let seed = d5.to_seed();
    let backup =
        maxsecu_client_core::seedblob::seal_seed(PW, &seed, maxsecu_crypto::ARGON2_FLOOR).unwrap();

    let dir = tempdir();
    let backup_path = dir.join("d5_recovery.blob");
    std::fs::write(&backup_path, &backup).unwrap();

    let server_cert = b"a-self-signed-server-cert-der".to_vec();
    let connect_addr = "203.0.113.7:8443".to_owned();

    let opts = RestoreOpts {
        passphrase: Zeroizing::new(PW.to_owned()),
        d5_recovery_in: backup_path,
        server_cert: server_cert.clone(),
        connect_addr: connect_addr.clone(),
        d5_out: dir.join("d5_key.blob"),
        dir_pub_out: dir.join("directory_pub.der"),
    };
    let report = maxsecu_setup::restore(&opts).expect("restore succeeds");

    // Same directory root (no client re-pin), and the same connection code a fresh
    // ceremony would have minted.
    assert_eq!(report.d5_pub, d5_pub, "restore yields the SAME D5 root");
    assert_eq!(
        std::fs::read(&opts.dir_pub_out).unwrap(),
        d5_pub.to_vec(),
        "directory_pub.der rebuilt from the backup"
    );
    let expected_code = format!(
        "{}#{}",
        connect_addr,
        maxsecu_crypto::pin_fingerprint(&server_cert, &d5_pub)
    );
    assert_eq!(report.connection_code, expected_code);

    // The re-established at-rest seal recovers the same seed.
    let at_rest = std::fs::read(&opts.d5_out).unwrap();
    let recovered = maxsecu_client_core::seedblob::unseal_seed(PW, &at_rest).unwrap();
    assert_eq!(
        *recovered, seed,
        "re-sealed at-rest blob recovers the D5 seed"
    );
}

#[test]
fn restore_refuses_to_clobber_existing_outputs() {
    let d5 = SigningKey::generate();
    let backup =
        maxsecu_client_core::seedblob::seal_seed(PW, &d5.to_seed(), maxsecu_crypto::ARGON2_FLOOR)
            .unwrap();
    let dir = tempdir();
    let backup_path = dir.join("d5_recovery.blob");
    std::fs::write(&backup_path, &backup).unwrap();
    let dir_pub_out = dir.join("directory_pub.der");
    std::fs::write(&dir_pub_out, b"already here").unwrap();

    let opts = RestoreOpts {
        passphrase: Zeroizing::new(PW.to_owned()),
        d5_recovery_in: backup_path,
        server_cert: b"cert".to_vec(),
        connect_addr: "h:1".to_owned(),
        d5_out: dir.join("d5_key.blob"),
        dir_pub_out,
    };
    assert!(
        matches!(maxsecu_setup::restore(&opts), Err(SetupError::Precheck(_))),
        "restore must not overwrite an existing directory_pub.der"
    );
}
