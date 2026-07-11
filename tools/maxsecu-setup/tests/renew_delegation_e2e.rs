//! Offline-D5 delegation RENEWAL e2e for `maxsecu-setup renew-delegation`
//! (workstream W5, spec §7 "Manual fallback") over REAL loopback TLS — mirrors the
//! W4 `d5_ceremony_e2e.rs` harness.
//!
//! Each test stands up a Prod-delegation server that is AWAITING a one-time token,
//! runs the FULL ceremony (`run()`) to register the recovery account, install the
//! initial 90-day delegation, and write `d5_key.blob` + `recovery_key.blob` to disk.
//! Then it drives `renew()`:
//!   * `renew_force…` — a `--force` renewal signs a FRESH 90-day cert, pushes it via
//!     the admin-gated `POST /v1/admin/delegation`, and the server serves it back;
//!     it verifies against the pinned D5 over the SAME operational key.
//!   * `renew_not_due…` — with the initial 90-day delegation still far from expiry,
//!     a non-forced renewal is a clean NO-OP (nothing pushed, window unchanged).

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
use maxsecu_crypto::{parse_delegation, sha256, verify_delegation, SigningKey};
use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, DelegationCtx, MemoryBlobStore, MemoryStore,
    NullAuditSink, NullDelegationPersist,
};
use maxsecu_setup::{renew, run, CeremonyOpts, RenewOpts, RenewOutcome, SetupOpts};
use zeroize::Zeroizing;

const PW: &str = "correct horse battery staple 9!";

// ---- loopback TLS harness (self-signed; mirrors d5_ceremony_e2e.rs) ----

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

/// A Prod-delegation server AWAITING the one-time `token`. Returns the state and
/// the server's operational public key.
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
    let json = if by.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&by).unwrap_or(serde_json::Value::Null)
    };
    (st, json)
}

fn tempdir() -> PathBuf {
    let rand: String = maxsecu_crypto::random_array::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let p = std::env::temp_dir().join(format!("maxsecu-d5-renew-{}-{rand}", std::process::id()));
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

/// Run the full ceremony against a fresh awaiting server: registers recovery,
/// installs the initial 90-day delegation, and writes `d5_key.blob` +
/// `recovery_key.blob` to `dir`. Returns `(transport, dir, d5_pub, op_pub,
/// initial_valid_until)`.
async fn ceremony(token: &str) -> (Transport, PathBuf, [u8; 32], [u8; 32], u64) {
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
    let report = run(&transport, &opts).await.expect("ceremony + setup ok");
    let cr = report.ceremony.expect("ceremony report present");
    (transport, dir, cr.d5_pub, op_pub, cr.valid_until)
}

fn renew_opts(dir: &std::path::Path, force: bool) -> RenewOpts {
    RenewOpts {
        host: "localhost".to_owned(),
        passphrase: Zeroizing::new(PW.to_owned()),
        d5_in: dir.join("d5_key.blob"),
        recovery_in: dir.join("recovery_key.blob"),
        force,
    }
}

// ---- --force renewal signs + installs a fresh 90-day delegation ----

#[tokio::test]
async fn renew_force_signs_and_installs_a_fresh_delegation_for_the_same_op_key() {
    let (transport, dir, d5_pub, op_pub, initial_vu) = ceremony("renew-token-force").await;

    // The initial delegation is ~90 days out → NOT within the 21-day threshold;
    // `--force` renews anyway. Unseal D5 + recovery from disk, recovery-login, push.
    let outcome = renew(&transport, &renew_opts(&dir, true))
        .await
        .expect("forced renew succeeds");
    let new_vu = match outcome {
        RenewOutcome::Renewed { valid_until } => valid_until,
        other => panic!("expected Renewed, got {other:?}"),
    };
    assert!(
        new_vu >= initial_vu,
        "the renewed window is at least as far out as the initial one"
    );

    // The server now serves the FRESH delegation; it verifies against the pinned D5
    // over the SAME operational key and within the new window (fail-closed chain).
    let mut c = open(&transport).await;
    let (st, doc) = get(&mut c, "/v1/bootstrap/delegation").await;
    assert_eq!(st, StatusCode::OK);
    let served_cert = B64
        .decode(doc["delegation_cert_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        parse_delegation(&served_cert).unwrap().valid_until(),
        new_vu,
        "the served cert carries the renewed window"
    );
    let extracted =
        verify_delegation(&d5_pub, &served_cert, now_secs()).expect("renewed cert verifies");
    assert_eq!(
        extracted, op_pub,
        "the renewal authorizes the SAME operational key"
    );
}

// ---- a not-due delegation is a clean no-op ----

#[tokio::test]
async fn renew_not_due_is_a_noop() {
    let (transport, dir, _d5_pub, _op_pub, initial_vu) = ceremony("renew-token-notdue").await;

    // The 90-day delegation is far from the 21-day threshold → NOT due.
    let outcome = renew(&transport, &renew_opts(&dir, false))
        .await
        .expect("not-due renew is a clean success (exit 0)");
    match outcome {
        RenewOutcome::NotDue { valid_until } => {
            assert_eq!(valid_until, initial_vu, "reports the unchanged window")
        }
        other => panic!("expected NotDue, got {other:?}"),
    }

    // The server's delegation is UNCHANGED (still the ceremony's cert / window).
    let mut c = open(&transport).await;
    let (st, doc) = get(&mut c, "/v1/bootstrap/delegation").await;
    assert_eq!(st, StatusCode::OK);
    let served_cert = B64
        .decode(doc["delegation_cert_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        parse_delegation(&served_cert).unwrap().valid_until(),
        initial_vu,
        "a not-due renewal left the delegation untouched"
    );
}
