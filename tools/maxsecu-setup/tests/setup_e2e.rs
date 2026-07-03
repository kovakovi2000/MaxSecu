//! T14 exit-gate end-to-end test for `maxsecu-setup` over REAL loopback TLS
//! (mirrors `server/tests/recovery_login_e2e.rs` for the harness + the recovery
//! round-trip, and `http.rs::first_registrant_is_admin_second_is_user_only` for
//! the admin check).
//!
//! Against a FRESH in-process server, one `maxsecu_setup::run` must:
//!   * write all THREE artifacts and return Ok;
//!   * emit a `recovery_pin.bin` that equals `canonical_pin` of the server's stored
//!     recovery enc-pub + ML-KEM (fetched from `GET /v1/recovery/pubkey`);
//!   * emit a first registration key that actually enrolls a user (201) whose
//!     directory binding is ADMIN;
//!
//! and a SECOND run against the same (now-registered) server must fail with
//! `AlreadyRegistered` and write NOTHING new (fresh output paths stay absent).

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

use maxsecu_client_app::recovery_pin::canonical_pin;
use maxsecu_client_app::transport::{pinned_client_config, Transport};
use maxsecu_client_core::Identity;
use maxsecu_crypto::SigningKey;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::Role;
use maxsecu_server::{
    router, serve, AppState, AuthConfig, AuthService, MemoryBlobStore, MemoryStore, NullAuditSink,
};
use maxsecu_setup::{run, SetupError, SetupOpts};
use zeroize::Zeroizing;

// ---- loopback TLS harness (self-signed; mirrors recovery_login_e2e.rs) ----

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

/// A server with the D5 admin gate configured (directory pub pinned + a dir signer
/// so registration-key enrollment can sign bindings) — the same state the recovery
/// admin session must satisfy.
fn state_with_admin_gate() -> AppState<MemoryStore> {
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

async fn start() -> (std::net::SocketAddr, CertificateDer<'static>) {
    let (server_config, cert_der) = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, server_config, router(state_with_admin_gate())));
    (addr, cert_der)
}

fn transport_to(addr: std::net::SocketAddr, cert: CertificateDer<'static>) -> Transport {
    Transport::new(
        pinned_client_config(cert).unwrap(),
        ServerName::try_from("localhost").unwrap(),
        addr.to_string(),
    )
}

// ---- HTTP helpers over the pinned Transport (mirror demo-seed) ----

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

fn parse_json(by: &[u8]) -> serde_json::Value {
    if by.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(by).unwrap_or(serde_json::Value::Null)
    }
}

fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "maxsecu-setup-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test]
async fn setup_bootstraps_recovery_first_key_and_pin_then_409_on_rerun() {
    let (addr, cert) = start().await;
    let transport = transport_to(addr, cert.clone());
    let dir = tempdir();

    let opts = SetupOpts {
        host: "localhost".to_owned(),
        out: dir.join("recovery_key_blob"),
        pin_out: dir.join("recovery_pin.bin"),
        first_key_out: dir.join("first_registration_key.txt"),
        passphrase: Zeroizing::new("correct horse battery staple 9!".to_owned()),
    };

    // ---- FIRST run: writes all three artifacts, returns Ok. ----
    let report = run(&transport, &opts).await.expect("first setup run succeeds");
    assert!(opts.out.exists(), "sealed recovery key blob written");
    assert!(opts.pin_out.exists(), "recovery_pin.bin written");
    assert!(opts.first_key_out.exists(), "first registration key written");

    // Sealed blob is NOT the bare key: it must unlock with the passphrase and yield
    // the SAME recovery identity that was registered (enc pub matches the report).
    let blob = std::fs::read(&opts.out).unwrap();
    let recovered = maxsecu_client_core::keyblob::unlock("correct horse battery staple 9!", &blob)
        .expect("sealed blob unlocks with the passphrase");
    assert_eq!(
        recovered.enc_pub_bytes(),
        report.recovery_enc_pub,
        "sealed blob is the registered recovery identity"
    );
    assert!(recovered.mlkem_pub_bytes().is_some(), "recovery account is hybrid (PQ)");

    // ---- the emitted pin equals canonical_pin of the server's STORED recovery key. ----
    let mut c = open(&transport).await;
    let (st, pk) = get(&mut c, "/v1/recovery/pubkey").await;
    assert_eq!(st, StatusCode::OK);
    let enc_pub: [u8; 32] = B64
        .decode(pk["enc_pub_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mlkem = B64.decode(pk["mlkem_pub_b64"].as_str().unwrap()).unwrap();
    let expected_pin = canonical_pin(&enc_pub, Some(&mlkem));
    assert_eq!(
        std::fs::read(&opts.pin_out).unwrap(),
        expected_pin,
        "recovery_pin.bin byte-matches the server's stored recovery pubkey"
    );

    // ---- the first registration key enrolls a user who is ADMIN. ----
    let first_key = std::fs::read_to_string(&opts.first_key_out).unwrap();
    let first_key = first_key.trim();
    assert!(!first_key.is_empty(), "first key is non-empty");

    let user = Identity::generate();
    let (st, res) = post(
        &mut c,
        "/v1/users",
        serde_json::json!({
            "username": "first-admin",
            "enc_pub_b64": B64.encode(user.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(user.sig_pub_bytes()),
            "registration_key": first_key,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "first key enrolls a user: {res}");

    // The served directory binding for that user is {User, Admin}.
    let (st, body) = get(&mut c, "/v1/directory/first-admin").await;
    assert_eq!(st, StatusCode::OK);
    let bytes = B64.decode(body["binding_b64"].as_str().unwrap()).unwrap();
    let binding = maxsecu_encoding::decode::<DirBinding>(&bytes).unwrap();
    assert!(
        binding.roles.roles().contains(&Role::Admin),
        "first enrollee is ADMIN"
    );

    // ---- SECOND run against the now-registered server → 409, writes nothing. ----
    let dir2 = tempdir();
    let opts2 = SetupOpts {
        host: "localhost".to_owned(),
        out: dir2.join("recovery_key_blob"),
        pin_out: dir2.join("recovery_pin.bin"),
        first_key_out: dir2.join("first_registration_key.txt"),
        passphrase: Zeroizing::new("correct horse battery staple 9!".to_owned()),
    };
    let err = run(&transport, &opts2).await.expect_err("second run must fail");
    assert!(
        matches!(err, SetupError::AlreadyRegistered),
        "second run is AlreadyRegistered (409), got {err:?}"
    );
    assert!(!opts2.out.exists(), "409 wrote no key blob");
    assert!(!opts2.pin_out.exists(), "409 wrote no pin");
    assert!(!opts2.first_key_out.exists(), "409 wrote no first key");
}

/// Robustness gap: if a cold-artifact WRITE fails AFTER the once-only register has
/// committed, `run` must surface an `Io` error (and, in the binary, emergency-dump the
/// sealed blob + first key to stderr) rather than silently losing the irreplaceable
/// recovery key. The registration nevertheless stands server-side, so the operator can
/// recover from the dump. Here we force the FIRST write to fail by pointing `--out`
/// under a parent that is a regular file (so `create_dir_all` fails) — preflight passes
/// (the path does not yet exist) but the write fails only post-commit — and we prove
/// register stuck via a 409 on a clean re-run.
#[tokio::test]
async fn post_register_write_failure_is_io_error_but_registration_commits() {
    let (addr, cert) = start().await;
    let transport = transport_to(addr, cert.clone());
    let dir = tempdir();

    // A regular file masquerading as the parent directory of `--out`.
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();

    let opts = SetupOpts {
        host: "localhost".to_owned(),
        out: blocker.join("recovery_key_blob"), // parent is a FILE → create_dir_all fails
        pin_out: dir.join("recovery_pin.bin"),
        first_key_out: dir.join("first_registration_key.txt"),
        passphrase: Zeroizing::new("correct horse battery staple 9!".to_owned()),
    };

    let err = run(&transport, &opts)
        .await
        .expect_err("post-commit write must fail");
    assert!(
        matches!(err, SetupError::Io(_)),
        "write failure surfaces as Io, got {err:?}"
    );
    // The failing first write aborts before the other two artifacts are touched.
    assert!(!opts.pin_out.exists(), "no pin written once the out-write failed");
    assert!(
        !opts.first_key_out.exists(),
        "no first key written once the out-write failed"
    );

    // Register nevertheless COMMITTED: the server serves a recovery pubkey now ...
    let mut c = open(&transport).await;
    let (st, _pk) = get(&mut c, "/v1/recovery/pubkey").await;
    assert_eq!(
        st,
        StatusCode::OK,
        "recovery account is registered despite the write failure"
    );

    // ... and a clean re-run is rejected 409 (the once-only register stuck).
    let dir2 = tempdir();
    let opts2 = SetupOpts {
        host: "localhost".to_owned(),
        out: dir2.join("recovery_key_blob"),
        pin_out: dir2.join("recovery_pin.bin"),
        first_key_out: dir2.join("first_registration_key.txt"),
        passphrase: Zeroizing::new("correct horse battery staple 9!".to_owned()),
    };
    let err2 = run(&transport, &opts2)
        .await
        .expect_err("clean re-run must 409");
    assert!(
        matches!(err2, SetupError::AlreadyRegistered),
        "re-run is AlreadyRegistered, got {err2:?}"
    );
}
