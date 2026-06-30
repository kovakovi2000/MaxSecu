//! DEV/DEMO-ONLY seeding tool. Provisions a usable two-account demo against an
//! already-running `maxsecu-portable-server`, exactly the way
//! `bootstrap_admin_e2e.rs` does — but driving the *real* running server and
//! using its on-disk dev D5 seed as the scripted offline ceremony:
//!
//!   1. bootstrap `root` (first-admin) with the live bootstrap secret;
//!   2. publish `root`'s [User,Admin] binding under the dev D5 → bootstrap closes;
//!   3. seal `root`'s identity into the root client folder's keystore;
//!   4. log in as `root`, issue a voucher; register `bob` via /v1/users;
//!   5. publish `bob`'s [User] binding; seal `bob` into the bob client folder;
//!   6. issue one spare voucher and print it (for the GUI voucher demo).
//!
//! NEVER a production path: it reads the cleartext dev D5 seed off disk. The real
//! ceremony runs offline with an air-gapped key. Configuration is via env vars so
//! the start script can pass the live bootstrap secret in.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};

use maxsecu_ceremony_harness::Ceremony;
use maxsecu_client_app::session::login_exchange;
use maxsecu_client_app::transport::{pinned_client_config, Transport};
use maxsecu_client_app::{keystore, session};
use maxsecu_client_core::Identity;
use maxsecu_crypto::sha256;
use maxsecu_encoding::types::Role;

/// Read an env var or fall back to `default`.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// 16-byte user_id rendered as 32 lowercase hex chars → bytes.
fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex user_id");
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Open a fresh pinned-TLS HTTP/1.1 connection; returns the sender + RFC-5705 exporter.
async fn open(t: &Transport) -> (SendRequest<Full<Bytes>>, [u8; 32]) {
    let (tls, exporter) = t.connect().await.expect("pinned TLS connect");
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("http1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, exporter)
}

/// POST one JSON body (optionally bearer-authed) → (status, json).
async fn post(
    s: &mut SendRequest<Full<Bytes>>,
    host: &str,
    uri: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    s.ready().await.expect("sender ready");
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("MaxSecu-Session {t}"));
    }
    let resp = s
        .send_request(b.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .expect("send POST");
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

/// Bootstrap-register a real identity; returns its server-assigned user_id.
async fn bootstrap_account(
    c: &mut SendRequest<Full<Bytes>>,
    host: &str,
    username: &str,
    id: &Identity,
    secret: &str,
) -> [u8; 16] {
    let (st, j) = post(
        c,
        host,
        "/v1/bootstrap",
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(id.sig_pub_bytes()),
            "bootstrap_secret": secret,
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "bootstrap {username}: {st} {j}");
    hex16(j["user_id"].as_str().expect("user_id"))
}

/// Publish a ceremony-signed binding for `username` under the dev D5.
async fn publish_binding(
    c: &mut SendRequest<Full<Bytes>>,
    host: &str,
    cer: &Ceremony,
    username: &str,
    uid: [u8; 16],
    id: &Identity,
    roles: &[Role],
) {
    let pb = cer.sign_binding(
        username,
        uid,
        id.enc_pub_bytes(),
        id.sig_pub_bytes(),
        roles,
        1,
    );
    let (st, j) = post(
        c,
        host,
        "/v1/directory",
        serde_json::json!({
            "binding_b64": B64.encode(&pb.binding_bytes),
            "directory_signature_b64": B64.encode(pb.signature),
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "publish {username} binding: {st} {j}");
}

/// Seal a generated identity into `<client_dir>/keystore/local_key_blob`.
fn seal_into(client_dir: &Path, password: &str, id: &Identity, who: &str) {
    if keystore::exists(client_dir) {
        eprintln!(
            "  [seed] {who}: keystore already present at {} — leaving it (delete keystore/ to re-seal)",
            client_dir.display()
        );
        return;
    }
    keystore::seal_identity(client_dir, password, id)
        .unwrap_or_else(|e| panic!("seal {who} keystore: {}", e.message));
    eprintln!("  [seed] {who}: sealed keystore → {}", client_dir.display());
}

/// Issue a voucher as the admin `token`; returns the plaintext code.
async fn issue_voucher(c: &mut SendRequest<Full<Bytes>>, host: &str, token: &str, code: &str) {
    let (st, j) = post(
        c,
        host,
        "/v1/vouchers",
        serde_json::json!({ "voucher_hash_b64": B64.encode(sha256(code.as_bytes())) }),
        Some(token),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "issue voucher: {st} {j}");
}

#[tokio::main]
async fn main() {
    // --- configuration (env, with demo defaults) ---
    let dial = env_or("SEED_SERVER", "127.0.0.1:8443"); // TCP dial target
    let host = env_or("SEED_HOST", "localhost"); // cert SAN / SNI / Host header
    let data_dir = PathBuf::from(env_or("SEED_DATA_DIR", "./maxsecu-server-data"));
    let root_dir = PathBuf::from(env_or("SEED_ROOT_DIR", "./dist/MaxSecuClient-root"));
    let bob_dir = PathBuf::from(env_or("SEED_BOB_DIR", "./dist/MaxSecuClient-bob"));
    let secret = std::env::var("SEED_BOOTSTRAP_SECRET")
        .expect("SEED_BOOTSTRAP_SECRET must be set (printed by the server on first run)");
    let root_pw = env_or("SEED_ROOT_PW", "root-demo-pass-9!");
    let bob_pw = env_or("SEED_BOB_PW", "bob-demo-pass-9!");

    // --- pinned cert + dev D5 seed off the server data dir ---
    let cert_path = data_dir.join("client-pins").join("server_cert.der");
    let cert_bytes = std::fs::read(&cert_path)
        .unwrap_or_else(|e| panic!("read pinned cert {}: {e}", cert_path.display()));
    let cert = CertificateDer::from(cert_bytes);

    let seed_path = data_dir.join("config").join("d5_secret.bin");
    let seed_vec = std::fs::read(&seed_path)
        .unwrap_or_else(|e| panic!("read dev D5 seed {}: {e}", seed_path.display()));
    let seed: [u8; 32] = seed_vec
        .as_slice()
        .try_into()
        .expect("d5_secret.bin must be exactly 32 bytes");
    let cer = Ceremony::from_seed(&seed);

    let transport = Transport::new(
        pinned_client_config(cert).expect("pinned client config"),
        ServerName::try_from(host.clone()).expect("server name"),
        dial.clone(),
    );

    eprintln!("[seed] target https://{host} (dialing {dial})");
    eprintln!("[seed] pinned D5 (from dev seed): {}", hex(&cer.directory_pub()));

    // --- 1) bootstrap root, 2) publish its admin binding (closes bootstrap) ---
    let root_id = Identity::generate();
    let (mut c, _e) = open(&transport).await;
    let root_uid = bootstrap_account(&mut c, &host, "root", &root_id, &secret).await;
    publish_binding(
        &mut c,
        &host,
        &cer,
        "root",
        root_uid,
        &root_id,
        &[Role::User, Role::Admin],
    )
    .await;
    eprintln!("  [seed] root user_id = {}", hex(&root_uid));

    // 3) seal root before any further failure point.
    seal_into(&root_dir, &root_pw, &root_id, "root");

    // --- 4) login as root, issue bob's voucher, register bob ---
    let (mut admin_conn, exporter) = open(&transport).await;
    let login = login_exchange(&mut admin_conn, &root_id, "root", &host, &exporter, now_ms())
        .await
        .expect("root login");
    let _: &session::LoginOk = &login; // type anchor
    let token = login.token;

    let voucher_code = format!("demo-voucher-{}", hex(&maxsecu_crypto::random_array::<6>()));
    issue_voucher(&mut admin_conn, &host, &token, &voucher_code).await;

    let bob_id = Identity::generate();
    let (mut bob_conn, _e) = open(&transport).await;
    let (st, j) = post(
        &mut bob_conn,
        &host,
        "/v1/users",
        serde_json::json!({
            "username": "bob",
            "enc_pub_b64": B64.encode(bob_id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(bob_id.sig_pub_bytes()),
            "enrollment_voucher": voucher_code,
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "register bob: {st} {j}");
    let bob_uid = hex16(j["user_id"].as_str().expect("bob user_id"));
    eprintln!("  [seed] bob user_id = {}", hex(&bob_uid));

    // --- 5) publish bob's user binding; seal bob ---
    publish_binding(&mut bob_conn, &host, &cer, "bob", bob_uid, &bob_id, &[Role::User]).await;
    seal_into(&bob_dir, &bob_pw, &bob_id, "bob");

    // --- 6) one spare voucher for the GUI voucher demo (appendix) ---
    let spare = format!("spare-voucher-{}", hex(&maxsecu_crypto::random_array::<6>()));
    issue_voucher(&mut admin_conn, &host, &token, &spare).await;

    println!();
    println!("================ DEMO SEED COMPLETE ================");
    println!("admin  : root  (password: {root_pw})  → {}", root_dir.display());
    println!("user   : bob   (password: {bob_pw})   → {}", bob_dir.display());
    println!("spare voucher code (for a GUI voucher-enrol demo): {spare}");
    println!("Both accounts have published directory bindings and sealed keystores.");
    println!("Launch either client → Connect to localhost:8443 with the username+password above.");
    println!("===================================================");
}
