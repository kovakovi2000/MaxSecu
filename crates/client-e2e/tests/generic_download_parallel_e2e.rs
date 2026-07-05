//! WS9 Task 9.2 exit-gate end-to-end tests, over REAL loopback TLS with NO mocked
//! crypto — mirroring the standard of `upload_e2e.rs` and `bundle_e2e.rs`.
//!
//! Two independent gates:
//!
//! - **Test A — generic upload + download byte-identical.** Uploads a
//!   `FileType::Generic` (download-only) file through the REAL `build_upload` +
//!   `run_pipeline` path (`prepare_generic_metadata` for the metadata), fetches it
//!   back, `verify_and_open`s it, and asserts the decrypted content stream is
//!   BYTE-IDENTICAL to the original plaintext AND that the metadata JSON carries the
//!   original `filename`.
//!
//! - **Test B — parallel feed decode via the authed connection pool.** Uploads N
//!   listed files with DISTINCT titles, then decodes them CONCURRENTLY through the
//!   REAL [`maxsecu_client_app::commands::pool::AuthedPool`]. Every authed read
//!   command normally re-authenticates on a fresh channel via `reauth`, which
//!   `try_lock`s the ONE `ConnectLock` and transiently `take`s the single non-`Clone`
//!   `Identity` — so two concurrent `decrypt_card`s cannot overlap (a second `reauth`
//!   gets `busy`). The pool hands each concurrent borrower its OWN channel-bound
//!   authed channel, so N reads proceed in parallel. This test drives the real pool
//!   with real authed channels (each its own TLS connection + channel-bound login),
//!   forces all N to be live simultaneously (a barrier), and asserts ALL N tasks
//!   succeed and return their EXPECTED title in the right correspondence — no
//!   cross-talk / identity race — while proving N distinct channels were minted.
//!
//! ## Why the flow is reconstructed rather than calling the Tauri commands
//! `confirm_upload` / `decrypt_card` are `#[tauri::command]`s taking Tauri
//! `State`/`AppHandle` (bound to the concrete `Wry` runtime — not constructible
//! headless), so an external test crate cannot reach them. Exactly as `upload_e2e.rs`
//! and `bundle_e2e.rs` reconstruct their flows from public primitives, this suite
//! reconstructs the generic-upload + parallel-decode flow from the SAME public
//! product code (`build_upload`, `run_pipeline`, `verify_and_open`, and the real
//! `AuthedPool`) over real transport + real crypto. No verification is weakened.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_admin_core::DirectorySigner;
use maxsecu_client_app::commands::pool::AuthedPool;
use maxsecu_client_app::error::UiError;
use maxsecu_client_app::upload::{prepare_blog_streams, run_pipeline, StageFlags};
use maxsecu_client_core::{
    build_upload, verify_and_open, DownloadBundle, Identity, OpenedFile, PlaintextStreams,
    StreamChunks, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey, SigningKey, WrappedDek};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{
    Bytes32, FileType, Id, RecipientType, Role, RoleSet, StreamType, Text, Timestamp,
};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const TS: u64 = 1_719_500_000_000;
const FAR_FUTURE_MS: u64 = 4_102_444_800_000;
const CHUNK: u32 = 4096;

// ============================================================================
// TLS + HTTP harness (copied from upload_e2e.rs / bundle_e2e.rs)
// ============================================================================

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

async fn get_json(conn: &mut Conn, uri: &str, auth: &str) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
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

async fn get_raw(conn: &mut Conn, uri: &str, auth: &str) -> (StatusCode, Vec<u8>) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = conn.sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes)
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

fn stream_from_name(s: &str) -> StreamType {
    match s {
        "content" => StreamType::Content,
        "metadata" => StreamType::Metadata,
        "thumbnail" => StreamType::Thumbnail,
        "preview" => StreamType::Preview,
        _ => panic!("unknown stream {s}"),
    }
}

fn wrap_from_bytes(b: &[u8]) -> WrappedDek {
    WrappedDek {
        enc: b[..32].try_into().unwrap(),
        ct: b[32..].to_vec(),
    }
}

/// The channel-bound login handshake (challenge + proof) for an already-registered
/// user, over a FRESH connection `c` — returns that channel's session token.
async fn do_login(c: &mut Conn, owner: &Identity, username: &str) -> String {
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
        use maxsecu_encoding::structs::AuthProofContext;
        let ctx = AuthProofContext {
            server_id: Text::new(&server_id).unwrap(),
            tls_exporter: Bytes32(c.exporter),
            nonce: Bytes32(nonce),
            timestamp: Timestamp(TS),
        };
        B64.encode(owner.signing_key().sign_canonical(labels::AUTH, &ctx))
    };
    let (st, res) = post(
        c,
        "/v1/session/proof",
        None,
        serde_json::json!({ "username": username, "timestamp": TS, "proof_b64": proof }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login over the bound channel ({username})");
    res["session_token"].as_str().unwrap().to_owned()
}

/// Register + channel-bound-login an identity; return its `user_id` + session token.
async fn register_and_login(
    c: &mut Conn,
    owner: &Identity,
    username: &str,
    reg_key: &str,
) -> ([u8; 16], String) {
    let (st, res) = post(
        c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(owner.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(owner.sig_pub_bytes()),
            "registration_key": reg_key,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS ({username})");
    let user_id = hex16(res["user_id"].as_str().unwrap());
    let token = do_login(c, owner, username).await;
    (user_id, token)
}

/// Publish a classical (v1) D5-signed binding for `(username, user_id, identity)`.
async fn publish_binding(
    c: &mut Conn,
    signer: &DirectorySigner,
    username: &str,
    uid: [u8; 16],
    id: &Identity,
) {
    let binding = DirBinding {
        username: Text::new(username).unwrap(),
        user_id: Id(uid),
        enc_pub: Bytes32(id.enc_pub_bytes()),
        sig_pub: Bytes32(id.sig_pub_bytes()),
        key_version: 1,
        roles: RoleSet::new([Role::User]),
        not_before: Timestamp(0),
        not_after: Timestamp(FAR_FUTURE_MS),
        mlkem_pub: None,
    };
    let signed = signer.sign_binding(&binding, None);
    let (st, _) = post(
        c,
        "/v1/directory",
        None,
        serde_json::json!({
            "binding_b64": B64.encode(maxsecu_encoding::encode(&signed.binding)),
            "directory_signature_b64": B64.encode(signed.signature),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "publish binding {username}");
}

/// GET the file view + every chunk back and rebuild a `DownloadBundle` — mirrors the
/// rebuild in upload_e2e.rs / bundle_e2e.rs.
async fn download_bundle(c: &mut Conn, token: &str, fid_hex: &str) -> DownloadBundle {
    let (st, rec) = get_json(c, &format!("/v1/files/{fid_hex}?version=latest"), token).await;
    assert_eq!(st, StatusCode::OK, "file view for {fid_hex}");
    let mut dl_streams = Vec::new();
    for s in rec["streams"].as_array().unwrap() {
        let st_name = s["stream_type"].as_str().unwrap();
        let count = s["chunk_count"].as_u64().unwrap();
        let mut chunks = Vec::new();
        for i in 0..count {
            let uri = format!("/v1/files/{fid_hex}/versions/1/streams/{st_name}/chunks/{i}");
            let (cs, bytes) = get_raw(c, &uri, token).await;
            assert_eq!(cs, StatusCode::OK);
            chunks.push(bytes);
        }
        dl_streams.push(StreamChunks {
            stream_type: stream_from_name(st_name),
            chunks,
        });
    }
    let dec = |v: &serde_json::Value| B64.decode(v.as_str().unwrap()).unwrap();
    let dec64 = |v: &serde_json::Value| -> [u8; 64] { dec(v).try_into().unwrap() };
    let mw = &rec["my_wrap"];
    let rg = &rec["recovery_grant"];
    DownloadBundle {
        manifest_bytes: dec(&rec["manifest_b64"]),
        manifest_sig: dec64(&rec["manifest_sig_b64"]),
        genesis_bytes: dec(&rec["genesis_b64"]),
        genesis_sig: dec64(&rec["genesis_sig_b64"]),
        wrapped_dek: wrap_from_bytes(&dec(&mw["wrapped_dek_b64"])),
        grant_bytes: dec(&mw["grant_b64"]),
        grant_sig: dec64(&mw["grant_sig_b64"]),
        ancestor_grants: vec![],
        recovery_grant_bytes: dec(&rg["grant_b64"]),
        recovery_grant_sig: dec64(&rg["grant_sig_b64"]),
        streams: dl_streams,
    }
}

/// Stand up the secret-free app server (MemoryStore + FsBlobStore) under a pinned D5
/// with the given registration keys. Returns `(addr, pinned_d5, dir_signer, blob_dir)`.
async fn spawn_server(
    reg_keys: &[&str],
    server_config: Arc<ServerConfig>,
) -> (
    std::net::SocketAddr,
    [u8; 32],
    DirectorySigner,
    std::path::PathBuf,
) {
    let d5_seed = maxsecu_crypto::random_array::<32>();
    let dir_signer = DirectorySigner::from_seed(&d5_seed);
    let pinned = dir_signer.public_key();

    let blob_dir = std::env::temp_dir().join(format!(
        "mxgdp_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let store = MemoryStore::new();
    for k in reg_keys {
        store.add_reg_key(sha256(k.as_bytes()));
    }
    let state = AppState {
        auth: Arc::new(
            AuthService::new(store, AuthConfig::default().with_directory_pub(pinned))
                .with_dir_signer(Arc::new(SigningKey::from_seed(&d5_seed))),
        ),
        blobs: Arc::new(FsBlobStore::new(&blob_dir)),
        audit: Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, server_config, maxsecu_server::router(state)));
    (addr, pinned, dir_signer, blob_dir)
}

/// Build the author's own-uploads `VerifyContext` (self-wrap). Borrows `owner`.
fn owner_ctx<'a>(owner: &'a Identity, owner_id: [u8; 16], file_id: Id) -> VerifyContext<'a> {
    VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(owner_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    }
}

/// Upload one file through the REAL pipeline (LISTED by default). Returns its
/// freshly-minted `file_id`.
async fn upload_listed(
    c: &mut Conn,
    token: &str,
    owner: &Identity,
    owner_id: [u8; 16],
    recovery_enc: [u8; 32],
    file_type: FileType,
    streams: &PlaintextStreams,
) -> [u8; 16] {
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let bundle = build_upload(
        &UploadParams {
            owner,
            owner_id: Id(owner_id),
            owner_key_version: 1,
            file_id,
            file_type,
            chunk_size: CHUNK,
            recovery_pub: EncPublicKey::from_bytes(recovery_enc),
            recovery_mlkem_pub: None,
            created_at: Timestamp(TS),
        },
        streams,
    )
    .unwrap();
    run_pipeline(
        &mut c.sender,
        "localhost",
        token,
        &bundle,
        |_d, _t| {},
        StageFlags::default(),
    )
    .await
    .unwrap();
    file_id.0
}

fn content_of(opened: &OpenedFile) -> &[u8] {
    &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext
}

fn metadata_of(opened: &OpenedFile) -> &[u8] {
    &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .unwrap()
        .plaintext
}

// ============================================================================
// Test A — generic upload + download byte-identical
// ============================================================================

#[tokio::test]
async fn generic_upload_download_byte_identical() {
    let pki = test_pki();
    let (addr, pinned, dir_signer, blob_dir) =
        spawn_server(&["rk-alice", "rk-recovery"], pki.server_config.clone()).await;
    let _ = pinned;
    let mut c = connect(addr, pki.client_config.clone()).await;

    let owner = Identity::generate();
    let (owner_id, token) = register_and_login(&mut c, &owner, "alice", "rk-alice").await;
    publish_binding(&mut c, &dir_signer, "alice", owner_id, &owner).await;

    let recovery = Identity::generate();
    let (recovery_uid, _rtok) =
        register_and_login(&mut c, &recovery, "recovery-1", "rk-recovery").await;
    publish_binding(&mut c, &dir_signer, "recovery-1", recovery_uid, &recovery).await;
    let recovery_enc = recovery.enc_pub_bytes();

    // A GENERIC (download-only) upload: arbitrary content bytes + generic metadata
    // carrying the original filename. Built + uploaded through the REAL pipeline.
    let original: Vec<u8> = {
        // A payload with NUL + high bytes so a byte-exact assertion has teeth.
        let mut v = Vec::new();
        for i in 0..5000u32 {
            v.push((i.wrapping_mul(31).wrapping_add(7) % 256) as u8);
        }
        v.extend_from_slice(b"\x00\x01\x02\xff\xfe-arbitrary-tail");
        v
    };
    let filename = "quarterly-report.bin";
    let generic_meta =
        maxsecu_client_app::upload::prepare_generic_metadata(filename, "Q3 Report", &["work".to_owned()]);
    let streams = PlaintextStreams {
        content: original.clone(),
        metadata: Some(generic_meta),
        thumbnail: None,
        preview: None,
    };
    let file_id = upload_listed(
        &mut c,
        &token,
        &owner,
        owner_id,
        recovery_enc,
        FileType::Generic,
        &streams,
    )
    .await;
    let fid_hex = hex(&file_id);

    // Fetch + verify + open, then assert the decrypted content is byte-identical.
    let dl = download_bundle(&mut c, &token, &fid_hex).await;
    let opened = verify_and_open(&owner_ctx(&owner, owner_id, Id(file_id)), &dl)
        .expect("generic file verifies + opens");
    assert_eq!(
        content_of(&opened),
        original.as_slice(),
        "generic content round-trips BYTE-IDENTICAL"
    );

    // The metadata JSON carries the original filename.
    let meta_json: serde_json::Value = serde_json::from_slice(metadata_of(&opened)).unwrap();
    assert_eq!(
        meta_json["filename"].as_str(),
        Some(filename),
        "generic metadata carries the original filename"
    );
    assert_eq!(
        meta_json["title"].as_str(),
        Some("Q3 Report"),
        "generic metadata title round-trips"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}

// ============================================================================
// Test B — parallel feed decode via the authed connection pool
// ============================================================================

/// A real authed channel for the pool: a whole TLS connection + its channel-bound
/// session token, reused as ONE unit (the token never leaves its channel). This is
/// the same `{sender, host, token}` unit shape the production `AuthedChannel` pools.
struct RealChannel {
    conn: Conn,
    token: String,
}

/// Mint a fresh authed channel: a NEW TLS connection + a channel-bound login for
/// `alice`. This is the real `reauth`-equivalent — the pool only ever runs it under
/// its internal auth gate (serialized), exactly as production does.
async fn mint_channel(
    addr: std::net::SocketAddr,
    client_config: Arc<ClientConfig>,
    owner: Arc<Identity>,
    mint_count: Arc<AtomicUsize>,
) -> Result<RealChannel, UiError> {
    let mut conn = connect(addr, client_config).await;
    let token = do_login(&mut conn, &owner, "alice").await;
    mint_count.fetch_add(1, Ordering::SeqCst);
    Ok(RealChannel { conn, token })
}

#[tokio::test]
async fn parallel_feed_decode_over_the_pool() {
    const N: usize = 5;

    let pki = test_pki();
    let (addr, pinned, dir_signer, blob_dir) =
        spawn_server(&["rk-alice", "rk-recovery"], pki.server_config.clone()).await;
    let _ = pinned;
    let mut c = connect(addr, pki.client_config.clone()).await;

    let owner = Arc::new(Identity::generate());
    let (owner_id, token) = register_and_login(&mut c, &owner, "alice", "rk-alice").await;
    publish_binding(&mut c, &dir_signer, "alice", owner_id, &owner).await;

    let recovery = Identity::generate();
    let (recovery_uid, _rtok) =
        register_and_login(&mut c, &recovery, "recovery-1", "rk-recovery").await;
    publish_binding(&mut c, &dir_signer, "recovery-1", recovery_uid, &recovery).await;
    let recovery_enc = recovery.enc_pub_bytes();

    // Upload N LISTED blog files with DISTINCT titles. We record (file_id, title) so
    // each concurrent decode can be checked against its EXPECTED title.
    let mut expected: Vec<([u8; 16], String)> = Vec::with_capacity(N);
    for i in 0..N {
        let title = format!("Feed Card {i}");
        let body = format!("body-of-card-{i}-must-round-trip").into_bytes();
        let streams = prepare_blog_streams(body, &title, &[]);
        let fid = upload_listed(
            &mut c,
            &token,
            &owner,
            owner_id,
            recovery_enc,
            FileType::Blog,
            &streams,
        )
        .await;
        expected.push((fid, title));
    }

    // The pool caps live channels at N and hands each concurrent borrower its own
    // channel-bound authed channel — the exact mechanism that lets N feed-card
    // decodes proceed in parallel where per-call `reauth` (one ConnectLock + one
    // identity-take) would serialize them.
    let pool: Arc<AuthedPool<RealChannel>> = Arc::new(AuthedPool::new(N));
    let mint_count = Arc::new(AtomicUsize::new(0));
    // A barrier forces all N channels to be LIVE simultaneously before any read, so
    // the pool genuinely sustains N concurrent authed channels (not one reused
    // serially) — the property per-call reauth cannot provide.
    let barrier = Arc::new(Barrier::new(N));

    let mut handles = Vec::with_capacity(N);
    for (idx, (fid, want_title)) in expected.iter().cloned().enumerate() {
        let pool = pool.clone();
        let client_config = pki.client_config.clone();
        let owner = owner.clone();
        let mint_count = mint_count.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            // Acquire an EXCLUSIVE pooled channel (mints its own authed channel).
            let mut guard = pool
                .acquire(|| mint_channel(addr, client_config, owner.clone(), mint_count))
                .await
                .expect("acquire a pooled authed channel");
            // Hold every channel until all N are live: proves N concurrent channels.
            barrier.wait().await;

            let fid_hex = hex(&fid);
            let tok = guard.token.clone();
            let dl = download_bundle(&mut guard.conn, &tok, &fid_hex).await;
            let opened = verify_and_open(&owner_ctx(&owner, owner_id, Id(fid)), &dl)
                .expect("pooled concurrent read verifies + opens");
            let meta_json: serde_json::Value =
                serde_json::from_slice(metadata_of(&opened)).unwrap();
            let got_title = meta_json["title"].as_str().unwrap().to_owned();
            (idx, want_title, got_title)
        }));
    }

    // Collect: EVERY task must succeed and return its OWN expected title (in the
    // correct correspondence — no cross-talk / identity race across the pool).
    let mut seen = vec![false; N];
    for h in handles {
        let (idx, want, got) = h.await.expect("a concurrent pooled decode task panicked");
        assert_eq!(
            got, want,
            "task {idx}: pooled concurrent decode returned the WRONG title (cross-talk?)"
        );
        seen[idx] = true;
    }
    assert!(
        seen.iter().all(|&s| s),
        "every one of the {N} concurrent pooled decodes completed"
    );
    assert_eq!(
        mint_count.load(Ordering::SeqCst),
        N,
        "the pool minted {N} DISTINCT concurrent authed channels (per-call reauth could sustain only 1)"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}
