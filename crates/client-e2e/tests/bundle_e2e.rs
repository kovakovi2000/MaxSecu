//! WS9 Task 9.1 exit-gate end-to-end test for the **bundle lifecycle**, over REAL
//! loopback TLS with NO mocked crypto — mirroring the standard of `upload_e2e.rs`
//! and `reshare_e2e.rs`.
//!
//! Stands up the secret-free app server (MemoryStore + FsBlobStore) under a pinned
//! D5 directory root, registers + channel-bound-logs-in an author + a recovery
//! recipient + a second user, then drives the whole bundle lifecycle over the live
//! connection at the crypto+HTTP level and asserts every gate:
//!
//! - GATE 1 (create): 3 MEMBER files (image + blog + generic) upload HIDDEN
//!   (`listed=false`, tagged with the parent `bundle_id`); the signed **bundle**
//!   file (`FileType::Bundle`, `file_id == bundle_id`, content = the ordered
//!   `BundleBody`) uploads LISTED.
//! - GATE 2 (listing hides members): `GET /v1/files` lists the bundle id but NOT
//!   any member id.
//! - GATE 3 (open in signed order): the verified `BundleBody` decoded from the
//!   bundle file's authenticated content stream equals the uploaded members IN
//!   ORDER, and EACH member independently verifies + decrypts to its exact
//!   plaintext.
//! - GATE 4 (member download byte-identical): a member's decrypted content stream
//!   equals the original plaintext bytes.
//! - GATE 5 (reshare cross-user): the owner reshares the bundle file + each member
//!   to a second user; that user then decodes the bundle member list and opens a
//!   member.
//! - GATE 6 (owner delete cascade + no-oracle): a NON-owner `DELETE` of the bundle
//!   → 404 (no oracle) and the file survives; then the owner `DELETE` → 204,
//!   after which `GET /v1/files` no longer lists the bundle AND a direct `GET` of
//!   every member id 404s (cascade + blob purge).
//!
//! ## Why the flow is reconstructed rather than calling the Tauri commands
//! `confirm_bundle` / `open_bundle` / `reshare_bundle` / `delete_content` are
//! `#[tauri::command]`s that take Tauri `State`/`AppHandle` (bound to the concrete
//! `Wry` runtime — not constructible headless), and their orchestration is
//! `pub(crate)`, so an external test crate cannot reach them. Exactly as
//! `upload_e2e.rs` reconstructs the upload pipeline and `reshare_e2e.rs`
//! reconstructs the reshare loop from public primitives, this suite reconstructs
//! the bundle lifecycle from the SAME public product code (`build_upload`,
//! `run_pipeline` with the member `StageFlags`, `verify_and_open`, `build_reshare`,
//! `resolve_recipient`, the canonical `BundleBody` codec) over real transport and
//! real crypto. No verification is weakened: member ids/order come only from the
//! SIGNED bundle content, and each member is re-verified by its signed id.

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

use maxsecu_admin_core::DirectorySigner;
use maxsecu_client_app::directory::resolve_recipient;
use maxsecu_client_app::upload::{
    prepare_blog_streams, prepare_image_streams, run_pipeline, StageFlags,
};
use maxsecu_client_core::{
    build_reshare, build_upload, verify_and_open, DirectoryVerifier, DownloadBundle, Identity,
    MemoryTrustStore, PlaintextStreams, ReshareParams, StreamChunks, TombstoneSet, UploadParams,
    VerifyContext, WrapOut, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{sha256, unwrap_dek, Dek, EncPublicKey, SigningKey, WrappedDek};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{
    BundleBody, BundleMember, DirBinding, Grant, Manifest, WrapContext,
};
use maxsecu_encoding::types::{
    Bytes32, FileType, Id, RecipientType, Role, RoleSet, StreamType, Suite, Text, Timestamp,
};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const TS: u64 = 1_719_500_000_000;
const FAR_FUTURE_MS: u64 = 4_102_444_800_000;
const CHUNK: u32 = 4096;

const BLOG_BODY: &[u8] = b"Dear diary, a bundled blog member that must round-trip exactly.";

// ============================================================================
// TLS + HTTP harness (copied from upload_e2e.rs / reshare_e2e.rs)
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
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

/// `DELETE /v1/files/{id}` over the harness; returns just the status.
async fn delete_file(conn: &mut Conn, uri: &str, auth: &str) -> StatusCode {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    conn.sender.send_request(req).await.unwrap().status()
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
    (user_id, res["session_token"].as_str().unwrap().to_owned())
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

/// GET the file view + every chunk back and rebuild a `DownloadBundle` — mirrors
/// the rebuild in upload_e2e.rs / reshare_e2e.rs. The `auth` token decides WHOSE
/// `my_wrap` (self-wrap or a reshared wrap) the view carries.
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

fn gen_png() -> Vec<u8> {
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;
    let mut img = RgbImage::new(96, 72);
    for (x, y, px) in img.enumerate_pixels_mut() {
        *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 21]);
    }
    let mut buf = Vec::new();
    DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

/// The `POST /v1/files/{id}/wraps` body — byte-identical to `share.rs::wrap_req_body`
/// (copied from reshare_e2e.rs).
fn wrap_body(w: &WrapOut) -> serde_json::Value {
    let mut wire = w.wrapped_dek.enc.to_vec();
    wire.extend_from_slice(&w.wrapped_dek.ct);
    serde_json::json!({
        "recipient_id": hex(&w.recipient_id.0),
        "recipient_type": "user",
        "wrapped_dek_b64": B64.encode(&wire),
        "wrap_alg": 1,
        "granted_by": hex(&w.granted_by.0),
        "grant_b64": B64.encode(maxsecu_encoding::encode::<Grant>(&w.grant)),
        "grant_sig_b64": B64.encode(w.grant_sig),
    })
}

/// A member upload: build the crypto bundle for `(file_type, streams)` and drive
/// the REAL `run_pipeline` HIDDEN under `bundle_id` (`listed=false`) — the exact
/// member-flags path `confirm_bundle` uses. Returns the freshly-minted `file_id`.
#[allow(clippy::too_many_arguments)]
async fn upload_member(
    c: &mut Conn,
    token: &str,
    owner: &Identity,
    owner_id: [u8; 16],
    recovery_enc: [u8; 32],
    bundle_id: [u8; 16],
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
        StageFlags {
            listed: false,
            bundle_id: Some(bundle_id),
        },
    )
    .await
    .unwrap();
    file_id.0
}

/// Recover the DEK from an owner's OWN self-wrapped download bundle (Suite::V1),
/// mirroring `download.rs::recover_own_dek`. The reshare possession precondition.
fn recover_own_dek(dl: &DownloadBundle, owner: &Identity, owner_id: [u8; 16]) -> Dek {
    let manifest: Manifest = maxsecu_encoding::decode(&dl.manifest_bytes).unwrap();
    assert_eq!(manifest.alg, Suite::V1, "classical recovery → V1 file");
    let ctx = WrapContext {
        file_id: manifest.file_id,
        version: manifest.version,
        recipient_id: Id(owner_id),
    };
    let dek = unwrap_dek(owner.enc_secret(), &dl.wrapped_dek, &ctx).unwrap();
    assert_eq!(
        dek.commit(),
        manifest.dek_commit.0,
        "recovered DEK opens to commitment"
    );
    dek
}

/// Reshare one already-uploaded file to `recipient` and assert the wrap POST 201s.
#[allow(clippy::too_many_arguments)]
async fn reshare_to(
    c: &mut Conn,
    owner_token: &str,
    owner: &Identity,
    owner_id: [u8; 16],
    file_id: [u8; 16],
    dek: &Dek,
    pinned: [u8; 32],
    recipient_username: &str,
) {
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let author = resolve_recipient(
        &mut c.sender,
        "localhost",
        recipient_username,
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .expect("recipient resolves under the pinned D5");
    let empty = TombstoneSet::verify(&[], maxsecu_encoding::GENESIS_HEAD.0).unwrap();
    let params = ReshareParams {
        granter: owner,
        granter_id: Id(owner_id),
        file_id: Id(file_id),
        version: 1,
        dek_commit: dek.commit(),
        recipient_id: Id(author.user_id),
        recipient_enc_pub: EncPublicKey::from_bytes(author.enc_pub),
        suite: Suite::V1,
        recipient_mlkem_pub: author.mlkem_pub,
        created_at: Timestamp(TS),
    };
    let w = build_reshare(&params, dek, &empty).expect("build_reshare");
    let (st, _) = post(
        c,
        &format!("/v1/files/{}/wraps", hex(&file_id)),
        Some(owner_token),
        wrap_body(&w),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "reshare wrap POST for {recipient_username}");
}

#[tokio::test]
async fn bundle_lifecycle_over_real_tls() {
    // ---- Server + pinned ceremony D5 (server holds the private half so
    // registration-key enrollment can sign bindings; the same seed signs the
    // published bindings, verifying under the pinned pubkey) ----
    let d5_seed = maxsecu_crypto::random_array::<32>();
    let dir_signer = DirectorySigner::from_seed(&d5_seed);
    let pinned = dir_signer.public_key();

    let blob_dir = std::env::temp_dir().join(format!(
        "mxbundle_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let store = MemoryStore::new();
    for k in ["rk-alice", "rk-recovery", "rk-bob"] {
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
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        pki.server_config.clone(),
        maxsecu_server::router(state),
    ));
    let mut c = connect(addr, pki.client_config.clone()).await;

    // ---- Author + recovery recipient + a second user, all published ----
    let owner = Identity::generate();
    let (owner_id, token) = register_and_login(&mut c, &owner, "alice", "rk-alice").await;
    publish_binding(&mut c, &dir_signer, "alice", owner_id, &owner).await;

    let recovery = Identity::generate();
    let (recovery_uid, _rtok) =
        register_and_login(&mut c, &recovery, "recovery-1", "rk-recovery").await;
    publish_binding(&mut c, &dir_signer, "recovery-1", recovery_uid, &recovery).await;
    let recovery_enc = recovery.enc_pub_bytes();

    let bob = Identity::generate();
    let (bob_id, bob_token) = register_and_login(&mut c, &bob, "bob", "rk-bob").await;
    publish_binding(&mut c, &dir_signer, "bob", bob_id, &bob).await;

    let owner_sig_pub = owner.sig_pub_bytes();
    // Owner opens its own uploads (self-wrap).
    let owner_ctx = |file_id: Id| VerifyContext {
        file_id,
        author_sig_pub: owner_sig_pub,
        owner_sig_pub,
        recipient_id: Id(owner_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };

    // ======================================================================
    // GATE 1 — create the bundle: 3 hidden members + the listed bundle file
    // ======================================================================
    let bundle_id = maxsecu_crypto::random_array::<16>();

    // Member 1: IMAGE.
    let png = gen_png();
    let (img_type, img_streams) =
        prepare_image_streams(&png, "Bundle Image", &["beach".to_owned()]).unwrap();
    assert_eq!(img_type, FileType::Image);
    let img_content = img_streams.content.clone();
    let img_id = upload_member(
        &mut c, &token, &owner, owner_id, recovery_enc, bundle_id, img_type, &img_streams,
    )
    .await;

    // Member 2: BLOG.
    let blog_streams = prepare_blog_streams(BLOG_BODY.to_vec(), "Bundle Blog", &[]);
    let blog_id = upload_member(
        &mut c,
        &token,
        &owner,
        owner_id,
        recovery_enc,
        bundle_id,
        FileType::Blog,
        &blog_streams,
    )
    .await;

    // Member 3: GENERIC (download-only) — a plain content+metadata stream pair, the
    // crypto-level equivalent of the disk-backed generic upload path.
    let generic_content = b"generic-download-payload-\x00\x01\x02-arbitrary-bytes".to_vec();
    let generic_meta =
        maxsecu_client_app::upload::prepare_generic_metadata("report.bin", "Bundle File", &[]);
    let generic_streams = PlaintextStreams {
        content: generic_content.clone(),
        metadata: Some(generic_meta),
        thumbnail: None,
        preview: None,
    };
    let generic_id = upload_member(
        &mut c,
        &token,
        &owner,
        owner_id,
        recovery_enc,
        bundle_id,
        FileType::Generic,
        &generic_streams,
    )
    .await;

    // The authoritative, ORDERED member list (image, blog, generic).
    let member_order: Vec<(Id, FileType)> = vec![
        (Id(img_id), FileType::Image),
        (Id(blog_id), FileType::Blog),
        (Id(generic_id), FileType::Generic),
    ];

    // The signed bundle file: file_id == bundle_id, content == encoded BundleBody.
    let bundle_content = maxsecu_encoding::encode(&BundleBody {
        members: member_order
            .iter()
            .map(|(id, ft)| BundleMember {
                file_id: *id,
                file_type: *ft,
            })
            .collect(),
    });
    let bundle_streams = PlaintextStreams {
        content: bundle_content.clone(),
        metadata: Some(prepare_blog_streams(vec![], "My Bundle", &["trip".to_owned()]).metadata.unwrap()),
        thumbnail: None,
        preview: None,
    };
    let bundle_upload = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(owner_id),
            owner_key_version: 1,
            file_id: Id(bundle_id),
            file_type: FileType::Bundle,
            chunk_size: CHUNK,
            recovery_pub: EncPublicKey::from_bytes(recovery_enc),
            recovery_mlkem_pub: None,
            created_at: Timestamp(TS),
        },
        &bundle_streams,
    )
    .unwrap();
    run_pipeline(
        &mut c.sender,
        "localhost",
        &token,
        &bundle_upload,
        |_d, _t| {},
        StageFlags::default(),
    )
    .await
    .unwrap();
    let bundle_hex = hex(&bundle_id);

    // ======================================================================
    // GATE 2 — the listing lists the bundle but HIDES every member
    // ======================================================================
    let (st, list) = get_json(&mut c, "/v1/files?limit=200", &token).await;
    assert_eq!(st, StatusCode::OK, "GATE 2: listing");
    let listed_ids: Vec<String> = list["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["file_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        listed_ids.contains(&bundle_hex),
        "GATE 2: the bundle file IS listed: {listed_ids:?}"
    );
    for (id, _) in &member_order {
        assert!(
            !listed_ids.contains(&hex(&id.0)),
            "GATE 2: member {} must be hidden from the listing",
            hex(&id.0)
        );
    }

    // ======================================================================
    // GATE 3 — open_bundle returns the verified member list IN SIGNED ORDER,
    //          and every member independently verifies + decrypts
    // ======================================================================
    let bundle_dl = download_bundle(&mut c, &token, &bundle_hex).await;
    let opened_bundle = verify_and_open(&owner_ctx(Id(bundle_id)), &bundle_dl)
        .expect("GATE 3: bundle file verifies + opens");
    let opened_content = &opened_bundle
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    // The member list comes ONLY from the SIGNED content stream — never a listing.
    let body: BundleBody = maxsecu_encoding::decode(opened_content).unwrap();
    let got_order: Vec<(Id, FileType)> =
        body.members.iter().map(|m| (m.file_id, m.file_type)).collect();
    assert_eq!(
        got_order, member_order,
        "GATE 3: verified members equal the uploaded members IN ORDER"
    );

    // Each member opens by its SIGNED id and decrypts to the exact plaintext.
    let expected_content: [&[u8]; 3] = [&img_content, BLOG_BODY, &generic_content];
    for ((id, _ft), expect) in member_order.iter().zip(expected_content.iter()) {
        let mdl = download_bundle(&mut c, &token, &hex(&id.0)).await;
        let opened = verify_and_open(&owner_ctx(*id), &mdl)
            .unwrap_or_else(|e| panic!("GATE 3: member {} opens: {e:?}", hex(&id.0)));
        let content = &opened
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap()
            .plaintext;
        assert_eq!(
            content, expect,
            "GATE 3: member {} content round-trips exactly",
            hex(&id.0)
        );
    }

    // ======================================================================
    // GATE 4 — member download is byte-identical to the original plaintext
    // ======================================================================
    let blog_dl = download_bundle(&mut c, &token, &hex(&blog_id)).await;
    let opened_blog =
        verify_and_open(&owner_ctx(Id(blog_id)), &blog_dl).expect("GATE 4: blog opens");
    let blog_out = &opened_blog
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    let tmp = blob_dir.join("member_download.bin");
    std::fs::create_dir_all(&blob_dir).ok();
    std::fs::write(&tmp, blog_out).unwrap();
    let read_back = std::fs::read(&tmp).unwrap();
    assert_eq!(
        read_back, BLOG_BODY,
        "GATE 4: downloaded member bytes equal the original plaintext"
    );

    // ======================================================================
    // GATE 5 — reshare the bundle + members cross-user; user2 opens both
    // ======================================================================
    // Recover the DEK of the bundle and each member from the owner's self-wraps,
    // then reshare to bob.
    let bundle_dek = recover_own_dek(&bundle_dl, &owner, owner_id);
    reshare_to(
        &mut c, &token, &owner, owner_id, bundle_id, &bundle_dek, pinned, "bob",
    )
    .await;
    for (id, _) in &member_order {
        let mdl = download_bundle(&mut c, &token, &hex(&id.0)).await;
        let dek = recover_own_dek(&mdl, &owner, owner_id);
        reshare_to(&mut c, &token, &owner, owner_id, id.0, &dek, pinned, "bob").await;
    }

    // Bob decodes the bundle member list from HIS reshared wrap …
    let bob_bundle_dl = download_bundle(&mut c, &bob_token, &bundle_hex).await;
    let bob_ctx = |file_id: Id| VerifyContext {
        file_id,
        author_sig_pub: owner_sig_pub,
        owner_sig_pub,
        recipient_id: Id(bob_id),
        recipient_type: RecipientType::User,
        recipient_secret: bob.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let bob_opened_bundle = verify_and_open(&bob_ctx(Id(bundle_id)), &bob_bundle_dl)
        .expect("GATE 5: bob opens the reshared bundle file");
    let bob_body: BundleBody = maxsecu_encoding::decode(
        &bob_opened_bundle
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap()
            .plaintext,
    )
    .unwrap();
    assert_eq!(
        bob_body
            .members
            .iter()
            .map(|m| (m.file_id, m.file_type))
            .collect::<Vec<_>>(),
        member_order,
        "GATE 5: bob's decoded member list matches, in order"
    );

    // … and opens a member (the image) via his reshared wrap.
    let bob_img_dl = download_bundle(&mut c, &bob_token, &hex(&img_id)).await;
    let bob_img = verify_and_open(&bob_ctx(Id(img_id)), &bob_img_dl)
        .expect("GATE 5: bob opens a reshared member");
    let bob_img_content = &bob_img
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    assert_eq!(
        bob_img_content, &img_content,
        "GATE 5: bob's reshared member content round-trips exactly"
    );

    // ======================================================================
    // GATE 6 — non-owner delete is a no-oracle 404; owner delete cascades
    // ======================================================================
    // 6a: bob (a recipient, NOT the owner) tries to delete the bundle → 404, and
    // the file survives (the owner can still fetch it).
    let bob_delete = delete_file(&mut c, &format!("/v1/files/{bundle_hex}"), &bob_token).await;
    assert_eq!(
        bob_delete,
        StatusCode::NOT_FOUND,
        "GATE 6a: a non-owner delete is a no-oracle 404"
    );
    let (st, _) = get_json(&mut c, &format!("/v1/files/{bundle_hex}?version=latest"), &token).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "GATE 6a: the bundle survives a non-owner delete attempt"
    );

    // 6b: the owner deletes the bundle → 204; the cascade removes the bundle AND
    // every member (blob purge). The listing no longer shows the bundle, and a
    // direct GET of each member id 404s.
    let owner_delete = delete_file(&mut c, &format!("/v1/files/{bundle_hex}"), &token).await;
    assert_eq!(
        owner_delete,
        StatusCode::NO_CONTENT,
        "GATE 6b: the owner delete succeeds"
    );

    let (st, list) = get_json(&mut c, "/v1/files?limit=200", &token).await;
    assert_eq!(st, StatusCode::OK);
    let after: Vec<String> = list["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["file_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        !after.contains(&bundle_hex),
        "GATE 6b: the deleted bundle is no longer listed: {after:?}"
    );
    for (id, _) in &member_order {
        let (st, _) =
            get_json(&mut c, &format!("/v1/files/{}?version=latest", hex(&id.0)), &token).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "GATE 6b: member {} was cascade-deleted (404)",
            hex(&id.0)
        );
    }

    let _ = std::fs::remove_dir_all(&blob_dir);
}
