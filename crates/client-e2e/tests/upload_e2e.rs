//! Phase-4 exit-gate end-to-end test (client upload) over REAL loopback TLS.
//!
//! Stands up the secret-free server (MemoryStore + FsBlobStore) under a pinned
//! ceremony D5, registers + channel-bound-logs-in an author, and publishes the
//! author's + a recovery recipient's D5-signed bindings. Then it drives the
//! **real** `client-app` upload modules
//! (`upload::{prepare_image_streams, prepare_blog_streams, run_pipeline}`,
//! `directory::resolve_recovery_recipient`) over the live connection, fetches
//! everything back, and runs the full `verify_and_open` ladder to prove the
//! exact plaintext round-trips. Asserts the Phase-4 gates:
//!
//! - GATE E: the recovery recipient resolves + D5-verifies under the pinned root;
//! - GATE A: an IMAGE upload driven by the real pipeline round-trips (content +
//!   metadata title);
//! - GATE B: a BLOG upload round-trips byte-exactly (+ metadata title);
//! - GATE C: the served file view carries a non-null `recovery_grant` (the
//!   pipeline wrapped to the recovery recipient);
//! - GATE D: the server's completeness gate rejects a premature finalize (400),
//!   a re-PUT of an already-uploaded chunk is idempotent (200), and finalize
//!   succeeds once the last chunk lands (200) — i.e. resume-safe.

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

use maxsecu_ceremony_harness::Ceremony;
use maxsecu_client_app::directory::resolve_recovery_recipient;
use maxsecu_client_core::{
    build_upload, verify_and_open, DirectoryVerifier, DownloadBundle, Identity, MemoryTrustStore,
    StreamChunks, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey, WrappedDek};
use maxsecu_encoding::labels;
use maxsecu_encoding::types::{FileType, Id, Role, StreamType, Timestamp};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const VOUCHER: &str = "in-person-code-001";
const VOUCHER2: &str = "in-person-code-002";
const TS: u64 = 1_719_500_000_000;
const BLOG_BODY: &[u8] = b"Dear diary, a Phase-4 upload that must round-trip exactly.";

// ---- TLS harness (copied from server/tests/file_e2e.rs) ----

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

async fn put_raw(conn: &mut Conn, uri: &str, auth: &str, body: Vec<u8>) -> StatusCode {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    conn.sender.send_request(req).await.unwrap().status()
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

fn stream_name(st: StreamType) -> &'static str {
    match st {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
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
    voucher: &str,
) -> ([u8; 16], String) {
    let (st, res) = post(
        c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(owner.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(owner.sig_pub_bytes()),
            "enrollment_voucher": voucher,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS");
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
        use maxsecu_encoding::types::{Bytes32, Text};
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
    assert_eq!(st, StatusCode::OK, "login over the bound channel");
    (user_id, res["session_token"].as_str().unwrap().to_owned())
}

/// Publish a D5-signed binding for `(username, user_id, identity)`.
async fn publish_binding(
    c: &mut Conn,
    ceremony: &Ceremony,
    username: &str,
    uid: [u8; 16],
    id: &Identity,
) {
    let pb = ceremony.sign_binding(
        username,
        uid,
        id.enc_pub_bytes(),
        id.sig_pub_bytes(),
        &[Role::User],
        1,
    );
    let (st, _) = post(
        c,
        "/v1/directory",
        None,
        serde_json::json!({
            "binding_b64": B64.encode(&pb.binding_bytes),
            "directory_signature_b64": B64.encode(pb.signature),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "publish binding {username}");
}

/// GET the file view + every chunk back and rebuild a `DownloadBundle` (mirrors
/// the rebuild in file_e2e.rs / browse_view_e2e.rs).
async fn download_bundle(c: &mut Conn, token: &str, fid_hex: &str) -> DownloadBundle {
    let (st, rec) = get_json(c, &format!("/v1/files/{fid_hex}?version=latest"), token).await;
    assert_eq!(st, StatusCode::OK, "file view");
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

#[tokio::test]
async fn phase4_upload_over_real_tls() {
    // ---- (1) Server + pinned ceremony D5 ----
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();

    let blob_dir = std::env::temp_dir().join(format!(
        "mxupload_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let store = MemoryStore::new();
    store.add_voucher(sha256(VOUCHER.as_bytes()));
    store.add_voucher(sha256(VOUCHER2.as_bytes()));
    let state = AppState {
        auth: Arc::new(AuthService::new(
            store,
            AuthConfig::default().with_directory_pub(pinned),
        )),
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

    // ---- (2) Register + login the author; publish author + recovery bindings ----
    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", VOUCHER).await;
    publish_binding(&mut c, &ceremony, "alice", user_id, &owner).await;

    // The recovery recipient is a real registered user (so the username→user_id
    // directory lookup resolves), with its own D5-signed binding.
    let recovery = Identity::generate();
    let (recovery_uid, _recovery_token) =
        register_and_login(&mut c, &recovery, "recovery-1", VOUCHER2).await;
    publish_binding(&mut c, &ceremony, "recovery-1", recovery_uid, &recovery).await;

    let owner_sig_pub = owner.sig_pub_bytes();

    // ---- GATE E: recovery recipient resolves + D5-verifies under the pinned root ----
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let rr = resolve_recovery_recipient(
        &mut c.sender,
        "localhost",
        "recovery-1",
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();
    assert_eq!(
        rr.enc_pub,
        recovery.enc_pub_bytes(),
        "GATE E: D5-verified recovery enc key"
    );

    // A reusable VerifyContext builder for the author opening its own uploads.
    let make_ctx = |file_id: Id| VerifyContext {
        file_id,
        author_sig_pub: owner_sig_pub,
        owner_sig_pub,
        recipient_id: Id(user_id),
        recipient_type: maxsecu_encoding::types::RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };

    // ---- GATE A: IMAGE upload round-trips via the REAL pipeline ----
    let src_png = {
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
    };
    let (file_type, image_streams) = maxsecu_client_app::upload::prepare_image_streams(
        &src_png,
        "Sunset",
        &["beach".to_owned()],
    )
    .unwrap();
    assert_eq!(file_type, FileType::Image);
    // The canonical content the pipeline will encrypt (for an exact round-trip check).
    let image_canonical_content = image_streams.content.clone();

    let image_file_id = Id(maxsecu_crypto::random_array::<16>());
    let image_fid_hex = hex(&image_file_id.0);
    let image_bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id: image_file_id,
            file_type,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
            recovery_mlkem_pub: rr.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &image_streams,
    )
    .unwrap();
    maxsecu_client_app::upload::run_pipeline(
        &mut c.sender,
        "localhost",
        &token,
        &image_bundle,
        |_d, _t| {},
    )
    .await
    .unwrap();

    let image_dl = download_bundle(&mut c, &token, &image_fid_hex).await;
    let ctx_img = make_ctx(image_file_id);
    let opened_img = verify_and_open(&ctx_img, &image_dl).expect("GATE A: image round-trips");
    let got_img_content = &opened_img
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    assert_eq!(
        got_img_content, &image_canonical_content,
        "GATE A: canonical image content round-trips exactly"
    );
    let got_img_meta = &opened_img
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .unwrap()
        .plaintext;
    assert!(
        std::str::from_utf8(got_img_meta)
            .unwrap()
            .contains("Sunset"),
        "GATE A: image metadata title decrypts"
    );
    assert!(
        opened_img.recovery_grant_ok,
        "GATE A: recovery grant verifies"
    );

    // ---- GATE B: BLOG upload round-trips byte-exactly via the REAL pipeline ----
    let blog_streams =
        maxsecu_client_app::upload::prepare_blog_streams(BLOG_BODY.to_vec(), "My Diary", &[]);
    let blog_file_id = Id(maxsecu_crypto::random_array::<16>());
    let blog_fid_hex = hex(&blog_file_id.0);
    let blog_bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id: blog_file_id,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
            recovery_mlkem_pub: rr.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &blog_streams,
    )
    .unwrap();
    maxsecu_client_app::upload::run_pipeline(
        &mut c.sender,
        "localhost",
        &token,
        &blog_bundle,
        |_d, _t| {},
    )
    .await
    .unwrap();

    let blog_dl = download_bundle(&mut c, &token, &blog_fid_hex).await;
    let ctx_blog = make_ctx(blog_file_id);
    let opened_blog = verify_and_open(&ctx_blog, &blog_dl).expect("GATE B: blog round-trips");
    let got_blog_content = &opened_blog
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    assert_eq!(
        got_blog_content, BLOG_BODY,
        "GATE B: blog content round-trips byte-exactly"
    );
    let got_blog_meta = &opened_blog
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .unwrap()
        .plaintext;
    assert!(
        std::str::from_utf8(got_blog_meta)
            .unwrap()
            .contains("My Diary"),
        "GATE B: blog metadata title decrypts"
    );

    // ---- GATE C: the served file view carries a non-null recovery_grant ----
    let (st, blog_view) = get_json(
        &mut c,
        &format!("/v1/files/{blog_fid_hex}?version=latest"),
        &token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !blog_view["recovery_grant"].is_null(),
        "GATE C: the upload wrapped to the recovery recipient"
    );

    // ---- GATE D: completeness gate (400) + idempotent resume (200) ----
    // Stage a THIRD file manually: a multi-chunk blog so we can hold back the
    // last chunk. Drive the raw endpoints via the test harness.
    let mut big_content = Vec::new();
    while big_content.len() < 4096 * 3 + 100 {
        big_content.extend_from_slice(BLOG_BODY);
    }
    let resume_streams = maxsecu_client_app::upload::prepare_blog_streams(
        big_content.clone(),
        "Resume",
        &["d".to_owned()],
    );
    let resume_file_id = Id(maxsecu_crypto::random_array::<16>());
    let resume_fid_hex = hex(&resume_file_id.0);
    let resume_bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id: resume_file_id,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
            recovery_mlkem_pub: rr.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &resume_streams,
    )
    .unwrap();

    // Stage with the REAL shaping helper.
    let (st, _res) = post(
        &mut c,
        "/v1/files",
        Some(&token),
        maxsecu_client_app::upload::stage_body(&resume_bundle),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "GATE D: stage the resume file");

    // Flat (stream, index, chunk) list across all streams.
    let mut all_chunks: Vec<(StreamType, u64, Vec<u8>)> = Vec::new();
    for s in &resume_bundle.streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            all_chunks.push((s.stream_type, i as u64, chunk.clone()));
        }
    }
    assert!(
        all_chunks.len() >= 2,
        "GATE D: need a multi-chunk upload to hold back the last chunk"
    );

    // PUT every chunk EXCEPT the last one.
    let last = all_chunks.len() - 1;
    for (stype, idx, chunk) in &all_chunks[..last] {
        let uri = format!(
            "/v1/files/{resume_fid_hex}/versions/1/streams/{}/chunks/{idx}",
            stream_name(*stype)
        );
        assert_eq!(
            put_raw(&mut c, &uri, &token, chunk.clone()).await,
            StatusCode::OK,
            "GATE D: PUT chunk before the last"
        );
    }

    // Premature finalize → 400 (server's completeness gate).
    let (st, _) = post(
        &mut c,
        &format!("/v1/files/{resume_fid_hex}/versions/1/finalize"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "GATE D: finalize with a missing chunk is rejected (incomplete)"
    );

    // Idempotent resume: re-PUT an already-uploaded chunk (index 0) → 200.
    {
        let (stype, idx, chunk) = &all_chunks[0];
        let uri = format!(
            "/v1/files/{resume_fid_hex}/versions/1/streams/{}/chunks/{idx}",
            stream_name(*stype)
        );
        assert_eq!(
            put_raw(&mut c, &uri, &token, chunk.clone()).await,
            StatusCode::OK,
            "GATE D: re-PUT of an already-uploaded chunk is idempotent"
        );
    }

    // PUT the missing last chunk → 200, then finalize → 200 (resume-safe).
    {
        let (stype, idx, chunk) = &all_chunks[last];
        let uri = format!(
            "/v1/files/{resume_fid_hex}/versions/1/streams/{}/chunks/{idx}",
            stream_name(*stype)
        );
        assert_eq!(
            put_raw(&mut c, &uri, &token, chunk.clone()).await,
            StatusCode::OK,
            "GATE D: PUT the final missing chunk"
        );
    }
    let (st, _) = post(
        &mut c,
        &format!("/v1/files/{resume_fid_hex}/versions/1/finalize"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "GATE D: finalize succeeds once every chunk is present"
    );

    // Sanity: the resumed file also round-trips exactly.
    let resume_dl = download_bundle(&mut c, &token, &resume_fid_hex).await;
    let ctx_resume = make_ctx(resume_file_id);
    let opened_resume =
        verify_and_open(&ctx_resume, &resume_dl).expect("GATE D: resumed file round-trips");
    let got_resume = &opened_resume
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    assert_eq!(
        got_resume, &big_content,
        "GATE D: the resumed upload round-trips exactly"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}
