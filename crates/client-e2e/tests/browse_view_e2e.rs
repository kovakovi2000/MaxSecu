//! Phase-3 exit-gate end-to-end test (browse + view) over REAL loopback TLS.
//!
//! Stands up the secret-free server (MemoryStore + FsBlobStore) under a pinned
//! ceremony D5, stages an IMAGE and a BLOG out of band (register + login +
//! build_upload + POST /v1/files + PUT chunks + finalize, exactly like
//! `server/tests/file_e2e.rs`), publishes the author's D5-signed binding, then
//! drives the REAL `client-app` browse/view orchestration modules
//! (`download::{parse_file_view, build_stream_header, build_download_bundle}`,
//! `directory::{resolve_and_verify_author, verify_author_binding}`) on top of
//! the `client-core` verify ladder. Asserts the served-interface Phase-3 gates:
//!
//! 1. listing returns the staged files;
//! 2. a header-only CARD open of the image under the pinned D5 recovers the
//!    metadata title + a thumbnail (NO content fetch);
//! 3. a full CONTENT open of the blog returns the exact staged text;
//! 4. a forged author binding is rejected (`untrusted`);
//! 5. a `DownloadBundle` verified against a DIFFERENT requested file_id is
//!    rejected (`FileIdMismatch`) — the integrity property the viewer relies on.

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
use maxsecu_client_app::directory::{resolve_and_verify_author, verify_author_binding};
use maxsecu_client_app::download::{build_download_bundle, build_stream_header, parse_file_view};
use maxsecu_client_core::{
    build_upload, verify_and_open, verify_and_open_headers, DirectoryVerifier, DownloadError,
    Identity, MediaBounds, MemoryTrustStore, PlaintextStreams, RustImageCodec, Transcoder,
    UploadBundle, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{generate_enc_keypair, sha256, SigningKey, WrappedDek};
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{FileType, Id, RecipientType, Role, StreamType, Timestamp};
use maxsecu_encoding::{decode, encode, labels};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const VOUCHER: &str = "in-person-code-001";
const TS: u64 = 1_719_500_000_000;
const IMG_META: &[u8] = br#"{"title":"Sunset","tags":["beach"]}"#;
const BLOG_META: &[u8] = br#"{"title":"My Diary","tags":[]}"#;
const BLOG_BODY: &[u8] = b"Dear diary, this is a Phase-3 blog post that must round-trip exactly.";

// ---- TLS harness (copied verbatim from server/tests/file_e2e.rs) ----

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

/// Wire form of a wrap: `enc(32) ‖ ct` (the server stores opaque bytes).
fn wrap_bytes(w: &WrappedDek) -> Vec<u8> {
    let mut v = w.enc.to_vec();
    v.extend_from_slice(&w.ct);
    v
}

/// Stage one prebuilt upload out of band: POST /v1/files + PUT every chunk +
/// finalize — exactly the sequence in `file_e2e.rs`.
async fn stage(c: &mut Conn, token: &str, file_type: &str, file_id: Id, bundle: &UploadBundle) {
    let fid_hex = hex(&file_id.0);
    let stream_specs: Vec<serde_json::Value> = bundle
        .streams
        .iter()
        .map(|s| {
            serde_json::json!({
                "stream_type": stream_name(s.stream_type),
                "chunk_count": s.chunk_count,
                "chunk_size": s.chunk_size,
                "total_bytes": s.total_bytes,
            })
        })
        .collect();
    let wraps: Vec<serde_json::Value> = bundle
        .wraps
        .iter()
        .map(|w| {
            let rid = if w.recipient_type == RecipientType::Recovery {
                "recovery".to_owned()
            } else {
                hex(&w.recipient_id.0)
            };
            serde_json::json!({
                "recipient_id": rid,
                "recipient_type": if w.recipient_type == RecipientType::Recovery { "recovery" } else { "user" },
                "wrapped_dek_b64": B64.encode(wrap_bytes(&w.wrapped_dek)),
                "wrap_alg": 1,
                "granted_by": hex(&w.granted_by.0),
                "grant_b64": B64.encode(encode(&w.grant)),
                "grant_sig_b64": B64.encode(w.grant_sig),
            })
        })
        .collect();
    let body = serde_json::json!({
        "file_id": fid_hex,
        "file_type": file_type,
        "genesis_b64": B64.encode(encode(&bundle.genesis)),
        "genesis_sig_b64": B64.encode(bundle.genesis_sig),
        "manifest_b64": B64.encode(encode(&bundle.manifest)),
        "manifest_sig_b64": B64.encode(bundle.manifest_sig),
        "streams": stream_specs,
        "wraps": wraps,
    });
    let (st, _res) = post(c, "/v1/files", Some(token), body).await;
    assert_eq!(st, StatusCode::CREATED, "stage {file_type}");

    for s in &bundle.streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            let uri = format!(
                "/v1/files/{fid_hex}/versions/1/streams/{}/chunks/{i}",
                stream_name(s.stream_type)
            );
            assert_eq!(
                put_raw(c, &uri, token, chunk.clone()).await,
                StatusCode::OK,
                "put chunk"
            );
        }
    }
    let (st, _) = post(
        c,
        &format!("/v1/files/{fid_hex}/versions/1/finalize"),
        Some(token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize {file_type}");
}

#[tokio::test]
async fn phase3_browse_view_over_real_tls() {
    // ---- (1) Server + pinned ceremony D5 ----
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();

    let blob_dir = std::env::temp_dir().join(format!(
        "mxbv_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let store = MemoryStore::new();
    store.add_voucher(sha256(VOUCHER.as_bytes()));
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

    // ---- (2) Register + login the author over the bound channel ----
    let owner = Identity::generate();
    let (st, res) = post(
        &mut c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": "alice",
            "enc_pub_b64": B64.encode(owner.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(owner.sig_pub_bytes()),
            "enrollment_voucher": VOUCHER,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS");
    let user_id = hex16(res["user_id"].as_str().unwrap());

    let (_st, ch) = post(
        &mut c,
        "/v1/session/challenge",
        None,
        serde_json::json!({"username":"alice"}),
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
        &mut c,
        "/v1/session/proof",
        None,
        serde_json::json!({"username":"alice","timestamp":TS,"proof_b64":proof}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login over the bound channel");
    let token = res["session_token"].as_str().unwrap().to_owned();

    let (_recovery_sk, recovery_pub) = generate_enc_keypair();

    // ---- (3) Stage the IMAGE out of band (real transcode) ----
    let image_file_id = Id(maxsecu_crypto::random_array::<16>());
    let image_fid_hex = hex(&image_file_id.0);
    let canonical = {
        use image::{DynamicImage, ImageFormat, RgbImage};
        use std::io::Cursor;
        let mut img = RgbImage::new(96, 72);
        for (x, y, px) in img.enumerate_pixels_mut() {
            *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 21]);
        }
        let mut buf = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)
            .unwrap();
        RustImageCodec
            .transcode(&buf, &MediaBounds::default())
            .unwrap()
    };
    assert_eq!(canonical.file_type, FileType::Image);
    let image_streams = canonical.into_plaintext_streams(Some(IMG_META.to_vec()));
    let image_bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id: image_file_id,
            file_type: FileType::Image,
            chunk_size: 4096,
            recovery_pub,
            recovery_mlkem_pub: None,
            created_at: Timestamp(TS),
        },
        &image_streams,
    )
    .unwrap();
    stage(&mut c, &token, "image", image_file_id, &image_bundle).await;

    // ---- (4) Stage the BLOG out of band ----
    let blog_file_id = Id(maxsecu_crypto::random_array::<16>());
    let blog_fid_hex = hex(&blog_file_id.0);
    let blog_streams = PlaintextStreams {
        content: BLOG_BODY.to_vec(),
        metadata: Some(BLOG_META.to_vec()),
        thumbnail: None,
        preview: None,
    };
    let blog_bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id: blog_file_id,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub,
            recovery_mlkem_pub: None,
            created_at: Timestamp(TS),
        },
        &blog_streams,
    )
    .unwrap();
    stage(&mut c, &token, "blog", blog_file_id, &blog_bundle).await;

    // ---- (5) Publish the author's D5-signed binding ----
    let pb = ceremony.sign_binding(
        "alice",
        user_id,
        owner.enc_pub_bytes(),
        owner.sig_pub_bytes(),
        &[Role::User],
        1,
    );
    let (st, _) = post(
        &mut c,
        "/v1/directory",
        None,
        serde_json::json!({
            "binding_b64": B64.encode(&pb.binding_bytes),
            "directory_signature_b64": B64.encode(pb.signature),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "publish author binding");

    // ---- GATE 1: listing returns the staged files ----
    let (st, body) = get_json(&mut c, "/v1/files?limit=50", &token).await;
    assert_eq!(st, StatusCode::OK, "listing");
    assert!(
        body["files"].as_array().unwrap().len() >= 2,
        "both staged files are listed"
    );

    // ---- Common verification context pieces ----
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();

    // ---- GATE 2: header-only CARD open of the image (NO content fetch) ----
    let (st, img_view_json) = get_json(
        &mut c,
        &format!("/v1/files/{image_fid_hex}?version=latest"),
        &token,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "image file view");
    let img_view = parse_file_view(&img_view_json).unwrap();

    let author = resolve_and_verify_author(
        &mut c.sender,
        "localhost",
        &hex(&user_id),
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();
    assert_eq!(
        author.sig_pub,
        owner.sig_pub_bytes(),
        "D5-verified author key"
    );
    assert_eq!(author.enc_pub, owner.enc_pub_bytes());

    let (header, _used_direct) = build_stream_header(
        &mut c.sender,
        "localhost",
        &token,
        &image_fid_hex,
        &img_view,
        maxsecu_client_app::config::RouteMode::PreferServer,
        None,
    )
    .await
    .unwrap();
    let ctx_img = VerifyContext {
        file_id: image_file_id,
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(user_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened = verify_and_open_headers(&ctx_img, &header).unwrap();
    let meta = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .unwrap();
    assert!(
        std::str::from_utf8(&meta.plaintext)
            .unwrap()
            .contains("Sunset"),
        "card metadata title decrypts"
    );
    assert!(
        opened
            .small_streams
            .iter()
            .any(|s| s.stream_type == StreamType::Thumbnail),
        "card has a thumbnail stream"
    );

    // ---- GATE 3: full CONTENT open of the blog returns the exact text ----
    let (st, blog_view_json) = get_json(
        &mut c,
        &format!("/v1/files/{blog_fid_hex}?version=latest"),
        &token,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "blog file view");
    let blog_view = parse_file_view(&blog_view_json).unwrap();
    let (bundle, _used_direct) = build_download_bundle(
        &mut c.sender,
        "localhost",
        &token,
        &blog_fid_hex,
        &blog_view,
        maxsecu_client_app::config::RouteMode::PreferServer,
        None,
    )
    .await
    .unwrap();
    let ctx_blog = VerifyContext {
        file_id: blog_file_id,
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(user_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened_blog = verify_and_open(&ctx_blog, &bundle).unwrap();
    let got_content = &opened_blog
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    assert_eq!(got_content, BLOG_BODY, "blog content round-trips exactly");
    let got_meta = &opened_blog
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .unwrap()
        .plaintext;
    assert!(
        std::str::from_utf8(got_meta).unwrap().contains("My Diary"),
        "blog metadata title decrypts"
    );

    // ---- GATE 4: forged author binding is rejected ----
    let attacker = SigningKey::generate();
    let forged = attacker.sign_canonical(
        labels::DIRBINDING,
        &decode::<DirBinding>(&pb.binding_bytes).unwrap(),
    );
    let mut fresh_trust = MemoryTrustStore::new();
    assert_eq!(
        verify_author_binding(&verifier, &mut fresh_trust, &pb.binding_bytes, &forged, TS)
            .unwrap_err()
            .code,
        "untrusted",
        "a binding signed by a non-D5 key is untrusted"
    );

    // ---- GATE 5: requested-id binding — a substituted record is rejected ----
    let ctx_wrong_id = VerifyContext {
        file_id: Id([0xAB; 16]),
        ..ctx_blog
    };
    assert_eq!(
        verify_and_open(&ctx_wrong_id, &bundle).unwrap_err(),
        DownloadError::FileIdMismatch,
        "a record whose file_id differs from the requested id is rejected"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}
