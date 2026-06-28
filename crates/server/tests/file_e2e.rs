//! Phase-3 exit-gate end-to-end test (DESIGN §17 Phase 3, §12.2/§12.5/§12.10).
//!
//! Drives the **real stack** over loopback TLS: the client (`client-core`)
//! builds a signed, encrypted upload, ships it to the secret-free server
//! (records in `MemoryStore`, ciphertext chunks on a real `FsBlobStore`),
//! finalizes, then fetches everything back and runs the full `verify_and_open`
//! ladder. Proves the served-interface Phase-3 exit gates:
//!
//! - large round-trip: build_upload → stage → chunk PUTs → finalize → GET →
//!   verify_and_open recovers the exact plaintext;
//! - a **spliced** (flipped-byte) and a **truncated** chunk stream are rejected;
//! - a **forged** manifest (bad author signature) is rejected;
//! - a **poisoned near-max version** is rejected (first-contact ceiling);
//! - a **malicious filename** in decrypted metadata cannot traverse the export dir;
//! - **no plaintext on disk**: the server's stored blob bytes are ciphertext only.

use std::path::Path;
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

use maxsecu_client_core::{
    build_upload, decode_rgba_bounded, safe_export_path, validate_decoded, verify_and_open,
    DownloadBundle, DownloadError, Identity, MediaBounds, PlaintextStreams, RustImageCodec,
    StreamChunks, Transcoder, UploadParams, VerifyContext, NO_GRANTERS,
};
use maxsecu_crypto::{generate_enc_keypair, sha256, WrappedDek};
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::{FileType, Id, RecipientType, StreamType, Timestamp};
use maxsecu_encoding::{decode, encode, labels};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, FsColdTier,
    MemoryStore, TieredBlobStore,
};

const VOUCHER: &str = "in-person-code-001";
const TS: u64 = 1_719_500_000_000;
const CONTENT: &[u8] = b"TOPSECRET_PLAINTEXT_MARKER_42_this_must_never_touch_disk_in_clear";
const FILENAME: &[u8] = b"../../etc/passwd"; // malicious metadata (D24)

// ---- TLS harness (mirrors tls_channel_binding.rs) ----

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

/// Wire form of a wrap: `enc(32) ‖ ct` (the server stores opaque bytes).
fn wrap_bytes(w: &WrappedDek) -> Vec<u8> {
    let mut v = w.enc.to_vec();
    v.extend_from_slice(&w.ct);
    v
}
fn wrap_from_bytes(b: &[u8]) -> WrappedDek {
    WrappedDek {
        enc: b[..32].try_into().unwrap(),
        ct: b[32..].to_vec(),
    }
}

#[tokio::test]
async fn phase3_exit_gates_over_real_tls() {
    // ---- Server: secret-free, records in memory, ciphertext blobs on disk ----
    let blob_dir = std::env::temp_dir().join(format!("mxe2e_{}", hex(&maxsecu_crypto::random_array::<8>())));
    let store = MemoryStore::new();
    store.add_voucher(sha256(VOUCHER.as_bytes()));
    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
        blobs: Arc::new(FsBlobStore::new(&blob_dir)),
        audit: Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
    };
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), maxsecu_server::router(state)));

    let mut c = connect(addr, pki.client_config.clone()).await;

    // ---- Client: a real identity registers, then logs in over the bound channel ----
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

    let (_st, ch) = post(&mut c, "/v1/session/challenge", None, serde_json::json!({"username":"alice"})).await;
    let nonce: [u8; 32] = B64.decode(ch["nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap();
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

    // ---- Build the signed, encrypted upload (client-core) ----
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let (_recovery_sk, recovery_pub) = generate_enc_keypair();
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Blog,
        chunk_size: 4096,
        recovery_pub,
        created_at: Timestamp(TS),
    };
    // Content large enough to span multiple chunks (exercises framing/streaming).
    let mut content = Vec::new();
    while content.len() < 4096 * 3 + 100 {
        content.extend_from_slice(CONTENT);
    }
    let streams = PlaintextStreams {
        content: content.clone(),
        metadata: Some(FILENAME.to_vec()),
        thumbnail: None,
        preview: None,
    };
    let bundle = build_upload(&params, &streams).unwrap();

    // ---- Stage (POST /v1/files) ----
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
        "file_id": hex(&file_id.0),
        "file_type": "blog",
        "genesis_b64": B64.encode(encode(&bundle.genesis)),
        "genesis_sig_b64": B64.encode(bundle.genesis_sig),
        "manifest_b64": B64.encode(encode(&bundle.manifest)),
        "manifest_sig_b64": B64.encode(bundle.manifest_sig),
        "streams": stream_specs,
        "wraps": wraps,
    });
    let (st, _res) = post(&mut c, "/v1/files", Some(&token), body).await;
    assert_eq!(st, StatusCode::CREATED, "stage v1");

    // ---- Upload every ciphertext chunk (PUT), then finalize ----
    let fid_hex = hex(&file_id.0);
    for s in &bundle.streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            let uri = format!(
                "/v1/files/{fid_hex}/versions/1/streams/{}/chunks/{i}",
                stream_name(s.stream_type)
            );
            assert_eq!(put_raw(&mut c, &uri, &token, chunk.clone()).await, StatusCode::OK);
        }
    }
    let (st, _) = post(
        &mut c,
        &format!("/v1/files/{fid_hex}/versions/1/finalize"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize after all chunks present");

    // ---- GET the records + chunks back, rebuild a DownloadBundle ----
    let (st, rec) = get_json(&mut c, &format!("/v1/files/{fid_hex}?version=latest"), &token).await;
    assert_eq!(st, StatusCode::OK);
    let mut dl_streams = Vec::new();
    for s in rec["streams"].as_array().unwrap() {
        let st_name = s["stream_type"].as_str().unwrap();
        let count = s["chunk_count"].as_u64().unwrap();
        let mut chunks = Vec::new();
        for i in 0..count {
            let uri = format!("/v1/files/{fid_hex}/versions/1/streams/{st_name}/chunks/{i}");
            let (cs, bytes) = get_raw(&mut c, &uri, &token).await;
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
    let good = DownloadBundle {
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
    };
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(user_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        tombstones: None,
    };

    // GATE — round-trip: the exact plaintext is recovered.
    let opened = verify_and_open(&ctx, &good).expect("round-trips");
    assert_eq!(opened.version, 1);
    assert!(opened.recovery_grant_ok);
    let got_content = &opened.streams.iter().find(|s| s.stream_type == StreamType::Content).unwrap().plaintext;
    assert_eq!(got_content, &content);
    let got_meta = opened.streams.iter().find(|s| s.stream_type == StreamType::Metadata).unwrap().plaintext.clone();
    assert_eq!(got_meta, FILENAME);

    // GATE — malicious filename in decrypted metadata cannot traverse on export.
    let name = String::from_utf8(got_meta).unwrap();
    assert!(
        safe_export_path(Path::new("/exports/alice"), &name).is_err(),
        "a `../../` filename must not resolve outside the export dir"
    );

    // GATE — spliced chunk: flip one byte of the first content chunk. Tamper is
    // caught either by the manifest digest (tag bytes) or the AEAD open (body
    // bytes) — both are fail-closed rejections of the content stream.
    let mut spliced = clone_bundle(&good);
    spliced.streams[0].chunks[0][0] ^= 0x01;
    assert!(matches!(
        verify_and_open(&ctx, &spliced).unwrap_err(),
        DownloadError::StreamDigestMismatch(StreamType::Content)
            | DownloadError::StreamFraming(StreamType::Content)
    ));

    // GATE — truncated stream: drop the last content chunk.
    let mut truncated = clone_bundle(&good);
    truncated.streams[0].chunks.pop();
    assert!(matches!(
        verify_and_open(&ctx, &truncated).unwrap_err(),
        DownloadError::FramingBoundsExceeded(_)
    ));

    // GATE — forged manifest: a bad author signature is rejected.
    let mut forged = clone_bundle(&good);
    forged.manifest_sig[0] ^= 0xFF;
    assert_eq!(verify_and_open(&ctx, &forged).unwrap_err(), DownloadError::ManifestSignature);

    // GATE — poisoned near-max version: re-sign a manifest at v=5_000_000 (above
    // the first-contact ceiling) with the genuine owner key → rejected by freshness.
    let mut poisoned = clone_bundle(&good);
    let mut m: Manifest = decode(&good.manifest_bytes).unwrap();
    m.version = 5_000_000;
    poisoned.manifest_bytes = encode(&m);
    poisoned.manifest_sig = owner.signing_key().sign_canonical(labels::MANIFEST, &m);
    assert_eq!(
        verify_and_open(&ctx, &poisoned).unwrap_err(),
        DownloadError::FirstContactCeiling { served: 5_000_000 }
    );

    // GATE — no plaintext on disk: scan every stored blob file; none contains the
    // content marker (the server only ever holds ciphertext).
    let mut files = 0usize;
    scan_no_plaintext(&blob_dir, CONTENT, &mut files);
    assert!(files > 0, "blobs were actually written to disk");

    let _ = std::fs::remove_dir_all(&blob_dir);
}

/// Phase-4b media exit gates over real TLS: the **real** image transcode →
/// upload across a **tiered** blob store (hot FS cache over an FS cold tier) →
/// download → decode/render; plus no-plaintext-on-either-tier and
/// tampered-cold-blob rejection.
#[tokio::test]
async fn phase4b_media_exit_gates_over_real_tls() {
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;

    const TITLE: &[u8] = b"MEDIA_TITLE_SECRET_MARKER_77";
    const PNG_SIG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    // ---- Server with a two-tier blob store: FS hot cache over an FS cold tier ----
    let tag = hex(&maxsecu_crypto::random_array::<8>());
    let cache_dir = std::env::temp_dir().join(format!("mxmedia_cache_{tag}"));
    let cold_dir = std::env::temp_dir().join(format!("mxmedia_cold_{tag}"));
    let store = MemoryStore::new();
    store.add_voucher(sha256(VOUCHER.as_bytes()));
    let tiered = TieredBlobStore::new(
        Arc::new(FsBlobStore::new(&cache_dir)),
        Arc::new(FsColdTier::new(&cold_dir)),
        64 * 1024 * 1024,
    );
    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
        blobs: Arc::new(tiered),
        audit: Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
    };
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), maxsecu_server::router(state)));
    let mut c = connect(addr, pki.client_config.clone()).await;

    // ---- Register + login ----
    let owner = Identity::generate();
    let (st, res) = post(
        &mut c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": "mira",
            "enc_pub_b64": B64.encode(owner.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(owner.sig_pub_bytes()),
            "enrollment_voucher": VOUCHER,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS");
    let user_id = hex16(res["user_id"].as_str().unwrap());
    let (_st, ch) = post(&mut c, "/v1/session/challenge", None, serde_json::json!({"username":"mira"})).await;
    let nonce: [u8; 32] = B64.decode(ch["nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap();
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
        serde_json::json!({"username":"mira","timestamp":TS,"proof_b64":proof}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login over the bound channel");
    let token = res["session_token"].as_str().unwrap().to_owned();

    // ---- Real transcode: a source JPEG → canonical PNG content + thumb + preview ----
    let src = {
        let mut img = RgbImage::new(96, 72);
        for (x, y, px) in img.enumerate_pixels_mut() {
            *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 21]);
        }
        let mut buf = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)
            .unwrap();
        buf
    };
    let canonical = RustImageCodec.transcode(&src, &MediaBounds::default()).unwrap();
    assert_eq!(canonical.file_type, FileType::Image);
    let canonical_content = canonical.content.clone();
    let streams = canonical.into_plaintext_streams(Some(TITLE.to_vec()));

    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let (_recovery_sk, recovery_pub) = generate_enc_keypair();
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Image,
        chunk_size: 4096,
        recovery_pub,
        created_at: Timestamp(TS),
    };
    let bundle = build_upload(&params, &streams).unwrap();

    // ---- Stage, upload chunks (write-through to BOTH tiers), finalize ----
    let stream_specs: Vec<serde_json::Value> = bundle
        .streams
        .iter()
        .map(|s| serde_json::json!({
            "stream_type": stream_name(s.stream_type),
            "chunk_count": s.chunk_count,
            "chunk_size": s.chunk_size,
            "total_bytes": s.total_bytes,
        }))
        .collect();
    let wraps: Vec<serde_json::Value> = bundle
        .wraps
        .iter()
        .map(|w| {
            let rid = if w.recipient_type == RecipientType::Recovery { "recovery".to_owned() } else { hex(&w.recipient_id.0) };
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
        "file_type": "image",
        "genesis_b64": B64.encode(encode(&bundle.genesis)),
        "genesis_sig_b64": B64.encode(bundle.genesis_sig),
        "manifest_b64": B64.encode(encode(&bundle.manifest)),
        "manifest_sig_b64": B64.encode(bundle.manifest_sig),
        "streams": stream_specs,
        "wraps": wraps,
    });
    let (st, _res) = post(&mut c, "/v1/files", Some(&token), body).await;
    assert_eq!(st, StatusCode::CREATED, "stage media v1");
    for s in &bundle.streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            let uri = format!("/v1/files/{fid_hex}/versions/1/streams/{}/chunks/{i}", stream_name(s.stream_type));
            assert_eq!(put_raw(&mut c, &uri, &token, chunk.clone()).await, StatusCode::OK);
        }
    }
    let (st, _) = post(&mut c, &format!("/v1/files/{fid_hex}/versions/1/finalize"), Some(&token), serde_json::Value::Null).await;
    assert_eq!(st, StatusCode::OK, "finalize media");

    // ---- GET records + chunks, rebuild the bundle ----
    let (st, rec) = get_json(&mut c, &format!("/v1/files/{fid_hex}?version=latest"), &token).await;
    assert_eq!(st, StatusCode::OK);
    let mut dl_streams = Vec::new();
    for s in rec["streams"].as_array().unwrap() {
        let st_name = s["stream_type"].as_str().unwrap();
        let count = s["chunk_count"].as_u64().unwrap();
        let mut chunks = Vec::new();
        for i in 0..count {
            let uri = format!("/v1/files/{fid_hex}/versions/1/streams/{st_name}/chunks/{i}");
            let (cs, bytes) = get_raw(&mut c, &uri, &token).await;
            assert_eq!(cs, StatusCode::OK);
            chunks.push(bytes);
        }
        dl_streams.push(StreamChunks { stream_type: stream_from_name(st_name), chunks });
    }
    let dec = |v: &serde_json::Value| B64.decode(v.as_str().unwrap()).unwrap();
    let dec64 = |v: &serde_json::Value| -> [u8; 64] { dec(v).try_into().unwrap() };
    let mw = &rec["my_wrap"];
    let rg = &rec["recovery_grant"];
    let good = DownloadBundle {
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
    };
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(user_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        tombstones: None,
    };

    // GATE — transcoded media round-trips: content/thumbnail/preview recovered.
    let opened = verify_and_open(&ctx, &good).expect("media round-trips");
    let got_content = &opened.streams.iter().find(|s| s.stream_type == StreamType::Content).unwrap().plaintext;
    assert_eq!(got_content, &canonical_content);
    assert!(opened.streams.iter().any(|s| s.stream_type == StreamType::Thumbnail));
    assert!(opened.streams.iter().any(|s| s.stream_type == StreamType::Preview));

    // GATE — renders: the recovered canonical content decodes to a valid frame,
    // identical to decoding the freshly-transcoded content.
    let frame = decode_rgba_bounded(got_content, &MediaBounds::default()).expect("recovered media renders");
    assert!(validate_decoded(&frame, &MediaBounds::default()).is_ok());
    assert_eq!((frame.width, frame.height), (96, 72));
    let canon_frame = decode_rgba_bounded(&canonical_content, &MediaBounds::default()).unwrap();
    assert_eq!(frame, canon_frame);

    // GATE — no plaintext on EITHER tier: neither the PNG header of any image
    // stream nor the title text appears in any stored blob (cache or cold).
    let mut files = 0usize;
    scan_no_plaintext(&cache_dir, PNG_SIG, &mut files);
    scan_no_plaintext(&cold_dir, PNG_SIG, &mut files);
    scan_no_plaintext(&cache_dir, TITLE, &mut files);
    scan_no_plaintext(&cold_dir, TITLE, &mut files);
    assert!(files > 0, "blobs were actually written to the tiers");

    // GATE — tampered cold blob: corrupt the cold copy of content chunk 0, drop
    // the hot cache so the read MUST come from cold, re-GET, and verify rejects.
    let cold_chunk0 = cold_dir.join(format!("{fid_hex}/1/1/0")); // stream_type Content=1
    let mut cbytes = std::fs::read(&cold_chunk0).expect("cold content chunk on disk");
    cbytes[0] ^= 0x01;
    std::fs::write(&cold_chunk0, &cbytes).unwrap();
    std::fs::remove_dir_all(&cache_dir).unwrap(); // force the next read to hit cold

    let cidx = good.streams.iter().position(|s| s.stream_type == StreamType::Content).unwrap();
    let ccount = good.streams[cidx].chunks.len();
    let mut tampered = clone_bundle(&good);
    let mut new_chunks = Vec::new();
    for i in 0..ccount {
        let uri = format!("/v1/files/{fid_hex}/versions/1/streams/content/chunks/{i}");
        let (cs, b) = get_raw(&mut c, &uri, &token).await;
        assert_eq!(cs, StatusCode::OK);
        new_chunks.push(b);
    }
    tampered.streams[cidx].chunks = new_chunks;
    assert!(matches!(
        verify_and_open(&ctx, &tampered).unwrap_err(),
        DownloadError::StreamDigestMismatch(StreamType::Content)
            | DownloadError::StreamFraming(StreamType::Content)
    ), "a tampered blob served from the cold tier must be rejected");

    let _ = std::fs::remove_dir_all(&cache_dir);
    let _ = std::fs::remove_dir_all(&cold_dir);
}

/// `DownloadBundle` is not `Clone`; rebuild one field-by-field for tampering.
fn clone_bundle(b: &DownloadBundle) -> DownloadBundle {
    DownloadBundle {
        manifest_bytes: b.manifest_bytes.clone(),
        manifest_sig: b.manifest_sig,
        genesis_bytes: b.genesis_bytes.clone(),
        genesis_sig: b.genesis_sig,
        wrapped_dek: b.wrapped_dek.clone(),
        grant_bytes: b.grant_bytes.clone(),
        grant_sig: b.grant_sig,
        ancestor_grants: b.ancestor_grants.clone(),
        recovery_grant_bytes: b.recovery_grant_bytes.clone(),
        recovery_grant_sig: b.recovery_grant_sig,
        streams: b
            .streams
            .iter()
            .map(|s| StreamChunks {
                stream_type: s.stream_type,
                chunks: s.chunks.clone(),
            })
            .collect(),
    }
}

/// Recursively assert no stored blob file contains the plaintext `marker`.
fn scan_no_plaintext(dir: &Path, marker: &[u8], files: &mut usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_no_plaintext(&path, marker, files);
        } else if let Ok(bytes) = std::fs::read(&path) {
            *files += 1;
            assert!(
                !contains_subslice(&bytes, marker),
                "plaintext marker found on disk in {path:?}"
            );
        }
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
