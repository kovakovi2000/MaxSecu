//! Streaming-upload end-to-end test over real in-process TLS (no ffmpeg / no
//! transcode worker — synthetic multi-6-MiB-chunk content throughout).
//!
//! Three scenarios:
//!
//! (A) `streaming_upload_download_roundtrips_over_tls` — full streaming upload
//!     (StreamingUploadBuilder → seal_from_reader → POST + PUT chunks + finalize)
//!     followed by a download + decrypt round-trip; asserts the recovered
//!     plaintext equals the original synthetic content byte-exactly.
//!
//! (B) `interrupted_streaming_upload_resumes_to_completion` — PUT only the first
//!     content chunk, then resume via `resume_content_sealer` + `seal_chunk` for
//!     the remaining chunks, finalize, and round-trip verify.
//!
//! (C) `discard_removes_never_finalized_upload` — POST /v1/files + PUT one content
//!     chunk (no finalize), DELETE /v1/files/{id} → 204, GET → 404.
//!
//! All three exercise the 6 MiB chunk PUT body limit validated by the streaming
//! large-file upload epic (Task-6 body-limit increment).

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
    resume_content_sealer, verify_and_open, DirectoryVerifier, DownloadBundle, Identity,
    MemoryTrustStore, SmallStreams, StreamChunks, StreamingUploadBuilder, UploadParams,
    UploadRecords, VerifyContext, WrapOut, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey, WrappedDek};
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::types::{FileType, Id, RecipientType, Role, StreamType, Suite, Timestamp};
use maxsecu_encoding::{encode, labels};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const VOUCHER: &str = "in-person-code-001";
const VOUCHER2: &str = "in-person-code-002";
const TS: u64 = 1_719_500_000_000;
/// Matches VIDEO_CHUNK_SIZE in client-app/src/upload.rs (6 MiB).
const CHUNK_SIZE: u32 = 6 * 1024 * 1024;

// ─── TLS harness ─────────────────────────────────────────────────────────────

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

async fn delete_raw(conn: &mut Conn, uri: &str, auth: &str) -> StatusCode {
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

fn wrap_wire(w: &WrapOut) -> Vec<u8> {
    let mut v = w.wrapped_dek.enc.to_vec();
    v.extend_from_slice(&w.wrapped_dek.ct);
    v
}

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

/// GET the file view + every chunk back and rebuild a `DownloadBundle`.
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
            assert_eq!(cs, StatusCode::OK, "download chunk {st_name}/{i}");
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

/// Build the §8.1 `POST /v1/files` JSON body from an `UploadRecords` (streaming
/// path) plus the content stream framing that the caller computed separately.
fn stage_body_from_records(
    records: &UploadRecords,
    content_chunk_count: u64,
    content_chunk_size: u32,
    content_total_bytes: u64,
) -> serde_json::Value {
    // Content sorts lowest (encoding-spec V-13); list it first then append small
    // streams in the order `build_records_inner` produced them.
    let mut streams = vec![serde_json::json!({
        "stream_type": "content",
        "chunk_count": content_chunk_count,
        "chunk_size": content_chunk_size,
        "total_bytes": content_total_bytes,
    })];
    for s in &records.small_streams {
        streams.push(serde_json::json!({
            "stream_type": stream_name(s.stream_type),
            "chunk_count": s.chunk_count,
            "chunk_size": s.chunk_size,
            "total_bytes": s.total_bytes,
        }));
    }
    let wraps: Vec<_> = records
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
                "wrapped_dek_b64": B64.encode(wrap_wire(w)),
                "wrap_alg": 1,
                "granted_by": hex(&w.granted_by.0),
                "grant_b64": B64.encode(encode(&w.grant)),
                "grant_sig_b64": B64.encode(w.grant_sig),
            })
        })
        .collect();
    serde_json::json!({
        "file_id": hex(&records.file_id.0),
        "file_type": "video",
        "genesis_b64": B64.encode(encode(&records.genesis)),
        "genesis_sig_b64": B64.encode(records.genesis_sig),
        "manifest_b64": B64.encode(encode(&records.manifest)),
        "manifest_sig_b64": B64.encode(records.manifest_sig),
        "streams": streams,
        "wraps": wraps,
    })
}

// ─── Scenario A ──────────────────────────────────────────────────────────────

/// Full streaming upload (StreamingUploadBuilder, 3 × 6 MiB content chunks) →
/// download → decrypt; the recovered plaintext must equal the original byte-exactly.
#[tokio::test]
async fn streaming_upload_download_roundtrips_over_tls() {
    // ── (1) Server + ceremony ────────────────────────────────────────────────
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxstrup_a_{}",
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

    // ── (2) Register owner + recovery; publish bindings ─────────────────────
    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", VOUCHER).await;
    publish_binding(&mut c, &ceremony, "alice", user_id, &owner).await;

    let recovery = Identity::generate();
    let (recovery_uid, _rt) =
        register_and_login(&mut c, &recovery, "recovery-1", VOUCHER2).await;
    publish_binding(&mut c, &ceremony, "recovery-1", recovery_uid, &recovery).await;

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

    // ── (3) Synthetic content: 2 full 6 MiB chunks + a short tail ───────────
    // Three sealed chunks total; the last is a short tail of 1234 bytes.
    let content: Vec<u8> =
        (0..(CHUNK_SIZE as usize * 2 + 1234)).map(|i| (i % 251) as u8).collect();

    // Write to a temp file so seal_from_reader reads from disk (real path).
    let tmp_dir = std::env::temp_dir().join(format!(
        "mxstrup_a_src_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let tmp_file = tmp_dir.join("out.mp4");
    std::fs::write(&tmp_file, &content).unwrap();

    // ── (4) StreamingUploadBuilder → Pass 1: seal_from_reader ───────────────
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Video,
        chunk_size: CHUNK_SIZE,
        recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
        recovery_mlkem_pub: rr.mlkem_pub,
        created_at: Timestamp(TS),
    };
    let meta_bytes = serde_json::to_vec(&serde_json::json!({
        "title": "Streaming test clip", "tags": ["synthetic"],
    }))
    .unwrap();
    let small = SmallStreams {
        metadata: Some(meta_bytes),
        thumbnail: None,
        preview: None,
    };

    let builder = StreamingUploadBuilder::new();
    let sealer = builder.content_sealer(&params);

    // Pass 1: stream-seal from disk, collecting ciphertext chunks + byte count.
    let mut content_chunks: Vec<Vec<u8>> = Vec::new();
    let mut content_total_bytes = 0u64;
    let mut file = std::fs::File::open(&tmp_file).unwrap();
    let (content_count, content_digest) = sealer
        .seal_from_reader(&mut file, |_i, ct| {
            content_total_bytes += ct.len() as u64;
            content_chunks.push(ct.to_vec());
            Ok(())
        })
        .expect("Pass 1: seal_from_reader over synthetic content");
    assert_eq!(content_count, 3, "three content chunks (2 full + 1 tail)");

    let records = builder
        .finish(&params, &small, content_digest, content_count)
        .expect("finish() assembles UploadRecords");

    // ── (5) POST /v1/files → 201 ─────────────────────────────────────────────
    let body = stage_body_from_records(&records, content_count, CHUNK_SIZE, content_total_bytes);
    let (st, _) = post(&mut c, "/v1/files", Some(&token), body).await;
    assert_eq!(st, StatusCode::CREATED, "POST /v1/files → 201");

    // ── (6) PUT small-stream chunks ──────────────────────────────────────────
    for s in &records.small_streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            let uri = format!(
                "/v1/files/{fid_hex}/versions/1/streams/{}/chunks/{i}",
                stream_name(s.stream_type)
            );
            assert_eq!(
                put_raw(&mut c, &uri, &token, chunk.clone()).await,
                StatusCode::OK,
                "PUT small stream chunk {i}"
            );
        }
    }

    // ── (7) PUT content chunks (validates the 6 MiB body limit, Task-6) ─────
    for (i, ct) in content_chunks.iter().enumerate() {
        let uri =
            format!("/v1/files/{fid_hex}/versions/1/streams/content/chunks/{i}");
        assert_eq!(
            put_raw(&mut c, &uri, &token, ct.clone()).await,
            StatusCode::OK,
            "PUT content chunk {i} ({} bytes)", ct.len()
        );
    }

    // ── (8) POST finalize → 200 ──────────────────────────────────────────────
    let (st, _) = post(
        &mut c,
        &format!("/v1/files/{fid_hex}/versions/1/finalize"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize → 200");

    // ── (9) Download + decrypt; assert recovered plaintext == original ────────
    let dl = download_bundle(&mut c, &token, &fid_hex).await;
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
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
    let opened = verify_and_open(&ctx, &dl).expect("verify_and_open over streaming upload");
    let got = &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .expect("content stream present in opened file")
        .plaintext;
    assert_eq!(
        got, &content,
        "ROUND-TRIP: recovered plaintext equals the original synthetic content byte-exactly"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
    let _ = std::fs::remove_dir_all(&blob_dir);
}

// ─── Scenario B ──────────────────────────────────────────────────────────────

/// Partial upload (only chunk 0 PUT), then resume via `resume_content_sealer`
/// + `seal_chunk` for chunks 1.., finalize, and round-trip verify.
#[tokio::test]
async fn interrupted_streaming_upload_resumes_to_completion() {
    // ── Server + ceremony ────────────────────────────────────────────────────
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxstrup_b_{}",
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

    // ── Register users ────────────────────────────────────────────────────────
    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", VOUCHER).await;
    publish_binding(&mut c, &ceremony, "alice", user_id, &owner).await;

    let recovery = Identity::generate();
    let (recovery_uid, _rt) =
        register_and_login(&mut c, &recovery, "recovery-1", VOUCHER2).await;
    publish_binding(&mut c, &ceremony, "recovery-1", recovery_uid, &recovery).await;

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

    // ── Synthetic content (same shape as A) ──────────────────────────────────
    let content: Vec<u8> =
        (0..(CHUNK_SIZE as usize * 2 + 1234)).map(|i| (i % 251) as u8).collect();

    let tmp_dir = std::env::temp_dir().join(format!(
        "mxstrup_b_src_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let tmp_file = tmp_dir.join("out.mp4");
    std::fs::write(&tmp_file, &content).unwrap();

    // ── StreamingUploadBuilder → Pass 1 (collect all chunks) ─────────────────
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Video,
        chunk_size: CHUNK_SIZE,
        recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
        recovery_mlkem_pub: rr.mlkem_pub,
        created_at: Timestamp(TS),
    };
    let small = SmallStreams { metadata: None, thumbnail: None, preview: None };

    let builder = StreamingUploadBuilder::new();
    let sealer = builder.content_sealer(&params);

    let mut content_chunks: Vec<Vec<u8>> = Vec::new();
    let mut content_total_bytes = 0u64;
    let mut file = std::fs::File::open(&tmp_file).unwrap();
    let (content_count, content_digest) = sealer
        .seal_from_reader(&mut file, |_i, ct| {
            content_total_bytes += ct.len() as u64;
            content_chunks.push(ct.to_vec());
            Ok(())
        })
        .expect("Pass 1: seal_from_reader");
    assert_eq!(content_count, 3, "three chunks");

    let records = builder
        .finish(&params, &small, content_digest, content_count)
        .expect("finish()");

    // ── POST /v1/files (only once — the resume path does NOT re-POST) ─────────
    let body = stage_body_from_records(&records, content_count, CHUNK_SIZE, content_total_bytes);
    let (st, _) = post(&mut c, "/v1/files", Some(&token), body).await;
    assert_eq!(st, StatusCode::CREATED, "stage → 201");

    // Small streams: none in this scenario (metadata == None).

    // ── Interrupted: PUT only chunk 0 ────────────────────────────────────────
    let uri0 = format!("/v1/files/{fid_hex}/versions/1/streams/content/chunks/0");
    assert_eq!(
        put_raw(&mut c, &uri0, &token, content_chunks[0].clone()).await,
        StatusCode::OK,
        "PUT content chunk 0 (first pass)"
    );
    // Simulate interruption here — chunks 1 and 2 are NOT yet uploaded.

    // ── Resume: recover the sealer from the self-wrap ─────────────────────────
    // The manifest tells us the suite; since neither owner nor recovery has
    // ML-KEM enrolled here, the manifest.alg is V1.
    let suite: Suite = records.manifest.alg;
    let self_wrap = records
        .wraps
        .iter()
        .find(|w| w.recipient_type == RecipientType::User)
        .expect("self-wrap exists in records");
    let wrap_ctx = WrapContext {
        file_id: records.file_id,
        version: 1,
        recipient_id: Id(user_id),
    };
    let resume_sealer = resume_content_sealer(
        &owner,
        &self_wrap.wrapped_dek,
        &wrap_ctx,
        suite,
        file_id,
        1,
        CHUNK_SIZE,
    )
    .expect("resume_content_sealer recovers from self-wrap");

    // PUT remaining chunks (1 and 2) via resume sealer — does NOT re-POST.
    let cs = CHUNK_SIZE as usize;
    for i in 1..content_count {
        let start = i as usize * cs;
        let end = ((i as usize + 1) * cs).min(content.len());
        let pt = &content[start..end];
        let is_last = i == content_count - 1;
        let ct = resume_sealer.seal_chunk(i, pt, is_last);
        let uri = format!("/v1/files/{fid_hex}/versions/1/streams/content/chunks/{i}");
        assert_eq!(
            put_raw(&mut c, &uri, &token, ct).await,
            StatusCode::OK,
            "PUT content chunk {i} (resume path)"
        );
    }

    // ── Finalize ──────────────────────────────────────────────────────────────
    let (st, _) = post(
        &mut c,
        &format!("/v1/files/{fid_hex}/versions/1/finalize"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize after resume → 200");

    // ── Download + decrypt: assert == original ────────────────────────────────
    let dl = download_bundle(&mut c, &token, &fid_hex).await;
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
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
    let opened =
        verify_and_open(&ctx, &dl).expect("verify_and_open over resumed streaming upload");
    let got = &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .expect("content stream present")
        .plaintext;
    assert_eq!(
        got, &content,
        "RESUME ROUND-TRIP: recovered plaintext equals original byte-exactly"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
    let _ = std::fs::remove_dir_all(&blob_dir);
}

// ─── Scenario C ──────────────────────────────────────────────────────────────

/// DELETE /v1/files/{id} removes a staged-but-never-finalized upload (204);
/// the file is absent (404) after discard; a second DELETE is idempotent (204).
#[tokio::test]
async fn discard_removes_never_finalized_upload() {
    // ── Server + ceremony ────────────────────────────────────────────────────
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxstrup_c_{}",
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

    // ── Register users ────────────────────────────────────────────────────────
    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", VOUCHER).await;
    publish_binding(&mut c, &ceremony, "alice", user_id, &owner).await;

    let recovery = Identity::generate();
    let (recovery_uid, _rt) =
        register_and_login(&mut c, &recovery, "recovery-1", VOUCHER2).await;
    publish_binding(&mut c, &ceremony, "recovery-1", recovery_uid, &recovery).await;

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

    // ── Small synthetic content: fits in one 6 MiB chunk ─────────────────────
    // Using a tiny buffer (no large allocation needed for the discard scenario).
    let content: Vec<u8> = (0..1234usize).map(|i| (i % 251) as u8).collect();

    // ── StreamingUploadBuilder → build records for one content chunk ──────────
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Video,
        chunk_size: CHUNK_SIZE,
        recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
        recovery_mlkem_pub: rr.mlkem_pub,
        created_at: Timestamp(TS),
    };
    let small = SmallStreams { metadata: None, thumbnail: None, preview: None };

    let builder = StreamingUploadBuilder::new();
    let sealer = builder.content_sealer(&params);

    let mut content_chunks: Vec<Vec<u8>> = Vec::new();
    let mut content_total_bytes = 0u64;
    let (content_count, content_digest) = sealer
        .seal_from_reader(&mut std::io::Cursor::new(&content), |_i, ct| {
            content_total_bytes += ct.len() as u64;
            content_chunks.push(ct.to_vec());
            Ok(())
        })
        .expect("seal_from_reader for discard test");
    assert_eq!(content_count, 1, "single chunk for small content");

    let records = builder
        .finish(&params, &small, content_digest, content_count)
        .expect("finish()");

    // ── POST /v1/files → 201 ─────────────────────────────────────────────────
    let body = stage_body_from_records(&records, content_count, CHUNK_SIZE, content_total_bytes);
    let (st, _) = post(&mut c, "/v1/files", Some(&token), body).await;
    assert_eq!(st, StatusCode::CREATED, "stage → 201");

    // ── PUT one content chunk, then deliberately skip finalize ────────────────
    let uri0 = format!("/v1/files/{fid_hex}/versions/1/streams/content/chunks/0");
    assert_eq!(
        put_raw(&mut c, &uri0, &token, content_chunks[0].clone()).await,
        StatusCode::OK,
        "PUT content chunk 0"
    );
    // No finalize — the upload is staged but never finalized.

    // ── DELETE /v1/files/{id} (owner) → 204 ──────────────────────────────────
    let file_uri = format!("/v1/files/{fid_hex}");
    assert_eq!(
        delete_raw(&mut c, &file_uri, &token).await,
        StatusCode::NO_CONTENT,
        "DELETE never-finalized upload → 204"
    );

    // ── GET /v1/files/{id} → 404 (gone after discard) ────────────────────────
    let (st, _) = get_json(&mut c, &format!("{file_uri}?version=latest"), &token).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "discarded file is absent → 404");

    // ── Second DELETE → 204 (idempotent) ─────────────────────────────────────
    assert_eq!(
        delete_raw(&mut c, &file_uri, &token).await,
        StatusCode::NO_CONTENT,
        "repeated DELETE is idempotent → 204"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}
