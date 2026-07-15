//! Disk-backed **resume** end-to-end test over real in-process TLS.
//!
//! `streaming_upload_e2e.rs` scenario B already resumes an interrupted upload — but
//! it POSTs `/v1/files` from a LOCAL `stage_body_from_records` copy built off the
//! in-memory `UploadRecords`. That leaves the PRODUCT resume body,
//! `commands::upload::stage_body_from_record` (which shapes the POST from the
//! on-disk `StagingRecord` a prior session persisted), with ZERO end-to-end cover.
//! An in-flight resumable upload (a large video stages for hours) that today's
//! client can no longer finalize is exactly the kind of silent break the
//! backward-compat gate exists to catch — and `stage_body_from_record` is the wire
//! shaper on that path.
//!
//! This test drives the REAL resume path:
//!   1. Pass-1 seal the content (`StreamingUploadBuilder`) to get the manifest
//!      digest/count, then assemble + **persist a `StagingRecord`** to disk exactly
//!      as `stage_upload` does (simulating a prior session's staged upload).
//!   2. First confirm (`progress == 0`): POST `/v1/files` from the product's
//!      `stage_body_from_record(&rec, …)` → 201, PUT the small-stream chunks, seal +
//!      PUT content chunk 0 via `resume_content_sealer`, checkpoint `progress = 1`,
//!      persist — then **INTERRUPT** (no finalize).
//!   3. Resume (`progress > 0`): reload the record from disk; because progress is
//!      advanced, SKIP the re-POST (the product's guard), re-derive the sealer,
//!      seal + PUT the remaining content chunks from the on-disk `out.mp4`, finalize.
//!   4. Download as the owner and run the full `verify_and_open` ladder; the
//!      recovered plaintext must equal the original byte-for-byte.

use std::path::PathBuf;
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
use maxsecu_client_app::commands::upload::stage_body_from_record;
use maxsecu_client_app::upload::StageFlags;
use maxsecu_client_app::upload_staging::{
    StagedSmallStream, StagedWrap, StagingRecord, StagingStore,
};
use maxsecu_client_core::{
    resume_content_sealer, verify_and_open, DownloadBundle, Identity, SmallStreams, StreamChunks,
    StreamingUploadBuilder, UploadParams, UploadRecords, VerifyContext, WrapOut, NO_ADMINS,
    NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey, SigningKey, WrappedDek};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::{Manifest, WrapContext};
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

// ─── TLS harness (mirrors streaming_upload_e2e.rs) ────────────────────────────

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

fn stream_from_name(s: &str) -> StreamType {
    match s {
        "content" => StreamType::Content,
        "metadata" => StreamType::Metadata,
        "thumbnail" => StreamType::Thumbnail,
        "preview" => StreamType::Preview,
        _ => panic!("unknown stream {s}"),
    }
}

/// The `StagedSmallStream.stream_type` wire tag (matches the server's stream_type
/// enum; content is 1 and is NEVER staged).
fn stream_type_u8(st: StreamType) -> u8 {
    match st {
        StreamType::Content => 1,
        StreamType::Metadata => 2,
        StreamType::Thumbnail => 3,
        StreamType::Preview => 4,
    }
}

fn wrap_from_bytes(b: &[u8]) -> WrappedDek {
    WrappedDek {
        enc: b[..32].try_into().unwrap(),
        ct: b[32..].to_vec(),
    }
}

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

/// Map an in-memory `UploadRecords` (streaming pass-1 output) into the disk-backed
/// `StagingRecord` that `stage_upload` persists — the SAME shape a prior session
/// would have written. `content_total_bytes` is the pass-1 ciphertext byte count.
fn staging_record_from(
    records: &UploadRecords,
    out_mp4_path: PathBuf,
    content_chunk_count: u64,
    content_total_bytes: u64,
) -> StagingRecord {
    let wraps: Vec<StagedWrap> = records
        .wraps
        .iter()
        .map(|w: &WrapOut| {
            let mut wire = w.wrapped_dek.enc.to_vec();
            wire.extend_from_slice(&w.wrapped_dek.ct);
            StagedWrap {
                recipient_id: w.recipient_id.0,
                recipient_type: if w.recipient_type == RecipientType::Recovery {
                    "recovery".to_owned()
                } else {
                    "user".to_owned()
                },
                wrapped_dek: wire,
                granted_by: w.granted_by.0,
                grant: encode(&w.grant),
                grant_sig: w.grant_sig.to_vec(),
            }
        })
        .collect();
    let small_streams: Vec<StagedSmallStream> = records
        .small_streams
        .iter()
        .map(|s| StagedSmallStream {
            stream_type: stream_type_u8(s.stream_type),
            chunk_size: s.chunk_size,
            chunk_count: s.chunk_count,
            total_bytes: s.total_bytes,
            digest: s.digest.to_vec(),
            chunks: s.chunks.clone(),
        })
        .collect();
    StagingRecord {
        file_id: records.file_id.0,
        file_type: "video".to_owned(),
        title: "Resumed clip".to_owned(),
        manifest: encode(&records.manifest),
        manifest_sig: records.manifest_sig.to_vec(),
        genesis: encode(&records.genesis),
        genesis_sig: records.genesis_sig.to_vec(),
        wraps,
        out_mp4_path,
        chunk_size: CHUNK_SIZE,
        content_chunk_count,
        content_total_bytes,
        small_streams,
        progress: 0,
        created_ms: TS,
        last_progress_ms: TS,
        finalized: false,
    }
}

/// Re-derive the content sealer from a staged record's self-wrap, exactly as
/// `streaming_confirm` does at resume time (reconstruct `WrappedDek` from the wire
/// bytes, decode the suite from the manifest, `resume_content_sealer`).
fn resume_sealer(
    owner: &Identity,
    rec: &StagingRecord,
) -> maxsecu_client_core::ContentStreamSealer {
    let suite: Suite = decode::<Manifest>(&rec.manifest)
        .map(|m| m.alg)
        .unwrap_or(Suite::V1);
    let self_wrap = rec
        .wraps
        .iter()
        .find(|w| w.recipient_type == "user")
        .expect("staged self-wrap present");
    let wrapped = WrappedDek {
        enc: self_wrap.wrapped_dek[..32].try_into().unwrap(),
        ct: self_wrap.wrapped_dek[32..].to_vec(),
    };
    let ctx = WrapContext {
        file_id: Id(rec.file_id),
        version: 1,
        recipient_id: Id(self_wrap.recipient_id),
    };
    resume_content_sealer(
        owner,
        &wrapped,
        &ctx,
        suite,
        Id(rec.file_id),
        1,
        rec.chunk_size,
    )
    .expect("resume_content_sealer recovers the DEK from the staged self-wrap")
}

/// Boot a server + register owner/recovery + publish bindings; return the pieces
/// the test drives.
async fn boot() -> (Conn, Identity, [u8; 16], String, [u8; 32], PathBuf) {
    let d5_seed = maxsecu_crypto::random_array::<32>();
    let ceremony = Ceremony::from_seed(&d5_seed);
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxresume_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let store = MemoryStore::new();
    store.add_reg_key(sha256(VOUCHER.as_bytes()));
    store.add_reg_key(sha256(VOUCHER2.as_bytes()));
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

    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", VOUCHER).await;
    publish_binding(&mut c, &ceremony, "alice", user_id, &owner).await;

    let recovery = Identity::generate();
    let (recovery_uid, _rt) = register_and_login(&mut c, &recovery, "recovery-1", VOUCHER2).await;
    publish_binding(&mut c, &ceremony, "recovery-1", recovery_uid, &recovery).await;

    (c, owner, user_id, token, recovery.enc_pub_bytes(), blob_dir)
}

/// A staged-then-interrupted video upload finalizes by RESUMING through the product
/// resume body (`commands::upload::stage_body_from_record`) and round-trips to the
/// identical plaintext.
#[tokio::test]
async fn staged_upload_resumes_through_stage_body_from_record_and_roundtrips() {
    let (mut c, owner, user_id, token, recovery_enc, blob_dir) = boot().await;

    // ── Content: 2 full 6 MiB chunks + a short tail; written to a real on-disk
    //    out.mp4 (the resume re-seals content from this file, like the product). ──
    let content: Vec<u8> = (0..(CHUNK_SIZE as usize * 2 + 4321))
        .map(|i| (i % 251) as u8)
        .collect();
    let staging_root = std::env::temp_dir().join(format!(
        "mxresume_stg_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    // The product lays out out.mp4 inside the per-file staging dir; mirror that.
    let job_dir = staging_root.join(&fid_hex);
    std::fs::create_dir_all(&job_dir).unwrap();
    let out_mp4 = job_dir.join("out.mp4");
    std::fs::write(&out_mp4, &content).unwrap();

    // ── Pass 1: seal content (for the manifest digest/count) + a metadata stream. ──
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(user_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Video,
        chunk_size: CHUNK_SIZE,
        recovery_pub: EncPublicKey::from_bytes(recovery_enc),
        recovery_mlkem_pub: None,
        created_at: Timestamp(TS),
    };
    let meta_bytes = serde_json::to_vec(&serde_json::json!({
        "title": "Resumed clip", "tags": ["synthetic"],
    }))
    .unwrap();
    let small = SmallStreams {
        metadata: Some(meta_bytes),
        thumbnail: None,
        preview: None,
    };

    let builder = StreamingUploadBuilder::new();
    let sealer = builder.content_sealer(&params);
    let mut content_total_bytes = 0u64;
    let mut file = std::fs::File::open(&out_mp4).unwrap();
    let (content_count, content_digest) = sealer
        .seal_from_reader(&mut file, |_i, ct| {
            content_total_bytes += ct.len() as u64;
            Ok(())
        })
        .expect("Pass 1: seal_from_reader");
    assert_eq!(content_count, 3, "three content chunks (2 full + 1 tail)");
    let records = builder
        .finish(&params, &small, content_digest, content_count)
        .expect("finish() assembles UploadRecords");
    assert_eq!(
        records.small_streams.len(),
        1,
        "one small (metadata) stream"
    );

    // ── Persist the StagingRecord to disk (a prior session's in-flight upload). ──
    let store = StagingStore::new(&staging_root);
    let rec = staging_record_from(
        &records,
        out_mp4.clone(),
        content_count,
        content_total_bytes,
    );
    store.persist(&rec).unwrap();

    // ══ First confirm (progress == 0): POST from the PRODUCT resume body ══════════
    let rec = store.load(&file_id.0).expect("reload staged record");
    assert_eq!(rec.progress, 0);
    let body = stage_body_from_record(&rec, StageFlags::default());
    // Sanity: the product body carries the on-disk file_id + the staged wraps/streams.
    assert_eq!(body["file_id"], fid_hex);
    assert_eq!(body["file_type"], "video");
    let (st, _) = post(&mut c, "/v1/files", Some(&token), body).await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "POST /v1/files from stage_body_from_record → 201"
    );

    // PUT the staged small-stream chunks (metadata).
    for s in &rec.small_streams {
        let name = match s.stream_type {
            2 => "metadata",
            3 => "thumbnail",
            4 => "preview",
            other => panic!("unexpected staged stream_type {other}"),
        };
        for (i, chunk) in s.chunks.iter().enumerate() {
            let uri = format!("/v1/files/{fid_hex}/versions/1/streams/{name}/chunks/{i}");
            assert_eq!(
                put_raw(&mut c, &uri, &token, chunk.clone()).await,
                StatusCode::OK,
                "PUT staged small-stream chunk {name}/{i}"
            );
        }
    }

    // Seal + PUT content chunk 0 from the on-disk out.mp4 (pass-2), checkpoint, then
    // INTERRUPT (no finalize) — exactly the partial state a killed confirm leaves.
    {
        let sealer = resume_sealer(&owner, &rec);
        let end = (CHUNK_SIZE as usize).min(content.len());
        let ct = sealer.seal_chunk(0, &content[..end], false);
        let uri = format!("/v1/files/{fid_hex}/versions/1/streams/content/chunks/0");
        assert_eq!(
            put_raw(&mut c, &uri, &token, ct).await,
            StatusCode::OK,
            "PUT content chunk 0 (first pass)"
        );
    }
    let mut rec = rec;
    rec.progress = 1;
    rec.last_progress_ms = TS + 1;
    store.persist(&rec).unwrap();
    // ── INTERRUPTED HERE: chunks 1 and 2 not uploaded, upload not finalized. ──

    // ══ Resume (progress > 0): reload, SKIP the re-POST, finish + finalize ════════
    let rec = store.load(&file_id.0).expect("reload after interrupt");
    assert_eq!(rec.progress, 1, "the checkpoint survived to disk");
    // The product guard: progress > 0 ⇒ the /v1/files record is already staged, so
    // the re-POST (and small-stream PUT) are SKIPPED. Re-POSTing would cascade-delete
    // the already-uploaded chunk 0. We honor that guard here and jump to pass-2.
    let sealer = resume_sealer(&owner, &rec);
    let cs = CHUNK_SIZE as usize;
    for i in rec.progress..rec.content_chunk_count {
        let start = i as usize * cs;
        let end = ((i as usize + 1) * cs).min(content.len());
        let is_last = i == rec.content_chunk_count - 1;
        let ct = sealer.seal_chunk(i, &content[start..end], is_last);
        let uri = format!("/v1/files/{fid_hex}/versions/1/streams/content/chunks/{i}");
        assert_eq!(
            put_raw(&mut c, &uri, &token, ct).await,
            StatusCode::OK,
            "PUT content chunk {i} (resume pass)"
        );
    }
    let (st, _) = post(
        &mut c,
        &format!("/v1/files/{fid_hex}/versions/1/finalize"),
        Some(&token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize after resume → 200");

    // ══ Download + decrypt: recovered plaintext == original byte-for-byte ═════════
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
    let opened = verify_and_open(&ctx, &dl).expect("verify_and_open over the resumed upload");
    let got = &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .expect("content stream present")
        .plaintext;
    assert_eq!(
        got, &content,
        "RESUME ROUND-TRIP: plaintext recovered through stage_body_from_record equals the original"
    );
    // The metadata staged into the record also decrypts.
    let meta = &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .expect("metadata stream present")
        .plaintext;
    assert!(
        std::str::from_utf8(meta).unwrap().contains("Resumed clip"),
        "staged metadata decrypts after resume"
    );

    let _ = std::fs::remove_dir_all(&staging_root);
    let _ = std::fs::remove_dir_all(&blob_dir);
}
