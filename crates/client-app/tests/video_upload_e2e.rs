//! Phase-7 Gate-6 exit-gate end-to-end test (author-side video ingest) — the
//! confined transcode + the Phase-4 pipeline over REAL loopback TLS.
//!
//! Drives the **real** `client-app` video upload modules end to end:
//!
//! - GATE T (confined ingest, NO network): `upload::prepare_video_streams` runs the
//!   TWO confined spawns — the embedded ffmpeg decodes a small real `.y4m` source to
//!   AV1/AAC `out.mp4` + a first-frame `thumb.png`, then the
//!   AppContainer/subprocess-confined `media-transcode-worker` re-muxes `out.mp4` to
//!   canonical AV1/CMAF streams + the fragment seek index (thumbnail/preview derived
//!   from `thumb.png` via the pure-Rust image codec). This step makes NO server call
//!   (no `Conn`/TLS is even created before it) — it is the preview-before-upload
//!   transcode.
//! - GATE M (metadata round-trip): `parse_fragment_index` over the staged metadata
//!   returns the SAME fragments the transcode produced (the author→view contract).
//! - GATE P (confirm pipeline): `build_upload` (FileType::Video, chunk_size 4096) +
//!   the real `run_pipeline` stage→PUT→finalize over TLS round-trips the canonical
//!   content byte-exactly through the full `verify_and_open` ladder, and the
//!   fragment index survives inside the authenticated metadata stream.
//!
//! GATE T requires the built `media-transcode-worker` binary; when absent (e.g. a
//! bare `-p maxsecu-client-app` run that did not build the sibling bins) the test
//! SKIPS with a note. The `--workspace` gate builds it first, so it exercises the
//! real spawn. Run isolated single-threaded.
//!
//! The old GATE D (confined-decode-session verification of the staged canonical
//! content, via `media-launcher`'s client-side `VideoSubprocessSession`/
//! `media-worker --video-session`) was removed with that client-side decode-session
//! driver once native `<video>` became the shipping viewer — see the Task-2
//! cleanup. Equivalent (more thorough) coverage — that the transcode output decodes
//! back to the correct source dimensions, including odd-dimension/SAR coercion —
//! already lives in `media-transcode-worker/tests/ingest_remux.rs`, which drives
//! the SAME `maxsecu_media_worker::VideoSession` in-process as a dev-only decode
//! oracle.

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
use maxsecu_client_app::directory::resolve_recovery_recipient;
use maxsecu_client_app::upload::{prepare_video_streams, run_pipeline, VIDEO_CHUNK_SIZE};
use maxsecu_client_app::video::parse_fragment_index;
use maxsecu_client_core::video::VideoBounds;
use maxsecu_client_core::{
    build_upload, verify_and_open, DirectoryVerifier, DownloadBundle, Identity, MemoryTrustStore,
    PlaintextStreams, StreamChunks, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey, WrappedDek};
use maxsecu_encoding::labels;
use maxsecu_encoding::types::{FileType, Id, Role, StreamType, Timestamp};
use maxsecu_media_launcher::TranscodeOptions;
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const VOUCHER: &str = "in-person-code-001";
const VOUCHER2: &str = "in-person-code-002";
const TS: u64 = 1_719_500_000_000;
const CHUNK: usize = VIDEO_CHUNK_SIZE as usize; // == upload chunk_size == video fragment-index unit (6 MiB)

// ---- worker-binary discovery (workspace target dir) -----------------------

/// Locate a built workspace binary (`media-transcode-worker` / `media-worker`) in
/// the same profile dir this test binary lives in. The integration-test exe is at
/// `target/<profile>/deps/<test>`, so the sibling bins are at `target/<profile>/`.
fn find_worker(name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let test_exe = std::env::current_exe().ok()?;
    // .../target/<profile>/deps/<test>  ->  .../target/<profile>
    let profile_dir = test_exe.parent()?.parent()?;
    let candidate = profile_dir.join(&exe);
    if candidate.is_file() {
        return Some(candidate);
    }
    None
}

// ---- real source video synthesis (Y4M; ffmpeg always reads it, no codec dep) ----

/// The vendored static ffmpeg the universal-video-ingest path drives. Discovered
/// relative to this crate (`crates/client-app/../../vendor/ffmpeg/ffmpeg.exe`).
/// `None` ⇒ the spawn gates SKIP (it is gitignored, fetched by `fetch-ffmpeg.ps1`).
fn vendored_ffmpeg() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vendor")
        .join("ffmpeg")
        .join("ffmpeg.exe");
    p.is_file().then_some(p)
}

/// A fresh, unique temp dir for a test's source file.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mxviding-{tag}-{}-{}",
        std::process::id(),
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build a real, decodable raw video as YUV4MPEG2 (`.y4m`) bytes — the confined
/// ffmpeg under test reads this with its built-in demuxer (no external codec), then
/// transcodes it to canonical AV1. `w`/`h` must be even (4:2:0). No audio track (the
/// re-mux worker handles an audio-absent source).
fn make_y4m(w: u32, h: u32, frames: u32, fps: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(format!("YUV4MPEG2 W{w} H{h} F{fps}:1 Ip A1:1 C420jpeg\n").as_bytes());
    let (cw, ch) = (w / 2, h / 2);
    for f in 0..frames {
        v.extend_from_slice(b"FRAME\n");
        for y in 0..h {
            for x in 0..w {
                v.push(((x + y + f) & 0xff) as u8); // Y: a moving gradient
            }
        }
        for _ in 0..(cw * ch) {
            v.push(((f.wrapping_mul(3)) & 0xff) as u8); // U
        }
        for _ in 0..(cw * ch) {
            v.push(((f.wrapping_mul(7)) & 0xff) as u8); // V
        }
    }
    v
}

/// Write a `.y4m` source into a fresh temp dir and return its path.
fn write_source_y4m(tag: &str, w: u32, h: u32, frames: u32, fps: u32) -> (PathBuf, PathBuf) {
    let dir = temp_dir(tag);
    let path = dir.join("source.y4m");
    std::fs::write(&path, make_y4m(w, h, frames, fps)).unwrap();
    (dir, path)
}

// ---- TLS harness (copied from upload_e2e.rs) ------------------------------

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
async fn phase7_video_upload_over_real_tls() {
    // ---- worker binaries + vendored ffmpeg (skip the spawn gates if absent) ----
    let transcode_worker = find_worker("media-transcode-worker");
    let Some(_transcode_worker) = transcode_worker else {
        eprintln!(
            "SKIP phase7_video_upload_over_real_tls: media-transcode-worker binary not found in \
             the target dir (build it, e.g. `cargo test --workspace`, to exercise the confined \
             transcode)."
        );
        return;
    };
    let Some(ffmpeg) = vendored_ffmpeg() else {
        eprintln!(
            "SKIP phase7_video_upload_over_real_tls: vendored ffmpeg \
             (vendor/ffmpeg/ffmpeg.exe) not present; run scripts/fetch-ffmpeg.ps1 to exercise the \
             confined ffmpeg ingest."
        );
        return;
    };

    // A tiny 64x64 clip; ~12 frames fits in a single GOP → one canonical fragment
    // (enough for the round-trip gates; the multi-fragment seek path is covered by
    // video_e2e.rs).
    let (w, h, frames, fps) = (64u32, 64u32, 12u32, 24u32);
    let (src_dir, source_path) = write_source_y4m("upload", w, h, frames, fps);

    // ---- GATE T: confined ffmpeg ingest + re-mux, NO network ----
    //
    // INVARIANT (no-network-at-stage): the ingest happens with NO connection /
    // transport / server in scope. This is STRUCTURAL, not merely ordering:
    // `prepare_video_streams` takes only `(input_path, ffmpeg_path, worker_path,
    // options, bounds, title, tags, on_phase, cancel)` — a local progress sink + a
    // cancel flag, NO `SendRequest`/host/socket parameter,
    // so it cannot reach the network even if a future refactor moved the server setup
    // earlier. The asserts below enforce that no networking object has been
    // constructed yet at this point: the only bindings in scope are the source +
    // tool paths (the server harness — `listener`/`addr`/`Conn`/`AppState` — is built
    // only AFTER this gate). The two confined spawns (ffmpeg, then the re-mux worker)
    // each run with no net/keys/children; `prepare_video_streams`'s signature is the
    // hard guarantee.
    let prepared = prepare_video_streams(
        &source_path,
        &ffmpeg,
        &TranscodeOptions::default(),
        &VideoBounds::default(),
        "Holiday clip",
        &["beach".to_owned()],
        |_p| {},                                    // no-op progress sink (not asserted here)
        &std::sync::atomic::AtomicBool::new(false), // never cancelled
    )
    .expect("GATE T: the confined ffmpeg + re-mux produced canonical streams");
    let _ = std::fs::remove_dir_all(&src_dir);
    // The handle keeps the transcoded fMP4 on DISK (content is not in RAM). Reconstruct
    // the in-memory `PlaintextStreams`/`fragments` the round-trip gates work against.
    let content = std::fs::read(&prepared.out_mp4_path).expect("read transcoded fMP4");
    let fragments = prepared.fragments.clone();
    let streams = PlaintextStreams {
        content,
        metadata: Some(prepared.metadata.clone()),
        thumbnail: Some(prepared.thumbnail.clone()),
        preview: Some(prepared.preview.clone()),
    };
    // `prepare_video_streams` no longer deletes its temp dir on success — the test owns it.
    let _ = std::fs::remove_dir_all(&prepared.job_dir);
    assert!(
        !fragments.is_empty(),
        "GATE T: the re-mux produced at least one canonical fragment"
    );
    let canonical = streams.content.clone();
    assert!(
        !canonical.is_empty(),
        "GATE T: canonical content is non-empty (the fMP4 is not chunk-aligned)"
    );
    // The thumbnail + preview are DERIVED from ffmpeg's first-frame PNG via the
    // pure-Rust image codec (this key-holding process stays codec-free).
    assert!(
        streams.thumbnail.as_ref().is_some_and(|t| !t.is_empty()),
        "GATE T: a thumbnail was derived from the first-frame PNG"
    );
    assert!(
        streams.preview.as_ref().is_some_and(|p| !p.is_empty()),
        "GATE T: a preview was derived from the first-frame PNG"
    );
    let metadata = streams.metadata.clone().expect("metadata present");

    // ---- GATE M: the fragment index round-trips through the authenticated metadata ----
    let meta_json: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    let parsed = parse_fragment_index(&meta_json).expect("GATE M: index parses");
    assert_eq!(parsed.len(), fragments.len());
    for (p, f) in parsed.iter().zip(fragments.iter()) {
        assert_eq!(
            (p.seq, p.pts_ms, p.chunk_start, p.chunk_len),
            (f.seq, f.pts_ms, f.chunk_start, f.chunk_len),
            "GATE M: parsed fragment matches the transcode output"
        );
    }
    // The index tiles the canonical content in VIDEO_CHUNK_SIZE chunks; the LAST chunk
    // is short (the fMP4 is not a whole multiple of the chunk size), so coverage is
    // asserted in chunk COUNT rather than byte length.
    let last = parsed.last().unwrap();
    let total_chunks = (canonical.len() as u64).div_ceil(CHUNK as u64);
    assert_eq!(
        last.chunk_start + last.chunk_len,
        total_chunks,
        "GATE M: fragment ranges cover the content's chunk count exactly"
    );

    // ---- Server + pinned ceremony D5 (for the confirm pipeline) ----
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxvidup_{}",
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

    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", VOUCHER).await;
    publish_binding(&mut c, &ceremony, "alice", user_id, &owner).await;
    let recovery = Identity::generate();
    let (recovery_uid, _rt) = register_and_login(&mut c, &recovery, "recovery-1", VOUCHER2).await;
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

    // ---- GATE P: build_upload(Video, chunk_size VIDEO_CHUNK_SIZE) + run_pipeline → round-trip ----
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id,
            file_type: FileType::Video,
            chunk_size: VIDEO_CHUNK_SIZE,
            recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
            recovery_mlkem_pub: rr.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &streams,
    )
    .unwrap();
    run_pipeline(&mut c.sender, "localhost", &token, &bundle, |_d, _t| {})
        .await
        .expect("GATE P: video upload pipeline succeeds");

    let dl = download_bundle(&mut c, &token, &fid_hex).await;
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
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
    let opened = verify_and_open(&ctx, &dl).expect("GATE P: video round-trips");
    let got_content = &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .unwrap()
        .plaintext;
    assert_eq!(
        got_content, &canonical,
        "GATE P: canonical AV1/CMAF content round-trips byte-exactly"
    );
    let got_meta = &opened
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .unwrap()
        .plaintext;
    let got_meta_json: serde_json::Value = serde_json::from_slice(got_meta).unwrap();
    let roundtripped = parse_fragment_index(&got_meta_json)
        .expect("GATE P: the authenticated metadata still carries the fragment index");
    assert_eq!(
        roundtripped, parsed,
        "GATE P: the fragment index survives the round-trip inside the authenticated metadata"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}
