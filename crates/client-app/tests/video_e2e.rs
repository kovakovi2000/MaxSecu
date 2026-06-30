//! Phase-7 Gate-6 **headline** end-to-end test (author → view) over REAL loopback
//! TLS — the culmination of Gates 1–6: an author transcodes + uploads a video and a
//! viewer browses + plays it through the WHOLE production view path (fetch
//! ciphertext → decrypt in the TCB → decode in the CONFINED worker → re-validate →
//! frames), seeks, and back-seeks into the on-disk ciphertext fragment cache with no
//! re-fetch.
//!
//! It drives the **real** `client-app` modules (the inner orchestration the Tauri
//! commands wrap — `upload::{prepare_video_streams,run_pipeline}`,
//! `download::{parse_file_view,build_stream_header}`,
//! `directory::{resolve_and_verify_author,resolve_my_user_id}`, the `client-core`
//! `verify_and_open_headers`/`open_content_decryptor` header ladder,
//! `video::{parse_fragment_index,fragment_for_time,chunks_for_fragment,feed_fragment}`,
//! and the codec-free confined session launcher `media-launcher`) over a live
//! connection to the secret-free server (`MemoryStore` + `FsBlobStore`, no Postgres).
//!
//! Five gates:
//!
//! 1. **Author transcode + upload** — the two confined spawns (the embedded ffmpeg
//!    decodes a small real `.y4m` source to AV1/AAC `out.mp4`, then the
//!    `media-transcode-worker` re-muxes it to canonical AV1/CMAF + a fragment index),
//!    then the real Phase-4 pipeline (`build_upload(Video,4096)` + `run_pipeline`)
//!    stages it over TLS. The video is now on the server (content + authenticated
//!    metadata + the recovery wrap).
//! 2. **Browse** — the D35 listing (`GET /v1/files?type=video`) returns the staged
//!    file with `file_type=video`, so the viewer can resolve it.
//! 3. **View (the headline)** — the open_video path on the REQUESTED `file_id`:
//!    resolve + D5-verify the author, fetch the view + header, run the verify ladder,
//!    parse the authenticated fragment index, derive the in-TCB `ContentDecryptor`,
//!    and play the initial bounded window — each fragment's CIPHERTEXT fetched +
//!    cached, decrypted in the TCB, decoded in the **confined session**
//!    (`AppContainerVideoSession` on Windows / `VideoSubprocessSession` elsewhere),
//!    and every worker frame RE-VALIDATED (`validate_i420`) back to the source dims
//!    (16×16).
//! 4. **Seek** — `fragment_for_time` maps a later pts to its fragment; playing that
//!    window fetches + decodes exactly the mapped fragment.
//! 5. **Back-seek hits the ciphertext cache (NO re-fetch)** — re-playing an
//!    already-watched window performs ZERO new server GETs (the feeder reads the
//!    cached ciphertext), and the on-disk cache blob is CIPHERTEXT (the decoded
//!    plaintext never appears at rest).
//!
//! Worker-spawning gates need the built `media-transcode-worker` + `media-worker`
//! binaries; a bare `-p maxsecu-client-app` run that did not build them SKIPS with a
//! note. The `cargo build -p maxsecu-media-worker -p maxsecu-media-transcode-worker`
//! gate (and `--workspace`) build them first, so the real confined spawn runs. Run
//! isolated single-threaded.

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
use maxsecu_client_app::directory::{
    resolve_and_verify_author, resolve_my_user_id, resolve_recovery_recipient,
    verify_author_binding,
};
use maxsecu_client_app::download::{build_stream_header, parse_file_view};
use maxsecu_client_app::error::UiError;
use maxsecu_client_app::fragment_cache::FragmentCache;
use maxsecu_client_app::upload::{prepare_video_streams, run_pipeline};
use maxsecu_client_app::video::{
    chunks_for_fragment, feed_fragment, fragment_for_time, parse_fragment_index, FragmentEntry,
};
use maxsecu_client_core::video::{validate_i420, ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_client_core::{
    build_upload, open_content_decryptor, verify_and_open_headers, ContentDecryptor,
    DirectoryVerifier, Identity, MemoryTrustStore, StreamHeader, UploadParams, VerifyContext,
    NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey};
use maxsecu_encoding::structs::{DirBinding, Manifest};
use maxsecu_encoding::types::{FileType, Id, RecipientType, Role, StreamType, Timestamp};
use maxsecu_encoding::{decode, labels};
use maxsecu_media_launcher::{TranscodeOptions, VideoSessionDecoder};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const VOUCHER: &str = "in-person-code-001";
const VOUCHER2: &str = "in-person-code-002";
const TS: u64 = 1_719_500_000_000;
const CHUNK: usize = 4096; // == upload chunk_size == TRANSCODE_CHUNK_SIZE
const PLAY_WINDOW: u32 = 4; // mirrors commands::video::PLAY_WINDOW

// ---- the production confined-decode session type (AppContainer on Windows) ----
//
// Exactly the alias `commands::video::SessionDecoder` resolves to: the OS-confined
// AppContainer + Job Object session on Windows, the cross-platform process-isolated
// subprocess elsewhere. Both link NO codecs (the codecs live only in the spawned
// `media-worker`); we drive whichever this platform uses via the shared
// `VideoSessionDecoder::run_session` trait method — the SAME call `play_window`
// makes in production.
#[cfg(windows)]
type SessionDecoder = maxsecu_media_launcher::AppContainerVideoSession;
#[cfg(not(windows))]
type SessionDecoder = maxsecu_media_launcher::VideoSubprocessSession;

// ---- worker-binary discovery (workspace target dir) -----------------------

/// Locate a built workspace binary (`media-transcode-worker` / `media-worker`) in
/// the same profile dir this test binary lives in (`target/<profile>/deps/<test>`
/// ⇒ sibling bins at `target/<profile>/`).
fn find_worker(name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let test_exe = std::env::current_exe().ok()?;
    let profile_dir = test_exe.parent()?.parent()?;
    let candidate = profile_dir.join(&exe);
    candidate.is_file().then_some(candidate)
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

/// Write a `.y4m` source into a fresh temp dir and return `(dir, path)`.
fn write_source_y4m(tag: &str, w: u32, h: u32, frames: u32, fps: u32) -> (PathBuf, PathBuf) {
    let dir = temp_dir(tag);
    let path = dir.join("source.y4m");
    std::fs::write(&path, make_y4m(w, h, frames, fps)).unwrap();
    (dir, path)
}

// ---- TLS harness (copied from upload_e2e.rs / video_upload_e2e.rs) ----------

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

/// GET one absolute `content` ciphertext chunk over TLS (the real per-chunk fetch
/// the feeder's prefetch makes). Returns the opaque ciphertext bytes.
async fn get_content_chunk(
    c: &mut Conn,
    token: &str,
    fid_hex: &str,
    version: u64,
    i: u64,
) -> Result<Vec<u8>, UiError> {
    c.sender.ready().await.unwrap();
    let uri = format!("/v1/files/{fid_hex}/versions/{version}/streams/content/chunks/{i}");
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {token}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = c.sender.send_request(req).await.unwrap();
    if resp.status() != StatusCode::OK {
        return Err(UiError::new("fetch_failed", "chunk fetch failed"));
    }
    Ok(resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec())
}

/// Drive ONE bounded playback window end-to-end exactly as
/// `commands::video::play_window_command` does, but inline so the e2e can
/// instrument the network: plan which fragments are NOT a cache hit, PREFETCH only
/// those over TLS (counting each server GET), then `feed_fragment` each fragment
/// (cache hit ⇒ no fetch) building a confined-decode `script`, run it through the
/// confined `SessionDecoder`, and RE-VALIDATE every worker frame. Returns the
/// re-validated decoded frames (so the caller can assert dims + count).
///
/// `fetch_count` is bumped once per ACTUAL server GET — a back-seek into an
/// already-cached window adds ZERO to it (the cache-hit gate).
#[allow(clippy::too_many_arguments)]
async fn play_window(
    c: &mut Conn,
    token: &str,
    fid_hex: &str,
    version: u64,
    index: &[FragmentEntry],
    cache: &mut FragmentCache,
    decryptor: &ContentDecryptor,
    decode_worker: &PathBuf,
    start: u32,
    count: u32,
    fetch_count: &mut u32,
) -> Result<Vec<maxsecu_client_core::I420Frame>, UiError> {
    let n = index.len() as u32;
    assert!(n > 0 && start < n, "window start in range");
    let end = start.saturating_add(count).min(n);

    // Phase A — plan: a fragment whose ciphertext is already cached needs NO fetch
    // (mirrors the feeder's hit condition). This is what makes a back-seek free.
    let mut fetch_indices: Vec<u64> = Vec::new();
    for seq in start..end {
        let (cs, cl) = chunks_for_fragment(index, seq).ok_or_else(|| UiError::new("e", "e"))?;
        if !cache.contains(fid_hex, seq) {
            fetch_indices.extend(cs..(cs + cl));
        }
    }

    // Phase B — prefetch the missing ciphertext chunks over TLS (one counted GET
    // each). A fully-cached window contributes nothing here ⇒ no network.
    let mut prefetched: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();
    for i in fetch_indices {
        let bytes = get_content_chunk(c, token, fid_hex, version, i).await?;
        *fetch_count += 1;
        prefetched.insert(i, bytes);
    }

    // Phase C — decrypt the window IN THE TCB into a confined-decode script. On a
    // cache hit `feed_fragment` reads the stored ciphertext and never calls the
    // fetch closure; on a miss it pulls the prefetched ciphertext and caches it.
    let mut script = vec![ClientMsg::Open {
        bounds: VideoBounds::default(),
    }];
    for seq in start..end {
        feed_fragment(
            index,
            cache,
            decryptor,
            fid_hex,
            seq,
            |i| {
                prefetched
                    .remove(&i)
                    .ok_or_else(|| UiError::new("fetch_failed", "missing prefetched chunk"))
            },
            |pt| {
                script.push(ClientMsg::Fragment {
                    seq,
                    bytes: pt.to_vec(),
                });
                Ok(())
            },
        )?;
    }
    script.push(ClientMsg::Close);

    // Phase D — decode in the CONFINED session + re-validate every worker frame in
    // this (trusted) process before it counts (spec §7), exactly as `decode_and_emit`.
    let out = SessionDecoder::new(decode_worker)
        .run_session(&script)
        .map_err(|_| UiError::new("video_failed", "confined decode failed"))?;
    let bounds = VideoBounds::default();
    let mut frames = Vec::new();
    for m in out {
        match m {
            WorkerMsg::Video(f) => {
                validate_i420(&f, &bounds)
                    .map_err(|_| UiError::new("video_failed", "frame re-validation failed"))?;
                frames.push(f);
            }
            WorkerMsg::Error(_) => return Err(UiError::new("video_failed", "worker error")),
            _ => {}
        }
    }
    Ok(frames)
}

#[tokio::test]
async fn phase7_video_author_to_view_over_real_tls() {
    // ---- worker binaries (skip the spawn gates if a bare -p run did not build them) ----
    let Some(transcode_worker) = find_worker("media-transcode-worker") else {
        eprintln!(
            "SKIP phase7_video_author_to_view_over_real_tls: media-transcode-worker binary not \
             found in the target dir (build it, e.g. `cargo build -p maxsecu-media-transcode-worker \
             -p maxsecu-media-worker`, to exercise the confined transcode + decode)."
        );
        return;
    };
    let Some(decode_worker) = find_worker("media-worker") else {
        eprintln!(
            "SKIP phase7_video_author_to_view_over_real_tls: media-worker (decode) binary not \
             found in the target dir."
        );
        return;
    };
    let Some(ffmpeg) = vendored_ffmpeg() else {
        eprintln!(
            "SKIP phase7_video_author_to_view_over_real_tls: vendored ffmpeg \
             (vendor/ffmpeg/ffmpeg.exe) not present; run scripts/fetch-ffmpeg.ps1 to exercise the \
             confined ffmpeg ingest."
        );
        return;
    };

    // A 64x64 clip spanning SEVERAL GOPs so seek + back-seek are meaningful: a
    // canonical fragment is one closed GOP (DEFAULT_GOP=48 frames), so ~200 frames
    // yields >=5 fragments (keyframes at 0,48,96,144,192).
    let (w, h, frames, fps) = (64u32, 64u32, 200u32, 24u32);
    let (src_dir, source_path) = write_source_y4m("view", w, h, frames, fps);

    // ---- GATE 1 (a): confined ffmpeg ingest + re-mux (NO network yet) ----
    let (streams, fragments) = prepare_video_streams(
        &source_path,
        &ffmpeg,
        &transcode_worker,
        &TranscodeOptions::default(),
        &VideoBounds::default(),
        "Holiday clip",
        &["beach".to_owned()],
    )
    .expect("GATE 1: the confined ffmpeg + re-mux produced canonical streams");
    let _ = std::fs::remove_dir_all(&src_dir);
    assert!(
        fragments.len() >= 5,
        "GATE 1: the source spans several GOPs → multiple canonical fragments (got {})",
        fragments.len()
    );
    let canonical = streams.content.clone();
    assert!(
        !canonical.is_empty() && canonical.len() % CHUNK == 0,
        "GATE 1: canonical content is whole 4096-byte chunks"
    );

    // ---- Server + pinned ceremony D5 ----
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxvidview_{}",
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

    // ---- Author + recovery: register, login, publish D5 bindings ----
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

    // ---- GATE 1 (b): build_upload(Video, 4096) + run_pipeline → the video is on the server ----
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id,
            file_type: FileType::Video,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
            recovery_mlkem_pub: rr.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &streams,
    )
    .unwrap();
    run_pipeline(&mut c.sender, "localhost", &token, &bundle, |_d, _t| {})
        .await
        .expect("GATE 1: video upload pipeline succeeds");

    // ---- GATE 2: browse — the D35 listing returns the video (file_type=video) ----
    let (st, listing) = get_json(&mut c, "/v1/files?type=video&limit=50", &token).await;
    assert_eq!(st, StatusCode::OK, "GATE 2: video listing");
    let files = listing["files"].as_array().expect("listing array");
    let listed = files
        .iter()
        .find(|f| f["file_id"].as_str() == Some(fid_hex.as_str()))
        .expect("GATE 2: the uploaded video is listed");
    assert_eq!(
        listed["file_type"].as_str(),
        Some("video"),
        "GATE 2: listing marks it a video so the viewer resolves it"
    );

    // ===================================================================
    // GATE 3: VIEW — the REAL open_video path (fetch ciphertext → decrypt in the
    // TCB → decode in the confined worker → re-validate → frames).
    // ===================================================================

    // (a) fetch the file view + parse it (no decrypt).
    let (st, view_json) = get_json(
        &mut c,
        &format!("/v1/files/{fid_hex}?version=latest"),
        &token,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "GATE 3: file view");
    let view = parse_file_view(&view_json).unwrap();
    let manifest: Manifest = decode(&view.manifest_bytes).expect("manifest decodes");

    // (b) resolve + D5-verify the author BEFORE any decode.
    let author = resolve_and_verify_author(
        &mut c.sender,
        "localhost",
        &hex(&manifest.author_id.0),
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();
    assert_eq!(
        author.sig_pub,
        owner.sig_pub_bytes(),
        "GATE 3: D5-verified author key matches the uploader"
    );
    let my_id = resolve_my_user_id(
        &mut c.sender,
        "localhost",
        "alice",
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();
    assert_eq!(
        my_id, user_id,
        "GATE 3: my own id resolves under the pinned D5"
    );

    // (c) header (small streams only — no content fetched here).
    let header: StreamHeader =
        build_stream_header(&mut c.sender, "localhost", &token, &fid_hex, &view)
            .await
            .unwrap();

    // (d) the TCB header ladder, exactly as `open_video_job_core`: verify the header,
    //     parse the AUTHENTICATED fragment index from the metadata plaintext, and
    //     derive the in-TCB content decryptor. `file_id` is the REQUESTED id (the
    //     ladder binds the served record to it).
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened = verify_and_open_headers(&ctx, &header).expect("GATE 3: header ladder opens");
    let meta = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .expect("metadata stream present");
    let meta_json: serde_json::Value = serde_json::from_slice(&meta.plaintext).unwrap();
    let index = parse_fragment_index(&meta_json).expect("GATE 3: authenticated fragment index");
    assert_eq!(
        index.len(),
        fragments.len(),
        "GATE 3: the authenticated fragment index matches the transcode output"
    );
    let decryptor = open_content_decryptor(&ctx, &header).expect("GATE 3: content decryptor");
    let version = decryptor.version();

    // (e) the on-disk ciphertext fragment cache (the back-seek's no-refetch store).
    let cache_dir = std::env::temp_dir().join(format!(
        "mxvidcache_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let mut cache = FragmentCache::open(&cache_dir, 8 * 1024 * 1024).unwrap();

    // (f) play the initial bounded window through the CONFINED decode session +
    //     re-validate every frame back to the source dims (16x16).
    let mut fetch_count = 0u32;
    let window0_frames = play_window(
        &mut c,
        &token,
        &fid_hex,
        version,
        &index,
        &mut cache,
        &decryptor,
        &decode_worker,
        0,
        PLAY_WINDOW,
        &mut fetch_count,
    )
    .await
    .expect("GATE 3: the confined decode session plays the initial window");
    // A canonical fragment is a whole GOP, so the window decodes to MANY frames (the
    // sum of the GOPs' frame counts), not one-per-fragment. Assert it decoded to at
    // least one frame and every frame is the source dims.
    assert!(
        !window0_frames.is_empty(),
        "GATE 3: the initial window decoded to frames"
    );
    let window0_count = window0_frames.len();
    for f in &window0_frames {
        assert_eq!(
            (f.width, f.height),
            (w, h),
            "GATE 3: frame decodes back to the source dims through the confined worker"
        );
    }
    assert!(
        fetch_count > 0,
        "GATE 3: the initial (uncached) window fetched ciphertext over the network"
    );
    let after_window0 = fetch_count;

    // ===================================================================
    // GATE 4: SEEK — map a later pts to its fragment and play that window.
    // ===================================================================
    let last = index.last().unwrap();
    let seek_seq = fragment_for_time(&index, last.pts_ms).expect("GATE 4: pts maps to a fragment");
    assert_eq!(
        seek_seq,
        index.len() as u32 - 1,
        "GATE 4: the last fragment's pts maps to the last fragment"
    );
    // The last fragment is NOT in the initial window (window covered 0..4, last == 4),
    // so this is a genuine forward seek that fetches the mapped fragment's ciphertext.
    assert!(
        !cache.contains(&fid_hex, seek_seq),
        "GATE 4: the seeked fragment was not in the initial window's cache"
    );
    let seek_frames = play_window(
        &mut c,
        &token,
        &fid_hex,
        version,
        &index,
        &mut cache,
        &decryptor,
        &decode_worker,
        seek_seq,
        PLAY_WINDOW,
        &mut fetch_count,
    )
    .await
    .expect("GATE 4: the seeked window plays");
    // Only the mapped (last) fragment is in this window; it decodes to >=1 frame (its
    // GOP), all at the source dims.
    assert!(
        !seek_frames.is_empty(),
        "GATE 4: the mapped (last) fragment decoded to frames"
    );
    for f in &seek_frames {
        assert_eq!((f.width, f.height), (w, h));
    }
    assert!(
        fetch_count > after_window0,
        "GATE 4: the forward seek fetched the mapped fragment's ciphertext"
    );
    let after_seek = fetch_count;

    // ===================================================================
    // GATE 5: BACK-SEEK hits the ciphertext cache — NO re-fetch + at-rest ciphertext.
    // ===================================================================
    // Re-play the initial window (fragments 0..4): every fragment is already cached,
    // so the feeder re-reads the stored CIPHERTEXT and performs ZERO new server GETs.
    let back_frames = play_window(
        &mut c,
        &token,
        &fid_hex,
        version,
        &index,
        &mut cache,
        &decryptor,
        &decode_worker,
        0,
        PLAY_WINDOW,
        &mut fetch_count,
    )
    .await
    .expect("GATE 5: the back-seek window plays from cache");
    assert_eq!(
        back_frames.len(),
        window0_count,
        "GATE 5: the back-seek re-decoded the cached window to the same frames"
    );
    assert_eq!(
        fetch_count, after_seek,
        "GATE 5: the back-seek into the cached window performed NO new server GET"
    );

    // The on-disk cache holds CIPHERTEXT, never the decoded plaintext. Fragment 0's
    // plaintext is `canonical[chunk_start*CHUNK .. (chunk_start+chunk_len)*CHUNK]`.
    let f0 = &index[0];
    let p_start = f0.chunk_start as usize * CHUNK;
    let p_end = (f0.chunk_start + f0.chunk_len) as usize * CHUNK;
    let plaintext0 = &canonical[p_start..p_end];
    let cached0 = cache
        .get(&fid_hex, 0)
        .expect("GATE 5: fragment 0's ciphertext is cached");
    assert_ne!(
        cached0.as_slice(),
        plaintext0,
        "GATE 5: the cached blob is not the decoded plaintext"
    );
    assert!(
        !cached0
            .windows(plaintext0.len().max(1))
            .any(|win| win == plaintext0),
        "GATE 5: the decoded plaintext never appears in the at-rest ciphertext blob"
    );

    // ===================================================================
    // GATE 6 (cheap extra): a forged author binding fails closed (`untrusted`).
    // ===================================================================
    {
        let pb = ceremony.sign_binding(
            "alice",
            user_id,
            owner.enc_pub_bytes(),
            owner.sig_pub_bytes(),
            &[Role::User],
            1,
        );
        let attacker = maxsecu_crypto::SigningKey::generate();
        let forged = attacker.sign_canonical(
            labels::DIRBINDING,
            &decode::<DirBinding>(&pb.binding_bytes).unwrap(),
        );
        let mut fresh = MemoryTrustStore::new();
        assert_eq!(
            verify_author_binding(&verifier, &mut fresh, &pb.binding_bytes, &forged, TS)
                .unwrap_err()
                .code,
            "untrusted",
            "GATE 6: a binding signed by a non-D5 key is untrusted (fail-closed)"
        );
    }

    let _ = std::fs::remove_dir_all(&blob_dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
}
