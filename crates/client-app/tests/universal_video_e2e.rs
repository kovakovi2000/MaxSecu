//! Universal-video-ingest **capstone** end-to-end test (Task 7.1) over REAL
//! loopback TLS — the whole pipeline on REAL video files, WITH AUDIO + A/V sync,
//! exercising the PRODUCTION decrypt-while-play emission path that the existing
//! video e2e tests do NOT cover.
//!
//! The existing `video_e2e.rs` drives an inline `play_window` that calls the
//! confined decoder's `run_session` and discards audio + `EndOfFragment` framing +
//! the window-relative pts offset. The production viewer (`commands::video`) instead
//! runs `decode_and_emit`, which (a) drives the RESILIENT decode driver
//! (`run_session_resilient`), (b) emits AUDIO (`PcmDto`) as well as video, (c)
//! applies the Task-5.2 window-relative pts offset so frames carry a single
//! monotonic timeline across fragment boundaries, and (d) bounds the in-flight
//! decoded-frame RAM (Task-6, `push_bounded`). `decode_and_emit` is a private
//! `async fn`, and this task forbids changing production code to expose it — so this
//! test drives the maximal REAL production surface (the embedded `ensure_ffmpeg`, the
//! confined `prepare_video_streams`, the full upload pipeline, the TCB header ladder +
//! `ContentDecryptor` + authenticated fragment index, `feed_fragment`
//! decrypt-while-play, and the REAL confined `AppContainerVideoSession` decoder via
//! `run_session_resilient` — the exact decode driver `decode_and_emit` uses) and
//! MIRRORS, verbatim, only `decode_and_emit`'s small post-decode emission glue
//! (`window_offset_ms` + the `EndOfFragment`-keyed flush + `push_bounded`). Every
//! GATE below is asserted on `I420FrameDto`/`PcmDto`/`PlayerPhase` produced by the
//! REAL confined decoder over the REAL decrypt path.
//!
//! Three cases (spec §11 e2e + the A/V-sync proof):
//!
//! * **Case A — canonical, WITH AUDIO + A/V sync** (the real
//!   `D:\Images\ttget-…hd….mp4`, H.264+AAC, 720×1280 portrait, ~10s, 24 fps): decoded
//!   geometry == the (even) source dims; ≥1 `PcmDto` with `channels==2` + a sane
//!   sample rate + non-empty samples (AAC→PCM end to end); video frame `pts_ms` are
//!   REAL (consecutive frames differ by ≈ the real frame duration, NOT a 0,1,2
//!   counter), MONOTONIC across fragment boundaries, and SPAN ≈ the window's real
//!   duration (the Task-5.2 window-relative offset); and a back-seek replays an
//!   earlier window from the ciphertext cache with ZERO new server GETs.
//! * **Case B — extreme / high-res (D-7)**: a SHORT synthesized 2560×1440 clip
//!   (`testsrc` + `sine`, 2s, via the vendored ffmpeg — chosen over a real `D:\Images`
//!   file because `prepare_video_streams` transcodes the WHOLE input with no duration
//!   cap, and a synthesized short clip keeps the test fast AND deterministically
//!   high-res with audio). Transcodes + uploads + decodes WITHOUT OOM/hang (the
//!   bounded delivery holds — `PlayerPhase::Gap` is benign), decoded geometry is the
//!   (even) high-res dims, and audio emits PCM.
//! * **Case C — resolution change**: stage the canonical file with
//!   `resolution = Height(720), bitrate = Original` and assert the decoded dims reflect
//!   the requested downscale (height 720, even width, narrower than Case A) — the D-5
//!   menu driving the real ffmpeg argv end to end.
//!
//! Spawns real confined processes (ffmpeg + the workers) → run single-threaded
//! (`-- --test-threads=1`). SKIPS cleanly (with a printed note) if the embedded
//! ffmpeg, a worker binary, or the `D:\Images` sample is absent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
use maxsecu_client_app::commands::video::{I420FrameDto, PcmDto};
use maxsecu_client_app::directory::{
    resolve_and_verify_author, resolve_my_user_id, resolve_recovery_recipient, RecoveryRecipient,
};
use maxsecu_client_app::download::{build_stream_header, parse_file_view};
use maxsecu_client_app::error::UiError;
use maxsecu_client_app::ffmpeg_bin::ensure_ffmpeg;
use maxsecu_client_app::fragment_cache::FragmentCache;
use maxsecu_client_app::state::PlayerPhase;
use maxsecu_client_app::upload::{prepare_video_streams, run_pipeline};
use maxsecu_client_app::video::{chunks_for_fragment, feed_fragment, parse_fragment_index, FragmentEntry};
use maxsecu_client_core::video::{
    validate_i420, validate_pcm, ClientMsg, I420Frame, PcmChunk, VideoBounds, WorkerMsg,
};
use maxsecu_client_core::{
    build_upload, open_content_decryptor, verify_and_open_headers, ContentDecryptor,
    DirectoryVerifier, Identity, MemoryTrustStore, PlaintextStreams, StreamHeader, UploadParams,
    VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey};
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::{FileType, Id, RecipientType, Role, StreamType, Timestamp};
use maxsecu_encoding::{decode, labels};
use maxsecu_media_launcher::{
    Bitrate, Resolution, TranscodeOptions, VideoSessionDecoder, MAX_RESPAWNS_PER_WINDOW,
};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const VOUCHER: &str = "in-person-code-001";
const VOUCHER2: &str = "in-person-code-002";
const TS: u64 = 1_719_500_000_000;
const CHUNK: usize = 4096; // == upload chunk_size == TRANSCODE_CHUNK_SIZE
const PLAY_WINDOW: u32 = 4; // mirrors commands::video::PLAY_WINDOW

/// The real canonical Case-A source (H.264+AAC, 720×1280, ~10s, 24 fps, real audio).
const TTGET: &str = r"D:\Images\ttget-7604733407821771146-video-hd-ttget.com.mp4";

// ---- the production confined-decode session type (AppContainer on Windows) ----
//
// Exactly the alias `commands::video::SessionDecoder` resolves to. Both link NO
// codecs (the codecs live only in the spawned `media-worker`); we drive whichever
// this platform uses via `run_session_resilient` — the SAME resilient decode driver
// `commands::video::decode_and_emit` calls in production.
#[cfg(windows)]
type SessionDecoder = maxsecu_media_launcher::AppContainerVideoSession;
#[cfg(not(windows))]
type SessionDecoder = maxsecu_media_launcher::VideoSubprocessSession;

// ===========================================================================
// `decode_and_emit` post-decode glue, mirrored VERBATIM from `commands/video.rs`
// (it is a private `async fn`; this task forbids exposing it). The REAL confined
// decoder + the REAL decrypt path feed this; only this thin emission/offset/bound
// arithmetic is reproduced here.
// ===========================================================================

/// D-7 backpressure ceiling — verbatim from `commands::video::MAX_FRAME_BUF_BYTES`.
const MAX_FRAME_BUF_BYTES: usize = 64 * 1024 * 1024;

/// Verbatim from `commands::video::window_offset_ms`: the window-relative base (ms)
/// for fragment `seq` from the AUTHENTICATED index.
fn window_offset_ms(index: &[FragmentEntry], seq: u32, window_start_pts: u64) -> u64 {
    index
        .iter()
        .find(|e| e.seq == seq)
        .map(|e| e.pts_ms.saturating_sub(window_start_pts))
        .unwrap_or(0)
}

/// Verbatim from `commands::video::frame_bytes`.
fn frame_bytes(f: &I420Frame) -> usize {
    f.y.len() + f.u.len() + f.v.len()
}

/// Verbatim from `commands::video::push_bounded`: push, then drop oldest while over
/// budget (always retaining the most recent). Returns the dropped count.
fn push_bounded(
    buf: &mut Vec<I420Frame>,
    buf_bytes: &mut usize,
    frame: I420Frame,
    budget: usize,
) -> u32 {
    *buf_bytes += frame_bytes(&frame);
    buf.push(frame);
    let mut dropped = 0u32;
    while *buf_bytes > budget && buf.len() > 1 {
        let old = buf.remove(0);
        *buf_bytes -= frame_bytes(&old);
        dropped += 1;
    }
    dropped
}

/// Verbatim from `commands::video::frame_dto`.
fn frame_dto(f: &I420Frame) -> I420FrameDto {
    I420FrameDto {
        width: f.width,
        height: f.height,
        pts_ms: f.pts_ms,
        y_b64: B64.encode(&f.y),
        u_b64: B64.encode(&f.u),
        v_b64: B64.encode(&f.v),
    }
}

/// Verbatim from `commands::video::pcm_dto`.
fn pcm_dto(p: &PcmChunk) -> PcmDto {
    let mut bytes = Vec::with_capacity(p.samples.len() * 2);
    for &s in &p.samples {
        bytes.extend_from_slice(&s.to_le_bytes());
    }
    PcmDto {
        channels: p.channels,
        sample_rate: p.sample_rate,
        pts_ms: p.pts_ms,
        samples_b64: B64.encode(&bytes),
    }
}

fn ui_err() -> UiError {
    UiError::new("video_failed", "The video could not be played.")
}

/// The PRODUCTION viewer emission path mirrored from `commands::video::decode_and_emit`:
/// run the REAL confined decoder via `run_session_resilient`, then re-validate every
/// untrusted worker output, buffer per fragment, and on each `EndOfFragment` flush
/// frames/audio with the fragment's window-relative offset applied
/// (`emitted = window_offset + worker_pts`), bounding the in-flight decoded-frame RAM.
/// Emits the same `PlayerPhase`s (Gap on respawn/skip/drop, then Playing). The decode
/// driver call, the re-validation, the offset math, and the bound are the REAL code
/// paths; only this orchestration is reproduced (the function it mirrors is private).
fn decode_and_emit_mirror(
    decode_worker: &Path,
    script: &[ClientMsg],
    frag_index: &[FragmentEntry],
    window_start_pts: u64,
    on_frame: &mut dyn FnMut(I420FrameDto),
    on_audio: &mut dyn FnMut(PcmDto),
    emit: &mut dyn FnMut(PlayerPhase),
) -> Result<(), UiError> {
    let outcome = SessionDecoder::new(decode_worker)
        .run_session_resilient(script, MAX_RESPAWNS_PER_WINDOW)
        .map_err(|_| ui_err())?;

    if outcome.respawns > 0 || !outcome.skipped.is_empty() {
        emit(PlayerPhase::Gap {
            skipped: outcome.skipped.len() as u32,
        });
    }

    let bounds = VideoBounds::default();
    let mut frame_buf: Vec<I420Frame> = Vec::new();
    let mut frame_buf_bytes = 0usize;
    let mut audio_buf: Vec<PcmChunk> = Vec::new();
    let mut dropped_frames = 0u32;
    for msg in outcome.msgs {
        match msg {
            WorkerMsg::Video(frame) => {
                validate_i420(&frame, &bounds).map_err(|_| ui_err())?;
                dropped_frames +=
                    push_bounded(&mut frame_buf, &mut frame_buf_bytes, frame, MAX_FRAME_BUF_BYTES);
            }
            WorkerMsg::Audio(chunk) => {
                validate_pcm(&chunk, &bounds).map_err(|_| ui_err())?;
                audio_buf.push(chunk);
            }
            WorkerMsg::Error(_) => return Err(ui_err()),
            WorkerMsg::EndOfFragment { seq } => {
                let base = window_offset_ms(frag_index, seq, window_start_pts);
                for frame in frame_buf.drain(..) {
                    let mut dto = frame_dto(&frame);
                    dto.pts_ms = base.saturating_add(frame.pts_ms);
                    on_frame(dto);
                }
                frame_buf_bytes = 0;
                for chunk in audio_buf.drain(..) {
                    let mut dto = pcm_dto(&chunk);
                    dto.pts_ms = base.saturating_add(chunk.pts_ms);
                    on_audio(dto);
                }
            }
            WorkerMsg::Ready => {}
        }
    }

    if dropped_frames > 0 {
        emit(PlayerPhase::Gap {
            skipped: dropped_frames,
        });
    }
    emit(PlayerPhase::Playing);
    Ok(())
}

/// The decoded outputs of one bounded playback window (what crossed the seam).
#[derive(Default)]
struct WindowOut {
    /// `(pts_ms, width, height)` per emitted video frame, in emission order. (We keep
    /// only the geometry + timeline summary; the full base64 `I420FrameDto` IS built
    /// by the production-mirror emit path, then dropped — avoids retaining hundreds of
    /// MB of pixels while still proving the seam DTO constructs.)
    frames: Vec<(u64, u32, u32)>,
    /// Every emitted audio chunk DTO (small; kept whole for the channels/rate gate).
    audio: Vec<PcmDto>,
    /// The `PlayerPhase`s emitted, in order.
    phases: Vec<PlayerPhase>,
    /// Whether at least one frame DTO carried non-empty base64 luma (real pixels).
    y_nonempty: bool,
}

impl WindowOut {
    fn saw_playing(&self) -> bool {
        self.phases
            .iter()
            .any(|p| matches!(p, PlayerPhase::Playing))
    }
    fn saw_error(&self) -> bool {
        self.phases.iter().any(|p| matches!(p, PlayerPhase::Error { .. }))
    }
    fn gap_total(&self) -> u32 {
        self.phases
            .iter()
            .map(|p| match p {
                PlayerPhase::Gap { skipped } => *skipped,
                _ => 0,
            })
            .sum()
    }
}

/// Drive ONE bounded window end-to-end through the PRODUCTION viewer path, mirroring
/// `commands::video::play_window_command` (Phases A–D): plan (cache-hit ⇒ no fetch),
/// prefetch the missing ciphertext over TLS (counting GETs), decrypt-while-play via
/// the REAL `feed_fragment`, then decode+emit via [`decode_and_emit_mirror`]. A
/// back-seek into an already-cached window adds ZERO to `fetch_count`.
#[allow(clippy::too_many_arguments)]
async fn play_window_emit(
    c: &mut Conn,
    token: &str,
    fid_hex: &str,
    version: u64,
    index: &[FragmentEntry],
    cache: &mut FragmentCache,
    decryptor: &ContentDecryptor,
    decode_worker: &Path,
    start: u32,
    count: u32,
    fetch_count: &mut u32,
) -> Result<WindowOut, UiError> {
    let n = index.len() as u32;
    assert!(n > 0 && start < n, "window start in range");
    let end = start.saturating_add(count).min(n);

    // Phase A — plan: a fragment whose ciphertext is already cached needs no fetch.
    let mut fetch_indices: Vec<u64> = Vec::new();
    for seq in start..end {
        let (cs, cl) = chunks_for_fragment(index, seq).ok_or_else(ui_err)?;
        if !cache.contains(fid_hex, seq) {
            fetch_indices.extend(cs..(cs + cl));
        }
    }

    // Phase B — prefetch the missing ciphertext chunks over TLS (one counted GET each).
    let mut prefetched: HashMap<u64, Vec<u8>> = HashMap::new();
    for i in fetch_indices {
        let bytes = get_content_chunk(c, token, fid_hex, version, i).await?;
        *fetch_count += 1;
        prefetched.insert(i, bytes);
    }

    // Phase C — decrypt the window IN THE TCB into a confined-decode script; capture
    // the window's first-fragment pts for the window-relative offset.
    let window_start_pts = index.get(start as usize).map(|e| e.pts_ms).unwrap_or(0);
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
            |i| prefetched.remove(&i).ok_or_else(ui_err),
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

    // Phase D — decode in the CONFINED session + re-validate + emit (the production glue).
    let mut frames: Vec<(u64, u32, u32)> = Vec::new();
    let mut audio: Vec<PcmDto> = Vec::new();
    let mut phases: Vec<PlayerPhase> = Vec::new();
    let mut y_nonempty = false;
    phases.push(PlayerPhase::Buffering); // production emits this on entry to decrypt_window
    {
        let mut on_frame = |d: I420FrameDto| {
            if !d.y_b64.is_empty() {
                y_nonempty = true;
            }
            frames.push((d.pts_ms, d.width, d.height));
        };
        let mut on_audio = |d: PcmDto| audio.push(d);
        let mut emit = |p: PlayerPhase| phases.push(p);
        decode_and_emit_mirror(
            decode_worker,
            &script,
            index,
            window_start_pts,
            &mut on_frame,
            &mut on_audio,
            &mut emit,
        )?;
    }
    Ok(WindowOut {
        frames,
        audio,
        phases,
        y_nonempty,
    })
}

// ---- worker-binary discovery (workspace target dir) -----------------------

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

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mxunividing-{tag}-{}-{}",
        std::process::id(),
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Synthesize a SHORT high-res `.mp4` (H.264 + AAC) via the vendored ffmpeg's lavfi
/// `testsrc` + `sine` — the Case-B extreme source. Returns `None` if the ffmpeg run
/// fails (so Case B can be reported, never hangs the suite).
fn synthesize_highres(ffmpeg: &Path, dir: &Path, w: u32, h: u32, secs: u32) -> Option<PathBuf> {
    let out = dir.join("highres.mp4");
    let status = std::process::Command::new(ffmpeg)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            &format!("testsrc=size={w}x{h}:rate=30:duration={secs}"),
            "-f",
            "lavfi",
            "-i",
            &format!("sine=frequency=440:duration={secs}"),
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-ac",
            "2",
            "-shortest",
        ])
        .arg(&out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    (status.success() && out.is_file()).then_some(out)
}

// ---- TLS harness (copied from video_e2e.rs) -------------------------------

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

/// GET one absolute `content` ciphertext chunk over TLS (the feeder's per-chunk fetch).
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
    Ok(resp.into_body().collect().await.unwrap().to_bytes().to_vec())
}

/// `build_upload(Video, 4096)` + `run_pipeline` over TLS — the real author confirm
/// pipeline. Returns the file id + its lowercase-hex form.
async fn stage_video(
    c: &mut Conn,
    owner: &Identity,
    user_id: [u8; 16],
    token: &str,
    rr: &RecoveryRecipient,
    streams: &PlaintextStreams,
) -> (Id, String) {
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let bundle = build_upload(
        &UploadParams {
            owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id,
            file_type: FileType::Video,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
            recovery_mlkem_pub: rr.mlkem_pub,
            created_at: Timestamp(TS),
        },
        streams,
    )
    .unwrap();
    run_pipeline(&mut c.sender, "localhost", token, &bundle, |_d, _t| {})
        .await
        .expect("video upload pipeline succeeds");
    (file_id, fid_hex)
}

/// The PRODUCTION view-open TCB ladder (mirrors `commands::video::open_video_inner` +
/// `open_video_job_core`): fetch the view, D5-verify the author + self, build the
/// header, run `verify_and_open_headers`, parse the AUTHENTICATED fragment index, and
/// derive the in-TCB `ContentDecryptor`. Returns `(index, decryptor, version)`.
#[allow(clippy::too_many_arguments)]
async fn open_view_session(
    c: &mut Conn,
    owner: &Identity,
    username: &str,
    user_id: [u8; 16],
    fid_hex: &str,
    file_id: Id,
    verifier: &DirectoryVerifier,
    trust: &mut MemoryTrustStore,
    token: &str,
) -> (Vec<FragmentEntry>, ContentDecryptor, u64) {
    let (st, view_json) = get_json(c, &format!("/v1/files/{fid_hex}?version=latest"), token).await;
    assert_eq!(st, StatusCode::OK, "file view");
    let view = parse_file_view(&view_json).unwrap();
    let manifest: Manifest = decode(&view.manifest_bytes).expect("manifest decodes");

    let author = resolve_and_verify_author(
        &mut c.sender,
        "localhost",
        &hex(&manifest.author_id.0),
        verifier,
        trust,
        TS,
    )
    .await
    .unwrap();
    assert_eq!(
        author.sig_pub,
        owner.sig_pub_bytes(),
        "D5-verified author key matches the uploader"
    );
    let my_id = resolve_my_user_id(&mut c.sender, "localhost", username, verifier, trust, TS)
        .await
        .unwrap();
    assert_eq!(my_id, user_id, "my own id resolves under the pinned D5");

    let header: StreamHeader = build_stream_header(&mut c.sender, "localhost", token, fid_hex, &view)
        .await
        .unwrap();
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
    let opened = verify_and_open_headers(&ctx, &header).expect("header ladder opens");
    let meta = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .expect("metadata stream present");
    let meta_json: serde_json::Value = serde_json::from_slice(&meta.plaintext).unwrap();
    let index = parse_fragment_index(&meta_json).expect("authenticated fragment index");
    let decryptor = open_content_decryptor(&ctx, &header).expect("content decryptor");
    let version = decryptor.version();
    (index, decryptor, version)
}

// ---- shared server/identity scaffolding -----------------------------------

struct Harness {
    c: Conn,
    owner: Identity,
    user_id: [u8; 16],
    token: String,
    rr: RecoveryRecipient,
    verifier: DirectoryVerifier,
    blob_dir: PathBuf,
}

async fn boot_harness(pki: &TestPki) -> Harness {
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxunivid_{}",
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

    Harness {
        c,
        owner,
        user_id,
        token,
        rr,
        verifier,
        blob_dir,
    }
}

// Capstone: three real preset-8 AV1 transcodes via confined ffmpeg + confined decode
// workers over real TLS — ~15-20 min. Marked #[ignore] so routine `cargo test` skips it;
// run explicitly: `cargo test -p maxsecu-client-app --test universal_video_e2e -- --ignored --test-threads=1`.
#[tokio::test]
#[ignore = "capstone: ~15-20 min real ffmpeg transcodes; run explicitly with --ignored"]
async fn universal_video_ingest_capstone_over_real_tls() {
    // ---- preconditions (skip cleanly if anything is absent) ----
    let Some(_transcode_worker) = find_worker("media-transcode-worker") else {
        eprintln!(
            "SKIP universal_video_ingest_capstone: media-transcode-worker binary not found \
             (build it: `cargo build -p maxsecu-media-transcode-worker -p maxsecu-media-worker`)."
        );
        return;
    };
    let Some(decode_worker) = find_worker("media-worker") else {
        eprintln!("SKIP universal_video_ingest_capstone: media-worker (decode) binary not found.");
        return;
    };
    // The PRODUCTION embedded ffmpeg materialization (step 1: ensure_ffmpeg(appdir)).
    let app_dir = temp_dir("appdir");
    let Ok(ffmpeg) = ensure_ffmpeg(&app_dir) else {
        eprintln!(
            "SKIP universal_video_ingest_capstone: embedded ffmpeg unavailable (no \
             vendor/ffmpeg/ffmpeg.exe at build time / embed-ffmpeg off)."
        );
        let _ = std::fs::remove_dir_all(&app_dir);
        return;
    };
    let ttget = PathBuf::from(TTGET);
    if !ttget.is_file() {
        eprintln!("SKIP universal_video_ingest_capstone: sample {TTGET} not present.");
        let _ = std::fs::remove_dir_all(&app_dir);
        return;
    }

    let pki = test_pki();
    let mut h = boot_harness(&pki).await;

    // =====================================================================
    // CASE A — canonical, WITH AUDIO + A/V sync (the real ttget mp4).
    // =====================================================================
    eprintln!("[case A] transcoding the real ttget source (720x1280, 24fps, ~10s, AAC stereo)…");
    let (a_streams, a_fragments) = prepare_video_streams(
        &ttget,
        &ffmpeg,
        &TranscodeOptions::default(), // Original/Original
        &VideoBounds::default(),
        "Holiday clip",
        &["beach".to_owned()],
        |_p| {},                                    // no-op progress sink (not asserted here)
        &std::sync::atomic::AtomicBool::new(false), // never cancelled
    )
    .expect("CASE A: confined ffmpeg + re-mux produced canonical AV1/AAC streams");
    assert!(
        a_fragments.len() >= 2,
        "CASE A: ttget spans multiple fragments so the A/V-sync proof crosses a boundary (got {})",
        a_fragments.len()
    );
    assert!(
        !a_streams.content.is_empty() && a_streams.content.len().is_multiple_of(CHUNK),
        "CASE A: canonical content is whole 4096-byte chunks"
    );

    let (a_file_id, a_fid) =
        stage_video(&mut h.c, &h.owner, h.user_id, &h.token, &h.rr, &a_streams).await;
    let mut trust = MemoryTrustStore::new();
    let (a_index, a_decryptor, a_version) = open_view_session(
        &mut h.c,
        &h.owner,
        "alice",
        h.user_id,
        &a_fid,
        a_file_id,
        &h.verifier,
        &mut trust,
        &h.token,
    )
    .await;
    assert_eq!(
        a_index.len(),
        a_fragments.len(),
        "CASE A: authenticated fragment index matches the transcode output"
    );

    let cache_dir = temp_dir("cacheA");
    let mut cache = FragmentCache::open(&cache_dir, 32 * 1024 * 1024).unwrap();
    let mut fetch_count = 0u32;
    let win0 = play_window_emit(
        &mut h.c,
        &h.token,
        &a_fid,
        a_version,
        &a_index,
        &mut cache,
        &a_decryptor,
        &decode_worker,
        0,
        PLAY_WINDOW,
        &mut fetch_count,
    )
    .await
    .expect("CASE A: the production viewer path plays the initial window");

    // -- GATE A1: geometry (even dims matching the source after even-coercion) --
    assert!(!win0.frames.is_empty(), "CASE A: the window decoded to frames");
    let (a_w, a_h) = (win0.frames[0].1, win0.frames[0].2);
    assert!(a_w.is_multiple_of(2) && a_h.is_multiple_of(2), "CASE A: even dims");
    for &(_, w, hgt) in &win0.frames {
        assert_eq!((w, hgt), (a_w, a_h), "CASE A: consistent decoded geometry");
    }
    assert_eq!(
        (a_w, a_h),
        (720, 1280),
        "CASE A: decoded geometry matches the 720x1280 source"
    );
    assert!(win0.y_nonempty, "CASE A: emitted frame DTOs carry real pixels");
    assert!(fetch_count > 0, "CASE A: the initial window fetched ciphertext");
    assert!(win0.saw_playing() && !win0.saw_error(), "CASE A: clean Playing");
    eprintln!("[case A] GATE geometry: decoded {a_w}x{a_h}, {} frames", win0.frames.len());

    // -- GATE A2: AUDIO — ≥1 PcmDto, stereo, sane rate, non-empty (AAC→PCM e2e) --
    assert!(
        !win0.audio.is_empty(),
        "CASE A (AUDIO): the AAC track decoded to ≥1 PCM chunk over the production path"
    );
    let pcm = &win0.audio[0];
    assert_eq!(pcm.channels, 2, "CASE A (AUDIO): stereo PCM");
    assert!(
        matches!(pcm.sample_rate, 44_100 | 48_000),
        "CASE A (AUDIO): sane sample rate (got {})",
        pcm.sample_rate
    );
    assert!(
        !pcm.samples_b64.is_empty(),
        "CASE A (AUDIO): non-empty samples"
    );
    eprintln!(
        "[case A] GATE audio: {} PcmDto(s), channels={}, sample_rate={}, first samples_b64 len={}",
        win0.audio.len(),
        pcm.channels,
        pcm.sample_rate,
        pcm.samples_b64.len()
    );

    // -- GATE A3: A/V timing is REAL + window-relative (the Task-5.2 offset) --
    let pts: Vec<u64> = win0.frames.iter().map(|f| f.0).collect();
    // (a) monotonic non-decreasing across all fragments in the window.
    assert!(
        pts.windows(2).all(|w| w[1] >= w[0]),
        "CASE A (A/V): frame pts are monotonic across fragment boundaries"
    );
    // (b) NOT a 0,1,2 counter: consecutive frames differ by ≈ the real frame
    //     duration (24 fps ⇒ ~41 ms), so SOME delta is ≥ 10 ms.
    let max_delta = pts.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0);
    assert!(
        max_delta >= 10,
        "CASE A (A/V): a real inter-frame delta (got max {max_delta} ms) — not a 1-ms counter"
    );
    // (c) span ≈ the window's REAL duration, not ≈ N milliseconds. With the Task-5.2
    //     window-relative offset, frames from later fragments carry the index-derived
    //     base (index[k].pts_ms - window_start), so the span reaches into the window's
    //     LAST fragment's timeline. Without the offset, later fragments would restart
    //     near 0 and the span would collapse to one fragment's duration.
    let span = *pts.last().unwrap() - *pts.first().unwrap();
    let end = PLAY_WINDOW.min(a_index.len() as u32);
    let last_base = a_index[(end - 1) as usize].pts_ms - a_index[0].pts_ms;
    assert!(
        span >= last_base && last_base > 0,
        "CASE A (A/V): pts span {span} ms reaches the last window fragment's base {last_base} ms \
         (window-relative offset applied)"
    );
    assert!(
        span as usize > pts.len() * 5,
        "CASE A (A/V): span {span} ms ≫ frame count {} (real time, not a per-frame counter)",
        pts.len()
    );
    eprintln!(
        "[case A] GATE A/V-sync: {} frames, span={span} ms, max_delta={max_delta} ms, \
         last-fragment base={last_base} ms (monotonic, window-relative)",
        pts.len()
    );

    // -- GATE A4: forward seek then BACK-SEEK cache hit (zero new GETs) --
    let seek_seq = a_index.len() as u32 - 1;
    let before_seek = fetch_count;
    if !cache.contains(&a_fid, seek_seq) {
        let _seek = play_window_emit(
            &mut h.c,
            &h.token,
            &a_fid,
            a_version,
            &a_index,
            &mut cache,
            &a_decryptor,
            &decode_worker,
            seek_seq,
            PLAY_WINDOW,
            &mut fetch_count,
        )
        .await
        .expect("CASE A: forward seek window plays");
        assert!(fetch_count > before_seek, "CASE A: forward seek fetched ciphertext");
    }
    let after_seek = fetch_count;
    let back = play_window_emit(
        &mut h.c,
        &h.token,
        &a_fid,
        a_version,
        &a_index,
        &mut cache,
        &a_decryptor,
        &decode_worker,
        0,
        PLAY_WINDOW,
        &mut fetch_count,
    )
    .await
    .expect("CASE A: back-seek window replays from cache");
    assert_eq!(
        fetch_count, after_seek,
        "CASE A (back-seek): replaying the cached window performed NO new server GET"
    );
    assert_eq!(
        back.frames.len(),
        win0.frames.len(),
        "CASE A (back-seek): the cached window re-decoded to the same frame count"
    );
    eprintln!(
        "[case A] GATE back-seek: window 0 replayed from cache with 0 new GETs (fetch_count steady at {after_seek})"
    );
    let _ = std::fs::remove_dir_all(&cache_dir);

    // =====================================================================
    // CASE B — extreme / high-res (synthesized 2560x1440 + sine, 2s).
    // =====================================================================
    let src_dir = temp_dir("highres-src");
    let Some(highres) = synthesize_highres(&ffmpeg, &src_dir, 2560, 1440, 2) else {
        panic!("CASE B: failed to synthesize the 2560x1440 source with the vendored ffmpeg");
    };
    eprintln!("[case B] transcoding a synthesized 2560x1440 (30fps, 2s, sine) extreme source…");
    let (b_streams, b_fragments) = prepare_video_streams(
        &highres,
        &ffmpeg,
        &TranscodeOptions::default(),
        &VideoBounds::default(),
        "Extreme clip",
        &[],
        |_p| {},                                    // no-op progress sink (not asserted here)
        &std::sync::atomic::AtomicBool::new(false), // never cancelled
    )
    .expect("CASE B: confined transcode of the high-res source succeeds");
    let _ = std::fs::remove_dir_all(&src_dir);
    assert!(!b_fragments.is_empty(), "CASE B: produced ≥1 canonical fragment");

    let (b_file_id, b_fid) =
        stage_video(&mut h.c, &h.owner, h.user_id, &h.token, &h.rr, &b_streams).await;
    let mut trust_b = MemoryTrustStore::new();
    let (b_index, b_decryptor, b_version) = open_view_session(
        &mut h.c,
        &h.owner,
        "alice",
        h.user_id,
        &b_fid,
        b_file_id,
        &h.verifier,
        &mut trust_b,
        &h.token,
    )
    .await;
    let cache_dir_b = temp_dir("cacheB");
    let mut cache_b = FragmentCache::open(&cache_dir_b, 32 * 1024 * 1024).unwrap();
    let mut fetch_b = 0u32;
    // Drives the BOUNDED delivery (push_bounded / 64 MiB) on real 1440p frames
    // (~5.5 MB each). It must complete WITHOUT OOM/hang; dropped frames surface as a
    // benign Gap, never an error.
    let win_b = play_window_emit(
        &mut h.c,
        &h.token,
        &b_fid,
        b_version,
        &b_index,
        &mut cache_b,
        &b_decryptor,
        &decode_worker,
        0,
        PLAY_WINDOW,
        &mut fetch_b,
    )
    .await
    .expect("CASE B: the extreme high-res window decodes without OOM/hang");
    assert!(!win_b.saw_error(), "CASE B: no decode error (bounded delivery holds)");
    assert!(
        !win_b.frames.is_empty(),
        "CASE B: at least one high-res frame survived the bound + decoded"
    );
    let (b_w, b_h) = (win_b.frames[0].1, win_b.frames[0].2);
    assert!(b_w.is_multiple_of(2) && b_h.is_multiple_of(2), "CASE B: even high-res dims");
    assert_eq!(
        (b_w, b_h),
        (2560, 1440),
        "CASE B: decoded geometry is the (even) high-res dims"
    );
    // Audio present (we synthesized a sine track) ⇒ PCM emits.
    assert!(
        !win_b.audio.is_empty() && win_b.audio[0].channels >= 1,
        "CASE B: the synthesized audio decoded to PCM"
    );
    eprintln!(
        "[case B] GATE extreme: decoded {b_w}x{b_h}, {} frames survived the bound, \
         dropped/skipped (benign Gap)={}, audio chunks={}",
        win_b.frames.len(),
        win_b.gap_total(),
        win_b.audio.len()
    );
    let _ = std::fs::remove_dir_all(&cache_dir_b);

    // =====================================================================
    // CASE C — resolution change (ttget @ Height(720), Original bitrate).
    // =====================================================================
    eprintln!("[case C] transcoding ttget with resolution=Height(720) (D-5 downscale)…");
    let (c_streams, _c_fragments) = prepare_video_streams(
        &ttget,
        &ffmpeg,
        &TranscodeOptions {
            resolution: Resolution::Height(720),
            bitrate: Bitrate::Original,
        },
        &VideoBounds::default(),
        "Downscaled clip",
        &[],
        |_p| {},                                    // no-op progress sink (not asserted here)
        &std::sync::atomic::AtomicBool::new(false), // never cancelled
    )
    .expect("CASE C: confined transcode with the resolution override succeeds");
    let (c_file_id, c_fid) =
        stage_video(&mut h.c, &h.owner, h.user_id, &h.token, &h.rr, &c_streams).await;
    let mut trust_c = MemoryTrustStore::new();
    let (c_index, c_decryptor, c_version) = open_view_session(
        &mut h.c,
        &h.owner,
        "alice",
        h.user_id,
        &c_fid,
        c_file_id,
        &h.verifier,
        &mut trust_c,
        &h.token,
    )
    .await;
    let cache_dir_c = temp_dir("cacheC");
    let mut cache_c = FragmentCache::open(&cache_dir_c, 32 * 1024 * 1024).unwrap();
    let mut fetch_c = 0u32;
    let win_c = play_window_emit(
        &mut h.c,
        &h.token,
        &c_fid,
        c_version,
        &c_index,
        &mut cache_c,
        &c_decryptor,
        &decode_worker,
        0,
        PLAY_WINDOW,
        &mut fetch_c,
    )
    .await
    .expect("CASE C: the downscaled window decodes");
    assert!(!win_c.frames.is_empty(), "CASE C: decoded to frames");
    let (c_w, c_h) = (win_c.frames[0].1, win_c.frames[0].2);
    assert_eq!(c_h, 720, "CASE C: decoded height reflects the requested downscale");
    assert!(c_w.is_multiple_of(2), "CASE C: even width (D-5 aspect-preserving, -2)");
    assert!(
        c_w < a_w,
        "CASE C: downscaled width {c_w} is narrower than the Case-A source width {a_w}"
    );
    eprintln!(
        "[case C] GATE resolution-change: decoded {c_w}x{c_h} (was {a_w}x{a_h}); \
         the D-5 Height(720) menu drove the real ffmpeg argv end to end"
    );
    let _ = std::fs::remove_dir_all(&cache_dir_c);

    // ---- cleanup ----
    let _ = std::fs::remove_dir_all(&h.blob_dir);
    let _ = std::fs::remove_dir_all(&app_dir);
    eprintln!("universal_video_ingest_capstone: ALL THREE CASES PASSED.");
}
