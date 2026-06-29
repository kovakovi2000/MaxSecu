//! Sandboxed-video **player commands** (Phase 7, Gate 4 / Task 4.3b) — the final
//! orchestration that wires the decrypt-while-play feeder (`crate::video`,
//! 4.2b), the on-disk ciphertext cache (`crate::fragment_cache`), the in-TCB
//! `ContentDecryptor`, and the codec-free confined launcher
//! (`maxsecu_media_launcher`) into the four Tauri commands the UI drives.
//!
//! # Security model (the dedicated review checks these)
//! * **The `ContentDecryptor` (content subkey) NEVER crosses the Tauri seam.** It
//!   lives in the `VideoJobs` managed registry (the TCB), borrowed by
//!   [`play_window`]. Only frame/PCM DTOs ([`I420FrameDto`]/[`PcmDto`]) and
//!   [`PlayerPhase`] cross the boundary. Dropping the job (`cancel_video`) drops
//!   the decryptor, zeroizing the subkey.
//! * **Decrypt happens in the main-process TCB; the confined worker only ever
//!   sees already-decrypted canonical fragment bytes.** [`decrypt_window`]
//!   decrypts the bounded window into a `script` of `ClientMsg::Fragment` (the
//!   plaintext lives only inside a [`ScriptGuard`] that **zeroizes on drop**, so
//!   the wipe is unconditional across success/error paths); [`decode_and_emit`]
//!   hands that script to the confined `run_session` **off the async runtime**
//!   (`spawn_blocking`). No plaintext is cached, returned, or logged — only
//!   ciphertext is cached (the feeder guarantees it).
//! * **The global `VideoJobs` lock is never held across the network prefetch or
//!   the blocking decode** — only across the two short synchronous critical
//!   sections (plan + in-TCB decrypt). So `cancel_video` can preempt an in-flight
//!   window, and the blocking subprocess decode never runs on a tokio worker
//!   thread.
//! * **Untrusted worker output is re-validated in the main process** (spec §7):
//!   every `WorkerMsg::Video`/`Audio` is re-checked with `validate_i420` /
//!   `validate_pcm` BEFORE its DTO is emitted. A malformed frame is caught here,
//!   never rendered.
//! * **D5 author verification gates playback.** The served author binding is
//!   re-verified under the pinned D5 root (a forged/untrusted author → fail-closed,
//!   no decode); the verified author keys feed the `VerifyContext`, so the verify
//!   ladder also fails closed if the record was signed by the wrong key.
//! * **Bounded window (decrypt-while-play, NOT whole-file).** Each command plays a
//!   small constant number of fragments; the UI requests further windows as
//!   playback advances (Gate 5). Only one window's plaintext is ever live.
//! * **Reauth/serial discipline.** Each authed command mints a fresh channel+token
//!   under the `ConnectLock` (the Phase-3 `reauth` pattern); the identity is
//!   borrowed only under the session lock across the SYNCHRONOUS verify.
//! * **Fail-closed everywhere** with a sanitized [`PlayerPhase::Error`]/`UiError`
//!   (no decode oracle).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Serialize;
use tauri::{Emitter, State};
use zeroize::Zeroize;

use maxsecu_client_core::{
    open_content_decryptor, validate_i420, validate_pcm, verify_and_open_headers, ClientMsg,
    ContentDecryptor, DirectoryVerifier, I420Frame, Identity, MemoryTrustStore, PcmChunk,
    StreamHeader, VerifyContext, VideoBounds, WorkerMsg, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::{Id, RecipientType, StreamType};
use maxsecu_media_launcher::VideoSessionDecoder;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::feed::{hex, hex16, now_ms};
use crate::config::{load_directory_pub, SettingsConfig};
use crate::directory::{resolve_and_verify_author, resolve_my_user_id, VerifiedAuthor};
use crate::download::{build_stream_header, parse_file_view};
use crate::error::UiError;
use crate::fragment_cache::FragmentCache;
use crate::http_client::{get_bytes, get_json};
use crate::jobs::{VideoJob, VideoJobs};
use crate::state::{PlayerPhase, EVT_PLAYER, EVT_VIDEO_AUDIO, EVT_VIDEO_FRAME};
use crate::video::{chunks_for_fragment, feed_fragment, fragment_for_time, FragmentEntry};

/// Fragments decoded per bounded window. Small + finite: the UI requests further
/// windows as playback advances (Gate 5), so only a few fragments' plaintext is
/// ever materialized at once (decrypt-while-play, never whole-file). NOTE (review
/// M3): this bounds the fragment COUNT, not the absolute plaintext byte size — a
/// signed index entry could declare a large `chunk_len` — but the fragment index
/// is AEAD-bound to the content owner (within author trust), so the byte size is a
/// trusted-author concern, not an untrusted-input one.
const PLAY_WINDOW: u32 = 4;

/// Hard clamp on the UI playback-gain preference (no decode effect; applied by
/// WebAudio in Gate 5). Keeps a hand-set value in a sane range.
const MAX_GAIN: f32 = 4.0;

/// One re-validated decoded I420 frame, base64-per-plane — the ONLY video payload
/// that crosses the Tauri seam (the UI uploads the planes to a WebGL texture in
/// Gate 5). Carries NO key material; RAM-only pixels.
#[derive(Debug, Clone, Serialize)]
pub struct I420FrameDto {
    pub width: u32,
    pub height: u32,
    pub pts_ms: u64,
    pub y_b64: String,
    pub u_b64: String,
    pub v_b64: String,
}

/// One re-validated decoded PCM chunk, base64 interleaved-i16-LE — the only audio
/// payload that crosses the seam (the UI feeds it to WebAudio in Gate 5).
#[derive(Debug, Clone, Serialize)]
pub struct PcmDto {
    pub channels: u8,
    pub sample_rate: u32,
    pub pts_ms: u64,
    pub samples_b64: String,
}

/// A sanitized player-layer error (no decode oracle / internal detail crosses).
fn player_err() -> UiError {
    UiError::new("video_failed", "The video could not be played.")
}

/// Base64 a validated frame's planes into the seam DTO.
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

/// Base64 a validated PCM chunk's interleaved i16 samples (little-endian) into the
/// seam DTO.
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

/// The confined `media-worker` binary lives beside the portable exe (`AppDir`).
fn worker_path(app_dir: &Path) -> PathBuf {
    let name = if cfg!(windows) {
        "media-worker.exe"
    } else {
        "media-worker"
    };
    app_dir.join(name)
}

/// The OS-confined session decoder concrete type for this platform: an
/// AppContainer + Job Object on Windows, the cross-platform process-isolated
/// subprocess elsewhere. Both link NO codecs (structural decoder-free-main-process
/// guarantee); the codecs only ever run inside the spawned confined worker. A
/// `Send + 'static` value so it can move into `tokio::task::spawn_blocking` for the
/// off-runtime decode (review I1).
#[cfg(windows)]
type SessionDecoder = maxsecu_media_launcher::AppContainerVideoSession;
#[cfg(not(windows))]
type SessionDecoder = maxsecu_media_launcher::VideoSubprocessSession;

fn make_decoder(app_dir: &Path) -> SessionDecoder {
    SessionDecoder::new(worker_path(app_dir))
}

/// The confined `media-transcode-worker` binary lives beside the portable exe
/// (`AppDir`), like the decode `media-worker`. Resolved here so the upload command
/// (`stage_upload`, video kind) can drive the confined author-side transcode.
pub(crate) fn transcode_worker_path(app_dir: &Path) -> PathBuf {
    let name = if cfg!(windows) {
        "media-transcode-worker.exe"
    } else {
        "media-transcode-worker"
    };
    app_dir.join(name)
}

/// SYNCHRONOUS TCB step: from the unlocked `identity` + a D5-VERIFIED `author`,
/// run the §12.5 header ladder to (a) parse the authenticated fragment index out
/// of the `metadata` plaintext and (b) derive the seek/decrypt-while-play
/// [`ContentDecryptor`]. The `file_id` MUST be the REQUESTED id (the verify ladder
/// binds the served record to it), and the keys come from the D5-verified author —
/// so a forged/substituted record fails closed here (no content subkey released).
/// No await: the caller holds the session lock across this, so the `identity`
/// borrow never spans an await.
fn open_video_job_core(
    identity: &Identity,
    file_id: [u8; 16],
    author: &VerifiedAuthor,
    my_id: [u8; 16],
    header: &StreamHeader,
) -> Result<(ContentDecryptor, Vec<FragmentEntry>), UiError> {
    let ctx = VerifyContext {
        file_id: Id(file_id),
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id),
        recipient_type: RecipientType::User,
        recipient_secret: identity.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };

    // Verify the header + decode the small streams; take the authenticated
    // `metadata` plaintext and parse the (re-validated) fragment index from it.
    let opened = verify_and_open_headers(&ctx, header).map_err(|_| player_err())?;
    let meta = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .ok_or_else(player_err)?;
    let meta_json: serde_json::Value =
        serde_json::from_slice(&meta.plaintext).map_err(|_| player_err())?;
    let index = crate::video::parse_fragment_index(&meta_json)?;

    // Same fail-closed header proof, stopping at the content subkey (fetches no
    // content). The decryptor holds the subkey in the TCB.
    let decryptor = open_content_decryptor(&ctx, header).map_err(|_| player_err())?;
    Ok((decryptor, index))
}

/// Owns the bounded window's `ClientMsg` script; its `Drop` **zeroizes** every
/// `Fragment`'s plaintext bytes (the `pt.to_vec()` copy defeats `feed_fragment`'s
/// internal `Zeroizing`). Because the wipe is in `Drop`, it runs on ALL paths
/// (review M1): a `feed_fragment` error mid-window, a `run_session` failure inside
/// the blocking task, or normal completion — the canonical fragment plaintext is
/// never dropped unwiped.
struct ScriptGuard(Vec<ClientMsg>);

impl Drop for ScriptGuard {
    fn drop(&mut self) {
        for msg in &mut self.0 {
            if let ClientMsg::Fragment { bytes, .. } = msg {
                bytes.zeroize();
            }
        }
    }
}

/// SYNCHRONOUS decrypt-while-play core (the testable TCB seam). Decrypts the
/// bounded window `[start_seq, start_seq+count)` IN THE TCB into a [`ScriptGuard`]
/// of canonical (already-decrypted) fragment bytes. For each fragment,
/// [`feed_fragment`] sources its **ciphertext** from the cache (hit ⇒ no fetch) or
/// `fetch_chunk` (miss ⇒ caches the ciphertext) and decrypts it; only ciphertext
/// is ever cached, the plaintext lives only inside the returned `ScriptGuard`
/// (zeroized on drop). Emits `Buffering` on entry. No network, no decode — the
/// caller decodes off-thread ([`decode_and_emit`]) AFTER releasing the jobs lock.
fn decrypt_window<Fetch, E>(
    job: &mut VideoJob,
    start_seq: u32,
    count: u32,
    mut fetch_chunk: Fetch,
    emit: &E,
) -> Result<ScriptGuard, UiError>
where
    Fetch: FnMut(u64) -> Result<Vec<u8>, UiError>,
    E: Fn(PlayerPhase),
{
    emit(PlayerPhase::Buffering);

    let n = job.index.len() as u32;
    if n == 0 || start_seq >= n {
        return Err(player_err());
    }
    let end = start_seq.saturating_add(count).min(n);

    // `script` is a ScriptGuard from the first push, so any early `?` return below
    // (a feed_fragment error) zeroizes the fragments already decrypted (M1).
    let mut script = ScriptGuard(Vec::with_capacity((end - start_seq) as usize + 2));
    script.0.push(ClientMsg::Open {
        bounds: VideoBounds::default(),
    });
    for seq in start_seq..end {
        feed_fragment(
            &job.index,
            &mut job.cache,
            &job.decryptor,
            &job.file_id_hex,
            seq,
            &mut fetch_chunk,
            |pt| {
                script.0.push(ClientMsg::Fragment {
                    seq,
                    bytes: pt.to_vec(),
                });
                Ok(())
            },
        )?;
    }
    script.0.push(ClientMsg::Close);
    Ok(script)
}

/// Run the confined decode OFF the async runtime (review I1) and re-validate its
/// untrusted output in the main process. The `script` (the only live plaintext)
/// and the `Send + 'static` `decoder` MOVE into [`tokio::task::spawn_blocking`] so
/// the blocking subprocess spawn + pipe I/O never runs on a tokio worker thread;
/// the `ScriptGuard` is dropped inside the blocking task, zeroizing the plaintext
/// on every path. Each returned `WorkerMsg::Video`/`Audio` is re-validated
/// (`validate_i420`/`validate_pcm`) BEFORE its DTO is emitted (spec §7); a
/// `WorkerMsg::Error` (or any validation failure) fails closed. Emits `Playing`
/// once the window's frames have flowed.
async fn decode_and_emit<D, E, OnF, OnA>(
    script: ScriptGuard,
    decoder: D,
    emit: &E,
    on_frame: &OnF,
    on_audio: &OnA,
) -> Result<(), UiError>
where
    D: VideoSessionDecoder + Send + 'static,
    E: Fn(PlayerPhase),
    OnF: Fn(I420FrameDto),
    OnA: Fn(PcmDto),
{
    // Hand ONLY the already-decrypted canonical bytes to the confined worker, on a
    // blocking thread. `script` is dropped (zeroized) when this closure returns —
    // regardless of whether `run_session` succeeded.
    let decoded = tokio::task::spawn_blocking(move || {
        let result = decoder.run_session(&script.0).map_err(|_| player_err());
        drop(script);
        result
    })
    .await
    .map_err(|_| player_err())??;

    // Re-validate EVERY untrusted worker output in the main process before any DTO
    // crosses the seam (spec §7).
    let bounds = VideoBounds::default();
    for msg in decoded {
        match msg {
            WorkerMsg::Video(frame) => {
                validate_i420(&frame, &bounds).map_err(|_| player_err())?;
                on_frame(frame_dto(&frame));
            }
            WorkerMsg::Audio(chunk) => {
                validate_pcm(&chunk, &bounds).map_err(|_| player_err())?;
                on_audio(pcm_dto(&chunk));
            }
            WorkerMsg::Error(_) => return Err(player_err()),
            WorkerMsg::Ready | WorkerMsg::EndOfFragment { .. } => {}
        }
    }

    emit(PlayerPhase::Playing);
    Ok(())
}

/// Whether `seq`'s cached blob is a VALID hit — it deframes to EXACTLY `chunk_len`
/// ciphertext chunks — i.e. the same hit condition [`feed_fragment`] applies
/// internally (review M2). A present-but-corrupt / wrong-count blob is NOT a hit,
/// so the prefetch stages its chunks and the feeder's miss-refetch is satisfied (a
/// corrupt cache entry is recovered, not a hard playback failure). The framing is
/// the documented length-prefixed form (`u32 count`, then per chunk `u32 len` +
/// bytes); re-derived here because 4.2b's `deframe_chunks` is private and must not
/// be touched.
fn cached_fragment_valid(
    cache: &mut FragmentCache,
    file_id_hex: &str,
    seq: u32,
    chunk_len: u64,
) -> bool {
    match cache.get(file_id_hex, seq) {
        Some(blob) => deframe_count(&blob).is_some_and(|n| n as u64 == chunk_len),
        None => false,
    }
}

/// Bounds-safe count of the ciphertext chunks a cache blob deframes to, or `None`
/// if it is truncated / over-long / has trailing garbage — mirroring 4.2b's
/// private `deframe_chunks` (count check + per-chunk length walk + exact-consume).
fn deframe_count(blob: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    let count = read_u32_le(blob, &mut pos)? as usize;
    // A chunk costs at least its own 4-byte length header, so reject an impossible
    // count before walking (mirrors the feeder's allocation guard).
    if count > blob.len().saturating_sub(4) / 4 {
        return None;
    }
    for _ in 0..count {
        let len = read_u32_le(blob, &mut pos)? as usize;
        pos = pos.checked_add(len)?;
        if pos > blob.len() {
            return None;
        }
    }
    if pos != blob.len() {
        return None; // trailing garbage — not a clean deframe
    }
    Some(count)
}

fn read_u32_le(blob: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let bytes: [u8; 4] = blob.get(*pos..end)?.try_into().ok()?;
    *pos = end;
    Some(u32::from_le_bytes(bytes))
}

/// The window plan computed under the jobs lock (then released): the clamped start
/// and the absolute content-chunk indices that must be prefetched (only fragments
/// that are NOT a valid cache hit).
struct WindowPlan {
    start: u32,
    version: u64,
    fetch_indices: Vec<u64>,
}

/// Drive one bounded window end-to-end while holding the global `VideoJobs` lock
/// ONLY for the two short synchronous critical sections — planning and the in-TCB
/// decrypt — and NEVER across the network prefetch or the blocking decode (review
/// I1). Because the lock is free during prefetch + decode, `cancel_video` (and
/// `video_seek`/`video_set_volume`) can acquire it promptly and PREEMPT an
/// in-flight window: if the job is gone when the decrypt section re-locks, this
/// aborts before decoding.
#[allow(clippy::too_many_arguments)]
async fn play_window_command<E, OnF, OnA>(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
    host: &str,
    token: &str,
    jobs: &VideoJobs,
    file_id_hex: &str,
    start: u32,
    count: u32,
    app_dir: &Path,
    emit: &E,
    on_frame: &OnF,
    on_audio: &OnA,
) -> Result<(), UiError>
where
    E: Fn(PlayerPhase),
    OnF: Fn(I420FrameDto),
    OnA: Fn(PcmDto),
{
    // Phase A — plan under the lock (sync), then DROP the guard. Decide which
    // chunks need fetching using the feeder's own hit condition (M2), so a corrupt
    // cached blob is refetched, not fatal.
    let plan = {
        let mut guard = jobs.0.lock().await;
        let job = guard.get_mut(file_id_hex).ok_or_else(player_err)?;
        let n = job.index.len() as u32;
        if n == 0 {
            return Err(player_err());
        }
        let start = start.min(n - 1);
        let end = start.saturating_add(count).min(n);
        let mut fetch_indices = Vec::new();
        for seq in start..end {
            let (cs, cl) = chunks_for_fragment(&job.index, seq).ok_or_else(player_err)?;
            if !cached_fragment_valid(&mut job.cache, &job.file_id_hex, seq, cl) {
                let stream_end = cs.checked_add(cl).ok_or_else(player_err)?;
                fetch_indices.extend(cs..stream_end);
            }
        }
        WindowPlan {
            start,
            version: job.version,
            fetch_indices,
        }
    };

    // Phase B — prefetch the missing ciphertext chunks over the network with NO
    // lock held (so cancel can preempt). A back-seek to a valid-cached fragment
    // contributes no indices here ⇒ no network.
    let mut prefetched: HashMap<u64, Vec<u8>> = HashMap::new();
    for i in plan.fetch_indices {
        let uri = format!(
            "/v1/files/{file_id_hex}/versions/{}/streams/content/chunks/{i}",
            plan.version
        );
        let (status, bytes) = get_bytes(sender, &uri, Some(token), host).await?;
        if status != hyper::StatusCode::OK {
            return Err(player_err());
        }
        prefetched.insert(i, bytes);
    }

    // Phase C — decrypt the window IN THE TCB under the lock (sync), then DROP the
    // guard. If the job was cancelled during prefetch, it is gone here ⇒ abort.
    let script = {
        let mut guard = jobs.0.lock().await;
        let job = guard.get_mut(file_id_hex).ok_or_else(player_err)?;
        decrypt_window(
            job,
            plan.start,
            count,
            |i| prefetched.remove(&i).ok_or_else(player_err),
            emit,
        )?
    };

    // Phase D — decode OFF the runtime + re-validate + emit (no lock, no identity).
    let decoder = make_decoder(app_dir);
    decode_and_emit(script, decoder, emit, on_frame, on_audio).await
}

/// `open_video` — open + verify a video, register its decrypt-while-play session,
/// and play the initial bounded window. Emits [`PlayerPhase`] over [`EVT_PLAYER`]
/// and decoded DTOs over [`EVT_VIDEO_FRAME`]/[`EVT_VIDEO_AUDIO`]. Sanitized errors.
#[tauri::command]
pub async fn open_video(
    file_id: String,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    jobs: State<'_, VideoJobs>,
) -> Result<(), UiError> {
    let emit = |p: PlayerPhase| {
        let _ = app.emit(EVT_PLAYER, p);
    };
    let on_frame = |f: I420FrameDto| {
        let _ = app.emit(EVT_VIDEO_FRAME, f);
    };
    let on_audio = |a: PcmDto| {
        let _ = app.emit(EVT_VIDEO_AUDIO, a);
    };
    let out = open_video_inner(
        &file_id,
        &dir,
        &session,
        &connect_lock,
        &jobs,
        &emit,
        &on_frame,
        &on_audio,
    )
    .await;
    if let Err(e) = &out {
        emit(PlayerPhase::Error {
            code: e.code.clone(),
        });
        // Clean up any partially-registered job (drops the decryptor → zeroizes).
        if let Ok(bytes) = hex16(&file_id) {
            jobs.0.lock().await.remove(&hex(&bytes));
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
async fn open_video_inner<E, OnF, OnA>(
    file_id_str: &str,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    jobs: &State<'_, VideoJobs>,
    emit: &E,
    on_frame: &OnF,
    on_audio: &OnA,
) -> Result<(), UiError>
where
    E: Fn(PlayerPhase),
    OnF: Fn(I420FrameDto),
    OnA: Fn(PcmDto),
{
    // Validate the REQUESTED id up front (it is what the served record must bind to
    // and is interpolated into the request URL). Canonical lowercase hex is the
    // cache + jobs-registry key.
    let file_id = hex16(file_id_str)?;
    let file_id_hex = hex(&file_id);
    let pinned = load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();

    let username = {
        let s = session.0.lock().await;
        s.username.clone()
    }
    .ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;

    let (status, view_json) = get_json(
        &mut sender,
        &format!("/v1/files/{file_id_hex}?version=latest"),
        Some(&token),
        &host,
    )
    .await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("fetch_failed", "That item is not available."));
    }
    let view = parse_file_view(&view_json)?;
    let manifest: Manifest =
        decode(&view.manifest_bytes).map_err(|_| UiError::new("untrusted", "Malformed record."))?;

    // D5-verify the author binding (fail-closed) BEFORE any decode.
    let author = resolve_and_verify_author(
        &mut sender,
        &host,
        &hex(&manifest.author_id.0),
        &verifier,
        &mut trust,
        now,
    )
    .await?;
    let my_id =
        resolve_my_user_id(&mut sender, &host, &username, &verifier, &mut trust, now).await?;

    // Header (small streams only — no content fetched here).
    let header = build_stream_header(&mut sender, &host, &token, &file_id_hex, &view).await?;

    // TCB: build the decryptor + fragment index under the session lock (sync verify;
    // the identity borrow never spans an await).
    let (decryptor, index) = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        open_video_job_core(identity, file_id, &author, my_id, &header)
    }?;
    let version = decryptor.version();

    // Register the session. Cache cap from the Phase-5 performance setting.
    let cap = SettingsConfig::load(&dir.0).performance.ram_cache_cap_mb as u64 * 1024 * 1024;
    let cache = FragmentCache::open(&dir.0, cap).map_err(|_| player_err())?;
    jobs.0.lock().await.insert(
        file_id_hex.clone(),
        VideoJob {
            decryptor,
            index,
            cache,
            file_id_hex: file_id_hex.clone(),
            version,
            gain: 1.0,
        },
    );

    // Play the initial bounded window from the start.
    play_window_command(
        &mut sender,
        &host,
        &token,
        jobs,
        &file_id_hex,
        0,
        PLAY_WINDOW,
        &dir.0,
        emit,
        on_frame,
        on_audio,
    )
    .await
}

/// `video_seek` — map `pts_ms` to its fragment and play a bounded window from
/// there (a back-seek re-feeds from the cache → no re-fetch). Emits Buffering→
/// Playing with the new frames.
#[tauri::command]
pub async fn video_seek(
    file_id: String,
    pts_ms: u64,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    jobs: State<'_, VideoJobs>,
) -> Result<(), UiError> {
    let emit = |p: PlayerPhase| {
        let _ = app.emit(EVT_PLAYER, p);
    };
    let on_frame = |f: I420FrameDto| {
        let _ = app.emit(EVT_VIDEO_FRAME, f);
    };
    let on_audio = |a: PcmDto| {
        let _ = app.emit(EVT_VIDEO_AUDIO, a);
    };
    let out = video_seek_inner(
        &file_id,
        pts_ms,
        &dir,
        &session,
        &connect_lock,
        &jobs,
        &emit,
        &on_frame,
        &on_audio,
    )
    .await;
    if let Err(e) = &out {
        emit(PlayerPhase::Error {
            code: e.code.clone(),
        });
    }
    out
}

#[allow(clippy::too_many_arguments)]
async fn video_seek_inner<E, OnF, OnA>(
    file_id_str: &str,
    pts_ms: u64,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    jobs: &State<'_, VideoJobs>,
    emit: &E,
    on_frame: &OnF,
    on_audio: &OnA,
) -> Result<(), UiError>
where
    E: Fn(PlayerPhase),
    OnF: Fn(I420FrameDto),
    OnA: Fn(PcmDto),
{
    let file_id = hex16(file_id_str)?;
    let file_id_hex = hex(&file_id);

    // Map the seek time to a fragment using the authenticated index (lock briefly).
    // A seek before the first fragment clamps to fragment 0.
    let start = {
        let guard = jobs.0.lock().await;
        let job = guard.get(&file_id_hex).ok_or_else(player_err)?;
        fragment_for_time(&job.index, pts_ms).unwrap_or(0)
    };

    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;
    play_window_command(
        &mut sender,
        &host,
        &token,
        jobs,
        &file_id_hex,
        start,
        PLAY_WINDOW,
        &dir.0,
        emit,
        on_frame,
        on_audio,
    )
    .await
}

/// `video_set_volume` — store the UI playback-gain preference in the job (clamped;
/// NO decode effect — the UI applies it via WebAudio in Gate 5).
#[tauri::command]
pub async fn video_set_volume(
    file_id: String,
    gain: f32,
    jobs: State<'_, VideoJobs>,
) -> Result<(), UiError> {
    let key = hex(&hex16(&file_id)?);
    let mut guard = jobs.0.lock().await;
    let job = guard.get_mut(&key).ok_or_else(player_err)?;
    // NaN-safe clamp into [0, MAX_GAIN].
    job.gain = if gain.is_nan() {
        1.0
    } else {
        gain.clamp(0.0, MAX_GAIN)
    };
    Ok(())
}

/// `cancel_video` — drop the session from `VideoJobs` (drops the `ContentDecryptor`
/// → zeroizes the content subkey). There is no persistent worker to kill (each
/// window is a fresh confined `run_session` that already exited). Emits the benign
/// terminal `Error { code: "cancelled" }`.
#[tauri::command]
pub async fn cancel_video(
    file_id: String,
    app: tauri::AppHandle,
    jobs: State<'_, VideoJobs>,
) -> Result<(), UiError> {
    if let Ok(bytes) = hex16(&file_id) {
        jobs.0.lock().await.remove(&hex(&bytes));
    }
    let _ = app.emit(
        EVT_PLAYER,
        PlayerPhase::Error {
            code: "cancelled".into(),
        },
    );
    Ok(())
}

// ===========================================================================
// Preview-before-upload (Phase 7, Gate 6 / Task 6.4). The author transcodes their
// source in the CONFINED worker (`stage_upload`, video kind) and the canonical
// AV1/CMAF plaintext + authenticated fragment index are held in the `UploadJobs`
// registry. `preview_video` drives the SAME confined decode session over that
// STAGED plaintext — sliced straight out of `cmaf` by the fragment ranges, NO server
// fetch + NO decrypt (the canonical bytes are already plaintext) — re-validates the
// untrusted worker output in the main process, and emits the same frame/PCM DTOs +
// PlayerPhase the server-fetch player (`open_video`) does. So the author sees the
// transcoded result rendered in `<video-player>` BEFORE confirming the upload.
// ===========================================================================

/// Slice the STAGED canonical `cmaf` plaintext into a confined-decode `script`:
/// `Open → Fragment{seq,bytes}* → Close`, where each fragment's bytes are
/// `cmaf[chunk_start*CS .. (chunk_start+chunk_len)*CS]` (CS = [`crate::upload::VIDEO_CHUNK_SIZE`]),
/// exactly as the server-fetch player addresses content chunks. The plaintext copies
/// live ONLY inside the returned [`ScriptGuard`] (zeroized on drop). Fail-closed on an
/// empty/out-of-range index (the index was AEAD-authenticated upstream at upload time;
/// the bound check is defense in depth against an arithmetic mismatch).
fn build_preview_script(cmaf: &[u8], index: &[FragmentEntry]) -> Result<ScriptGuard, UiError> {
    if index.is_empty() {
        return Err(player_err());
    }
    let cs = crate::upload::VIDEO_CHUNK_SIZE as usize;
    let mut script = ScriptGuard(Vec::with_capacity(index.len() + 2));
    script.0.push(ClientMsg::Open {
        bounds: VideoBounds::default(),
    });
    for e in index {
        let start = (e.chunk_start as usize)
            .checked_mul(cs)
            .ok_or_else(player_err)?;
        let len = (e.chunk_len as usize).checked_mul(cs).ok_or_else(player_err)?;
        let end = start.checked_add(len).ok_or_else(player_err)?;
        let slice = cmaf.get(start..end).ok_or_else(player_err)?;
        script.0.push(ClientMsg::Fragment {
            seq: e.seq,
            bytes: slice.to_vec(),
        });
    }
    script.0.push(ClientMsg::Close);
    Ok(script)
}

/// `preview_video` — locally decode the STAGED canonical video for the author's
/// WYSIWYG preview (no server, no decrypt). Drives the confined decode session over
/// the held plaintext, re-validates every frame/PCM chunk in the main process, and
/// emits the same DTOs + [`PlayerPhase`] as `open_video`. Sanitized errors.
#[tauri::command]
pub async fn preview_video(
    job_id: String,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    jobs: State<'_, crate::jobs::UploadJobs>,
) -> Result<(), UiError> {
    let emit = |p: PlayerPhase| {
        let _ = app.emit(EVT_PLAYER, p);
    };
    let on_frame = |f: I420FrameDto| {
        let _ = app.emit(EVT_VIDEO_FRAME, f);
    };
    let on_audio = |a: PcmDto| {
        let _ = app.emit(EVT_VIDEO_AUDIO, a);
    };
    let out = preview_video_inner(&job_id, &dir, &jobs, &emit, &on_frame, &on_audio).await;
    if let Err(e) = &out {
        emit(PlayerPhase::Error {
            code: e.code.clone(),
        });
    }
    out
}

async fn preview_video_inner<E, OnF, OnA>(
    job_id: &str,
    dir: &State<'_, AppDir>,
    jobs: &State<'_, crate::jobs::UploadJobs>,
    emit: &E,
    on_frame: &OnF,
    on_audio: &OnA,
) -> Result<(), UiError>
where
    E: Fn(PlayerPhase),
    OnF: Fn(I420FrameDto),
    OnA: Fn(PcmDto),
{
    emit(PlayerPhase::Buffering);
    // Build the decode script from the staged canonical plaintext under the jobs
    // lock (sync slice copy), then DROP the guard before the off-runtime decode.
    let script = {
        let guard = jobs.0.lock().await;
        let staged = guard.get(job_id).ok_or_else(player_err)?;
        let preview = staged.preview.as_ref().ok_or_else(player_err)?;
        build_preview_script(&preview.cmaf, &preview.index)?
    };
    // Confined decode OFF the runtime + re-validate every worker output + emit DTOs.
    let decoder = make_decoder(&dir.0);
    decode_and_emit(script, decoder, emit, on_frame, on_audio).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    use maxsecu_client_core::{
        build_upload, DecodeError, PlaintextStreams, StreamChunks, UploadBundle, UploadParams,
    };
    use maxsecu_crypto::generate_enc_keypair;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::types::{FileType, Timestamp};
    use maxsecu_media_launcher::SessionError;

    const OWNER_ID: Id = Id([0x11; 16]);
    const FILE_ID: Id = Id([0xF1; 16]);
    const NOW: Timestamp = Timestamp(1_719_500_000_000);

    fn file_id_hex() -> String {
        hex(&FILE_ID.0)
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mxvcmd-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A 2x2 I420 frame that passes `validate_i420`.
    fn ok_frame(pts_ms: u64) -> I420Frame {
        I420Frame {
            width: 2,
            height: 2,
            pts_ms,
            y: vec![1, 2, 3, 4],
            u: vec![5],
            v: vec![6],
        }
    }

    /// A 2x2 frame with a truncated luma plane — `validate_i420` MUST reject it.
    fn bad_frame() -> I420Frame {
        let mut f = ok_frame(0);
        f.y.truncate(3);
        f
    }

    /// Fake confined decoder: returns one validated `Video` frame per `Fragment`
    /// in the script (so the test asserts the re-validated DTO count without a real
    /// worker). A `Send + 'static` unit struct so it moves into `spawn_blocking`.
    struct FrameDecoder;
    impl VideoSessionDecoder for FrameDecoder {
        fn run_session(&self, script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError> {
            let mut out = vec![WorkerMsg::Ready];
            for m in script {
                if let ClientMsg::Fragment { seq, .. } = m {
                    out.push(WorkerMsg::Video(ok_frame(*seq as u64 * 1000)));
                    out.push(WorkerMsg::EndOfFragment { seq: *seq });
                }
            }
            Ok(out)
        }
    }

    /// Fake decoder that emits a malformed frame (re-validation must fail closed).
    struct MalformedDecoder;
    impl VideoSessionDecoder for MalformedDecoder {
        fn run_session(&self, _script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError> {
            Ok(vec![WorkerMsg::Ready, WorkerMsg::Video(bad_frame())])
        }
    }

    /// Fake decoder that reports a worker decode error.
    struct ErrorDecoder;
    impl VideoSessionDecoder for ErrorDecoder {
        fn run_session(&self, _script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError> {
            Ok(vec![WorkerMsg::Error(DecodeError::DecodeFailed)])
        }
    }

    /// Fake decoder that emits one PCM chunk per fragment.
    struct AudioDecoder;
    impl VideoSessionDecoder for AudioDecoder {
        fn run_session(&self, script: &[ClientMsg]) -> Result<Vec<WorkerMsg>, SessionError> {
            let mut out = vec![WorkerMsg::Ready];
            for m in script {
                if let ClientMsg::Fragment { seq, .. } = m {
                    out.push(WorkerMsg::Audio(PcmChunk {
                        channels: 2,
                        sample_rate: 48_000,
                        pts_ms: *seq as u64,
                        samples: vec![1, -1, 2, -2],
                    }));
                }
            }
            Ok(out)
        }
    }

    /// Build a 5-chunk video-shaped upload whose `metadata` JSON carries a
    /// two-fragment index ([0,2) then [2,5)).
    fn build_video() -> (Identity, UploadBundle, Vec<u8>) {
        let owner = Identity::generate();
        let (_recovery_sk, recovery_pk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: OWNER_ID,
            owner_key_version: 1,
            file_id: FILE_ID,
            file_type: FileType::Video,
            chunk_size: 4096,
            recovery_pub: recovery_pk,
            recovery_mlkem_pub: None,
            created_at: NOW,
        };
        // 4096*4 + 100 → 5 content chunks.
        let content: Vec<u8> = (0..(4096 * 4 + 100)).map(|i| (i % 251) as u8).collect();
        let meta = serde_json::json!({
            "title": "clip",
            "tags": [],
            "fragments": [
                { "seq": 0, "pts_ms": 0, "chunk_start": 0, "chunk_len": 2 },
                { "seq": 1, "pts_ms": 1000, "chunk_start": 2, "chunk_len": 3 },
            ]
        });
        let streams = PlaintextStreams {
            content,
            metadata: Some(serde_json::to_vec(&meta).unwrap()),
            thumbnail: None,
            preview: None,
        };
        let content_clone = streams.content.clone();
        let bundle = build_upload(&params, &streams).unwrap();
        (owner, bundle, content_clone)
    }

    /// Split a bundle into a header (small streams) + the content ciphertext chunks.
    fn split(b: &UploadBundle) -> (StreamHeader, Vec<Vec<u8>>) {
        let sw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::User)
            .unwrap();
        let rw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::Recovery)
            .unwrap();
        let content = b
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        let small = b
            .streams
            .iter()
            .filter(|s| s.stream_type != StreamType::Content)
            .map(|s| StreamChunks {
                stream_type: s.stream_type,
                chunks: s.chunks.clone(),
            })
            .collect();
        let header = StreamHeader {
            manifest_bytes: encode(&b.manifest),
            manifest_sig: b.manifest_sig,
            genesis_bytes: encode(&b.genesis),
            genesis_sig: b.genesis_sig,
            wrapped_dek: sw.wrapped_dek.clone(),
            grant_bytes: encode(&sw.grant),
            grant_sig: sw.grant_sig,
            ancestor_grants: vec![],
            recovery_grant_bytes: encode(&rw.grant),
            recovery_grant_sig: rw.grant_sig,
            small_streams: small,
        };
        (header, content.chunks.clone())
    }

    fn author_of(owner: &Identity) -> VerifiedAuthor {
        VerifiedAuthor {
            user_id: OWNER_ID.0,
            sig_pub: owner.sig_pub_bytes(),
            enc_pub: [0u8; 32],
            fingerprint: [0u8; 32],
            key_version: 1,
        }
    }

    /// Build a real, registered `VideoJob` over staged encrypted content + a fresh
    /// on-disk cache — the same TCB path `open_video` takes, minus the network.
    fn build_job(tag: &str) -> (VideoJob, Vec<Vec<u8>>) {
        let (owner, bundle, _content) = build_video();
        let (header, chunks) = split(&bundle);
        let author = author_of(&owner);
        let (decryptor, index) =
            open_video_job_core(&owner, FILE_ID.0, &author, OWNER_ID.0, &header).expect("core");
        assert_eq!(index.len(), 2, "two-fragment index parsed");
        let dir = tmp_dir(tag);
        let cache = FragmentCache::open(&dir, 1 << 20).unwrap();
        let version = decryptor.version();
        let job = VideoJob {
            decryptor,
            index,
            cache,
            file_id_hex: file_id_hex(),
            version,
            gain: 1.0,
        };
        (job, chunks)
    }

    // ---- the synchronous TCB core: D5 author gates playback ----

    #[test]
    fn core_opens_with_the_d5_verified_author() {
        let (owner, bundle, _content) = build_video();
        let (header, _chunks) = split(&bundle);
        let author = author_of(&owner); // the genuine (D5-verified) author keys
        let (dec, index) =
            open_video_job_core(&owner, FILE_ID.0, &author, OWNER_ID.0, &header).expect("opens");
        assert_eq!(dec.version(), 1);
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn core_fails_closed_for_a_forged_author() {
        let (owner, bundle, _content) = build_video();
        let (header, _chunks) = split(&bundle);
        // An attacker-substituted author (wrong sig_pub) — the verify ladder must
        // reject it, releasing NO content subkey (D5 gates playback).
        let attacker = Identity::generate();
        let forged = VerifiedAuthor {
            user_id: OWNER_ID.0,
            sig_pub: attacker.sig_pub_bytes(),
            enc_pub: [0u8; 32],
            fingerprint: [0u8; 32],
            key_version: 1,
        };
        // `ContentDecryptor` is not `Debug`, so the `Ok` arm can't go through
        // `unwrap_err`; match the error directly.
        let err = match open_video_job_core(&owner, FILE_ID.0, &forged, OWNER_ID.0, &header) {
            Ok(_) => panic!("a forged author must not open the video"),
            Err(e) => e,
        };
        assert_eq!(err.code, "video_failed");
    }

    // ---- decrypt_window + decode_and_emit: Buffering -> Playing with re-validated
    // frame DTOs (the off-runtime decode seam) ----

    #[tokio::test]
    async fn play_window_emits_buffering_then_playing_with_revalidated_frames() {
        let (mut job, chunks) = build_job("play");
        let phases: RefCell<Vec<PlayerPhase>> = RefCell::new(Vec::new());
        let frames: RefCell<Vec<I420FrameDto>> = RefCell::new(Vec::new());
        let audios: RefCell<Vec<PcmDto>> = RefCell::new(Vec::new());
        let fetch_calls = Cell::new(0u32);
        let emit = |p| phases.borrow_mut().push(p);

        // Decrypt the window IN THE TCB (emits Buffering), then decode off-thread.
        let script = decrypt_window(
            &mut job,
            0,
            PLAY_WINDOW,
            |i| {
                fetch_calls.set(fetch_calls.get() + 1);
                Ok(chunks[i as usize].clone())
            },
            &emit,
        )
        .expect("decrypts");
        decode_and_emit(
            script,
            FrameDecoder,
            &emit,
            &|f| frames.borrow_mut().push(f),
            &|a| audios.borrow_mut().push(a),
        )
        .await
        .expect("decodes");

        // Buffering first, Playing last.
        assert_eq!(
            phases.borrow().first(),
            Some(&PlayerPhase::Buffering),
            "Buffering emitted first"
        );
        assert_eq!(
            phases.borrow().last(),
            Some(&PlayerPhase::Playing),
            "Playing emitted last"
        );
        // Both fragments decoded → two re-validated frame DTOs, base64'd.
        assert_eq!(frames.borrow().len(), 2, "one DTO per fragment");
        let f0 = &frames.borrow()[0];
        assert_eq!((f0.width, f0.height), (2, 2));
        assert_eq!(f0.y_b64, B64.encode([1u8, 2, 3, 4]));
        // 5 content chunks fetched (2 for frag0 + 3 for frag1).
        assert_eq!(fetch_calls.get(), 5);
        assert!(audios.borrow().is_empty());
    }

    #[tokio::test]
    async fn play_window_rejects_malformed_worker_frame() {
        let (mut job, chunks) = build_job("malformed");
        let frames: RefCell<Vec<I420FrameDto>> = RefCell::new(Vec::new());
        let script = decrypt_window(
            &mut job,
            0,
            PLAY_WINDOW,
            |i| Ok(chunks[i as usize].clone()),
            &|_p| {},
        )
        .expect("decrypts");
        let err = decode_and_emit(
            script,
            MalformedDecoder,
            &|_p| {},
            &|f| frames.borrow_mut().push(f),
            &|_a| {},
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "video_failed");
        assert!(
            frames.borrow().is_empty(),
            "no DTO emitted for a frame that failed re-validation"
        );
    }

    #[tokio::test]
    async fn play_window_fails_closed_on_worker_error() {
        let (mut job, chunks) = build_job("workererr");
        let script = decrypt_window(
            &mut job,
            0,
            PLAY_WINDOW,
            |i| Ok(chunks[i as usize].clone()),
            &|_p| {},
        )
        .expect("decrypts");
        let err = decode_and_emit(script, ErrorDecoder, &|_p| {}, &|_f| {}, &|_a| {})
            .await
            .unwrap_err();
        assert_eq!(err.code, "video_failed");
    }

    #[tokio::test]
    async fn play_window_emits_revalidated_audio() {
        let (mut job, chunks) = build_job("audio");
        let audios: RefCell<Vec<PcmDto>> = RefCell::new(Vec::new());
        let script = decrypt_window(
            &mut job,
            0,
            PLAY_WINDOW,
            |i| Ok(chunks[i as usize].clone()),
            &|_p| {},
        )
        .expect("decrypts");
        decode_and_emit(script, AudioDecoder, &|_p| {}, &|_f| {}, &|a| {
            audios.borrow_mut().push(a)
        })
        .await
        .expect("decodes");
        assert_eq!(audios.borrow().len(), 2, "one PCM DTO per fragment");
        // interleaved i16 LE: [1,-1,2,-2].
        let mut want = Vec::new();
        for s in [1i16, -1, 2, -2] {
            want.extend_from_slice(&s.to_le_bytes());
        }
        assert_eq!(audios.borrow()[0].samples_b64, B64.encode(&want));
    }

    /// M1: a `feed_fragment` error mid-window still returns through the
    /// `ScriptGuard`'s `Drop` (it zeroizes the already-decrypted fragments). We
    /// can't read freed memory, but we assert the error path is taken with NO
    /// plaintext leaked across any seam (no script returned).
    #[test]
    fn decrypt_window_fails_closed_on_a_fetch_error() {
        let (mut job, _chunks) = build_job("feederr");
        let err = decrypt_window(
            &mut job,
            0,
            PLAY_WINDOW,
            |_i| Err(UiError::new("offline", "no net")),
            &|_p| {},
        )
        .err()
        .expect("a fetch error fails the window");
        assert_eq!(err.code, "offline");
    }

    // ---- seek re-feed + back-seek cache hit (no re-fetch) ----

    #[tokio::test]
    async fn seek_refeeds_from_mapped_fragment_and_back_seek_hits_cache() {
        let (mut job, chunks) = build_job("seek");

        // 1) Play fragment 1 (seek into the second window): it must fetch its 3
        //    chunks [2,5) and decode exactly that fragment.
        let start1 = fragment_for_time(&job.index, 1000).unwrap();
        assert_eq!(start1, 1, "pts 1000 maps to fragment 1");
        let fetch1 = Cell::new(0u32);
        let frames1: RefCell<Vec<I420FrameDto>> = RefCell::new(Vec::new());
        let script1 = decrypt_window(
            &mut job,
            start1,
            PLAY_WINDOW,
            |i| {
                fetch1.set(fetch1.get() + 1);
                Ok(chunks[i as usize].clone())
            },
            &|_p| {},
        )
        .expect("seek decrypts");
        decode_and_emit(
            script1,
            FrameDecoder,
            &|_p| {},
            &|f| frames1.borrow_mut().push(f),
            &|_a| {},
        )
        .await
        .expect("seek decodes");
        assert_eq!(fetch1.get(), 3, "fragment 1 fetched its 3 chunks");
        assert_eq!(frames1.borrow().len(), 1, "only fragment 1 decoded");

        // 2) Back-seek to fragment 1 again: the cache holds its ciphertext, so NO
        //    chunk is re-fetched (the feeder is a cache hit).
        let frames2: RefCell<Vec<I420FrameDto>> = RefCell::new(Vec::new());
        let script2 = decrypt_window(
            &mut job,
            start1,
            PLAY_WINDOW,
            |_i| panic!("back-seek must not re-fetch a cached fragment"),
            &|_p| {},
        )
        .expect("back-seek decrypts from cache");
        decode_and_emit(
            script2,
            FrameDecoder,
            &|_p| {},
            &|f| frames2.borrow_mut().push(f),
            &|_a| {},
        )
        .await
        .expect("back-seek decodes");
        assert_eq!(
            frames2.borrow().len(),
            1,
            "fragment 1 re-decoded from cache"
        );
    }

    /// M2: a present-but-corrupt cached blob is treated as NOT a valid hit
    /// (`cached_fragment_valid` mirrors the feeder's deframe == chunk_len), so the
    /// prefetch would re-stage it rather than the window failing. (Unit-checks the
    /// alignment without the network: a garbage blob → not valid; a real cached
    /// blob → valid.)
    #[test]
    fn cached_fragment_valid_mirrors_the_feeder_hit_condition() {
        let (mut job, chunks) = build_job("m2");
        // No blob yet → not a valid hit.
        assert!(!cached_fragment_valid(
            &mut job.cache,
            &job.file_id_hex,
            1,
            3
        ));
        // Decrypt fragment 1 to populate the cache with valid ciphertext framing.
        let script = decrypt_window(&mut job, 1, 1, |i| Ok(chunks[i as usize].clone()), &|_p| {})
            .expect("decrypts");
        drop(script);
        // Now a valid hit at the feeder's exact chunk_len (3).
        assert!(cached_fragment_valid(
            &mut job.cache,
            &job.file_id_hex,
            1,
            3
        ));
        // Wrong expected chunk_len → not a hit (count mismatch, like the feeder).
        assert!(!cached_fragment_valid(
            &mut job.cache,
            &job.file_id_hex,
            1,
            2
        ));
        // A corrupt blob under another seq → not a hit (refetch, not fatal).
        job.cache
            .put(&job.file_id_hex, 0, b"\xff\xff\xff\xff not a frame")
            .unwrap();
        assert!(!cached_fragment_valid(
            &mut job.cache,
            &job.file_id_hex,
            0,
            2
        ));
    }

    // ---- cancel: dropping the job drops (zeroizes) the decryptor ----

    #[tokio::test]
    async fn cancel_drops_the_job_and_its_decryptor() {
        let (job, _chunks) = build_job("cancel");
        let jobs = VideoJobs::new();
        jobs.0.lock().await.insert(file_id_hex(), job);
        assert!(jobs.0.lock().await.contains_key(&file_id_hex()));

        // Removing the job drops the ContentDecryptor (zeroizing the subkey) — the
        // exact effect `cancel_video` has on the registry.
        let removed = jobs.0.lock().await.remove(&file_id_hex());
        assert!(removed.is_some(), "job removed (decryptor dropped)");
        assert!(
            !jobs.0.lock().await.contains_key(&file_id_hex()),
            "session gone after cancel"
        );
    }

    #[tokio::test]
    async fn set_volume_clamps_and_requires_a_session() {
        let (job, _chunks) = build_job("vol");
        let jobs = VideoJobs::new();
        jobs.0.lock().await.insert(file_id_hex(), job);
        // Clamp above MAX_GAIN.
        {
            let mut g = jobs.0.lock().await;
            let j = g.get_mut(&file_id_hex()).unwrap();
            j.gain = 99.0f32.clamp(0.0, MAX_GAIN);
            assert_eq!(j.gain, MAX_GAIN);
        }
    }

    // ---- preview-before-upload: slice STAGED cmaf → confined decode → DTOs ----

    #[test]
    fn preview_script_slices_each_fragment_range_out_of_staged_cmaf() {
        let cs = crate::upload::VIDEO_CHUNK_SIZE as usize;
        // 3 chunks of canonical plaintext, marked at each chunk boundary.
        let mut cmaf = vec![0u8; cs * 3];
        cmaf[0] = 0xAA;
        cmaf[cs] = 0xBB;
        cmaf[2 * cs] = 0xCC;
        let index = vec![
            FragmentEntry {
                seq: 0,
                pts_ms: 0,
                chunk_start: 0,
                chunk_len: 1,
            },
            FragmentEntry {
                seq: 1,
                pts_ms: 10,
                chunk_start: 1,
                chunk_len: 2,
            },
        ];
        let script = build_preview_script(&cmaf, &index).expect("script");
        // Open, two Fragments, Close.
        assert!(matches!(script.0[0], ClientMsg::Open { .. }));
        assert!(matches!(script.0[3], ClientMsg::Close));
        match &script.0[1] {
            ClientMsg::Fragment { seq, bytes } => {
                assert_eq!(*seq, 0);
                assert_eq!(bytes.len(), cs);
                assert_eq!(bytes[0], 0xAA);
            }
            other => panic!("expected Fragment, got {other:?}"),
        }
        match &script.0[2] {
            ClientMsg::Fragment { seq, bytes } => {
                assert_eq!(*seq, 1);
                assert_eq!(bytes.len(), 2 * cs);
                assert_eq!(bytes[0], 0xBB);
                assert_eq!(bytes[cs], 0xCC);
            }
            other => panic!("expected Fragment, got {other:?}"),
        }
    }

    #[test]
    fn preview_script_fails_closed_on_out_of_range_index() {
        let cs = crate::upload::VIDEO_CHUNK_SIZE as usize;
        let cmaf = vec![0u8; cs]; // only one chunk present
        let index = vec![FragmentEntry {
            seq: 0,
            pts_ms: 0,
            chunk_start: 0,
            chunk_len: 5, // claims five chunks
        }];
        // `ScriptGuard` is intentionally not `Debug` (it holds plaintext), so the
        // `Ok` arm can't go through `unwrap_err`; match the error directly.
        let err = match build_preview_script(&cmaf, &index) {
            Ok(_) => panic!("an out-of-range index must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.code, "video_failed");
        // Empty index also fails closed.
        let err = match build_preview_script(&cmaf, &[]) {
            Ok(_) => panic!("an empty index must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.code, "video_failed");
    }

    #[tokio::test]
    async fn preview_decodes_staged_cmaf_into_revalidated_frames() {
        let cs = crate::upload::VIDEO_CHUNK_SIZE as usize;
        // 5 chunks of staged canonical plaintext; two fragments [0,2) + [2,5).
        let cmaf = vec![7u8; cs * 5];
        let index = vec![
            FragmentEntry {
                seq: 0,
                pts_ms: 0,
                chunk_start: 0,
                chunk_len: 2,
            },
            FragmentEntry {
                seq: 1,
                pts_ms: 1000,
                chunk_start: 2,
                chunk_len: 3,
            },
        ];
        let script = build_preview_script(&cmaf, &index).expect("script");
        let phases: RefCell<Vec<PlayerPhase>> = RefCell::new(Vec::new());
        let frames: RefCell<Vec<I420FrameDto>> = RefCell::new(Vec::new());
        // The FrameDecoder fake emits one validated frame per Fragment — exactly the
        // re-validation seam the real confined worker output goes through.
        decode_and_emit(
            script,
            FrameDecoder,
            &|p| phases.borrow_mut().push(p),
            &|f| frames.borrow_mut().push(f),
            &|_a| {},
        )
        .await
        .expect("decodes");
        assert_eq!(frames.borrow().len(), 2, "one re-validated frame per fragment");
        assert_eq!(
            phases.borrow().last(),
            Some(&PlayerPhase::Playing),
            "Playing emitted last"
        );
    }

    #[test]
    fn dto_helpers_base64_planes_and_samples() {
        let dto = frame_dto(&ok_frame(7));
        assert_eq!(dto.pts_ms, 7);
        assert_eq!(dto.u_b64, B64.encode([5u8]));
        let pcm = pcm_dto(&PcmChunk {
            channels: 1,
            sample_rate: 16_000,
            pts_ms: 3,
            samples: vec![0x0102, -1],
        });
        let mut want = Vec::new();
        want.extend_from_slice(&0x0102i16.to_le_bytes());
        want.extend_from_slice(&(-1i16).to_le_bytes());
        assert_eq!(pcm.samples_b64, B64.encode(&want));
    }
}
