//! Video player commands — the native `stream://` range-protocol path.
//!
//! The VIEWER plays video via a native `<video>` element (WebView2 decoder) over
//! the `stream://` byte-range protocol ([`serve_range`]/[`stream_media`]); this
//! module no longer decodes anything in-process. [`open_video`] only registers
//! the decrypt-while-stream session (D5-verifies the author, derives the in-TCB
//! `ContentDecryptor`, parses the fragment index, and probes the total plaintext
//! length) — it plays nothing. The retired confined pure-Rust decode-and-emit
//! player commands (the old bounded-window decode driver, its per-window seek and
//! volume commands, and the confined-decode preview-before-upload command) have
//! been removed now that native `<video>` is the shipping viewer; see `stream.rs`
//! for the range-serving core this module wraps.
//!
//! # Security model (the dedicated review checks these)
//! * **The `ContentDecryptor` (content subkey) NEVER crosses the Tauri seam.** It
//!   lives in the `VideoJobs` managed registry (the TCB); only sliced plaintext
//!   byte ranges (already exposed by the `stream://` protocol) ever cross.
//!   Dropping the job (`cancel_video`) drops the decryptor, zeroizing the subkey.
//! * **The global `VideoJobs` lock is never held across the network prefetch.**
//!   [`serve_range`] takes it only for the two short synchronous critical sections
//!   (plan + in-TCB assemble), so `cancel_video` can preempt an in-flight range.
//! * **D5 author verification gates playback.** The served author binding is
//!   re-verified under the pinned D5 root (a forged/untrusted author → fail-closed,
//!   no content subkey released); the verified author keys feed the
//!   `VerifyContext`, so the verify ladder also fails closed if the record was
//!   signed by the wrong key.
//! * **Bounded ranges (decrypt-while-stream, NOT whole-file).** Each range request
//!   decrypts only the fragments covering the requested byte span, capped at
//!   [`MAX_RANGE_BODY`]; only ciphertext is cached (in RAM or on disk per the
//!   cache-location setting — ciphertext-only either way), plaintext is transient.
//! * **Reauth/serial discipline.** Each authed command mints a fresh channel+token
//!   under the `ConnectLock` (the Phase-3 `reauth` pattern); the identity is
//!   borrowed only under the session lock across the SYNCHRONOUS verify.
//! * **Fail-closed everywhere** with a sanitized [`PlayerPhase::Error`]/`UiError`
//!   (no decode oracle).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tauri::{Emitter, State};

use maxsecu_client_core::{
    open_content_decryptor, verify_and_open_headers, ContentDecryptor, Identity,
    MemoryTrustStore, StreamHeader,
};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::StreamType;

use crate::blob_cache::{BlobCache, Ns};
use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::commands::feed::{hex, hex16, now_ms};
use crate::config::{load_directory_pub, RouteMode, SettingsConfig};
use crate::directory::{resolve_and_verify_author_logged, resolve_my_user_id, VerifiedAuthor};
use crate::download::{build_stream_header, parse_file_view};
use crate::error::UiError;
use crate::http_client::get_json;
use crate::jobs::{AuthedChannel, UploadJobs, VideoJob, VideoJobs};
use crate::media_cache::MediaCache;
use crate::state::{PlayerPhase, EVT_PLAYER};
use crate::thumb_cache::ThumbCache;
use crate::video::{chunks_for_fragment, FragmentEntry};

/// Cap on a single range response body (open-ended `bytes=N-` streams in pieces).
/// Kept small (2 MiB) so the FIRST `bytes=0-` request a native `<video>` issues
/// only pulls ~2 covering 1 MiB chunks before returning — the browser then streams
/// the rest in bounded pieces, cutting time-to-first-frame. This need NOT be ≥ the
/// content chunk size: `assemble_range` always decrypts the whole covering
/// fragment and `slice_range` returns only the requested sub-range, so older
/// 6 MiB-chunk videos still serve correctly (a 2 MiB response slices a 6 MiB
/// fragment; the fragment is cached, so later slices of it need no refetch).
const MAX_RANGE_BODY: u64 = 2 * 1024 * 1024;

/// The body + metadata of one satisfied range response (206). `total_len` is the
/// Content-Range denominator; `start`/`len` describe the returned slice.
pub struct RangeResponse {
    pub start: u64,
    pub len: u64,
    pub total_len: u64,
    pub body: Vec<u8>,
}

/// A sanitized player-layer error (no decode oracle / internal detail crosses).
fn player_err() -> UiError {
    UiError::new("video_failed", "The video could not be played.")
}

/// The connection for this session dropped; the caller (stream_media_inner) may
/// reconnect once and retry. Distinct from player_err so the retry is targeted.
fn channel_dead() -> UiError { UiError::new("channel_dead", "The video connection dropped.") }

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
    // The shared recipient-open ctx (content-substitution guard + the REQUIRED
    // `recipient_mlkem_seed` for V2/PQ videos) lives in `build_verify_ctx`.
    let ctx = crate::directory::build_verify_ctx(file_id, author, my_id, identity);

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

/// Whether `seq`'s cached blob is a VALID hit — it deframes to EXACTLY `chunk_len`
/// ciphertext chunks — i.e. the same hit condition [`feed_fragment`] applies
/// internally (review M2). A present-but-corrupt / wrong-count blob is NOT a hit,
/// so the prefetch stages its chunks and the feeder's miss-refetch is satisfied (a
/// corrupt cache entry is recovered, not a hard playback failure). The framing is
/// the documented length-prefixed form (`u32 count`, then per chunk `u32 len` +
/// bytes); re-derived here because 4.2b's `deframe_chunks` is private and must not
/// be touched.
fn cached_fragment_valid(
    cache: &mut BlobCache,
    ns: Ns,
    file_id_hex: &str,
    seq: u32,
    chunk_len: u64,
) -> bool {
    match cache.get(ns, file_id_hex, seq) {
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

/// Probe the total plaintext content length by decrypting the LAST chunk once
/// over the real server (fetch its ciphertext, then `open_range`). Returns
/// `(n-1)*chunk_size + last_chunk_plaintext`. Uses the job's stored
/// `AuthedChannel` (no per-call reauth).
///
/// Prefers the direct-link download route (`crate::direct_link`) under
/// [`RouteMode::PreferDropbox`]; on ANY problem — link off/absent/mis-fetched, or
/// (checked here, since this fetch bypasses the fragment cache entirely — in RAM
/// or on disk per the cache-location setting — so there is no poisoned-cache
/// concern to clean up) an AEAD failure on the
/// decrypt below — it falls back to the ordinary server-proxied GET and retries
/// the decrypt exactly once. `route_mode == TorOnly` never attempts direct
/// (`direct_link::direct_allowed`).
async fn probe_total_len(
    jobs: &VideoJobs,
    file_id_hex: &str,
    chunk_size: u64,
    route_mode: RouteMode,
) -> Result<u64, UiError> {
    // Phase 1 (global lock): read n, last_idx, version, and clone the channel Arc.
    let (n, last_idx, version, channel) = {
        let guard = jobs.0.lock().await;
        let job = guard.get(file_id_hex).ok_or_else(player_err)?;
        let n = job.decryptor.content_chunk_count();
        if n == 0 {
            return Err(player_err());
        }
        let channel = job.channel.clone().ok_or_else(player_err)?;
        (n, n - 1, job.version, channel)
    };
    let direct_http = crate::direct_link::shared_direct_http();

    // Phase 2 (channel lock, no global lock): fetch the last ciphertext chunk,
    // preferring the direct route. No immediate per-chunk verify is threaded in
    // here (the decryptor lives behind the global lock, which must never be held
    // across this network await) — `accept = |_| true`; the real AEAD check is
    // Phase 3 below, with a targeted forced-proxy retry on failure.
    let (mut ct, mut used_direct) = {
        let mut ch = channel.lock().await;
        let AuthedChannel { sender, host, token } = &mut *ch;
        crate::direct_link::fetch_chunk_routed(
            sender,
            host.as_str(),
            token.as_str(),
            file_id_hex,
            version,
            "content",
            last_idx,
            route_mode,
            direct_http,
            |_| true,
        )
        .await?
    };

    // Phase 3 (global lock): decrypt just that chunk to learn its plaintext
    // length. A direct-sourced chunk that fails AEAD is refetched via the
    // server proxy and retried exactly once (fail-closed: a bad direct byte
    // never denies playback, it falls back).
    loop {
        let attempt = {
            let guard = jobs.0.lock().await;
            let job = guard.get(file_id_hex).ok_or_else(player_err)?;
            job.decryptor
                .open_range(last_idx, std::slice::from_ref(&ct))
                .map(|pt| pt.len() as u64)
        };
        match attempt {
            Ok(last_len) => return crate::stream::total_len(n, chunk_size, last_len),
            Err(_) if used_direct => {
                let mut ch = channel.lock().await;
                let AuthedChannel { sender, host, token } = &mut *ch;
                ct = crate::direct_link::fetch_chunk_proxy(
                    sender,
                    host.as_str(),
                    token.as_str(),
                    file_id_hex,
                    version,
                    "content",
                    last_idx,
                )
                .await?;
                used_direct = false; // exactly one retry
            }
            Err(_) => return Err(player_err()),
        }
    }
}

/// Trust the server-advertised plaintext content length ONLY if it is internally
/// consistent with the AUTHENTICATED `content_chunk_count` (`n`) and `chunk_size`:
/// the total must land in the last chunk, i.e. `(n-1)*cs < total <= n*cs`. Returns
/// `None` (⇒ fall back to the authenticated last-chunk probe) when the length is
/// absent (0), outside that band, or on any arithmetic overflow.
///
/// Rationale: this lets a normal open SKIP fetching + decrypting the final content
/// chunk just to learn `total_len`. The server value is unauthenticated, but it is
/// bounded here to at most one `chunk_size` of slack, and `total_len` only affects
/// range CLAMPING of the final chunk (availability) — every served content chunk is
/// still AEAD-verified, so a dishonest length can never inject or substitute bytes.
fn trusted_total_len(n: u64, chunk_size: u64, server_total: u64) -> Option<u64> {
    if n == 0 || chunk_size == 0 || server_total == 0 {
        return None;
    }
    let hi = n.checked_mul(chunk_size)?;
    let lo = (n - 1).checked_mul(chunk_size)?;
    (server_total > lo && server_total <= hi).then_some(server_total)
}

/// `open_video` — open + verify a video and register its decrypt-while-stream
/// session (D5-verifies the author, derives the in-TCB `ContentDecryptor`, parses
/// the fragment index, and probes the total plaintext length). Plays nothing: the
/// native `<video>` element drives playback via the `stream://` range protocol
/// ([`serve_range`]/[`stream_media`]) once this registers the session. Emits
/// [`PlayerPhase::Error`] over [`EVT_PLAYER`] on failure. Sanitized errors.
#[tauri::command]
pub async fn open_video(
    file_id: String,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    jobs: State<'_, VideoJobs>,
    dir_cache: State<'_, crate::directory::DirectoryCache>,
) -> Result<(), UiError> {
    let out = open_video_inner(&file_id, &dir, &session, &connect_lock, &jobs, &dir_cache).await;
    if let Err(e) = &out {
        let _ = app.emit(
            EVT_PLAYER,
            PlayerPhase::Error {
                code: e.code.clone(),
            },
        );
        // Clean up any partially-registered job (drops the decryptor → zeroizes).
        if let Ok(bytes) = hex16(&file_id) {
            jobs.0.lock().await.remove(&hex(&bytes));
        }
    }
    out
}

async fn open_video_inner(
    file_id_str: &str,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    jobs: &State<'_, VideoJobs>,
    dir_cache: &State<'_, crate::directory::DirectoryCache>,
) -> Result<(), UiError> {
    // Validate the REQUESTED id up front (it is what the served record must bind to
    // and is interpolated into the request URL). Canonical lowercase hex is the
    // cache + jobs-registry key.
    let file_id = hex16(file_id_str)?;
    let file_id_hex = hex(&file_id);
    // The route setting is read once here and reused for every network fetch
    // this session makes (the header below, the total-length probe, and every
    // `serve_range`) — a mid-session settings edit takes effect on the NEXT
    // `open_video`, not retroactively.
    let settings = SettingsConfig::load(&dir.0);
    let route_mode = settings.connection.route_mode;
    let direct_http = crate::direct_link::shared_direct_http();
    let pinned = load_directory_pub(&dir.0)?;
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();

    let username = {
        let s = session.0.lock().await;
        s.username.clone()
    }
    .ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;
    // Offline-D5 hop (spec §3/§7): resolve the effective directory verifier over the
    // pinned connection; fail closed on a bad delegation before any binding is trusted.
    // A warm session delegation cache makes this a no-op (no extra round-trip) on the
    // hot path shared by a bundle's videos.
    let verifier =
        crate::directory::build_delegated_verifier(&mut sender, &host, pinned, now).await?;

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

    // D5-verify the author binding (fail-closed) BEFORE any decode — reusing the
    // session cache when a recent open already verified this author (a bundle's
    // videos share one author). A cache entry was D5-verified AND transparency-
    // checked at insert time, so a hit safely skips both network round-trips.
    let author_id = manifest.author_id.0;
    let author = match dir_cache.author(&author_id, now) {
        Some(a) => a,
        None => {
            let (author, author_binding) = resolve_and_verify_author_logged(
                &mut sender,
                &host,
                &hex(&author_id),
                &verifier,
                &mut trust,
                now,
            )
            .await?;
            // Trust-alarm C (spec §0-C/§7): block the streaming OPEN unless the served
            // author binding is provably present in the directory key-transparency log
            // under a pinned, non-equivocating checkpoint (opt-in; mirrors feed/viewer).
            crate::commands::feed::enforce_author_transparency(
                &dir.0,
                session.inner(),
                author_binding,
            )
            .await?;
            dir_cache.put_author(author_id, author.clone(), now);
            author
        }
    };
    // My own user_id is stable for the session — cache it after the first resolve.
    let my_id = match dir_cache.my_id(&username) {
        Some(id) => id,
        None => {
            let id =
                resolve_my_user_id(&mut sender, &host, &username, &verifier, &mut trust, now)
                    .await?;
            dir_cache.put_my_id(&username, id);
            id
        }
    };

    // Header (small streams only — no content fetched here). Prefers the
    // direct-link route per the effective `route_mode`.
    let (header, header_used_direct) = build_stream_header(
        &mut sender,
        &host,
        &token,
        &file_id_hex,
        &view,
        route_mode,
        direct_http,
    )
    .await?;

    // TCB: build the decryptor + fragment index under the session lock (sync verify;
    // the identity borrow never spans an await). If a direct-sourced header chunk
    // failed the header's AEAD/digest verification, refetch the WHOLE header
    // forced-proxy and retry exactly once — fail-closed: a tampered/substituted
    // direct link never denies playback, it falls back (the link source is
    // untrusted; a genuinely-invalid record still fails on the retry, same as
    // today).
    let (decryptor, index) = match {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        open_video_job_core(identity, file_id, &author, my_id, &header)
    } {
        Ok(opened) => opened,
        Err(e) if header_used_direct => {
            let (header, _) = build_stream_header(
                &mut sender,
                &host,
                &token,
                &file_id_hex,
                &view,
                RouteMode::PreferServer,
                None,
            )
            .await?;
            let guard = session.0.lock().await;
            let identity = guard
                .identity
                .as_ref()
                .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
            open_video_job_core(identity, file_id, &author, my_id, &header).map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };
    let version = decryptor.version();

    // Content stream descriptor from the (authenticated-envelope) view — `chunk_size`
    // is the byte↔chunk unit for range serving.
    let content_stream = view
        .streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .ok_or_else(player_err)?;
    let chunk_size = content_stream.chunk_size;
    // Prefer the server-advertised plaintext length when it is consistent with the
    // AUTHENTICATED content_chunk_count (skips the last-chunk fetch+decrypt probe →
    // faster time-to-first-frame). `None` ⇒ fall back to the authenticated probe.
    let trusted_total =
        trusted_total_len(decryptor.content_chunk_count(), chunk_size, content_stream.total_bytes);

    // Register the session; probe the total plaintext length by decrypting ONLY the
    // last fragment once, but ONLY when the server length was unusable (`route_mode`
    // was loaded above and is reused for every network fetch in the session). The
    // ciphertext fragment cache is the app-global shared `MediaCache` (built at
    // startup, Task 7) — no per-job cache is created here.

    // Move the open-time authed connection into a persistent channel for all range
    // fetches in this session (probe_total_len + every serve_range). After this point
    // `sender`/`host`/`token` are consumed — all subsequent network access goes
    // through the channel's Mutex, serializing overlapping range requests.
    let channel = Arc::new(tokio::sync::Mutex::new(
        AuthedChannel { sender, host, token },
    ));
    jobs.0.lock().await.insert(
        file_id_hex.clone(),
        VideoJob {
            decryptor,
            index,
            file_id_hex: file_id_hex.clone(),
            version,
            chunk_size,
            total_len: trusted_total.unwrap_or(0), // authenticated probe below if None
            channel: Some(channel),
            route_mode,
        },
    );

    // Only probe (fetch + decrypt the last chunk) when the server length was absent
    // or inconsistent with the authenticated chunk count.
    if trusted_total.is_none() {
        let total = probe_total_len(jobs, &file_id_hex, chunk_size, route_mode).await?;
        if let Some(job) = jobs.0.lock().await.get_mut(&file_id_hex) {
            job.total_len = total;
        }
    }
    Ok(())
}

/// `cancel_video` — drop the session from `VideoJobs` (drops the `ContentDecryptor`
/// → zeroizes the content subkey). Emits the benign terminal `Error { code:
/// "cancelled" }`.
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

/// Dual-mode gauge readout for BOTH app-global caches (Media + Thumbnails).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CacheStats {
    /// Media cache fill: in-RAM ciphertext bytes (Memory mode) or on-disk bytes
    /// (Disk mode). Reconciled to the live cap in Memory mode so the gauge never
    /// reads over 100%.
    pub media_used: u64,
    /// Thumbnails cache fill, same RAM/disk semantics as `media_used`.
    pub thumb_used: u64,
    /// `true` when both caches use the on-disk backend (they share one location),
    /// so the UI divides the fill by `disk_free_estimate` instead of the RAM cap.
    pub disk_mode: bool,
    /// The startup free-space estimate for the Disk-mode gauge denominator; `0`
    /// when unknown (probe failed) or in RAM mode.
    pub disk_free_estimate: u64,
}

/// `cache_stats` — the header gauges' poll (~every 1.5 s). Reconciles EACH cache to
/// its live cap in Memory mode (LRU-evicts down so a gauge dividing by the live cap
/// can never read over 100% — the >100% bug this rework fixes) and reports both
/// fills. Because both caches share the one location, the Media cache's `disk_mode`
/// governs the denominator: RAM cap in Memory mode, the stashed startup disk-free
/// estimate in Disk mode. Cheap: two brief locks + LRU trims, no network I/O.
#[tauri::command]
pub async fn cache_stats(
    media_cap_bytes: u64,
    thumb_cap_bytes: u64,
    media: State<'_, MediaCache>,
    thumb: State<'_, ThumbCache>,
    disk_free: State<'_, crate::disk_free::DiskFreeEstimate>,
) -> Result<CacheStats, UiError> {
    let (media_used, disk_mode) = media.gauge_fill(media_cap_bytes).await;
    let (thumb_used, _) = thumb.gauge_fill(thumb_cap_bytes).await;
    let disk_free_estimate = if disk_mode {
        disk_free.0.unwrap_or(0)
    } else {
        0
    };
    Ok(CacheStats {
        media_used,
        thumb_used,
        disk_mode,
        disk_free_estimate,
    })
}

/// Clear + zeroize the Media cache (D8 case 3). No effect on any open VideoJob's
/// decryptor — only cached bytes drop; an in-flight serve_range simply re-fetches.
#[tauri::command]
pub async fn clear_media_cache(media: State<'_, MediaCache>) -> Result<(), UiError> {
    media.0.lock().await.clear_and_zeroize();
    Ok(())
}

/// Clear + zeroize the Thumbnails cache.
#[tauri::command]
pub async fn clear_thumb_cache(thumb: State<'_, ThumbCache>) -> Result<(), UiError> {
    thumb.clear_and_zeroize().await;
    Ok(())
}

// ===========================================================================
// stream:// range protocol (Task 5). Serves per-range-decrypted plaintext bytes
// to a native <video> element via a Tauri async URI-scheme protocol. The content
// key NEVER leaves this process; only sliced plaintext is returned. Errors are
// oracle-free: 404 (unknown/closed id or bad path), 416 (unsatisfiable range),
// 500 (everything else), empty bodies.
// ===========================================================================

/// Map a routed/proxy fetch error to the caller's two outcomes: `"offline"`
/// (a real transport failure — the persistent channel is dead, so the caller
/// reconnects once and retries) becomes [`channel_dead`]; anything else (a
/// non-OK status, a malformed response) becomes the generic [`player_err`] (the
/// server actively refused/errored — not a dead channel).
fn map_fetch_err(e: UiError) -> UiError {
    if e.code == "offline" {
        channel_dead()
    } else {
        player_err()
    }
}

/// Serve one plaintext byte range for an OPEN video session over the real server:
/// (A) plan the covering fragment span + which ciphertext chunks are missing, under
/// the jobs lock; (B) prefetch the missing ciphertext under the JOB's persistent
/// `AuthedChannel` lock (no global jobs lock held, no per-range reauth), preferring
/// the direct-link download route (`crate::direct_link`) per the job's captured
/// [`RouteMode`]; (C) assemble + slice under the jobs lock. If a direct-sourced
/// chunk fails the fragment's AEAD check, (D) refetch precisely those indices via
/// the forced server proxy and retry the assemble exactly once — fail-closed: a
/// tampered/substituted direct link never denies playback, it falls back. The
/// content key never leaves this process; only the sliced plaintext is returned.
/// `first`/`last_inclusive` are the parsed HTTP byte-range bounds. Returns
/// `channel_dead` on a transport error so the caller can reconnect once and retry.
///
/// Public: the stream:// protocol core (carries no secret across the seam — only sliced
/// plaintext the protocol already exposes).
///
/// The fragment cache is the app-global shared [`MediaCache`]; every phase that
/// touches it locks `media` NESTED inside the `jobs` lock (lock order
/// **VideoJobs → MediaCache**, never the reverse — that would deadlock). The
/// `job` borrow is now immutable (the cache is external), so `cancel_video` can
/// drop the session between phases while its cached fragments persist in the
/// shared cache.
pub async fn serve_range(
    jobs: &VideoJobs,
    media: &MediaCache,
    file_id_hex: &str,
    first: u64,
    last_inclusive: Option<u64>,
) -> Result<RangeResponse, UiError> {
    use crate::stream::{assemble_range, plan_range, resolve_range};

    // Phase A — resolve the request + plan the fragment span + fetch list, under the
    // jobs lock; check the shared cache under the media lock (nested, VideoJobs →
    // MediaCache). Also clone the channel Arc (a cheap ref-count bump) before
    // dropping the guards.
    let (req, plan, total_len, version, fetch_indices, channel, route_mode) = {
        let guard = jobs.0.lock().await;
        let job = guard.get(file_id_hex).ok_or_else(player_err)?;
        let req = resolve_range(first, last_inclusive, job.total_len, MAX_RANGE_BODY)
            .ok_or_else(|| UiError::new("range_not_satisfiable", "range"))?;
        let plan = plan_range(&job.index, job.chunk_size, &req)?;
        let mut fetch_indices: Vec<u64> = Vec::new();
        {
            let mut cache = media.0.lock().await; // VideoJobs -> MediaCache
            for seq in plan.f0..=plan.f1 {
                let (cs, cl) = chunks_for_fragment(&job.index, seq).ok_or_else(player_err)?;
                if !cached_fragment_valid(&mut cache, Ns::Frag, &job.file_id_hex, seq, cl) {
                    let end = cs.checked_add(cl).ok_or_else(player_err)?;
                    fetch_indices.extend(cs..end);
                }
            }
        }
        let channel = job.channel.clone().ok_or_else(player_err)?;
        (req, plan, job.total_len, job.version, fetch_indices, channel, job.route_mode)
    };

    // Phase B — prefetch missing ciphertext under the channel lock (no global jobs lock
    // held). Overlapping range requests serialize here over the single HTTP/1.1 connection
    // instead of contending the ConnectLock with concurrent reauths. Prefers the
    // direct-link route; `direct_used` tracks which indices came from it (untrusted
    // source) so a later AEAD failure can be retried precisely against those.
    let direct_http = crate::direct_link::shared_direct_http();
    let mut prefetched: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut direct_used: HashSet<u64> = HashSet::new();
    {
        let mut ch = channel.lock().await;
        let AuthedChannel { sender, host, token } = &mut *ch;
        for i in fetch_indices {
            let (bytes, used_direct) = crate::direct_link::fetch_chunk_routed(
                sender,
                host.as_str(),
                token.as_str(),
                file_id_hex,
                version,
                "content",
                i,
                route_mode,
                direct_http,
                |_| true, // no immediate per-chunk verify here — see Phase D below
            )
            .await
            .map_err(map_fetch_err)?;
            prefetched.insert(i, bytes);
            if used_direct {
                direct_used.insert(i);
            }
        }
    }

    // Phase C — assemble + slice under jobs → media (sync decrypt in the TCB).
    // `work` is a throwaway clone so `prefetched` survives intact for a Phase-D
    // retry (`assemble_range`'s fetch closure destructively removes from whatever
    // map it is given). `job` is an immutable borrow (the cache is external now).
    let attempt = {
        let guard = jobs.0.lock().await;
        let job = guard.get(file_id_hex).ok_or_else(player_err)?;
        let mut cache = media.0.lock().await; // VideoJobs -> MediaCache
        let mut work = prefetched.clone();
        assemble_range(
            &job.index,
            &mut cache,
            Ns::Frag,
            &job.decryptor,
            &job.file_id_hex,
            &plan,
            &req,
            |i| work.remove(&i).ok_or_else(player_err),
        )
    };

    let body = match attempt {
        Ok(b) => b,
        Err(_) if !direct_used.is_empty() => {
            // Phase D — a direct-sourced chunk failed AEAD (the link source is
            // untrusted). Refetch exactly those indices via the forced proxy...
            {
                let mut ch = channel.lock().await;
                let AuthedChannel { sender, host, token } = &mut *ch;
                for i in &direct_used {
                    let bytes = crate::direct_link::fetch_chunk_proxy(
                        sender,
                        host.as_str(),
                        token.as_str(),
                        file_id_hex,
                        version,
                        "content",
                        *i,
                    )
                    .await
                    .map_err(map_fetch_err)?;
                    prefetched.insert(*i, bytes);
                }
            }
            // ...evict every fragment in the plan span first (under jobs → media):
            // `feed_fragment` writes a fragment's ciphertext to the cache BEFORE the
            // AEAD check that just failed, so the failed attempt may have poisoned
            // the cache with the tampered bytes — without evicting, the retry would
            // read those same bad bytes back as a cache "hit" and never see the
            // fresh (now-proxied) ones.
            let guard = jobs.0.lock().await;
            let job = guard.get(file_id_hex).ok_or_else(player_err)?;
            let mut cache = media.0.lock().await; // VideoJobs -> MediaCache
            for seq in plan.f0..=plan.f1 {
                cache.evict(Ns::Frag, &job.file_id_hex, seq);
            }
            assemble_range(
                &job.index,
                &mut cache,
                Ns::Frag,
                &job.decryptor,
                &job.file_id_hex,
                &plan,
                &req,
                |i| prefetched.remove(&i).ok_or_else(player_err),
            )?
        }
        Err(e) => return Err(e),
    };

    Ok(RangeResponse { start: req.start, len: req.len, total_len, body })
}

/// The `stream://media/<file_id_hex>` protocol entry point. Resolves the open
/// session, mints a fresh authed channel (Phase-3 reauth), serves the requested
/// byte range, and builds a `206 Partial Content` response. Errors map to 416
/// (unsatisfiable range) or 500 (everything else) with an empty body — no oracle.
pub async fn stream_media(
    app: &tauri::AppHandle,
    path: &str,
    range_header: Option<&str>,
) -> http::Response<Vec<u8>> {
    match stream_media_inner(app, path, range_header).await {
        Ok(r) => http::Response::builder()
            .status(206)
            .header(http::header::CONTENT_TYPE, "video/mp4")
            .header(http::header::ACCEPT_RANGES, "bytes")
            .header(
                http::header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", r.start, r.start + r.len - 1, r.total_len),
            )
            .header(http::header::CONTENT_LENGTH, r.len.to_string())
            .body(r.body)
            .unwrap_or_else(|_| http::Response::builder().status(500).body(Vec::new()).unwrap()),
        Err(code) => {
            let status = if code == 416 { 416 } else { 500 };
            http::Response::builder().status(status).body(Vec::new()).unwrap()
        }
    }
}

/// Serve one bounded byte range from the on-disk staged fMP4 (`out.mp4` in the
/// per-job temp dir). Bounded — never reads the whole file; caps the response to
/// [`MAX_RANGE_BODY`]. Returns `None` (⇒ 416) for an unsatisfiable range or any
/// I/O error (fail-closed). Pure — no lock, no network, no decrypt.
fn preview_slice_file(path: &std::path::Path, first: u64, last_inclusive: Option<u64>) -> Option<RangeResponse> {
    use std::io::{Read, Seek, SeekFrom};
    let total = std::fs::metadata(path).ok()?.len();
    let req = crate::stream::resolve_range(first, last_inclusive, total, MAX_RANGE_BODY)?;
    let mut file = std::fs::File::open(path).ok()?;
    file.seek(SeekFrom::Start(req.start)).ok()?;
    let mut body = vec![0u8; req.len as usize];
    file.read_exact(&mut body).ok()?;
    Some(RangeResponse { start: req.start, len: req.len, total_len: total, body })
}

/// Serve one byte range of an author PREVIEW's staged fMP4 — plaintext the author
/// already owns, read by range from disk; NO decrypt, NO auth, NO network.
/// Unknown job / no preview ⇒ not_found; unsatisfiable range ⇒ range_not_satisfiable.
async fn serve_preview_range(jobs: &UploadJobs, job_id: &str, first: u64, last_inclusive: Option<u64>) -> Result<RangeResponse, UiError> {
    let guard = jobs.0.lock().await;
    let job = guard.get(job_id).ok_or_else(|| UiError::new("not_found", "unknown preview"))?;
    let preview = job.preview.as_ref().ok_or_else(|| UiError::new("not_found", "no preview"))?;
    preview_slice_file(&preview.out_mp4_path, first, last_inclusive).ok_or_else(|| UiError::new("range_not_satisfiable", "range"))
}

/// Inner: resolve the namespace and id from the path, dispatch to the media (view)
/// or preview (author staged fMP4) handler, parse the Range header, and serve.
/// Returns an HTTP status code (`u16`) on error.
async fn stream_media_inner(
    app: &tauri::AppHandle,
    path: &str,
    range_header: Option<&str>,
) -> Result<RangeResponse, u16> {
    use tauri::Manager;
    // Parse `/<ns>/<id>` from the path. The host is `stream.localhost`; the FIRST
    // non-empty segment is the namespace (`media` or `preview`), the SECOND is the id.
    // Anything else (missing segment, extra segments, bare path) 404s.
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let (ns, id) = match segs.as_slice() { [ns, id] => (*ns, *id), _ => return Err(404u16) };

    match ns {
        "media" => {
            // Validate the file id — must be 16 raw hex bytes (32 hex chars).
            let file_id_hex = id.to_string();
            let _ = hex16(&file_id_hex).map_err(|_| 404u16)?;

            let dir = app.state::<AppDir>();
            let session = app.state::<Session>();
            let connect_lock = app.state::<ConnectLock>();
            let jobs = app.state::<VideoJobs>();
            let media = app.state::<MediaCache>();

            // The session must already be open (open_video registered it).
            {
                let guard = jobs.0.lock().await;
                if !guard.contains_key(&file_id_hex) {
                    return Err(404);
                }
            }

            // Parse "bytes=first-[last]" (default first=0 when absent).
            let (first, last_inclusive) = parse_byte_range(range_header);

            // First attempt over the session's persistent authed channel (no reauth
            // needed for normal operation — overlapping requests serialize via the
            // channel Mutex).
            match serve_range(&jobs, &media, &file_id_hex, first, last_inclusive).await {
                Ok(r) => Ok(r),
                Err(e) if e.code == "channel_dead" => {
                    // The persistent connection dropped. Reconnect ONCE (needs app
                    // state), replace the job's channel in-place, and retry the range.
                    let server = server_of(&dir.0).map_err(|_| 500u16)?;
                    let (sender, host, token) =
                        reauth(&dir.0, &server, &session, &connect_lock).await.map_err(|_| 500u16)?;
                    let chan = {
                        let g = jobs.0.lock().await;
                        g.get(&file_id_hex).and_then(|j| j.channel.clone())
                    }
                    .ok_or(404u16)?;
                    {
                        let mut c = chan.lock().await;
                        *c = AuthedChannel { sender, host, token };
                    }
                    serve_range(&jobs, &media, &file_id_hex, first, last_inclusive)
                        .await
                        .map_err(|e| if e.code == "range_not_satisfiable" { 416 } else { 500 })
                }
                Err(e) => Err(if e.code == "range_not_satisfiable" { 416 } else { 500 }),
            }
        }
        "preview" => {
            // Serve the author's staged plaintext fMP4 by range. No hex16 validation —
            // a job_id is an opaque string, not a file hex16. No decrypt, no auth, no
            // network — the author already owns this plaintext.
            let upload_jobs = app.state::<UploadJobs>();
            let (first, last_inclusive) = parse_byte_range(range_header);
            serve_preview_range(&upload_jobs, id, first, last_inclusive).await
                .map_err(|e| match e.code.as_str() {
                    "not_found" => 404u16,
                    "range_not_satisfiable" => 416,
                    _ => 500,
                })
        }
        _ => Err(404u16),
    }
}

/// Parse an HTTP `Range: bytes=first-[last]` value into `(first, last_inclusive)`.
/// A missing/garbled header defaults to `(0, None)` (whole resource from the start,
/// capped by `MAX_RANGE_BODY` in `resolve_range`). Only a single range is honored.
fn parse_byte_range(h: Option<&str>) -> (u64, Option<u64>) {
    let Some(h) = h else { return (0, None) };
    let Some(spec) = h.trim().strip_prefix("bytes=") else { return (0, None) };
    let spec = spec.split(',').next().unwrap_or("").trim();
    let mut parts = spec.splitn(2, '-');
    let first = parts.next().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    let last = parts
        .next()
        .and_then(|s| { let s = s.trim(); if s.is_empty() { None } else { s.parse::<u64>().ok() } });
    (first, last)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use crate::video::feed_fragment;
    use maxsecu_client_core::{
        build_upload, PlaintextStreams, StreamChunks, UploadBundle, UploadParams,
    };
    use maxsecu_crypto::generate_enc_keypair;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::types::{FileType, Id, RecipientType, Timestamp};

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
            mlkem_pub: None,
        }
    }

    /// Build a real, registered `VideoJob` over staged encrypted content — the same
    /// TCB path `open_video` takes, minus the network. The fragment cache is now the
    /// app-global shared cache (external to the job), so this also returns a fresh
    /// standalone `BlobCache` (`Ns::Frag`) that the range-serving tests thread in
    /// where `serve_range` would supply the shared `MediaCache`.
    fn build_job(tag: &str) -> (VideoJob, BlobCache, Vec<Vec<u8>>) {
        let (owner, bundle, _content) = build_video();
        let (header, chunks) = split(&bundle);
        let author = author_of(&owner);
        let (decryptor, index) =
            open_video_job_core(&owner, FILE_ID.0, &author, OWNER_ID.0, &header).expect("core");
        assert_eq!(index.len(), 2, "two-fragment index parsed");
        let dir = tmp_dir(tag);
        let cache = BlobCache::open(&dir, 1 << 20).unwrap();
        let version = decryptor.version();
        let job = VideoJob {
            decryptor,
            index,
            file_id_hex: file_id_hex(),
            version,
            chunk_size: 4096,
            total_len: 0,
            channel: None, // unit tests never serve ranges
            route_mode: RouteMode::PreferServer,
        };
        (job, cache, chunks)
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
            mlkem_pub: None,
        };
        // `ContentDecryptor` is not `Debug`, so the `Ok` arm can't go through
        // `unwrap_err`; match the error directly.
        let err = match open_video_job_core(&owner, FILE_ID.0, &forged, OWNER_ID.0, &header) {
            Ok(_) => panic!("a forged author must not open the video"),
            Err(e) => e,
        };
        assert_eq!(err.code, "video_failed");
    }

    /// M2: a present-but-corrupt cached blob is treated as NOT a valid hit
    /// (`cached_fragment_valid` mirrors the feeder's deframe == chunk_len), so the
    /// prefetch would re-stage it rather than the window failing. (Unit-checks the
    /// alignment without the network: a garbage blob → not valid; a real cached
    /// blob → valid.) Populates the cache directly via `feed_fragment` (the shared
    /// range-serving feeder) rather than the retired decode-path `decrypt_window`.
    #[test]
    fn cached_fragment_valid_mirrors_the_feeder_hit_condition() {
        let (job, mut cache, chunks) = build_job("m2");
        // No blob yet → not a valid hit.
        assert!(!cached_fragment_valid(
            &mut cache,
            Ns::Frag,
            &job.file_id_hex,
            1,
            3
        ));
        // Feed fragment 1 directly to populate the cache with valid ciphertext framing.
        feed_fragment(
            &job.index,
            &mut cache,
            Ns::Frag,
            &job.decryptor,
            &job.file_id_hex,
            1,
            |i| Ok(chunks[i as usize].clone()),
            |_pt| Ok(()),
        )
        .expect("feeds");
        // Now a valid hit at the feeder's exact chunk_len (3).
        assert!(cached_fragment_valid(
            &mut cache,
            Ns::Frag,
            &job.file_id_hex,
            1,
            3
        ));
        // Wrong expected chunk_len → not a hit (count mismatch, like the feeder).
        assert!(!cached_fragment_valid(
            &mut cache,
            Ns::Frag,
            &job.file_id_hex,
            1,
            2
        ));
        // A corrupt blob under another seq → not a hit (refetch, not fatal).
        cache
            .put(Ns::Frag, &job.file_id_hex, 0, b"\xff\xff\xff\xff not a frame")
            .unwrap();
        assert!(!cached_fragment_valid(
            &mut cache,
            Ns::Frag,
            &job.file_id_hex,
            0,
            2
        ));
    }

    // ---- cancel: dropping the job drops (zeroizes) the decryptor ----

    #[tokio::test]
    async fn cancel_drops_the_job_and_its_decryptor() {
        let (job, _cache, _chunks) = build_job("cancel");
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

    /// The rework's core guarantee: the ciphertext cache is app-global and EXTERNAL
    /// to the `VideoJob`, so dropping a job (exactly what `cancel_video` does —
    /// remove it from `VideoJobs`) must NOT drop the cached fragment bytes. A later
    /// re-open is then a cache HIT (no refetch). The standalone `BlobCache` here
    /// stands in for the shared `MediaCache` the real `serve_range` threads in.
    #[tokio::test]
    async fn cancel_drops_job_but_shared_cache_persists() {
        let (job, mut cache, _chunks) = build_job("persist");
        let fid = job.file_id_hex.clone();
        // Populate the shared cache with a fragment keyed by this job's file_id.
        let blob = b"\x00opaque-ciphertext\xff".to_vec();
        cache.put(Ns::Frag, &fid, 0, &blob).unwrap();
        assert!(cache.contains(Ns::Frag, &fid, 0));

        let jobs = VideoJobs::new();
        jobs.0.lock().await.insert(fid.clone(), job);
        assert!(jobs.0.lock().await.contains_key(&fid));

        // Remove the job (the exact effect of `cancel_video`) — drops the decryptor,
        // NOT the external cache.
        let removed = jobs.0.lock().await.remove(&fid);
        assert!(removed.is_some(), "job removed (decryptor dropped)");
        assert!(
            !jobs.0.lock().await.contains_key(&fid),
            "session gone after cancel"
        );

        // The shared cache STILL holds the fragment — a re-open is a hit, not a
        // refetch. This is the whole point of the rework.
        assert!(
            cache.contains(Ns::Frag, &fid, 0),
            "cache bytes persist across cancel"
        );
        assert_eq!(
            cache.get(Ns::Frag, &fid, 0).as_deref(),
            Some(blob.as_slice()),
            "the exact ciphertext survives the job drop"
        );
    }

    #[test]
    fn trusted_total_len_accepts_only_last_chunk_consistent_lengths() {
        let cs = 1024 * 1024;
        // n=3 chunks: total must be in ((3-1)*cs, 3*cs] = (2 MiB, 3 MiB].
        assert_eq!(super::trusted_total_len(3, cs, 2 * cs + 1), Some(2 * cs + 1)); // just over lo
        assert_eq!(super::trusted_total_len(3, cs, 3 * cs), Some(3 * cs)); // full last chunk
        assert_eq!(super::trusted_total_len(3, cs, 2 * cs + 500), Some(2 * cs + 500));
        // Out of band → probe (None).
        assert_eq!(super::trusted_total_len(3, cs, 2 * cs), None); // == lo (too small)
        assert_eq!(super::trusted_total_len(3, cs, 3 * cs + 1), None); // > hi
        assert_eq!(super::trusted_total_len(3, cs, 0), None); // absent
        assert_eq!(super::trusted_total_len(0, cs, 100), None); // no chunks
        assert_eq!(super::trusted_total_len(3, 0, 100), None); // no chunk size
        // n=1: total in (0, cs].
        assert_eq!(super::trusted_total_len(1, cs, 1), Some(1));
        assert_eq!(super::trusted_total_len(1, cs, cs), Some(cs));
        assert_eq!(super::trusted_total_len(1, cs, cs + 1), None);
    }

    #[test]
    fn parse_byte_range_forms() {
        assert_eq!(super::parse_byte_range(None), (0, None));
        assert_eq!(super::parse_byte_range(Some("bytes=0-")), (0, None));
        assert_eq!(super::parse_byte_range(Some("bytes=100-199")), (100, Some(199)));
        assert_eq!(super::parse_byte_range(Some("bytes=500-")), (500, None));
        assert_eq!(super::parse_byte_range(Some("garbage")), (0, None));
        assert_eq!(super::parse_byte_range(Some("bytes=0-99,200-299")), (0, Some(99)));
    }

    /// `preview_slice_file` reads exactly the requested bounded range from disk, caps
    /// open-ended requests at `MAX_RANGE_BODY`, and returns `None` for an unsatisfiable
    /// range (`first == total_len`). Exercises the seek+read_exact path without a whole-
    /// file read.
    #[test]
    fn preview_slice_file_reads_bounded_range() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "mxs-pvf-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.mp4");
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        {
            let mut f = std::fs::File::create(&path).expect("create test file");
            f.write_all(&data).expect("write test data");
        }

        // Bounded range [100, 199] inclusive → exactly 100 bytes at the right offset.
        let r = preview_slice_file(&path, 100, Some(199))
            .expect("bounded range should be satisfiable");
        assert_eq!(r.start, 100);
        assert_eq!(r.len, 100);
        assert_eq!(r.total_len, 5000);
        assert_eq!(r.body, data[100..200].to_vec(), "body must match file bytes [100,200)");

        // Open-ended [0, ): 5000 < MAX_RANGE_BODY → entire file returned.
        let r2 = preview_slice_file(&path, 0, None)
            .expect("open-ended range should be satisfiable");
        assert_eq!(r2.len, 5000);
        assert_eq!(r2.total_len, 5000);
        assert_eq!(r2.body, data, "open-ended body must equal entire file");

        // Unsatisfiable: first == total_len → None (⇒ 416).
        assert!(
            preview_slice_file(&path, 5000, None).is_none(),
            "first == total_len must be unsatisfiable (None/416)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gauge readout (via `MediaCache::gauge_fill`, which `cache_stats` calls) can
    /// never report over the live cap in Memory mode — it reconciles down first.
    #[tokio::test]
    async fn cache_stats_memory_never_over_cap() {
        let dir = tmp_dir("stats-cap");
        let media = MediaCache::open(&dir, 1, crate::config::FragmentCacheLocation::Memory).unwrap();
        {
            let mut c = media.0.lock().await;
            for s in 0..8u32 {
                c.put(Ns::Frag, "aa", s, &[0u8; 100 * 1024]).unwrap();
            }
        }
        let cap = 200 * 1024;
        let (used, disk_mode) = media.gauge_fill(cap).await;
        assert!(!disk_mode);
        assert!(used <= cap, "fill {used} must not exceed the live cap {cap}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `clear_media_cache` / `clear_thumb_cache` each zero ONLY their own target
    /// (they are independent caches sharing only the process seal).
    #[tokio::test]
    async fn clear_one_cache_leaves_the_other_intact() {
        let dir = tmp_dir("clear-indep");
        let seal = std::sync::Arc::new(crate::session_seal::SessionSeal::generate());
        let media = MediaCache::open(&dir, 1, crate::config::FragmentCacheLocation::Memory).unwrap();
        let thumb = ThumbCache::new(&dir, 64, crate::config::FragmentCacheLocation::Memory, seal.clone()).unwrap();
        let key = crate::thumb_cache::CacheKey {
            file_id: [5u8; 16],
            version: 1,
        };
        media.put_content(&seal, key, b"content-bytes").await;
        thumb
            .put_card(
                key,
                crate::thumb_cache::CachedMeta {
                    file_type: "blog".into(),
                    title: "t".into(),
                    tags: vec![],
                    thumbnail_b64: None,
                    author_fp: "fp".into(),
                    recovery_ok: true,
                    mine: false,
                    member_counts: crate::dto::MemberCounts::default(),
                },
            )
            .await;
        assert!(media.get_content(&seal, key).await.is_some());
        assert!(thumb.get_meta(key).await.is_some());

        // Clearing Media leaves Thumbnails intact…
        media.0.lock().await.clear_and_zeroize();
        assert!(media.get_content(&seal, key).await.is_none());
        assert!(thumb.get_meta(key).await.is_some(), "thumb untouched by media clear");

        // …and vice versa.
        thumb.clear_and_zeroize().await;
        assert!(thumb.get_meta(key).await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
