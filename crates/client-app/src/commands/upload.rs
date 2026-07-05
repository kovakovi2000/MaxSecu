//! Upload commands. `stage_upload` transcodes/encrypts the user's chosen content
//! and holds the bundle for preview (NO network write); `confirm_upload` runs the
//! network pipeline. Only preview/progress DTOs cross the seam — never the bundle,
//! keys, or plaintext.
//!
//! Video uploads are STREAMING (no whole-file RAM buffer):
//!   - `stage_upload` does a pass-1 disk stream to compute the manifest digest,
//!     builds the signed records WITHOUT content ciphertext, persists a
//!     `StagingRecord`, and moves `out.mp4` into the app staging dir — NO network.
//!   - `confirm_upload` does a pass-2 disk stream: re-seals one chunk at a time
//!     (O(one 6 MiB chunk) RAM) and PUTs each chunk immediately.
//! Images and blogs are unchanged (in-RAM `UploadBundle`).

use std::io::{Read, Seek, SeekFrom};

use tauri::State;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::Zeroize;

use maxsecu_client_core::{
    build_upload, resume_content_sealer, DirectoryVerifier, Identity, MemoryTrustStore,
    SmallStreams, StreamingUploadBuilder, UploadParams,
};
use maxsecu_crypto::{EncPublicKey, WrappedDek};
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::types::{Id, RecipientType, Suite, Timestamp};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{open_conn, reauth, server_of};
use crate::config::load_directory_pub;
use crate::directory::{resolve_my_binding, resolve_recovery_pin};
use crate::dto::{
    BundlePreview, CancelUploadRequest, ConfirmUploadRequest, MemberCounts, PendingUploadView,
    StageBundleRequest, StageUploadRequest, UploadJobView, UploadKind, UploadPreview,
};
use crate::error::UiError;
use crate::ffmpeg_bin::ensure_ffmpeg;
use crate::http_client::{delete_req, post_json};
use crate::jobs::{
    BundleJob, BundleJobs, MemberMeta, StagedContent, StagedUpload, StagedVideoPreview, UploadJobs,
    VideoPrepareCancel,
};
use crate::state::{
    BundleStagePhase, PreparePhase, UploadPhase, EVT_BUNDLE_STAGE, EVT_UPLOAD, EVT_VIDEO_PREPARE,
};
use crate::upload::{
    apply_stage_flags, build_metadata, file_type_str, prepare_blog_streams,
    prepare_generic_metadata, prepare_image_streams, prepare_video_streams, put_chunk_retried,
    run_pipeline, total_chunks, wrap_wire, PreparedVideo, StageFlags,
};
use crate::upload_staging::{StagedSmallStream, StagedWrap, StagingRecord, StagingStore};

use tauri::Emitter;

/// Max bytes we read from a chosen file / accept as blog text (DoS guard).
const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// The content chunk size for EVERY upload kind. This is the SINGLE source of truth
/// for the content chunk size — it is `crate::upload::VIDEO_CHUNK_SIZE` (6 MiB),
/// the same constant the video fragment-index validator uses. Tying them here makes
/// it impossible to stage video at a `chunk_size` that differs from the fragment
/// index's chunk unit (a divergence would silently misseek after upload).
const CHUNK_SIZE: u32 = crate::upload::VIDEO_CHUNK_SIZE;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
fn rand_job_id() -> String {
    maxsecu_crypto::random_array::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Rolling throughput estimate: ciphertext bytes over elapsed seconds.
fn bytes_per_s_from_window(bytes: u64, secs: f64) -> u64 {
    if secs <= 0.0 { 0 } else { (bytes as f64 / secs) as u64 }
}

/// Map a `StagedSmallStream.stream_type` (u8) to the wire name used in the
/// POST /v1/files `streams[]` array. Never called for type 1 (content).
fn small_stream_type_name(v: u8) -> &'static str {
    match v {
        0x02 => "metadata",
        0x03 => "thumbnail",
        0x04 => "preview",
        _ => "unknown",
    }
}

/// Map a `StagedSmallStream.stream_type` u8 to the typed `StreamType` enum for
/// `put_chunk_retried`. Fail-closed on unknown values.
fn stream_type_from_u8(v: u8) -> Option<maxsecu_encoding::types::StreamType> {
    use maxsecu_encoding::types::StreamType;
    match v {
        0x01 => Some(StreamType::Content),
        0x02 => Some(StreamType::Metadata),
        0x03 => Some(StreamType::Thumbnail),
        0x04 => Some(StreamType::Preview),
        _ => None,
    }
}

/// Shape the §8.1 `POST /v1/files` JSON body from a disk-backed `StagingRecord`.
/// Mirrors `upload::stage_body` but base64-encodes the already-stored bytes
/// directly (no re-encoding). `total_bytes` for the content stream is the exact
/// ciphertext byte count from pass 1 (advisory: server uses it for listing/quota,
/// not enforcement).
fn stage_body_from_record(rec: &StagingRecord, flags: StageFlags) -> serde_json::Value {
    let file_id_hex: String = rec.file_id.iter().map(|b| format!("{b:02x}")).collect();

    // Content stream first (ascending stream_type order)
    let mut streams = vec![serde_json::json!({
        "stream_type": "content",
        "chunk_count":  rec.content_chunk_count,
        "chunk_size":   rec.chunk_size,
        "total_bytes":  rec.content_total_bytes,
    })];
    for s in &rec.small_streams {
        streams.push(serde_json::json!({
            "stream_type": small_stream_type_name(s.stream_type),
            "chunk_count":  s.chunk_count,
            "chunk_size":   s.chunk_size,
            "total_bytes":  s.total_bytes,
        }));
    }

    let hex16 = |b: &[u8; 16]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    let wraps: Vec<serde_json::Value> = rec.wraps.iter().map(|w| {
        let rid = if w.recipient_type == "recovery" {
            "recovery".to_owned()
        } else {
            hex16(&w.recipient_id)
        };
        serde_json::json!({
            "recipient_id":    rid,
            "recipient_type":  &w.recipient_type,
            "wrapped_dek_b64": B64.encode(&w.wrapped_dek),
            "wrap_alg":        1,
            "granted_by":      hex16(&w.granted_by),
            "grant_b64":       B64.encode(&w.grant),
            "grant_sig_b64":   B64.encode(&w.grant_sig),
        })
    }).collect();

    let mut body = serde_json::json!({
        "file_id":         file_id_hex,
        "file_type":       &rec.file_type,
        "genesis_b64":     B64.encode(&rec.genesis),
        "genesis_sig_b64": B64.encode(&rec.genesis_sig),
        "manifest_b64":    B64.encode(&rec.manifest),
        "manifest_sig_b64":B64.encode(&rec.manifest_sig),
        "streams": streams,
        "wraps":   wraps,
    });
    // Optional bundle-member visibility flags (Task 2.4): shared shaper so this and
    // `upload::stage_body` can never drift (`listed:false` only when set; `bundle_id`
    // only when `Some`). A normal single-upload passes the default (a no-op here).
    apply_stage_flags(&mut body, flags);
    body
}

// ---------------------------------------------------------------------------
// stage_upload
// ---------------------------------------------------------------------------

/// The fully-staged result of ONE item (a single post OR one bundle member): the
/// in-TCB [`StagedUpload`] plus the small facts a preview DTO and the bundle
/// member metadata need. `staged` holds the `UploadBundle`/`StagingRecord` and
/// NEVER crosses the Tauri seam; only DTOs derived from the other fields do.
struct StagedItem {
    staged: StagedUpload,
    file_id: [u8; 16],
    /// The item's `FileType` enum. Named `kind` to avoid confusion with
    /// `staged.file_type`, which is the wire STRING form ("image"/"blog"/…).
    kind: maxsecu_encoding::types::FileType,
    thumbnail_b64: Option<String>,
}

/// `stage_upload` — prepare + encrypt/stage a post and hold it for preview.
/// No network write. Video uploads are streaming (disk-backed); image/blog are
/// in-RAM as before. Thin wrapper over [`stage_item`]: stage the single item,
/// then register it in [`UploadJobs`] under a fresh `job_id` and return its
/// preview.
#[tauri::command]
pub async fn stage_upload(
    req: StageUploadRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    jobs: State<'_, UploadJobs>,
    prepare_cancel: State<'_, VideoPrepareCancel>,
) -> Result<UploadPreview, UiError> {
    let item = stage_item(&req, &app, &dir, &session, &prepare_cancel).await?;
    // Capture the preview fields BEFORE moving `staged` into the jobs map.
    let file_type = item.staged.file_type.clone();
    let total_chunks = item.staged.total_chunks;
    let byte_size = item.staged.byte_size;
    let thumbnail_b64 = item.thumbnail_b64;
    let job_id = rand_job_id();
    jobs.0.lock().await.insert(job_id.clone(), item.staged);
    Ok(UploadPreview {
        job_id,
        file_type,
        title: req.title,
        tags: req.tags,
        byte_size,
        total_chunks,
        thumbnail_b64,
    })
}

/// Resolve the upload recipients under the pinned directory key (D5): the caller's
/// own verified binding (`me`) and the recovery recipient. Shared by [`stage_item`]
/// (single post / bundle member) and [`run_bundle_pipeline`] (the bundle file) so the
/// **security-critical** recovery-pin trust-alarm A lives in exactly ONE place.
///
/// Trust-alarm A (spec §3/§7): [`resolve_recovery_pin`] fetches the server-served
/// recovery pubkey and constant-time-compares it against this client's compiled-in
/// recovery pin BEFORE any DEK wrap. A mismatch returns a `server_untrusted` error and
/// aborts here — nothing is wrapped, staged, or uploaded. On a match the caller wraps
/// the file DEK to the EMBEDDED pin's keys (the trusted, compiled-in value), NOT the
/// server-served key (which is only ever compared, never trusted).
///
/// Returns `(me, recovery, now)` where `now` is the SINGLE timestamp used both for the
/// binding freshness check AND as the upload `created_at`, so the caller and the
/// trust-alarm agree on one instant. This helper does NOT resolve or borrow the
/// signing identity — that stays with the caller, borrowed later only under the
/// session lock across the SYNCHRONOUS `build_upload` (the lock-discipline split is
/// preserved exactly). All GETs are unauthenticated directory reads over a fresh
/// connection; nothing here crosses the Tauri seam.
async fn resolve_recipients(
    app_dir: &std::path::Path,
    session: &Session,
) -> Result<(crate::directory::VerifiedAuthor, crate::directory::RecoveryRecipient, u64), UiError> {
    let pinned = load_directory_pub(app_dir)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();
    let username = { session.0.lock().await.username.clone() }
        .ok_or_else(|| UiError::new("locked", "Sign in first."))?;
    let server = server_of(app_dir)?;
    let (mut sender, host, _exporter) = open_conn(app_dir, &server).await?;
    let me =
        resolve_my_binding(&mut sender, &host, &username, &verifier, &mut trust, now).await?;
    let recovery = resolve_recovery_pin(&mut sender, &host).await?;
    Ok((me, recovery, now))
}

/// Prepare + encrypt/stage ONE item (a single post or one bundle member) WITHOUT
/// inserting it into any job registry and WITHOUT any network write. The reusable
/// core shared by [`stage_upload`] (single post) and [`stage_bundle`] (per
/// member). It performs, in order: (1) type-specific preparation (blog / image /
/// generic / video — the video arm runs the confined transcode via
/// `prepare_cancel`'s in-flight slot); (2) recipient resolution under the pinned
/// D5 (unauth directory GETs + the embedded-pin recovery trust-alarm A);
/// (3) content build (video/generic streaming disk-backed, image/blog in-RAM);
/// (4) total-chunk / file-type-string / byte-size / thumbnail computation.
///
/// On Ok the returned [`StagedUpload`] OWNS its staging dir (if any); the internal
/// stage-error cleanup guard is disarmed just before returning so the dir is NOT
/// deleted. On ANY error the guard drops and wipes the partial staging dir, so a
/// failed item leaves nothing on disk. Identity is borrowed only across the
/// synchronous seal (as before) — no `.await` holds the identity.
async fn stage_item(
    req: &StageUploadRequest,
    app: &tauri::AppHandle,
    dir: &AppDir,
    session: &Session,
    prepare_cancel: &VideoPrepareCancel,
) -> Result<StagedItem, UiError> {
    // RAII guard that deletes a dir on any error path before the job is inserted.
    // For video: initially guards the transcode temp dir; switched to the staging
    // dir once the file is moved. Disarmed after `jobs.insert`.
    struct DirCleanup(Option<std::path::PathBuf>);
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            if let Some(d) = &self.0 {
                let _ = std::fs::remove_dir_all(d);
            }
        }
    }

    // Aggregates the results of `prepare_video_streams` so we can carry them
    // out of the match arm without a large tuple.
    struct VideoPrep {
        prepared: PreparedVideo,
        frag_index: Vec<crate::video::FragmentEntry>,
        job_dir: std::path::PathBuf,
    }

    // Carries the generic (download-only) inputs out of the match arm. The source
    // is the user's OWN file — it is COPIED into staging, never moved or deleted.
    struct GenericPrep {
        src_path: std::path::PathBuf,
        byte_size: u64,
        metadata: Vec<u8>,
    }

    // 1) Type-specific preparation — no network, no crypto yet.
    let (file_type, opt_streams, opt_video, opt_generic) = match req.kind {
        UploadKind::Blog => {
            let text = req.content.clone().unwrap_or_default();
            if text.len() as u64 > MAX_UPLOAD_BYTES {
                return Err(UiError::new("too_large", "That post is too large."));
            }
            (
                maxsecu_encoding::types::FileType::Blog,
                Some(prepare_blog_streams(text.into_bytes(), &req.title, &req.tags)),
                None::<VideoPrep>,
                None::<GenericPrep>,
            )
        }
        UploadKind::Image => {
            let path = req
                .path
                .clone()
                .ok_or_else(|| UiError::new("bad_request", "No image was chosen."))?;
            let meta = std::fs::metadata(&path)
                .map_err(|_| UiError::new("bad_request", "That file could not be read."))?;
            if meta.len() > MAX_UPLOAD_BYTES {
                return Err(UiError::new("too_large", "That image is too large."));
            }
            let bytes = std::fs::read(&path)
                .map_err(|_| UiError::new("bad_request", "That file could not be read."))?;
            let (ft, s) = prepare_image_streams(&bytes, &req.title, &req.tags)?;
            (ft, Some(s), None, None)
        }
        UploadKind::Generic => {
            // Generic download-only upload: no transcode. Stream the RAW file via the
            // disk-backed path (no in-RAM MAX_UPLOAD_BYTES cap — it is chunked from
            // disk), carrying the original filename in the metadata.
            let path = req
                .path
                .clone()
                .ok_or_else(|| UiError::new("bad_request", "No file was chosen."))?;
            let src_path = std::path::PathBuf::from(&path);
            let meta = std::fs::metadata(&src_path)
                .map_err(|_| UiError::new("bad_request", "That file could not be read."))?;
            if !meta.is_file() {
                return Err(UiError::new("bad_request", "That is not a file."));
            }
            let byte_size = meta.len();
            // The original filename (basename) baked into the metadata for the
            // viewer's "download as <name>" action.
            let filename = src_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("download.bin")
                .to_owned();
            let metadata = prepare_generic_metadata(&filename, &req.title, &req.tags);
            (
                maxsecu_encoding::types::FileType::Generic,
                None,
                None,
                Some(GenericPrep { src_path, byte_size, metadata }),
            )
        }
        UploadKind::Video => {
            let path = req
                .path
                .clone()
                .ok_or_else(|| UiError::new("bad_request", "No video was chosen."))?;
            let input_path = std::path::PathBuf::from(path);
            let ffmpeg_path = ensure_ffmpeg(&dir.0)
                .map_err(|_| UiError::new("video_failed", "That video could not be processed."))?;
            let options = req.options.clone().unwrap_or_default();
            // Honor the user's confined-transcode thread budget (Task 7.3). Read from
            // the normalized settings (already clamped 1..=cores); flows into ffmpeg's
            // `-threads N`.
            let transcode_threads =
                crate::config::SettingsConfig::load(&dir.0).performance.transcode_threads;
            let title = req.title.clone();
            let tags = req.tags.clone();
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            *prepare_cancel.0.lock().unwrap() = Some(cancel.clone());
            let handle = app.clone();
            let cancel_task = cancel.clone();
            let staged = tokio::task::spawn_blocking(move || {
                let on_phase = move |phase: PreparePhase| {
                    let _ = handle.emit(EVT_VIDEO_PREPARE, phase);
                };
                prepare_video_streams(
                    &input_path,
                    &ffmpeg_path,
                    &options,
                    &maxsecu_client_core::video::VideoBounds::default(),
                    transcode_threads,
                    &title,
                    &tags,
                    on_phase,
                    &cancel_task,
                )
            })
            .await;
            *prepare_cancel.0.lock().unwrap() = None;
            let prepared: PreparedVideo = match staged {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    let phase = if e.code == "cancelled" {
                        PreparePhase::Cancelled
                    } else {
                        PreparePhase::Failed { code: e.code.clone() }
                    };
                    let _ = app.emit(EVT_VIDEO_PREPARE, phase);
                    return Err(e);
                }
                Err(_) => {
                    let _ = app.emit(
                        EVT_VIDEO_PREPARE,
                        PreparePhase::Failed { code: "video_failed".into() },
                    );
                    return Err(UiError::new(
                        "encrypt_failed",
                        "Could not prepare the upload.",
                    ));
                }
            };
            let frag_index: Vec<crate::video::FragmentEntry> = prepared
                .fragments
                .iter()
                .map(|f| crate::video::FragmentEntry {
                    seq: f.seq,
                    pts_ms: f.pts_ms,
                    chunk_start: f.chunk_start,
                    chunk_len: f.chunk_len,
                })
                .collect();
            let job_dir = prepared.job_dir.clone();
            (
                maxsecu_encoding::types::FileType::Video,
                None,
                Some(VideoPrep { prepared, frag_index, job_dir }),
                None,
            )
        }
    };

    // Arm the stage-error cleanup guard. For video: guards the transcode temp dir
    // until we switch it to the staging dir (or disarm after insert). For
    // image/blog: DirCleanup(None) is a no-op.
    let mut dir_cleanup = DirCleanup(opt_video.as_ref().map(|v| v.job_dir.clone()));

    // Compute thumbnail_b64 and byte_size BEFORE consuming thumbnail/content into
    // SmallStreams (must be before the session lock block for video).
    let thumbnail_b64: Option<String> = if let Some(ref v) = opt_video {
        Some(B64.encode(&v.prepared.thumbnail))
    } else {
        opt_streams.as_ref().and_then(|s| s.thumbnail.as_ref().map(|t| B64.encode(t)))
    };
    let byte_size: u64 = if let Some(ref v) = opt_video {
        v.prepared.output_size
    } else if let Some(ref g) = opt_generic {
        g.byte_size
    } else {
        opt_streams.as_ref().map(|s| s.content.len() as u64).unwrap_or(0)
    };

    // 2) Resolve recipients under the pinned D5 (unauth directory GETs). The
    //    security-critical recovery-pin trust-alarm A (spec §3/§7) lives in the shared
    //    `resolve_recipients` helper (also used by the bundle file in
    //    `run_bundle_pipeline`); `now` is the single timestamp for both the binding
    //    freshness check and the `created_at` below.
    let (me, recovery, now) = resolve_recipients(&dir.0, session).await?;

    // 3) Build the upload content. Video: streaming (disk-backed); Image/Blog: InRam.
    let file_id = Id(maxsecu_crypto::random_array::<16>());

    let (content, final_preview, final_job_dir) = if let Some(vp) = opt_video {
        // ── VIDEO STREAMING PATH ──────────────────────────────────────────────
        // Stream via the shared helper: MOVE the generated `out.mp4` into staging
        // and remove the transcode temp dir afterwards.
        let small = SmallStreams {
            metadata: Some(vp.prepared.metadata),
            thumbnail: Some(vp.prepared.thumbnail),
            preview: Some(vp.prepared.preview),
        };
        let (rec, staging_dir) = stage_streaming_content(
            session,
            &vp.prepared.out_mp4_path,
            true, // MOVE the generated temp file
            "out.mp4",
            Some(&vp.job_dir),
            file_type,
            small,
            StagingCryptoInputs {
                owner_id: me.user_id,
                owner_key_version: me.key_version,
                file_id,
                recovery_enc_pub: recovery.enc_pub,
                recovery_mlkem_pub: recovery.mlkem_pub,
                created_at: now,
            },
            &req.title,
            dir.0.join("staging"),
            &mut dir_cleanup.0,
        )
        .await?;

        let preview = StagedVideoPreview {
            out_mp4_path: rec.out_mp4_path.clone(),
            index: vp.frag_index,
        };
        (StagedContent::Streaming(rec), Some(preview), Some(staging_dir))
    } else if let Some(g) = opt_generic {
        // ── GENERIC STREAMING PATH ────────────────────────────────────────────
        // Stream the raw source via the shared helper: COPY the user's OWN file
        // into staging (never move/delete it), metadata-only small streams, no
        // thumbnail/preview.
        let small = SmallStreams {
            metadata: Some(g.metadata),
            thumbnail: None,
            preview: None,
        };
        let (rec, staging_dir) = stage_streaming_content(
            session,
            &g.src_path,
            false, // COPY the user's source (never move/delete)
            "content.bin",
            None,
            file_type,
            small,
            StagingCryptoInputs {
                owner_id: me.user_id,
                owner_key_version: me.key_version,
                file_id,
                recovery_enc_pub: recovery.enc_pub,
                recovery_mlkem_pub: recovery.mlkem_pub,
                created_at: now,
            },
            &req.title,
            dir.0.join("staging"),
            &mut dir_cleanup.0,
        )
        .await?;

        (StagedContent::Streaming(rec), None, Some(staging_dir))
    } else {
        // ── IMAGE / BLOG PATH (unchanged) ────────────────────────────────────
        let mut streams = opt_streams.unwrap();
        let bundle = {
            let guard = session.0.lock().await;
            let identity: &Identity = guard
                .identity
                .as_ref()
                .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
            let params = UploadParams {
                owner: identity,
                owner_id: Id(me.user_id),
                owner_key_version: me.key_version,
                file_id,
                file_type,
                chunk_size: CHUNK_SIZE,
                recovery_pub: EncPublicKey::from_bytes(recovery.enc_pub),
                recovery_mlkem_pub: recovery.mlkem_pub,
                created_at: Timestamp(now),
            };
            build_upload(&params, &streams)
                .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?
        };
        // Wipe the transient plaintext content (defense-in-depth).
        streams.content.zeroize();
        (StagedContent::InRam(bundle), None, None)
    };

    // 4) Compute total_chunks and file_type_str per content variant.
    let (total, file_type_str) = match &content {
        StagedContent::InRam(b) => (total_chunks(b), bundle_file_type_str(b)),
        StagedContent::Streaming(r) => {
            let sc: u64 = r.small_streams.iter().map(|s| s.chunk_count).sum();
            (r.content_chunk_count + sc, r.file_type.clone())
        }
    };

    // 5) Assemble the staged item (NO network). The content stays in the TCB.
    let staged = StagedUpload {
        content,
        file_type: file_type_str,
        title: req.title.clone(),
        total_chunks: total,
        byte_size,
        preview: final_preview,
        job_dir: final_job_dir,
    };
    // Ownership of the staging dir now lives in `staged` — disarm the guard so it
    // is NOT deleted when this function returns.
    dir_cleanup.0 = None;
    Ok(StagedItem {
        staged,
        file_id: file_id.0,
        kind: file_type,
        thumbnail_b64,
    })
}

fn bundle_file_type_str(b: &maxsecu_client_core::UploadBundle) -> String {
    use maxsecu_encoding::types::FileType;
    match b.file_type {
        FileType::Image => "image",
        FileType::Blog => "blog",
        FileType::Video => "video",
        FileType::Generic => "generic",
        FileType::Bundle => "bundle",
    }
    .to_owned()
}

/// Lowercase hex of a 16-byte id (file id / bundle id).
fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Encode a bundle's ordered member list into the canonical `BundleBody` bytes that
/// become the bundle file's authenticated `content` stream (Task 1.2/2.4). Order is
/// preserved verbatim — `members[i]` maps to `BundleMember { file_id, file_type }` in
/// the SAME position (the codec neither sorts nor de-duplicates), so the viewer reads
/// the members back in the authoritative bundle order.
fn build_bundle_content(members: &[(Id, maxsecu_encoding::types::FileType)]) -> Vec<u8> {
    use maxsecu_encoding::structs::{BundleBody, BundleMember};
    let body = BundleBody {
        members: members
            .iter()
            .map(|(id, ft)| BundleMember { file_id: *id, file_type: *ft })
            .collect(),
    };
    maxsecu_encoding::encode(&body)
}

// ---------------------------------------------------------------------------
// stage_bundle
// ---------------------------------------------------------------------------

/// `stage_bundle` — prepare + encrypt/stage EVERY member of a bundle and hold them
/// for preview. No network write beyond the per-member directory resolution that
/// [`stage_item`] already performs. Members are staged sequentially in request
/// order (the video transcode slot serves one at a time); that order IS the
/// authoritative bundle member order carried in `BundleJob.member_meta`.
///
/// On any member's staging failure the whole bundle is aborted: the
/// already-staged members' staging dirs are explicitly removed (dropping a
/// [`StagedUpload`] does NOT delete its `job_dir`) so nothing leaks on disk, and
/// the error is returned. On success a single [`BundleJob`] is registered in
/// [`BundleJobs`] under a fresh `job_id`. Only the [`BundlePreview`] DTO crosses
/// the seam — the staged members (and their keys/ciphertext) stay in the TCB.
#[tauri::command]
pub async fn stage_bundle(
    req: StageBundleRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    jobs: State<'_, BundleJobs>,
    prepare_cancel: State<'_, VideoPrepareCancel>,
) -> Result<BundlePreview, UiError> {
    use maxsecu_encoding::types::FileType;

    // RAII guard that owns the accumulating staged members and wipes each one's
    // staging dir on drop (a `StagedUpload` drop does NOT delete its `job_dir`).
    // Disk hygiene is thus fail-closed BY CONSTRUCTION: an early return, a `?`, or
    // a panic anywhere in the member loop drops this guard and cleans up every
    // already-staged member. Disarmed via `std::mem::take` only just before the
    // successful `jobs.insert`, at which point ownership passes to the `BundleJob`.
    struct BundleStagingCleanup(Vec<StagedUpload>);
    impl Drop for BundleStagingCleanup {
        fn drop(&mut self) {
            for s in &self.0 {
                if let Some(d) = &s.job_dir {
                    let _ = std::fs::remove_dir_all(d);
                }
            }
        }
    }

    // Generate the bundle id up front (never leaves the TCB).
    let bundle_id = maxsecu_crypto::random_array::<16>();

    if req.members.is_empty() {
        return Err(UiError::new("bad_request", "A bundle needs at least one item."));
    }

    // The staged members accumulate INSIDE the guard; the parallel `member_meta`
    // and previews accumulate alongside in the same order.
    let mut cleanup = BundleStagingCleanup(Vec::with_capacity(req.members.len()));
    let mut member_meta: Vec<MemberMeta> = Vec::with_capacity(req.members.len());
    let mut member_previews: Vec<UploadPreview> = Vec::with_capacity(req.members.len());
    let mut counts = MemberCounts::default();
    // Raw PNG bytes of the cover member's thumbnail (from `cover_index`), captured
    // as we stage that member. Sealed into the bundle file's Thumbnail stream below.
    let mut cover_thumbnail: Option<Vec<u8>> = None;

    let total = req.members.len();
    for (i, m) in req.members.iter().enumerate() {
        // Progress feedback: tell the composer which member (1-based) of how many
        // is now being staged so the "Preparing preview…" step is not a silent
        // spinner. For a video member, finer transcode progress still streams over
        // EVT_VIDEO_PREPARE. Best-effort: a dropped event never fails staging.
        let _ = app.emit(
            EVT_BUNDLE_STAGE,
            BundleStagePhase::Member {
                index: i + 1,
                total,
                title: m.title.clone(),
            },
        );
        let member_req = StageUploadRequest {
            kind: m.kind,
            path: m.path.clone(),
            content: m.content.clone(),
            options: m.options.clone(),
            title: m.title.clone(),
            tags: m.tags.clone(),
        };
        // On error the `?` returns, dropping `cleanup` → all prior members' dirs
        // are wiped. No manual cleanup arm needed.
        let item = stage_item(&member_req, &app, &dir, &session, &prepare_cancel).await?;
        match item.kind {
            FileType::Video => counts.video += 1,
            FileType::Image => counts.image += 1,
            FileType::Blog => counts.blog += 1,
            FileType::Generic => counts.generic += 1,
            // A bundle member is never itself a bundle; leave counts as-is.
            FileType::Bundle => {}
        }
        // A member is not individually confirmable, so its preview `job_id` is a
        // stable UI key derived from its file id (not a jobs-map key).
        member_previews.push(UploadPreview {
            job_id: hex16(&item.file_id),
            file_type: item.staged.file_type.clone(),
            title: item.staged.title.clone(),
            tags: m.tags.clone(),
            byte_size: item.staged.byte_size,
            total_chunks: item.staged.total_chunks,
            thumbnail_b64: item.thumbnail_b64.clone(),
        });
        // Capture the chosen cover member's thumbnail (decoded to raw PNG). If the
        // cover member has no thumbnail (e.g. a generic/blog member), the bundle
        // simply gets no cover.
        if req.cover_index == Some(i) {
            cover_thumbnail = item.thumbnail_b64.as_ref().and_then(|b| B64.decode(b).ok());
        }
        member_meta.push(MemberMeta {
            file_id: item.file_id,
            file_type: item.kind,
        });
        cleanup.0.push(item.staged);
    }

    // Disarm the guard: move the staged members out (their dirs now belong to the
    // `BundleJob`). `member_meta` is parallel and same-order by construction above.
    let members = std::mem::take(&mut cleanup.0);

    // Register the assembled bundle (NO network). The members stay in the TCB.
    let job_id = rand_job_id();
    jobs.0.lock().await.insert(
        job_id.clone(),
        BundleJob {
            bundle_id,
            title: req.title,
            tags: req.tags,
            members,
            member_meta,
            cover_thumbnail,
        },
    );
    Ok(BundlePreview {
        job_id,
        member_previews,
        counts,
    })
}

/// The crypto/identity scalars forwarded verbatim into the [`UploadParams`] that
/// [`stage_streaming_content`] builds under the session lock. Grouping them keeps the
/// helper signature small and prevents a caller from mis-ordering the several
/// fixed-size byte arrays.
struct StagingCryptoInputs {
    owner_id: [u8; 16],
    owner_key_version: u64,
    file_id: Id,
    recovery_enc_pub: [u8; 32],
    recovery_mlkem_pub: Option<[u8; 1184]>,
    created_at: u64,
}

/// Shared streaming-seal + stage for disk-backed uploads (video and generic).
///
/// Under the session lock (identity borrowed only across the SYNCHRONOUS pass-1
/// seal + `finish` — never across an `.await`), this:
/// 1. Pass-1 streams `input_path` → `(chunk_count, digest)`, DISCARDING the
///    ciphertext (the staged file on disk stays PLAINTEXT; pass-2 re-seals it
///    byte-identically at PUT time). The closure sums ciphertext bytes for the
///    advisory `total_bytes`.
/// 2. `finish` signs/wraps and seals the small (metadata/thumbnail/preview) streams.
/// 3. Places the plaintext content in a fresh staging dir — MOVEs the input when
///    `move_input` (video's generated `out.mp4`; `rename` w/ copy+remove fallback
///    across volumes), else COPIes it (generic: the user's OWN source file is never
///    moved or deleted).
/// 4. Removes `temp_dir` after the move, if any (the video transcode temp dir —
///    Low-IL container artifacts).
/// 5. Builds + persists the `StagingRecord` (its `file_type` string is derived from
///    `file_type` via [`file_type_str`], so it can never drift from the wrapped
///    `UploadParams.file_type`).
///
/// `dir_cleanup_slot` is the caller's error-cleanup guard field: it is switched to
/// the staging dir once the content is in place, so a later persist failure (or an
/// error after this returns) wipes the staging dir. Returns the persisted record and
/// its staging dir.
// Grouping the six crypto scalars into `StagingCryptoInputs` cut this from 17 → 11
// args; the remaining 11 (placement + I/O concerns, deliberately not bundled) still
// exceed clippy's default-7 threshold, so the allow stays.
#[allow(clippy::too_many_arguments)]
async fn stage_streaming_content(
    session: &Session,
    input_path: &std::path::Path,
    move_input: bool,
    content_filename: &str,
    temp_dir: Option<&std::path::Path>,
    file_type: maxsecu_encoding::types::FileType,
    small: SmallStreams,
    crypto: StagingCryptoInputs,
    title: &str,
    staging_root: std::path::PathBuf,
    dir_cleanup_slot: &mut Option<std::path::PathBuf>,
) -> Result<(StagingRecord, std::path::PathBuf), UiError> {
    let now = crypto.created_at;
    let file_id = crypto.file_id;
    // Pass 1 (digest) + finish (sign/wrap/seal small streams) + move/copy + persist
    // all happen under the session lock. There is NO `.await` while the identity is
    // borrowed — the seal/finish sequence is fully synchronous.
    let guard = session.0.lock().await;
    let identity: &Identity = guard
        .identity
        .as_ref()
        .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
    let params = UploadParams {
        owner: identity,
        owner_id: Id(crypto.owner_id),
        owner_key_version: crypto.owner_key_version,
        file_id,
        file_type,
        chunk_size: CHUNK_SIZE,
        recovery_pub: EncPublicKey::from_bytes(crypto.recovery_enc_pub),
        recovery_mlkem_pub: crypto.recovery_mlkem_pub,
        created_at: Timestamp(now),
    };

    let builder = StreamingUploadBuilder::new();
    let sealer = builder.content_sealer(&params);

    // Pass 1: stream the plaintext content → (chunk_count, digest). The ciphertext
    // is discarded (re-sealed on confirm). The content stream's advisory
    // `total_bytes` is the PLAINTEXT length = the input file size (the fMP4 for a
    // video, the user's file for a generic) — recorded so the viewer can learn
    // total_len WITHOUT fetching + decrypting the last chunk (see
    // `commands::video::trusted_total_len`). Metadata is read before sealing
    // consumes the reader (it is independent of read position).
    let mut in_file = std::fs::File::open(input_path)
        .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?;
    let plaintext_total = in_file.metadata().map(|m| m.len()).unwrap_or(0);
    let (count, digest) = sealer
        .seal_from_reader(&mut in_file, |_, _| Ok(()))
        .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?;
    drop(in_file); // close before rename/copy

    let records = builder
        .finish(&params, &small, digest, count)
        .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?;

    // Place the plaintext content in the staging dir.
    let store = StagingStore::new(staging_root);
    let sdir = store.dir_for(&file_id.0);
    std::fs::create_dir_all(&sdir)
        .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?;
    let dest = sdir.join(content_filename);
    if move_input {
        // MOVE the generated temp file. rename() can fail across volumes → copy+remove.
        if std::fs::rename(input_path, &dest).is_err() {
            std::fs::copy(input_path, &dest)
                .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?;
            let _ = std::fs::remove_file(input_path);
        }
    } else {
        // COPY the user's OWN source file — never move or delete it.
        std::fs::copy(input_path, &dest)
            .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?;
    }
    // Delete the now-empty transcode temp dir (Low-IL container artifacts), if any.
    if let Some(td) = temp_dir {
        let _ = std::fs::remove_dir_all(td);
    }
    // Switch the cleanup guard to the staging dir: if persist (or a later step)
    // fails, the staging dir is wiped on drop.
    *dir_cleanup_slot = Some(sdir.clone());

    let rec = StagingRecord {
        file_id: file_id.0,
        file_type: file_type_str(file_type).to_owned(),
        title: title.to_owned(),
        manifest: maxsecu_encoding::encode(&records.manifest),
        manifest_sig: records.manifest_sig.to_vec(),
        genesis: maxsecu_encoding::encode(&records.genesis),
        genesis_sig: records.genesis_sig.to_vec(),
        wraps: records
            .wraps
            .iter()
            .map(|w| StagedWrap {
                recipient_id: w.recipient_id.0,
                recipient_type: if w.recipient_type == RecipientType::Recovery {
                    "recovery".into()
                } else {
                    "user".into()
                },
                wrapped_dek: wrap_wire(w),
                granted_by: w.granted_by.0,
                grant: maxsecu_encoding::encode(&w.grant),
                grant_sig: w.grant_sig.to_vec(),
            })
            .collect(),
        out_mp4_path: dest,
        chunk_size: CHUNK_SIZE,
        content_chunk_count: count,
        content_total_bytes: plaintext_total,
        small_streams: records
            .small_streams
            .iter()
            .map(|s| StagedSmallStream {
                stream_type: s.stream_type as u8,
                chunk_size: s.chunk_size,
                chunk_count: s.chunk_count,
                total_bytes: s.total_bytes,
                digest: s.digest.to_vec(),
                chunks: s.chunks.clone(),
            })
            .collect(),
        progress: 0,
        created_ms: now,
        last_progress_ms: now,
        finalized: false,
    };
    store
        .persist(&rec)
        .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))?;
    Ok((rec, sdir))
}

// ---------------------------------------------------------------------------
// confirm_upload
// ---------------------------------------------------------------------------

/// `confirm_upload` — run the staged bundle's network pipeline (stage → resumable
/// chunk PUT → finalize), emitting `UploadPhase` over `EVT_UPLOAD`. On success the
/// job is removed; on failure it is RETAINED so the tray can retry. Neither the
/// bundle nor the DEK ever leaves the TCB.
#[tauri::command]
pub async fn confirm_upload(
    req: ConfirmUploadRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    jobs: State<'_, UploadJobs>,
) -> Result<String, UiError> {
    let emit = |p: UploadPhase| {
        let _ = app.emit(EVT_UPLOAD, p);
    };
    let job_id = req.job_id.clone();
    let out = confirm_inner(&req, &dir, &session, &connect_lock, &jobs, &emit).await;
    match &out {
        Ok(file_id) => {
            jobs.0.lock().await.remove(&job_id);
            emit(UploadPhase::Done {
                job_id: job_id.clone(),
                file_id: file_id.clone(),
            });
        }
        Err(e) => {
            emit(UploadPhase::Failed {
                job_id: job_id.clone(),
                code: e.code.clone(),
            });
        }
    }
    out
}

async fn confirm_inner(
    req: &ConfirmUploadRequest,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    jobs: &State<'_, UploadJobs>,
    emit: &impl Fn(UploadPhase),
) -> Result<String, UiError> {
    let job_id = req.job_id.clone();
    let server = server_of(&dir.0)?;
    emit(UploadPhase::Staging { job_id: job_id.clone() });
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;

    // Take the job out of the registry for the duration of the upload.
    // Re-inserted on failure so the tray can retry.
    let staged = { jobs.0.lock().await.remove(&job_id) }
        .ok_or_else(|| UiError::new("no_such_job", "That upload is no longer staged."))?;

    // Destructure so we can move `content` into the branch and reconstruct on error.
    let StagedUpload { content, file_type, title, total_chunks, byte_size, preview, job_dir } =
        staged;

    // Derive file_id_hex from whichever variant we have.
    let file_id_hex: String = match &content {
        StagedContent::InRam(b) => b.file_id.0.iter().map(|b| format!("{b:02x}")).collect(),
        StagedContent::Streaming(r) => r.file_id.iter().map(|b| format!("{b:02x}")).collect(),
    };

    // Clone the re-insertable fields (preview + job_dir are small).
    let preview_clone = preview.clone();
    let job_dir_clone = job_dir.clone();

    let (result, content_back) = match content {
        StagedContent::InRam(bundle) => {
            // ── IMAGE / BLOG: unchanged run_pipeline path ─────────────────────
            let r = run_pipeline(
                &mut sender,
                &host,
                &token,
                &bundle,
                |done, total| {
                    emit(UploadPhase::Uploading {
                        job_id: job_id.clone(),
                        done,
                        total,
                        bytes_per_s: 0,
                    });
                    if done == total {
                        emit(UploadPhase::Finalizing { job_id: job_id.clone() });
                    }
                },
                StageFlags::default(),
            )
            .await;
            (r, StagedContent::InRam(bundle))
        }
        StagedContent::Streaming(mut rec) => {
            // ── VIDEO STREAMING CONFIRM ───────────────────────────────────────
            let r = streaming_confirm(
                &mut rec,
                &job_id,
                &file_id_hex,
                &dir.0,
                session,
                &mut sender,
                &host,
                &token,
                total_chunks,
                StageFlags::default(),
                emit,
            )
            .await;
            (r, StagedContent::Streaming(rec))
        }
    };

    match result {
        Ok(()) => {
            // For video: staging dir already removed inside streaming_confirm.
            // For image/blog: job_dir is None (no-op).
            if let Some(d) = &job_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            Ok(file_id_hex)
        }
        Err(e) => {
            // Retain for retry — the staging dir (video) must survive so the
            // updated progress persists and preview ranges keep working.
            jobs.0.lock().await.insert(
                job_id,
                StagedUpload {
                    content: content_back,
                    file_type,
                    title,
                    total_chunks,
                    byte_size,
                    preview: preview_clone,
                    job_dir: job_dir_clone,
                },
            );
            Err(e)
        }
    }
}

/// Pass-2 streaming upload for a video `StagingRecord`. Called from `confirm_inner`.
///
/// Steps:
/// 1. POST /v1/files (stage).
/// 2. PUT each small-stream chunk (idempotent).
/// 3. Recover the DEK from the self-wrap; seal + PUT each content chunk from disk
///    one at a time (O(one 6 MiB chunk) RAM), checkpointing `rec.progress` after
///    each successful PUT.
/// 4. POST finalize. On success: wipe staging dir.
///
/// On failure at any step: return the error without wiping the staging dir so the
/// caller can re-insert `rec` (with updated `progress`) for retry.
#[allow(clippy::too_many_arguments)]
async fn streaming_confirm(
    rec: &mut StagingRecord,
    job_id: &str,
    file_id_hex: &str,
    app_dir: &std::path::Path,
    session: &State<'_, Session>,
    sender: &mut hyper::client::conn::http1::SendRequest<
        http_body_util::Full<hyper::body::Bytes>,
    >,
    host: &str,
    token: &str,
    total_for_progress: u64,
    flags: StageFlags,
    emit: &impl Fn(UploadPhase),
) -> Result<(), UiError> {
    use maxsecu_encoding::structs::Manifest;

    // ── Steps 1+2: POST /v1/files + small-stream PUT (skipped on resume) ─────
    //
    // Guard: if `progress > 0` the file-version is already staged on the server
    // and its small streams are already uploaded.  Re-POSTing `/v1/files` would
    // trigger a `DELETE FROM file_versions WHERE finalized=false` cascade on the
    // server, silently wiping all content chunks `0..progress`.  Skip directly to
    // the content pass-2 loop in that case; the finalize step is unchanged.
    //
    // When `progress == 0` (fresh confirm OR a resume that failed before any chunk
    // was PUT), the POST+small run harmlessly re-stages any partial server state.
    let small_done: u64 = rec.small_streams.iter().map(|s| s.chunk_count).sum();
    let mut done: u64 = 0;

    if rec.progress == 0 {
        // ── Step 1: POST /v1/files ────────────────────────────────────────────
        let body = stage_body_from_record(rec, flags);
        let (st, _) = post_json(sender, "/v1/files", &body, Some(token), host).await?;
        if st != hyper::StatusCode::CREATED {
            return Err(UiError::new("stage_failed", "Could not start the upload."));
        }

        // ── Step 2: PUT small-stream chunks ──────────────────────────────────
        for s in &rec.small_streams {
            let stype = stream_type_from_u8(s.stream_type).ok_or_else(|| {
                UiError::new("upload_chunk_failed", "Bad stream type in staging record.")
            })?;
            for (i, chunk) in s.chunks.iter().enumerate() {
                put_chunk_retried(sender, host, token, file_id_hex, stype, i as u64, chunk)
                    .await?;
                done += 1;
                emit(UploadPhase::Uploading {
                    job_id: job_id.to_owned(),
                    done,
                    total: total_for_progress,
                    bytes_per_s: 0,
                });
            }
        }
    }

    // ── Step 3: Pass 2 — seal + PUT content chunks from disk ─────────────────
    //
    // Recover the DEK from the self-wrap under the session lock (brief: only
    // `resume_content_sealer` runs while the lock is held, then the lock drops
    // so network I/O can proceed without blocking other session operations).
    let suite = maxsecu_encoding::decode::<Manifest>(&rec.manifest)
        .map(|m| m.alg)
        .unwrap_or(Suite::V1);

    let self_wrap = rec
        .wraps
        .iter()
        .find(|w| w.recipient_type == "user")
        .ok_or_else(|| UiError::new("encrypt_failed", "Upload data is corrupt (no self-wrap)."))?;

    if self_wrap.wrapped_dek.len() < 32 {
        return Err(UiError::new("encrypt_failed", "Upload data is corrupt (short wrap)."));
    }
    let wrapped_dek = WrappedDek {
        enc: self_wrap.wrapped_dek[..32].try_into().unwrap(),
        ct: self_wrap.wrapped_dek[32..].to_vec(),
    };
    let file_id_arr: [u8; 16] = rec.file_id;
    let file_id_id = Id(file_id_arr);
    let ctx = WrapContext {
        file_id: file_id_id,
        version: 1,
        recipient_id: Id(self_wrap.recipient_id),
    };

    // Borrow identity under lock, derive sealer, release lock before any .await.
    let sealer = {
        let guard = session.0.lock().await;
        let identity: &Identity = guard.identity.as_ref().ok_or_else(|| {
            UiError::new("locked", "Unlock your keystore first.")
        })?;
        resume_content_sealer(identity, &wrapped_dek, &ctx, suite, file_id_id, 1, rec.chunk_size)
            .map_err(|_| UiError::new("encrypt_failed", "Could not resume upload."))?
    }; // guard drops here — identity no longer borrowed

    // Open the on-disk fMP4 for sequential read (pass 2).
    let mut mp4_file = std::fs::File::open(&rec.out_mp4_path)
        .map_err(|_| UiError::new("upload_chunk_failed", "Cannot read the staged file."))?;

    let chunk_size = rec.chunk_size as u64;
    let count = rec.content_chunk_count;

    // Rolling throughput window.
    let mut speed_instant = std::time::Instant::now();
    let mut speed_bytes: u64 = 0;
    let mut bps: u64 = 0;

    // One reused read buffer (at most chunk_size bytes in RAM at any time).
    let mut buf = vec![0u8; rec.chunk_size as usize];

    let store = StagingStore::new(app_dir.join("staging"));

    for i in rec.progress..count {
        // Seek to chunk boundary and read up to chunk_size bytes.
        mp4_file.seek(SeekFrom::Start(i * chunk_size)).map_err(|_| {
            UiError::new("upload_chunk_failed", "Cannot seek in staged file.")
        })?;
        let n = read_exact_or_eof(&mut mp4_file, &mut buf).map_err(|_| {
            UiError::new("upload_chunk_failed", "Cannot read staged file.")
        })?;
        let plaintext = &buf[..n];
        let is_last = i == count - 1;
        let ct = sealer.seal_chunk(i, plaintext, is_last);

        put_chunk_retried(
            sender,
            host,
            token,
            file_id_hex,
            maxsecu_encoding::types::StreamType::Content,
            i,
            &ct,
        )
        .await?;

        // Update rolling throughput.
        speed_bytes += ct.len() as u64;
        let elapsed = speed_instant.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            bps = bytes_per_s_from_window(speed_bytes, elapsed);
            speed_bytes = 0;
            speed_instant = std::time::Instant::now();
        }

        // Checkpoint progress (best-effort — a persist failure does not abort the upload).
        rec.progress = i + 1;
        rec.last_progress_ms = now_ms();
        let _ = store.persist(rec);

        done = small_done + i + 1;
        emit(UploadPhase::Uploading {
            job_id: job_id.to_owned(),
            done,
            total: total_for_progress,
            bytes_per_s: bps,
        });
        if done == total_for_progress {
            emit(UploadPhase::Finalizing { job_id: job_id.to_owned() });
        }
    }

    // ── Step 4: POST finalize ─────────────────────────────────────────────────
    let (st, _) = post_json(
        sender,
        &format!("/v1/files/{file_id_hex}/versions/1/finalize"),
        &serde_json::Value::Null,
        Some(token),
        host,
    )
    .await?;
    if st != hyper::StatusCode::OK {
        return Err(UiError::new("finalize_failed", "Could not finalize the upload."));
    }

    // Success: wipe the staging dir (record.json + out.mp4).
    let _ = store.remove(&rec.file_id);
    let staging_dir = store.dir_for(&rec.file_id);
    let _ = std::fs::remove_dir_all(&staging_dir);
    Ok(())
}

/// Read from `r` filling `buf` as much as possible, returning the bytes read.
/// Returns `Ok(0)` only at the very start of an EOF. Unlike `read_exact`, a
/// short read at the end of a file is normal (last chunk).
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// confirm_bundle
// ---------------------------------------------------------------------------

/// `confirm_bundle` — run a staged bundle's network pipeline: upload every member
/// as a HIDDEN (`listed=false`) file tagged with the parent `bundle_id`, THEN upload
/// the signed, individually-listed bundle file whose `content` is the ordered member
/// list. Uploading the bundle file LAST means a partial/failed bundle leaves no
/// visible orphan (the members stay `listed=false` — invisible in the feed — until
/// the bundle file that lists them lands). On success the job is removed and each
/// member's staging dir is cleaned up; on failure the whole [`BundleJob`] is RETAINED
/// so the tray can retry. Neither member nor bundle DEK ever leaves the TCB.
#[tauri::command]
pub async fn confirm_bundle(
    req: ConfirmUploadRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    jobs: State<'_, BundleJobs>,
) -> Result<String, UiError> {
    let emit = |p: UploadPhase| {
        let _ = app.emit(EVT_UPLOAD, p);
    };
    let job_id = req.job_id.clone();
    let out = confirm_bundle_inner(&req, &dir, &session, &connect_lock, &jobs, &emit).await;
    match &out {
        Ok(bundle_id_hex) => {
            emit(UploadPhase::Done {
                job_id: job_id.clone(),
                file_id: bundle_id_hex.clone(),
            });
        }
        Err(e) => {
            emit(UploadPhase::Failed {
                job_id: job_id.clone(),
                code: e.code.clone(),
            });
        }
    }
    out
}

/// `retry_confirm` — the uploads tray's Retry entry point. A tray row only knows a
/// `job_id` (from the `EVT_UPLOAD` event); it cannot tell a single-file job from a
/// bundle job, and the two live in DIFFERENT registries ([`UploadJobs`] vs
/// [`BundleJobs`]). This dispatches by looking the id up in [`BundleJobs`] first: a
/// hit routes to [`confirm_bundle`], otherwise to [`confirm_upload`]. Without this a
/// bundle retry always hit `no_such_job` (it was hard-wired to `confirm_upload`).
#[tauri::command]
pub async fn retry_confirm(
    req: ConfirmUploadRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
    bundle_jobs: State<'_, BundleJobs>,
    upload_jobs: State<'_, UploadJobs>,
) -> Result<String, UiError> {
    let is_bundle = bundle_jobs.0.lock().await.contains_key(&req.job_id);
    if is_bundle {
        confirm_bundle(req, app, dir, session, connect_lock, bundle_jobs).await
    } else {
        confirm_upload(req, app, dir, session, connect_lock, upload_jobs).await
    }
}

async fn confirm_bundle_inner(
    req: &ConfirmUploadRequest,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    jobs: &State<'_, BundleJobs>,
    emit: &impl Fn(UploadPhase),
) -> Result<String, UiError> {
    let job_id = req.job_id.clone();
    let server = server_of(&dir.0)?;
    emit(UploadPhase::Staging { job_id: job_id.clone() });
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;

    // Take the bundle job out of the registry for the duration of the upload;
    // re-inserted verbatim on failure so the tray can retry.
    let mut job = { jobs.0.lock().await.remove(&job_id) }
        .ok_or_else(|| UiError::new("no_such_job", "That bundle is no longer staged."))?;

    let result = run_bundle_pipeline(
        &mut job, &job_id, &dir.0, session, &mut sender, &host, &token, emit,
    )
    .await;

    match result {
        Ok(bundle_id_hex) => {
            // Members are already uploaded + finalized; the bundle file has landed.
            // Clean up each member's staging dir (streaming members; InRam are None).
            for m in &job.members {
                if let Some(d) = &m.job_dir {
                    let _ = std::fs::remove_dir_all(d);
                }
            }
            Ok(bundle_id_hex)
        }
        Err(e) => {
            // Retain the whole job (with any streaming members' advanced progress
            // persisted on disk) for retry. Members already uploaded are listed=false,
            // so a failed bundle leaves NO visible orphan in the feed.
            jobs.0.lock().await.insert(job_id, job);
            Err(e)
        }
    }
}

/// Upload every member (hidden, under `bundle_id`) then the signed bundle file
/// (listed). Returns `hex16(bundle_id)` on success. Does NOT touch the job registry —
/// the caller owns take/re-insert. On the FIRST member/bundle-file error this returns
/// early; the caller retains the job for retry (see the retry-semantics note below).
///
/// **Retry semantics (best-effort).** A retry re-runs from the FIRST member. Members
/// that already fully finalized on a prior attempt will be re-POSTed; the server
/// answers a re-POST of a finalized version with `409 CONFLICT`, which surfaces here
/// as `stage_failed`. So a retry only converges cleanly when the failure happened
/// BEFORE any member fully finalized (e.g. a mid-member transport drop, which the
/// per-chunk PUT retry + streaming checkpoint already recover). A bundle that fails
/// AFTER a member has fully finalized therefore leaves that finalized member on the
/// server under a `bundle_id` that a retry can no longer complete (it 409s) — this is
/// NOT corruption and NOT visible (the member stays `listed=false`), and the orphan is
/// reclaimable via owner delete; full idempotent resume is the WS9 e2e's gate. Here
/// the guarantee is happy-path + retain-on-failure + no visible orphan.
#[allow(clippy::too_many_arguments)]
async fn run_bundle_pipeline(
    job: &mut BundleJob,
    job_id: &str,
    app_dir: &std::path::Path,
    session: &State<'_, Session>,
    sender: &mut hyper::client::conn::http1::SendRequest<
        http_body_util::Full<hyper::body::Bytes>,
    >,
    host: &str,
    token: &str,
    emit: &impl Fn(UploadPhase),
) -> Result<String, UiError> {
    use maxsecu_encoding::types::FileType;

    let bundle_id = job.bundle_id;

    // ── Build the signed bundle file up front (crypto only, NO network) ──────────
    // Its file_id IS the bundle_id, its content is the ordered member list, its
    // metadata is the bundle title/tags. Building it first gives us its chunk count
    // for the aggregate progress denominator; it is UPLOADED last (below).
    //
    // Resolve recipients under the pinned D5 (directory GETs + embedded-pin recovery
    // trust-alarm A) — the SAME shared helper `stage_item` uses.
    let (me, recovery, now) = resolve_recipients(app_dir, session).await?;

    let member_pairs: Vec<(Id, FileType)> =
        job.member_meta.iter().map(|m| (Id(m.file_id), m.file_type)).collect();
    let bundle_content = build_bundle_content(&member_pairs);

    // Identity is borrowed ONLY across the synchronous `build_upload` (no `.await`
    // holds it) — exactly as the single-upload build path does.
    let bundle_file = {
        let guard = session.0.lock().await;
        let identity: &Identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        let params = UploadParams {
            owner: identity,
            owner_id: Id(me.user_id),
            owner_key_version: me.key_version,
            file_id: Id(bundle_id),
            file_type: FileType::Bundle,
            chunk_size: CHUNK_SIZE,
            recovery_pub: EncPublicKey::from_bytes(recovery.enc_pub),
            recovery_mlkem_pub: recovery.mlkem_pub,
            created_at: Timestamp(now),
        };
        // The bundle's cover: the chosen member's thumbnail (captured at stage time
        // via `cover_index`), sealed here into the bundle file's Thumbnail stream so
        // the bundle's own feed card shows a cover image. `None` ⇒ no cover (the card
        // falls back to the member previews).
        let streams = maxsecu_client_core::PlaintextStreams {
            content: bundle_content,
            metadata: Some(build_metadata(&job.title, &job.tags)),
            thumbnail: job.cover_thumbnail.clone(),
            preview: None,
        };
        build_upload(&params, &streams)
            .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the bundle."))?
    }; // guard drops here — identity no longer borrowed

    let bundle_total = total_chunks(&bundle_file);
    let members_total: u64 = job.members.iter().map(|m| m.total_chunks).sum();
    let grand_total = members_total + bundle_total;

    // ── Upload each member in order, HIDDEN under the bundle_id ───────────────────
    let mut base: u64 = 0;
    for (member, meta) in job.members.iter_mut().zip(job.member_meta.iter()) {
        let member_total = member.total_chunks;
        let member_fid_hex = hex16(&meta.file_id);
        let flags = StageFlags { listed: false, bundle_id: Some(bundle_id) };
        match &mut member.content {
            StagedContent::InRam(bundle) => {
                run_pipeline(
                    sender,
                    host,
                    token,
                    bundle,
                    |done, _total| {
                        emit(UploadPhase::Uploading {
                            job_id: job_id.to_owned(),
                            done: base + done,
                            total: grand_total,
                            bytes_per_s: 0,
                        });
                    },
                    flags,
                )
                .await?;
            }
            StagedContent::Streaming(rec) => {
                // Rewrite the member's own (done,total) into the aggregate frame,
                // but CARRY THROUGH the member's real throughput so the tray shows
                // MB/s during a bundle's video upload (same as a single video). The
                // member's per-file Finalizing/Staging phases are suppressed.
                let member_emit = |p: UploadPhase| {
                    if let UploadPhase::Uploading { done, bytes_per_s, .. } = p {
                        emit(UploadPhase::Uploading {
                            job_id: job_id.to_owned(),
                            done: base + done,
                            total: grand_total,
                            bytes_per_s,
                        });
                    }
                };
                streaming_confirm(
                    rec,
                    job_id,
                    &member_fid_hex,
                    app_dir,
                    session,
                    sender,
                    host,
                    token,
                    member_total,
                    flags,
                    &member_emit,
                )
                .await?;
            }
        }
        base += member_total;
    }

    // ── Upload the bundle file LAST (listed=true, a normal file) ──────────────────
    emit(UploadPhase::Finalizing { job_id: job_id.to_owned() });
    run_pipeline(
        sender,
        host,
        token,
        &bundle_file,
        |done, _total| {
            emit(UploadPhase::Uploading {
                job_id: job_id.to_owned(),
                done: members_total + done,
                total: grand_total,
                bytes_per_s: 0,
            });
        },
        StageFlags::default(),
    )
    .await?;

    Ok(hex16(&bundle_id))
}

// ---------------------------------------------------------------------------
// cancel_upload / cancel_video_prepare / upload_jobs
// ---------------------------------------------------------------------------

/// `cancel_upload` — drop a staged (pre-confirm or retained-after-failure) job.
/// Also deletes the per-job dir (video staging dir or None for image/blog) so no
/// artifacts linger on disk.  For streaming (video) jobs, additionally issues a
/// best-effort server DELETE so the orphaned unfinalized file-version is cleaned up
/// (server returns 204/404/409; all are silently ignored).  InRam (image/blog) jobs
/// have no server state at cancel time — nothing was ever POSTed during stage.
#[tauri::command]
pub async fn cancel_upload(
    req: CancelUploadRequest,
    jobs: State<'_, UploadJobs>,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<(), UiError> {
    if let Some(s) = jobs.0.lock().await.remove(&req.job_id) {
        if let Some(d) = &s.job_dir {
            let _ = std::fs::remove_dir_all(d);
        }
        // Best-effort server DELETE for streaming jobs (the file may or may not have
        // been staged yet; 404 from the server is silently ignored).
        if let StagedContent::Streaming(rec) = &s.content {
            let fid_hex: String = rec.file_id.iter().map(|b| format!("{b:02x}")).collect();
            discard_server_orphan(&dir.0, &session, &connect_lock, &fid_hex).await;
        }
    }
    Ok(())
}

/// `cancel_bundle` — drop a staged (pre-confirm) [`BundleJob`] and wipe each
/// member's on-disk staging dir.
///
/// **No server state to delete.** Unlike a single upload, `stage_bundle` performs
/// NO network write — members are POSTed only during `confirm_bundle`. So cancelling
/// a STAGED (never-confirmed) bundle is pure local cleanup: remove the `BundleJob`
/// from the registry and `remove_dir_all` each member's `Some(job_dir)`. There is
/// nothing on the server to DELETE (contrast `cancel_upload`, which best-effort
/// DELETEs a streaming job's orphaned unfinalized version).
///
/// **Partial-confirm caveat.** If `confirm_bundle` failed part-way, the members it
/// already uploaded are `listed=false` (invisible in the feed) and the whole
/// `BundleJob` is RETAINED for retry; cancelling it here wipes local staging but does
/// NOT delete those already-uploaded members from the server. `BundleJob` does not
/// track which members finalized, so per-member server cleanup on cancel is out of
/// scope (deferred per the plan) — such members are reclaimable later via owner delete
/// and stay invisible until then.
///
/// Idempotent: cancelling an id that is already gone returns `Ok(())`. Dir removal is
/// best-effort — a missing/locked dir never errors the command.
#[tauri::command]
pub async fn cancel_bundle(
    req: CancelUploadRequest,
    jobs: State<'_, BundleJobs>,
) -> Result<(), UiError> {
    cancel_bundle_inner(&jobs, &req.job_id).await
}

/// Testable core of [`cancel_bundle`]: remove the `BundleJob` (if any) and
/// best-effort wipe each member's staging dir. Always `Ok` (idempotent).
async fn cancel_bundle_inner(jobs: &BundleJobs, job_id: &str) -> Result<(), UiError> {
    // Take the job and RELEASE the async lock before any blocking fs I/O (the guard
    // drops at the `;`), mirroring `confirm_bundle_inner`.
    let job = jobs.0.lock().await.remove(job_id);
    if let Some(job) = job {
        for m in &job.members {
            if let Some(dir) = &m.job_dir {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
    Ok(())
}

/// `cancel_video_prepare` — request cancellation of the in-flight video
/// `stage_upload` transcode. Best-effort: sets the stored cancel token's flag.
#[tauri::command]
pub async fn cancel_video_prepare(
    prepare_cancel: State<'_, VideoPrepareCancel>,
) -> Result<(), UiError> {
    if let Some(flag) = prepare_cancel.0.lock().unwrap().as_ref() {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// `upload_jobs` — list the currently staged/retained jobs for the tray.
#[tauri::command]
pub async fn upload_jobs(jobs: State<'_, UploadJobs>) -> Result<Vec<UploadJobView>, UiError> {
    let g = jobs.0.lock().await;
    Ok(g.iter()
        .map(|(id, s)| UploadJobView {
            job_id: id.clone(),
            title: s.title.clone(),
            file_type: s.file_type.clone(),
            total_chunks: s.total_chunks,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Resume / sweep / dismiss helpers
// ---------------------------------------------------------------------------

/// Parse a 32-char lowercase hex string into a 16-byte file id.
fn parse_file_id_hex(hex: &str) -> Result<[u8; 16], UiError> {
    if hex.len() != 32 {
        return Err(UiError::new("bad_request", "Invalid file id."));
    }
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| UiError::new("bad_request", "Invalid file id."))?;
    }
    Ok(bytes)
}

/// Returns `true` when a staged upload has had no progress for more than 24 hours
/// and should be swept (local dir removed + server orphan discarded).
fn should_sweep(now_ms: u64, last_progress_ms: u64) -> bool {
    now_ms.saturating_sub(last_progress_ms) > 24 * 60 * 60 * 1000
}

/// Best-effort server DELETE for an unfinalized file-version.  Opens a fresh
/// authenticated channel, sends `DELETE /v1/files/<file_id_hex>`, and ignores all
/// errors (204 / 404 / 409 / network failure are all silent).
async fn discard_server_orphan(
    dir: &std::path::Path,
    session: &Session,
    connect_lock: &ConnectLock,
    file_id_hex: &str,
) {
    let server = match server_of(dir) {
        Ok(s) => s,
        Err(_) => return,
    };
    let (mut sender, host, token) =
        match reauth(dir, &server, session, connect_lock).await {
            Ok(t) => t,
            Err(_) => return,
        };
    let uri = format!("/v1/files/{file_id_hex}");
    let _ = delete_req(&mut sender, &uri, Some(&token), &host).await;
}

// ---------------------------------------------------------------------------
// resume_upload / list_pending_uploads / dismiss_pending_upload
// ---------------------------------------------------------------------------

/// `resume_upload` — resume an interrupted video upload from the last persisted
/// checkpoint.  Calls `streaming_confirm` which skips the POST+small-stream phase
/// (because `rec.progress > 0` after any chunk was PUT) and continues from
/// `rec.progress`.  On success the staging dir is removed and `file_id_hex` is
/// returned.  On failure the record is already checkpointed on disk with the
/// advanced `progress`; return the error so the UI can offer another retry later.
#[tauri::command]
pub async fn resume_upload(
    file_id_hex: String,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<String, UiError> {
    let file_id = parse_file_id_hex(&file_id_hex)?;
    let store = StagingStore::new(dir.0.join("staging"));
    let mut rec = store
        .load(&file_id)
        .map_err(|_| UiError::new("no_such_job", "No staged upload to resume."))?;

    // Already finalized (edge case: previous run succeeded but cleanup failed).
    if rec.finalized {
        let _ = store.remove(&file_id);
        return Ok(file_id_hex);
    }

    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;

    let total: u64 = rec.content_chunk_count
        + rec.small_streams.iter().map(|s| s.chunk_count).sum::<u64>();

    // Use file_id_hex as both job_id and file_id_hex for progress events so the
    // UI can key the tray entry by it — mirrors confirm_upload's pattern.
    let job_id = file_id_hex.clone();
    let emit = |p: UploadPhase| {
        let _ = app.emit(EVT_UPLOAD, p);
    };

    emit(UploadPhase::Staging { job_id: job_id.clone() });

    let result = streaming_confirm(
        &mut rec,
        &job_id,
        &file_id_hex,
        &dir.0,
        &session,
        &mut sender,
        &host,
        &token,
        total,
        StageFlags::default(),
        &emit,
    )
    .await;

    match result {
        Ok(()) => {
            emit(UploadPhase::Done {
                job_id: job_id.clone(),
                file_id: file_id_hex.clone(),
            });
            Ok(file_id_hex)
        }
        Err(e) => {
            // The staging record already has the advanced progress on disk — a
            // later retry (via resume_upload again) will continue from there.
            emit(UploadPhase::Failed {
                job_id: job_id.clone(),
                code: e.code.clone(),
            });
            Err(e)
        }
    }
}

/// `list_pending_uploads` — scan the staging store for incomplete video uploads
/// from previous sessions.  Any upload whose `last_progress_ms` is more than 24 h
/// ago is SWEPT (local dir deleted + best-effort server DELETE).  The rest are
/// returned as `PendingUploadView` for the UI's resume prompt.
#[tauri::command]
pub async fn list_pending_uploads(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<PendingUploadView>, UiError> {
    let store = StagingStore::new(dir.0.join("staging"));
    let now = now_ms();
    let mut result = Vec::new();

    for rec in store.list_pending() {
        if should_sweep(now, rec.last_progress_ms) {
            // Remove local staging dir (record.json + out.mp4).
            let _ = store.remove(&rec.file_id);
            // Best-effort server DELETE — 404 if never staged, ignored either way.
            let fid_hex: String = rec.file_id.iter().map(|b| format!("{b:02x}")).collect();
            discard_server_orphan(&dir.0, &session, &connect_lock, &fid_hex).await;
        } else {
            let total = rec.content_chunk_count
                + rec.small_streams.iter().map(|s| s.chunk_count).sum::<u64>();
            let fid_hex: String = rec.file_id.iter().map(|b| format!("{b:02x}")).collect();
            result.push(PendingUploadView {
                file_id_hex: fid_hex,
                title: rec.title.clone(),
                progress: rec.progress,
                total,
            });
        }
    }

    Ok(result)
}

/// `dismiss_pending_upload` — the user explicitly dismisses a pending (interrupted)
/// upload from the resume prompt.  Removes the local staging dir and issues a
/// best-effort server DELETE.
#[tauri::command]
pub async fn dismiss_pending_upload(
    file_id_hex: String,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<(), UiError> {
    let file_id = parse_file_id_hex(&file_id_hex)?;
    let store = StagingStore::new(dir.0.join("staging"));
    let _ = store.remove(&file_id);
    discard_server_orphan(&dir.0, &session, &connect_lock, &file_id_hex).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upload_staging::{StagedSmallStream, StagedWrap, StagingRecord};
    use std::io::Cursor;
    use std::path::PathBuf;

    // ── should_sweep unit tests ───────────────────────────────────────────────

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    const HOUR_MS: u64 = 60 * 60 * 1000;

    #[test]
    fn should_sweep_more_than_24h_returns_true() {
        let now = 1_700_000_000_000u64;
        assert!(should_sweep(now, now - DAY_MS - 1));
    }

    #[test]
    fn should_sweep_exactly_24h_returns_false() {
        // The boundary is STRICTLY greater-than; exactly 24 h is not swept.
        let now = 1_700_000_000_000u64;
        assert!(!should_sweep(now, now - DAY_MS));
    }

    #[test]
    fn should_sweep_less_than_24h_returns_false() {
        let now = 1_700_000_000_000u64;
        assert!(!should_sweep(now, now - HOUR_MS));
    }

    #[test]
    fn should_sweep_future_last_progress_saturates_to_false() {
        // last_progress_ms > now_ms (e.g. clock skew): saturating_sub → 0 → false.
        let now = 1_700_000_000_000u64;
        assert!(!should_sweep(now, now + 1));
    }

    #[test]
    fn should_sweep_zero_last_progress_far_future_now_is_true() {
        // A record that was persisted at epoch 0 is always swept once now > 24 h.
        let now = DAY_MS + 1;
        assert!(should_sweep(now, 0));
    }

    // ── parse_file_id_hex unit tests ──────────────────────────────────────────

    #[test]
    fn parse_file_id_hex_roundtrips() {
        let id = [0xf1u8; 16];
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let parsed = parse_file_id_hex(&hex).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_file_id_hex_rejects_short() {
        assert!(parse_file_id_hex("abc").is_err());
    }

    #[test]
    fn parse_file_id_hex_rejects_non_hex() {
        assert!(parse_file_id_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    // ── build_bundle_content roundtrip (Task 2.4) ────────────────────────────

    #[test]
    fn build_bundle_content_roundtrips_in_order() {
        use maxsecu_encoding::types::{FileType, Id};
        let members = vec![
            (Id([0x01; 16]), FileType::Video),
            (Id([0x02; 16]), FileType::Image),
            (Id([0x03; 16]), FileType::Generic),
        ];
        let bytes = build_bundle_content(&members);
        let body: maxsecu_encoding::structs::BundleBody =
            maxsecu_encoding::decode(&bytes).unwrap();
        assert_eq!(body.members.len(), 3);
        assert_eq!(body.members[0].file_type, FileType::Video);
        assert_eq!(body.members[2].file_id, Id([0x03; 16]));
        assert_eq!(body.members[1].file_id, Id([0x02; 16])); // order authoritative
    }

    // ── prepare_generic_metadata unit test ───────────────────────────────────

    #[test]
    fn prepare_generic_metadata_carries_filename_title_tags() {
        let bytes = crate::upload::prepare_generic_metadata(
            "itinerary.pdf",
            "Trip plan",
            &["travel".to_owned(), "2026".to_owned()],
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["filename"], "itinerary.pdf");
        assert_eq!(json["title"], "Trip plan");
        assert_eq!(json["tags"][0], "travel");
        assert_eq!(json["tags"][1], "2026");
    }

    // ── bytes_per_s tests (unchanged) ─────────────────────────────────────────

    #[test]
    fn bytes_per_s_computes_correctly() {
        assert_eq!(bytes_per_s_from_window(6 * 1024 * 1024, 1.0), 6 * 1024 * 1024);
        assert_eq!(bytes_per_s_from_window(1_000_000, 0.5), 2_000_000);
        assert_eq!(bytes_per_s_from_window(0, 1.0), 0);
        // No divide-by-zero on zero elapsed.
        assert_eq!(bytes_per_s_from_window(1000, 0.0), 0);
    }

    fn make_test_record() -> StagingRecord {
        StagingRecord {
            file_id: [0xF1u8; 16],
            file_type: "video".into(),
            title: "clip.mp4".into(),
            manifest: vec![0x01, 0x02],
            manifest_sig: vec![0xAB; 64],
            genesis: vec![0x03, 0x04],
            genesis_sig: vec![0xCD; 64],
            wraps: vec![
                StagedWrap {
                    recipient_id: [0x11; 16],
                    recipient_type: "user".into(),
                    wrapped_dek: vec![0xDE; 48], // enc(32) ‖ ct(16)
                    granted_by: [0x11; 16],
                    grant: vec![0x55; 8],
                    grant_sig: vec![0x77; 64],
                },
                StagedWrap {
                    recipient_id: [0x22; 16],
                    recipient_type: "recovery".into(),
                    wrapped_dek: vec![0xEF; 48],
                    granted_by: [0x11; 16],
                    grant: vec![0x66; 8],
                    grant_sig: vec![0x88; 64],
                },
            ],
            out_mp4_path: PathBuf::from("/tmp/out.mp4"),
            chunk_size: 6 * 1024 * 1024,
            content_chunk_count: 3,
            content_total_bytes: 3 * 6 * 1024 * 1024,
            small_streams: vec![
                StagedSmallStream {
                    stream_type: 0x02, // metadata
                    chunk_size: 65536,
                    chunk_count: 1,
                    total_bytes: 128,
                    digest: vec![0xAA; 32],
                    chunks: vec![vec![0u8; 8]],
                },
            ],
            progress: 0,
            created_ms: 1_700_000_000_000,
            last_progress_ms: 1_700_000_000_000,
            finalized: false,
        }
    }

    #[test]
    fn stage_body_from_record_shapes_the_post() {
        let rec = make_test_record();
        let body = stage_body_from_record(&rec, StageFlags::default());

        // file_id is the hex of [0xF1; 16]
        assert_eq!(
            body["file_id"],
            "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
        );
        assert_eq!(body["file_type"], "video");

        // genesis and manifest are base64-encoded.
        assert!(body["genesis_b64"].is_string());
        assert!(body["manifest_b64"].is_string());

        // streams: content first, then small streams.
        let streams = body["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0]["stream_type"], "content");
        assert_eq!(streams[0]["chunk_count"], 3u64);
        assert_eq!(streams[0]["total_bytes"], 3u64 * 6 * 1024 * 1024);
        assert_eq!(streams[1]["stream_type"], "metadata");

        // wraps: user + recovery; each carries wrapped_dek_b64 and grant_b64.
        let wraps = body["wraps"].as_array().unwrap();
        assert_eq!(wraps.len(), 2);
        assert!(wraps.iter().any(|w| w["recipient_type"] == "user"));
        assert!(wraps.iter().any(|w| w["recipient_type"] == "recovery"));
        // Recovery recipient_id is the literal string "recovery".
        let rec_wrap = wraps.iter().find(|w| w["recipient_type"] == "recovery").unwrap();
        assert_eq!(rec_wrap["recipient_id"], "recovery");
        // User wrap carries a hex recipient_id.
        let user_wrap = wraps.iter().find(|w| w["recipient_type"] == "user").unwrap();
        assert_eq!(user_wrap["recipient_id"], "11111111111111111111111111111111");
        assert!(user_wrap["wrapped_dek_b64"].is_string());
        assert!(user_wrap["grant_b64"].is_string());
        assert_eq!(user_wrap["wrap_alg"], 1);

        // Default flags → a normal listed file: neither field is emitted.
        assert!(body.get("listed").is_none());
        assert!(body.get("bundle_id").is_none());
    }

    #[test]
    fn stage_body_from_record_member_flags_emit_listed_false_and_bundle_id() {
        let rec = make_test_record();
        let flags = StageFlags { listed: false, bundle_id: Some([0xAB; 16]) };
        let body = stage_body_from_record(&rec, flags);
        assert_eq!(body["listed"], false);
        assert_eq!(body["bundle_id"], "abababababababababababababababab");
    }

    /// Prove that `resume_content_sealer` recovers the same DEK as the original
    /// upload: pass-1 `seal_from_reader` and pass-2 `seal_chunk` produce
    /// BYTE-IDENTICAL ciphertext for the same plaintext input.
    #[test]
    fn seal_chunk_pass2_is_byte_identical_to_seal_from_reader() {
        use maxsecu_client_core::{
            resume_content_sealer, SmallStreams, StreamingUploadBuilder, UploadParams,
            Identity,
        };
        use maxsecu_crypto::generate_enc_keypair;
        use maxsecu_encoding::types::{FileType, Id, Suite, Timestamp};

        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let file_id = Id([0x5C; 16]);
        let params = UploadParams {
            owner: &owner,
            owner_id: Id([0x11; 16]),
            owner_key_version: 1,
            file_id,
            file_type: FileType::Video,
            chunk_size: 4096,
            recovery_pub: rpk,
            recovery_mlkem_pub: None,
            created_at: Timestamp(1_719_500_000_000),
        };

        // A small fixture — fits in ONE 4096-byte chunk.
        let fixture: Vec<u8> = (0u8..200).collect();

        // Pass 1: seal_from_reader → capture ciphertext chunks.
        let builder = StreamingUploadBuilder::new();
        let sealer1 = builder.content_sealer(&params);
        let mut chunks_pass1: Vec<Vec<u8>> = Vec::new();
        let (count, digest) = sealer1
            .seal_from_reader(&mut Cursor::new(&fixture), |_, ct| {
                chunks_pass1.push(ct.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1, "fixture fits in one chunk");

        // finish → UploadRecords (signs/wraps; needed to find the self-wrap for pass 2).
        let records = builder
            .finish(
                &params,
                &SmallStreams { metadata: None, thumbnail: None, preview: None },
                digest,
                count,
            )
            .unwrap();

        // Find the self-wrap (recipient_type == User).
        use maxsecu_encoding::types::RecipientType;
        let self_wrap = records
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::User)
            .expect("self-wrap present");

        // Build WrappedDek from wire form (enc ‖ ct).
        let wire = wrap_wire(self_wrap);
        let wrapped_dek = WrappedDek {
            enc: wire[..32].try_into().unwrap(),
            ct: wire[32..].to_vec(),
        };
        let ctx = WrapContext {
            file_id,
            version: 1,
            recipient_id: self_wrap.recipient_id,
        };

        // Pass 2: resume_content_sealer → seal_chunk → must match pass-1 ct.
        let sealer2 = resume_content_sealer(
            &owner,
            &wrapped_dek,
            &ctx,
            Suite::V1,
            file_id,
            1,
            params.chunk_size,
        )
        .unwrap();

        let ct2 = sealer2.seal_chunk(0, &fixture, true);
        assert_eq!(
            ct2, chunks_pass1[0],
            "pass-2 seal_chunk must produce byte-identical ciphertext to pass-1"
        );
    }

    // ── cancel_bundle_inner unit tests (Task 2.5) ────────────────────────────

    /// Build a minimal in-RAM `StagedUpload` (image/blog-shaped) whose `job_dir`
    /// points at `dir`, so the cancel path has a staging dir to wipe.
    fn staged_member_with_dir(dir: std::path::PathBuf) -> StagedUpload {
        use maxsecu_client_core::{build_upload, Identity, PlaintextStreams, UploadParams};
        use maxsecu_crypto::generate_enc_keypair;
        use maxsecu_encoding::types::{FileType, Id, Timestamp};
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: Id([0x11; 16]),
            owner_key_version: 1,
            file_id: Id([0xF1; 16]),
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: rpk,
            recovery_mlkem_pub: None,
            created_at: Timestamp(1_719_500_000_000),
        };
        let streams = PlaintextStreams {
            content: b"hi".to_vec(),
            metadata: None,
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload(&params, &streams).unwrap();
        StagedUpload {
            content: StagedContent::InRam(bundle),
            file_type: "blog".into(),
            title: "T".into(),
            total_chunks: 1,
            byte_size: 2,
            preview: None,
            job_dir: Some(dir),
        }
    }

    #[tokio::test]
    async fn cancel_bundle_drops_job_and_wipes_member_dirs() {
        // Two members, each with a real on-disk staging dir holding a file.
        let base = std::env::temp_dir().join(format!(
            "maxsecu_cancel_bundle_{}",
            rand_job_id()
        ));
        let dir_a = base.join("a");
        let dir_b = base.join("b");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        std::fs::write(dir_a.join("record.json"), b"x").unwrap();
        std::fs::write(dir_b.join("out.mp4"), b"y").unwrap();

        let jobs = BundleJobs::new();
        let job = BundleJob {
            bundle_id: [0xB1; 16],
            title: "Trip".into(),
            tags: vec!["a".into()],
            members: vec![
                staged_member_with_dir(dir_a.clone()),
                staged_member_with_dir(dir_b.clone()),
            ],
            member_meta: vec![
                MemberMeta {
                    file_id: [0x01; 16],
                    file_type: maxsecu_encoding::types::FileType::Blog,
                },
                MemberMeta {
                    file_id: [0x02; 16],
                    file_type: maxsecu_encoding::types::FileType::Blog,
                },
            ],
            cover_thumbnail: None,
        };
        jobs.0.lock().await.insert("b-1".into(), job);

        // (a) cancel drops the job.
        cancel_bundle_inner(&jobs, "b-1").await.unwrap();
        assert!(jobs.0.lock().await.get("b-1").is_none(), "job removed");

        // (b) each member's staging dir was wiped.
        assert!(!dir_a.exists(), "member A staging dir removed");
        assert!(!dir_b.exists(), "member B staging dir removed");

        // (c) a second cancel of the same id is a no-op Ok (idempotent).
        cancel_bundle_inner(&jobs, "b-1").await.unwrap();

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn cancel_bundle_unknown_id_is_ok_noop() {
        let jobs = BundleJobs::new();
        cancel_bundle_inner(&jobs, "never-staged").await.unwrap();
    }
}
