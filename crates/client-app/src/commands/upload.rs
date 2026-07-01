//! Upload commands. `stage_upload` transcodes/encrypts the user's chosen content
//! and holds the bundle for preview (NO network write); `confirm_upload` (Task 7)
//! runs the pipeline. Only preview/progress DTOs cross the seam — never the bundle,
//! keys, or plaintext.

use tauri::State;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::Zeroize;

use maxsecu_client_core::{
    build_upload, DirectoryVerifier, Identity, MemoryTrustStore, PlaintextStreams, UploadParams,
};
use maxsecu_crypto::EncPublicKey;
use maxsecu_encoding::types::{Id, Timestamp};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{open_conn, reauth, server_of};
use crate::config::{load_directory_pub, recovery_recipient_username};
use crate::directory::{resolve_my_binding, resolve_recovery_recipient};
use crate::dto::{
    CancelUploadRequest, ConfirmUploadRequest, StageUploadRequest, UploadJobView, UploadKind,
    UploadPreview,
};
use crate::error::UiError;
use crate::ffmpeg_bin::ensure_ffmpeg;
use crate::jobs::{StagedUpload, StagedVideoPreview, UploadJobs, VideoPrepareCancel};
use crate::state::{PreparePhase, UploadPhase, EVT_UPLOAD, EVT_VIDEO_PREPARE};
use crate::upload::{
    prepare_blog_streams, prepare_image_streams, prepare_video_streams, run_pipeline, total_chunks,
    PreparedVideo,
};

use tauri::Emitter;

/// Max bytes we read from a chosen file / accept as blog text (DoS guard).
const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// The `build_upload` chunk size for EVERY kind. This is the SINGLE source of truth
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

/// `stage_upload` — prepare + encrypt a post and hold it for preview. No network write.
#[tauri::command]
pub async fn stage_upload(
    req: StageUploadRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    jobs: State<'_, UploadJobs>,
    prepare_cancel: State<'_, VideoPrepareCancel>,
) -> Result<UploadPreview, UiError> {
    // RAII guard that deletes the per-job temp dir on any error path AFTER a
    // successful `prepare_video_streams` (which forgot its own guard and handed the
    // dir to us). Disarmed (set to None) immediately after `jobs.insert` so the dir
    // survives to serve preview ranges while the job is staged.
    struct DirCleanup(Option<std::path::PathBuf>);
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            if let Some(d) = &self.0 {
                let _ = std::fs::remove_dir_all(d);
            }
        }
    }

    // 1) Prepare the plaintext streams from the user's own content. For a video the
    //    transcode runs in the CONFINED worker (no network) and additionally yields
    //    the on-disk fMP4 path + fragment index held for the local preview.
    let (file_type, mut streams, video_preview, video_job_dir) = match req.kind {
        UploadKind::Blog => {
            let text = req.content.clone().unwrap_or_default();
            if text.len() as u64 > MAX_UPLOAD_BYTES {
                return Err(UiError::new("too_large", "That post is too large."));
            }
            (
                maxsecu_encoding::types::FileType::Blog,
                prepare_blog_streams(text.into_bytes(), &req.title, &req.tags),
                None,
                None,
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
            (ft, s, None, None)
        }
        UploadKind::Video => {
            // The video source is now an ARBITRARY file (a path from the Browse
            // picker), decoded by the confined ffmpeg — no in-memory source, no seam
            // size limit on it.
            let path = req
                .path
                .clone()
                .ok_or_else(|| UiError::new("bad_request", "No video was chosen."))?;
            let input_path = std::path::PathBuf::from(path);
            // Materialize + verify the embedded confined ffmpeg; resolve the confined
            // re-mux worker beside the exe. Map any ffmpeg-availability error to the
            // sanitized video error (no internal detail crosses).
            let ffmpeg_path = ensure_ffmpeg(&dir.0)
                .map_err(|_| UiError::new("video_failed", "That video could not be processed."))?;
            let options = req.options.clone().unwrap_or_default();
            // Confined ingest OFF the async runtime (two confined subprocess spawns +
            // file/pipe I/O must not run on a tokio worker thread). NO network here —
            // this is the preview-before-upload transcode.
            let title = req.title.clone();
            let tags = req.tags.clone();
            // Fresh cancel token for THIS transcode; store it so `cancel_video_prepare`
            // and the app-shutdown hook can flip it (tearing the confined children
            // down). Replaces any stale token (there is at most one in-flight prepare).
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            *prepare_cancel.0.lock().unwrap() = Some(cancel.clone());
            // Emit live prepare phases over the Tauri bus from the blocking task via a
            // cloned AppHandle (AppHandle is Send+Sync). Only the sanitized PreparePhase
            // crosses — no ffmpeg stderr/paths.
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
                    &title,
                    &tags,
                    on_phase,
                    &cancel_task,
                )
            })
            .await;
            // Clear the stored token on EVERY outcome (completion / cancel / error) so a
            // later `cancel_video_prepare` cannot flip a dead token.
            *prepare_cancel.0.lock().unwrap() = None;
            let prepared: PreparedVideo = match staged {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    // Emit the sanitized terminal phase mirroring the returned code: a
                    // benign `Cancelled` for a user/shutdown cancel, else `Failed`.
                    let phase = if e.code == "cancelled" {
                        PreparePhase::Cancelled
                    } else {
                        PreparePhase::Failed {
                            code: e.code.clone(),
                        }
                    };
                    let _ = app.emit(EVT_VIDEO_PREPARE, phase);
                    return Err(e);
                }
                Err(_) => {
                    let _ = app.emit(
                        EVT_VIDEO_PREPARE,
                        PreparePhase::Failed {
                            code: "video_failed".into(),
                        },
                    );
                    return Err(UiError::new(
                        "encrypt_failed",
                        "Could not prepare the upload.",
                    ));
                }
            };
            // BRIDGE: read the on-disk fMP4 back into RAM for `build_upload`.
            // A later task removes this read and streams directly from disk; for now
            // it is the minimal delta (no change to build_upload / PlaintextStreams).
            let content = std::fs::read(&prepared.out_mp4_path).map_err(|_| {
                UiError::new("encrypt_failed", "Could not prepare the upload.")
            })?;
            let streams = PlaintextStreams {
                content,
                metadata: Some(prepared.metadata),
                thumbnail: Some(prepared.thumbnail),
                preview: Some(prepared.preview),
            };
            // Build the authenticated fragment seek index (VIDEO_CHUNK_SIZE units).
            let index: Vec<crate::video::FragmentEntry> = prepared
                .fragments
                .iter()
                .map(|f| crate::video::FragmentEntry {
                    seq: f.seq,
                    pts_ms: f.pts_ms,
                    chunk_start: f.chunk_start,
                    chunk_len: f.chunk_len,
                })
                .collect();
            // File-backed preview: hold the on-disk path, NOT the bytes. Range
            // requests are served by seek+read via `preview_slice_file`.
            let preview = StagedVideoPreview {
                out_mp4_path: prepared.out_mp4_path.clone(),
                index,
            };
            (
                maxsecu_encoding::types::FileType::Video,
                streams,
                Some(preview),
                Some(prepared.job_dir),
            )
        }
    };
    // Arm the stage-error cleanup guard. For video, any `?` error between here and
    // `jobs.insert` (recipient resolution, build_upload, etc.) triggers Drop → dir
    // wipe. For blog/image, DirCleanup(None) is a no-op. Disarmed after insert.
    let mut dir_cleanup = DirCleanup(video_job_dir.clone());

    let thumbnail_b64 = streams.thumbnail.as_ref().map(|t| B64.encode(t));
    let byte_size = streams.content.len() as u64;

    // 2) Resolve recipients under the pinned D5 (unauth directory GETs).
    let pinned = load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();
    let username = { session.0.lock().await.username.clone() }
        .ok_or_else(|| UiError::new("locked", "Sign in first."))?;
    let server = server_of(&dir.0)?;
    let (mut sender, host, _exporter) = open_conn(&dir.0, &server).await?;
    let me = resolve_my_binding(&mut sender, &host, &username, &verifier, &mut trust, now).await?;
    let recovery_username = recovery_recipient_username(&dir.0)?;
    let recovery = resolve_recovery_recipient(
        &mut sender,
        &host,
        &recovery_username,
        &verifier,
        &mut trust,
        now,
    )
    .await?;

    // 3) Build the signed, encrypted bundle (identity borrowed UNDER the lock, sync).
    let file_id = Id(maxsecu_crypto::random_array::<16>());
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

    // The bundle now holds the encrypted content; wipe the transient plaintext
    // content copy in `streams` (defense-in-depth, matching the Zeroizing preview
    // copy). The small metadata/thumbnail/preview streams are derived public-shape
    // data; the full-file content is the sensitive plaintext.
    streams.content.zeroize();

    // 4) Hold for preview (NO network). The bundle stays in the TCB.
    let total = total_chunks(&bundle);
    let file_type_str = bundle_file_type_str(&bundle);
    let job_id = rand_job_id();
    jobs.0.lock().await.insert(
        job_id.clone(),
        StagedUpload {
            bundle,
            file_type: file_type_str.clone(),
            title: req.title.clone(),
            total_chunks: total,
            byte_size,
            preview: video_preview,
            job_dir: video_job_dir,
        },
    );
    // Ownership of the temp dir now lives in StagedUpload — disarm the guard so it
    // does not clean up the dir on return. If anything above panics after insert (not
    // expected here), the dir persists, which is acceptable.
    dir_cleanup.0 = None;
    Ok(UploadPreview {
        job_id,
        file_type: file_type_str,
        title: req.title,
        tags: req.tags,
        byte_size,
        total_chunks: total,
        thumbnail_b64,
    })
}

fn bundle_file_type_str(b: &maxsecu_client_core::UploadBundle) -> String {
    use maxsecu_encoding::types::FileType;
    match b.file_type {
        FileType::Image => "image",
        FileType::Blog => "blog",
        FileType::Video => "video",
    }
    .to_owned()
}

/// `confirm_upload` — run the staged bundle's network pipeline (stage → resumable
/// chunk PUT → finalize), emitting `UploadPhase` over `EVT_UPLOAD`. On success the
/// job is removed; on failure it is RETAINED so the tray can retry. The bundle
/// never leaves the TCB — only progress events + the returned file_id cross.
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
            // committed — drop the staged copy (confirm_inner already took it out on
            // the success path; this is a defensive no-op that also covers a racing
            // retry insert).
            jobs.0.lock().await.remove(&job_id);
            emit(UploadPhase::Done {
                job_id: job_id.clone(),
                file_id: file_id.clone(),
            });
        }
        Err(e) => {
            // The job is retained by confirm_inner so the user can retry from the tray.
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
    emit(UploadPhase::Staging {
        job_id: job_id.clone(),
    });
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;

    // Take the bundle out for the duration of the upload (UploadBundle isn't Clone);
    // re-insert on failure so the tray can retry.
    let staged = { jobs.0.lock().await.remove(&job_id) }
        .ok_or_else(|| UiError::new("no_such_job", "That upload is no longer staged."))?;
    let file_id_hex = staged
        .bundle
        .file_id
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    // Emit `Uploading{done,total}` per chunk; when the last chunk lands (done==total)
    // emit `Finalizing` — `run_pipeline` finalizes immediately after the chunk loop,
    // so this is the honest pre-finalize signal. `emit` already captures `app`.
    let result = run_pipeline(&mut sender, &host, &token, &staged.bundle, |done, total| {
        emit(UploadPhase::Uploading {
            job_id: job_id.clone(),
            done,
            total,
        });
        if done == total {
            emit(UploadPhase::Finalizing {
                job_id: job_id.clone(),
            });
        }
    })
    .await;

    match result {
        Ok(()) => {
            // Upload committed: the on-disk transcode is no longer needed. Delete the
            // per-job temp dir (video) or no-op (image/blog where job_dir is None).
            if let Some(d) = &staged.job_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            Ok(file_id_hex)
        }
        Err(e) => {
            // Retain the job (and its job_dir) for retry — the on-disk fMP4 must
            // still be readable so preview ranges keep working in the upload tray.
            jobs.0.lock().await.insert(job_id, staged);
            Err(e)
        }
    }
}

/// `cancel_upload` — drop a staged (pre-confirm or retained-after-failure) job. An
/// in-flight confirm is not interrupted (documented Phase-4 limitation). Also deletes
/// the per-job temp dir (video) so no Low-IL container artifacts linger on disk.
#[tauri::command]
pub async fn cancel_upload(
    req: CancelUploadRequest,
    jobs: State<'_, UploadJobs>,
) -> Result<(), UiError> {
    if let Some(s) = jobs.0.lock().await.remove(&req.job_id) {
        if let Some(d) = s.job_dir {
            let _ = std::fs::remove_dir_all(&d);
        }
    }
    Ok(())
}

/// `cancel_video_prepare` — request cancellation of the in-flight video `stage_upload`
/// transcode. Best-effort: sets the stored cancel token's flag (which the confined
/// ffmpeg + re-mux waits poll → they terminate the confined children), then
/// `stage_upload` returns the distinct `cancelled` error and emits `PreparePhase::Cancelled`.
/// `Ok(())` if there is no in-flight prepare (nothing to cancel). This is also invoked
/// by the app-shutdown hook so an in-flight transcode kills its confined child on exit.
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
