//! Upload commands. `stage_upload` transcodes/encrypts the user's chosen content
//! and holds the bundle for preview (NO network write); `confirm_upload` (Task 7)
//! runs the pipeline. Only preview/progress DTOs cross the seam — never the bundle,
//! keys, or plaintext.

use tauri::State;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

use maxsecu_client_core::{
    build_upload, DirectoryVerifier, Identity, MemoryTrustStore, UploadParams,
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
use crate::jobs::{StagedUpload, StagedVideoPreview, UploadJobs};
use crate::state::{UploadPhase, EVT_UPLOAD};
use crate::upload::{
    prepare_blog_streams, prepare_image_streams, prepare_video_streams, run_pipeline, total_chunks,
};

use tauri::Emitter;

/// Max bytes we read from a chosen file / accept as blog text (DoS guard).
const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// The `build_upload` chunk size for EVERY kind. This is the SINGLE source of truth
/// for the 4096-byte chunking — it is `crate::upload::VIDEO_CHUNK_SIZE`, the same
/// constant the video fragment-index validator uses. Tying them here makes it
/// impossible to stage video at a `chunk_size` that differs from the fragment
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
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    jobs: State<'_, UploadJobs>,
) -> Result<UploadPreview, UiError> {
    // 1) Prepare the plaintext streams from the user's own content. For a video the
    //    transcode runs in the CONFINED worker (no network) and additionally yields
    //    the canonical plaintext + fragment index held for the local preview.
    let (file_type, mut streams, video_preview) = match req.kind {
        UploadKind::Blog => {
            let text = req.content.clone().unwrap_or_default();
            if text.len() as u64 > MAX_UPLOAD_BYTES {
                return Err(UiError::new("too_large", "That post is too large."));
            }
            (
                maxsecu_encoding::types::FileType::Blog,
                prepare_blog_streams(text.into_bytes(), &req.title, &req.tags),
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
            (ft, s, None)
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
            let tw_path = crate::commands::video::transcode_worker_path(&dir.0);
            let options = req.options.clone().unwrap_or_default();
            // Confined ingest OFF the async runtime (two confined subprocess spawns +
            // file/pipe I/O must not run on a tokio worker thread). NO network here —
            // this is the preview-before-upload transcode.
            let title = req.title.clone();
            let tags = req.tags.clone();
            let (s, frags) = tokio::task::spawn_blocking(move || {
                prepare_video_streams(
                    &input_path,
                    &ffmpeg_path,
                    &tw_path,
                    &options,
                    &maxsecu_client_core::video::VideoBounds::default(),
                    &title,
                    &tags,
                )
            })
            .await
            .map_err(|_| UiError::new("encrypt_failed", "Could not prepare the upload."))??;
            // Hold the canonical plaintext + the authenticated seek index for the
            // local WYSIWYG preview (the bundle also carries the ciphertext form).
            let index: Vec<crate::video::FragmentEntry> = frags
                .iter()
                .map(|f| crate::video::FragmentEntry {
                    seq: f.seq,
                    pts_ms: f.pts_ms,
                    chunk_start: f.chunk_start,
                    chunk_len: f.chunk_len,
                })
                .collect();
            // Hold the canonical plaintext in a Zeroizing buffer so the full-file
            // plaintext is wiped on drop (confirm/cancel) — matching the per-window
            // ScriptGuard zeroize discipline. It is RAM-only, never on disk.
            let preview = StagedVideoPreview {
                cmaf: Zeroizing::new(s.content.clone()),
                index,
            };
            (
                maxsecu_encoding::types::FileType::Video,
                s,
                Some(preview),
            )
        }
    };
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
        },
    );
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
        Ok(()) => Ok(file_id_hex),
        Err(e) => {
            jobs.0.lock().await.insert(job_id, staged); // retain for retry
            Err(e)
        }
    }
}

/// `cancel_upload` — drop a staged (pre-confirm or retained-after-failure) job. An
/// in-flight confirm is not interrupted (documented Phase-4 limitation).
#[tauri::command]
pub async fn cancel_upload(
    req: CancelUploadRequest,
    jobs: State<'_, UploadJobs>,
) -> Result<(), UiError> {
    jobs.0.lock().await.remove(&req.job_id);
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
