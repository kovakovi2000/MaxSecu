//! Upload preparation + pipeline (DESIGN §12.2). Transcodes the user's OWN chosen
//! file (images via the pure-Rust codec; blogs are sanitized text), writes metadata
//! as the JSON {"title","tags"} form the viewer reads, builds the signed/encrypted
//! bundle via client-core, then stages + resumably uploads + finalizes. Only
//! preview/progress DTOs cross the Tauri seam — never keys/wraps/plaintext.

use std::path::Path;

use maxsecu_client_core::media::{
    FragmentEntry as TranscodeFragment, TranscodeRequest, TranscodeResult,
};
use maxsecu_client_core::video::VideoBounds;
use maxsecu_client_core::{MediaBounds, PlaintextStreams, RustImageCodec, Transcoder};
use maxsecu_encoding::types::FileType;
use maxsecu_media_launcher::{build_ffmpeg_args, FfmpegLauncher, TranscodeLauncher, TranscodeOptions};

use crate::error::UiError;

/// The upload `chunk_size` for video content. It **MUST** equal the transcode
/// worker's `TRANSCODE_CHUNK_SIZE` (4096): the fragment index's `chunk_start` /
/// `chunk_len` are expressed in whole units of this size, so the upload's content
/// chunks line up one-for-one with the fragment ranges. A mismatch would silently
/// break seek (`chunks_for_fragment` would resolve a fragment to the wrong byte
/// range), so [`prepare_video_streams`] enforces the alignment against this value.
/// (The worker's `TRANSCODE_CHUNK_SIZE` lives in a crate this codec-free process
/// does not depend on, so the constant is duplicated here and checked at runtime.)
pub const VIDEO_CHUNK_SIZE: u32 = 4096;

/// Build the canonical metadata blob: JSON `{"title","tags"}` (UTF-8) — exactly
/// what `commands::feed::parse_title_tags` reads back.
pub fn build_metadata(title: &str, tags: &[String]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "title": title, "tags": tags })).unwrap_or_default()
}

/// Build the canonical **video** metadata blob: JSON `{"title","tags","fragments"}`
/// where each fragment is `{seq,pts_ms,chunk_start,chunk_len}` — the EXACT shape the
/// viewer's [`crate::video::parse_fragment_index`] reads back (the author→view seek
/// contract). The field names are the verbatim wire/JSON names from the transcode
/// worker, so the index round-trips unchanged through the authenticated metadata
/// stream.
pub fn build_metadata_with_fragments(
    title: &str,
    tags: &[String],
    fragments: &[TranscodeFragment],
) -> Vec<u8> {
    let frags: Vec<serde_json::Value> = fragments
        .iter()
        .map(|f| {
            serde_json::json!({
                "seq": f.seq,
                "pts_ms": f.pts_ms,
                "chunk_start": f.chunk_start,
                "chunk_len": f.chunk_len,
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "title": title, "tags": tags, "fragments": frags,
    }))
    .unwrap_or_default()
}

/// Sanitized video-prep error (no internal detail / decode oracle crosses the seam).
fn video_prep_err() -> UiError {
    UiError::new("video_failed", "That video could not be processed.")
}

/// DISTINCT, benign terminal for a user-initiated (or app-shutdown) cancel of the
/// confined transcode — the UI returns to idle rather than surfacing a failure. Kept
/// separate from [`video_prep_err`] so a real decode failure and a deliberate cancel
/// never look alike.
fn video_cancelled_err() -> UiError {
    UiError::new("cancelled", "Transcode cancelled.")
}

/// RAII guard that recursively deletes a per-job temp dir on **every** exit path
/// (success and error). This is the [`FfmpegLauncher::run`] CLEANUP OBLIGATION, not
/// mere hygiene: the confined ffmpeg writes output files inside the granted dir that
/// inherit the container-SID allow ACE + a Low integrity label at creation, and
/// revoking the dir grant cannot retroactively strip those from the child files —
/// only wholesale deletion of the WHOLE per-job dir removes the
/// container-accessible, Low-IL artifacts. Because the wipe is in `Drop`, it runs
/// even on an early `?`/`return` mid-flow.
struct JobDirGuard {
    dir: std::path::PathBuf,
}

impl Drop for JobDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A fresh, unique per-job dir path under the system temp dir. The pid + 8 random
/// bytes make it collision-free across concurrent ingests; the caller `create_dir`s
/// it so it is guaranteed freshly created (not pre-existing).
fn unique_job_dir() -> std::path::PathBuf {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        hex(&maxsecu_crypto::random_array::<8>())
    );
    std::env::temp_dir().join(format!("maxsecu-vjob-{unique}"))
}

/// Transcode the author's **arbitrary** source video to canonical AV1/CMAF streams
/// via TWO confined spawns, keeping this key-holding process CODEC-FREE (it links
/// only the codec-free `media-launcher` + the pure-Rust `RustImageCodec`; rav1d /
/// symphonia never enter it).
///
/// Flow (topology A — two confined spawns):
/// 1. A fresh, unique, freshly-created per-job dir is made; a [`JobDirGuard`]
///    recursively deletes the WHOLE dir on every return path (the
///    [`FfmpegLauncher::run`] cleanup obligation).
/// 2. The source is COPIED into the granted dir (the confined ffmpeg reads it under
///    the single ReadWrite grant), preserving the extension so ffmpeg can sniff it.
/// 3. **Confined ffmpeg** ([`FfmpegLauncher`], no net/keys/children, mem cap,
///    bounded timeout) runs the pinned [`build_ffmpeg_args`] argv — ONE invocation
///    producing both `out.mp4` (AV1 + AAC) and `thumb.png` (first frame). A nonzero
///    exit fails closed; the bounded stderr tail is diagnostic only and never
///    surfaced to the UI (no decode oracle).
/// 4. **Confined re-mux worker** ([`TranscodeLauncher`]) takes `out.mp4`'s BYTES and
///    returns the canonical [`TranscodeResult`] (CMAF fragments; its
///    `thumbnail`/`preview` are empty — derived below instead).
/// 5. The real thumbnail + preview are derived from `thumb.png` via the pure-Rust
///    [`RustImageCodec`] (the same path image uploads use).
///
/// Maps `TranscodeResult.cmaf` → `content`, the derived image streams →
/// `thumbnail`/`preview`, and `build_metadata_with_fragments(title, tags,
/// &fragments)` → `metadata`. This does **NO network** — it is the
/// preview-before-upload transcode.
///
/// **Chunk-size invariant.** The fragment index is expressed in
/// [`VIDEO_CHUNK_SIZE`] (4096)-byte units. This re-validates the worker's index
/// against the canonical content: it must parse + validate as a contiguous index
/// (`parse_fragment_index`) AND cover the `cmaf` exactly in whole 4096-byte chunks
/// (so the upload's content chunks map one-for-one onto the fragment ranges). A
/// worker that returns a misaligned stream/index fails closed here rather than
/// silently breaking seek after upload.
// Each input is a distinct concern of the confined two-stage transcode (source path,
// the two confined binaries, options/bounds, the title/tags baked into metadata, the
// progress sink, and the cancel flag); a params struct would only indirect the one
// call site in `commands::upload::stage_upload`.
#[allow(clippy::too_many_arguments)]
pub fn prepare_video_streams(
    input_path: &Path,
    ffmpeg_path: &Path,
    transcode_worker_path: &Path,
    options: &TranscodeOptions,
    bounds: &VideoBounds,
    title: &str,
    tags: &[String],
    on_phase: impl Fn(crate::state::PreparePhase) + Sync,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<(PlaintextStreams, Vec<TranscodeFragment>), UiError> {
    // 1) Fresh, unique, freshly-created per-job dir. The guard recursively deletes
    //    the WHOLE dir on every return path (security cleanup, see JobDirGuard).
    let dir = unique_job_dir();
    std::fs::create_dir(&dir).map_err(|_| video_prep_err())?;
    let _guard = JobDirGuard { dir: dir.clone() };

    // 2) Copy the source INTO the granted dir so the confined ffmpeg can read it
    //    under the single ReadWrite grant. Preserve the original extension (ffmpeg
    //    sniffs by content too, so a missing ext falls back to `input.bin`).
    let input_copy = match input_path.extension() {
        Some(ext) => {
            let mut name = std::ffi::OsString::from("input.");
            name.push(ext);
            dir.join(name)
        }
        None => dir.join("input.bin"),
    };
    std::fs::copy(input_path, &input_copy).map_err(|_| video_prep_err())?;

    // 3) The pinned argv: ONE confined ffmpeg run → out.mp4 (AV1+AAC) + thumb.png.
    let out_mp4 = dir.join("out.mp4");
    let thumb_png = dir.join("thumb.png");
    let args = build_ffmpeg_args(&input_copy, &out_mp4, &thumb_png, options, bounds);

    // 4) Decode the untrusted source in the CONFINED ffmpeg (no net / keys /
    //    children, mem cap, bounded timeout). A nonzero exit fails closed; the
    //    bounded stderr is diagnostic only and never reaches the UI.
    //    `on_progress` forwards ffmpeg's sanitized percent to the UI as a
    //    `Transcoding{percent}` phase; `cancel` is polled throughout so a user cancel
    //    / app shutdown tears the confined child down (RAII grant revoked on that path
    //    exactly as on every other) and returns the DISTINCT `cancelled` error.
    let outcome = FfmpegLauncher::new(ffmpeg_path)
        .run(
            &args,
            &dir,
            |p| on_phase(crate::state::PreparePhase::Transcoding { percent: p.percent }),
            cancel,
        )
        .map_err(|_| video_prep_err())?;
    if outcome.cancelled {
        return Err(video_cancelled_err());
    }
    if outcome.exit_code != 0 {
        return Err(video_prep_err());
    }

    // 5) Read ffmpeg's outputs from the granted dir; both must exist, be non-empty,
    //    and sit within the re-mux worker's accept ceiling. The size pre-check fails
    //    closed BEFORE allocating an arbitrarily large `out.mp4` only for the worker's
    //    framed codec to reject it past MAX_FRAME_BYTES — a self-OOM guard on large
    //    sources (full large-source streaming is a deferred residual). A missing file
    //    makes `metadata` error → `over_cap` true → fail closed (covers "must exist").
    let cap = maxsecu_media_launcher::framing::MAX_FRAME_BYTES as u64;
    let over_cap =
        |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len() > cap).unwrap_or(true);
    if over_cap(&out_mp4) || over_cap(&thumb_png) {
        return Err(video_prep_err());
    }
    let out_mp4_bytes = std::fs::read(&out_mp4).map_err(|_| video_prep_err())?;
    let thumb_png_bytes = std::fs::read(&thumb_png).map_err(|_| video_prep_err())?;
    if out_mp4_bytes.is_empty() || thumb_png_bytes.is_empty() {
        return Err(video_prep_err());
    }

    // 6) Re-mux out.mp4's bytes → canonical AV1/CMAF in the SECOND confined spawn.
    //    The worker's thumbnail/preview come back empty (derived below). `cancel` is
    //    forwarded so a user cancel tears the re-mux child down promptly rather than
    //    waiting out the full bound; a cancel-induced worker failure maps to the
    //    distinct `cancelled` error, a real failure to the sanitized one.
    on_phase(crate::state::PreparePhase::Remuxing);
    let result: TranscodeResult = TranscodeLauncher::new(transcode_worker_path)
        .transcode(
            &TranscodeRequest {
                source: out_mp4_bytes,
                bounds: *bounds,
            },
            cancel,
        )
        .map_err(|_| {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                video_cancelled_err()
            } else {
                video_prep_err()
            }
        })?;
    // A cancel that raced the worker's clean exit still returns the benign terminal.
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(video_cancelled_err());
    }

    // 7) Derive the real thumbnail + preview from ffmpeg's first-frame PNG via the
    //    pure-Rust image codec — NO C codec enters this key-holding process. This +
    //    the index validation + assemble are the final local step.
    on_phase(crate::state::PreparePhase::Finalizing);
    let derived = RustImageCodec
        .transcode(&thumb_png_bytes, &MediaBounds::default())
        .map_err(|_| video_prep_err())?;

    let metadata = build_metadata_with_fragments(title, tags, &result.fragments);

    // 8) Enforce the chunk-size mapping (seek correctness). The metadata fragment
    //    index must validate (contiguity/ordering/coverage) AND tile the canonical
    //    content exactly in whole VIDEO_CHUNK_SIZE chunks.
    let chunk = VIDEO_CHUNK_SIZE as usize;
    if result.cmaf.is_empty() || !result.cmaf.len().is_multiple_of(chunk) {
        return Err(video_prep_err());
    }
    let meta_json: serde_json::Value =
        serde_json::from_slice(&metadata).map_err(|_| video_prep_err())?;
    let index = crate::video::parse_fragment_index(&meta_json)?;
    let last = index.last().ok_or_else(video_prep_err)?;
    let covered_chunks = last
        .chunk_start
        .checked_add(last.chunk_len)
        .ok_or_else(video_prep_err)?;
    if covered_chunks != (result.cmaf.len() / chunk) as u64 {
        return Err(video_prep_err());
    }

    // 9) Assemble — canonical content + metadata, derived thumbnail + preview.
    let streams = PlaintextStreams {
        content: result.cmaf,
        metadata: Some(metadata),
        thumbnail: Some(derived.thumbnail),
        preview: Some(derived.preview),
    };
    // 10) `_guard` drops here → the per-job dir is recursively deleted.
    Ok((streams, result.fragments))
}

/// Blog: `content` is the plain UTF-8 bytes; metadata is the JSON title/tags; no
/// thumbnail/preview.
pub fn prepare_blog_streams(content: Vec<u8>, title: &str, tags: &[String]) -> PlaintextStreams {
    PlaintextStreams {
        content,
        metadata: Some(build_metadata(title, tags)),
        thumbnail: None,
        preview: None,
    }
}

/// Image: transcode the user's chosen bytes to canonical streams (content +
/// thumbnail + preview), then attach the metadata JSON. Fail-closed on a bad image.
/// Returns the detected `FileType` (Image) and the prepared streams.
pub fn prepare_image_streams(
    src: &[u8],
    title: &str,
    tags: &[String],
) -> Result<(FileType, PlaintextStreams), UiError> {
    let canonical = RustImageCodec
        .transcode(src, &MediaBounds::default())
        .map_err(|_| UiError::new("bad_image", "That image could not be processed."))?;
    let file_type = canonical.file_type;
    let streams = canonical.into_plaintext_streams(Some(build_metadata(title, tags)));
    Ok((file_type, streams))
}

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;

use maxsecu_client_core::{UploadBundle, WrapOut};
use maxsecu_encoding::encode;
use maxsecu_encoding::types::{RecipientType, StreamType};

use crate::http_client::{post_json, put_bytes};

/// Max re-PUT attempts per chunk (idempotent server-side → safe to retry/resume).
const MAX_CHUNK_RETRY: u32 = 3;

fn stream_name(s: StreamType) -> &'static str {
    match s {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
}
fn wrap_wire(w: &WrapOut) -> Vec<u8> {
    let mut v = w.wrapped_dek.enc.to_vec();
    v.extend_from_slice(&w.wrapped_dek.ct);
    v
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn file_type_str(t: FileType) -> &'static str {
    match t {
        FileType::Image => "image",
        FileType::Blog => "blog",
        FileType::Video => "video",
    }
}

/// Shape the §8.1 `POST /v1/files` JSON body from a built bundle.
pub fn stage_body(b: &UploadBundle) -> serde_json::Value {
    let streams: Vec<_> = b
        .streams
        .iter()
        .map(|s| {
            serde_json::json!({
                "stream_type": stream_name(s.stream_type), "chunk_count": s.chunk_count,
                "chunk_size": s.chunk_size, "total_bytes": s.total_bytes,
            })
        })
        .collect();
    let wraps: Vec<_> = b
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
                "wrapped_dek_b64": B64.encode(wrap_wire(w)), "wrap_alg": 1,
                "granted_by": hex(&w.granted_by.0),
                "grant_b64": B64.encode(encode(&w.grant)), "grant_sig_b64": B64.encode(w.grant_sig),
            })
        })
        .collect();
    serde_json::json!({
        "file_id": hex(&b.file_id.0), "file_type": file_type_str(b.file_type),
        "genesis_b64": B64.encode(encode(&b.genesis)), "genesis_sig_b64": B64.encode(b.genesis_sig),
        "manifest_b64": B64.encode(encode(&b.manifest)), "manifest_sig_b64": B64.encode(b.manifest_sig),
        "streams": streams, "wraps": wraps,
    })
}

/// Total ciphertext chunks across all streams (progress denominator).
pub fn total_chunks(b: &UploadBundle) -> u64 {
    b.streams.iter().map(|s| s.chunk_count).sum()
}

/// PUT one chunk, retrying up to MAX_CHUNK_RETRY on a transport error or non-200
/// (idempotent by index → safe). Fail-closed `upload_chunk_failed` after retries.
// Wired into `confirm_upload` + exercised by the Task-10 e2e.
async fn put_chunk_retried(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    stype: StreamType,
    index: u64,
    chunk: &[u8],
) -> Result<(), UiError> {
    let uri = format!(
        "/v1/files/{file_id_hex}/versions/1/streams/{}/chunks/{index}",
        stream_name(stype)
    );
    let mut attempt = 0u32;
    // Always re-PUT the SAME chunk: PUT is idempotent by index, so a retry after a
    // partial/failed attempt simply resumes that slot (no backoff needed in-process).
    loop {
        match put_bytes(sender, &uri, chunk.to_vec(), token, host).await {
            Ok(s) if s == hyper::StatusCode::OK => return Ok(()),
            _ if attempt < MAX_CHUNK_RETRY => attempt += 1,
            _ => {
                return Err(UiError::new(
                    "upload_chunk_failed",
                    "A chunk failed to upload.",
                ))
            }
        }
    }
}

/// Stage → PUT every chunk (resumable/idempotent, retried) → finalize.
/// `on_progress(done, total)` after each successful chunk. Fail-closed.
// Wired into `confirm_upload` + exercised by the Task-10 e2e.
pub async fn run_pipeline<F: FnMut(u64, u64)>(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    bundle: &UploadBundle,
    mut on_progress: F,
) -> Result<(), UiError> {
    let fid = hex(&bundle.file_id.0);
    let (st, _res) = post_json(sender, "/v1/files", &stage_body(bundle), Some(token), host).await?;
    if st != hyper::StatusCode::CREATED {
        return Err(UiError::new("stage_failed", "Could not start the upload."));
    }
    let total = total_chunks(bundle);
    let mut done = 0u64;
    for s in &bundle.streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            put_chunk_retried(sender, host, token, &fid, s.stream_type, i as u64, chunk).await?;
            done += 1;
            on_progress(done, total);
        }
    }
    let (st, _res) = post_json(
        sender,
        &format!("/v1/files/{fid}/versions/1/finalize"),
        &serde_json::Value::Null,
        Some(token),
        host,
    )
    .await?;
    if st != hyper::StatusCode::OK {
        return Err(UiError::new(
            "finalize_failed",
            "Could not finalize the upload.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrips_through_parse_title_tags() {
        let meta = build_metadata("Sunset", &["beach".to_owned(), "2026".to_owned()]);
        let (t, tags) = crate::commands::feed::parse_title_tags(&meta);
        assert_eq!(t, "Sunset");
        assert_eq!(tags, vec!["beach".to_owned(), "2026".to_owned()]);
    }

    #[test]
    fn video_metadata_with_fragments_roundtrips_through_parse_fragment_index() {
        let frags = vec![
            TranscodeFragment {
                seq: 0,
                pts_ms: 0,
                chunk_start: 0,
                chunk_len: 2,
            },
            TranscodeFragment {
                seq: 1,
                pts_ms: 1000,
                chunk_start: 2,
                chunk_len: 3,
            },
        ];
        let meta = build_metadata_with_fragments("Clip", &["holiday".to_owned()], &frags);
        // Title/tags still parse via the shared title/tag reader.
        let (t, tags) = crate::commands::feed::parse_title_tags(&meta);
        assert_eq!(t, "Clip");
        assert_eq!(tags, vec!["holiday".to_owned()]);
        // And the fragment index round-trips byte-for-field through the viewer's
        // authenticated-metadata reader (the author→view seek contract).
        let json: serde_json::Value = serde_json::from_slice(&meta).unwrap();
        let parsed = crate::video::parse_fragment_index(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[1],
            crate::video::FragmentEntry {
                seq: 1,
                pts_ms: 1000,
                chunk_start: 2,
                chunk_len: 3,
            }
        );
    }

    #[test]
    fn video_chunk_size_matches_the_upload_chunk_size() {
        // The fragment index is in VIDEO_CHUNK_SIZE units; the upload stages video
        // content at exactly this chunk size so the ranges map one-for-one. This is
        // the same 4096 the transcode worker's TRANSCODE_CHUNK_SIZE pads to.
        assert_eq!(VIDEO_CHUNK_SIZE, 4096);
    }

    #[test]
    fn blog_streams_carry_content_and_metadata() {
        let s = prepare_blog_streams(b"hello world".to_vec(), "T", &[]);
        assert_eq!(s.content, b"hello world");
        assert!(s.metadata.is_some());
        assert!(s.thumbnail.is_none() && s.preview.is_none());
    }

    #[test]
    fn image_streams_transcode_and_attach_metadata() {
        // A tiny real image so the pure-Rust codec produces canonical streams.
        use image::{DynamicImage, ImageFormat, RgbImage};
        use std::io::Cursor;
        let mut img = RgbImage::new(32, 24);
        for (x, y, px) in img.enumerate_pixels_mut() {
            *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 7]);
        }
        let mut buf = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .unwrap();
        let (ft, streams) = prepare_image_streams(&buf, "Pic", &["a".to_owned()]).unwrap();
        assert_eq!(ft, FileType::Image);
        assert!(!streams.content.is_empty());
        assert!(streams.metadata.is_some());
        // A bad image fails closed. (`PlaintextStreams` is not `Debug`, so the
        // `Ok` arm can't go through `unwrap_err`; match the error directly.)
        let err = match prepare_image_streams(b"not-an-image", "x", &[]) {
            Ok(_) => panic!("garbage bytes must not transcode"),
            Err(e) => e,
        };
        assert_eq!(err.code, "bad_image");
    }

    #[test]
    fn stage_body_shapes_streams_and_wraps() {
        use maxsecu_client_core::{build_upload, Identity, UploadParams};
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
        let streams = prepare_blog_streams(b"hello".to_vec(), "Hi", &["t".to_owned()]);
        let bundle = build_upload(&params, &streams).unwrap();
        let body = stage_body(&bundle);
        assert_eq!(body["file_id"], "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1");
        assert_eq!(body["file_type"], "blog");
        assert!(body["streams"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["stream_type"] == "content"));
        // self + recovery wraps; each carries a wrapped_dek + grant.
        let wraps = body["wraps"].as_array().unwrap();
        assert!(wraps.len() >= 2);
        assert!(wraps
            .iter()
            .all(|w| w["wrapped_dek_b64"].is_string() && w["grant_b64"].is_string()));
        assert!(wraps.iter().any(|w| w["recipient_type"] == "recovery"));
        // total_chunks counts every stream's chunks.
        assert!(total_chunks(&bundle) >= 1);
    }
}
