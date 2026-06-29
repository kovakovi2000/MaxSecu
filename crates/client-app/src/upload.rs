//! Upload preparation + pipeline (DESIGN §12.2). Transcodes the user's OWN chosen
//! file (images via the pure-Rust codec; blogs are sanitized text), writes metadata
//! as the JSON {"title","tags"} form the viewer reads, builds the signed/encrypted
//! bundle via client-core, then stages + resumably uploads + finalizes. Only
//! preview/progress DTOs cross the Tauri seam — never keys/wraps/plaintext.

use maxsecu_client_core::{MediaBounds, PlaintextStreams, RustImageCodec, Transcoder};
use maxsecu_encoding::types::FileType;

use crate::error::UiError;

/// Build the canonical metadata blob: JSON `{"title","tags"}` (UTF-8) — exactly
/// what `commands::feed::parse_title_tags` reads back.
// Wired into the upload command in the next Phase-4 task; exercised by tests now.
#[allow(dead_code)]
pub(crate) fn build_metadata(title: &str, tags: &[String]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "title": title, "tags": tags })).unwrap_or_default()
}

/// Blog: `content` is the plain UTF-8 bytes; metadata is the JSON title/tags; no
/// thumbnail/preview.
// Wired into the upload command in the next Phase-4 task; exercised by tests now.
#[allow(dead_code)]
pub(crate) fn prepare_blog_streams(
    content: Vec<u8>,
    title: &str,
    tags: &[String],
) -> PlaintextStreams {
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
// Wired into the upload command in the next Phase-4 task; exercised by tests now.
#[allow(dead_code)]
pub(crate) fn prepare_image_streams(
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
pub(crate) fn stage_body(b: &UploadBundle) -> serde_json::Value {
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
pub(crate) fn total_chunks(b: &UploadBundle) -> u64 {
    b.streams.iter().map(|s| s.chunk_count).sum()
}

/// PUT one chunk, retrying up to MAX_CHUNK_RETRY on a transport error or non-200
/// (idempotent by index → safe). Fail-closed `upload_chunk_failed` after retries.
// Wired into `confirm_upload` in Task 7 + exercised by the Task-10 e2e; the body
// is live (calls `put_bytes`), only the entry point is not yet called.
#[allow(dead_code)]
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
// Wired into `confirm_upload` in Task 7 + exercised by the Task-10 e2e.
#[allow(dead_code)]
pub(crate) async fn run_pipeline<F: FnMut(u64, u64)>(
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
