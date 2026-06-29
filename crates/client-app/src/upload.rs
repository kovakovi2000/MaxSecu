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
}
