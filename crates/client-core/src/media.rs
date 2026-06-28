//! Client-side media pipeline (DESIGN §8.1/§13/D30, Phase 4b).
//!
//! The author's client **transcodes every video/image to one canonical format
//! before encryption** and derives a `thumbnail` + `preview`, so a *viewer* only
//! ever decodes that one format (a single hardened decoder, media-sandbox §4).
//! This module is the **seam**: a [`Transcoder`] turns arbitrary source bytes
//! into [`CanonicalStreams`] (content + thumbnail + preview) under hard
//! pre-decode bounds, and those map straight onto the [`PlaintextStreams`] the
//! existing upload core encrypts (`crate::upload`).
//!
//! What ships now:
//! * [`RustImageCodec`] — the **real** image path, in **pure Rust** (`image`
//!   crate, png/jpeg), so the largest decode surface isn't C at all
//!   (media-sandbox §4). Canonical image format is **PNG** (lossless); an
//!   already-PNG source is **stream-copied** (no re-encode, media-sandbox §4).
//! * [`FfmpegVideo`] — the video path, **deferred** behind the trait as a
//!   separate C carve-out decision; it returns [`TranscodeError::CodecUnavailable`]
//!   until a sandboxed ffmpeg/dav1d transcoder is ratified (the only sanctioned C
//!   so far is `aws-lc-rs`).
//!
//! Decoding *any* untrusted bytes is an RCE surface; the **viewer**-side decode
//! runs in the sandboxed worker (`P4b.6`). Here the author transcodes their
//! *own* input — less adversarial, but still bounded (decompression-bomb guard).

use crate::error::TranscodeError;
use crate::upload::PlaintextStreams;
use maxsecu_encoding::types::FileType;

/// Canonical image format dimension/preview parameters (media-sandbox §3,
/// parameters §1.6). The pixel cap is the decompression-bomb guard applied
/// **before** any frame buffer is allocated.
pub const MEDIA_MAX_WIDTH: u32 = 16_384;
pub const MEDIA_MAX_HEIGHT: u32 = 16_384;
pub const MEDIA_MAX_PIXELS: u64 = 64_000_000; // ~64 MP
/// Thumbnail / preview bounding boxes (aspect-preserving downscale).
pub const THUMBNAIL_MAX_DIM: u32 = 256;
pub const PREVIEW_MAX_DIM: u32 = 1024;

/// Hard pre-decode bounds: reject anything over these **before** allocating
/// (media-sandbox §3). `max_pixels` guards the width×height decompression bomb a
/// width/height check alone misses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaBounds {
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixels: u64,
}

impl Default for MediaBounds {
    fn default() -> Self {
        MediaBounds {
            max_width: MEDIA_MAX_WIDTH,
            max_height: MEDIA_MAX_HEIGHT,
            max_pixels: MEDIA_MAX_PIXELS,
        }
    }
}

/// The canonical, plaintext-derived streams produced from one source media file
/// (D33): the full `content`, a small `thumbnail`, and a `preview`. All are
/// client-made and carry the same confidentiality as the content — never stored
/// as server plaintext (§13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStreams {
    pub file_type: FileType,
    pub content: Vec<u8>,
    pub thumbnail: Vec<u8>,
    pub preview: Vec<u8>,
}

impl CanonicalStreams {
    /// Map onto the [`PlaintextStreams`] the upload core encrypts, attaching the
    /// caller's encoded `metadata` (title + attributes, §13) if any.
    pub fn into_plaintext_streams(self, metadata: Option<Vec<u8>>) -> PlaintextStreams {
        PlaintextStreams {
            content: self.content,
            metadata,
            thumbnail: Some(self.thumbnail),
            preview: Some(self.preview),
        }
    }
}

/// Transcode source media to the canonical streams before encryption (D30). One
/// impl per media class; the viewer later decodes only the canonical format.
pub trait Transcoder {
    /// Transcode `source` to canonical streams, rejecting anything past `bounds`
    /// **before** allocation. Fail-closed.
    fn transcode(
        &self,
        source: &[u8],
        bounds: &MediaBounds,
    ) -> Result<CanonicalStreams, TranscodeError>;
}

/// The **real** pure-Rust image path (media-sandbox §4): decode png/jpeg under
/// bounds, emit canonical **PNG** content (stream-copied if the source is already
/// PNG), and derive an aspect-preserving thumbnail + preview.
pub struct RustImageCodec;

impl Transcoder for RustImageCodec {
    fn transcode(
        &self,
        source: &[u8],
        bounds: &MediaBounds,
    ) -> Result<CanonicalStreams, TranscodeError> {
        use image::ImageReader;
        use std::io::Cursor;

        if source.is_empty() {
            return Err(TranscodeError::Empty);
        }

        // Read the format + dimensions from the header only (cheap), and reject
        // anything over the caps BEFORE allocating frame buffers — the
        // decompression-bomb guard (media-sandbox §3).
        let reader = ImageReader::new(Cursor::new(source))
            .with_guessed_format()
            .map_err(|_| TranscodeError::DecodeFailed)?;
        let format = reader.format();
        let (w, h) = reader
            .into_dimensions()
            .map_err(|_| TranscodeError::DecodeFailed)?;
        if w > bounds.max_width
            || h > bounds.max_height
            || (w as u64) * (h as u64) > bounds.max_pixels
        {
            return Err(TranscodeError::TooLarge {
                width: w,
                height: h,
            });
        }

        // Decode with the same caps as a defense-in-depth allocation guard.
        let mut decoder = ImageReader::new(Cursor::new(source))
            .with_guessed_format()
            .map_err(|_| TranscodeError::DecodeFailed)?;
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(bounds.max_width);
        limits.max_image_height = Some(bounds.max_height);
        decoder.limits(limits);
        let img = decoder.decode().map_err(|_| TranscodeError::DecodeFailed)?;

        // Canonical content = PNG. An already-PNG source is stream-copied verbatim
        // (no re-encode, no loss — media-sandbox §4); anything else is re-encoded.
        let content = if format == Some(image::ImageFormat::Png) {
            source.to_vec()
        } else {
            encode_png(&img)?
        };

        // Aspect-preserving thumbnail + preview (fast downscale, fit within box).
        let thumbnail = encode_png(&img.thumbnail(THUMBNAIL_MAX_DIM, THUMBNAIL_MAX_DIM))?;
        let preview = encode_png(&img.thumbnail(PREVIEW_MAX_DIM, PREVIEW_MAX_DIM))?;

        Ok(CanonicalStreams {
            file_type: FileType::Image,
            content,
            thumbnail,
            preview,
        })
    }
}

/// Encode a decoded image to canonical PNG bytes.
fn encode_png(img: &image::DynamicImage) -> Result<Vec<u8>, TranscodeError> {
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
        .map_err(|_| TranscodeError::EncodeFailed)?;
    Ok(buf)
}

/// The video path — **deferred**. A real implementation transcodes to the
/// canonical video format (AV1/fMP4) in the sandboxed worker via ffmpeg/dav1d,
/// the system's headline C carve-out; until that is ratified this returns
/// [`TranscodeError::CodecUnavailable`] so the seam is wired end-to-end without
/// pulling C.
pub struct FfmpegVideo;

impl Transcoder for FfmpegVideo {
    fn transcode(
        &self,
        _source: &[u8],
        _bounds: &MediaBounds,
    ) -> Result<CanonicalStreams, TranscodeError> {
        Err(TranscodeError::CodecUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;

    /// Encode a `w`×`h` test image to the given format, as a source the codec
    /// will ingest.
    fn make_image(w: u32, h: u32, fmt: ImageFormat) -> Vec<u8> {
        let mut img = RgbImage::new(w, h);
        for (x, y, px) in img.enumerate_pixels_mut() {
            *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 0]);
        }
        let mut buf = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut buf), fmt)
            .unwrap();
        buf
    }

    fn png_dims(bytes: &[u8]) -> (u32, u32) {
        let img = image::load_from_memory_with_format(bytes, ImageFormat::Png).unwrap();
        (img.width(), img.height())
    }

    #[test]
    fn transcodes_jpeg_to_canonical_png_with_thumbnail_and_preview() {
        let src = make_image(640, 480, ImageFormat::Jpeg);
        let out = RustImageCodec
            .transcode(&src, &MediaBounds::default())
            .unwrap();
        assert_eq!(out.file_type, FileType::Image);
        // content is canonical PNG at the source dimensions.
        assert_eq!(png_dims(&out.content), (640, 480));
        // thumbnail + preview are PNG, downscaled within their bounding boxes.
        let (tw, th) = png_dims(&out.thumbnail);
        assert!(tw <= THUMBNAIL_MAX_DIM && th <= THUMBNAIL_MAX_DIM);
        let (pw, ph) = png_dims(&out.preview);
        assert!(pw <= PREVIEW_MAX_DIM && ph <= PREVIEW_MAX_DIM);
    }

    #[test]
    fn stream_copies_already_canonical_png_content() {
        let src = make_image(64, 64, ImageFormat::Png);
        let out = RustImageCodec
            .transcode(&src, &MediaBounds::default())
            .unwrap();
        // Already canonical → content is the source bytes verbatim (no re-encode).
        assert_eq!(out.content, src);
        // Thumbnail/preview are still derived from the decoded image.
        assert!(!out.thumbnail.is_empty());
        assert!(!out.preview.is_empty());
    }

    #[test]
    fn rejects_oversized_dimensions_before_decode() {
        let src = make_image(64, 64, ImageFormat::Png);
        // Tight bounds the 64x64 image exceeds → rejected on the header dims.
        let bounds = MediaBounds {
            max_width: 16,
            max_height: 16,
            max_pixels: 256,
        };
        assert_eq!(
            RustImageCodec.transcode(&src, &bounds),
            Err(TranscodeError::TooLarge {
                width: 64,
                height: 64
            })
        );
    }

    #[test]
    fn rejects_pixel_bomb_within_dimension_caps() {
        // Each side within the dimension caps, but the pixel product exceeds the
        // bomb guard.
        let src = make_image(64, 64, ImageFormat::Png);
        let bounds = MediaBounds {
            max_width: 100,
            max_height: 100,
            max_pixels: 1000, // 64*64 = 4096 > 1000
        };
        assert_eq!(
            RustImageCodec.transcode(&src, &bounds),
            Err(TranscodeError::TooLarge {
                width: 64,
                height: 64
            })
        );
    }

    #[test]
    fn rejects_empty_and_garbage_input() {
        assert_eq!(
            RustImageCodec.transcode(&[], &MediaBounds::default()),
            Err(TranscodeError::Empty)
        );
        assert_eq!(
            RustImageCodec.transcode(&[0xDE, 0xAD, 0xBE, 0xEF], &MediaBounds::default()),
            Err(TranscodeError::DecodeFailed)
        );
    }

    #[test]
    fn ffmpeg_video_is_deferred() {
        let src = make_image(32, 32, ImageFormat::Png);
        assert_eq!(
            FfmpegVideo.transcode(&src, &MediaBounds::default()),
            Err(TranscodeError::CodecUnavailable)
        );
    }

    #[test]
    fn transcoded_image_flows_through_build_upload_as_four_streams() {
        use crate::identity::Identity;
        use crate::upload::{build_upload, UploadParams};
        use maxsecu_crypto::generate_enc_keypair;
        use maxsecu_encoding::types::{Id, StreamType, Timestamp};

        let src = make_image(320, 240, ImageFormat::Jpeg);
        let out = RustImageCodec
            .transcode(&src, &MediaBounds::default())
            .unwrap();
        let file_type = out.file_type;
        let ps = out.into_plaintext_streams(Some(b"title=holiday".to_vec()));

        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: Id([0x11; 16]),
            owner_key_version: 1,
            file_id: Id([0xF2; 16]),
            file_type, // the authenticated D35 listing key, from the transcoder
            chunk_size: 4096,
            recovery_pub: rpk,
            recovery_mlkem_pub: None,
            created_at: Timestamp(1_719_500_000_000),
        };
        let bundle = build_upload(&params, &ps).expect("media upload builds");

        assert_eq!(bundle.manifest.file_type, FileType::Image);
        // All four streams are present, ascending/unique by type.
        let types: Vec<u8> = bundle
            .manifest
            .streams
            .iter()
            .map(|s| s.stream_type as u8)
            .collect();
        assert_eq!(
            types,
            vec![
                StreamType::Content as u8,
                StreamType::Metadata as u8,
                StreamType::Thumbnail as u8,
                StreamType::Preview as u8,
            ]
        );
    }

    #[test]
    fn canonical_streams_map_to_plaintext_streams() {
        let cs = CanonicalStreams {
            file_type: FileType::Image,
            content: vec![1, 2, 3],
            thumbnail: vec![4],
            preview: vec![5, 6],
        };
        let ps = cs.into_plaintext_streams(Some(vec![9]));
        assert_eq!(ps.content, vec![1, 2, 3]);
        assert_eq!(ps.metadata, Some(vec![9]));
        assert_eq!(ps.thumbnail, Some(vec![4]));
        assert_eq!(ps.preview, Some(vec![5, 6]));
    }
}
