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
use crate::video::VideoBounds;
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

// ===========================================================================
// Author-side transcode worker wire protocol (Phase 7, Gate 6). The codec-free
// `media-launcher` and the confined `media-transcode-worker` exchange these over a
// ONE-SHOT confined spawn: the launcher writes a framed `TranscodeRequest` to the
// worker's stdin, the worker writes a framed `TranscodeResult` to its stdout. The
// real C ingest (`ac-ffmpeg`) and the pure-Rust rav1e/CMAF mux live ONLY in that
// confined worker; this crate (the TCB) owns just the TYPES + the codec.
//
// As with the `video` duplex proto, the byte-for-byte codec lives in `client-core`
// (C-free) so the launcher and worker agree exactly. Framed, little-endian,
// INJECTIVE (exactly one byte string per value; trailing bytes rejected) and
// bounds-safe (a hostile/truncated/over-declared message yields
// `Err(TranscodeProtoError)`, never a panic or an unbounded allocation). The outer
// `u32` length-prefix that frames each message on the pipe is the transport's job
// (`media-launcher::framing`); these codecs operate on one complete message body.
// ===========================================================================

/// Hard ceiling on any single declared byte-vector length on the transcode wire
/// (source / cmaf / thumbnail / preview). Sized above `VideoBounds::max_total_bytes`
/// (4 GiB) so a legitimate clip fits, while a hostile/corrupt length prefix beyond
/// it is rejected up front rather than driving a multi-GiB take.
pub const MAX_TRANSCODE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Hard ceiling on the declared number of fragment-index entries — a hostile count
/// is rejected before any reservation. Well above `VideoBounds::max_fragments`
/// (4096).
pub const MAX_TRANSCODE_FRAGMENTS: u64 = 1 << 20;

/// One CMAF fragment's seek + storage mapping in the transcode output: the
/// presentation time `pts_ms` and the half-open absolute `content`-chunk range
/// `[chunk_start, chunk_start + chunk_len)` it occupies.
///
/// **Wire/JSON contract.** These field names (`seq`, `pts_ms`, `chunk_start`,
/// `chunk_len`) are serialized verbatim into the upload's authenticated `metadata`
/// JSON, which the player's `client-app::video::parse_fragment_index` reads back.
/// The two live in different crates joined only by that JSON, so the names MUST
/// stay identical here and there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentEntry {
    pub seq: u32,
    pub pts_ms: u64,
    pub chunk_start: u64,
    pub chunk_len: u64,
}

/// Launcher -> worker: the source media bytes + the pre-decode `VideoBounds` the
/// worker must enforce before allocating (the decompression-bomb guard, applied in
/// the confined worker, not the TCB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscodeRequest {
    pub source: Vec<u8>,
    pub bounds: VideoBounds,
}

/// Worker -> launcher: the canonical AV1/CMAF `cmaf` stream, a `thumbnail` +
/// `preview` (PNG, as for images), the `fragments` seek index over `cmaf`, and an
/// optional `loudness_gain_db` normalization gain. All are plaintext-derived and
/// carry the same confidentiality as the content (never server plaintext, §13).
#[derive(Debug, Clone, PartialEq)]
pub struct TranscodeResult {
    pub cmaf: Vec<u8>,
    pub thumbnail: Vec<u8>,
    pub preview: Vec<u8>,
    pub fragments: Vec<FragmentEntry>,
    pub loudness_gain_db: Option<f32>,
}

/// Malformed transcode message on the wire (truncated / trailing / over-ceiling
/// declared length / oversized fragment count / unknown option tag). A unit type:
/// the caller never needs to distinguish *why* the untrusted bytes were rejected,
/// only that they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscodeProtoError;

fn tr_put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn tr_put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn tr_put_bytes(buf: &mut Vec<u8>, v: &[u8]) {
    tr_put_u64(buf, v.len() as u64);
    buf.extend_from_slice(v);
}
fn tr_take_u8(b: &[u8], at: &mut usize) -> Result<u8, TranscodeProtoError> {
    let v = *b.get(*at).ok_or(TranscodeProtoError)?;
    *at += 1;
    Ok(v)
}
fn tr_take_u32(b: &[u8], at: &mut usize) -> Result<u32, TranscodeProtoError> {
    let end = at.checked_add(4).ok_or(TranscodeProtoError)?;
    let slice = b.get(*at..end).ok_or(TranscodeProtoError)?;
    *at = end;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}
fn tr_take_u64(b: &[u8], at: &mut usize) -> Result<u64, TranscodeProtoError> {
    let end = at.checked_add(8).ok_or(TranscodeProtoError)?;
    let slice = b.get(*at..end).ok_or(TranscodeProtoError)?;
    *at = end;
    Ok(u64::from_le_bytes(slice.try_into().unwrap()))
}
/// Read a `u64`-length-prefixed byte vector, rejecting a declared length over
/// [`MAX_TRANSCODE_BYTES`] or one that overruns the buffer (bounds-safe: the
/// `.get()` only ever copies bytes actually present).
fn tr_take_bytes(b: &[u8], at: &mut usize) -> Result<Vec<u8>, TranscodeProtoError> {
    let len = tr_take_u64(b, at)?;
    if len > MAX_TRANSCODE_BYTES {
        return Err(TranscodeProtoError);
    }
    let end = at.checked_add(len as usize).ok_or(TranscodeProtoError)?;
    let slice = b.get(*at..end).ok_or(TranscodeProtoError)?;
    *at = end;
    Ok(slice.to_vec())
}

fn tr_put_bounds(buf: &mut Vec<u8>, b: &VideoBounds) {
    tr_put_u32(buf, b.max_width);
    tr_put_u32(buf, b.max_height);
    tr_put_u64(buf, b.max_pixels);
    tr_put_u64(buf, b.max_duration_ms);
    tr_put_u32(buf, b.max_framerate);
    tr_put_u64(buf, b.max_fragment_bytes);
    tr_put_u64(buf, b.max_total_bytes);
    tr_put_u32(buf, b.max_fragments);
    buf.push(b.max_audio_channels);
    tr_put_u32(buf, b.max_sample_rate);
}
fn tr_take_bounds(b: &[u8], at: &mut usize) -> Result<VideoBounds, TranscodeProtoError> {
    Ok(VideoBounds {
        max_width: tr_take_u32(b, at)?,
        max_height: tr_take_u32(b, at)?,
        max_pixels: tr_take_u64(b, at)?,
        max_duration_ms: tr_take_u64(b, at)?,
        max_framerate: tr_take_u32(b, at)?,
        max_fragment_bytes: tr_take_u64(b, at)?,
        max_total_bytes: tr_take_u64(b, at)?,
        max_fragments: tr_take_u32(b, at)?,
        max_audio_channels: tr_take_u8(b, at)?,
        max_sample_rate: tr_take_u32(b, at)?,
    })
}

fn tr_put_fragment(buf: &mut Vec<u8>, f: &FragmentEntry) {
    tr_put_u32(buf, f.seq);
    tr_put_u64(buf, f.pts_ms);
    tr_put_u64(buf, f.chunk_start);
    tr_put_u64(buf, f.chunk_len);
}
fn tr_take_fragment(b: &[u8], at: &mut usize) -> Result<FragmentEntry, TranscodeProtoError> {
    Ok(FragmentEntry {
        seq: tr_take_u32(b, at)?,
        pts_ms: tr_take_u64(b, at)?,
        chunk_start: tr_take_u64(b, at)?,
        chunk_len: tr_take_u64(b, at)?,
    })
}

/// Serialize a [`TranscodeRequest`] message body (no outer length-prefix).
pub fn encode_transcode_request(req: &TranscodeRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    tr_put_bounds(&mut buf, &req.bounds);
    tr_put_bytes(&mut buf, &req.source);
    buf
}

/// Parse a [`TranscodeRequest`] message body. Rejects truncated, trailing, and
/// over-ceiling-length input with `Err(TranscodeProtoError)` — never panics.
pub fn decode_transcode_request(bytes: &[u8]) -> Result<TranscodeRequest, TranscodeProtoError> {
    let at = &mut 0usize;
    let bounds = tr_take_bounds(bytes, at)?;
    let source = tr_take_bytes(bytes, at)?;
    if *at != bytes.len() {
        return Err(TranscodeProtoError); // trailing data — reject (injective frame)
    }
    Ok(TranscodeRequest { source, bounds })
}

/// Serialize a [`TranscodeResult`] message body (no outer length-prefix).
pub fn encode_transcode_result(res: &TranscodeResult) -> Vec<u8> {
    let mut buf = Vec::new();
    tr_put_bytes(&mut buf, &res.cmaf);
    tr_put_bytes(&mut buf, &res.thumbnail);
    tr_put_bytes(&mut buf, &res.preview);
    tr_put_u64(&mut buf, res.fragments.len() as u64);
    for f in &res.fragments {
        tr_put_fragment(&mut buf, f);
    }
    match res.loudness_gain_db {
        // f32 is carried as its IEEE-754 bits so the round-trip is exact.
        Some(g) => {
            buf.push(1);
            tr_put_u32(&mut buf, g.to_bits());
        }
        None => buf.push(0),
    }
    buf
}

/// Parse a [`TranscodeResult`] message body. Rejects truncated, trailing,
/// over-ceiling-length, oversized-fragment-count, and unknown-option-tag input with
/// `Err(TranscodeProtoError)` — never panics, never over-allocates on a hostile
/// fragment count.
pub fn decode_transcode_result(bytes: &[u8]) -> Result<TranscodeResult, TranscodeProtoError> {
    let at = &mut 0usize;
    let cmaf = tr_take_bytes(bytes, at)?;
    let thumbnail = tr_take_bytes(bytes, at)?;
    let preview = tr_take_bytes(bytes, at)?;
    let count = tr_take_u64(bytes, at)?;
    if count > MAX_TRANSCODE_FRAGMENTS {
        return Err(TranscodeProtoError);
    }
    // `with_capacity` is clamped (allocation guard); the loop still pushes the true
    // `count`, and a count larger than the bytes present fails the take below.
    let mut fragments = Vec::with_capacity((count as usize).min(4096));
    for _ in 0..count {
        fragments.push(tr_take_fragment(bytes, at)?);
    }
    let loudness_gain_db = match tr_take_u8(bytes, at)? {
        0 => None,
        1 => Some(f32::from_bits(tr_take_u32(bytes, at)?)),
        _ => return Err(TranscodeProtoError),
    };
    if *at != bytes.len() {
        return Err(TranscodeProtoError); // trailing data — reject (injective frame)
    }
    Ok(TranscodeResult {
        cmaf,
        thumbnail,
        preview,
        fragments,
        loudness_gain_db,
    })
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

    // ---- transcode worker wire protocol (Gate 6) ----

    fn sample_request() -> TranscodeRequest {
        TranscodeRequest {
            source: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            bounds: VideoBounds::default(),
        }
    }

    fn sample_result() -> TranscodeResult {
        TranscodeResult {
            cmaf: vec![1, 2, 3, 4, 5],
            thumbnail: vec![9, 9],
            preview: vec![7],
            fragments: vec![
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
            ],
            loudness_gain_db: Some(-3.5),
        }
    }

    #[test]
    fn transcode_request_roundtrips() {
        let req = sample_request();
        assert_eq!(
            decode_transcode_request(&encode_transcode_request(&req)).unwrap(),
            req
        );
        // An empty source is a legitimate (degenerate) body.
        let empty = TranscodeRequest {
            source: vec![],
            bounds: VideoBounds::default(),
        };
        assert_eq!(
            decode_transcode_request(&encode_transcode_request(&empty)).unwrap(),
            empty
        );
    }

    #[test]
    fn transcode_result_roundtrips_both_loudness_arms() {
        let res = sample_result();
        assert_eq!(
            decode_transcode_result(&encode_transcode_result(&res)).unwrap(),
            res
        );
        // The `None` loudness arm + an empty fragment list.
        let none = TranscodeResult {
            cmaf: vec![],
            thumbnail: vec![],
            preview: vec![],
            fragments: vec![],
            loudness_gain_db: None,
        };
        assert_eq!(
            decode_transcode_result(&encode_transcode_result(&none)).unwrap(),
            none
        );
    }

    #[test]
    fn transcode_request_rejects_trailing_and_truncated() {
        let wire = encode_transcode_request(&sample_request());
        // Every short prefix must error (never panic).
        for n in 0..wire.len() {
            assert!(
                decode_transcode_request(&wire[..n]).is_err(),
                "prefix len {n} should be rejected"
            );
        }
        // Trailing junk → rejected (injective frame).
        let mut trailing = wire.clone();
        trailing.push(0xFF);
        assert!(decode_transcode_request(&trailing).is_err());
    }

    #[test]
    fn transcode_result_rejects_trailing_and_truncated() {
        let wire = encode_transcode_result(&sample_result());
        for n in 0..wire.len() {
            assert!(
                decode_transcode_result(&wire[..n]).is_err(),
                "prefix len {n} should be rejected"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0x00);
        assert!(decode_transcode_result(&trailing).is_err());
    }

    #[test]
    fn transcode_request_rejects_oversized_source_length() {
        // A hostile declared source length over MAX_TRANSCODE_BYTES is rejected up
        // front, before any take — no multi-GiB allocation.
        let mut wire = Vec::new();
        tr_put_bounds(&mut wire, &VideoBounds::default());
        tr_put_u64(&mut wire, MAX_TRANSCODE_BYTES + 1); // declared len, no payload
        assert!(decode_transcode_request(&wire).is_err());
        // And a plausible-but-overrunning declared length (payload absent) fails the
        // bounds-safe take rather than panicking.
        let mut wire2 = Vec::new();
        tr_put_bounds(&mut wire2, &VideoBounds::default());
        tr_put_u64(&mut wire2, 64); // claims 64 bytes follow; none do
        assert!(decode_transcode_request(&wire2).is_err());
    }

    #[test]
    fn transcode_result_rejects_oversized_fragment_count() {
        // Encode a valid header, then an absurd fragment count with no entries.
        let mut wire = Vec::new();
        tr_put_bytes(&mut wire, &[]); // cmaf
        tr_put_bytes(&mut wire, &[]); // thumbnail
        tr_put_bytes(&mut wire, &[]); // preview
        tr_put_u64(&mut wire, MAX_TRANSCODE_FRAGMENTS + 1);
        assert!(decode_transcode_result(&wire).is_err());
        // A modest-but-impossible count (more entries than bytes can hold) fails the
        // per-entry take without a large reservation.
        let mut wire2 = Vec::new();
        tr_put_bytes(&mut wire2, &[]);
        tr_put_bytes(&mut wire2, &[]);
        tr_put_bytes(&mut wire2, &[]);
        tr_put_u64(&mut wire2, 1000); // claims 1000 fragments; none follow
        assert!(decode_transcode_result(&wire2).is_err());
    }

    #[test]
    fn transcode_result_rejects_unknown_loudness_tag() {
        let mut wire = Vec::new();
        tr_put_bytes(&mut wire, &[]);
        tr_put_bytes(&mut wire, &[]);
        tr_put_bytes(&mut wire, &[]);
        tr_put_u64(&mut wire, 0); // no fragments
        wire.push(0x07); // neither 0 (None) nor 1 (Some) → reject
        assert!(decode_transcode_result(&wire).is_err());
    }
}
