//! Sandboxed media **decode** — the viewer path (DESIGN §8.1/D30, media-sandbox).
//!
//! Viewing shared media runs a decoder on **attacker-authored bytes** (authenticated
//! ≠ benign, D24) — the system's top RCE surface. The defense is to decode in an
//! OS-isolated worker that holds **no keys and no network**, behind hard
//! **pre-decode bounds**, and to treat the worker's **output as untrusted too**
//! (media-sandbox §1).
//!
//! This module is the cross-platform, fully-testable core of that path:
//! * [`SandboxedDecoder`] — the seam: "hand raw canonical bytes to the isolated
//!   worker, get decoded frames back." The real Windows AppContainer worker
//!   implements this in a later increment (`P4b.6b`, `cfg(windows)`); the
//!   [`InProcessFakeDecoder`] here stands in for tests on every platform.
//! * **Pre-decode bounds** — reject oversize dimensions/pixels **before**
//!   allocation (the decompression-bomb guard, media-sandbox §3), reusing
//!   [`MediaBounds`].
//! * [`validate_decoded`] — the **untrusted-output** check: the main process
//!   validates the worker's returned dimensions / channel count / buffer length
//!   for internal consistency and against the caps **before** handing anything to
//!   the renderer (media-sandbox §1). A worker compromise that returns a
//!   malformed frame is caught here.

use crate::media::MediaBounds;

/// A decoded raster frame returned by the (isolated, untrusted) decoder. Held in
/// RAM only (§8.1); validated by [`validate_decoded`] before any renderer use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    /// Samples per pixel — 3 (RGB) or 4 (RGBA).
    pub channels: u8,
    /// Raw interleaved samples; length must equal `width * height * channels`.
    pub pixels: Vec<u8>,
}

/// A sandboxed-decode failure. Fail-closed — nothing reaches the renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Empty input.
    Empty,
    /// The bytes could not be decoded as the canonical format.
    DecodeFailed,
    /// Declared dimensions exceed the caps — rejected **before** allocation.
    TooLarge { width: u32, height: u32 },
    /// The (untrusted) decoder output failed validation before the renderer:
    /// inconsistent dimensions, channel count, or buffer length.
    OutputRejected { reason: OutputReject },
    /// The isolated worker itself failed (spawn/IPC/crash) — surfaced by the real
    /// AppContainer impl; the in-process fake never returns it.
    Worker,
}

/// Why a decoded frame was rejected (media-sandbox §1 output validation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputReject {
    /// `width`/`height`/pixels exceed the configured caps.
    OverCap,
    /// Zero width or height.
    EmptyDims,
    /// `channels` is not 3 or 4.
    BadChannels,
    /// `pixels.len()` != `width * height * channels` — over/under-read risk.
    BufferLenMismatch,
}

/// Validate an **untrusted** decoded frame before the renderer touches it
/// (media-sandbox §1): dimensions within caps, sane channel count, and a buffer
/// whose length exactly matches `width * height * channels`. A `u64` arithmetic
/// avoids overflow on hostile dimensions.
pub fn validate_decoded(img: &DecodedImage, bounds: &MediaBounds) -> Result<(), DecodeError> {
    let reject = |reason| {
        Err(DecodeError::OutputRejected { reason })
    };
    if img.width == 0 || img.height == 0 {
        return reject(OutputReject::EmptyDims);
    }
    if img.channels != 3 && img.channels != 4 {
        return reject(OutputReject::BadChannels);
    }
    let (w, h, c) = (img.width as u64, img.height as u64, img.channels as u64);
    if img.width > bounds.max_width || img.height > bounds.max_height || w * h > bounds.max_pixels {
        return reject(OutputReject::OverCap);
    }
    if (img.pixels.len() as u64) != w * h * c {
        return reject(OutputReject::BufferLenMismatch);
    }
    Ok(())
}

/// Hand raw **canonical** bytes to an isolated decoder and get a decoded frame.
/// Implementors must enforce the pre-decode bounds; the caller still runs
/// [`validate_decoded`] on the result (output is untrusted).
pub trait SandboxedDecoder {
    fn decode_image(
        &self,
        canonical: &[u8],
        bounds: &MediaBounds,
    ) -> Result<DecodedImage, DecodeError>;
}

/// Decode canonical image bytes to an RGBA8 [`DecodedImage`] under the pre-decode
/// bounds (the decompression-bomb guard, media-sandbox §3). Pure Rust (`image`),
/// no keys, no I/O beyond the in-memory buffer — the **exact decode the isolated
/// worker runs**, shared so there is one decoder used both in-process (the fake)
/// and across the process boundary (the `media-worker` bin).
pub fn decode_rgba_bounded(
    canonical: &[u8],
    bounds: &MediaBounds,
) -> Result<DecodedImage, DecodeError> {
    use image::ImageReader;
    use std::io::Cursor;

    if canonical.is_empty() {
        return Err(DecodeError::Empty);
    }
    // Pre-decode bounds: reject oversize on the header dims BEFORE allocating.
    let header = ImageReader::new(Cursor::new(canonical))
        .with_guessed_format()
        .map_err(|_| DecodeError::DecodeFailed)?;
    let (w, h) = header
        .into_dimensions()
        .map_err(|_| DecodeError::DecodeFailed)?;
    if w > bounds.max_width || h > bounds.max_height || (w as u64) * (h as u64) > bounds.max_pixels {
        return Err(DecodeError::TooLarge {
            width: w,
            height: h,
        });
    }
    // Decode with the same caps as an allocation guard, then flatten to RGBA8.
    let mut decoder = ImageReader::new(Cursor::new(canonical))
        .with_guessed_format()
        .map_err(|_| DecodeError::DecodeFailed)?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(bounds.max_width);
    limits.max_image_height = Some(bounds.max_height);
    decoder.limits(limits);
    let img = decoder.decode().map_err(|_| DecodeError::DecodeFailed)?;
    let rgba = img.to_rgba8();
    Ok(DecodedImage {
        width: rgba.width(),
        height: rgba.height(),
        channels: 4,
        pixels: rgba.into_raw(),
    })
}

/// In-process decoder fake (cross-platform) standing in for the real isolated
/// worker in tests: runs [`decode_rgba_bounded`] directly. The **real**
/// AppContainer/Job-Object worker (`media-worker`, P4b.6b) runs the same decode
/// in an OS-isolated process; both feed [`validate_decoded`].
pub struct InProcessFakeDecoder;

impl SandboxedDecoder for InProcessFakeDecoder {
    fn decode_image(
        &self,
        canonical: &[u8],
        bounds: &MediaBounds,
    ) -> Result<DecodedImage, DecodeError> {
        decode_rgba_bounded(canonical, bounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;

    fn make_png(w: u32, h: u32) -> Vec<u8> {
        let mut img = RgbImage::new(w, h);
        for (x, y, px) in img.enumerate_pixels_mut() {
            *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 7]);
        }
        let mut buf = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .unwrap();
        buf
    }

    #[test]
    fn fake_decodes_canonical_png_to_rgba_frame() {
        let png = make_png(48, 32);
        let img = InProcessFakeDecoder
            .decode_image(&png, &MediaBounds::default())
            .unwrap();
        assert_eq!((img.width, img.height), (48, 32));
        assert_eq!(img.channels, 4);
        assert_eq!(img.pixels.len(), 48 * 32 * 4);
        // The decoded frame passes output validation.
        assert!(validate_decoded(&img, &MediaBounds::default()).is_ok());
    }

    #[test]
    fn fake_rejects_oversize_before_decode() {
        let png = make_png(64, 64);
        let bounds = MediaBounds {
            max_width: 16,
            max_height: 16,
            max_pixels: 256,
        };
        assert_eq!(
            InProcessFakeDecoder.decode_image(&png, &bounds),
            Err(DecodeError::TooLarge {
                width: 64,
                height: 64
            })
        );
    }

    #[test]
    fn fake_rejects_empty_and_garbage() {
        assert_eq!(
            InProcessFakeDecoder.decode_image(&[], &MediaBounds::default()),
            Err(DecodeError::Empty)
        );
        assert_eq!(
            InProcessFakeDecoder.decode_image(&[1, 2, 3, 4], &MediaBounds::default()),
            Err(DecodeError::DecodeFailed)
        );
    }

    #[test]
    fn validate_accepts_a_consistent_frame() {
        let img = DecodedImage {
            width: 4,
            height: 3,
            channels: 4,
            pixels: vec![0u8; 4 * 3 * 4],
        };
        assert!(validate_decoded(&img, &MediaBounds::default()).is_ok());
    }

    #[test]
    fn validate_rejects_buffer_length_mismatch() {
        // A hostile/buggy worker claims 4x3x4 but ships too few bytes.
        let img = DecodedImage {
            width: 4,
            height: 3,
            channels: 4,
            pixels: vec![0u8; 10],
        };
        assert_eq!(
            validate_decoded(&img, &MediaBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BufferLenMismatch
            })
        );
    }

    #[test]
    fn validate_rejects_dims_over_cap() {
        let img = DecodedImage {
            width: 100,
            height: 100,
            channels: 4,
            pixels: vec![0u8; 100 * 100 * 4],
        };
        let bounds = MediaBounds {
            max_width: 50,
            max_height: 50,
            max_pixels: 10_000,
        };
        assert_eq!(
            validate_decoded(&img, &bounds),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::OverCap
            })
        );
    }

    #[test]
    fn validate_rejects_bad_channels_and_empty_dims() {
        let bad_ch = DecodedImage {
            width: 2,
            height: 2,
            channels: 2,
            pixels: vec![0u8; 2 * 2 * 2],
        };
        assert_eq!(
            validate_decoded(&bad_ch, &MediaBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BadChannels
            })
        );
        let empty = DecodedImage {
            width: 0,
            height: 5,
            channels: 4,
            pixels: vec![],
        };
        assert_eq!(
            validate_decoded(&empty, &MediaBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::EmptyDims
            })
        );
    }
}
