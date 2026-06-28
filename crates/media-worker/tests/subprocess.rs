//! End-to-end tests for the cross-platform [`SubprocessDecoder`] over the real
//! worker binary (process isolation + the one-shot wire protocol). The decoded
//! frame must match the in-process decode exactly.

use image::{DynamicImage, ImageFormat, RgbImage};
use maxsecu_client_core::media::MediaBounds;
use maxsecu_client_core::sandbox::{
    decode_rgba_bounded, DecodeError, InProcessFakeDecoder, SandboxedDecoder,
};
use maxsecu_media_worker::SubprocessDecoder;
use std::io::Cursor;

/// Absolute path to the built worker binary (cargo provides this for the bin
/// target named `media-worker`).
const WORKER: &str = env!("CARGO_BIN_EXE_media-worker");

fn make_png(w: u32, h: u32) -> Vec<u8> {
    let mut img = RgbImage::new(w, h);
    for (x, y, px) in img.enumerate_pixels_mut() {
        *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 11]);
    }
    let mut buf = Vec::new();
    DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

#[test]
fn subprocess_decode_matches_in_process() {
    let png = make_png(50, 40);
    let bounds = MediaBounds::default();

    let via_worker = SubprocessDecoder::new(WORKER)
        .decode_image(&png, &bounds)
        .expect("worker decodes");
    // Byte-for-byte identical to decoding in this process.
    let in_proc = decode_rgba_bounded(&png, &bounds).unwrap();
    assert_eq!(via_worker, in_proc);
    // And to the in-process fake (same trait).
    assert_eq!(
        via_worker,
        InProcessFakeDecoder.decode_image(&png, &bounds).unwrap()
    );
}

#[test]
fn subprocess_rejects_oversize_before_decode() {
    let png = make_png(64, 64);
    let bounds = MediaBounds {
        max_width: 16,
        max_height: 16,
        max_pixels: 256,
    };
    assert_eq!(
        SubprocessDecoder::new(WORKER).decode_image(&png, &bounds),
        Err(DecodeError::TooLarge {
            width: 64,
            height: 64
        })
    );
}

#[test]
fn subprocess_rejects_garbage_and_empty() {
    let dec = SubprocessDecoder::new(WORKER);
    assert_eq!(
        dec.decode_image(&[0xDE, 0xAD, 0xBE, 0xEF], &MediaBounds::default()),
        Err(DecodeError::DecodeFailed)
    );
    assert_eq!(
        dec.decode_image(&[], &MediaBounds::default()),
        Err(DecodeError::Empty)
    );
}

#[test]
fn missing_worker_binary_is_a_worker_error() {
    let dec = SubprocessDecoder::new("definitely-not-a-real-worker-binary-xyz");
    assert_eq!(
        dec.decode_image(&make_png(8, 8), &MediaBounds::default()),
        Err(DecodeError::Worker)
    );
}
