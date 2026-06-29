//! Gate-6 verification: prove the pure-Rust transcode output is **genuinely
//! canonical** — each chunk-aligned CMAF fragment, sliced straight out of the `cmaf`
//! stream by its index range, demuxes (symphonia) and decodes (rav1d) back to the
//! source dimensions, and the thumbnail/preview are valid in-bounds PNGs.
//!
//! These tests use the VIEW-path decoders (rav1d/symphonia) + `image` as **dev-deps**
//! (they never enter the worker's shipped graph). The rav1d FFI decode is the one
//! `unsafe` site — scoped + justified, mirroring `media-worker/tests/support`. Per
//! CF-2, the rav1d decode runs on a 64 MiB-stack worker thread.
//!
//! The package-level lint denies `unsafe_code`; the dav1d C ABI is `pub unsafe extern
//! "C"`, so this test target re-allows it crate-wide and contains every FFI call to
//! the single justified helper below.
#![allow(unsafe_code)]

use std::io::Cursor;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

use maxsecu_client_core::media::TranscodeRequest;
use maxsecu_client_core::video::VideoBounds;
use maxsecu_media_transcode_worker::{transcode, RAW_MAGIC, TRANSCODE_CHUNK_SIZE};

use symphonia::core::codecs::CodecParameters;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::formats::IsoMp4Reader;

/// Build a raw-frame source (the worker's documented default-path container) with a
/// deterministic per-frame gradient.
fn make_raw_source(w: u32, h: u32, frames: u32, fps: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(RAW_MAGIC);
    v.extend_from_slice(&w.to_le_bytes());
    v.extend_from_slice(&h.to_le_bytes());
    v.extend_from_slice(&frames.to_le_bytes());
    v.extend_from_slice(&fps.to_le_bytes());
    for f in 0..frames {
        for i in 0..(w * h) {
            v.push(((i + f) & 0xff) as u8);
            v.push(((i / w) & 0xff) as u8);
            v.push((f.wrapping_mul(40) & 0xff) as u8);
        }
    }
    v
}

fn req(source: Vec<u8>) -> TranscodeRequest {
    TranscodeRequest {
        source,
        bounds: VideoBounds::default(),
    }
}

/// Demux the first video sample (+ its `av01` geometry) out of one fragment MP4.
fn demux_first_video_sample(mp4: Vec<u8>) -> (Vec<u8>, u32, u32) {
    let mss = MediaSourceStream::new(
        Box::new(Cursor::new(mp4)),
        MediaSourceStreamOptions::default(),
    );
    let mut reader = IsoMp4Reader::try_new(mss, FormatOptions::default())
        .expect("symphonia: failed to open the (padded) fragment MP4");

    let track = reader
        .first_track(TrackType::Video)
        .expect("symphonia: no video track found");
    let track_id = track.id;

    let (w, h) = match track.codec_params.as_ref() {
        Some(CodecParameters::Video(v)) => (
            u32::from(v.width.expect("symphonia: no width")),
            u32::from(v.height.expect("symphonia: no height")),
        ),
        other => panic!("symphonia: expected video codec params, got {other:?}"),
    };

    loop {
        match reader.next_packet().expect("symphonia: next_packet") {
            Some(pkt) if pkt.track_id == track_id => return (pkt.data.into_vec(), w, h),
            Some(_) => continue,
            None => panic!("symphonia: no packets for the video track"),
        }
    }
}

/// Decode one AV1 sample and return its picture geometry, on a 64 MiB-stack worker
/// thread (CF-2: rav1d's deep single-threaded decode overflows the default stack).
fn decode_av1_dims(bitstream: &[u8]) -> Option<(u32, u32)> {
    let owned = bitstream.to_vec();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || decode_av1_dims_ffi(&owned))
        .expect("spawn enlarged-stack decode thread")
        .join()
        .expect("rav1d decode thread panicked")
}

/// rav1d FFI decode of one still AV1 sample, single-threaded, minimal delay. The one
/// `unsafe` site in this crate's tests; every call is justified inline (mirrors the
/// ratified `media-worker` posture).
fn decode_av1_dims_ffi(bitstream: &[u8]) -> Option<(u32, u32)> {
    use rav1d::include::dav1d::data::Dav1dData;
    use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
    use rav1d::include::dav1d::picture::Dav1dPicture;
    use rav1d::src::lib::{
        dav1d_close, dav1d_data_create, dav1d_data_unref, dav1d_default_settings,
        dav1d_get_picture, dav1d_open, dav1d_picture_unref, dav1d_send_data,
    };

    // SAFETY: every dav1d FFI call below is given valid, correctly-typed,
    // non-aliasing pointers to live stack storage; results are checked before any
    // output is read. The sequence is the dav1d-documented single-still lifecycle:
    // open -> (send_data/get_picture)* -> unref -> close.
    unsafe {
        // SAFETY: uninitialized settings storage fully initialized through the
        // non-null ptr by dav1d_default_settings.
        let mut settings = MaybeUninit::<Dav1dSettings>::uninit();
        dav1d_default_settings(NonNull::new(settings.as_mut_ptr()).unwrap());
        let mut settings = settings.assume_init();
        settings.n_threads = 1;
        settings.max_frame_delay = 1;

        // SAFETY: &mut ctx receives the opened handle; &mut settings is fully init'd.
        let mut ctx: Option<Dav1dContext> = None;
        let res = dav1d_open(
            Some(NonNull::from(&mut ctx)),
            Some(NonNull::from(&mut settings)),
        );
        if res.0 != 0 {
            return None;
        }
        let handle = ctx.expect("dav1d_open returned a null context");

        // SAFETY: data is uninitialized Dav1dData; dav1d_data_create initializes it
        // and returns a writable buffer of exactly bitstream.len() bytes.
        let mut data = MaybeUninit::<Dav1dData>::uninit();
        let buf = dav1d_data_create(
            Some(NonNull::new(data.as_mut_ptr()).unwrap()),
            bitstream.len(),
        );
        if buf.is_null() {
            dav1d_close(Some(NonNull::from(&mut ctx)));
            return None;
        }
        std::ptr::copy_nonoverlapping(bitstream.as_ptr(), buf, bitstream.len());
        let mut data = data.assume_init();

        const DAV1D_ERR_AGAIN: i32 = -11; // -EAGAIN (11 on every target this builds for)

        let mut result = None;
        for _ in 0..64 {
            if data.sz > 0 {
                // SAFETY: handle is live; &mut data is initialized. On success dav1d
                // takes the bytes; on -EAGAIN it keeps our ref for a retry.
                let sr = dav1d_send_data(Some(handle), Some(NonNull::from(&mut data)));
                if sr.0 != 0 && sr.0 != DAV1D_ERR_AGAIN {
                    break;
                }
            }
            // SAFETY: pic is uninitialized; on a 0 result dav1d fully initializes it
            // and we own a ref to release.
            let mut pic = MaybeUninit::<Dav1dPicture>::uninit();
            let r = dav1d_get_picture(Some(handle), Some(NonNull::new(pic.as_mut_ptr()).unwrap()));
            if r.0 == 0 {
                let mut pic = pic.assume_init();
                let dims = (pic.p.w.max(0) as u32, pic.p.h.max(0) as u32);
                // SAFETY: live dav1d-initialized picture we own; release exactly once.
                dav1d_picture_unref(Some(NonNull::from(&mut pic)));
                result = Some(dims);
                break;
            }
        }

        // SAFETY: data is a valid initialized local; release our ref unconditionally
        // (send_data only empties it on success). dav1d_data_unref is idempotent.
        dav1d_data_unref(Some(NonNull::from(&mut data)));
        // SAFETY: &mut ctx still holds the live handle; close exactly once.
        dav1d_close(Some(NonNull::from(&mut ctx)));
        result
    }
}

#[test]
fn each_chunk_aligned_fragment_demuxes_and_decodes_to_source_dims() {
    let (w, h, frames) = (16u32, 16u32, 3u32);
    let out = transcode(&req(make_raw_source(w, h, frames, 10))).expect("transcodes");

    assert_eq!(
        out.fragments.len(),
        frames as usize,
        "one fragment per source frame"
    );

    for fr in &out.fragments {
        // Slice the fragment's contiguous chunk range straight out of `cmaf` exactly
        // as client-app::chunks_for_fragment would address it.
        let start = fr.chunk_start as usize * TRANSCODE_CHUNK_SIZE;
        let end = (fr.chunk_start + fr.chunk_len) as usize * TRANSCODE_CHUNK_SIZE;
        let fragment = out.cmaf[start..end].to_vec();

        // Demux the (padded) fragment — proves the trailing `free` box is tolerated —
        // and confirm the sample-entry geometry.
        let (sample, dw, dh) = demux_first_video_sample(fragment);
        assert_eq!((dw, dh), (w, h), "demuxed geometry matches the source");

        // Decode the av01 sample back to its picture dimensions (on the 64 MiB stack).
        let dims = decode_av1_dims(&sample).expect("rav1d decoded the fragment sample");
        assert_eq!(dims, (w, h), "rav1d-decoded dims match the source");
    }
}

#[test]
fn thumbnail_and_preview_are_valid_pngs_within_bounds() {
    let out = transcode(&req(make_raw_source(40, 24, 2, 12))).expect("transcodes");

    let thumb = image::load_from_memory_with_format(&out.thumbnail, image::ImageFormat::Png)
        .expect("thumbnail is a valid PNG");
    assert!(
        thumb.width() <= 256 && thumb.height() <= 256,
        "thumb in box"
    );
    assert!(thumb.width() > 0 && thumb.height() > 0);

    let preview = image::load_from_memory_with_format(&out.preview, image::ImageFormat::Png)
        .expect("preview is a valid PNG");
    assert!(
        preview.width() <= 1024 && preview.height() <= 1024,
        "preview in box"
    );
    assert!(preview.width() > 0 && preview.height() > 0);
}
