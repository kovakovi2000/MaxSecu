//! Windows AppContainer + Job Object **containment** tests for the author-side
//! transcode worker (DESIGN §8.1/D30, Phase 7 Gate 6 — the C carve-out). The future
//! `ac-ffmpeg` C decode runs INSIDE this same confinement; these tests prove that
//! (a) the confinement does NOT break the transcode — a confined run still produces a
//! genuinely canonical clip — and (b) the confined worker is DENIED network /
//! child-spawn / key-blob-read, while the SAME worker run unconfined is allowed. So
//! the test proves the confinement bites, not merely that the action happened to fail
//! — even a libav 0-day in the confined transcode worker cannot exfiltrate, shell out,
//! or read the user's keys.
//!
//! Mirrors `media-worker/tests/containment_windows.rs`. The functional proof reuses the
//! Task-6.2 VIEW-path decoders (symphonia demux + rav1d decode) as dev-deps; the rav1d
//! FFI decode is the one `unsafe` site, scoped + justified below (the dav1d C ABI is
//! `pub unsafe extern "C"`). Per CF-2 the rav1d decode runs on a 64 MiB-stack thread.
//!
//! Run ISOLATED single-threaded (`-- --test-threads=1`): the AppContainer profile name
//! is shared with the decode worker, a known parallel-only flake source.
#![cfg(windows)]
#![allow(unsafe_code)]

use std::io::Cursor;
use std::mem::MaybeUninit;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::ptr::NonNull;
use std::sync::Once;
use std::thread;
use std::time::Duration;

use maxsecu_client_core::media::TranscodeRequest;
use maxsecu_client_core::video::VideoBounds;
use maxsecu_media_launcher::TranscodeLauncher;
use maxsecu_media_transcode_worker::{RAW_MAGIC, TRANSCODE_CHUNK_SIZE};

use symphonia::core::codecs::CodecParameters;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::formats::IsoMp4Reader;

const WORKER: &str = env!("CARGO_BIN_EXE_media-transcode-worker");

/// Prime the freshly-built worker exe ONCE before any real confined spawn. On a clean
/// build the FIRST `CreateProcessW` against the just-written binary can hit a
/// COLD-START transient — `ERROR_FILE_NOT_FOUND` (code 2) — while Defender's real-time
/// scan / the AppContainer profile cold-start still holds the new file busy. It fails
/// CLOSED (a failed confined spawn `.expect()`-panics, never a false-ALLOWED), but
/// would otherwise flake this gate single-threaded on a clean build. So before the
/// assertions run we do one confined `--selftest-noop` spawn through the SAME
/// `win32::spawn_confined` path (confinement code untouched), retrying ONLY that
/// specific code-2 transient a few times; once it lands the binary is warm and every
/// later spawn is deterministic. Any OTHER spawn error is surfaced immediately (a real
/// confinement-setup regression is never masked); the noop verdict is discarded.
static WARM: Once = Once::new();
fn warm_up_worker() {
    WARM.call_once(|| {
        let launcher = TranscodeLauncher::new(WORKER);
        for attempt in 0..16 {
            match launcher.selftest(&["--selftest-noop"]) {
                Ok(_) => return, // binary is warm — done.
                Err(e) if e.ctx == "CreateProcessW" && e.code == 2 && attempt < 15 => {
                    // Cold-start ERROR_FILE_NOT_FOUND only — back off briefly and retry.
                    thread::sleep(Duration::from_millis(200));
                }
                Err(e) => panic!("warm-up confined spawn failed unexpectedly: {e}"),
            }
        }
    });
}

// ===========================================================================
// (1) Functional confined: the AppContainer/Job confinement does NOT break the
// transcode — a confined run still produces a genuinely canonical clip.
// ===========================================================================

/// Build a raw-frame source (the worker's documented default-path container) with a
/// deterministic per-frame gradient — same shape as the Task-6.2 test.
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
/// `unsafe` site in this test; every call is justified inline (mirrors the ratified
/// `media-worker` posture and the Task-6.2 pipeline test).
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
fn appcontainer_transcode_still_produces_a_canonical_clip() {
    warm_up_worker();
    let (w, h, frames) = (16u32, 16u32, 3u32);
    // Drive the REAL confined worker (AppContainer + Job Object) end-to-end: framed
    // request in, framed result out, over the confined stdio pipes.
    let out = TranscodeLauncher::new(WORKER)
        .transcode(&req(make_raw_source(w, h, frames, 10)))
        .expect("confined transcode worker should still produce a result");

    assert_eq!(
        out.fragments.len(),
        frames as usize,
        "one fragment per source frame"
    );

    // Each chunk-aligned fragment, sliced straight out of `cmaf` by its index range,
    // must demux + decode back to the source dims — i.e. the confined output is a
    // genuinely canonical clip, confinement did NOT corrupt it.
    for fr in &out.fragments {
        let start = fr.chunk_start as usize * TRANSCODE_CHUNK_SIZE;
        let end = (fr.chunk_start + fr.chunk_len) as usize * TRANSCODE_CHUNK_SIZE;
        let fragment = out.cmaf[start..end].to_vec();

        let (sample, dw, dh) = demux_first_video_sample(fragment);
        assert_eq!((dw, dh), (w, h), "demuxed geometry matches the source");

        let dims = decode_av1_dims(&sample).expect("rav1d decoded the confined fragment");
        assert_eq!(dims, (w, h), "rav1d-decoded dims match the source");
    }
}

// ===========================================================================
// (2) Differential containment: the SAME worker is DENIED net/spawn/read when
// confined, yet allowed when run unconfined — so the confinement is what blocks
// them, not a general inability.
// ===========================================================================

/// Run a worker `--selftest-*` probe WITHOUT confinement (plain child) and return its
/// verdict (`true` = the action SUCCEEDED). The differential against the confined
/// `TranscodeLauncher::selftest` is what proves confinement bites.
fn unconfined_selftest(args: &[&str]) -> bool {
    let out = Command::new(WORKER)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("spawn unconfined worker");
    out.stdout.first().copied() == Some(1)
}

#[test]
fn appcontainer_blocks_network_while_unconfined_allows() {
    warm_up_worker();
    // A loopback listener the worker will try to reach (offline, deterministic).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || loop {
        if listener.accept().is_err() {
            break;
        }
    });
    let ports = port.to_string();
    let args = ["--selftest-net", ports.as_str()];

    // Sanity: the same worker unconfined DOES reach loopback.
    assert!(
        unconfined_selftest(&args),
        "unconfined worker should reach loopback (test sanity)"
    );

    // The containment gate: the AppContainer worker cannot reach the network.
    let confined = TranscodeLauncher::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    assert!(
        !confined,
        "AppContainer transcode worker reached the network — confinement FAILED"
    );
}

#[test]
fn appcontainer_blocks_reading_the_key_blob_while_unconfined_allows() {
    warm_up_worker();
    // A stand-in for the user's `local_key_blob`: a file in the user profile that does
    // not grant access to app packages.
    let mut path = std::env::temp_dir();
    path.push(format!(
        "maxsecu_transcode_secret_{}.bin",
        std::process::id()
    ));
    std::fs::write(&path, b"PRETEND-KEY-MATERIAL").unwrap();
    let p = path.to_string_lossy().to_string();
    let args = ["--selftest-read", p.as_str()];

    let unconfined = unconfined_selftest(&args);
    let confined = TranscodeLauncher::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    let _ = std::fs::remove_file(&path);

    assert!(
        unconfined,
        "unconfined worker can read the user file (test sanity)"
    );
    assert!(
        !confined,
        "AppContainer transcode worker read the user's key blob — confinement FAILED"
    );
}

#[test]
fn appcontainer_blocks_child_spawn_while_unconfined_allows() {
    warm_up_worker();
    let args = ["--selftest-spawn"];

    assert!(
        unconfined_selftest(&args),
        "unconfined worker can spawn a child (test sanity)"
    );

    let confined = TranscodeLauncher::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    assert!(
        !confined,
        "Job Object (active-process=1) must block child spawn"
    );
}
