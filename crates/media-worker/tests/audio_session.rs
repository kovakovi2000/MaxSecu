//! Integration test for **Task 5.1** — the confined decode session emits AAC PCM
//! (R1 audio) for canonical A+V fragments.
//!
//! `VideoSession::on_fragment` now demuxes BOTH the video AND the audio track of
//! each self-contained canonical fragment: it AAC-LC-decodes the audio packets to
//! interleaved-i16 PCM and emits `WorkerMsg::Audio(PcmChunk)` (validated) AFTER the
//! fragment's video frames and BEFORE its `EndOfFragment`. This test feeds a REAL
//! A+V canonical fragment (built by re-muxing a vendored-ffmpeg AV1+AAC mp4 through
//! the author-side `transcode`) and asserts both video and audio come out; it also
//! covers a video-only fragment (no Audio) and a hostile-audio fragment (no panic).
//!
//! CF-2: the whole session runs on a 64 MiB-stack thread (rav1d's single-threaded
//! decode overflows Windows' default 1 MiB main-thread stack).
//!
//! Gated: if the vendored ffmpeg is absent the A+V test prints SKIP and returns.
//! Run single-threaded:
//! `cargo test -p maxsecu-media-worker --test audio_session -- --test-threads=1`.

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::Command;

use maxsecu_client_core::media::{TranscodeRequest, TranscodeResult};
use maxsecu_client_core::video::{ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_transcode_worker::{transcode, TRANSCODE_CHUNK_SIZE};
use maxsecu_media_worker::VideoSession;

use support::make_canonical_clip;

const W: u32 = 128;
const H: u32 = 96;

/// Run `f` on a 64 MiB-stack thread (CF-2).
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .expect("spawn 64 MiB decode thread")
        .join()
        .expect("decode thread panicked")
}

/// The vendored ffmpeg pinned by the ratification, relative to this crate's manifest.
fn vendored_ffmpeg() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor/ffmpeg/ffmpeg.exe");
    p.exists().then_some(p)
}

/// Produce a real `out.mp4` (AV1 + AAC-LC, stereo) from a synthetic
/// `testsrc`+`sine` source via the vendored ffmpeg, with the canonical encode
/// flags. `None` if ffmpeg is absent or the encode failed. (Mirrors the
/// media-transcode-worker test-support helper; replicated here so this crate's
/// test target is self-contained.)
fn make_ffmpeg_source(w: u32, h: u32, dur_s: u32, gop: u32) -> Option<Vec<u8>> {
    let ff = vendored_ffmpeg()?;
    let dir = std::env::temp_dir().join(format!(
        "maxsecu_audio_session_test_{}_{w}x{h}_{}",
        std::process::id(),
        gop
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let out = dir.join("out.mp4");
    let _ = std::fs::remove_file(&out);

    let result = Command::new(&ff)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            &format!("testsrc=duration={dur_s}:size={w}x{h}:rate=24"),
            "-f",
            "lavfi",
            "-i",
            &format!("sine=duration={dur_s}"),
            "-shortest",
            "-vf",
            "scale=trunc(iw/2)*2:trunc(ih/2)*2",
            "-pix_fmt",
            "yuv420p",
            "-c:v",
            "libsvtav1",
            "-preset",
            "12",
            "-g",
            &gop.to_string(),
            "-svtav1-params",
            &format!("keyint={gop}:pred-struct=1"),
            "-c:a",
            "aac",
            "-ac",
            "2",
        ])
        .arg(&out)
        .output()
        .ok()?;

    if !result.status.success() {
        eprintln!(
            "vendored ffmpeg encode failed (status {:?}):\n{}",
            result.status.code(),
            String::from_utf8_lossy(&result.stderr)
        );
        return None;
    }
    std::fs::read(&out).ok()
}

/// Slice each fragment's contiguous chunk range straight out of `cmaf`, exactly as
/// `client-app::chunks_for_fragment` would address it.
fn fragment_slices(out: &TranscodeResult) -> Vec<Vec<u8>> {
    out.fragments
        .iter()
        .map(|fr| {
            let s = fr.chunk_start as usize * TRANSCODE_CHUNK_SIZE;
            let e = (fr.chunk_start + fr.chunk_len) as usize * TRANSCODE_CHUNK_SIZE;
            out.cmaf[s..e].to_vec()
        })
        .collect()
}

#[test]
fn av_fragment_emits_video_and_aac_pcm() {
    // 2 s @ 24 fps, keyint 24 ⇒ a couple of closed-GOP A+V fragments.
    let Some(source) = make_ffmpeg_source(W, H, 2, 24) else {
        eprintln!(
            "SKIP av_fragment_emits_video_and_aac_pcm: vendored ffmpeg.exe not found at \
             <crate>/../../vendor/ffmpeg/ffmpeg.exe"
        );
        return;
    };

    let out = transcode(&TranscodeRequest {
        source,
        bounds: VideoBounds::default(),
    })
    .expect("transcode re-muxes ffmpeg output into canonical A+V CMAF");
    let frags = fragment_slices(&out);
    assert!(!frags.is_empty(), "at least one canonical fragment");

    // Feed the FIRST fragment through the real VideoSession on the 64 MiB stack.
    let frag0 = frags[0].clone();
    let (videos, audios, last_is_eof) = on_big_stack(move || {
        let mut session = VideoSession::new();
        assert_eq!(
            session.feed(ClientMsg::Open {
                bounds: VideoBounds::default()
            }),
            vec![WorkerMsg::Ready],
            "Open yields Ready"
        );
        let msgs = session.feed(ClientMsg::Fragment {
            seq: 0,
            bytes: frag0,
        });
        assert!(
            session.feed(ClientMsg::Close).is_empty(),
            "Close emits nothing"
        );

        let mut videos: Vec<(u32, u32)> = Vec::new();
        let mut audios: Vec<(u8, u32, usize, u64)> = Vec::new();
        for m in &msgs {
            match m {
                WorkerMsg::Video(f) => videos.push((f.width, f.height)),
                WorkerMsg::Audio(p) => {
                    audios.push((p.channels, p.sample_rate, p.samples.len(), p.pts_ms))
                }
                WorkerMsg::Error(e) => panic!("unexpected worker error on canonical A+V: {e:?}"),
                WorkerMsg::Ready | WorkerMsg::EndOfFragment { .. } => {}
            }
        }
        let last_is_eof = matches!(msgs.last(), Some(WorkerMsg::EndOfFragment { seq: 0 }));
        (videos, audios, last_is_eof)
    });

    // ---- video ----
    assert!(
        !videos.is_empty(),
        "fragment decodes ≥1 video frame, got {}",
        videos.len()
    );
    for (w, h) in &videos {
        assert_eq!((*w, *h), (W, H), "decoded geometry");
    }

    // ---- audio (the Task 5.1 deliverable) ----
    assert!(
        !audios.is_empty(),
        "fragment AAC-decodes ≥1 PCM chunk, got {}",
        audios.len()
    );
    let mut last_pts = 0u64;
    for (i, (ch, rate, nsamp, pts)) in audios.iter().enumerate() {
        assert_eq!(*ch, 2, "stereo (matches -ac 2)");
        assert!(
            *rate == 44_100 || *rate == 48_000,
            "sane AAC sample rate, got {rate}"
        );
        assert!(*nsamp > 0, "non-empty PCM samples");
        assert_eq!(*nsamp % 2, 0, "interleaved stereo => even sample count");
        if i > 0 {
            assert!(*pts >= last_pts, "audio pts monotonic non-decreasing");
        }
        last_pts = *pts;
    }
    assert!(last_is_eof, "EndOfFragment{{0}} is emitted LAST");

    let total: usize = audios.iter().map(|a| a.2).sum();
    eprintln!(
        "PASS A+V fragment: {} video frame(s) at {W}x{H}; {} PCM chunk(s) \
         ch={} rate={} total_samples={total}",
        videos.len(),
        audios.len(),
        audios[0].0,
        audios[0].1,
    );
}

#[test]
fn video_only_fragment_emits_no_audio() {
    // The pure-Rust canonical-clip fixture is video-only (no audio track).
    let (videos, audios, eofs) = on_big_stack(|| {
        let clip = make_canonical_clip(64, 48, 1, false);
        let mut session = VideoSession::new();
        session.feed(ClientMsg::Open {
            bounds: VideoBounds::default(),
        });
        let msgs = session.feed(ClientMsg::Fragment {
            seq: 0,
            bytes: clip.fragments[0].clone(),
        });
        session.feed(ClientMsg::Close);

        let mut videos = 0usize;
        let mut audios = 0usize;
        let mut eofs = 0usize;
        for m in &msgs {
            match m {
                WorkerMsg::Video(_) => videos += 1,
                WorkerMsg::Audio(_) => audios += 1,
                WorkerMsg::EndOfFragment { .. } => eofs += 1,
                WorkerMsg::Error(e) => panic!("unexpected error on video-only fragment: {e:?}"),
                WorkerMsg::Ready => {}
            }
        }
        (videos, audios, eofs)
    });

    assert_eq!(videos, 1, "video-only fragment still decodes its video frame");
    assert_eq!(audios, 0, "no audio track => no Audio messages");
    assert_eq!(eofs, 1, "one EndOfFragment");
}

#[test]
fn hostile_audio_fails_closed_without_panic() {
    // (a) pure garbage within the byte cap: not an MP4 at all -> the session must
    //     terminate (video path Errors, audio path emits nothing), never panic,
    //     and still close with EndOfFragment.
    let garbage: Vec<u8> = (0..8192u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let last_is_eof = on_big_stack(move || {
        let mut session = VideoSession::new();
        session.feed(ClientMsg::Open {
            bounds: VideoBounds::default(),
        });
        let msgs = session.feed(ClientMsg::Fragment {
            seq: 7,
            bytes: garbage,
        });
        session.feed(ClientMsg::Close);
        matches!(msgs.last(), Some(WorkerMsg::EndOfFragment { seq: 7 }))
    });
    assert!(last_is_eof, "garbage fragment still closes with EndOfFragment");

    // (b) a REAL A+V fragment with its trailing (sample-data) bytes corrupted: the
    //     audio AAC decode of hostile bytes must fail closed (Error or simply no
    //     Audio) and NEVER panic; the fragment still closes with EndOfFragment.
    let Some(source) = make_ffmpeg_source(W, H, 1, 24) else {
        eprintln!("SKIP hostile_audio (corrupt-sample case): vendored ffmpeg.exe not found");
        return;
    };
    let out = transcode(&TranscodeRequest {
        source,
        bounds: VideoBounds::default(),
    })
    .expect("transcode");
    let mut frag = fragment_slices(&out).remove(0);
    // Corrupt the back half (where mdat sample bytes live) so the demuxer's box
    // structure is likely intact but the AAC packet bytes are hostile.
    let start = frag.len() / 2;
    for b in &mut frag[start..] {
        *b ^= 0xA5;
    }
    let last_is_eof = on_big_stack(move || {
        let mut session = VideoSession::new();
        session.feed(ClientMsg::Open {
            bounds: VideoBounds::default(),
        });
        let msgs = session.feed(ClientMsg::Fragment { seq: 3, bytes: frag });
        session.feed(ClientMsg::Close);
        // We do NOT over-assert video/audio outcome (corruption may hit either);
        // the security contract is: no panic, terminates, and closes cleanly.
        matches!(msgs.last(), Some(WorkerMsg::EndOfFragment { seq: 3 }))
    });
    assert!(
        last_is_eof,
        "corrupted-audio fragment fails closed and still closes with EndOfFragment"
    );
    eprintln!("PASS hostile-audio: no panic; both cases closed with EndOfFragment");
}
