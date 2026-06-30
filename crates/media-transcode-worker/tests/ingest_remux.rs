//! Integration test for **Task 3.3** — re-mux ffmpeg's output MP4 into the canonical
//! AV1+AAC CMAF fragment layout, then prove the result round-trips through the REAL,
//! unmodified viewer.
//!
//! The flow mirrors production: drive the **vendored** ffmpeg (unconfined, test-only)
//! to produce a genuine `out.mp4` from a tiny synthetic source, feed its bytes to
//! [`transcode`], and assert:
//! * the `cmaf` is whole-`TRANSCODE_CHUNK_SIZE`-aligned and the `fragments` index is
//!   contiguous + pts-monotonic + within the per-fragment cap;
//! * every produced fragment decodes through the existing `media-worker::VideoSession`
//!   (Open → Fragment* → Close) to validated I420 at the source geometry — i.e. the
//!   re-mux is byte-compatible with the tested view path;
//! * the re-muxed audio track (the verbatim ffmpeg `mp4a`/`esds`) demuxes and
//!   AAC-decodes to PCM through symphonia's exact viewer codec stack;
//! * hostile input (garbage / truncated MP4) fails closed, never panicking.
//!
//! Gated: if the vendored ffmpeg is absent the ffmpeg-dependent test prints SKIP and
//! returns. Run single-threaded: `cargo test -p maxsecu-media-transcode-worker
//! --test ingest_remux -- --test-threads=1`.

#[path = "common/mod.rs"]
mod common;

use std::io::Cursor;

use maxsecu_client_core::media::TranscodeRequest;
use maxsecu_client_core::video::{ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_transcode_worker::{transcode, TranscodeError, TRANSCODE_CHUNK_SIZE};
use maxsecu_media_worker::VideoSession;

use symphonia::core::codecs::audio::{AudioDecoder, AudioDecoderOptions};
use symphonia::core::codecs::CodecParameters;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::codecs::AacDecoder;
use symphonia::default::formats::IsoMp4Reader;

const W: u32 = 128;
const H: u32 = 96;

/// Run `f` on a 64 MiB-stack thread (CF-2): rav1d's single-threaded decode inside
/// `VideoSession` overflows Windows' default 1 MiB main-thread stack.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .expect("spawn 64 MiB decode thread")
        .join()
        .expect("decode thread panicked")
}

fn req(source: Vec<u8>) -> TranscodeRequest {
    TranscodeRequest {
        source,
        bounds: VideoBounds::default(),
    }
}

/// Slice each fragment's contiguous chunk range straight out of `cmaf`, exactly as
/// `client-app::chunks_for_fragment` would address it.
fn fragment_slices(out: &maxsecu_client_core::media::TranscodeResult) -> Vec<Vec<u8>> {
    out.fragments
        .iter()
        .map(|fr| {
            let s = fr.chunk_start as usize * TRANSCODE_CHUNK_SIZE;
            let e = (fr.chunk_start + fr.chunk_len) as usize * TRANSCODE_CHUNK_SIZE;
            out.cmaf[s..e].to_vec()
        })
        .collect()
}

/// Demux ONE canonical fragment and AAC-decode its audio track to PCM, returning
/// `(channels, sample_rate, pcm_packet_count)`.
fn decode_fragment_audio(frag: &[u8]) -> (usize, u32, usize) {
    let mss = MediaSourceStream::new(
        Box::new(Cursor::new(frag.to_vec())),
        MediaSourceStreamOptions::default(),
    );
    let mut reader =
        IsoMp4Reader::try_new(mss, FormatOptions::default()).expect("open canonical fragment");
    let atrack = reader
        .first_track(TrackType::Audio)
        .expect("canonical fragment has an audio track");
    let a_id = atrack.id;
    let params = match atrack.codec_params.as_ref() {
        Some(CodecParameters::Audio(a)) => a.clone(),
        other => panic!("expected audio codec params, got {other:?}"),
    };

    let mut decoder =
        AacDecoder::try_new(&params, &AudioDecoderOptions::default()).expect("aac decoder");
    let (mut ch, mut rate, mut pkts) = (0usize, 0u32, 0usize);
    loop {
        match reader.next_packet() {
            Ok(Some(pkt)) if pkt.track_id == a_id => {
                if let Ok(buf) = decoder.decode(&pkt) {
                    ch = buf.spec().channels().count();
                    rate = buf.spec().rate();
                    if buf.frames() > 0 {
                        pkts += 1;
                    }
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => break,
        }
    }
    (ch, rate, pkts)
}

#[test]
fn ffmpeg_output_remuxes_to_canonical_av1_aac_cmaf() {
    // 2 s @ 24 fps with keyint 24 ⇒ ~48 video samples across ~2 closed-GOP fragments.
    let Some(source) = common::make_ffmpeg_source(W, H, 2, 24) else {
        eprintln!(
            "SKIP ffmpeg_output_remuxes_to_canonical_av1_aac_cmaf: vendored ffmpeg.exe not \
             found at <crate>/../../vendor/ffmpeg/ffmpeg.exe"
        );
        return;
    };

    let bounds = VideoBounds::default();
    let out = transcode(&req(source)).expect("transcode re-muxes ffmpeg output");

    // ---- index shape ----
    assert!(!out.fragments.is_empty(), "at least one fragment");
    assert_eq!(
        out.cmaf.len() % TRANSCODE_CHUNK_SIZE,
        0,
        "cmaf chunk-aligned"
    );
    assert!(
        out.thumbnail.is_empty() && out.preview.is_empty(),
        "thumbnail/preview are client-app's job (Task 3.4)"
    );
    assert!(
        out.loudness_gain_db.is_none(),
        "no loudness gain emitted here"
    );

    assert_eq!(out.fragments[0].chunk_start, 0, "starts at chunk 0");
    let mut last_pts = 0u64;
    for (k, fr) in out.fragments.iter().enumerate() {
        assert_eq!(fr.seq, k as u32, "seq is dense 0..N");
        assert!(fr.chunk_len >= 1, "each fragment covers ≥ 1 chunk");
        if k > 0 {
            let prev = &out.fragments[k - 1];
            assert_eq!(
                fr.chunk_start,
                prev.chunk_start + prev.chunk_len,
                "fragments are contiguous"
            );
        }
        assert!(fr.pts_ms >= last_pts, "pts monotonic non-decreasing");
        last_pts = fr.pts_ms;
        let bytes = fr.chunk_len * TRANSCODE_CHUNK_SIZE as u64;
        assert!(
            bytes <= bounds.max_fragment_bytes,
            "fragment within per-fragment cap"
        );
    }
    let last = out.fragments.last().unwrap();
    assert_eq!(
        out.cmaf.len(),
        (last.chunk_start + last.chunk_len) as usize * TRANSCODE_CHUNK_SIZE,
        "cmaf is exactly the concatenation of whole-chunk fragments"
    );

    let frags = fragment_slices(&out);
    let n_frags = frags.len();

    // ---- video round-trip through the REAL, unmodified VideoSession ----
    let video_frags = frags.clone();
    let (frames, eofs) = on_big_stack(move || {
        let mut session = VideoSession::new();
        assert_eq!(
            session.feed(ClientMsg::Open {
                bounds: VideoBounds::default()
            }),
            vec![WorkerMsg::Ready],
            "Open yields Ready"
        );
        let (mut frames, mut eofs) = (0usize, 0usize);
        for (i, frag) in video_frags.iter().enumerate() {
            let msgs = session.feed(ClientMsg::Fragment {
                seq: i as u32,
                bytes: frag.clone(),
            });
            for m in msgs {
                match m {
                    WorkerMsg::Video(f) => {
                        assert_eq!((f.width, f.height), (W, H), "decoded geometry");
                        assert_eq!(f.width % 2, 0, "even width");
                        assert_eq!(f.height % 2, 0, "even height");
                        frames += 1;
                    }
                    WorkerMsg::EndOfFragment { .. } => eofs += 1,
                    WorkerMsg::Error(e) => panic!("VideoSession decode error: {e:?}"),
                    other => panic!("unexpected worker message: {other:?}"),
                }
            }
        }
        assert!(
            session.feed(ClientMsg::Close).is_empty(),
            "Close emits nothing"
        );
        (frames, eofs)
    });

    eprintln!("PASS VideoSession decoded {frames} frame(s) at {W}x{H} across {eofs} fragment(s)");
    assert_eq!(eofs, n_frags, "one EndOfFragment per produced fragment");
    assert!(
        frames >= n_frags && frames >= 2,
        "multi-sample GOP fragments decoded all their frames ({frames} frames, {n_frags} fragments)"
    );

    // ---- audio round-trip: AAC → PCM through symphonia's viewer codec stack ----
    let (ch, rate, pcm_pkts) = decode_fragment_audio(&frags[0]);
    eprintln!("PASS audio AAC->PCM: ch={ch} rate={rate} packets={pcm_pkts}");
    assert_eq!(ch, 2, "stereo (matches -ac 2)");
    assert!(
        (8_000..=48_000).contains(&rate),
        "sane sample rate, got {rate}"
    );
    assert!(pcm_pkts >= 1, "at least one decoded PCM packet");
}

#[test]
fn rejects_hostile_input_without_panic() {
    // Random garbage is not an MP4 → DecodeFailed, never a panic.
    let garbage: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    assert_eq!(
        transcode(&req(garbage)).unwrap_err(),
        TranscodeError::DecodeFailed
    );

    // A truncated MP4 (valid ftyp, then a moov box header claiming far more bytes than
    // are present) must fail closed without OOB-indexing.
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&16u32.to_be_bytes());
    truncated.extend_from_slice(b"ftyp");
    truncated.extend_from_slice(b"av01\0\0\0\0");
    truncated.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // moov size: absurd
    truncated.extend_from_slice(b"moov");
    truncated.extend_from_slice(&[0u8; 8]); // far short of the declared size
    assert_eq!(
        transcode(&req(truncated)).unwrap_err(),
        TranscodeError::DecodeFailed
    );

    // Empty source.
    assert_eq!(transcode(&req(vec![])).unwrap_err(), TranscodeError::Empty);
}
