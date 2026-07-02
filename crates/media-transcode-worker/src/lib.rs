//! Author-side ingest/transcode **worker** library (Universal Video Ingest, Task 3.3;
//! DESIGN §8.1/D30).
//!
//! This worker is the **re-mux stage** of the author-side video pipeline. It runs in
//! its own confined address space (spawned one-shot by
//! `media-launcher::TranscodeLauncher`), holds **no keys**, opens **no sockets**, and —
//! unlike its earlier form — links and runs **no codec** at all. The arbitrary-format
//! decode + AV1/AAC encode happen UPSTREAM, in a separate confined `ffmpeg.exe` spawned
//! by `client-app`; this worker only takes ffmpeg's standard output MP4 and re-packages
//! it into the canonical on-wire layout the viewer expects.
//!
//! # What `transcode` does (Fork X — see the ratification, §3/§4)
//! `req.source` is **ffmpeg's output `out.mp4`** (one AV1 video track + one AAC-LC
//! audio track, produced by the pinned argv in `media-launcher::ffmpeg_args`). The
//! worker:
//! 1. **symphonia-demuxes** that MP4 into ordered AV1 video samples + AAC audio frames
//!    (DEMUX ONLY — no decode, so no codec RCE surface is linked here);
//! 2. groups the video samples into **closed GOPs** at keyframe boundaries (read from
//!    the source's `stss` sync-sample table — see [`remux::parse_tables`]);
//! 3. **re-muxes** each GOP (plus the AAC frames whose presentation time falls inside
//!    it) into one **self-contained, chunk-aligned MP4 fragment** — extending the
//!    hand-rolled muxer to a multi-sample video `trak` + an audio `trak` whose
//!    `mp4a`/`esds` SampleEntry is **copied byte-for-byte from ffmpeg's output** (no
//!    hand-authored AudioSpecificConfig; ratification §4/§5);
//! 4. pads each fragment with a trailing `free` box to a whole [`TRANSCODE_CHUNK_SIZE`]
//!    multiple and records its contiguous chunk range in the [`FragmentEntry`] index.
//!
//! The produced fragments are byte-compatible with the existing, tested viewer
//! (`media-worker::VideoSession`) and `client-app`'s fragment index — the spike proved
//! the unmodified `VideoSession` decodes them and symphonia's `aac` decoder reads the
//! re-muxed audio track.
//!
//! # Thumbnails are NOT produced here
//! The thumbnail/preview come from ffmpeg's first-frame `thumb.png` and are derived in
//! `client-app` (Task 3.4) via `client-core::RustImageCodec`. So [`transcode`] returns
//! an **empty** `thumbnail`/`preview` (and `loudness_gain_db: None`); client-app fills
//! them. This keeps the codec-free worker free of any image-encode code too.
//!
//! # Trust boundary (the dedicated security review checks this)
//! `req.source` is **attacker-derived** (ffmpeg's output of the author's arbitrary
//! input). ALL parsing — both symphonia's demux and the two tiny hand-rolled box
//! readers in [`remux`] — is **bounds-safe and fail-closed**: it never panics, never
//! indexes out of bounds, and never allocates from an unchecked declared length. Every
//! [`VideoBounds`] cap (dimensions, fragment/total bytes, fragment count, audio
//! channels/rate, duration, packet count) is enforced **before** the corresponding
//! allocation. There is **no `unsafe`** in this crate (symphonia is pure-Rust; the mux
//! is plain byte-pushing). A malformed/oversized source yields `Err(TranscodeError)`,
//! which the worker `main` maps to a non-zero exit and `client-app` to the sanitized
//! `video_failed`.

use std::io::Cursor;

use maxsecu_client_core::media::{FragmentEntry, TranscodeRequest, TranscodeResult};
use maxsecu_client_core::video::VideoBounds;

use symphonia::core::codecs::CodecParameters;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::formats::IsoMp4Reader;

mod remux;

/// The upload chunk size the fragment layout aligns to. Each closed-GOP CMAF
/// fragment occupies a whole multiple of this many bytes inside `cmaf`, so a
/// fragment maps to a contiguous absolute chunk range.
///
/// **This MUST match the upload pipeline's `chunk_size`** (the Phase-4
/// `UploadParams::chunk_size`, **4096**). If the upload chunk size ever changes, this
/// constant must change with it, or `client-app::chunks_for_fragment` will resolve a
/// fragment to the wrong byte range.
pub const TRANSCODE_CHUNK_SIZE: usize = 4096;

/// A transcode failure inside the worker. Carries no secrets; fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscodeError {
    /// Empty source — nothing to ingest.
    Empty,
    /// The source could not be demuxed as ffmpeg's AV1/AAC MP4 (not an MP4, no video
    /// track, missing geometry/timebase, or a missing audio SampleEntry for a present
    /// audio track). Covers all malformed/hostile inputs — bounds-safe, never a panic.
    DecodeFailed,
    /// The source exceeds a pre-build [`VideoBounds`] cap (dimensions, duration,
    /// packet/fragment count, per-fragment or total bytes, audio channels/rate) —
    /// rejected before the corresponding allocation (the decompression-bomb guard).
    TooLarge,
    /// The hand-rolled CMAF re-mux failed (e.g. an empty GOP) — surfaced rather than
    /// silently producing a bad stream.
    MuxFailed,
}

impl std::fmt::Display for TranscodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranscodeError::Empty => write!(f, "empty source media"),
            TranscodeError::DecodeFailed => write!(f, "source media could not be demuxed"),
            TranscodeError::TooLarge => write!(f, "source media exceeds the ingest caps"),
            TranscodeError::MuxFailed => write!(f, "canonical re-mux failed"),
        }
    }
}

impl std::error::Error for TranscodeError {}

/// The audio side of the demuxed source: ordered AAC frames + their presentation times
/// (ns) and the track's sample rate / channel count.
struct DemuxedAudio {
    sample_rate: u32,
    samples: Vec<Vec<u8>>,
    sample_ns: Vec<i128>,
}

/// The demuxed-but-not-yet-regrouped source: ordered AV1 video samples + per-sample
/// presentation times (ns), the source geometry, and the optional audio track.
struct Demuxed {
    width: u32,
    height: u32,
    video_samples: Vec<Vec<u8>>,
    video_ns: Vec<i128>,
    audio: Option<DemuxedAudio>,
}

/// Presentation time of a packet in nanoseconds, from its (timebase-relative) pts.
/// A negative pts (encoder delay) is clamped to 0; `den` is the timebase denominator
/// (always ≥ 1 — symphonia stores it as `NonZero`).
fn ns_of(pts: i64, num: u32, den: u32) -> i128 {
    (pts.max(0) as i128) * (num as i128) * 1_000_000_000 / (den.max(1) as i128)
}

/// REAL per-sample presentation durations (in ms — the canonical video media
/// timescale 1000) for one closed GOP, from its consecutive source frame pts
/// (`gop_ns`, fragment-relative pts in nanoseconds of each sample in decode order).
///
/// Within the self-contained fragment the per-sample pts start at 0, so durations are
/// derived from the *differences* of fragment-relative ms pts (telescoping ⇒ the sum
/// equals the last sample's relative pts plus the final sample's duration, with no
/// accumulating rounding drift). The LAST sample's duration is the previous delta (it
/// has no successor); a single-sample GOP gets a nominal 1 ms (matching the historical
/// one-frame-per-fragment layout).
///
/// Bounds-/overflow-safe on hostile pts (the input is attacker-derived): all math is in
/// `i128`; a NON-MONOTONIC pts is clamped to its predecessor (so a delta is never
/// negative); each delta is floored at 1 ms (no zero-duration sample) and a huge delta
/// saturates to `u32::MAX`. Never panics. Returns one duration per input sample.
fn frame_durations_ms(gop_ns: &[i128]) -> Vec<u32> {
    let n = gop_ns.len();
    if n == 0 {
        return Vec::new();
    }
    let base = gop_ns[0];
    // Fragment-relative ms pts, clamped non-negative AND monotonic non-decreasing
    // (a hostile out-of-order pts is pinned to its predecessor rather than producing a
    // negative duration).
    let mut rel_ms: Vec<i128> = Vec::with_capacity(n);
    let mut prev = 0i128;
    for &ns in gop_ns {
        let mut ms = (ns - base) / 1_000_000;
        if ms < 0 {
            ms = 0;
        }
        if ms < prev {
            ms = prev;
        }
        rel_ms.push(ms);
        prev = ms;
    }
    let mut durs: Vec<u32> = Vec::with_capacity(n);
    for w in rel_ms.windows(2) {
        let d = (w[1] - w[0]).max(1); // floor at 1 ms; never negative (monotonic above).
        durs.push(u32::try_from(d).unwrap_or(u32::MAX));
    }
    // The last sample has no successor: reuse the previous delta, else a nominal 1 ms.
    let last = durs.last().copied().unwrap_or(1);
    durs.push(last);
    durs
}

/// symphonia-demux ffmpeg's output MP4 into ordered video + audio samples, enforcing
/// the magnitude caps that bound subsequent allocation **before** building anything.
/// Bounds-safe and fail-closed on any malformed/hostile input (returns `Err`, never
/// panics, never reads out of bounds).
fn demux_source(src: &[u8], bounds: &VideoBounds) -> Result<Demuxed, TranscodeError> {
    let mss = MediaSourceStream::new(
        Box::new(Cursor::new(src.to_vec())),
        MediaSourceStreamOptions::default(),
    );
    let mut reader = IsoMp4Reader::try_new(mss, FormatOptions::default())
        .map_err(|_| TranscodeError::DecodeFailed)?;

    // --- video track: id, geometry, timebase (extracted before the packet loop so no
    // immutable track borrow is held across the &mut next_packet calls) ---
    let vtrack = reader
        .first_track(TrackType::Video)
        .ok_or(TranscodeError::DecodeFailed)?;
    let v_id = vtrack.id;
    let (width, height) = match vtrack.codec_params.as_ref() {
        Some(CodecParameters::Video(v)) => (
            u32::from(v.width.ok_or(TranscodeError::DecodeFailed)?),
            u32::from(v.height.ok_or(TranscodeError::DecodeFailed)?),
        ),
        _ => return Err(TranscodeError::DecodeFailed),
    };
    let v_tb = vtrack.time_base.ok_or(TranscodeError::DecodeFailed)?;
    let (v_num, v_den) = (v_tb.numer.get(), v_tb.denom.get());

    // --- audio track (optional): id, timebase, rate, channels ---
    let audio_meta = match reader.first_track(TrackType::Audio) {
        Some(t) => {
            let a_id = t.id;
            let a_tb = t.time_base.ok_or(TranscodeError::DecodeFailed)?;
            let (rate, channels) = match t.codec_params.as_ref() {
                Some(CodecParameters::Audio(a)) => (
                    a.sample_rate.ok_or(TranscodeError::DecodeFailed)?,
                    a.channels.as_ref().map(|c| c.count()).unwrap_or(0),
                ),
                _ => return Err(TranscodeError::DecodeFailed),
            };
            Some((a_id, a_tb.numer.get(), a_tb.denom.get(), rate, channels))
        }
        None => None,
    };

    // Packet-count ceilings derived from the caps: bound the per-packet allocations so a
    // pathological sample table (millions of tiny/empty samples) can't exhaust memory.
    let secs = bounds.max_duration_ms / 1000 + 2;
    let max_video_pkts = secs.saturating_mul(bounds.max_framerate as u64);
    let max_audio_pkts = secs.saturating_mul(bounds.max_sample_rate as u64) / 1024 + 16;

    let mut video_samples: Vec<Vec<u8>> = Vec::new();
    let mut video_ns: Vec<i128> = Vec::new();
    let mut audio_samples: Vec<Vec<u8>> = Vec::new();
    let mut audio_ns: Vec<i128> = Vec::new();

    loop {
        match reader.next_packet() {
            Ok(Some(pkt)) => {
                if pkt.track_id == v_id {
                    if video_samples.len() as u64 >= max_video_pkts {
                        return Err(TranscodeError::TooLarge);
                    }
                    video_ns.push(ns_of(pkt.pts.get(), v_num, v_den));
                    video_samples.push(pkt.data.into_vec());
                } else if let Some((a_id, a_num, a_den, _, _)) = audio_meta {
                    if pkt.track_id == a_id {
                        if audio_samples.len() as u64 >= max_audio_pkts {
                            return Err(TranscodeError::TooLarge);
                        }
                        audio_ns.push(ns_of(pkt.pts.get(), a_num, a_den));
                        audio_samples.push(pkt.data.into_vec());
                    }
                }
                // packets of any other track are ignored.
            }
            Ok(None) => break, // clean end of stream.
            Err(_) => break,   // truncated/EOF — re-mux what was demuxed cleanly.
        }
    }

    if video_samples.is_empty() {
        return Err(TranscodeError::DecodeFailed);
    }

    // --- magnitude caps (before any fragment is built/allocated) ---
    let (w64, h64) = (width as u64, height as u64);
    if width > bounds.max_width || height > bounds.max_height || w64 * h64 > bounds.max_pixels {
        return Err(TranscodeError::TooLarge);
    }
    let duration_ms = (video_ns.last().copied().unwrap_or(0) / 1_000_000).max(0) as u64;
    if duration_ms > bounds.max_duration_ms {
        return Err(TranscodeError::TooLarge);
    }

    let audio = match audio_meta {
        Some((_, _, _, rate, channels)) if !audio_samples.is_empty() => {
            if channels == 0 || channels as u64 > bounds.max_audio_channels as u64 {
                return Err(TranscodeError::TooLarge);
            }
            if rate == 0 || rate > bounds.max_sample_rate {
                return Err(TranscodeError::TooLarge);
            }
            Some(DemuxedAudio {
                sample_rate: rate,
                samples: audio_samples,
                sample_ns: audio_ns,
            })
        }
        _ => None,
    };

    Ok(Demuxed {
        width,
        height,
        video_samples,
        video_ns,
        audio,
    })
}

/// Re-mux one ffmpeg output MP4 (`req.source`) into the canonical [`TranscodeResult`]:
/// a chunk-aligned AV1/AAC CMAF stream + a contiguous [`FragmentEntry`] seek index.
///
/// `thumbnail`/`preview` are returned **empty** and `loudness_gain_db` is `None` —
/// client-app derives the thumbnail from ffmpeg's `thumb.png` (Task 3.4). Fail-closed
/// on a malformed or over-bounds source.
pub fn transcode(req: &TranscodeRequest) -> Result<TranscodeResult, TranscodeError> {
    if req.source.is_empty() {
        return Err(TranscodeError::Empty);
    }
    let bounds = &req.bounds;

    // The two facts symphonia doesn't surface, read bounds-safely from the source:
    // the video sync samples (GOP boundaries) and the verbatim audio `mp4a` entry.
    let tables = remux::parse_tables(&req.source);
    let dem = demux_source(&req.source, bounds)?;

    // A present audio track REQUIRES the verbatim ffmpeg `mp4a`/`esds` SampleEntry; if
    // the source has audio but we couldn't lift it, fail closed rather than drop audio.
    let audio_entry = tables.audio_sample_entry;
    if dem.audio.is_some() && audio_entry.is_none() {
        return Err(TranscodeError::DecodeFailed);
    }

    // --- keyframe boundaries → closed-GOP fragment starts ---
    let v = dem.video_samples.len();
    let mut kf: Vec<usize> = tables
        .video_sync
        .iter()
        .filter_map(|&s| (s >= 1).then_some((s - 1) as usize))
        .filter(|&i| i < v)
        .collect();
    kf.push(0); // a fragment MUST start with a keyframe; the first sample always is.
    kf.sort_unstable();
    kf.dedup();
    // `kf` is non-empty (v ≥ 1, and we pushed 0).

    let num_fragments = kf.len();
    if num_fragments as u64 > bounds.max_fragments as u64 {
        return Err(TranscodeError::TooLarge);
    }

    let gop_start_ns: Vec<i128> = kf.iter().map(|&i| dem.video_ns[i]).collect();

    // Assign each AAC frame to the GOP whose presentation span contains it (the last
    // GOP with start ≤ the frame's pts; frames before the first GOP fall to GOP 0).
    let mut audio_buckets: Vec<Vec<&[u8]>> = vec![Vec::new(); num_fragments];
    if let Some(a) = &dem.audio {
        for (j, s) in a.samples.iter().enumerate() {
            let ns = a.sample_ns[j];
            let cnt = gop_start_ns.partition_point(|&start| start <= ns);
            let g = cnt.saturating_sub(1).min(num_fragments - 1);
            audio_buckets[g].push(s.as_slice());
        }
    }

    let mut cmaf: Vec<u8> = Vec::new();
    let mut fragments: Vec<FragmentEntry> = Vec::with_capacity(num_fragments);

    for (g, &start) in kf.iter().enumerate() {
        let end = kf.get(g + 1).copied().unwrap_or(v);
        let video_slice: Vec<&[u8]> = dem.video_samples[start..end]
            .iter()
            .map(|s| s.as_slice())
            .collect();
        // REAL per-sample durations for this GOP, from its source frame pts.
        let video_durations = frame_durations_ms(&dem.video_ns[start..end]);

        // Pre-build cap: this GOP's raw sample bytes must fit the per-fragment cap
        // BEFORE we allocate and assemble its fragment buffer.
        let vbytes: u64 = video_slice.iter().map(|s| s.len() as u64).sum();
        let abytes: u64 = audio_buckets[g].iter().map(|s| s.len() as u64).sum();
        if vbytes.saturating_add(abytes) > bounds.max_fragment_bytes {
            return Err(TranscodeError::TooLarge);
        }

        let bucket = std::mem::take(&mut audio_buckets[g]);
        let audio_frag = match (dem.audio.as_ref(), audio_entry.as_deref()) {
            (Some(a), Some(entry)) if !bucket.is_empty() => Some(remux::AudioFragment {
                sample_rate: a.sample_rate,
                sample_entry: entry,
                samples: bucket,
            }),
            _ => None,
        };

        let fragment = remux::build_av_fragment(
            &video_slice,
            &video_durations,
            audio_frag.as_ref(),
            dem.width,
            dem.height,
        )?;

        // Defense-in-depth: the padded fragment must not exceed the per-fragment cap.
        if fragment.len() as u64 > bounds.max_fragment_bytes {
            return Err(TranscodeError::TooLarge);
        }

        let offset = cmaf.len();
        let pts_ms = (gop_start_ns[g] / 1_000_000).max(0) as u64;
        fragments.push(remux::fragment_entry(
            g as u32,
            pts_ms,
            offset,
            fragment.len(),
        ));
        cmaf.extend_from_slice(&fragment);

        if cmaf.len() as u64 > bounds.max_total_bytes {
            return Err(TranscodeError::TooLarge);
        }
    }

    Ok(TranscodeResult {
        cmaf,
        // Thumbnail/preview are derived in client-app from ffmpeg's thumb.png (Task 3.4).
        thumbnail: Vec::new(),
        preview: Vec::new(),
        fragments,
        // Loudness normalization stays an ffmpeg-side concern; none emitted here.
        loudness_gain_db: None,
    })
}

// ---------------------------------------------------------------------------
// Chunk alignment: pad a fragment up to a whole TRANSCODE_CHUNK_SIZE multiple with a
// trailing ISO-BMFF `free` box, so each fragment occupies a contiguous, chunk-aligned
// byte range AND still demuxes (a `free` box is standard free-space a compliant reader
// skips — verified by the symphonia round-trip test).
// ---------------------------------------------------------------------------

/// Pad `fragment` up to a whole multiple of [`TRANSCODE_CHUNK_SIZE`] by appending a
/// single `free` box. A `free` box needs ≥ 8 bytes (size + type), so a 1..7-byte gap
/// is bumped by one whole chunk to leave room — the result is always chunk-aligned.
pub(crate) fn pad_to_chunk(mut fragment: Vec<u8>) -> Vec<u8> {
    let r = fragment.len() % TRANSCODE_CHUNK_SIZE;
    if r == 0 {
        return fragment;
    }
    let mut gap = TRANSCODE_CHUNK_SIZE - r;
    if gap < 8 {
        gap += TRANSCODE_CHUNK_SIZE; // need room for the 8-byte free-box header.
    }
    fragment.extend_from_slice(&(gap as u32).to_be_bytes());
    fragment.extend_from_slice(b"free");
    fragment.resize(fragment.len() + (gap - 8), 0);
    fragment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(source: Vec<u8>) -> TranscodeRequest {
        TranscodeRequest {
            source,
            bounds: VideoBounds::default(),
        }
    }

    #[test]
    fn rejects_empty_source() {
        assert_eq!(transcode(&req(vec![])).unwrap_err(), TranscodeError::Empty);
    }

    #[test]
    fn rejects_garbage_source_without_panic() {
        // Not an MP4 → DecodeFailed; arbitrary short junk must never panic.
        assert_eq!(
            transcode(&req(vec![0xDE, 0xAD, 0xBE, 0xEF])).unwrap_err(),
            TranscodeError::DecodeFailed
        );
        assert_eq!(
            transcode(&req(vec![0u8; 64])).unwrap_err(),
            TranscodeError::DecodeFailed
        );
    }

    #[test]
    fn rejects_truncated_mp4_without_panic() {
        // A valid ftyp header followed by nothing — no moov, no tracks → DecodeFailed,
        // never a panic on the truncated box stream.
        let mut src = Vec::new();
        src.extend_from_slice(&20u32.to_be_bytes());
        src.extend_from_slice(b"ftyp");
        src.extend_from_slice(b"av01\0\0\0\0av01");
        assert_eq!(
            transcode(&req(src)).unwrap_err(),
            TranscodeError::DecodeFailed
        );
    }

    #[test]
    fn frame_durations_are_real_not_uniform() {
        // 24 fps: each frame is 1000/24 = 41.66… ms apart. Fragment-relative source
        // pts in ns (telescoping from 0). Six frames.
        let step_ns: i128 = 1_000_000_000 / 24; // ~41_666_666 ns
        let gop: Vec<i128> = (0..6).map(|i| i as i128 * step_ns).collect();
        let durs = frame_durations_ms(&gop);
        assert_eq!(durs.len(), 6, "one duration per sample");
        // Deltas are ~41/42 ms (NOT 1 ms): the cumulative ms pts are 0,41,83,124,166,208.
        // diffs: 41,42,41,42,42 ; the last reuses the previous delta (42).
        assert_eq!(durs, vec![41, 42, 41, 42, 42, 42]);
        let total: u64 = durs.iter().map(|&d| d as u64).sum();
        // ≈ 6/24 s = 250 ms, emphatically not 6 ms.
        assert!(
            (240..=260).contains(&total),
            "total ≈ frames/fps seconds, got {total} ms"
        );
    }

    #[test]
    fn frame_durations_are_bounds_safe_on_hostile_pts() {
        // Empty GOP → no durations.
        assert!(frame_durations_ms(&[]).is_empty());
        // Single sample → one nominal 1 ms duration (the historical layout).
        assert_eq!(frame_durations_ms(&[5_000_000]), vec![1]);
        // NON-MONOTONIC pts must never yield a negative/zero duration: each delta is
        // floored at 1 ms and an out-of-order pts is pinned to its predecessor.
        let gop = vec![0i128, 100_000_000, 10_000_000, 200_000_000];
        let durs = frame_durations_ms(&gop);
        assert_eq!(durs.len(), 4);
        assert!(durs.iter().all(|&d| d >= 1), "no zero/negative durations");
        // A HUGE pts jump saturates rather than overflowing u32.
        let huge = vec![0i128, i128::MAX];
        let durs = frame_durations_ms(&huge);
        assert_eq!(durs, vec![u32::MAX, u32::MAX]);
    }

    #[test]
    fn pad_to_chunk_always_aligns_and_handles_tiny_gaps() {
        // Exact multiple → untouched.
        let exact = vec![0u8; TRANSCODE_CHUNK_SIZE * 2];
        assert_eq!(pad_to_chunk(exact.clone()).len(), exact.len());
        // A 1-byte gap (len = 2*CS - 1) cannot fit an 8-byte free box in 1 byte, so it
        // is bumped a whole chunk; the result is still aligned.
        let near = vec![0u8; TRANSCODE_CHUNK_SIZE * 2 - 1];
        let padded = pad_to_chunk(near);
        assert_eq!(padded.len() % TRANSCODE_CHUNK_SIZE, 0);
        assert!(padded.len() >= TRANSCODE_CHUNK_SIZE * 2);
        // A generic small fragment pads up to one chunk.
        let small = vec![0u8; 100];
        assert_eq!(pad_to_chunk(small).len(), TRANSCODE_CHUNK_SIZE);
    }
}
