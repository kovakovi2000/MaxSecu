//! Canonical **CMAF re-muxer** (Fork X, ratification §3/§4): turn one closed GOP of
//! ffmpeg-produced AV1 video samples (+ the matching AAC audio frames) into a single
//! self-contained, non-fragmented MP4 — exactly the per-fragment layout the existing
//! viewer (`media-worker::VideoSession` + `client-app`'s fragment index) already
//! decodes.
//!
//! This module is the **inverse** of an MP4 sample-table reader: it hand-writes the
//! `ftyp`/`moov`/`mdat` boxes (extending the single-sample muxer the crate shipped
//! before) to a **multi-sample video `trak`** plus an **optional audio `trak`** whose
//! `mp4a`/`esds` SampleEntry is **copied byte-for-byte from ffmpeg's output** (so we
//! never hand-author the AudioSpecificConfig — the riskiest part — see ratification
//! §4/§5). It also carries the two tiny, **bounds-safe** box readers the re-mux needs
//! and symphonia does not expose: the video `stss` (sync-sample → GOP boundaries) and
//! the audio `stsd`'s first SampleEntry (the verbatim `mp4a`).
//!
//! # Trust boundary
//! `parse_tables` runs over the **attacker-derived** ffmpeg output (`req.source`).
//! Every read is bounds-checked (`slice::get`, never an index) and fail-soft: a
//! malformed/short box yields an empty/None result, never a panic, never an
//! out-of-bounds access, never an allocation sized from an unchecked declared length.
//! The muxer itself only ever writes bytes derived from already-validated, in-bounds
//! inputs.

use maxsecu_client_core::media::FragmentEntry;

use crate::{pad_to_chunk, TranscodeError, TRANSCODE_CHUNK_SIZE};

// ===========================================================================
// ISO-BMFF box primitives (hand-rolled; NO external muxer crate, NO ffmpeg).
// ===========================================================================

/// Box: `[u32 size][u8;4 type][payload]`.
pub(crate) fn box_(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&((payload.len() as u32) + 8).to_be_bytes());
    v.extend_from_slice(typ);
    v.extend_from_slice(payload);
    v
}

/// Full box: `[size][type][version + 3-byte flags][payload]`.
fn fbox(typ: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + payload.len());
    p.push(version);
    p.extend_from_slice(&flags.to_be_bytes()[1..]); // 3-byte flags
    p.extend_from_slice(payload);
    box_(typ, &p)
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

const UNITY_MATRIX: [u8; 36] = [
    0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, // a, b, u
    0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, // c, d, v
    0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x00, 0x00, 0x00, // x, y, w
];

// ===========================================================================
// Bounds-safe MP4 box readers over the attacker-derived ffmpeg output.
// ===========================================================================

/// The two sample-table facts the re-mux needs from ffmpeg's output that symphonia
/// does not surface: the video track's sync samples (GOP boundaries) and the audio
/// track's verbatim `mp4a` SampleEntry bytes.
pub(crate) struct ParsedTables {
    /// 1-based sync-sample numbers from the VIDEO track's `stss` (empty if absent).
    pub video_sync: Vec<u32>,
    /// The audio track's first SampleEntry box (`mp4a`+`esds`), copied VERBATIM.
    pub audio_sample_entry: Option<Vec<u8>>,
}

/// Parse exactly ONE box at byte `off` in `data`, **bounds-safely**, returning
/// `(type, payload-range, next-offset)` or `None` when there is no well-formed box at
/// `off` (truncation, header underflow, or a length — including a hostile 64-bit
/// `largesize` up to `u64::MAX` — that overruns the container). Handles 32-bit sizes,
/// the 64-bit `largesize` (`size == 1`) and the to-end form (`size == 0`).
///
/// All length checks compare against the **remaining bytes** (`total > remaining`)
/// rather than via addition (`off + total > data.len()`), which would overflow/wrap on
/// a hostile `largesize` and could push a reversed range. `remaining = data.len() - off`
/// is computed with `checked_sub`, and the function returns early unless
/// `remaining >= 8`; on success it guarantees `total <= remaining`, so the returned
/// range `off+hdr..off+total` and next-offset `off+total` can neither overflow nor
/// reverse.
fn box_at(data: &[u8], off: usize) -> Option<([u8; 4], core::ops::Range<usize>, usize)> {
    let remaining = data.len().checked_sub(off)?;
    if remaining < 8 {
        return None;
    }
    let size = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    let typ = [data[off + 4], data[off + 5], data[off + 6], data[off + 7]];
    let (hdr, total): (usize, usize) = if size == 1 {
        // 64-bit largesize follows the type.
        if remaining < 16 {
            return None;
        }
        let large = u64::from_be_bytes([
            data[off + 8],
            data[off + 9],
            data[off + 10],
            data[off + 11],
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]);
        // A largesize beyond usize is unrepresentable here ⇒ treat as an overrun.
        (16, usize::try_from(large).unwrap_or(usize::MAX))
    } else if size == 0 {
        (8, remaining) // extends to end of the container.
    } else {
        (8, size as usize)
    };
    // Reject a box that underflows its own header or overruns the container. Compared
    // against the remaining bytes — no addition, so no overflow/wrap/reversed range.
    if total < hdr || total > remaining {
        return None;
    }
    Some((typ, off + hdr..off + total, off + total))
}

/// Iterate the immediate child boxes of `data`, returning each `(type, payload-range)`
/// **bounds-safely**. Stops at the first malformed/over-long box (see [`box_at`]).
fn child_boxes(data: &[u8]) -> Vec<([u8; 4], core::ops::Range<usize>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while let Some((typ, range, next)) = box_at(data, off) {
        out.push((typ, range));
        off = next; // strictly increases (total >= hdr >= 8), so the loop terminates.
    }
    out
}

/// First immediate child box of `data` whose type is `typ`, as a payload slice. Scans
/// lazily and **short-circuits** at the first match — it never materializes the whole
/// child list (a 64 MiB source of 8-byte boxes would otherwise build ~8M entries).
fn find_child<'a>(data: &'a [u8], typ: &[u8; 4]) -> Option<&'a [u8]> {
    let mut off = 0usize;
    while let Some((t, range, next)) = box_at(data, off) {
        if &t == typ {
            return Some(&data[range]);
        }
        off = next;
    }
    None
}

/// The 4-byte handler type out of an `hdlr` full-box payload
/// (`[version+flags 4][pre_defined 4][handler_type 4]…`).
fn handler_type(hdlr: &[u8]) -> Option<[u8; 4]> {
    hdlr.get(8..12).map(|s| [s[0], s[1], s[2], s[3]])
}

/// Parse a video `stss` full-box payload (`[version+flags 4][entry_count 4][u32…]`)
/// into its 1-based sync-sample numbers, bounded by the bytes actually present.
fn parse_stss(stss: &[u8]) -> Vec<u32> {
    let Some(cnt_bytes) = stss.get(4..8) else {
        return Vec::new();
    };
    let declared = u32::from_be_bytes([cnt_bytes[0], cnt_bytes[1], cnt_bytes[2], cnt_bytes[3]]);
    // Never trust the declared count for sizing: cap the reserve by the bytes present.
    let available = stss.len().saturating_sub(8) / 4;
    let count = (declared as usize).min(available);
    let mut v = Vec::with_capacity(count);
    let mut off = 8;
    for _ in 0..count {
        let Some(b) = stss.get(off..off + 4) else {
            break;
        };
        v.push(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        off += 4;
    }
    v
}

/// Copy the first SampleEntry box (header + payload) out of an `stsd` full-box payload
/// (`[version+flags 4][entry_count 4][SampleEntry box…]`). This is ffmpeg's `mp4a`
/// (with its child `esds`), lifted **verbatim** — bounds-safe, `None` on a short box.
fn first_sample_entry(stsd: &[u8]) -> Option<Vec<u8>> {
    let entries = stsd.get(8..)?; // skip version+flags(4) + entry_count(4)
                                  // The first SampleEntry box, parsed by the shared bounds-safe reader; `next` is its
                                  // total length (header + payload), so `entries[..next]` is the full box verbatim.
    let (_, _, next) = box_at(entries, 0)?;
    Some(entries[..next].to_vec())
}

/// Walk ffmpeg's `moov` and extract, bounds-safely, the video `stss` sync samples and
/// the audio `stsd`'s verbatim `mp4a` SampleEntry. Any missing/malformed box leaves
/// the corresponding field empty/None (fail-soft) — `transcode` then fails closed if
/// a required piece (e.g. the audio SampleEntry for a present audio track) is absent.
pub(crate) fn parse_tables(src: &[u8]) -> ParsedTables {
    let mut res = ParsedTables {
        video_sync: Vec::new(),
        audio_sample_entry: None,
    };
    let Some(moov) = find_child(src, b"moov") else {
        return res;
    };
    for (typ, range) in child_boxes(moov) {
        if &typ != b"trak" {
            continue;
        }
        let trak = &moov[range];
        let Some(mdia) = find_child(trak, b"mdia") else {
            continue;
        };
        let handler = find_child(mdia, b"hdlr").and_then(handler_type);
        let Some(minf) = find_child(mdia, b"minf") else {
            continue;
        };
        let Some(stbl) = find_child(minf, b"stbl") else {
            continue;
        };
        match handler.as_ref() {
            Some(b"vide") => {
                if let Some(stss) = find_child(stbl, b"stss") {
                    res.video_sync = parse_stss(stss);
                }
            }
            Some(b"soun") => {
                if let Some(stsd) = find_child(stbl, b"stsd") {
                    res.audio_sample_entry = first_sample_entry(stsd);
                }
            }
            _ => {}
        }
    }
    res
}

// ===========================================================================
// The canonical multi-track / multi-sample fragment muxer (Fork X, §4).
// ===========================================================================

/// The audio side of one fragment: the ordered AAC frames for this GOP, the track
/// sample rate (used as the audio media timescale), and the verbatim ffmpeg `mp4a`
/// SampleEntry bytes to reuse.
pub(crate) struct AudioFragment<'a> {
    pub sample_rate: u32,
    pub sample_entry: &'a [u8],
    pub samples: Vec<&'a [u8]>,
}

/// Build ONE self-contained, chunk-aligned canonical fragment MP4 for a closed GOP.
///
/// `video_samples` is the GOP in decode order (sample 1 = the keyframe); `video_durations`
/// are the matching REAL per-sample presentation durations in the video media timescale
/// (ms — see [`build_video_trak`]); `audio` are the AAC frames whose presentation time
/// falls in the GOP's span (or `None` when the source has no audio). Returns the padded,
/// whole-`TRANSCODE_CHUNK_SIZE` fragment.
pub(crate) fn build_av_fragment(
    video_samples: &[&[u8]],
    video_durations: &[u32],
    audio: Option<&AudioFragment<'_>>,
    width: u32,
    height: u32,
) -> Result<Vec<u8>, TranscodeError> {
    if video_samples.is_empty() {
        return Err(TranscodeError::MuxFailed);
    }
    let video_total: usize = video_samples.iter().map(|s| s.len()).sum();
    let audio_total: usize = audio
        .map(|a| a.samples.iter().map(|s| s.len()).sum())
        .unwrap_or(0);

    let ftyp = box_(b"ftyp", b"av01\0\0\0\0av01isommp41");

    // Two-pass for the `stco` chunk offsets: the offset *values* don't change the
    // moov's *length* (fixed-width u32), so build once with placeholder offsets to
    // learn moov.len(), then rebuild with the real absolute mdat offsets.
    let moov_probe = build_moov(0, 0, video_samples, video_durations, audio, width, height);
    let mdat_payload_off = ftyp.len() + moov_probe.len() + 8; // +8 = mdat box header
    let video_off = mdat_payload_off;
    let audio_off = mdat_payload_off + video_total;
    let moov = build_moov(
        video_off as u32,
        audio_off as u32,
        video_samples,
        video_durations,
        audio,
        width,
        height,
    );
    debug_assert_eq!(
        moov.len(),
        moov_probe.len(),
        "moov length must be offset-stable"
    );

    let mut mdat_payload = Vec::with_capacity(video_total + audio_total);
    for s in video_samples {
        mdat_payload.extend_from_slice(s);
    }
    if let Some(a) = audio {
        for s in &a.samples {
            mdat_payload.extend_from_slice(s);
        }
    }
    let mdat = box_(b"mdat", &mdat_payload);

    Ok(pad_to_chunk(concat(&[&ftyp, &moov, &mdat])))
}

/// Compute the `FragmentEntry` for a freshly built, already chunk-aligned fragment at
/// the given running `cmaf` offset.
pub(crate) fn fragment_entry(seq: u32, pts_ms: u64, offset: usize, len: usize) -> FragmentEntry {
    debug_assert_eq!(offset % TRANSCODE_CHUNK_SIZE, 0, "fragments stay aligned");
    debug_assert_eq!(
        len % TRANSCODE_CHUNK_SIZE,
        0,
        "fragment padded to a whole chunk"
    );
    FragmentEntry {
        seq,
        pts_ms,
        chunk_start: (offset / TRANSCODE_CHUNK_SIZE) as u64,
        chunk_len: (len / TRANSCODE_CHUNK_SIZE) as u64,
    }
}

fn build_moov(
    video_chunk_off: u32,
    audio_chunk_off: u32,
    video_samples: &[&[u8]],
    video_durations: &[u32],
    audio: Option<&AudioFragment<'_>>,
    width: u32,
    height: u32,
) -> Vec<u8> {
    // Total video presentation time = the sum of the REAL per-sample durations (video
    // media timescale 1000, i.e. ms), saturating so a degenerate duration table can
    // never overflow the running total.
    let video_dur_ms: u64 = video_durations
        .iter()
        .fold(0u64, |acc, &d| acc.saturating_add(d as u64));

    let audio_dur_ms = audio
        .map(|a| {
            let m = a.samples.len() as u64;
            // AAC frame = 1024 samples; duration in ms at the audio sample rate.
            m.saturating_mul(1024).saturating_mul(1000) / a.sample_rate.max(1) as u64
        })
        .unwrap_or(0);
    let movie_dur_ms = video_dur_ms.max(audio_dur_ms);

    let next_track_id: u32 = if audio.is_some() { 3 } else { 2 };

    // ---- mvhd (movie timescale 1000) ----
    let mut mvhd = Vec::new();
    mvhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    mvhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    mvhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
    mvhd.extend_from_slice(&(movie_dur_ms.min(u32::MAX as u64) as u32).to_be_bytes()); // duration
    mvhd.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
    mvhd.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
    mvhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    mvhd.extend_from_slice(&[0u8; 8]); // reserved
    mvhd.extend_from_slice(&UNITY_MATRIX);
    mvhd.extend_from_slice(&[0u8; 24]); // predefined
    mvhd.extend_from_slice(&next_track_id.to_be_bytes());
    let mvhd = fbox(b"mvhd", 0, 0, &mvhd);

    let video_trak = build_video_trak(
        video_chunk_off,
        video_samples,
        video_durations,
        width,
        height,
        video_dur_ms,
    );

    let mut children: Vec<&[u8]> = vec![&mvhd, &video_trak];
    let audio_trak = audio.map(|a| build_audio_trak(audio_chunk_off, a, audio_dur_ms));
    if let Some(at) = audio_trak.as_ref() {
        children.push(at);
    }
    box_(b"moov", &concat(&children))
}

fn build_video_trak(
    chunk_off: u32,
    samples: &[&[u8]],
    durations: &[u32],
    w: u32,
    h: u32,
    dur_ms: u64,
) -> Vec<u8> {
    let n = samples.len() as u32;

    // tkhd (track 1, video; width/height in 16.16)
    let mut tkhd = Vec::new();
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    tkhd.extend_from_slice(&1u32.to_be_bytes()); // track_id
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&(dur_ms.min(u32::MAX as u64) as u32).to_be_bytes()); // duration
    tkhd.extend_from_slice(&[0u8; 8]); // reserved
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // layer
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // alternate_group
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // volume (0 for video)
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&UNITY_MATRIX);
    tkhd.extend_from_slice(&(w << 16).to_be_bytes()); // width 16.16
    tkhd.extend_from_slice(&(h << 16).to_be_bytes()); // height 16.16
    let tkhd = fbox(b"tkhd", 0, 0x000007, &tkhd); // enabled|in-movie|in-preview

    // mdhd (video media timescale 1000)
    let mdhd = mdhd_box(1000, dur_ms);

    // hdlr 'vide'
    let mut hdlr = Vec::new();
    hdlr.extend_from_slice(&0u32.to_be_bytes()); // predefined
    hdlr.extend_from_slice(b"vide"); // handler_type
    hdlr.extend_from_slice(&[0u8; 12]); // reserved
    hdlr.extend_from_slice(b"VideoHandler\0"); // name
    let hdlr = fbox(b"hdlr", 0, 0, &hdlr);

    // vmhd
    let mut vmhd = Vec::new();
    vmhd.extend_from_slice(&0u16.to_be_bytes()); // graphicsmode
    vmhd.extend_from_slice(&[0u8; 6]); // opcolor
    let vmhd = fbox(b"vmhd", 0, 1, &vmhd);

    let dinf = dinf_box();

    // stsd > av01 (VisualSampleEntry; NO av1C — the seq-header OBU is in-band).
    let mut av01 = Vec::new();
    av01.extend_from_slice(&[0u8; 6]); // SampleEntry reserved
    av01.extend_from_slice(&1u16.to_be_bytes()); // data_reference_index
    av01.extend_from_slice(&0u16.to_be_bytes()); // predefined
    av01.extend_from_slice(&0u16.to_be_bytes()); // reserved
    av01.extend_from_slice(&[0u8; 12]); // predefined
    av01.extend_from_slice(&(w as u16).to_be_bytes()); // width
    av01.extend_from_slice(&(h as u16).to_be_bytes()); // height
    av01.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // horiz_res 72dpi
    av01.extend_from_slice(&0x0048_0000u32.to_be_bytes()); // vert_res 72dpi
    av01.extend_from_slice(&0u32.to_be_bytes()); // reserved
    av01.extend_from_slice(&1u16.to_be_bytes()); // frame_count
    av01.extend_from_slice(&[0u8; 32]); // compressorname
    av01.extend_from_slice(&0x0018u16.to_be_bytes()); // depth
    av01.extend_from_slice(&0xffffu16.to_be_bytes()); // predefined
    let av01 = box_(b"av01", &av01);
    let stsd = stsd_box(&av01);

    // stts: REAL per-sample durations (video media timescale 1000 ⇒ ms), run-length
    // compressed (consecutive equal deltas coalesce into one entry), so the decoder
    // reads true frame presentation times instead of a synthetic ~1000 fps. A 24 fps
    // GOP, for example, alternates 41/42 ms deltas summing to ≈ N/fps seconds rather
    // than N ms. Fail-safe: when `durations` does not match the sample count (it always
    // should — the caller derives one per sample) fall back to the old uniform delta=1
    // so the table stays well-formed; a 0-length GOP is impossible here (n ≥ 1).
    let stts = if durations.len() == samples.len() && !durations.is_empty() {
        // Coalesce consecutive equal deltas: each entry is (sample_count, sample_delta).
        let mut entries: Vec<(u32, u32)> = Vec::new();
        for &d in durations {
            match entries.last_mut() {
                Some((cnt, delta)) if *delta == d => *cnt = cnt.saturating_add(1),
                _ => entries.push((1, d)),
            }
        }
        let mut stts = Vec::with_capacity(8 + entries.len() * 8);
        stts.extend_from_slice(&(entries.len() as u32).to_be_bytes()); // entry_count
        for (cnt, delta) in &entries {
            stts.extend_from_slice(&cnt.to_be_bytes()); // sample_count
            stts.extend_from_slice(&delta.to_be_bytes()); // sample_delta
        }
        fbox(b"stts", 0, 0, &stts)
    } else {
        // Defensive fallback: a single uniform entry (sample_count=N, delta=1).
        let mut stts = Vec::new();
        stts.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        stts.extend_from_slice(&n.to_be_bytes()); // sample_count
        stts.extend_from_slice(&1u32.to_be_bytes()); // sample_delta
        fbox(b"stts", 0, 0, &stts)
    };

    // stsc: 1 entry, all N samples in one chunk.
    let stsc = stsc_box(n);
    // stsz: per-sample sizes.
    let stsz = stsz_box(samples.iter().map(|s| s.len() as u32));
    // stco: the single video chunk offset.
    let stco = stco_box(chunk_off);

    // stss: sample 1 is a sync sample (the closed-GOP keyframe).
    let mut stss = Vec::new();
    stss.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stss.extend_from_slice(&1u32.to_be_bytes()); // sample_number
    let stss = fbox(b"stss", 0, 0, &stss);

    let stbl = box_(
        b"stbl",
        &concat(&[&stsd, &stts, &stsc, &stsz, &stco, &stss]),
    );
    let minf = box_(b"minf", &concat(&[&vmhd, &dinf, &stbl]));
    let mdia = box_(b"mdia", &concat(&[&mdhd, &hdlr, &minf]));
    box_(b"trak", &concat(&[&tkhd, &mdia]))
}

fn build_audio_trak(chunk_off: u32, audio: &AudioFragment<'_>, dur_ms: u64) -> Vec<u8> {
    let m = audio.samples.len() as u32;
    let rate = audio.sample_rate.max(1);
    let media_dur = (m as u64).saturating_mul(1024); // in audio timescale units.

    // tkhd (track 2, audio; width=height=0, volume 1.0)
    let mut tkhd = Vec::new();
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    tkhd.extend_from_slice(&2u32.to_be_bytes()); // track_id
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&(dur_ms.min(u32::MAX as u64) as u32).to_be_bytes()); // duration
    tkhd.extend_from_slice(&[0u8; 8]); // reserved
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // layer
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // alternate_group
    tkhd.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&UNITY_MATRIX);
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // width 0
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // height 0
    let tkhd = fbox(b"tkhd", 0, 0x000007, &tkhd);

    // mdhd (audio media timescale = sample rate)
    let mdhd = mdhd_box(rate, media_dur);

    // hdlr 'soun'
    let mut hdlr = Vec::new();
    hdlr.extend_from_slice(&0u32.to_be_bytes()); // predefined
    hdlr.extend_from_slice(b"soun"); // handler_type
    hdlr.extend_from_slice(&[0u8; 12]); // reserved
    hdlr.extend_from_slice(b"SoundHandler\0"); // name
    let hdlr = fbox(b"hdlr", 0, 0, &hdlr);

    // smhd
    let mut smhd = Vec::new();
    smhd.extend_from_slice(&0u16.to_be_bytes()); // balance
    smhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    let smhd = fbox(b"smhd", 0, 0, &smhd);

    let dinf = dinf_box();

    // stsd > the VERBATIM ffmpeg mp4a/esds SampleEntry.
    let stsd = stsd_box(audio.sample_entry);

    // stts: 1 entry, sample_count=M, delta=1024 (AAC frame).
    let mut stts = Vec::new();
    stts.extend_from_slice(&1u32.to_be_bytes());
    stts.extend_from_slice(&m.to_be_bytes());
    stts.extend_from_slice(&1024u32.to_be_bytes());
    let stts = fbox(b"stts", 0, 0, &stts);

    let stsc = stsc_box(m);
    let stsz = stsz_box(audio.samples.iter().map(|s| s.len() as u32));
    let stco = stco_box(chunk_off);
    // No stss for audio — every AAC frame is independently decodable.

    let stbl = box_(b"stbl", &concat(&[&stsd, &stts, &stsc, &stsz, &stco]));
    let minf = box_(b"minf", &concat(&[&smhd, &dinf, &stbl]));
    let mdia = box_(b"mdia", &concat(&[&mdhd, &hdlr, &minf]));
    box_(b"trak", &concat(&[&tkhd, &mdia]))
}

// ---- small shared box builders ----

fn mdhd_box(timescale: u32, duration: u64) -> Vec<u8> {
    let mut mdhd = Vec::new();
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    mdhd.extend_from_slice(&timescale.to_be_bytes());
    mdhd.extend_from_slice(&(duration.min(u32::MAX as u64) as u32).to_be_bytes());
    mdhd.extend_from_slice(&0x55c4u16.to_be_bytes()); // language 'und'
    mdhd.extend_from_slice(&0u16.to_be_bytes()); // predefined
    fbox(b"mdhd", 0, 0, &mdhd)
}

fn dinf_box() -> Vec<u8> {
    let url = fbox(b"url ", 0, 1, &[]); // self-contained
    let mut dref = Vec::new();
    dref.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    dref.extend_from_slice(&url);
    let dref = fbox(b"dref", 0, 0, &dref);
    box_(b"dinf", &dref)
}

fn stsd_box(entry: &[u8]) -> Vec<u8> {
    let mut stsd = Vec::new();
    stsd.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsd.extend_from_slice(entry);
    fbox(b"stsd", 0, 0, &stsd)
}

fn stsc_box(samples_per_chunk: u32) -> Vec<u8> {
    let mut stsc = Vec::new();
    stsc.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsc.extend_from_slice(&1u32.to_be_bytes()); // first_chunk
    stsc.extend_from_slice(&samples_per_chunk.to_be_bytes()); // samples_per_chunk
    stsc.extend_from_slice(&1u32.to_be_bytes()); // sample_description_index
    fbox(b"stsc", 0, 0, &stsc)
}

fn stsz_box(sizes: impl ExactSizeIterator<Item = u32>) -> Vec<u8> {
    let mut stsz = Vec::new();
    stsz.extend_from_slice(&0u32.to_be_bytes()); // sample_size 0 => table follows
    stsz.extend_from_slice(&(sizes.len() as u32).to_be_bytes()); // sample_count
    for s in sizes {
        stsz.extend_from_slice(&s.to_be_bytes());
    }
    fbox(b"stsz", 0, 0, &stsz)
}

fn stco_box(chunk_offset: u32) -> Vec<u8> {
    let mut stco = Vec::new();
    stco.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stco.extend_from_slice(&chunk_offset.to_be_bytes());
    fbox(b"stco", 0, 0, &stco)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_boxes_is_bounds_safe_on_truncation() {
        // A declared size that overruns the buffer yields no child (no panic).
        let data = [0, 0, 0, 0x40, b'm', b'o', b'o', b'v', 1, 2, 3];
        assert!(child_boxes(&data).is_empty());
        // Empty / sub-header buffers are fine too.
        assert!(child_boxes(&[]).is_empty());
        assert!(child_boxes(&[0, 0, 0]).is_empty());
    }

    #[test]
    fn child_boxes_is_bounds_safe_on_hostile_largesize() {
        // A valid 8-byte `free` box (advances off to 8, so off > 0) followed by a
        // `size == 1` (64-bit largesize) box whose largesize is u64::MAX. The old
        // `off + total > data.len()` check would overflow/wrap with off > 0 and push a
        // reversed range that then slice-panics; the subtraction guard must reject it.
        let mut data = Vec::new();
        data.extend_from_slice(&8u32.to_be_bytes());
        data.extend_from_slice(b"free");
        data.extend_from_slice(&1u32.to_be_bytes()); // size == 1 → largesize follows
        data.extend_from_slice(b"moov");
        data.extend_from_slice(&u64::MAX.to_be_bytes()); // hostile largesize

        // Returns WITHOUT panic, yielding only the well-formed first box.
        let boxes = child_boxes(&data);
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].0, *b"free");

        // The short-circuiting lookup also never panics on the hostile box.
        assert!(find_child(&data, b"free").is_some());
        assert!(find_child(&data, b"moov").is_none());

        // And the top-level table parse over the hostile input fails soft (no moov
        // payload is reachable), never panicking on a reversed slice range.
        let tables = parse_tables(&data);
        assert!(tables.video_sync.is_empty());
        assert!(tables.audio_sample_entry.is_none());
    }

    #[test]
    fn parse_stss_caps_declared_count_to_present_bytes() {
        // Declares 1000 entries but supplies only two: we read the two present, no OOB.
        let mut stss = Vec::new();
        stss.extend_from_slice(&0u32.to_be_bytes()); // version+flags
        stss.extend_from_slice(&1000u32.to_be_bytes()); // declared count (hostile)
        stss.extend_from_slice(&1u32.to_be_bytes());
        stss.extend_from_slice(&7u32.to_be_bytes());
        assert_eq!(parse_stss(&stss), vec![1, 7]);
    }

    #[test]
    fn first_sample_entry_rejects_overlong_box() {
        // entry box claims 999 bytes but only a few are present → None, no OOB.
        let mut stsd = Vec::new();
        stsd.extend_from_slice(&0u32.to_be_bytes()); // version+flags
        stsd.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        stsd.extend_from_slice(&999u32.to_be_bytes()); // box size (hostile)
        stsd.extend_from_slice(b"mp4a");
        assert!(first_sample_entry(&stsd).is_none());
    }
}
