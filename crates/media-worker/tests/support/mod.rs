//! Test-support: a **canonical-clip fixture generator** for the sandboxed-video
//! session-decode tasks (MaxSecu Media App Phase 7, Gate 3).
//!
//! This module synthesizes known-good **AV1 / CMAF** clips entirely in pure Rust
//! (no ffmpeg at test time) so the persistent-session decode worker (3.2+) has
//! deterministic, independently-decodable inputs to resume from.
//!
//! Pipeline (all zero-C — the `asm` features of rav1d/rav1e are OFF):
//! * `rav1e` encodes each raw YUV420 frame to a self-contained **still-picture**
//!   AV1 bitstream (its own sequence-header OBU → a closed GOP of exactly one
//!   keyframe).
//! * a hand-rolled minimal **ISO-BMFF/CMAF** muxer wraps that one sample in its
//!   own tiny MP4 (`ftyp` + `moov` + `mdat`). Each `CanonicalClip::fragments[i]`
//!   is therefore one **independently-decodable closed-GOP fragment** — exactly
//!   the "resume from fragment K" unit the session worker consumes.
//! * `symphonia` (isomp4) can demux any fragment back to its `av01` sample +
//!   geometry; `rav1d` decodes that sample back to the source dimensions.
//!
//! The muxer is hand-built (NO external muxer crate, NO ffmpeg) to keep the
//! view/fixture path C-free and cross-platform. It is reconstructed from the
//! Gate-1 codec-ratification spike (deleted), generalized to arbitrary W×H.
//!
//! NOTE: integration-test submodule — `#[cfg(test)]`-only by construction (it is
//! compiled solely as part of the `tests/` target tree). `rav1e` is a dev-dep, so
//! this module cannot be reached from non-test builds.
#![allow(dead_code)] // helpers here are also consumed by sibling tests (3.2+).

use std::io::Cursor;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

use rav1e::prelude::{ChromaSampling, Config, Context, EncoderConfig, EncoderStatus};

use symphonia::core::codecs::CodecParameters;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::formats::IsoMp4Reader;

/// A pre-canonical AV1/CMAF clip: a sequence of independently-decodable closed-GOP
/// fragments (each a self-contained tiny MP4 carrying exactly one keyframe).
pub struct CanonicalClip {
    pub width: u32,
    pub height: u32,
    /// Each entry is ONE independently-decodable closed-GOP CMAF fragment.
    pub fragments: Vec<Vec<u8>>,
    pub has_audio: bool,
}

/// Encode `frames` synthetic frames to AV1 and mux them into `frames`
/// independently-decodable single-keyframe CMAF fragments.
///
/// `with_audio` is **not yet implemented** (no pure-Rust AAC encoder exists; the
/// committed-AAC-sample path is closed in Gate 3.2 — residual R1). It currently
/// panics rather than fabricate an audio track; the 3.1 deliverable is the video
/// fixture + assertion, which `with_audio=false` exercises fully.
pub fn make_canonical_clip(w: u32, h: u32, frames: u32, with_audio: bool) -> CanonicalClip {
    assert!(w > 0 && h > 0, "clip dimensions must be non-zero");
    assert!(frames > 0, "a clip needs at least one frame");
    if with_audio {
        // Honest stub: do NOT fabricate an AAC track. See module/task notes — the
        // committed AAC-LC asset + audio mux lands with the AAC→PCM decode in 3.2,
        // which genuinely exercises symphonia's `aac` decoder (closing R1).
        panic!(
            "make_canonical_clip(with_audio=true) is deferred to Gate 3.2 \
             (committed AAC-LC asset + audio-track mux); use with_audio=false"
        );
    }

    let mut fragments = Vec::with_capacity(frames as usize);
    for i in 0..frames {
        let sample = encode_av1_still(w, h, i);
        fragments.push(mux_minimal_mp4(&sample, w, h));
    }

    CanonicalClip {
        width: w,
        height: h,
        fragments,
        has_audio: false,
    }
}

/// Encode one synthetic still YUV420 frame to a self-contained AV1 bitstream.
///
/// `still_picture = true` makes rav1e emit a single self-decodable keyframe whose
/// packet carries its own sequence-header OBU — i.e. a closed GOP of one frame,
/// decodable with no separate `av1C`.
fn encode_av1_still(w: u32, h: u32, seed: u32) -> Vec<u8> {
    let (wu, hu) = (w as usize, h as usize);
    // Luma: a deterministic gradient (content is irrelevant — only geometry is
    // asserted; `seed` just varies frames so they aren't byte-identical).
    let mut y = vec![0u8; wu * hu];
    for (idx, px) in y.iter_mut().enumerate() {
        let (x, row) = (idx % wu, idx / wu);
        *px = ((x + row + seed as usize) & 0xff) as u8;
    }
    // Chroma planes are ceil(w/2)×ceil(h/2) for 4:2:0; neutral grey (128).
    let cw = wu.div_ceil(2);
    let ch = hu.div_ceil(2);
    let chroma = vec![128u8; cw * ch];

    let mut enc = EncoderConfig::with_speed_preset(10);
    enc.width = wu;
    enc.height = hu;
    enc.bit_depth = 8;
    enc.chroma_sampling = ChromaSampling::Cs420;
    enc.still_picture = true;

    let cfg = Config::new().with_encoder_config(enc);
    let mut ctx: Context<u8> = cfg.new_context().expect("rav1e: invalid encoder config");

    let mut frame = ctx.new_frame();
    frame.planes[0].copy_from_raw_u8(&y, wu, 1);
    frame.planes[1].copy_from_raw_u8(&chroma, cw, 1);
    frame.planes[2].copy_from_raw_u8(&chroma, cw, 1);

    ctx.send_frame(frame).expect("rav1e: send_frame");
    ctx.flush();

    let mut out = Vec::new();
    loop {
        match ctx.receive_packet() {
            Ok(pkt) => out.extend_from_slice(&pkt.data),
            Err(EncoderStatus::Encoded) => continue,
            Err(EncoderStatus::LimitReached) | Err(EncoderStatus::NeedMoreData) => break,
            Err(e) => panic!("rav1e: receive_packet: {e:?}"),
        }
    }
    assert!(!out.is_empty(), "rav1e produced no AV1 bytes");
    out
}

// ---------------------------------------------------------------------------
// Demux (symphonia, isomp4) — read one av01 sample + geometry from a fragment.
// ---------------------------------------------------------------------------

/// Demux the first video sample (and its `av01` geometry) out of a fragment MP4
/// with symphonia's isomp4 reader. Panics with the symphonia error on malformed
/// input — these are our own freshly-muxed, well-formed fixtures.
pub fn demux_first_video_sample(mp4: Vec<u8>) -> (Vec<u8>, u32, u32) {
    let mss = MediaSourceStream::new(
        Box::new(Cursor::new(mp4)),
        MediaSourceStreamOptions::default(),
    );
    let mut reader = IsoMp4Reader::try_new(mss, FormatOptions::default())
        .expect("symphonia: failed to open the muxed fragment MP4");

    let track = reader
        .first_track(TrackType::Video)
        .expect("symphonia: no video track found");
    let track_id = track.id;

    let (w, h) = match track.codec_params.as_ref() {
        Some(CodecParameters::Video(v)) => (
            u32::from(v.width.expect("symphonia: video track has no width")),
            u32::from(v.height.expect("symphonia: video track has no height")),
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

// ---------------------------------------------------------------------------
// Decode (rav1d) — the AV1-decode RCE surface. Runs on an enlarged-stack worker
// thread (CF-2: rav1d's single-threaded decode overflows Windows' default 1 MiB
// main-thread stack).
// ---------------------------------------------------------------------------

/// Decode a single AV1 sample and return its picture geometry, or `None` if no
/// picture was produced. The actual FFI decode runs on a 64 MiB-stack worker
/// thread so the deep dav1d call frames don't overflow the default thread stack.
pub fn decode_av1_dims(bitstream: &[u8]) -> Option<(u32, u32)> {
    let owned = bitstream.to_vec();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || decode_av1_dims_ffi(&owned))
        .expect("spawn enlarged-stack decode thread")
        .join()
        .expect("rav1d decode thread panicked")
}

/// rav1d FFI decode of one still AV1 sample, single-threaded, minimal delay.
///
/// This is the ONE place in `media-worker` outside `src/win32.rs` that uses
/// `unsafe`: rav1d exposes the dav1d C ABI as `pub unsafe extern "C"` fns, so the
/// FFI calls are inherently unsafe. The surface is kept minimal and contained to
/// this helper; every call is justified inline.
#[allow(unsafe_code)]
fn decode_av1_dims_ffi(bitstream: &[u8]) -> Option<(u32, u32)> {
    use rav1d::include::dav1d::data::Dav1dData;
    use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
    use rav1d::include::dav1d::picture::Dav1dPicture;
    use rav1d::src::lib::{
        dav1d_close, dav1d_data_create, dav1d_data_unref, dav1d_default_settings,
        dav1d_get_picture, dav1d_open, dav1d_picture_unref, dav1d_send_data,
    };

    // SAFETY: every dav1d FFI call below is given valid, correctly-typed,
    // non-aliasing pointers to live stack storage, and results are checked before
    // any output is read. The whole sequence is open → (send_data/get_picture)* →
    // unref → close, the dav1d-documented single-still lifecycle.
    unsafe {
        // SAFETY: `settings` is uninitialized stack storage of the right type;
        // `dav1d_default_settings` fully initializes it through the non-null ptr.
        let mut settings = MaybeUninit::<Dav1dSettings>::uninit();
        dav1d_default_settings(NonNull::new(settings.as_mut_ptr()).unwrap());
        let mut settings = settings.assume_init();
        settings.n_threads = 1; // single-threaded: a lone still returns immediately.
        settings.max_frame_delay = 1;

        // SAFETY: `&mut ctx` (a live `Option<Dav1dContext>`) receives the opened
        // handle; `&mut settings` is a fully-initialized settings struct. On
        // success dav1d sets `ctx` to `Some(handle)`.
        let mut ctx: Option<Dav1dContext> = None;
        let res = dav1d_open(
            Some(NonNull::from(&mut ctx)),
            Some(NonNull::from(&mut settings)),
        );
        if res.0 != 0 {
            return None;
        }
        let handle = ctx.expect("dav1d_open returned a null context");

        // SAFETY: `data` is uninitialized `Dav1dData` storage; `dav1d_data_create`
        // initializes it and returns a writable dav1d-owned buffer of exactly
        // `bitstream.len()` bytes, into which we copy the (non-overlapping) sample.
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

        // dav1d's data-feed protocol: `-EAGAIN` means "I can't take more input
        // right now — drain a picture first, then retry". Any OTHER negative
        // `dav1d_send_data` result (e.g. `-EINVAL`) is a hard error: we fail fast
        // rather than burn the retry budget spinning. dav1d returns the *negated*
        // errno (`Dav1dResult.0 == -EAGAIN`); `EAGAIN == 11` on every target this
        // crate builds for (Windows MSVC and Linux x86_64 both define it as 11),
        // matching `rav1d`'s `Rav1dError::EAGAIN = libc::EAGAIN`.
        const DAV1D_ERR_AGAIN: i32 = -11;

        // Bounded send/drain. Keep feeding remaining bytes and polling until a
        // picture pops, a fatal send error trips, or the bound is reached (so a
        // genuinely bad stream terminates instead of spinning forever).
        let mut result = None;
        for _ in 0..64 {
            if data.sz > 0 {
                // SAFETY: `handle` is the live context; `&mut data` is the live,
                // initialized data struct. On success dav1d takes the bytes
                // (`data.sz` → 0); on `-EAGAIN` it keeps our ref for a retry.
                let sr = dav1d_send_data(Some(handle), Some(NonNull::from(&mut data)));
                if sr.0 != 0 && sr.0 != DAV1D_ERR_AGAIN {
                    break; // fatal feed error — stop and let cleanup run.
                }
            }
            // SAFETY: `pic` is uninitialized `Dav1dPicture` storage; on a `0`
            // result dav1d has fully initialized it and we own a ref to release.
            let mut pic = MaybeUninit::<Dav1dPicture>::uninit();
            let r = dav1d_get_picture(Some(handle), Some(NonNull::new(pic.as_mut_ptr()).unwrap()));
            if r.0 == 0 {
                let mut pic = pic.assume_init();
                let dims = (pic.p.w.max(0) as u32, pic.p.h.max(0) as u32);
                // SAFETY: `pic` is a live, dav1d-initialized picture we own;
                // releasing our reference exactly once.
                dav1d_picture_unref(Some(NonNull::from(&mut pic)));
                result = Some(dims);
                break;
            }
        }

        // SAFETY: `data` is a valid, initialized local `Dav1dData`. We release our
        // ref UNCONDITIONALLY here: `dav1d_send_data` only empties it on success,
        // so a stuck/early-exit stream can leave bytes (and the ref-counted input
        // buffer) un-taken, which `dav1d_close` does NOT free (it only releases the
        // context's internal ref). `dav1d_data_unref` is `mem::take(buf)` inside —
        // idempotent and safe to call even after the data was already consumed.
        dav1d_data_unref(Some(NonNull::from(&mut data)));

        // SAFETY: `&mut ctx` still holds the live handle; closing exactly once,
        // after which `ctx` must not be reused.
        dav1d_close(Some(NonNull::from(&mut ctx)));
        result
    }
}

// ---------------------------------------------------------------------------
// Minimal ISO-BMFF / CMAF muxer (hand-rolled; NO external muxer crate, NO
// ffmpeg). Emits one self-contained MP4 per fragment carrying exactly one av01
// sample (one keyframe = one closed GOP). Reconstructed from the Gate-1 spike,
// generalized to arbitrary W×H.
// ---------------------------------------------------------------------------

/// Box: `[u32 size][u8;4 type][payload]`.
fn b(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&((payload.len() as u32) + 8).to_be_bytes());
    v.extend_from_slice(typ);
    v.extend_from_slice(payload);
    v
}

/// Full box: `[size][type][version + 3-byte flags][payload]`.
fn fb(typ: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + payload.len());
    p.push(version);
    p.extend_from_slice(&flags.to_be_bytes()[1..]); // 3-byte flags
    p.extend_from_slice(payload);
    b(typ, &p)
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

/// Wrap one AV1 sample in a self-contained non-fragmented MP4 (`ftyp` + `moov` +
/// `mdat`). The `stco` chunk offset is the byte offset of the `mdat` payload, so
/// `moov` is built once with a placeholder (to learn its fixed length), then
/// rebuilt with the real offset (same width → identical length).
fn mux_minimal_mp4(sample: &[u8], w: u32, h: u32) -> Vec<u8> {
    let ftyp = b(b"ftyp", b"av01\0\0\0\0av01isommp41");

    let moov_probe = build_moov(sample, 0, w, h);
    let mdat_payload_offset = (ftyp.len() + moov_probe.len() + 8) as u32;
    let moov = build_moov(sample, mdat_payload_offset, w, h);
    let mdat = b(b"mdat", sample);

    concat(&[&ftyp, &moov, &mdat])
}

fn build_moov(sample: &[u8], chunk_offset: u32, w: u32, h: u32) -> Vec<u8> {
    // mvhd
    let mut mvhd = Vec::new();
    mvhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    mvhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    mvhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
    mvhd.extend_from_slice(&1u32.to_be_bytes()); // duration
    mvhd.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
    mvhd.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
    mvhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    mvhd.extend_from_slice(&[0u8; 8]); // reserved
    mvhd.extend_from_slice(&UNITY_MATRIX);
    mvhd.extend_from_slice(&[0u8; 24]); // predefined
    mvhd.extend_from_slice(&2u32.to_be_bytes()); // next_track_id
    let mvhd = fb(b"mvhd", 0, 0, &mvhd);

    // tkhd
    let mut tkhd = Vec::new();
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    tkhd.extend_from_slice(&1u32.to_be_bytes()); // track_id
    tkhd.extend_from_slice(&0u32.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&1u32.to_be_bytes()); // duration
    tkhd.extend_from_slice(&[0u8; 8]); // reserved
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // layer
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // alternate_group
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // volume (0 for video)
    tkhd.extend_from_slice(&0u16.to_be_bytes()); // reserved
    tkhd.extend_from_slice(&UNITY_MATRIX);
    tkhd.extend_from_slice(&(w << 16).to_be_bytes()); // width 16.16
    tkhd.extend_from_slice(&(h << 16).to_be_bytes()); // height 16.16
    let tkhd = fb(b"tkhd", 0, 0x000007, &tkhd); // enabled|in-movie|in-preview

    // mdhd
    let mut mdhd = Vec::new();
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    mdhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
    mdhd.extend_from_slice(&1u32.to_be_bytes()); // duration
    mdhd.extend_from_slice(&0x55c4u16.to_be_bytes()); // language 'und'
    mdhd.extend_from_slice(&0u16.to_be_bytes()); // predefined
    let mdhd = fb(b"mdhd", 0, 0, &mdhd);

    // hdlr
    let mut hdlr = Vec::new();
    hdlr.extend_from_slice(&0u32.to_be_bytes()); // predefined
    hdlr.extend_from_slice(b"vide"); // handler_type
    hdlr.extend_from_slice(&[0u8; 12]); // reserved
    hdlr.extend_from_slice(b"VideoHandler\0"); // name
    let hdlr = fb(b"hdlr", 0, 0, &hdlr);

    // vmhd
    let mut vmhd = Vec::new();
    vmhd.extend_from_slice(&0u16.to_be_bytes()); // graphicsmode
    vmhd.extend_from_slice(&[0u8; 6]); // opcolor
    let vmhd = fb(b"vmhd", 0, 1, &vmhd);

    // dinf > dref > url (self-contained)
    let url = fb(b"url ", 0, 1, &[]);
    let mut dref = Vec::new();
    dref.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    dref.extend_from_slice(&url);
    let dref = fb(b"dref", 0, 0, &dref);
    let dinf = b(b"dinf", &dref);

    // stsd > av01 (VisualSampleEntry; no av1C — symphonia reads geometry here).
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
    let av01 = b(b"av01", &av01);

    let mut stsd = Vec::new();
    stsd.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsd.extend_from_slice(&av01);
    let stsd = fb(b"stsd", 0, 0, &stsd);

    // stts (1 sample, delta 1)
    let mut stts = Vec::new();
    stts.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stts.extend_from_slice(&1u32.to_be_bytes()); // sample_count
    stts.extend_from_slice(&1u32.to_be_bytes()); // sample_delta
    let stts = fb(b"stts", 0, 0, &stts);

    // stsc (1 chunk, 1 sample/chunk, desc 1)
    let mut stsc = Vec::new();
    stsc.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsc.extend_from_slice(&1u32.to_be_bytes()); // first_chunk
    stsc.extend_from_slice(&1u32.to_be_bytes()); // samples_per_chunk
    stsc.extend_from_slice(&1u32.to_be_bytes()); // sample_description_index
    let stsc = fb(b"stsc", 0, 0, &stsc);

    // stsz (per-sample sizes)
    let mut stsz = Vec::new();
    stsz.extend_from_slice(&0u32.to_be_bytes()); // sample_size 0 => table follows
    stsz.extend_from_slice(&1u32.to_be_bytes()); // sample_count
    stsz.extend_from_slice(&(sample.len() as u32).to_be_bytes()); // entry size
    let stsz = fb(b"stsz", 0, 0, &stsz);

    // stco (chunk offset into mdat payload)
    let mut stco = Vec::new();
    stco.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stco.extend_from_slice(&chunk_offset.to_be_bytes()); // chunk_offset
    let stco = fb(b"stco", 0, 0, &stco);

    // stss (sample 1 is a sync sample → closed GOP)
    let mut stss = Vec::new();
    stss.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stss.extend_from_slice(&1u32.to_be_bytes()); // sample_number
    let stss = fb(b"stss", 0, 0, &stss);

    let stbl = b(
        b"stbl",
        &concat(&[&stsd, &stts, &stsc, &stsz, &stco, &stss]),
    );
    let minf = b(b"minf", &concat(&[&vmhd, &dinf, &stbl]));
    let mdia = b(b"mdia", &concat(&[&mdhd, &hdlr, &minf]));
    let trak = b(b"trak", &concat(&[&tkhd, &mdia]));
    b(b"moov", &concat(&[&mvhd, &trak]))
}
