//! Author-side ingest/transcode **worker** library (DESIGN §8.1/D30, Phase 7 Gate 6).
//!
//! This is the system's sole **C carve-out**: the confined, secret-less,
//! network-less process that turns an author's arbitrary source media into the
//! single canonical AV1/CMAF format every *viewer* then decodes. It runs in its own
//! address space (spawned one-shot by `media-launcher::TranscodeLauncher`), holds no
//! keys, and opens no sockets — the author hands it only their own plaintext source.
//!
//! # Two ingest paths (the carve-out is contained)
//! * **Default (no `ffmpeg` feature):** the pure-Rust path implemented here — parse
//!   the author's **already-decoded raw frames** ([the raw-frame source
//!   format](#raw-frame-source-format)), AV1-encode each frame with [`rav1e`], mux to
//!   self-contained CMAF fragments by hand, and lay them out **chunk-aligned**. No C
//!   is linked or run. This is the committed/tested build.
//! * **`ffmpeg` feature (OFF by default):** the real broad-format ingest via
//!   `ac-ffmpeg` — the ONLY `ac-ffmpeg` link in the workspace. A documented
//!   deferred-op: enabling it requires a provisioned FFmpeg ≤ 7.x dev library on the
//!   host (the ratification flagged the FFmpeg-8.0 pairing as weak ABI evidence). It
//!   is the front-end that turns arbitrary media INTO the raw-frame form the default
//!   pipeline below consumes; see [`ffmpeg_decode_source`].
//!
//! # Raw-frame source format
//! Without ffmpeg the worker cannot demux arbitrary mp4/mov, so the default path
//! consumes a tiny, fully-documented **raw-frame** container — the author's
//! "already-decoded source". Layout (all integers little-endian):
//!
//! | Offset | Size | Field                                                  |
//! |--------|------|--------------------------------------------------------|
//! | 0      | 8    | magic = [`RAW_MAGIC`] (`b"MXRAWV01"`)                   |
//! | 8      | 4    | `width`  (u32)                                          |
//! | 12     | 4    | `height` (u32)                                          |
//! | 16     | 4    | `frame_count` (u32)                                     |
//! | 20     | 4    | `fps` (u32, ≥ 1)                                        |
//! | 24     | …    | `frame_count` × (`width`·`height`·3) **RGB24** bytes    |
//!
//! Frames are tightly packed, row-major, 3 bytes/pixel (R,G,B), no row padding. The
//! header is parsed and **every cap in [`VideoBounds`] is enforced BEFORE any frame
//! buffer is allocated** (the decompression-bomb guard): an over-cap or
//! over-/under-declared-length source is rejected up front, never driving an
//! allocation past the bytes actually present.
//!
//! # Canonical output (default path)
//! Each frame becomes its **own closed GOP** (one `rav1e` `still_picture` keyframe →
//! independently decodable), muxed into a self-contained `av01` MP4 fragment, then
//! padded with a trailing ISO-BMFF `free` box so the fragment occupies a
//! **contiguous, chunk-aligned** byte range in `cmaf` ([`TRANSCODE_CHUNK_SIZE`]). The
//! emitted [`FragmentEntry`] index maps each fragment to its exact whole-chunk range,
//! so `client-app::chunks_for_fragment(seq)` resolves a fragment to its contiguous
//! upload-chunk span. Thumbnail + preview are PNG (derived from the first frame, like
//! the image path). **Audio (AAC) + loudness normalization are DEFERRED** to the
//! ffmpeg carve-out (needs an AAC encoder + a loudnorm filter): `loudness_gain_db` is
//! always `None` and the default-path `cmaf` carries no audio track.
//!
//! # Large-source note (Task-6.4 / deferred)
//! `media-launcher::framing::MAX_FRAME_BYTES` (64 MiB) caps one
//! `TranscodeRequest.source`, but a real raw clip is far larger. Delivering a large
//! source (temp file / chunked stream / a raised request-frame ceiling) is a
//! **Task-6.4 / deferred concern** — NOT addressed here; the tested path uses a small
//! clip that fits the 64 MiB ceiling.

use maxsecu_client_core::media::{FragmentEntry, TranscodeRequest, TranscodeResult};
use maxsecu_client_core::video::VideoBounds;
use maxsecu_client_core::{MediaBounds, RustImageCodec, Transcoder};

use rav1e::prelude::{ChromaSampling, Config, Context, EncoderConfig, EncoderStatus};

/// Magic prefix of the [raw-frame source format](index.html#raw-frame-source-format).
pub const RAW_MAGIC: &[u8; 8] = b"MXRAWV01";

/// Fixed raw-frame header length: magic(8) + width/height/frame_count/fps (4×4).
const RAW_HEADER_LEN: usize = 8 + 4 * 4;

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
    /// The source could not be parsed as the raw-frame format (bad magic, short
    /// header, or a body whose length does not match the declared geometry).
    DecodeFailed,
    /// The declared geometry exceeds the pre-decode [`VideoBounds`] caps — rejected
    /// before any frame buffer is allocated (the decompression-bomb guard).
    TooLarge,
    /// The `rav1e` encode or the hand-rolled CMAF mux failed (should not happen on
    /// in-bounds input; surfaced rather than silently producing a bad stream).
    EncodeFailed,
    /// The real broad-format ingest is not wired in this build (the `ffmpeg`
    /// front-end is a documented deferred stub — see [`ffmpeg_decode_source`]).
    NotImplemented,
}

impl std::fmt::Display for TranscodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranscodeError::Empty => write!(f, "empty source media"),
            TranscodeError::DecodeFailed => write!(f, "source media could not be parsed"),
            TranscodeError::TooLarge => write!(f, "source media exceeds the decode caps"),
            TranscodeError::EncodeFailed => write!(f, "canonical encode/mux failed"),
            TranscodeError::NotImplemented => {
                write!(f, "broad-format ingest not wired in this build")
            }
        }
    }
}

impl std::error::Error for TranscodeError {}

/// A parsed, bounds-checked view over the raw-frame source. `frames` borrows the
/// per-frame RGB24 byte slices out of the original source (no copy).
struct RawSource<'a> {
    width: u32,
    height: u32,
    fps: u32,
    frames: Vec<&'a [u8]>,
}

/// Parse + **bounds-check** the raw-frame source, rejecting anything over `bounds`
/// BEFORE allocating any frame buffer (the decompression-bomb guard). Fail-closed:
/// a bad magic, a short/over-/under-declared body, or an over-cap geometry yields an
/// `Err`, never a panic and never an out-of-bounds index.
fn parse_raw_source<'a>(
    src: &'a [u8],
    bounds: &VideoBounds,
) -> Result<RawSource<'a>, TranscodeError> {
    if src.len() < RAW_HEADER_LEN || &src[0..8] != RAW_MAGIC {
        return Err(TranscodeError::DecodeFailed);
    }
    let rd = |off: usize| u32::from_le_bytes(src[off..off + 4].try_into().unwrap());
    let width = rd(8);
    let height = rd(12);
    let frame_count = rd(16);
    let fps = rd(20);

    // Degenerate geometry is a parse failure (no frames / no time base).
    if width == 0 || height == 0 || frame_count == 0 || fps == 0 {
        return Err(TranscodeError::DecodeFailed);
    }

    // --- caps, all in u64 so nothing overflows before the comparison ---
    let (w, h, fc) = (width as u64, height as u64, frame_count as u64);
    if width > bounds.max_width || height > bounds.max_height || w * h > bounds.max_pixels {
        return Err(TranscodeError::TooLarge);
    }
    if fps > bounds.max_framerate {
        return Err(TranscodeError::TooLarge);
    }
    if fc > bounds.max_fragments as u64 {
        return Err(TranscodeError::TooLarge);
    }
    // Duration: each frame lasts 1/fps s; the whole clip is frame_count/fps s.
    let duration_ms = fc.saturating_mul(1000) / fps as u64;
    if duration_ms > bounds.max_duration_ms {
        return Err(TranscodeError::TooLarge);
    }
    // Raw decoded volume the pipeline will allocate; bound it before allocating.
    // All arithmetic is checked (uniform with `fc.checked_mul` below): the operands
    // are already cap-bounded by the `max_pixels`/`max_total_bytes` early-returns and
    // `req.bounds` is set only by the TCB launcher (never the author), so overflow is
    // reachable only via a pathological launcher misconfig — fail-closed regardless.
    let frame_bytes = w
        .checked_mul(h)
        .and_then(|x| x.checked_mul(3))
        .ok_or(TranscodeError::TooLarge)?;
    let total_raw = fc
        .checked_mul(frame_bytes)
        .ok_or(TranscodeError::TooLarge)?;
    if total_raw > bounds.max_total_bytes {
        return Err(TranscodeError::TooLarge);
    }

    // The body MUST be exactly the declared frames — an over-declared frame_count
    // (a hostile header with no backing data) or trailing junk is rejected here,
    // before any per-frame slice is taken.
    let expected = (RAW_HEADER_LEN as u64)
        .checked_add(total_raw)
        .ok_or(TranscodeError::DecodeFailed)?;
    if src.len() as u64 != expected {
        return Err(TranscodeError::DecodeFailed);
    }

    // Safe to slice now: every range is within the verified length.
    let fb = frame_bytes as usize;
    let mut frames = Vec::with_capacity(frame_count as usize);
    for i in 0..frame_count as usize {
        let start = RAW_HEADER_LEN + i * fb;
        frames.push(&src[start..start + fb]);
    }

    Ok(RawSource {
        width,
        height,
        fps,
        frames,
    })
}

/// Transcode one source to the canonical [`TranscodeResult`]: an AV1/CMAF stream,
/// thumbnail, preview, and a chunk-aligned fragment index (`loudness_gain_db` is
/// always `None` in the default path — audio is the ffmpeg deferred-op).
///
/// Pipeline (default, pure-Rust): [`parse_raw_source`] (bounds-checked) → per frame
/// RGB→I420 → `rav1e` `still_picture` AV1 encode (one closed GOP) → hand-rolled
/// self-contained `av01` CMAF mux → pad to a whole [`TRANSCODE_CHUNK_SIZE`] multiple
/// with a `free` box → append to `cmaf` and record the fragment's whole-chunk range.
/// Thumbnail + preview are derived from the first frame via the shared pure-Rust
/// image path. Fail-closed on a bad source, over-bounds geometry, or an encode/mux
/// error.
pub fn transcode(req: &TranscodeRequest) -> Result<TranscodeResult, TranscodeError> {
    if req.source.is_empty() {
        return Err(TranscodeError::Empty);
    }
    let raw = parse_raw_source(&req.source, &req.bounds)?;
    let (w, h) = (raw.width, raw.height);

    let mut cmaf: Vec<u8> = Vec::new();
    let mut fragments: Vec<FragmentEntry> = Vec::with_capacity(raw.frames.len());

    for (i, frame) in raw.frames.iter().enumerate() {
        let (y, u, v) = rgb24_to_i420(frame, w as usize, h as usize);
        let sample = encode_av1_still(w, h, &y, &u, &v)?;
        let fragment = pad_to_chunk(mux_av01_fragment(&sample, w, h));

        // Defense-in-depth: a single fragment must not exceed the per-fragment cap.
        if fragment.len() as u64 > req.bounds.max_fragment_bytes {
            return Err(TranscodeError::TooLarge);
        }

        let offset = cmaf.len();
        debug_assert_eq!(offset % TRANSCODE_CHUNK_SIZE, 0, "fragments stay aligned");
        debug_assert_eq!(fragment.len() % TRANSCODE_CHUNK_SIZE, 0, "fragment padded");

        fragments.push(FragmentEntry {
            seq: i as u32,
            // Integer division keeps pts_ms monotonic non-decreasing (the player's
            // index validator requires that).
            pts_ms: (i as u64) * 1000 / raw.fps as u64,
            chunk_start: (offset / TRANSCODE_CHUNK_SIZE) as u64,
            chunk_len: (fragment.len() / TRANSCODE_CHUNK_SIZE) as u64,
        });
        cmaf.extend_from_slice(&fragment);
    }

    // Total volume bound (the encoded stream is smaller than the raw frames, but
    // bound it anyway so a pathological expansion cannot blow the cap silently).
    if cmaf.len() as u64 > req.bounds.max_total_bytes {
        return Err(TranscodeError::TooLarge);
    }

    let (thumbnail, preview) = derive_thumbnail_preview(raw.frames[0], w, h)?;

    Ok(TranscodeResult {
        cmaf,
        thumbnail,
        preview,
        fragments,
        // Audio + loudness normalization are the ffmpeg deferred-op (AAC encode +
        // loudnorm filter); the default path emits no audio and no gain.
        loudness_gain_db: None,
    })
}

/// The **C ingest front-end** (the carve-out), compiled ONLY under the `ffmpeg`
/// feature. It would decode the author's broad-format source via `ac-ffmpeg` into
/// the [raw-frame form](index.html#raw-frame-source-format) the default `rav1e`
/// encode + CMAF mux path consumes.
///
/// **Deferred stub (intentionally NOT a real decode).** The ratification flagged the
/// only available host FFmpeg (8.0) as unsupported/weak-ABI evidence, so no
/// unvalidated-ABI C decode is written here. A future Gate-6-deferred increment wires
/// the real `ac-ffmpeg` demux/decode against a vendored FFmpeg ≤ 7.x inside the
/// confined worker; the `#[allow(unsafe_code)]` FFI sites will live inside this
/// `#[cfg]` island (matching the `media-worker` rav1d-FFI posture). It returns
/// [`TranscodeError::NotImplemented`].
#[cfg(feature = "ffmpeg")]
pub fn ffmpeg_decode_source(_source: &[u8]) -> Result<Vec<u8>, TranscodeError> {
    // DEFERRED: Gate-6-deferred wires the real ac-ffmpeg decode against a vendored
    // FFmpeg <= 7.x. No unvalidated-ABI C is run in the committed build.
    Err(TranscodeError::NotImplemented)
}

// ---------------------------------------------------------------------------
// RGB24 -> I420 (pure-Rust BT.601 integer conversion). Content is not asserted by
// the view-path round-trip (only geometry is), but a correct conversion keeps the
// fragments visually faithful.
// ---------------------------------------------------------------------------

/// Convert a tightly-packed RGB24 frame to planar I420 (YUV 4:2:0, 8-bit). Chroma
/// planes are `ceil(w/2) × ceil(h/2)`; each chroma sample averages its (edge-clamped)
/// 2×2 luma block.
fn rgb24_to_i420(rgb: &[u8], w: usize, h: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut y = vec![0u8; w * h];
    for i in 0..w * h {
        let r = rgb[i * 3] as i32;
        let g = rgb[i * 3 + 1] as i32;
        let b = rgb[i * 3 + 2] as i32;
        // BT.601 luma: (77R + 150G + 29B) / 256.
        y[i] = (((77 * r + 150 * g + 29 * b) >> 8).clamp(0, 255)) as u8;
    }

    let cw = w.div_ceil(2);
    let ch = h.div_ceil(2);
    let mut u = vec![0u8; cw * ch];
    let mut v = vec![0u8; cw * ch];
    for cy in 0..ch {
        for cx in 0..cw {
            let (mut rs, mut gs, mut bs, mut n) = (0i32, 0i32, 0i32, 0i32);
            for dy in 0..2 {
                for dx in 0..2 {
                    let sx = (cx * 2 + dx).min(w - 1);
                    let sy = (cy * 2 + dy).min(h - 1);
                    let idx = (sy * w + sx) * 3;
                    rs += rgb[idx] as i32;
                    gs += rgb[idx + 1] as i32;
                    bs += rgb[idx + 2] as i32;
                    n += 1;
                }
            }
            let (r, g, b) = (rs / n, gs / n, bs / n);
            // BT.601 chroma, +128 bias.
            u[cy * cw + cx] = ((((-43 * r - 85 * g + 128 * b) >> 8) + 128).clamp(0, 255)) as u8;
            v[cy * cw + cx] = ((((128 * r - 107 * g - 21 * b) >> 8) + 128).clamp(0, 255)) as u8;
        }
    }
    (y, u, v)
}

// ---------------------------------------------------------------------------
// AV1 encode (rav1e, asm OFF). One self-contained still-picture keyframe per frame
// (a closed GOP of one), per the Gate-1 ratification §2.3 API.
// ---------------------------------------------------------------------------

/// Encode one I420 frame as a self-contained AV1 still picture (a one-keyframe
/// closed GOP whose packet carries its own sequence-header OBU — decodable with no
/// separate `av1C`).
fn encode_av1_still(
    w: u32,
    h: u32,
    y: &[u8],
    u: &[u8],
    v: &[u8],
) -> Result<Vec<u8>, TranscodeError> {
    let (wu, hu) = (w as usize, h as usize);
    let cw = wu.div_ceil(2);

    let mut enc = EncoderConfig::with_speed_preset(10);
    enc.width = wu;
    enc.height = hu;
    enc.bit_depth = 8;
    enc.chroma_sampling = ChromaSampling::Cs420;
    enc.still_picture = true;

    let cfg = Config::new().with_encoder_config(enc);
    let mut ctx: Context<u8> = cfg
        .new_context()
        .map_err(|_| TranscodeError::EncodeFailed)?;

    let mut frame = ctx.new_frame();
    frame.planes[0].copy_from_raw_u8(y, wu, 1);
    frame.planes[1].copy_from_raw_u8(u, cw, 1);
    frame.planes[2].copy_from_raw_u8(v, cw, 1);

    ctx.send_frame(frame)
        .map_err(|_| TranscodeError::EncodeFailed)?;
    ctx.flush();

    let mut out = Vec::new();
    loop {
        match ctx.receive_packet() {
            Ok(pkt) => out.extend_from_slice(&pkt.data),
            Err(EncoderStatus::Encoded) => continue,
            Err(EncoderStatus::LimitReached) | Err(EncoderStatus::NeedMoreData) => break,
            Err(_) => return Err(TranscodeError::EncodeFailed),
        }
    }
    if out.is_empty() {
        return Err(TranscodeError::EncodeFailed);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Chunk alignment: pad a fragment up to a whole TRANSCODE_CHUNK_SIZE multiple with a
// trailing ISO-BMFF `free` box, so each fragment occupies a contiguous, chunk-aligned
// byte range AND still demuxes (a `free` box is standard free-space a compliant
// reader skips — verified by the symphonia round-trip test).
// ---------------------------------------------------------------------------

/// Pad `fragment` up to a whole multiple of [`TRANSCODE_CHUNK_SIZE`] by appending a
/// single `free` box. A `free` box needs ≥ 8 bytes (size + type), so a 1..7-byte gap
/// is bumped by one whole chunk to leave room — the result is always chunk-aligned.
fn pad_to_chunk(mut fragment: Vec<u8>) -> Vec<u8> {
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

// ---------------------------------------------------------------------------
// Thumbnail + preview: PNG-encode the first frame (pure-Rust, no extra dep), then run
// the shared `client-core::RustImageCodec` to produce the aspect-preserving
// thumbnail + preview (the same pure-Rust image path the image upload uses).
// ---------------------------------------------------------------------------

/// Derive a PNG thumbnail + preview from the first frame. The frame is PNG-encoded
/// in-crate (stored-zlib, no extra dependency) and handed to the shared pure-Rust
/// [`RustImageCodec`], which downscales it within the thumbnail/preview boxes.
fn derive_thumbnail_preview(
    first: &[u8],
    w: u32,
    h: u32,
) -> Result<(Vec<u8>, Vec<u8>), TranscodeError> {
    let png = png_encode_rgb24(first, w, h);
    let streams = RustImageCodec
        .transcode(&png, &MediaBounds::default())
        .map_err(|_| TranscodeError::EncodeFailed)?;
    Ok((streams.thumbnail, streams.preview))
}

/// Minimal pure-Rust PNG encoder for an 8-bit RGB image, using a **stored (level-0)**
/// zlib stream — no compression, no external dependency, correct and decodable by the
/// `image` crate. The output is only ever fed to the downscaler and never shipped, so
/// stored deflate (slightly larger) is fine.
fn png_encode_rgb24(rgb: &[u8], w: u32, h: u32) -> Vec<u8> {
    let row = w as usize * 3;
    // Filtered scanlines: each row prefixed with filter byte 0 (None).
    let mut raw = Vec::with_capacity((row + 1) * h as usize);
    for y in 0..h as usize {
        raw.push(0);
        raw.extend_from_slice(&rgb[y * row..(y + 1) * row]);
    }

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // bit depth 8, color type 2 (RGB), defaults

    let mut out: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    out.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    out.extend_from_slice(&png_chunk(b"IDAT", &zlib_stored(&raw)));
    out.extend_from_slice(&png_chunk(b"IEND", &[]));
    out
}

/// One PNG chunk: `[u32 len][4-byte type][data][u32 CRC32(type||data)]`.
fn png_chunk(typ: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + data.len());
    v.extend_from_slice(&(data.len() as u32).to_be_bytes());
    v.extend_from_slice(typ);
    v.extend_from_slice(data);
    let mut crc_in = Vec::with_capacity(4 + data.len());
    crc_in.extend_from_slice(typ);
    crc_in.extend_from_slice(data);
    v.extend_from_slice(&crc32(&crc_in).to_be_bytes());
    v
}

/// Wrap `data` in a zlib stream of **stored** (uncompressed) deflate blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78u8, 0x01]; // zlib header (CMF=0x78, FLG=0x01).
    if data.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]); // one empty final block
    } else {
        let mut i = 0;
        while i < data.len() {
            let n = (data.len() - i).min(0xFFFF);
            let last = i + n >= data.len();
            out.push(if last { 1 } else { 0 }); // BFINAL, BTYPE=00 (stored)
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(&(!(n as u16)).to_le_bytes());
            out.extend_from_slice(&data[i..i + n]);
            i += n;
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// CRC-32 (IEEE, reflected, poly 0xEDB88320) — PNG chunk checksum.
fn crc32(buf: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Adler-32 — zlib stream checksum.
fn adler32(buf: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in buf {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Minimal ISO-BMFF / CMAF muxer (hand-rolled; NO external muxer crate, NO ffmpeg).
// Emits one self-contained MP4 per fragment carrying exactly one `av01` sample (one
// keyframe = one closed GOP). Re-implemented in this crate from the Gate-3.1 pattern
// (`media-worker/tests/support`); each fragment is independently demuxable by
// symphonia and decodable by rav1d.
// ---------------------------------------------------------------------------

/// Box: `[u32 size][u8;4 type][payload]`.
fn box_(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
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

/// Wrap one AV1 sample in a self-contained non-fragmented MP4 (`ftyp` + `moov` +
/// `mdat`). The `stco` chunk offset is the byte offset of the `mdat` payload, so
/// `moov` is built once with a placeholder (to learn its fixed length), then rebuilt
/// with the real offset (same width → identical length).
fn mux_av01_fragment(sample: &[u8], w: u32, h: u32) -> Vec<u8> {
    let ftyp = box_(b"ftyp", b"av01\0\0\0\0av01isommp41");

    let moov_probe = build_moov(sample, 0, w, h);
    let mdat_payload_offset = (ftyp.len() + moov_probe.len() + 8) as u32;
    let moov = build_moov(sample, mdat_payload_offset, w, h);
    let mdat = box_(b"mdat", sample);

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
    let mvhd = fbox(b"mvhd", 0, 0, &mvhd);

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
    let tkhd = fbox(b"tkhd", 0, 0x000007, &tkhd); // enabled|in-movie|in-preview

    // mdhd
    let mut mdhd = Vec::new();
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // creation
    mdhd.extend_from_slice(&0u32.to_be_bytes()); // modification
    mdhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
    mdhd.extend_from_slice(&1u32.to_be_bytes()); // duration
    mdhd.extend_from_slice(&0x55c4u16.to_be_bytes()); // language 'und'
    mdhd.extend_from_slice(&0u16.to_be_bytes()); // predefined
    let mdhd = fbox(b"mdhd", 0, 0, &mdhd);

    // hdlr
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

    // dinf > dref > url (self-contained)
    let url = fbox(b"url ", 0, 1, &[]);
    let mut dref = Vec::new();
    dref.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    dref.extend_from_slice(&url);
    let dref = fbox(b"dref", 0, 0, &dref);
    let dinf = box_(b"dinf", &dref);

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
    let av01 = box_(b"av01", &av01);

    let mut stsd = Vec::new();
    stsd.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsd.extend_from_slice(&av01);
    let stsd = fbox(b"stsd", 0, 0, &stsd);

    // stts (1 sample, delta 1)
    let mut stts = Vec::new();
    stts.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stts.extend_from_slice(&1u32.to_be_bytes()); // sample_count
    stts.extend_from_slice(&1u32.to_be_bytes()); // sample_delta
    let stts = fbox(b"stts", 0, 0, &stts);

    // stsc (1 chunk, 1 sample/chunk, desc 1)
    let mut stsc = Vec::new();
    stsc.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsc.extend_from_slice(&1u32.to_be_bytes()); // first_chunk
    stsc.extend_from_slice(&1u32.to_be_bytes()); // samples_per_chunk
    stsc.extend_from_slice(&1u32.to_be_bytes()); // sample_description_index
    let stsc = fbox(b"stsc", 0, 0, &stsc);

    // stsz (per-sample sizes)
    let mut stsz = Vec::new();
    stsz.extend_from_slice(&0u32.to_be_bytes()); // sample_size 0 => table follows
    stsz.extend_from_slice(&1u32.to_be_bytes()); // sample_count
    stsz.extend_from_slice(&(sample.len() as u32).to_be_bytes()); // entry size
    let stsz = fbox(b"stsz", 0, 0, &stsz);

    // stco (chunk offset into mdat payload)
    let mut stco = Vec::new();
    stco.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stco.extend_from_slice(&chunk_offset.to_be_bytes()); // chunk_offset
    let stco = fbox(b"stco", 0, 0, &stco);

    // stss (sample 1 is a sync sample → closed GOP)
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
    let trak = box_(b"trak", &concat(&[&tkhd, &mdia]));
    box_(b"moov", &concat(&[&mvhd, &trak]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::media::{decode_transcode_result, encode_transcode_result};

    /// Build a raw-frame source ([the documented format](super)) with a deterministic
    /// per-frame gradient.
    fn make_raw_source(w: u32, h: u32, frames: u32, fps: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(RAW_MAGIC);
        v.extend_from_slice(&w.to_le_bytes());
        v.extend_from_slice(&h.to_le_bytes());
        v.extend_from_slice(&frames.to_le_bytes());
        v.extend_from_slice(&fps.to_le_bytes());
        for f in 0..frames {
            for i in 0..(w * h) {
                v.push(((i + f) & 0xff) as u8); // R
                v.push(((i / w) & 0xff) as u8); // G
                v.push((f.wrapping_mul(40) & 0xff) as u8); // B
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

    #[test]
    fn rejects_empty_source() {
        assert_eq!(transcode(&req(vec![])).unwrap_err(), TranscodeError::Empty);
    }

    #[test]
    fn rejects_garbage_source_without_panic() {
        // No magic → DecodeFailed; arbitrary short junk must never panic.
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
    fn rejects_over_bounds_geometry_pre_alloc() {
        // A header declaring 100k×100k with NO backing frame data: the cap check
        // must fire on the declared geometry before any allocation, never panicking
        // on the absent body.
        let mut src = Vec::new();
        src.extend_from_slice(RAW_MAGIC);
        src.extend_from_slice(&100_000u32.to_le_bytes()); // width  > max_width
        src.extend_from_slice(&100_000u32.to_le_bytes()); // height > max_height
        src.extend_from_slice(&1u32.to_le_bytes()); // frame_count
        src.extend_from_slice(&30u32.to_le_bytes()); // fps
        assert_eq!(transcode(&req(src)).unwrap_err(), TranscodeError::TooLarge);
    }

    #[test]
    fn rejects_body_length_mismatch() {
        // Declares 2 frames of 4×4 but supplies only the header → DecodeFailed
        // (over-declared frame_count is rejected before slicing).
        let mut src = Vec::new();
        src.extend_from_slice(RAW_MAGIC);
        src.extend_from_slice(&4u32.to_le_bytes());
        src.extend_from_slice(&4u32.to_le_bytes());
        src.extend_from_slice(&2u32.to_le_bytes());
        src.extend_from_slice(&10u32.to_le_bytes());
        assert_eq!(
            transcode(&req(src)).unwrap_err(),
            TranscodeError::DecodeFailed
        );
    }

    #[test]
    fn produces_chunk_aligned_contiguous_fragment_index() {
        let frames = 3u32;
        let out = transcode(&req(make_raw_source(16, 16, frames, 10))).expect("transcodes");

        // One fragment per frame, seq 0..N.
        assert_eq!(out.fragments.len(), frames as usize);
        for (k, fr) in out.fragments.iter().enumerate() {
            assert_eq!(fr.seq, k as u32);
            assert!(fr.chunk_len >= 1, "each fragment covers >= 1 chunk");
        }

        // Chunk-aligned + contiguous starting at 0 (exactly what
        // client-app::parse_fragment_index enforces over the same field shape).
        assert_eq!(out.fragments[0].chunk_start, 0);
        let mut last_pts = 0u64;
        for k in 0..out.fragments.len() {
            if k > 0 {
                let prev = &out.fragments[k - 1];
                assert_eq!(
                    out.fragments[k].chunk_start,
                    prev.chunk_start + prev.chunk_len,
                    "fragments are contiguous"
                );
            }
            assert!(out.fragments[k].pts_ms >= last_pts, "pts non-decreasing");
            last_pts = out.fragments[k].pts_ms;
        }

        // The cmaf stream is exactly the concatenation of whole-chunk fragments.
        let last = out.fragments.last().unwrap();
        let total_chunks = last.chunk_start + last.chunk_len;
        assert_eq!(out.cmaf.len(), total_chunks as usize * TRANSCODE_CHUNK_SIZE);
        assert_eq!(out.cmaf.len() % TRANSCODE_CHUNK_SIZE, 0);

        // Audio + loudness are the ffmpeg deferred-op: none here.
        assert!(out.loudness_gain_db.is_none());
        // Thumbnail + preview are present (validated as real PNGs in the
        // integration round-trip test).
        assert!(!out.thumbnail.is_empty());
        assert!(!out.preview.is_empty());

        // The whole result round-trips through the client-core wire codec the
        // worker bin uses.
        let wire = encode_transcode_result(&out);
        assert_eq!(decode_transcode_result(&wire).unwrap(), out);
    }

    #[test]
    fn pad_to_chunk_always_aligns_and_handles_tiny_gaps() {
        // Exact multiple → untouched.
        let exact = vec![0u8; TRANSCODE_CHUNK_SIZE * 2];
        assert_eq!(pad_to_chunk(exact.clone()).len(), exact.len());
        // A 1-byte gap (len = 2*CS - 1) cannot fit an 8-byte free box in 1 byte, so
        // it is bumped a whole chunk; the result is still aligned.
        let near = vec![0u8; TRANSCODE_CHUNK_SIZE * 2 - 1];
        let padded = pad_to_chunk(near);
        assert_eq!(padded.len() % TRANSCODE_CHUNK_SIZE, 0);
        assert!(padded.len() >= TRANSCODE_CHUNK_SIZE * 2);
        // A generic small fragment pads up to one chunk.
        let small = vec![0u8; 100];
        assert_eq!(pad_to_chunk(small).len(), TRANSCODE_CHUNK_SIZE);
    }
}
