//! Video decode contracts (DESIGN §8.1/D30, Phase 7). Pure types + untrusted-output
//! validation; NO codec dependency (codecs live in the spawned, confined worker).

use crate::sandbox::{DecodeError, OutputReject};

/// Pre-decode bounds for video (media-sandbox §3 + spec §2.1). Hard ceilings,
/// checked before any allocation, in the main process AND each worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoBounds {
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixels: u64,
    pub max_duration_ms: u64,
    pub max_framerate: u32,
    pub max_fragment_bytes: u64,
    pub max_total_bytes: u64,
    pub max_fragments: u32,
    pub max_audio_channels: u8,
    pub max_sample_rate: u32,
}

impl Default for VideoBounds {
    fn default() -> Self {
        // Values mirror docs/parameters.md §11 (set in Task 1.4).
        VideoBounds {
            max_width: 7680,
            max_height: 4320,
            max_pixels: 33_177_600, // 8K
            max_duration_ms: 30 * 60 * 1000,
            max_framerate: 120,
            max_fragment_bytes: 16 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_fragments: 4096,
            max_audio_channels: 2,
            max_sample_rate: 48_000,
        }
    }
}

/// One decoded I420 (planar YUV 4:2:0) frame from the untrusted worker. RAM-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I420Frame {
    pub width: u32,
    pub height: u32,
    pub pts_ms: u64,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

/// One decoded interleaved-i16 PCM chunk from the untrusted worker. RAM-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcmChunk {
    pub channels: u8,
    pub sample_rate: u32,
    pub pts_ms: u64,
    pub samples: Vec<i16>,
}

#[inline]
fn chroma_dims(w: u32, h: u32) -> (u64, u64) {
    ((w as u64).div_ceil(2), (h as u64).div_ceil(2))
}

/// Validate an untrusted decoded frame BEFORE the renderer (spec §7).
pub fn validate_i420(f: &I420Frame, b: &VideoBounds) -> Result<(), DecodeError> {
    let reject = |reason| Err(DecodeError::OutputRejected { reason });
    if f.width == 0 || f.height == 0 {
        return reject(OutputReject::EmptyDims);
    }
    let (w, h) = (f.width as u64, f.height as u64);
    if f.width > b.max_width || f.height > b.max_height || w * h > b.max_pixels {
        return reject(OutputReject::OverCap);
    }
    let (cw, ch) = chroma_dims(f.width, f.height);
    if f.y.len() as u64 != w * h || f.u.len() as u64 != cw * ch || f.v.len() as u64 != cw * ch {
        return reject(OutputReject::BufferLenMismatch);
    }
    Ok(())
}

/// Validate an untrusted decoded PCM chunk BEFORE WebAudio (spec §7).
pub fn validate_pcm(p: &PcmChunk, b: &VideoBounds) -> Result<(), DecodeError> {
    let reject = |reason| Err(DecodeError::OutputRejected { reason });
    // The audio path reuses the shared `OutputReject` variants from `sandbox.rs`
    // (whose doc-comments read image-centric, RGB/RGBA): `BadChannels` covers the
    // channel-count check and `OverCap` the sample-rate check here.
    if p.channels == 0 || p.channels > b.max_audio_channels {
        return reject(OutputReject::BadChannels);
    }
    if p.sample_rate == 0 || p.sample_rate > b.max_sample_rate {
        return reject(OutputReject::OverCap);
    }
    // `samples` is only consistency-checked (len divisible by channels), NOT
    // magnitude-capped here: per-fragment/total byte size is the session layer's
    // job (`max_fragment_bytes`/`max_total_bytes`). This differs from
    // `validate_i420`, where plane lengths are implicitly magnitude-bounded by the
    // cap-checked dimensions — so the omission here is deliberate, not an oversight.
    if !p.samples.len().is_multiple_of(p.channels as usize) {
        return reject(OutputReject::BufferLenMismatch);
    }
    Ok(())
}

// ===========================================================================
// Duplex decode-session wire protocol (Phase 7, Task 2.2). The launcher and the
// untrusted worker exchange these messages over the confined pipe. Framed,
// little-endian, INJECTIVE (exactly one byte string per message; trailing bytes
// and unknown tags rejected) and bounds-safe (a hostile/truncated message yields
// `Err(VideoProtoError)`, never a panic).
//
// The helpers are deliberately duplicated from `media-worker`'s one-shot `proto`
// module: `client-core` cannot depend on `media-worker`, and a self-contained
// codec is the only way the launcher and worker can agree byte-for-byte. The
// outer u32 length-prefix that frames each message on the pipe is added by the
// Task-3 transport — these codecs operate on a single complete message body.
// ===========================================================================

/// Malformed message on the wire (truncated / trailing / bad length / unknown
/// tag). A unit type: the caller never needs to distinguish *why* a hostile
/// worker message was rejected, only that it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoProtoError;

// ClientMsg tag bytes (launcher → worker).
const C_OPEN: u8 = 1;
const C_FRAGMENT: u8 = 2;
const C_SEEK: u8 = 3;
const C_CLOSE: u8 = 4;

// WorkerMsg tag bytes (worker → launcher).
const W_READY: u8 = 1;
const W_VIDEO: u8 = 2;
const W_AUDIO: u8 = 3;
const W_END_OF_FRAGMENT: u8 = 4;
const W_ERROR: u8 = 5;

// DecodeError sub-tags (inside WorkerMsg::Error).
const E_EMPTY: u8 = 1;
const E_DECODE_FAILED: u8 = 2;
const E_TOO_LARGE: u8 = 3;
const E_OUTPUT_REJECTED: u8 = 4;
const E_WORKER: u8 = 5;

// OutputReject sub-tags (inside DecodeError::OutputRejected).
const R_OVER_CAP: u8 = 1;
const R_EMPTY_DIMS: u8 = 2;
const R_BAD_CHANNELS: u8 = 3;
const R_BUFFER_LEN_MISMATCH: u8 = 4;

/// Launcher -> worker (one message per call; the session feeds many).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMsg {
    Open { bounds: VideoBounds },
    Fragment { seq: u32, bytes: Vec<u8> },
    Seek { fragment_seq: u32 },
    Close,
}

/// Worker -> launcher (streamed; many per fragment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerMsg {
    Ready,
    Video(I420Frame),
    Audio(PcmChunk),
    EndOfFragment { seq: u32 },
    Error(DecodeError),
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_i16(buf: &mut Vec<u8>, v: i16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn take_u32(b: &[u8], at: &mut usize) -> Result<u32, VideoProtoError> {
    let end = at.checked_add(4).ok_or(VideoProtoError)?;
    let slice = b.get(*at..end).ok_or(VideoProtoError)?;
    *at = end;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}
fn take_u64(b: &[u8], at: &mut usize) -> Result<u64, VideoProtoError> {
    let end = at.checked_add(8).ok_or(VideoProtoError)?;
    let slice = b.get(*at..end).ok_or(VideoProtoError)?;
    *at = end;
    Ok(u64::from_le_bytes(slice.try_into().unwrap()))
}
fn take_u8(b: &[u8], at: &mut usize) -> Result<u8, VideoProtoError> {
    let v = *b.get(*at).ok_or(VideoProtoError)?;
    *at += 1;
    Ok(v)
}
fn take_i16(b: &[u8], at: &mut usize) -> Result<i16, VideoProtoError> {
    let end = at.checked_add(2).ok_or(VideoProtoError)?;
    let slice = b.get(*at..end).ok_or(VideoProtoError)?;
    *at = end;
    Ok(i16::from_le_bytes(slice.try_into().unwrap()))
}
fn take_bytes(b: &[u8], at: &mut usize, len: usize) -> Result<Vec<u8>, VideoProtoError> {
    let end = at.checked_add(len).ok_or(VideoProtoError)?;
    let slice = b.get(*at..end).ok_or(VideoProtoError)?;
    *at = end;
    Ok(slice.to_vec())
}

fn put_bounds(buf: &mut Vec<u8>, b: &VideoBounds) {
    put_u32(buf, b.max_width);
    put_u32(buf, b.max_height);
    put_u64(buf, b.max_pixels);
    put_u64(buf, b.max_duration_ms);
    put_u32(buf, b.max_framerate);
    put_u64(buf, b.max_fragment_bytes);
    put_u64(buf, b.max_total_bytes);
    put_u32(buf, b.max_fragments);
    buf.push(b.max_audio_channels);
    put_u32(buf, b.max_sample_rate);
}
fn take_bounds(b: &[u8], at: &mut usize) -> Result<VideoBounds, VideoProtoError> {
    Ok(VideoBounds {
        max_width: take_u32(b, at)?,
        max_height: take_u32(b, at)?,
        max_pixels: take_u64(b, at)?,
        max_duration_ms: take_u64(b, at)?,
        max_framerate: take_u32(b, at)?,
        max_fragment_bytes: take_u64(b, at)?,
        max_total_bytes: take_u64(b, at)?,
        max_fragments: take_u32(b, at)?,
        max_audio_channels: take_u8(b, at)?,
        max_sample_rate: take_u32(b, at)?,
    })
}

fn put_frame(buf: &mut Vec<u8>, f: &I420Frame) {
    put_u32(buf, f.width);
    put_u32(buf, f.height);
    put_u64(buf, f.pts_ms);
    // Plane lengths are bounded well under u32::MAX by VideoBounds (an 8K luma
    // plane is ~33 MB); the `as u32` truncation can never fire on valid input.
    debug_assert!(f.y.len() <= u32::MAX as usize, "I420 y plane len fits u32");
    put_u32(buf, f.y.len() as u32);
    buf.extend_from_slice(&f.y);
    debug_assert!(f.u.len() <= u32::MAX as usize, "I420 u plane len fits u32");
    put_u32(buf, f.u.len() as u32);
    buf.extend_from_slice(&f.u);
    debug_assert!(f.v.len() <= u32::MAX as usize, "I420 v plane len fits u32");
    put_u32(buf, f.v.len() as u32);
    buf.extend_from_slice(&f.v);
}
fn take_frame(b: &[u8], at: &mut usize) -> Result<I420Frame, VideoProtoError> {
    let width = take_u32(b, at)?;
    let height = take_u32(b, at)?;
    let pts_ms = take_u64(b, at)?;
    let y_len = take_u32(b, at)? as usize;
    let y = take_bytes(b, at, y_len)?;
    let u_len = take_u32(b, at)? as usize;
    let u = take_bytes(b, at, u_len)?;
    let v_len = take_u32(b, at)? as usize;
    let v = take_bytes(b, at, v_len)?;
    Ok(I420Frame {
        width,
        height,
        pts_ms,
        y,
        u,
        v,
    })
}

fn put_pcm(buf: &mut Vec<u8>, p: &PcmChunk) {
    buf.push(p.channels);
    put_u32(buf, p.sample_rate);
    put_u64(buf, p.pts_ms);
    // Per-chunk sample count is session-bounded (max_fragment_bytes / max_total_bytes),
    // far under u32::MAX; the `as u32` truncation can never fire on valid input.
    debug_assert!(
        p.samples.len() <= u32::MAX as usize,
        "PCM sample count fits u32"
    );
    put_u32(buf, p.samples.len() as u32);
    for &s in &p.samples {
        put_i16(buf, s);
    }
}
fn take_pcm(b: &[u8], at: &mut usize) -> Result<PcmChunk, VideoProtoError> {
    let channels = take_u8(b, at)?;
    let sample_rate = take_u32(b, at)?;
    let pts_ms = take_u64(b, at)?;
    let count = take_u32(b, at)? as usize;
    let mut samples = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        samples.push(take_i16(b, at)?);
    }
    Ok(PcmChunk {
        channels,
        sample_rate,
        pts_ms,
        samples,
    })
}

fn put_decode_error(buf: &mut Vec<u8>, e: &DecodeError) {
    match e {
        DecodeError::Empty => buf.push(E_EMPTY),
        DecodeError::DecodeFailed => buf.push(E_DECODE_FAILED),
        DecodeError::TooLarge { width, height } => {
            buf.push(E_TOO_LARGE);
            put_u32(buf, *width);
            put_u32(buf, *height);
        }
        DecodeError::OutputRejected { reason } => {
            buf.push(E_OUTPUT_REJECTED);
            buf.push(match reason {
                OutputReject::OverCap => R_OVER_CAP,
                OutputReject::EmptyDims => R_EMPTY_DIMS,
                OutputReject::BadChannels => R_BAD_CHANNELS,
                OutputReject::BufferLenMismatch => R_BUFFER_LEN_MISMATCH,
            });
        }
        DecodeError::Worker => buf.push(E_WORKER),
    }
}
fn take_decode_error(b: &[u8], at: &mut usize) -> Result<DecodeError, VideoProtoError> {
    Ok(match take_u8(b, at)? {
        E_EMPTY => DecodeError::Empty,
        E_DECODE_FAILED => DecodeError::DecodeFailed,
        E_TOO_LARGE => {
            let width = take_u32(b, at)?;
            let height = take_u32(b, at)?;
            DecodeError::TooLarge { width, height }
        }
        E_OUTPUT_REJECTED => {
            let reason = match take_u8(b, at)? {
                R_OVER_CAP => OutputReject::OverCap,
                R_EMPTY_DIMS => OutputReject::EmptyDims,
                R_BAD_CHANNELS => OutputReject::BadChannels,
                R_BUFFER_LEN_MISMATCH => OutputReject::BufferLenMismatch,
                _ => return Err(VideoProtoError),
            };
            DecodeError::OutputRejected { reason }
        }
        E_WORKER => DecodeError::Worker,
        _ => return Err(VideoProtoError),
    })
}

/// Serialize one launcher → worker message (no outer length-prefix).
pub fn encode_client_msg(msg: &ClientMsg) -> Vec<u8> {
    let mut buf = Vec::new();
    match msg {
        ClientMsg::Open { bounds } => {
            buf.push(C_OPEN);
            put_bounds(&mut buf, bounds);
        }
        ClientMsg::Fragment { seq, bytes } => {
            buf.push(C_FRAGMENT);
            put_u32(&mut buf, *seq);
            // Fragment payloads are bounded by VideoBounds::max_fragment_bytes
            // (16 MiB), far under u32::MAX; the `as u32` truncation can never fire.
            debug_assert!(
                bytes.len() <= u32::MAX as usize,
                "fragment payload len fits u32"
            );
            put_u32(&mut buf, bytes.len() as u32);
            buf.extend_from_slice(bytes);
        }
        ClientMsg::Seek { fragment_seq } => {
            buf.push(C_SEEK);
            put_u32(&mut buf, *fragment_seq);
        }
        ClientMsg::Close => buf.push(C_CLOSE),
    }
    buf
}

/// Parse one launcher → worker message body. Rejects truncated, trailing, and
/// unknown-tag input with `Err(VideoProtoError)` — never panics.
pub fn decode_client_msg(bytes: &[u8]) -> Result<ClientMsg, VideoProtoError> {
    let at = &mut 0usize;
    let msg = match take_u8(bytes, at)? {
        C_OPEN => ClientMsg::Open {
            bounds: take_bounds(bytes, at)?,
        },
        C_FRAGMENT => {
            let seq = take_u32(bytes, at)?;
            let len = take_u32(bytes, at)? as usize;
            let payload = take_bytes(bytes, at, len)?;
            ClientMsg::Fragment {
                seq,
                bytes: payload,
            }
        }
        C_SEEK => ClientMsg::Seek {
            fragment_seq: take_u32(bytes, at)?,
        },
        C_CLOSE => ClientMsg::Close,
        _ => return Err(VideoProtoError),
    };
    if *at != bytes.len() {
        return Err(VideoProtoError); // trailing data — reject (injective frame)
    }
    Ok(msg)
}

/// Serialize one worker → launcher message (no outer length-prefix).
pub fn encode_worker_msg(msg: &WorkerMsg) -> Vec<u8> {
    let mut buf = Vec::new();
    match msg {
        WorkerMsg::Ready => buf.push(W_READY),
        WorkerMsg::Video(frame) => {
            buf.push(W_VIDEO);
            put_frame(&mut buf, frame);
        }
        WorkerMsg::Audio(chunk) => {
            buf.push(W_AUDIO);
            put_pcm(&mut buf, chunk);
        }
        WorkerMsg::EndOfFragment { seq } => {
            buf.push(W_END_OF_FRAGMENT);
            put_u32(&mut buf, *seq);
        }
        WorkerMsg::Error(e) => {
            buf.push(W_ERROR);
            put_decode_error(&mut buf, e);
        }
    }
    buf
}

/// Parse one worker → launcher message body. Rejects truncated, trailing, and
/// unknown-tag input with `Err(VideoProtoError)` — never panics.
pub fn decode_worker_msg(bytes: &[u8]) -> Result<WorkerMsg, VideoProtoError> {
    let at = &mut 0usize;
    let msg = match take_u8(bytes, at)? {
        W_READY => WorkerMsg::Ready,
        W_VIDEO => WorkerMsg::Video(take_frame(bytes, at)?),
        W_AUDIO => WorkerMsg::Audio(take_pcm(bytes, at)?),
        W_END_OF_FRAGMENT => WorkerMsg::EndOfFragment {
            seq: take_u32(bytes, at)?,
        },
        W_ERROR => WorkerMsg::Error(take_decode_error(bytes, at)?),
        _ => return Err(VideoProtoError),
    };
    if *at != bytes.len() {
        return Err(VideoProtoError); // trailing data — reject (injective frame)
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_frame() -> I420Frame {
        // 2x2 luma (len 4), 1x1 chroma (len 1 each).
        I420Frame {
            width: 2,
            height: 2,
            pts_ms: 0,
            y: vec![1, 2, 3, 4],
            u: vec![5],
            v: vec![6],
        }
    }

    fn small_pcm() -> PcmChunk {
        PcmChunk {
            channels: 2,
            sample_rate: 48_000,
            pts_ms: 0,
            samples: vec![1, -1, 2, -2],
        }
    }

    #[test]
    fn open_and_fragment_roundtrip() {
        let open = ClientMsg::Open {
            bounds: VideoBounds::default(),
        };
        assert_eq!(decode_client_msg(&encode_client_msg(&open)).unwrap(), open);
        let frag = ClientMsg::Fragment {
            seq: 7,
            bytes: vec![1, 2, 3],
        };
        assert_eq!(decode_client_msg(&encode_client_msg(&frag)).unwrap(), frag);
        let seek = ClientMsg::Seek { fragment_seq: 4 };
        assert_eq!(decode_client_msg(&encode_client_msg(&seek)).unwrap(), seek);
    }

    #[test]
    fn close_roundtrip() {
        let close = ClientMsg::Close;
        assert_eq!(
            decode_client_msg(&encode_client_msg(&close)).unwrap(),
            close
        );
    }

    #[test]
    fn worker_video_audio_roundtrip() {
        let v = WorkerMsg::Video(small_frame());
        assert_eq!(decode_worker_msg(&encode_worker_msg(&v)).unwrap(), v);
        let a = WorkerMsg::Audio(small_pcm());
        assert_eq!(decode_worker_msg(&encode_worker_msg(&a)).unwrap(), a);
    }

    #[test]
    fn worker_ready_eof_roundtrip() {
        let ready = WorkerMsg::Ready;
        assert_eq!(
            decode_worker_msg(&encode_worker_msg(&ready)).unwrap(),
            ready
        );
        let eof = WorkerMsg::EndOfFragment { seq: 99 };
        assert_eq!(decode_worker_msg(&encode_worker_msg(&eof)).unwrap(), eof);
    }

    #[test]
    fn worker_error_variants_roundtrip() {
        for e in [
            DecodeError::Empty,
            DecodeError::DecodeFailed,
            DecodeError::TooLarge {
                width: 64,
                height: 48,
            },
            DecodeError::OutputRejected {
                reason: OutputReject::OverCap,
            },
            DecodeError::OutputRejected {
                reason: OutputReject::EmptyDims,
            },
            DecodeError::OutputRejected {
                reason: OutputReject::BadChannels,
            },
            DecodeError::OutputRejected {
                reason: OutputReject::BufferLenMismatch,
            },
            DecodeError::Worker,
        ] {
            let msg = WorkerMsg::Error(e.clone());
            assert_eq!(decode_worker_msg(&encode_worker_msg(&msg)).unwrap(), msg);
        }
    }

    #[test]
    fn rejects_trailing_and_truncated() {
        let mut b = encode_client_msg(&ClientMsg::Seek { fragment_seq: 1 });
        b.push(0xFF);
        assert!(decode_client_msg(&b).is_err());
        assert!(decode_client_msg(&b[..1]).is_err());
    }

    #[test]
    fn client_empty_and_unknown_tag_rejected() {
        // Empty buffer (no tag) → error.
        assert!(decode_client_msg(&[]).is_err());
        // Unknown leading tag → error.
        assert!(decode_client_msg(&[0xAA]).is_err());
    }

    #[test]
    fn worker_empty_and_unknown_tag_rejected() {
        assert!(decode_worker_msg(&[]).is_err());
        assert!(decode_worker_msg(&[0xAA]).is_err());
    }

    #[test]
    fn worker_unknown_error_subtags_rejected() {
        // Error tag with an unknown DecodeError sub-tag.
        let err_tag = encode_worker_msg(&WorkerMsg::Error(DecodeError::Empty))[0];
        assert!(decode_worker_msg(&[err_tag, 0xFE]).is_err());
        // OutputRejected sub-tag with an unknown OutputReject sub-tag (named
        // const, so the test survives a future DecodeError tag renumbering).
        assert!(decode_worker_msg(&[err_tag, E_OUTPUT_REJECTED, 0xFE]).is_err());
    }

    #[test]
    fn worker_rejects_trailing_and_truncated() {
        // Trailing byte rejection on every worker variant.
        for msg in [
            WorkerMsg::Ready,
            WorkerMsg::Video(small_frame()),
            WorkerMsg::Audio(small_pcm()),
            WorkerMsg::EndOfFragment { seq: 3 },
            WorkerMsg::Error(DecodeError::TooLarge {
                width: 1,
                height: 2,
            }),
        ] {
            let mut wire = encode_worker_msg(&msg);
            // Round-trip clean first.
            assert_eq!(decode_worker_msg(&wire).unwrap(), msg);
            wire.push(0x00);
            assert!(decode_worker_msg(&wire).is_err(), "trailing not rejected");
        }
    }

    #[test]
    fn client_fragment_truncated_at_each_stage() {
        let frag = ClientMsg::Fragment {
            seq: 5,
            bytes: vec![7, 8, 9, 10],
        };
        let wire = encode_client_msg(&frag);
        // Truncating anywhere short of the full body must error (never panic).
        for n in 0..wire.len() {
            assert!(
                decode_client_msg(&wire[..n]).is_err(),
                "prefix len {n} should be rejected"
            );
        }
        assert_eq!(decode_client_msg(&wire).unwrap(), frag);
    }

    #[test]
    fn worker_video_truncated_at_each_stage() {
        let wire = encode_worker_msg(&WorkerMsg::Video(small_frame()));
        for n in 0..wire.len() {
            assert!(
                decode_worker_msg(&wire[..n]).is_err(),
                "prefix len {n} should be rejected"
            );
        }
    }

    #[test]
    fn worker_audio_truncated_at_each_stage() {
        let wire = encode_worker_msg(&WorkerMsg::Audio(small_pcm()));
        for n in 0..wire.len() {
            assert!(
                decode_worker_msg(&wire[..n]).is_err(),
                "prefix len {n} should be rejected"
            );
        }
    }

    #[test]
    fn fragment_oversized_declared_len_rejected() {
        // A hostile declared payload length that overruns the buffer must fail the
        // bounds-safe take, never panic.
        let mut wire = Vec::new();
        wire.push(
            encode_client_msg(&ClientMsg::Fragment {
                seq: 0,
                bytes: vec![],
            })[0],
        );
        super::put_u32(&mut wire, 0); // seq
        super::put_u32(&mut wire, 0xFFFF_FFFF); // declared len, no payload follows
        assert!(decode_client_msg(&wire).is_err());
    }

    #[test]
    fn pcm_roundtrip_over_capacity_clamp() {
        // 5000 samples > the `count.min(4096)` with_capacity clamp. This locks in
        // that the clamp is purely an allocation guard: the decode loop still
        // pushes the true `count`, the Vec grows past 4096, and the chunk round-
        // trips byte-for-byte. (channels=2 → 5000 divisible by channels.)
        let samples: Vec<i16> = (0..5000).map(|i| (i % 7) as i16 - 3).collect();
        let chunk = PcmChunk {
            channels: 2,
            sample_rate: 48_000,
            pts_ms: 42,
            samples,
        };
        let msg = WorkerMsg::Audio(chunk);
        assert_eq!(decode_worker_msg(&encode_worker_msg(&msg)).unwrap(), msg);
    }

    #[test]
    fn client_open_truncated_at_each_stage() {
        // The multi-field VideoBounds body: every prefix short of the full body
        // must error (belt-and-suspenders on the fixed-size takes), never panic.
        let open = ClientMsg::Open {
            bounds: VideoBounds::default(),
        };
        let wire = encode_client_msg(&open);
        for n in 0..wire.len() {
            assert!(
                decode_client_msg(&wire[..n]).is_err(),
                "prefix len {n} should be rejected"
            );
        }
        assert_eq!(decode_client_msg(&wire).unwrap(), open);
    }

    #[test]
    fn worker_error_too_large_truncated_at_each_stage() {
        // The two-u32 TooLarge payload: every short prefix must error.
        let msg = WorkerMsg::Error(DecodeError::TooLarge {
            width: 1920,
            height: 1080,
        });
        let wire = encode_worker_msg(&msg);
        for n in 0..wire.len() {
            assert!(
                decode_worker_msg(&wire[..n]).is_err(),
                "prefix len {n} should be rejected"
            );
        }
        assert_eq!(decode_worker_msg(&wire).unwrap(), msg);
    }

    fn frame(w: u32, h: u32) -> I420Frame {
        let (cw, ch) = ((w as usize).div_ceil(2), (h as usize).div_ceil(2));
        I420Frame {
            width: w,
            height: h,
            pts_ms: 0,
            y: vec![0u8; w as usize * h as usize],
            u: vec![0u8; cw * ch],
            v: vec![0u8; cw * ch],
        }
    }

    #[test]
    fn accepts_consistent_i420() {
        assert!(validate_i420(&frame(4, 4), &VideoBounds::default()).is_ok());
    }

    #[test]
    fn accepts_odd_dimension_chroma() {
        // w=5,h=5 → chroma ceil(5/2)=3 per axis → 3*3 plane.
        assert!(validate_i420(&frame(5, 5), &VideoBounds::default()).is_ok());
    }

    #[test]
    fn rejects_empty_dims() {
        assert_eq!(
            validate_i420(&frame(0, 4), &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::EmptyDims
            })
        );
    }

    #[test]
    fn rejects_plane_length_mismatch() {
        let mut f = frame(4, 4);
        f.y.truncate(3); // hostile/buggy worker under-reads
        assert_eq!(
            validate_i420(&f, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BufferLenMismatch
            })
        );
    }

    #[test]
    fn rejects_u_plane_truncation() {
        // A worker under-reading ONLY the U chroma plane must be caught.
        let mut f = frame(4, 4);
        f.u.truncate(f.u.len() - 1);
        assert_eq!(
            validate_i420(&f, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BufferLenMismatch
            })
        );
    }

    #[test]
    fn rejects_v_plane_truncation() {
        // A worker under-reading ONLY the V chroma plane must be caught.
        let mut f = frame(4, 4);
        f.v.truncate(f.v.len() - 1);
        assert_eq!(
            validate_i420(&f, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BufferLenMismatch
            })
        );
    }

    #[test]
    fn rejects_too_long_plane() {
        // Over-read (plane longer than expected) is rejected too, not just under-read.
        let mut f = frame(4, 4);
        f.y.push(0);
        assert_eq!(
            validate_i420(&f, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BufferLenMismatch
            })
        );
    }

    #[test]
    fn rejects_pixels_over_cap_independently() {
        // Width/height within their caps, but w*h exceeds max_pixels → the
        // `w*h > max_pixels` OR-arm fires on its own.
        let b = VideoBounds {
            max_pixels: 4,
            ..VideoBounds::default()
        };
        assert_eq!(
            validate_i420(&frame(4, 4), &b),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::OverCap
            })
        );
    }

    #[test]
    fn accepts_frame_exactly_at_caps() {
        // Caps are inclusive (`>` not `>=`): dims/pixels equal to the caps pass.
        let b = VideoBounds {
            max_width: 4,
            max_height: 4,
            max_pixels: 16,
            ..VideoBounds::default()
        };
        assert!(validate_i420(&frame(4, 4), &b).is_ok());
    }

    #[test]
    fn rejects_dims_over_cap() {
        let b = VideoBounds {
            max_width: 2,
            ..VideoBounds::default()
        };
        assert_eq!(
            validate_i420(&frame(4, 4), &b),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::OverCap
            })
        );
    }

    #[test]
    fn validates_pcm_shape() {
        let good = PcmChunk {
            channels: 2,
            sample_rate: 48_000,
            pts_ms: 0,
            samples: vec![0i16; 8],
        };
        assert!(validate_pcm(&good, &VideoBounds::default()).is_ok());
        // 7 is not divisible by channels=2 → length mismatch (channels kept in cap).
        let bad = PcmChunk {
            samples: vec![0i16; 7],
            ..good.clone()
        };
        assert_eq!(
            validate_pcm(&bad, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BufferLenMismatch
            })
        );
    }

    #[test]
    fn rejects_pcm_over_channel_cap() {
        let p = PcmChunk {
            channels: 3,
            sample_rate: 48_000,
            pts_ms: 0,
            samples: vec![0i16; 6],
        };
        assert_eq!(
            validate_pcm(&p, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BadChannels
            })
        );
    }

    #[test]
    fn rejects_pcm_zero_channels() {
        let p = PcmChunk {
            channels: 0,
            sample_rate: 48_000,
            pts_ms: 0,
            samples: vec![],
        };
        assert_eq!(
            validate_pcm(&p, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::BadChannels
            })
        );
    }

    #[test]
    fn rejects_pcm_sample_rate_over_cap() {
        let p = PcmChunk {
            channels: 2,
            sample_rate: 96_000,
            pts_ms: 0,
            samples: vec![0i16; 4],
        };
        assert_eq!(
            validate_pcm(&p, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::OverCap
            })
        );
    }

    #[test]
    fn rejects_pcm_zero_sample_rate() {
        // sample_rate == 0 (channels in-cap, len divisible) → OverCap arm.
        let p = PcmChunk {
            channels: 2,
            sample_rate: 0,
            pts_ms: 0,
            samples: vec![0i16; 4],
        };
        assert_eq!(
            validate_pcm(&p, &VideoBounds::default()),
            Err(DecodeError::OutputRejected {
                reason: OutputReject::OverCap
            })
        );
    }
}
