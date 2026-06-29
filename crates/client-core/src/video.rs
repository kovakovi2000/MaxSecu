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

#[cfg(test)]
mod tests {
    use super::*;

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
