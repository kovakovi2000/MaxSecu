//! Author-side ingest/transcode **worker** library (DESIGN §8.1/D30, Phase 7 Gate 6).
//!
//! This is the system's sole **C carve-out**: the confined, secret-less,
//! network-less process that turns an author's arbitrary source media into the
//! single canonical AV1/CMAF format every *viewer* then decodes. It runs in its own
//! address space (spawned one-shot by `media-launcher::TranscodeLauncher`), holds no
//! keys, and opens no sockets — the author hands it only their own plaintext source.
//!
//! # Two ingest paths (the carve-out is contained)
//! * **Default (no `ffmpeg` feature):** the pure-Rust path — decode the author's
//!   source with safe Rust, AV1-encode with [`rav1e`], and mux to CMAF by hand. No
//!   C is linked or run. This is the committed/tested build.
//! * **`ffmpeg` feature (OFF by default):** the real broad-format ingest via
//!   `ac-ffmpeg` — the ONLY `ac-ffmpeg` link in the workspace. A documented
//!   deferred-op: enabling it requires a provisioned FFmpeg ≤ 7.x dev library on the
//!   host (the ratification flagged the FFmpeg-8.0 pairing as weak ABI evidence).
//!
//! # This task (Gate 6, skeleton)
//! [`transcode`] is a **clearly-marked placeholder** so the crate skeleton compiles
//! and the bin runs the request→result framing end-to-end; Task 6.2 fills in the
//! real `rav1e` encode + CMAF mux (and, under the feature, the `ac-ffmpeg` decode
//! front-end). The encoder/muxer choices and the `#[cfg(feature = "ffmpeg")]` FFI
//! signature below are the seams that work fills in.

use maxsecu_client_core::media::{FragmentEntry, TranscodeRequest, TranscodeResult};

/// A transcode failure inside the worker. Carries no secrets; fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscodeError {
    /// Empty source — nothing to ingest.
    Empty,
    /// The source could not be decoded as a supported format (Task 6.2 / the
    /// `ffmpeg` front-end produce this on real decode failure).
    DecodeFailed,
    /// The real encode/mux pipeline is not wired yet in this build (skeleton). The
    /// default placeholder never returns this for a non-empty source; it exists so
    /// Task 6.2 can surface "no pipeline" distinctly while the skeleton stands.
    NotImplemented,
}

impl std::fmt::Display for TranscodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranscodeError::Empty => write!(f, "empty source media"),
            TranscodeError::DecodeFailed => write!(f, "source media could not be decoded"),
            TranscodeError::NotImplemented => {
                write!(f, "transcode pipeline not wired in this build")
            }
        }
    }
}

impl std::error::Error for TranscodeError {}

/// Transcode one source to the canonical [`TranscodeResult`] (AV1/CMAF + thumbnail
/// + preview + fragment index + optional loudness gain).
///
/// **PLACEHOLDER (Gate 6 skeleton).** This returns a minimal, well-formed stub so
/// the worker bin exercises the full stdin→stdout framing path end-to-end. It only
/// fail-closes on an empty source. **Task 6.2 replaces the body** with the real
/// pipeline: (default) decode → `rav1e` AV1 encode → hand-rolled CMAF mux → derive
/// thumbnail/preview/fragment-index/loudness; or, under `#[cfg(feature = "ffmpeg")]`,
/// the broad-format [`ffmpeg_decode_source`] front-end feeding that same encode/mux.
pub fn transcode(req: &TranscodeRequest) -> Result<TranscodeResult, TranscodeError> {
    if req.source.is_empty() {
        return Err(TranscodeError::Empty);
    }

    // --- PLACEHOLDER body (Task 6.2 fills in the real rav1e encode + CMAF mux) ---
    // A single empty-CMAF fragment covering one notional content chunk, so the
    // result is structurally valid and round-trips through the wire codec. No real
    // media is produced here.
    Ok(TranscodeResult {
        cmaf: Vec::new(),
        thumbnail: Vec::new(),
        preview: Vec::new(),
        fragments: vec![FragmentEntry {
            seq: 0,
            pts_ms: 0,
            chunk_start: 0,
            chunk_len: 1,
        }],
        loudness_gain_db: None,
    })
}

/// The **C ingest front-end** (the carve-out), compiled ONLY under the `ffmpeg`
/// feature. Decodes the author's broad-format source via `ac-ffmpeg` into the raw
/// frames the (default) `rav1e` encode + CMAF mux path consumes.
///
/// **Task 6.2** implements the real FFI decode here (the `#[allow(unsafe_code)]`
/// FFI sites live inside this `#[cfg]` island, matching the `media-worker`
/// rav1d-FFI posture). This skeleton only pins the cfg-gated signature so the
/// `--features ffmpeg` build type-checks; it returns [`TranscodeError::NotImplemented`].
#[cfg(feature = "ffmpeg")]
pub fn ffmpeg_decode_source(_source: &[u8]) -> Result<(), TranscodeError> {
    // Placeholder: Task 6.2 wires the ac-ffmpeg demux/decode here.
    Err(TranscodeError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::media::{decode_transcode_result, encode_transcode_result};
    use maxsecu_client_core::VideoBounds;

    fn req(source: Vec<u8>) -> TranscodeRequest {
        TranscodeRequest {
            source,
            bounds: VideoBounds::default(),
        }
    }

    #[test]
    fn placeholder_transcode_rejects_empty_source() {
        assert_eq!(transcode(&req(vec![])).unwrap_err(), TranscodeError::Empty);
    }

    #[test]
    fn placeholder_transcode_yields_a_wire_roundtrippable_result() {
        let out = transcode(&req(vec![0xAA, 0xBB, 0xCC])).expect("placeholder transcodes");
        // The stub is structurally valid: exactly one fragment, no loudness.
        assert_eq!(out.fragments.len(), 1);
        assert_eq!(out.fragments[0].seq, 0);
        assert!(out.loudness_gain_db.is_none());
        // And it round-trips through the client-core wire codec the worker bin uses.
        let wire = encode_transcode_result(&out);
        assert_eq!(decode_transcode_result(&wire).unwrap(), out);
    }
}
