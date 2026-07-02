//! Author-side **transcode shaping options** (resolution / bitrate) for the
//! universal-video-ingest ffmpeg spawn (decision D-5).
//!
//! In the chosen "two confined spawns" topology these options shape **only the
//! ffmpeg argv** (the next task builds the argv from them) on the author side —
//! resolution + bitrate. They cross the Tauri seam (UI → client-app) and feed the
//! ffmpeg-argv builder; they never cross a worker wire protocol of their own —
//! the re-mux worker gets ffmpeg's canonical output bytes directly. They
//! therefore live in this **codec-free** launcher crate (which owns the ffmpeg
//! spawn), keeping client-core's TCB and client-app codec-free.
//!
//! # JSON shape (serde, default externally-tagged enums)
//!
//! The Tauri command (de)serializes these across the seam, so the UI mirrors this
//! exact shape:
//!
//! ```json
//! { "resolution": "Original",                          "bitrate": "Original" }
//! { "resolution": { "Height": 720 },                   "bitrate": { "Kbps": 4000 } }
//! { "resolution": { "Custom": { "width": 1920, "height": 1080 } }, "bitrate": "Original" }
//! ```
//!
//! i.e. a unit variant is the bare string `"Original"`; a single-field variant is
//! `{ "<Variant>": <value> }` (`Height` carries a number, `Custom` a
//! `{width,height}` object, `Kbps` a number). Simple, stable, trivially built in TS.

use maxsecu_client_core::video::VideoBounds;
use serde::{Deserialize, Serialize};

/// Lowest target audio/video bitrate (kbps) [`Bitrate::Kbps`] is clamped UP to —
/// below this ffmpeg output is uselessly degraded; a hostile `0`/`1` can't drive a
/// pathological encode.
pub const MIN_BITRATE_KBPS: u32 = 64;

/// Highest target bitrate (kbps) [`Bitrate::Kbps`] is clamped DOWN to — a generous
/// 200 Mbps ceiling (well above any sane delivery target) so an absurd/hostile
/// value (e.g. `u32::MAX`) can't drive ffmpeg into a pathological allocation/encode.
pub const MAX_BITRATE_KBPS: u32 = 200_000;

/// Smallest even dimension a clamped resolution can collapse to (avoids a 0-sized
/// scale; AV1 4:2:0 needs even, non-zero W/H).
const MIN_DIM: u32 = 2;

/// Target output resolution shaping (decision D-5).
///
/// * [`Resolution::Original`] — keep the source resolution unchanged.
/// * [`Resolution::Height`] — scale to exactly this height, **preserving aspect**
///   (ffmpeg derives the width). The UI presets 2160/1440/1080/720/480 map here.
/// * [`Resolution::Custom`] — exact output dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution {
    /// Keep the source resolution unchanged.
    Original,
    /// Scale to this height, preserving aspect ratio.
    Height(u32),
    /// Exact output dimensions.
    Custom { width: u32, height: u32 },
}

/// Target output bitrate shaping (decision D-4 default: preserve the source).
///
/// * [`Bitrate::Original`] — preserve the source bitrate (the default).
/// * [`Bitrate::Kbps`] — explicit target bitrate in kbps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bitrate {
    /// Preserve the source bitrate.
    Original,
    /// Explicit target bitrate, in kbps.
    Kbps(u32),
}

/// Author-side transcode shaping: resolution + bitrate for the ffmpeg argv.
///
/// [`Default`] is `{ Original, Original }` (D-4: defaults preserve the source).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeOptions {
    pub resolution: Resolution,
    pub bitrate: Bitrate,
}

impl Default for TranscodeOptions {
    fn default() -> Self {
        // D-4: defaults preserve the source (no forced rescale / re-bitrate).
        TranscodeOptions {
            resolution: Resolution::Original,
            bitrate: Bitrate::Original,
        }
    }
}

/// Floor `v` to the nearest even number (AV1 4:2:0 needs even dims), never below
/// [`MIN_DIM`].
fn floor_even(v: u32) -> u32 {
    (v & !1).max(MIN_DIM)
}

/// Round-even + clamp a single dimension to `[MIN_DIM, cap]` (cap itself floored
/// even). `cap` is a `VideoBounds` width/height ceiling.
fn even_within(v: u32, cap: u32) -> u32 {
    let cap_even = (cap & !1).max(MIN_DIM);
    floor_even(v).min(cap_even)
}

impl TranscodeOptions {
    /// Return a fail-safe **normalized** copy clamped against `bounds`.
    ///
    /// Clamping rules (the source of truth the ffmpeg-argv builder relies on):
    ///
    /// * `Resolution::Original` / `Bitrate::Original` — passed through unchanged
    ///   (defaults preserve the source).
    /// * `Resolution::Height(h)` — `h` floored to EVEN and clamped to
    ///   `[MIN_DIM, bounds.max_height]`. (Width is ffmpeg-derived from the source
    ///   aspect, so it is bounded at encode time; only the height is shaped here.)
    /// * `Resolution::Custom { width, height }` — each dim floored to EVEN and
    ///   clamped to `bounds.max_width` / `bounds.max_height`; then if
    ///   `width * height > bounds.max_pixels` the pair is scaled DOWN preserving
    ///   aspect (uniform `sqrt(max_pixels / pixels)` factor) and re-floored even,
    ///   so the output never exceeds the pixel cap.
    /// * `Bitrate::Kbps(n)` — clamped to `[MIN_BITRATE_KBPS, MAX_BITRATE_KBPS]` so a
    ///   hostile/absurd value can't drive ffmpeg pathologically.
    pub fn normalized(&self, bounds: &VideoBounds) -> TranscodeOptions {
        TranscodeOptions {
            resolution: normalize_resolution(&self.resolution, bounds),
            bitrate: normalize_bitrate(&self.bitrate),
        }
    }
}

fn normalize_resolution(res: &Resolution, bounds: &VideoBounds) -> Resolution {
    match res {
        Resolution::Original => Resolution::Original,
        Resolution::Height(h) => Resolution::Height(even_within(*h, bounds.max_height)),
        Resolution::Custom { width, height } => {
            let mut w = even_within(*width, bounds.max_width);
            let mut h = even_within(*height, bounds.max_height);
            // Pixel-count cap: scale the (already per-dim clamped) pair down
            // uniformly, preserving aspect, until w*h fits max_pixels.
            let pixels = w as u64 * h as u64;
            if bounds.max_pixels > 0 && pixels > bounds.max_pixels {
                let scale = (bounds.max_pixels as f64 / pixels as f64).sqrt();
                w = floor_even((w as f64 * scale) as u32);
                h = floor_even((h as f64 * scale) as u32);
            }
            Resolution::Custom {
                width: w,
                height: h,
            }
        }
    }
}

fn normalize_bitrate(bitrate: &Bitrate) -> Bitrate {
    match bitrate {
        Bitrate::Original => Bitrate::Original,
        Bitrate::Kbps(n) => Bitrate::Kbps((*n).clamp(MIN_BITRATE_KBPS, MAX_BITRATE_KBPS)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> VideoBounds {
        VideoBounds::default()
    }

    #[test]
    fn default_is_original_original() {
        assert_eq!(
            TranscodeOptions::default(),
            TranscodeOptions {
                resolution: Resolution::Original,
                bitrate: Bitrate::Original,
            }
        );
    }

    #[test]
    fn serde_round_trip_each_variant() {
        let cases = [
            TranscodeOptions {
                resolution: Resolution::Original,
                bitrate: Bitrate::Original,
            },
            TranscodeOptions {
                resolution: Resolution::Height(720),
                bitrate: Bitrate::Kbps(4000),
            },
            TranscodeOptions {
                resolution: Resolution::Custom {
                    width: 1921,
                    height: 1081,
                },
                bitrate: Bitrate::Original,
            },
        ];
        for opts in cases {
            let json = serde_json::to_string(&opts).unwrap();
            let back: TranscodeOptions = serde_json::from_str(&json).unwrap();
            assert_eq!(opts, back, "round-trip mismatch for {json}");
        }
    }

    #[test]
    fn serde_json_shape_is_stable() {
        // Unit variants serialize as a bare string; single-field variants as
        // `{ "<Variant>": <value> }`. The UI relies on this exact shape.
        let opts = TranscodeOptions {
            resolution: Resolution::Height(720),
            bitrate: Bitrate::Kbps(4000),
        };
        assert_eq!(
            serde_json::to_string(&opts).unwrap(),
            r#"{"resolution":{"Height":720},"bitrate":{"Kbps":4000}}"#
        );

        let original = TranscodeOptions {
            resolution: Resolution::Original,
            bitrate: Bitrate::Original,
        };
        assert_eq!(
            serde_json::to_string(&original).unwrap(),
            r#"{"resolution":"Original","bitrate":"Original"}"#
        );

        let custom = TranscodeOptions {
            resolution: Resolution::Custom {
                width: 1920,
                height: 1080,
            },
            bitrate: Bitrate::Original,
        };
        assert_eq!(
            serde_json::to_string(&custom).unwrap(),
            r#"{"resolution":{"Custom":{"width":1920,"height":1080}},"bitrate":"Original"}"#
        );
    }

    #[test]
    fn normalize_custom_rounds_to_even() {
        let opts = TranscodeOptions {
            resolution: Resolution::Custom {
                width: 1921,
                height: 1081,
            },
            bitrate: Bitrate::Original,
        };
        assert_eq!(
            opts.normalized(&bounds()).resolution,
            Resolution::Custom {
                width: 1920,
                height: 1080,
            }
        );
    }

    #[test]
    fn normalize_height_clamps_to_max_height() {
        let opts = TranscodeOptions {
            resolution: Resolution::Height(9000), // > 4320 (default max_height)
            bitrate: Bitrate::Original,
        };
        assert_eq!(
            opts.normalized(&bounds()).resolution,
            Resolution::Height(4320)
        );
    }

    #[test]
    fn normalize_custom_clamps_dims_to_caps() {
        let opts = TranscodeOptions {
            resolution: Resolution::Custom {
                width: 100_000,
                height: 100_000,
            },
            bitrate: Bitrate::Original,
        };
        // Per-dim clamp to (max_width=7680, max_height=4320); 7680*4320 fits 8K
        // max_pixels exactly so no further pixel-cap scaling.
        assert_eq!(
            opts.normalized(&bounds()).resolution,
            Resolution::Custom {
                width: 7680,
                height: 4320,
            }
        );
    }

    #[test]
    fn normalize_custom_clamps_to_max_pixels_preserving_aspect() {
        // Tight pixel cap (1080p worth of pixels) with roomy per-dim caps; a 4K
        // custom request must scale down by sqrt(0.25)=0.5 to 1920x1080.
        let tight = VideoBounds {
            max_pixels: 1920 * 1080,
            ..VideoBounds::default()
        };
        let opts = TranscodeOptions {
            resolution: Resolution::Custom {
                width: 3840,
                height: 2160,
            },
            bitrate: Bitrate::Original,
        };
        let norm = opts.normalized(&tight).resolution;
        match norm {
            Resolution::Custom { width, height } => {
                assert_eq!((width, height), (1920, 1080));
                assert!((width as u64) * (height as u64) <= tight.max_pixels);
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn normalize_bitrate_clamps_floor_and_ceiling() {
        let hi = TranscodeOptions {
            resolution: Resolution::Original,
            bitrate: Bitrate::Kbps(10_000_000),
        };
        assert_eq!(
            hi.normalized(&bounds()).bitrate,
            Bitrate::Kbps(MAX_BITRATE_KBPS)
        );

        let lo = TranscodeOptions {
            resolution: Resolution::Original,
            bitrate: Bitrate::Kbps(1),
        };
        assert_eq!(
            lo.normalized(&bounds()).bitrate,
            Bitrate::Kbps(MIN_BITRATE_KBPS)
        );

        let ok = TranscodeOptions {
            resolution: Resolution::Original,
            bitrate: Bitrate::Kbps(4000),
        };
        assert_eq!(ok.normalized(&bounds()).bitrate, Bitrate::Kbps(4000));
    }

    #[test]
    fn normalize_original_passes_through() {
        let opts = TranscodeOptions::default();
        assert_eq!(opts.normalized(&bounds()), TranscodeOptions::default());
    }
}
