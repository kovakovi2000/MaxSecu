// Pure transcode-shaping options for the upload screen's resolution/bitrate menu
// (Task 4.2 wires these into the DOM). NO DOM, NO Tauri, NO side effects — just
// types + pure functions, so they unit-test without a browser.
//
// The `TranscodeOptions` shape MUST match the Rust `media-launcher::TranscodeOptions`
// (default externally-tagged serde) byte-for-byte, because it crosses the Tauri
// seam and is deserialized into that Rust enum:
//
//   "Original"                                   -> Resolution::Original / Bitrate::Original
//   { "Height": 720 }                            -> Resolution::Height(720)
//   { "Custom": { "width": W, "height": H } }    -> Resolution::Custom { width, height }
//   { "Kbps": 4000 }                             -> Bitrate::Kbps(4000)
//
// i.e. a unit variant is the bare string; a single-field variant is
// `{ Variant: value }`. JSON.stringify of the types below reproduces that exactly.
//
// The clamp here is a UX nicety only — the Rust side ALWAYS re-clamps against the
// authoritative `VideoBounds`, so this never widens trust. It just keeps the UI
// from showing/sending absurd values. The constants mirror `VideoBounds::default()`
// + the Rust `TranscodeOptions::normalized` clamp.

export type Resolution = "Original" | { Height: number } | { Custom: { width: number; height: number } };
export type Bitrate = "Original" | { Kbps: number };
export interface TranscodeOptions {
  resolution: Resolution;
  bitrate: Bitrate;
}

// Mirror of `VideoBounds::default()` (8K) + the Rust kbps clamp. Kept in sync with
// `crates/client-core/src/video.rs` and `crates/media-launcher/src/transcode_opts.rs`.
export const MAX_WIDTH = 7680;
export const MAX_HEIGHT = 4320;
export const MAX_PIXELS = 33_177_600; // 8K (7680 * 4320)
export const MIN_KBPS = 64;
export const MAX_KBPS = 200_000;

// Smallest even dimension a clamped resolution can collapse to (AV1 4:2:0 needs
// even, non-zero W/H) — mirrors the Rust `MIN_DIM`.
const MIN_DIM = 2;

// Bits-per-pixel target for the AV1 auto-bitrate heuristic. AV1 is efficient, so a
// low bpp still looks good; 0.07 puts 1920x1080x30 at ~4355 kbps and 1280x720x30 at
// ~1935 kbps — sane delivery targets. Tunable; lives in the 0.07-0.1 band.
const AV1_BPP = 0.07;

// Floor `v` to the nearest even number, never below MIN_DIM. Non-finite/negative
// inputs collapse to MIN_DIM (fail-safe). Mirrors the Rust `floor_even`.
function floorEven(v: number): number {
  if (!Number.isFinite(v) || v < MIN_DIM) return MIN_DIM;
  const floored = Math.floor(v);
  return Math.max(floored - (floored % 2), MIN_DIM);
}

// Round-even + clamp a single dimension to [MIN_DIM, cap] (cap itself floored even).
// Mirrors the Rust `even_within`.
function evenWithin(v: number, cap: number): number {
  const capEven = Math.max(cap - (cap % 2), MIN_DIM);
  return Math.min(floorEven(v), capEven);
}

/**
 * AV1 auto-bitrate heuristic (bits-per-pixel): `kbps = round(w * h * fps * BPP / 1000)`,
 * clamped into `[MIN_KBPS, MAX_KBPS]`. Non-finite / zero / negative inputs return the
 * MIN_KBPS floor (fail-safe), never NaN/Infinity.
 */
export function suggestKbps(width: number, height: number, fps: number): number {
  if (
    !Number.isFinite(width) ||
    !Number.isFinite(height) ||
    !Number.isFinite(fps) ||
    width <= 0 ||
    height <= 0 ||
    fps <= 0
  ) {
    return MIN_KBPS;
  }
  const kbps = Math.round((width * height * fps * AV1_BPP) / 1000);
  return Math.min(Math.max(kbps, MIN_KBPS), MAX_KBPS);
}

function normalizeResolution(res: Resolution): Resolution {
  if (res === "Original") return "Original";
  if ("Height" in res) {
    return { Height: evenWithin(res.Height, MAX_HEIGHT) };
  }
  let w = evenWithin(res.Custom.width, MAX_WIDTH);
  let h = evenWithin(res.Custom.height, MAX_HEIGHT);
  // Pixel-count cap: scale the (already per-dim clamped) pair down uniformly,
  // preserving aspect, until w*h fits MAX_PIXELS. Mirrors the Rust sqrt-factor scale.
  const pixels = w * h;
  if (MAX_PIXELS > 0 && pixels > MAX_PIXELS) {
    const scale = Math.sqrt(MAX_PIXELS / pixels);
    w = floorEven(w * scale);
    h = floorEven(h * scale);
  }
  return { Custom: { width: w, height: h } };
}

function normalizeBitrate(bitrate: Bitrate): Bitrate {
  if (bitrate === "Original") return "Original";
  return { Kbps: Math.min(Math.max(Math.floor(bitrate.Kbps), MIN_KBPS), MAX_KBPS) };
}

/**
 * Fail-safe clamp of `opts`, mirroring the Rust `TranscodeOptions::normalized`:
 * Original passes through; Height/Custom dims are floored even + clamped to the 8K
 * caps (Custom additionally scaled down aspect-preserving to fit MAX_PIXELS); Kbps
 * is clamped to `[MIN_KBPS, MAX_KBPS]`. Returns a fresh object.
 */
export function normalizeOptions(opts: TranscodeOptions): TranscodeOptions {
  return {
    resolution: normalizeResolution(opts.resolution),
    bitrate: normalizeBitrate(opts.bitrate),
  };
}

/**
 * Map a menu preset id to a `Resolution`. `"original"` -> `"Original"`; the height
 * presets (`"2160" | "1440" | "1080" | "720" | "480"`) -> `{ Height: n }`. Any
 * unknown preset falls back to `"Original"` (fail-safe). The DOM wiring is Task 4.2.
 */
export function resolutionForPreset(preset: string): Resolution {
  switch (preset) {
    case "2160":
    case "1440":
    case "1080":
    case "720":
    case "480":
      return { Height: Number(preset) };
    case "original":
    default:
      return "Original";
  }
}
