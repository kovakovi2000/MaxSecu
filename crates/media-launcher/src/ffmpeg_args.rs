//! Pure **ffmpeg argv builder** for the universal-video-ingest spawn (Task 3.2).
//!
//! Decisions D-4 (bitrate) / D-5 (resolution) shape the author-side ffmpeg
//! command line; this module turns the user's [`TranscodeOptions`] (clamped
//! against the trusted [`VideoBounds`]) plus the per-job paths into the EXACT
//! argv pinned by the Phase-0 ratification
//! (`docs/superpowers/ratification/2026-06-30-universal-video-ingest-ratification.md` §2),
//! extended with a second output that emits a first-frame thumbnail PNG. The ONE
//! confined ffmpeg run therefore produces BOTH the canonical-source MP4 and the
//! thumbnail, so the codec-free `client-app` never decodes video.
//!
//! This is a **pure function**: no process spawn, no filesystem, no network — it
//! only assembles strings. The caller ([`crate::FfmpegLauncher`], Task 3.3)
//! passes the ffmpeg program path separately and spawns the confined process.
//!
//! # Security properties (the review checks these)
//!
//! * **No argv injection.** Every flag and every path is a SEPARATE
//!   [`OsString`] element — there is no shell and no string-concatenation of a
//!   path into a flag. Paths are carried as [`OsStr`](std::ffi::OsStr) bytes
//!   (never lossily stringified), so a hostile basename cannot smuggle options.
//! * **`-protocol_whitelist file`.** Defense-in-depth atop the no-network
//!   AppContainer: ffmpeg may only open local files, never a network/other
//!   protocol, so a crafted input filename can't make it open a URL.
//! * **`-i` immediately precedes the input path**, so a `-`-leading basename
//!   cannot be misparsed as an option.
//! * **All clamping goes through [`TranscodeOptions::normalized`]** — the trusted
//!   [`VideoBounds`] bound the user-supplied resolution/bitrate before they reach
//!   ffmpeg, so an absurd/hostile value can't drive a pathological encode.

use std::ffi::OsString;
use std::path::Path;

use maxsecu_client_core::video::VideoBounds;

use crate::transcode_opts::{Bitrate, Resolution, TranscodeOptions};

/// Default SVT-AV1 `-preset` (speed/quality trade-off; lower = slower/better).
/// `6` favours quality (a step slower than the old `8`); it does NOT affect the
/// canonical fragment layout (ratification §2) and is freely tunable per deployment.
pub const DEFAULT_PRESET: u32 = 6;

/// Default SVT-AV1 constant-quality `-crf` used when the caller leaves the bitrate
/// at [`Bitrate::Original`] (the default path). SVT-AV1's own fallback rate control
/// (~CRF 35) is visibly lossy at 1080p; `18` is a near-lossless, essentially
/// transparent target (larger files — can exceed the source). An explicit
/// [`Bitrate::Kbps`] instead switches to bitrate-targeted `-b:v` (below). This is a
/// pure quality knob — it does NOT change the canonical AV1/AAC fragment layout the
/// viewer decodes, so it is freely tunable.
pub const DEFAULT_CRF: u32 = 18;

/// Default closed-GOP keyframe interval (`-g` / SVT-AV1 `keyint`). This is the
/// **fragment granularity**: one closed GOP per canonical fragment, so the
/// fragment duration is `GOP / source_fps` (≈1 s at ~48 fps). The Phase-0 spike
/// validated a 60-sample 4K GOP at 6.43 MB — comfortably under the 16 MiB
/// `VideoBounds::max_fragment_bytes` cap (ratification §4/§6). Tunable.
pub const DEFAULT_GOP: u32 = 48;

/// Longest edge (px) the first-frame thumbnail is downscaled to via
/// `scale='min(THUMBNAIL_MAX_DIM,iw)':-2` (height auto-rounded even, aspect
/// preserved; never upscales). A modest preview size.
pub const THUMBNAIL_MAX_DIM: u32 = 1024;

/// Fixed AAC-LC audio bitrate (`-b:a`). Audio is not user-configurable (D-5);
/// the canonical output is always `-c:a aac -b:a 128k -ac 2`.
pub const AUDIO_BITRATE: &str = "128k";

/// Build the ffmpeg argv (everything AFTER the program path) for one ingest job.
///
/// Produces the pinned main output (AV1 + AAC-LC canonical MP4 at `output`)
/// followed, in the SAME command, by a first-frame thumbnail PNG at `thumbnail`.
/// `opts` is [`normalized`](TranscodeOptions::normalized) against `bounds` first,
/// so all user-supplied resolution/bitrate values are clamped to the trusted
/// caps before they reach ffmpeg.
///
/// Each flag and each path is a discrete [`OsString`] element — no shell, no
/// concatenation — so there is no argv-injection surface and paths are never
/// lossily stringified.
pub fn build_ffmpeg_args(
    input: &Path,
    output: &Path,
    thumbnail: &Path,
    opts: &TranscodeOptions,
    bounds: &VideoBounds,
    threads: u16,
) -> Vec<OsString> {
    // Clamp the user-supplied shaping against the trusted bounds FIRST.
    let opts = opts.normalized(bounds);

    let mut args: Vec<OsString> = Vec::new();
    // Push one argv element. A macro (not a closure) so it never holds a borrow of
    // `args` across the path pushes; accepts anything `Into<OsString>` — a `&str`
    // flag, an owned `String`, or a path's `&OsStr` (carried verbatim, never
    // lossily stringified, so there is no argv-injection surface).
    macro_rules! arg {
        ($v:expr) => {
            args.push(OsString::from($v))
        };
    }

    // --- Main output: AV1 video + AAC-LC audio --------------------------------
    arg!("-y");
    // Machine-readable progress to stderr (fd 2, already the bounded capture pipe):
    // the launcher parses `Duration:` + `out_time`/`progress=` lines live for the UI
    // progress bar AND the progress-based stall watchdog (Task A/B). `pipe:2` writes
    // to the EXISTING stderr pipe — no new stream, no media on it.
    arg!("-progress");
    arg!("pipe:2");
    // Defense in depth: ffmpeg may only open local files (never a URL/other
    // protocol), atop the no-network AppContainer.
    arg!("-protocol_whitelist");
    arg!("file");
    arg!("-i");
    arg!(input.as_os_str());

    arg!("-vf");
    arg!(main_scale_filter(&opts.resolution));

    // Force 8-bit I420 — the only pixel layout the viewer decoder accepts.
    arg!("-pix_fmt");
    arg!("yuv420p");

    // Encoder worker-thread budget (Task 7.3): the confined transcode honors the
    // user's `transcode_threads` performance setting. Passed as a plain argv value
    // into the confined ffmpeg (never an env var — consistent with every other flag
    // here, so it cannot influence confinement). Clamp to >=1: a 0 would ask ffmpeg
    // to auto-pick all cores, defeating the user's budget.
    arg!("-threads");
    arg!(threads.max(1).to_string());

    arg!("-c:v");
    arg!("libsvtav1");
    arg!("-preset");
    arg!(DEFAULT_PRESET.to_string());
    arg!("-g");
    arg!(DEFAULT_GOP.to_string());
    // keyint re-asserts the GOP to SVT-AV1's parser; pred-struct=1 = low-delay
    // (decode order == presentation order ⇒ no ctts needed).
    arg!("-svtav1-params");
    arg!(format!("keyint={DEFAULT_GOP}:pred-struct=1"));

    // Rate control (mutually exclusive):
    //   * Bitrate::Kbps(n)   → bitrate-targeted `-b:v {n}k` (explicit user target).
    //   * Bitrate::Original  → constant-quality `-crf DEFAULT_CRF`. SVT-AV1's own
    //     fallback (no -b:v, no -crf) is ~CRF 35 and visibly lossy at 1080p, so we
    //     pin an explicit high-quality CRF instead of leaving it to the encoder.
    match opts.bitrate {
        Bitrate::Kbps(n) => {
            arg!("-b:v");
            arg!(format!("{n}k"));
        }
        Bitrate::Original => {
            arg!("-crf");
            arg!(DEFAULT_CRF.to_string());
        }
    }

    arg!("-c:a");
    arg!("aac");
    arg!("-b:a");
    arg!(AUDIO_BITRATE);
    arg!("-ac");
    arg!("2");

    // Fragmented-MP4: single continuous fMP4 (init moov + moof/mdat fragments)
    // proven to play natively in WebView2 via the Media Source Extensions path.
    // Must be placed before the output path so it applies ONLY to the main mp4
    // (not to the thumbnail second output).
    arg!("-movflags");
    arg!("+frag_keyframe+empty_moov+default_base_moof");

    arg!(output.as_os_str());

    // --- Second output: one first-frame thumbnail PNG -------------------------
    // ffmpeg applies output options to the NEXT output file, so these precede the
    // thumbnail path. One decoded first frame, downscaled, emitted as PNG.
    arg!("-map");
    arg!("0:v:0");
    arg!("-frames:v");
    arg!("1");
    arg!("-vf");
    arg!(thumb_scale_filter());
    arg!("-y");
    arg!(thumbnail.as_os_str());

    args
}

/// The `-vf` scale filter for the MAIN output (D-5 / ratification §7). Always yields
/// even W/H (AV1 4:2:0 requires it) AND **square pixels** (`setsar=1`) at the correct
/// DISPLAY shape, so a genuinely anamorphic (SAR≠1) source renders at the right aspect
/// (D-7 / spec §8) — not just byte-correct on square-pixel sources.
///
/// SAR-awareness: ffmpeg's scale expressions expose `sar` (input sample aspect ratio)
/// and `dar` (input display aspect ratio). For a square-pixel source both collapse to
/// the storage ratio (`sar == 1`), so every branch below is byte-identical to the prior
/// even-only coercion — the existing e2e/round-trips are unaffected. ffmpeg evaluates
/// `sar`/`dar` as 1 / the storage ratio when the source SAR is undefined or 0 (verified
/// with the vendored ffmpeg), so `iw*sar` / `h*dar` never collapse to 0.
fn main_scale_filter(res: &Resolution) -> String {
    match res {
        // Resample WIDTH by the input SAR so anamorphic pixels become square at the true
        // display width, force both dims even, and stamp the output square (`setsar=1`).
        Resolution::Original => "scale='trunc(iw*sar/2)*2':'trunc(ih/2)*2',setsar=1".to_string(),
        // Fixed display height; width = height × input DISPLAY aspect (`dar`) so an
        // anamorphic source keeps its display shape (a naive `-2:h` would preserve the
        // STORAGE ratio and distort). Even-rounded; output marked square.
        Resolution::Height(h) => format!("scale='trunc({h}*dar/2)*2':{h},setsar=1"),
        // Exact (already-even) DISPLAY dims; mark them square-pixel.
        Resolution::Custom { width, height } => format!("scale={width}:{height},setsar=1"),
    }
}

/// The `-vf` scale filter for the THUMBNAIL: downscale the first frame so its
/// width is at most [`THUMBNAIL_MAX_DIM`] (never upscaling), height auto-rounded
/// to an even number with aspect preserved.
fn thumb_scale_filter() -> String {
    format!("scale='min({THUMBNAIL_MAX_DIM},iw)':-2")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn bounds() -> VideoBounds {
        VideoBounds::default()
    }

    fn paths() -> (PathBuf, PathBuf, PathBuf) {
        (
            PathBuf::from("/jobs/in put-video.mp4"),
            PathBuf::from("/jobs/out.mp4"),
            PathBuf::from("/jobs/thumb.png"),
        )
    }

    /// Find the position of a flag among the argv elements.
    fn pos(args: &[OsString], flag: &str) -> Option<usize> {
        args.iter().position(|a| a == flag)
    }

    fn contains(args: &[OsString], flag: &str) -> bool {
        pos(args, flag).is_some()
    }

    /// The element immediately after the (first) occurrence of `flag`, as a
    /// lossy string for convenience in assertions.
    fn value_after(args: &[OsString], flag: &str) -> String {
        let i = pos(args, flag).unwrap_or_else(|| panic!("flag {flag} not present"));
        args[i + 1].to_string_lossy().into_owned()
    }

    #[test]
    fn original_original_pins_the_canonical_argv() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions {
            resolution: Resolution::Original,
            bitrate: Bitrate::Original,
        };
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 4);

        // D-4: Original bitrate ⇒ NO -b:v, but an explicit high-quality -crf instead
        // of SVT-AV1's lossy default rate control.
        assert!(
            !contains(&args, "-b:v"),
            "Original bitrate must not emit -b:v"
        );
        assert_eq!(
            value_after(&args, "-crf"),
            DEFAULT_CRF.to_string(),
            "Original bitrate must pin an explicit high-quality -crf"
        );

        // The SAR-aware even-guard scale filter: width resampled by the input SAR to
        // square pixels, both dims even, output marked square (`setsar=1`). For a square
        // source `sar == 1` so this is byte-identical to the prior even-only coercion.
        assert_eq!(
            value_after(&args, "-vf"),
            "scale='trunc(iw*sar/2)*2':'trunc(ih/2)*2',setsar=1"
        );
        // The fix is present: SAR-aware width term + an explicit square-pixel stamp.
        assert!(
            value_after(&args, "-vf").contains("iw*sar"),
            "Original scale must be SAR-aware"
        );
        assert!(
            value_after(&args, "-vf").ends_with("setsar=1"),
            "output must be marked square-pixel"
        );

        // Core pinned flags + their values.
        assert_eq!(value_after(&args, "-c:v"), "libsvtav1");
        assert_eq!(value_after(&args, "-c:a"), "aac");
        assert_eq!(value_after(&args, "-pix_fmt"), "yuv420p");
        assert!(contains(&args, "-protocol_whitelist"));
        assert_eq!(value_after(&args, "-protocol_whitelist"), "file");
        assert_eq!(value_after(&args, "-g"), DEFAULT_GOP.to_string());
        assert_eq!(value_after(&args, "-preset"), DEFAULT_PRESET.to_string());
        assert_eq!(
            value_after(&args, "-svtav1-params"),
            format!("keyint={DEFAULT_GOP}:pred-struct=1")
        );
        assert_eq!(value_after(&args, "-b:a"), AUDIO_BITRATE);
        assert_eq!(value_after(&args, "-ac"), "2");

        // Both output paths appear as their own discrete args.
        assert!(
            args.iter().any(|a| a == o.as_os_str()),
            "output mp4 present"
        );
        assert!(args.iter().any(|a| a == t.as_os_str()), "thumbnail present");

        // Thumbnail second-output options.
        assert_eq!(value_after(&args, "-map"), "0:v:0");
        assert_eq!(value_after(&args, "-frames:v"), "1");
    }

    #[test]
    fn height_720_and_kbps_4000() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions {
            resolution: Resolution::Height(720),
            bitrate: Bitrate::Kbps(4000),
        };
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 4);

        // Height: width = height × input display aspect (`dar`), even, output square.
        // For a square source `dar` is the storage ratio, matching the prior `-2:h`.
        assert_eq!(value_after(&args, "-vf"), "scale='trunc(720*dar/2)*2':720,setsar=1");
        assert!(contains(&args, "-b:v"), "Kbps must emit -b:v");
        assert_eq!(value_after(&args, "-b:v"), "4000k");
        // Explicit bitrate uses -b:v rate control, NOT constant-quality -crf.
        assert!(
            !contains(&args, "-crf"),
            "explicit Kbps must not also emit -crf"
        );
    }

    #[test]
    fn custom_odd_dims_are_normalized_to_even() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions {
            resolution: Resolution::Custom {
                width: 1921,
                height: 1081,
            },
            bitrate: Bitrate::Original,
        };
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 4);
        // normalize floors each dim to even ⇒ 1920x1080; output marked square-pixel.
        assert_eq!(value_after(&args, "-vf"), "scale=1920:1080,setsar=1");
    }

    #[test]
    fn absurd_values_are_clamped_via_normalize() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions {
            resolution: Resolution::Custom {
                width: 100_000,
                height: 100_000,
            },
            bitrate: Bitrate::Kbps(10_000_000),
        };
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 4);
        // Per-dim clamp to the 8K caps (7680x4320 fits max_pixels exactly); square-pixel.
        assert_eq!(value_after(&args, "-vf"), "scale=7680:4320,setsar=1");
        // Bitrate clamped down to the ceiling.
        assert_eq!(
            value_after(&args, "-b:v"),
            format!("{}k", crate::transcode_opts::MAX_BITRATE_KBPS)
        );
    }

    #[test]
    fn ffmpeg_args_include_thread_budget() {
        // The confined transcode honors the user's `transcode_threads` budget:
        // the argv carries `-threads <n>` (Task 7.3).
        let (i, o, t) = paths();
        let opts = TranscodeOptions::default();
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 3);
        let pos = args
            .iter()
            .position(|a| a == "-threads")
            .expect("-threads present");
        assert_eq!(args[pos + 1], "3");
    }

    #[test]
    fn thread_budget_is_clamped_to_at_least_one() {
        // A 0 budget would ask ffmpeg to auto-pick all cores; clamp to >=1.
        let (i, o, t) = paths();
        let opts = TranscodeOptions::default();
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 0);
        assert_eq!(value_after(&args, "-threads"), "1");
    }

    #[test]
    fn main_output_is_fragmented_mp4() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions::default();
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 4);

        assert!(
            contains(&args, "-movflags"),
            "-movflags must be present for fragmented-MP4"
        );
        assert_eq!(
            value_after(&args, "-movflags"),
            "+frag_keyframe+empty_moov+default_base_moof"
        );
    }

    #[test]
    fn paths_are_discrete_args_no_injection() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions::default();
        let args = build_ffmpeg_args(&i, &o, &t, &opts, &bounds(), 4);

        // -i is immediately followed by the EXACT input path (its own OsString),
        // so a '-'-leading basename can't be misparsed as an option and nothing
        // is concatenated onto a flag.
        let ii = pos(&args, "-i").expect("-i present");
        assert_eq!(args[ii + 1].as_os_str(), i.as_os_str());

        // Output + thumbnail likewise appear verbatim as their own elements.
        assert!(args.iter().any(|a| a.as_os_str() == o.as_os_str()));
        assert!(args.iter().any(|a| a.as_os_str() == t.as_os_str()));

        // No element fuses a path into a flag (e.g. "-i/jobs/..").
        for a in &args {
            let s = a.to_string_lossy();
            assert!(
                !(s.starts_with("-i") && s.len() > 2),
                "no flag/path concatenation: {s}"
            );
        }
    }
}
