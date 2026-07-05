//! Pure **ffmpeg argv builder** for the remux-first universal-video-ingest spawn.
//!
//! The ingest is now **copy-first**: a source whose video is already H.264/AV1 and
//! whose audio is already AAC (and no rescale/re-rate is requested) is STREAM-COPIED
//! into the canonical streamable fMP4 — no re-encode. Otherwise the needed streams
//! are re-encoded to H.264 (GPU `h264_nvenc`/`h264_amf` when available, else the
//! always-present `libx264` CPU fallback) + AAC. The per-stream decision is taken by
//! [`plan_ingest`] from the [`crate::probe::ProbeResult`]; the caller then maps it to
//! a [`VideoArg`] (with the resolved [`H264Encoder`]) and calls [`build_ingest_args`].
//! The ONE confined ffmpeg run still produces BOTH the canonical MP4 and the
//! first-frame thumbnail, so the codec-free `client-app` never decodes video.
//!
//! These are **pure functions**: no process spawn, no filesystem, no network — they
//! only assemble strings. The caller ([`crate::FfmpegLauncher`]) passes the ffmpeg
//! program path separately and spawns the confined process.
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

use crate::probe::{AudioCodec, ProbeResult, VideoCodec};
use crate::transcode_opts::{Bitrate, Resolution, TranscodeOptions};

/// Default libx264 CRF for the CPU fallback (visually near-lossless), on a 0..=51
/// scale (lower = better). Used when the caller leaves the bitrate at
/// [`Bitrate::Original`]; an explicit [`Bitrate::Kbps`] switches to `-b:v` instead.
pub const DEFAULT_CRF: u32 = 18;

/// Default NVENC constant-quality value (near-transparent H.264).
pub const DEFAULT_NVENC_CQ: u32 = 19;
/// Default AMF constant-QP value.
pub const DEFAULT_AMF_QP: u32 = 20;

/// Default closed-GOP keyframe interval (`-g`). This is the **fragment granularity**:
/// one closed GOP per canonical fragment, so the fragment duration is
/// `GOP / source_fps` (≈1 s at ~48 fps). Under the 16 MiB
/// `VideoBounds::max_fragment_bytes` cap (ratification §4/§6). Tunable.
pub const DEFAULT_GOP: u32 = 48;

/// Longest edge (px) the first-frame thumbnail is downscaled to via
/// `scale='min(THUMBNAIL_MAX_DIM,iw)':-2` (height auto-rounded even, aspect
/// preserved; never upscales). A modest preview size.
pub const THUMBNAIL_MAX_DIM: u32 = 1024;

/// Fixed AAC-LC audio bitrate (`-b:a`). Audio is not user-configurable (D-5);
/// when audio is re-encoded the canonical output is always `-c:a aac -b:a 128k -ac 2`.
pub const AUDIO_BITRATE: &str = "128k";

/// The H.264 encoder selected for a re-encode. `Nvenc`/`Amf` are the GPU paths (used
/// only when the launcher has probed them as available on this host); `X264` is the
/// always-present pure-CPU fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264Encoder { Nvenc, Amf, X264 }

/// Per-run video disposition: `Copy` stream-copies the source video track; `Encode`
/// re-encodes it to H.264 with the given encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoArg { Copy, Encode(H264Encoder) }

/// The per-stream copy-vs-reencode decision produced by [`plan_ingest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestPlan { pub reencode_video: bool, pub reencode_audio: bool }

/// Decide per-stream copy-vs-reencode from the probe + shaping options. A video
/// stream is copyable only if already H.264/AV1, **already a plain 8-bit 4:2:0**
/// (`probe.video_8bit_420`), AND no rescale/re-rate is asked (copy cannot filter).
/// A 10/12-bit, HDR, or 4:2:2/4:4:4 source — even if H.264/AV1 — is re-encoded to
/// 8-bit 4:2:0 H.264 so it is guaranteed to play in the WebView2 `<video>` decoder
/// (a deliberate conservative tradeoff: guaranteed playability over a lossless copy).
/// Audio is copyable iff already AAC (or absent).
pub fn plan_ingest(probe: &ProbeResult, opts: &TranscodeOptions) -> IngestPlan {
    let vid_copy_ok = matches!(probe.video, VideoCodec::H264 | VideoCodec::Av1)
        && probe.video_8bit_420
        && matches!(opts.resolution, Resolution::Original)
        && matches!(opts.bitrate, Bitrate::Original);
    let aud_reencode = matches!(probe.audio, AudioCodec::Opus | AudioCodec::Mp3 | AudioCodec::Other);
    IngestPlan { reencode_video: !vid_copy_ok, reencode_audio: aud_reencode }
}

/// Probe argv: open the input, print stream info to stderr, produce NO output
/// (ffmpeg then exits non-zero — expected; the caller parses stderr).
pub fn build_probe_args(input: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    macro_rules! arg {
        ($v:expr) => {
            args.push(OsString::from($v))
        };
    }
    arg!("-hide_banner");
    arg!("-protocol_whitelist");
    arg!("file");
    arg!("-i");
    arg!(input.as_os_str());
    args
}

/// Build the ingest argv (everything after the program path): a copy-or-encode main
/// output as streamable fMP4, followed by the first-frame thumbnail second output.
///
/// `opts` is [`normalized`](TranscodeOptions::normalized) against `bounds` first, so
/// all user-supplied resolution/bitrate values are clamped to the trusted caps before
/// they reach ffmpeg. Each flag and each path is a discrete [`OsString`] element — no
/// shell, no concatenation — so there is no argv-injection surface and paths are never
/// lossily stringified.
#[allow(clippy::too_many_arguments)]
pub fn build_ingest_args(
    input: &Path,
    output: &Path,
    thumbnail: &Path,
    video: VideoArg,
    reencode_audio: bool,
    opts: &TranscodeOptions,
    bounds: &VideoBounds,
    threads: u16,
) -> Vec<OsString> {
    // Clamp the user-supplied shaping against the trusted bounds FIRST.
    let opts = opts.normalized(bounds);

    let mut args: Vec<OsString> = Vec::new();
    // Push one argv element. A macro (not a closure) so it never holds a borrow of
    // `args` across the path pushes; accepts anything `Into<OsString>` — a `&str`
    // flag, an owned `String`, or a path's `&OsStr` (carried verbatim, never lossily
    // stringified, so there is no argv-injection surface).
    macro_rules! arg {
        ($v:expr) => {
            args.push(OsString::from($v))
        };
    }

    arg!("-y");
    // Machine-readable progress to stderr (fd 2, the bounded capture pipe): the
    // launcher parses `Duration:` + `out_time`/`progress=` lines live for the UI
    // progress bar AND the stall watchdog. `pipe:2` writes to the EXISTING stderr
    // pipe — no new stream, no media on it.
    arg!("-progress");
    arg!("pipe:2");
    // Defense in depth: ffmpeg may only open local files (never a URL/other
    // protocol), atop the no-network AppContainer.
    arg!("-protocol_whitelist");
    arg!("file");
    arg!("-i");
    arg!(input.as_os_str());

    // --- Main output: copy-or-encode H.264 video -----------------------------
    match video {
        VideoArg::Copy => {
            arg!("-c:v");
            arg!("copy");
        }
        VideoArg::Encode(enc) => {
            arg!("-vf");
            arg!(main_scale_filter(&opts.resolution));
            // Force 8-bit I420 — the only pixel layout the viewer decoder accepts.
            arg!("-pix_fmt");
            arg!("yuv420p");
            arg!("-g");
            arg!(DEFAULT_GOP.to_string());
            match enc {
                H264Encoder::Nvenc => {
                    arg!("-c:v");
                    arg!("h264_nvenc");
                    arg!("-preset");
                    arg!("p5");
                    arg!("-tune");
                    arg!("hq");
                    match opts.bitrate {
                        Bitrate::Original => {
                            arg!("-rc");
                            arg!("vbr");
                            arg!("-cq");
                            arg!(DEFAULT_NVENC_CQ.to_string());
                        }
                        Bitrate::Kbps(n) => {
                            arg!("-b:v");
                            arg!(format!("{n}k"));
                        }
                    }
                }
                H264Encoder::Amf => {
                    arg!("-c:v");
                    arg!("h264_amf");
                    arg!("-quality");
                    arg!("quality");
                    match opts.bitrate {
                        Bitrate::Original => {
                            arg!("-rc");
                            arg!("cqp");
                            arg!("-qp_i");
                            arg!(DEFAULT_AMF_QP.to_string());
                            arg!("-qp_p");
                            arg!(DEFAULT_AMF_QP.to_string());
                        }
                        Bitrate::Kbps(n) => {
                            arg!("-rc");
                            arg!("vbr");
                            arg!("-b:v");
                            arg!(format!("{n}k"));
                        }
                    }
                }
                H264Encoder::X264 => {
                    arg!("-c:v");
                    arg!("libx264");
                    arg!("-preset");
                    arg!("veryfast");
                    // Encoder worker-thread budget: the confined transcode honors the
                    // user's `transcode_threads` setting. Passed as a plain argv value
                    // (never an env var), clamped to >=1 (a 0 would auto-pick all cores).
                    arg!("-threads");
                    arg!(threads.max(1).to_string());
                    match opts.bitrate {
                        Bitrate::Original => {
                            arg!("-crf");
                            arg!(DEFAULT_CRF.to_string());
                        }
                        Bitrate::Kbps(n) => {
                            arg!("-b:v");
                            arg!(format!("{n}k"));
                        }
                    }
                }
            }
        }
    }

    if reencode_audio {
        arg!("-c:a");
        arg!("aac");
        arg!("-b:a");
        arg!(AUDIO_BITRATE);
        arg!("-ac");
        arg!("2");
    } else {
        arg!("-c:a");
        arg!("copy");
    }

    // Fragmented-MP4: single continuous fMP4 (init moov + moof/mdat fragments) proven
    // to play natively in WebView2 via the MSE path. `+global_sidx` writes ONE
    // segment-index box at the FRONT covering every fragment, so the native <video>
    // learns total duration + all fragment byte offsets from a single leading range
    // read. Must precede the output path so it applies ONLY to the main mp4.
    arg!("-movflags");
    arg!("+frag_keyframe+empty_moov+default_base_moof+global_sidx");

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
/// even W/H (H.264 4:2:0 requires it) AND **square pixels** (`setsar=1`) at the correct
/// DISPLAY shape, so a genuinely anamorphic (SAR≠1) source renders at the right aspect
/// (D-7 / spec §8) — not just byte-correct on square-pixel sources.
///
/// SAR-awareness: ffmpeg's scale expressions expose `sar` (input sample aspect ratio)
/// and `dar` (input display aspect ratio). For a square-pixel source both collapse to
/// the storage ratio (`sar == 1`), so every branch below is byte-identical to the prior
/// even-only coercion — the existing e2e/round-trips are unaffected. ffmpeg evaluates
/// `sar`/`dar` as 1 / the storage ratio when the source SAR is undefined or 0, so
/// `iw*sar` / `h*dar` never collapse to 0.
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
    fn probe_args_are_hide_banner_dash_i_input() {
        // Non-.mp4 extension so the "no .mp4 output file" assertion is meaningful
        // (probe emits stream info only, never an output file).
        let args = build_probe_args(std::path::Path::new("/jobs/in put.mkv"));
        assert!(contains(&args, "-hide_banner"));
        let ii = pos(&args, "-i").expect("-i present");
        assert_eq!(args[ii + 1].as_os_str(), std::ffi::OsStr::new("/jobs/in put.mkv"));
        assert!(!args.iter().any(|a| a.to_string_lossy().ends_with(".mp4")));
    }

    #[test]
    fn plan_copy_when_h264_aac_original() {
        use crate::probe::{AudioCodec, ProbeResult, VideoCodec};
        let p = ProbeResult { video: VideoCodec::H264, audio: AudioCodec::Aac, video_8bit_420: true };
        let plan = plan_ingest(&p, &TranscodeOptions::default());
        assert!(!plan.reencode_video && !plan.reencode_audio);
    }

    #[test]
    fn plan_reencodes_video_when_hevc_and_audio_when_opus() {
        use crate::probe::{AudioCodec, ProbeResult, VideoCodec};
        let p = ProbeResult { video: VideoCodec::Hevc, audio: AudioCodec::Opus, video_8bit_420: false };
        let plan = plan_ingest(&p, &TranscodeOptions::default());
        assert!(plan.reencode_video && plan.reencode_audio);
    }

    #[test]
    fn plan_reencodes_video_when_rescale_requested_even_if_h264() {
        use crate::probe::{AudioCodec, ProbeResult, VideoCodec};
        let p = ProbeResult { video: VideoCodec::H264, audio: AudioCodec::Aac, video_8bit_420: true };
        let opts = TranscodeOptions { resolution: Resolution::Height(720), bitrate: Bitrate::Original };
        let plan = plan_ingest(&p, &opts);
        assert!(plan.reencode_video);
        assert!(!plan.reencode_audio);
    }

    #[test]
    fn plan_reencodes_video_when_10bit_even_if_h264_original() {
        // A 10-bit H.264 at Original res is NOT copy-safe (WebView2 can't decode it):
        // the 8-bit-4:2:0 gate forces a re-encode.
        use crate::probe::{AudioCodec, ProbeResult, VideoCodec};
        let p = ProbeResult { video: VideoCodec::H264, audio: AudioCodec::Aac, video_8bit_420: false };
        let plan = plan_ingest(&p, &TranscodeOptions::default());
        assert!(plan.reencode_video, "10-bit source must re-encode even at Original");
        assert!(!plan.reencode_audio);
    }

    #[test]
    fn plan_no_audio_reencode_when_absent() {
        use crate::probe::{AudioCodec, ProbeResult, VideoCodec};
        let p = ProbeResult { video: VideoCodec::Av1, audio: AudioCodec::None, video_8bit_420: true };
        let plan = plan_ingest(&p, &TranscodeOptions::default());
        assert!(!plan.reencode_video && !plan.reencode_audio);
    }

    #[test]
    fn copy_args_stream_copy_with_frag_and_no_filter() {
        let (i, o, t) = paths();
        let args = build_ingest_args(&i, &o, &t, VideoArg::Copy, false, &TranscodeOptions::default(), &bounds(), 4);
        assert_eq!(value_after(&args, "-c:v"), "copy");
        assert_eq!(value_after(&args, "-c:a"), "copy");
        // The MAIN (copy) output carries no scale filter — copy cannot filter. The
        // only `-vf` is the thumbnail second output, which appears AFTER the main
        // output path, so assert no `-vf` precedes it.
        let out_idx = args
            .iter()
            .position(|a| a.as_os_str() == o.as_os_str())
            .expect("output path present");
        assert!(!args[..out_idx].iter().any(|a| a == "-vf"), "copy main output must not scale");
        assert!(!contains(&args, "-pix_fmt"));
        // Copy carries no encoder GOP flag either (nothing is being encoded).
        assert!(!contains(&args, "-g"), "copy must not set an encoder GOP");
        assert_eq!(value_after(&args, "-movflags"), "+frag_keyframe+empty_moov+default_base_moof+global_sidx");
        assert_eq!(value_after(&args, "-frames:v"), "1");
    }

    #[test]
    fn copy_video_but_reencode_audio() {
        // A copyable H.264 video with a non-AAC audio track: copy the video, re-encode
        // only the audio to AAC.
        let (i, o, t) = paths();
        let args = build_ingest_args(&i, &o, &t, VideoArg::Copy, true, &TranscodeOptions::default(), &bounds(), 4);
        assert_eq!(value_after(&args, "-c:v"), "copy");
        assert_eq!(value_after(&args, "-c:a"), "aac");
        assert_eq!(value_after(&args, "-b:a"), AUDIO_BITRATE);
    }

    #[test]
    fn reencode_nvenc_h264_original_uses_cq() {
        let (i, o, t) = paths();
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::Nvenc), true, &TranscodeOptions::default(), &bounds(), 4);
        assert_eq!(value_after(&args, "-c:v"), "h264_nvenc");
        assert_eq!(value_after(&args, "-pix_fmt"), "yuv420p");
        assert!(contains(&args, "-cq"));
        assert!(!contains(&args, "-b:v"));
        assert_eq!(value_after(&args, "-g"), DEFAULT_GOP.to_string());
        assert_eq!(value_after(&args, "-c:a"), "aac");
        assert_eq!(value_after(&args, "-b:a"), AUDIO_BITRATE);
    }

    #[test]
    fn reencode_x264_kbps_uses_bitrate_and_threads() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions { resolution: Resolution::Original, bitrate: Bitrate::Kbps(4000) };
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::X264), false, &opts, &bounds(), 3);
        assert_eq!(value_after(&args, "-c:v"), "libx264");
        assert_eq!(value_after(&args, "-preset"), "veryfast");
        assert_eq!(value_after(&args, "-b:v"), "4000k");
        assert!(!contains(&args, "-crf"));
        assert_eq!(value_after(&args, "-threads"), "3");
        assert_eq!(value_after(&args, "-c:a"), "copy");
    }

    #[test]
    fn reencode_amf_h264_original_uses_cqp() {
        let (i, o, t) = paths();
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::Amf), true, &TranscodeOptions::default(), &bounds(), 4);
        assert_eq!(value_after(&args, "-c:v"), "h264_amf");
        assert!(contains(&args, "-rc") && value_after(&args, "-rc") == "cqp");
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
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::X264), false, &opts, &bounds(), 4);
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
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::X264), false, &opts, &bounds(), 4);
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
        // the argv carries `-threads <n>` on the CPU (libx264) path.
        let (i, o, t) = paths();
        let opts = TranscodeOptions::default();
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::X264), true, &opts, &bounds(), 3);
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
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::X264), true, &opts, &bounds(), 0);
        assert_eq!(value_after(&args, "-threads"), "1");
    }

    #[test]
    fn paths_are_discrete_args_no_injection() {
        let (i, o, t) = paths();
        let opts = TranscodeOptions::default();
        let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::X264), true, &opts, &bounds(), 4);

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
