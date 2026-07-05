# Fast remux-first ingest (GPU re-encode) + in-RAM fragment cache — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop unconditionally re-encoding every upload to CPU-only AV1; instead probe the source, stream-copy when the codec is already player-compatible (seconds, no quality loss), and re-encode only incompatible streams to H.264 using the GPU (NVIDIA NVENC / AMD AMF) with a confined libx264 CPU fallback — plus an option to hold the ciphertext fragment cache in RAM instead of on disk.

**Architecture:** Client-side only; no server, wire, or `client-core` changes. A new confined `ffmpeg -i` probe classifies the source. A pure planner decides per-stream copy-vs-reencode. New pure argv builders emit copy / H.264-encode argv (NVENC/AMF/x264). The existing single confined spawn still produces both `out.mp4` and `thumb.png`. GPU spawns use a spike-gated "AppContainer + GPU device grant" confinement (keys + network still blocked); libx264 and copy stay fully confined. `FragmentCache` gains a Memory backend selected by a new `fragment_cache_location` setting.

**Tech Stack:** Rust (2 cargo workspaces — outer for `media-launcher`, inner for `client-app`), Tauri v2, vanilla-TS UI, vendored static ffmpeg (`libsvtav1`/`h264_nvenc`/`hevc_nvenc`/`h264_amf`/`libx264` + h264/hevc/av1/vp9 decoders), Windows AppContainer + Job Object confinement.

**Environment (every Rust step):** cargo is not on PATH. Prefix commands with:
- PowerShell: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";`
- Bash: `export PATH="$HOME/.cargo/bin:$PATH";`

`media-launcher` builds in the OUTER workspace (`cargo test -p maxsecu-media-launcher`). `client-app` is its OWN workspace — build/test it with `--manifest-path crates\client-app\Cargo.toml`. NEVER `cargo fmt --all`; match in-file style. NEVER `git add -A` (untracked artifacts exist) — use scoped `git add`.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `crates/media-launcher/src/win32.rs` | (spike) add GPU device/driver-DLL grant to the AppContainer spawn; new confinement flag | 0, 4 |
| `crates/media-launcher/src/probe.rs` **(new)** | `VideoCodec`/`AudioCodec`/`ProbeResult`, pure `parse_probe`, confined `probe_source` spawn | 2 |
| `crates/media-launcher/src/ffmpeg_args.rs` | replace AV1 `build_ffmpeg_args` with `build_probe_args` + `build_ingest_args` (copy / NVENC / AMF / x264) + pure `plan_ingest` | 1 |
| `crates/media-launcher/src/lib.rs` | re-exports; `Confinement` enum; thread it through `FfmpegLauncher`/`spawn_confined_exe` | 1, 2, 4 |
| `crates/client-app/src/config.rs` | `FragmentCacheLocation` enum + `PerformanceSettings.fragment_cache_location` | 3 |
| `crates/client-app/src/fragment_cache.rs` | backend enum (Disk/Memory) behind the existing LRU API; `open_located` | 3 |
| `crates/client-app/src/upload.rs` | orchestration: copy source → probe → plan → spawn ladder (GPU→x264) + session-cached encoder | 5 |
| `crates/client-app/src/commands/video.rs:479` | build the cache from the setting via `open_located` | 3 |
| `crates/client-app/src/state.rs` | session-cached `H264Encoder` (the winning ladder rung) | 5 |
| `crates/client-app/ui/src/components/settings-screen.ts` + `core/types.ts` | Disk/Memory control in the performance section | 6 |
| `crates/client-e2e/tests/video_upload_e2e.rs` | copy-path + reencode-path e2e gates | 7 |
| `docs/security-review-2026-07-05-remux-gpu-ingest.md` **(new)** | confinement + no-new-egress sign-off | 7 |

**Shared types (defined in Task 1/2, referenced everywhere):**

```rust
// media-launcher/src/probe.rs
pub enum VideoCodec { H264, Hevc, Av1, Vp9, Vp8, Other }
pub enum AudioCodec { Aac, Opus, Mp3, Other, None }
pub struct ProbeResult { pub video: VideoCodec, pub audio: AudioCodec }

// media-launcher/src/ffmpeg_args.rs
pub enum H264Encoder { Nvenc, Amf, X264 }   // the GPU→CPU ladder rungs
pub enum VideoArg { Copy, Encode(H264Encoder) }
pub struct IngestPlan { pub reencode_video: bool, pub reencode_audio: bool }
pub fn plan_ingest(probe: &ProbeResult, opts: &TranscodeOptions) -> IngestPlan

// media-launcher/src/lib.rs
pub enum Confinement { Full, GpuGrant }     // GpuGrant = Full + GPU device/DLL access
```

---

## Task 0: GPU-in-AppContainer spike (gating, NOT TDD)

**Purpose:** Determine whether `h264_nvenc` / `h264_amf` can initialize inside the current capability-free AppContainer once a GPU device/driver-DLL grant is added — WITHOUT dropping the AppContainer (keys + network stay blocked). Output is a written decision that gates Task 4's GPU mechanism. This does not block Tasks 1–3.

**Files:** scratch only (a throwaway `examples/gpu_spike.rs` or an `#[ignore]` test); plus notes appended to `docs/security-review-2026-07-05-remux-gpu-ingest.md` (created in Task 7, or a scratch note now).

- [ ] **Step 1: Reproduce a confined H.264 GPU encode attempt.** In a scratch `#[ignore]`d test under `crates/media-launcher/tests/`, build argv `["-y","-f","lavfi","-i","testsrc=size=320x240:rate=30:duration=1","-c:v","h264_nvenc","-f","mp4", <out>]` and run it via `FfmpegLauncher::new(ffmpeg_path).run(...)` with the CURRENT full confinement. Record: does ffmpeg exit 0, or fail with an encoder-init error (e.g. "Cannot load nvcuda.dll" / "OpenEncodeSessionEx failed" / "Cannot load amfrt64.dll")?

- [ ] **Step 2: Add a minimal GPU device/driver-DLL grant.** In `win32.rs`, identify where the AppContainer SID's access is scoped (the capability list + path grants around `CreateAppContainerProfile` / `grant_path_to_appcontainer`). Add read/execute access for the NVIDIA/AMD driver DLL directories (`%SystemRoot%\System32\nvEncodeAPI64.dll`, `nvcuda.dll`, `amfrt64.dll` and their dependency dirs) and the GPU device objects the driver opens. Re-run Step 1.

- [ ] **Step 3: Record the outcome (the gate).** Write a short note (paste into the security-review doc later): "NVENC in-container: WORKS / FAILS with <error>. AMF in-container: WORKS / FAILS with <error>. Minimum grant that made it work: <list>." 
  - If **either GPU works in-container** → Task 4 implements `Confinement::GpuGrant` as exactly that grant (no AppContainer drop). Proceed.
  - If **both fail in-container** → STOP. Do not drop the AppContainer. Report the concrete errors to the user and await a decision; ship the rest of the feature (copy + libx264 confined) meanwhile.

- [ ] **Step 4: Commit the spike note + any grant scaffolding** (guarded so it is inert until Task 4 wires it).

```bash
git add crates/media-launcher/src/win32.rs crates/media-launcher/tests/
git commit -m "spike(ingest): probe GPU encoder init inside AppContainer + minimal device grant"
```

---

## Task 1: Argv builders — replace AV1 emitter with probe + copy/H.264 builders

**Files:**
- Modify: `crates/media-launcher/src/ffmpeg_args.rs` (replace `build_ffmpeg_args`; keep `main_scale_filter`/`thumb_scale_filter`/`THUMBNAIL_MAX_DIM`/`AUDIO_BITRATE`/`DEFAULT_GOP`/`DEFAULT_CRF`)
- Modify: `crates/media-launcher/src/lib.rs` (exports)
- Test: inline `#[cfg(test)]` in `ffmpeg_args.rs`

**Context:** The current `build_ffmpeg_args` emits AV1 (`-c:v libsvtav1 …`). We replace it with (a) `build_probe_args` (probe argv), (b) `plan_ingest` (pure planner), and (c) `build_ingest_args` (copy / H.264-encode argv). The re-encode target is **H.264** with `-g DEFAULT_GOP` to keep ~1s fragments; copy emits no `-vf`/`-pix_fmt`/`-threads` (invalid with `-c copy`). Thumbnail second output is unchanged.

- [ ] **Step 1: Write failing tests** (append to `ffmpeg_args.rs` tests; delete the old AV1 tests `original_original_pins_the_canonical_argv`, `height_720_and_kbps_4000`, `main_output_is_fragmented_mp4` that assert `libsvtav1`/`-crf 18` on the main path — they are superseded):

```rust
#[test]
fn probe_args_are_hide_banner_dash_i_input() {
    let args = build_probe_args(std::path::Path::new("/jobs/in put.mp4"));
    assert!(contains(&args, "-hide_banner"));
    let ii = pos(&args, "-i").expect("-i present");
    assert_eq!(args[ii + 1].as_os_str(), std::ffi::OsStr::new("/jobs/in put.mp4"));
    // No output file element (probe must not encode).
    assert!(!args.iter().any(|a| a.to_string_lossy().ends_with(".mp4")));
}

#[test]
fn plan_copy_when_h264_aac_original() {
    use crate::probe::{ProbeResult, VideoCodec, AudioCodec};
    let p = ProbeResult { video: VideoCodec::H264, audio: AudioCodec::Aac };
    let plan = plan_ingest(&p, &TranscodeOptions::default());
    assert!(!plan.reencode_video && !plan.reencode_audio, "pure copy");
}

#[test]
fn plan_reencodes_video_when_hevc_and_audio_when_opus() {
    use crate::probe::{ProbeResult, VideoCodec, AudioCodec};
    let p = ProbeResult { video: VideoCodec::Hevc, audio: AudioCodec::Opus };
    let plan = plan_ingest(&p, &TranscodeOptions::default());
    assert!(plan.reencode_video && plan.reencode_audio);
}

#[test]
fn plan_reencodes_video_when_rescale_requested_even_if_h264() {
    use crate::probe::{ProbeResult, VideoCodec, AudioCodec};
    let p = ProbeResult { video: VideoCodec::H264, audio: AudioCodec::Aac };
    let opts = TranscodeOptions { resolution: Resolution::Height(720), bitrate: Bitrate::Original };
    let plan = plan_ingest(&p, &opts);
    assert!(plan.reencode_video, "rescale forces re-encode");
    assert!(!plan.reencode_audio);
}

#[test]
fn plan_no_audio_reencode_when_absent() {
    use crate::probe::{ProbeResult, VideoCodec, AudioCodec};
    let p = ProbeResult { video: VideoCodec::Av1, audio: AudioCodec::None };
    let plan = plan_ingest(&p, &TranscodeOptions::default());
    assert!(!plan.reencode_video && !plan.reencode_audio);
}

#[test]
fn copy_args_stream_copy_with_frag_and_no_filter() {
    let (i, o, t) = paths();
    let args = build_ingest_args(&i, &o, &t, VideoArg::Copy, false, &TranscodeOptions::default(), &bounds(), 4);
    // Both streams copied.
    assert_eq!(value_after(&args, "-c:v"), "copy");
    assert_eq!(value_after(&args, "-c:a"), "copy");
    // NO scale/pix_fmt on the copy path (invalid with -c copy).
    assert!(!args.iter().any(|a| a == "-vf" ), "no -vf before the copy output");
    assert!(!contains(&args, "-pix_fmt"));
    // Streamable fMP4 with the front global index.
    assert_eq!(value_after(&args, "-movflags"), "+frag_keyframe+empty_moov+default_base_moof+global_sidx");
    // Thumbnail second output still present.
    assert_eq!(value_after(&args, "-frames:v"), "1");
}

#[test]
fn reencode_nvenc_h264_original_uses_cq() {
    let (i, o, t) = paths();
    let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::Nvenc), true,
        &TranscodeOptions::default(), &bounds(), 4);
    assert_eq!(value_after(&args, "-c:v"), "h264_nvenc");
    assert_eq!(value_after(&args, "-pix_fmt"), "yuv420p");
    assert!(contains(&args, "-cq"), "Original bitrate -> constant quality");
    assert!(!contains(&args, "-b:v"));
    assert_eq!(value_after(&args, "-g"), DEFAULT_GOP.to_string());
    // audio re-encoded to AAC
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
    assert!(!contains(&args, "-crf"), "explicit kbps -> no -crf");
    assert_eq!(value_after(&args, "-threads"), "3");
    assert_eq!(value_after(&args, "-c:a"), "copy", "audio kept");
}

#[test]
fn reencode_amf_h264_original_uses_cqp() {
    let (i, o, t) = paths();
    let args = build_ingest_args(&i, &o, &t, VideoArg::Encode(H264Encoder::Amf), true,
        &TranscodeOptions::default(), &bounds(), 4);
    assert_eq!(value_after(&args, "-c:v"), "h264_amf");
    assert!(contains(&args, "-rc") && value_after(&args, "-rc") == "cqp");
}
```

- [ ] **Step 2: Run — expect fail** (unresolved `build_probe_args`/`plan_ingest`/`build_ingest_args`/`VideoArg`/`H264Encoder`).

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-media-launcher ffmpeg_args 2>&1 | tail -20`
Expected: compile errors (functions/types not found).

- [ ] **Step 3: Implement.** Replace `build_ffmpeg_args` with the following in `ffmpeg_args.rs` (keep the `arg!` macro, `main_scale_filter`, `thumb_scale_filter`, and the constants; `DEFAULT_PRESET` may be deleted):

```rust
use crate::probe::{ProbeResult, VideoCodec, AudioCodec};

/// Default libx264 CRF for the CPU fallback (visually near-lossless).
pub const DEFAULT_X264_CRF: u32 = 18;
/// Default NVENC constant-quality value (near-transparent H.264).
pub const DEFAULT_NVENC_CQ: u32 = 19;
/// Default AMF constant-QP value.
pub const DEFAULT_AMF_QP: u32 = 20;

/// The H.264 encoder chosen by the runtime GPU→CPU ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264Encoder { Nvenc, Amf, X264 }

/// What to do with the video stream: copy it, or re-encode to H.264 with `enc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoArg { Copy, Encode(H264Encoder) }

/// Per-stream copy/re-encode decision (orchestration fills the encoder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestPlan { pub reencode_video: bool, pub reencode_audio: bool }

/// Decide per-stream copy-vs-reencode from the probe + shaping options. A video
/// stream is copyable only if already H.264/AV1 AND no rescale/re-rate is asked
/// (copy cannot filter). Audio is copyable iff already AAC (or absent).
pub fn plan_ingest(probe: &ProbeResult, opts: &TranscodeOptions) -> IngestPlan {
    let vid_copy_ok = matches!(probe.video, VideoCodec::H264 | VideoCodec::Av1)
        && matches!(opts.resolution, Resolution::Original)
        && matches!(opts.bitrate, Bitrate::Original);
    let aud_reencode = matches!(probe.audio, AudioCodec::Opus | AudioCodec::Mp3 | AudioCodec::Other);
    IngestPlan { reencode_video: !vid_copy_ok, reencode_audio: aud_reencode }
}

/// Probe argv: open the input, print stream info to stderr, produce NO output
/// (ffmpeg then exits non-zero — expected; the caller parses stderr).
pub fn build_probe_args(input: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    macro_rules! arg { ($v:expr) => { args.push(OsString::from($v)) }; }
    arg!("-hide_banner");
    arg!("-protocol_whitelist"); arg!("file");
    arg!("-i"); arg!(input.as_os_str());
    args
}

/// Build the ingest argv (everything after the program path): a copy-or-encode main
/// output as streamable fMP4, followed by the first-frame thumbnail second output.
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
    let opts = opts.normalized(bounds);
    let mut args: Vec<OsString> = Vec::new();
    macro_rules! arg { ($v:expr) => { args.push(OsString::from($v)) }; }

    arg!("-y");
    arg!("-progress"); arg!("pipe:2");
    arg!("-protocol_whitelist"); arg!("file");
    arg!("-i"); arg!(input.as_os_str());

    // --- Video stream ---
    match video {
        VideoArg::Copy => { arg!("-c:v"); arg!("copy"); }
        VideoArg::Encode(enc) => {
            arg!("-vf"); arg!(main_scale_filter(&opts.resolution));
            arg!("-pix_fmt"); arg!("yuv420p");
            arg!("-g"); arg!(DEFAULT_GOP.to_string());
            match enc {
                H264Encoder::Nvenc => {
                    arg!("-c:v"); arg!("h264_nvenc");
                    arg!("-preset"); arg!("p5");
                    arg!("-tune"); arg!("hq");
                    match opts.bitrate {
                        Bitrate::Original => { arg!("-rc"); arg!("vbr"); arg!("-cq"); arg!(DEFAULT_NVENC_CQ.to_string()); }
                        Bitrate::Kbps(n) => { arg!("-b:v"); arg!(format!("{n}k")); }
                    }
                }
                H264Encoder::Amf => {
                    arg!("-c:v"); arg!("h264_amf");
                    arg!("-quality"); arg!("quality");
                    match opts.bitrate {
                        Bitrate::Original => {
                            arg!("-rc"); arg!("cqp");
                            arg!("-qp_i"); arg!(DEFAULT_AMF_QP.to_string());
                            arg!("-qp_p"); arg!(DEFAULT_AMF_QP.to_string());
                        }
                        Bitrate::Kbps(n) => { arg!("-rc"); arg!("vbr"); arg!("-b:v"); arg!(format!("{n}k")); }
                    }
                }
                H264Encoder::X264 => {
                    arg!("-c:v"); arg!("libx264");
                    arg!("-preset"); arg!("veryfast");
                    arg!("-threads"); arg!(threads.max(1).to_string());
                    match opts.bitrate {
                        Bitrate::Original => { arg!("-crf"); arg!(DEFAULT_X264_CRF.to_string()); }
                        Bitrate::Kbps(n) => { arg!("-b:v"); arg!(format!("{n}k")); }
                    }
                }
            }
        }
    }

    // --- Audio stream ---
    if reencode_audio {
        arg!("-c:a"); arg!("aac"); arg!("-b:a"); arg!(AUDIO_BITRATE); arg!("-ac"); arg!("2");
    } else {
        arg!("-c:a"); arg!("copy");
    }

    // Streamable fMP4 with a single leading global index (flat time-to-first-frame).
    arg!("-movflags"); arg!("+frag_keyframe+empty_moov+default_base_moof+global_sidx");
    arg!(output.as_os_str());

    // --- Thumbnail second output (decodes exactly one frame regardless of main -c) ---
    arg!("-map"); arg!("0:v:0");
    arg!("-frames:v"); arg!("1");
    arg!("-vf"); arg!(thumb_scale_filter());
    arg!("-y"); arg!(thumbnail.as_os_str());

    args
}
```

In `lib.rs` change the re-export line `pub use ffmpeg_args::build_ffmpeg_args;` to:
```rust
pub use ffmpeg_args::{build_ingest_args, build_probe_args, plan_ingest, H264Encoder, IngestPlan, VideoArg};
```

- [ ] **Step 4: Run — expect pass.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-media-launcher ffmpeg_args 2>&1 | tail -20`
Expected: PASS (`ffmpeg_confine` module has a separate compile; if it references `build_ffmpeg_args`, update it in Task 5).

- [ ] **Step 5: Commit.**

```bash
git add crates/media-launcher/src/ffmpeg_args.rs crates/media-launcher/src/lib.rs
git commit -m "feat(ingest): copy/H.264 argv builders + pure ingest planner (retire AV1 emit)"
```

---

## Task 2: Probe module — classify the source

**Files:**
- Create: `crates/media-launcher/src/probe.rs`
- Modify: `crates/media-launcher/src/lib.rs` (`pub mod probe; pub use probe::{...};`)
- Test: inline `#[cfg(test)]` in `probe.rs`

**Context:** No `ffprobe.exe` is vendored, so we spawn the confined `ffmpeg -i` (Task 1's `build_probe_args`) and parse its stderr. `parse_probe` is a pure function tested against captured real ffmpeg stderr. Unknown/absent codecs fail toward re-encode.

- [ ] **Step 1: Write failing tests** in `probe.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // A real BtbN ffmpeg stderr excerpt (H.264 video + AAC audio).
    const H264_AAC: &[u8] = b"\
Input #0, mov,mp4,m4a,3gp,3g2,mj2, from '/jobs/input.mp4':\n\
  Duration: 00:00:12.34, start: 0.000000, bitrate: 1500 kb/s\n\
  Stream #0:0[0x1](und): Video: h264 (High) (avc1 / 0x31637661), yuv420p(tv, bt709), 1920x1080, 1400 kb/s, 30 fps\n\
  Stream #0:1[0x2](und): Audio: aac (LC) (mp4a / 0x6134706D), 48000 Hz, stereo, fltp, 128 kb/s\n\
At least one output file must be specified\n";

    const HEVC_OPUS: &[u8] = b"\
  Stream #0:0: Video: hevc (Main) (hev1 / 0x31766568), yuv420p10le, 3840x2160\n\
  Stream #0:1: Audio: opus, 48000 Hz, stereo, fltp\n";

    const VP9_NOAUDIO: &[u8] = b"  Stream #0:0: Video: vp9 (Profile 0), yuv420p, 1280x720\n";

    #[test]
    fn parses_h264_aac() {
        let r = parse_probe(H264_AAC);
        assert_eq!(r.video, VideoCodec::H264);
        assert_eq!(r.audio, AudioCodec::Aac);
    }

    #[test]
    fn parses_hevc_opus() {
        let r = parse_probe(HEVC_OPUS);
        assert_eq!(r.video, VideoCodec::Hevc);
        assert_eq!(r.audio, AudioCodec::Opus);
    }

    #[test]
    fn no_audio_stream_is_none() {
        let r = parse_probe(VP9_NOAUDIO);
        assert_eq!(r.video, VideoCodec::Vp9);
        assert_eq!(r.audio, AudioCodec::None);
    }

    #[test]
    fn empty_or_garbage_is_other_none() {
        let r = parse_probe(b"no streams here");
        assert_eq!(r.video, VideoCodec::Other);
        assert_eq!(r.audio, AudioCodec::None);
    }

    #[test]
    fn first_video_and_audio_win() {
        // Two video streams; the first classifies the result.
        let s = b"  Stream #0:0: Video: av1 (Main)\n  Stream #0:1: Video: h264\n  Stream #0:2: Audio: mp3\n";
        let r = parse_probe(s);
        assert_eq!(r.video, VideoCodec::Av1);
        assert_eq!(r.audio, AudioCodec::Mp3);
    }
}
```

- [ ] **Step 2: Run — expect fail.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-media-launcher probe 2>&1 | tail -20`
Expected: module `probe` not found / functions unresolved.

- [ ] **Step 3: Implement `probe.rs`:**

```rust
//! Source-media classification for the remux-first ingest. Spawns the CONFINED
//! `ffmpeg -i <input>` (no output → ffmpeg prints stream info to stderr and exits
//! non-zero, which is expected) and parses the first Video:/Audio: codec token.
//! `parse_probe` is a pure function; unknown/absent codecs fail toward re-encode.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::atomic::AtomicBool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec { H264, Hevc, Av1, Vp9, Vp8, Other }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec { Aac, Opus, Mp3, Other, None }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResult { pub video: VideoCodec, pub audio: AudioCodec }

/// Parse ffmpeg stderr for the FIRST `… Video: <codec>` and `… Audio: <codec>`
/// tokens. No video line → `Other`; no audio line → `None`.
pub fn parse_probe(stderr: &[u8]) -> ProbeResult {
    let text = String::from_utf8_lossy(stderr);
    let mut video: Option<VideoCodec> = None;
    let mut audio: Option<AudioCodec> = None;
    for line in text.lines() {
        if video.is_none() {
            if let Some(tok) = codec_after(line, "Video:") { video = Some(classify_video(&tok)); }
        }
        if audio.is_none() {
            if let Some(tok) = codec_after(line, "Audio:") { audio = Some(classify_audio(&tok)); }
        }
    }
    ProbeResult { video: video.unwrap_or(VideoCodec::Other), audio: audio.unwrap_or(AudioCodec::None) }
}

/// The codec token right after `marker` on a line: the run of `[a-z0-9]` after the
/// marker + one space (ffmpeg formats it as `Video: h264 (High) …`).
fn codec_after(line: &str, marker: &str) -> Option<String> {
    let idx = line.find(marker)? + marker.len();
    let rest = line[idx..].trim_start();
    let tok: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    if tok.is_empty() { None } else { Some(tok.to_ascii_lowercase()) }
}

fn classify_video(tok: &str) -> VideoCodec {
    match tok {
        "h264" | "avc" | "avc1" => VideoCodec::H264,
        "hevc" | "h265" => VideoCodec::Hevc,
        "av1" => VideoCodec::Av1,
        "vp9" => VideoCodec::Vp9,
        "vp8" => VideoCodec::Vp8,
        _ => VideoCodec::Other,
    }
}

fn classify_audio(tok: &str) -> AudioCodec {
    match tok {
        "aac" => AudioCodec::Aac,
        "opus" => AudioCodec::Opus,
        "mp3" | "mp3float" => AudioCodec::Mp3,
        _ => AudioCodec::Other,
    }
}

/// Spawn the confined `ffmpeg -i` and classify the source. Uses FULL confinement
/// (the probe touches untrusted input and needs no GPU). ffmpeg exits non-zero
/// (no output file) — that is expected; only stderr is parsed.
#[cfg(windows)]
pub fn probe_source(
    ffmpeg_path: &Path,
    input: &Path,
    grant_dir: &Path,
) -> Result<ProbeResult, crate::SpawnError> {
    let args = crate::build_probe_args(input);
    let cancel = AtomicBool::new(false);
    let outcome = crate::FfmpegLauncher::new(ffmpeg_path).run(&args, grant_dir, |_| {}, &cancel)?;
    Ok(parse_probe(&outcome.stderr_tail))
}

// Silence unused-import warnings on non-windows (probe_source is windows-only).
#[cfg(not(windows))]
#[allow(dead_code)]
fn _unused(_: &OsStr) {}
```

In `lib.rs` add near the other `pub mod`s:
```rust
pub mod probe;
pub use probe::{parse_probe, ProbeResult, VideoCodec, AudioCodec};
#[cfg(windows)]
pub use probe::probe_source;
```

- [ ] **Step 4: Run — expect pass.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-media-launcher probe 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/media-launcher/src/probe.rs crates/media-launcher/src/lib.rs
git commit -m "feat(ingest): confined ffmpeg -i source probe + pure codec classifier"
```

---

## Task 3: In-RAM fragment cache backend + setting

### Task 3a: `FragmentCacheLocation` setting

**Files:**
- Modify: `crates/client-app/src/config.rs` (add enum + field)
- Test: inline in `config.rs`

- [ ] **Step 1: Write failing test** (append near the existing config tests):

```rust
#[test]
fn fragment_cache_location_defaults_to_disk_and_back_compat_loads() {
    // Default is Disk.
    assert_eq!(PerformanceSettings::default().fragment_cache_location, FragmentCacheLocation::Disk);
    // An older settings.json without the key still deserializes (serde default).
    let json = r#"{"ram_cache_cap_mb":512}"#;
    let p: PerformanceSettings = serde_json::from_str(json).unwrap();
    assert_eq!(p.fragment_cache_location, FragmentCacheLocation::Disk);
}
```

- [ ] **Step 2: Run — expect fail.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates\client-app\Cargo.toml fragment_cache_location 2>&1 | tail -15`
Expected: `FragmentCacheLocation` not found.

- [ ] **Step 3: Implement.** In `config.rs` add above `PerformanceSettings`:

```rust
/// Where the ciphertext fragment cache lives. `Disk` (default) = today's
/// `<dir>/cache/frag/*.frag`. `Memory` = an in-process ciphertext LRU that never
/// touches disk (same byte budget). Both store ONLY ciphertext.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum FragmentCacheLocation {
    #[default]
    Disk,
    Memory,
}
```

Add the field to `PerformanceSettings` (after `decode_threads`):
```rust
    /// Fragment-cache backend. `#[serde(default)]` keeps older settings.json loading.
    #[serde(default)]
    pub fragment_cache_location: FragmentCacheLocation,
```
And in `impl Default for PerformanceSettings`, add `fragment_cache_location: FragmentCacheLocation::default(),`.

- [ ] **Step 4: Run — expect pass.** Same command as Step 2. Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
git add crates/client-app/src/config.rs
git commit -m "feat(settings): add fragment_cache_location (Disk|Memory), default Disk"
```

### Task 3b: Refactor `FragmentCache` to a backend enum (keep disk behavior green)

**Files:** Modify `crates/client-app/src/fragment_cache.rs`. The existing 8 tests MUST stay green.

- [ ] **Step 1: Refactor internals** — replace the `Entry.filename` string + `root` field with a `Backend`, deriving the disk filename from the key. Change the struct + methods:

```rust
enum Backend { Disk { root: PathBuf }, Memory { blobs: BTreeMap<(String, u32), Vec<u8>> } }

#[derive(Debug, Clone)]
struct Entry { size_bytes: u64, last_used: u64 }

pub struct FragmentCache {
    backend: Backend,
    cap_bytes: u64,
    total_bytes: u64,
    tick: u64,
    index: BTreeMap<(String, u32), Entry>,
}
```
(Add `#[derive(Debug)]` on `Backend` or `#[derive(Debug)] for FragmentCache` manually — `Vec<u8>` and `PathBuf` are Debug, so `#[derive(Debug)]` on both works.)

Rewrite `put`/`get`/`remove_entry` to branch on `self.backend`:
- `put`: compute `map_key`, `remove_entry`, skip if `size > cap`, evict loop, then **write** — Disk: `std::fs::write(root.join(blob_filename(&k.0, k.1)), ct)?`; Memory: `blobs.insert(map_key.clone(), ct.to_vec());`. Then bump tick/total/index.
- `get`: Disk: `std::fs::read(root.join(blob_filename(...)))` (on Err → `remove_entry`, `None`); Memory: `blobs.get(&map_key).cloned()` (always present if indexed). On hit bump tick + `last_used`.
- `remove_entry`: Disk: `let _ = std::fs::remove_file(root.join(blob_filename(&key.0, key.1)));`; Memory: `if let Backend::Memory{blobs} = &mut self.backend { blobs.remove(key); }`. Then adjust totals.

Keep `open(app_dir, cap)` returning the **Disk** backend (unchanged public signature + behavior: create dir, wipe prior blobs, mark not-content-indexed).

- [ ] **Step 2: Run existing tests — expect PASS (behavior preserved).**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates\client-app\Cargo.toml -p maxsecu-client-app fragment_cache 2>&1 | tail -20`
Expected: all existing tests PASS.

- [ ] **Step 3: Commit.**
```bash
git add crates/client-app/src/fragment_cache.rs
git commit -m "refactor(cache): FragmentCache backend enum (disk unchanged)"
```

### Task 3c: Add the Memory backend + `open_located`

**Files:** Modify `crates/client-app/src/fragment_cache.rs`.

- [ ] **Step 1: Write failing tests** (append to the cache test module):

```rust
#[test]
fn memory_backend_roundtrips_and_writes_nothing_to_disk() {
    let dir = tmp_dir("mem");
    let mut c = FragmentCache::open_located(&dir, 1024, crate::config::FragmentCacheLocation::Memory).unwrap();
    let ct = b"\x00opaque\xff".to_vec();
    c.put("aa", 0, &ct).unwrap();
    assert_eq!(c.get("aa", 0).as_deref(), Some(ct.as_slice()));
    // Nothing on disk.
    assert!(!dir.join("cache").join("frag").join("aa_0.frag").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn memory_backend_evicts_lru_like_disk() {
    let dir = tmp_dir("mem-lru");
    let mut c = FragmentCache::open_located(&dir, 30, crate::config::FragmentCacheLocation::Memory).unwrap();
    let blob = |b: u8| vec![b; 10];
    c.put("aa", 0, &blob(0)).unwrap();
    c.put("aa", 1, &blob(1)).unwrap();
    c.put("aa", 2, &blob(2)).unwrap();
    assert!(c.get("aa", 0).is_some());          // touch 0
    c.put("aa", 3, &blob(3)).unwrap();          // evicts LRU (aa,1)
    assert_eq!(c.total_bytes(), 30);
    assert_eq!(c.get("aa", 1), None);
    let _ = std::fs::remove_dir_all(&dir);
}
```

- [ ] **Step 2: Run — expect fail** (`open_located` not found).

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates\client-app\Cargo.toml -p maxsecu-client-app memory_backend 2>&1 | tail -15`

- [ ] **Step 3: Implement `open_located`:**

```rust
use crate::config::FragmentCacheLocation;

impl FragmentCache {
    /// Open the cache with the configured backend. `Disk` behaves exactly like
    /// [`open`]; `Memory` holds ciphertext in-process and never touches disk.
    pub fn open_located(app_dir: &Path, cap_bytes: u64, location: FragmentCacheLocation) -> io::Result<Self> {
        match location {
            FragmentCacheLocation::Disk => Self::open(app_dir, cap_bytes),
            FragmentCacheLocation::Memory => Ok(Self {
                backend: Backend::Memory { blobs: BTreeMap::new() },
                cap_bytes,
                total_bytes: 0,
                tick: 0,
                index: BTreeMap::new(),
            }),
        }
    }
}
```

- [ ] **Step 4: Run — expect pass** (new + all existing cache tests).

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates\client-app\Cargo.toml -p maxsecu-client-app fragment_cache 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
git add crates/client-app/src/fragment_cache.rs
git commit -m "feat(cache): in-RAM ciphertext fragment-cache backend (open_located)"
```

### Task 3d: Build the cache from the setting at the play path

**Files:** Modify `crates/client-app/src/commands/video.rs` around line 479.

- [ ] **Step 1: Change the construction.** The current line:
```rust
let cache = FragmentCache::open(&dir.0, cap).map_err(|_| player_err())?;
```
Read the location from settings already loaded in this function (there is a `SettingsConfig::load(&dir.0)` nearby producing `settings`; the play path around 479 has access to `dir`). Replace with:
```rust
let location = SettingsConfig::load(&dir.0).performance.fragment_cache_location;
let cache = FragmentCache::open_located(&dir.0, cap, location).map_err(|_| player_err())?;
```
(If `settings` is already in scope at 479, reuse `settings.performance.fragment_cache_location` instead of re-loading.)

- [ ] **Step 2: Build the client-app to verify it compiles.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo build --manifest-path crates\client-app\Cargo.toml -p maxsecu-client-app 2>&1 | tail -15`
Expected: builds.

- [ ] **Step 3: Commit.**
```bash
git add crates/client-app/src/commands/video.rs
git commit -m "feat(cache): select fragment-cache backend from settings at play time"
```

---

## Task 4: Confinement level plumbing (spike-gated)

**Files:** Modify `crates/media-launcher/src/lib.rs`, `crates/media-launcher/src/win32.rs`.

**Precondition:** Task 0 spike concluded GPU works in-container with a device grant. If it did NOT, skip the GPU wiring here (leave `Confinement::GpuGrant` == `Full`) and stop for a user decision; the ladder in Task 5 will simply always land on x264.

- [ ] **Step 1: Add the `Confinement` enum + launcher option** in `lib.rs`:

```rust
/// Confinement level for a spawn. `Full` = the Phase-7 AppContainer + low-IL +
/// no-network + memory cap + ActiveProcessLimit. `GpuGrant` = `Full` PLUS the
/// minimal GPU device/driver-DLL access the spike proved NVENC/AMF need — keys and
/// network stay blocked.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confinement { Full, GpuGrant }
```
Add a field `confinement: Confinement` to `FfmpegLauncher` (default `Full` in `new`/`with_memory_cap`) and a builder `pub fn with_confinement(mut self, c: Confinement) -> Self`. Thread it into the `win32::spawn_confined_exe` call.

- [ ] **Step 2: Thread the flag through `spawn_confined_exe`** — add a `confinement: Confinement` parameter and, in the AppContainer setup (the capability/grant assembly identified in Task 0 Step 2), apply the extra GPU device/DLL grant only when `confinement == GpuGrant`. Everything else (no-network capability set, low-IL token, job-object mem cap, `ActiveProcessLimit=1`) is IDENTICAL for both levels.

- [ ] **Step 3: Update all existing `spawn_confined_exe`/`FfmpegLauncher::run` call sites** to pass `Confinement::Full` (probe, copy, x264). Only Task 5's GPU spawn passes `GpuGrant`.

- [ ] **Step 4: Build + run media-launcher tests.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-media-launcher 2>&1 | tail -25`
Expected: builds; existing confinement tests PASS.

- [ ] **Step 5: Commit.**
```bash
git add crates/media-launcher/src/lib.rs crates/media-launcher/src/win32.rs
git commit -m "feat(confine): Confinement::{Full,GpuGrant} spawn level (GPU device grant)"
```

---

## Task 5: Orchestration — probe → plan → GPU ladder + session cache

**Files:** Modify `crates/client-app/src/upload.rs` (`prepare_video_streams`, ~lines 198–266), `crates/client-app/src/state.rs` (session encoder cache).

**Context:** Replace the single fixed `build_ffmpeg_args` spawn with: copy source in (unchanged) → **probe** (confined) → `plan_ingest` → run the plan. When re-encoding video, walk the GPU→CPU ladder, remembering the winner in app state so later uploads skip dead rungs.

- [ ] **Step 1: Add a session-cached encoder** in `state.rs`:

```rust
/// The H.264 encoder the runtime ladder settled on (probed once per session so
/// later uploads skip dead GPU rungs). `None` until the first re-encode probes it.
#[derive(Default)]
pub struct H264EncoderCache(pub std::sync::Mutex<Option<maxsecu_media_launcher::H264Encoder>>);
```
Register it in `main.rs` with `.manage(maxsecu_client_app::state::H264EncoderCache::default())` (only if the orchestration reads it via Tauri state; if `prepare_video_streams` is called from a command that already has the needed handles, thread it as a parameter instead — follow the existing call site in `commands::upload::stage_upload`).

- [ ] **Step 2: Rewrite the spawn section of `prepare_video_streams`.** After the source copy (step 2 in the current code) and before building the fragment index (step 7), replace the fixed-argv block (current steps 3–4) with:

```rust
// 3) Probe the source (confined) and plan per-stream copy vs re-encode.
let probe = maxsecu_media_launcher::probe_source(ffmpeg_path, &input_copy, &dir)
    .map_err(|_| video_prep_err())?;
let plan = maxsecu_media_launcher::plan_ingest(&probe, options);

let out_mp4 = dir.join("out.mp4");
let thumb_png = dir.join("thumb.png");

// 4) Execute the plan. Copy / x264 run FULLY confined; GPU rungs add the GPU grant.
let outcome = if !plan.reencode_video {
    // Copy video (audio copied or re-encoded to AAC per the plan) — fully confined.
    let args = maxsecu_media_launcher::build_ingest_args(
        &input_copy, &out_mp4, &thumb_png,
        maxsecu_media_launcher::VideoArg::Copy, plan.reencode_audio,
        options, bounds, transcode_threads);
    run_confined_ingest(ffmpeg_path, &args, &dir, &on_phase, cancel)?
} else {
    run_reencode_ladder(
        ffmpeg_path, &input_copy, &out_mp4, &thumb_png, &plan,
        options, bounds, transcode_threads, &on_phase, cancel, encoder_cache)?
};
if outcome.cancelled { return Err(video_cancelled_err()); }
if outcome.exit_code != 0 { return Err(video_prep_err()); }
```

- [ ] **Step 3: Add the ladder + spawn helpers** in `upload.rs`:

```rust
use maxsecu_media_launcher::{Confinement, FfmpegLauncher, H264Encoder, VideoArg, FfmpegOutcome};

/// Run one ingest spawn under FULL confinement (probe/copy/x264).
fn run_confined_ingest(
    ffmpeg_path: &Path, args: &[std::ffi::OsString], dir: &Path,
    on_phase: &(impl Fn(crate::state::PreparePhase) + Sync), cancel: &std::sync::atomic::AtomicBool,
) -> Result<FfmpegOutcome, UiError> {
    FfmpegLauncher::new(ffmpeg_path)
        .run(args, dir, |p| on_phase(crate::state::PreparePhase::Transcoding { percent: p.percent }), cancel)
        .map_err(|_| video_prep_err())
}

/// Re-encode the video to H.264, walking NVENC → AMF → x264. GPU rungs use the
/// GpuGrant confinement; x264 is fully confined. The winning rung is cached so later
/// uploads skip dead GPU rungs. A GPU rung that produces a nonzero exit OR a cancel
/// is retried on the NEXT rung (a real user-cancel short-circuits — checked first).
#[allow(clippy::too_many_arguments)]
fn run_reencode_ladder(
    ffmpeg_path: &Path, input: &Path, out_mp4: &Path, thumb: &Path,
    plan: &maxsecu_media_launcher::IngestPlan,
    options: &TranscodeOptions, bounds: &VideoBounds, threads: u16,
    on_phase: &(impl Fn(crate::state::PreparePhase) + Sync), cancel: &std::sync::atomic::AtomicBool,
    encoder_cache: &std::sync::Mutex<Option<H264Encoder>>,
) -> Result<FfmpegOutcome, UiError> {
    // Ladder: cached winner first (if any), else the full GPU→CPU order.
    let order: Vec<H264Encoder> = match *encoder_cache.lock().unwrap() {
        Some(enc) => vec![enc],
        None => vec![H264Encoder::Nvenc, H264Encoder::Amf, H264Encoder::X264],
    };
    let mut last_err = video_prep_err();
    for enc in order {
        let args = maxsecu_media_launcher::build_ingest_args(
            input, out_mp4, thumb, VideoArg::Encode(enc), plan.reencode_audio, options, bounds, threads);
        let confine = if matches!(enc, H264Encoder::X264) { Confinement::Full } else { Confinement::GpuGrant };
        let outcome = FfmpegLauncher::new(ffmpeg_path)
            .with_confinement(confine)
            .run(&args, out_mp4.parent().unwrap(),
                 |p| on_phase(crate::state::PreparePhase::Transcoding { percent: p.percent }), cancel)
            .map_err(|_| video_prep_err())?;
        // A genuine user cancel short-circuits (never fall through to the next rung).
        if outcome.cancelled { return Ok(outcome); }
        if outcome.exit_code == 0 {
            *encoder_cache.lock().unwrap() = Some(enc);   // remember the winner
            return Ok(outcome);
        }
        last_err = video_prep_err();   // GPU rung failed to init/encode → try next
    }
    Err(last_err)
}
```

Add `encoder_cache: &std::sync::Mutex<Option<H264Encoder>>` to `prepare_video_streams`' signature and thread it from `commands::upload::stage_upload` (pass `&state.0` from the managed `H264EncoderCache`, or a `&Default::default()` for the confined-ingest e2e/test that doesn't exercise the GPU path).

- [ ] **Step 4: Fix any remaining `build_ffmpeg_args` references** (e.g. `ffmpeg_confine_windows.rs`, `video_upload_e2e.rs`) to use `build_ingest_args` with `VideoArg::Encode(H264Encoder::X264)` (the always-available path) so tests run without a GPU.

- [ ] **Step 5: Build client-app + media-launcher.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo build --manifest-path crates\client-app\Cargo.toml 2>&1 | tail -20; cargo build -p maxsecu-media-launcher 2>&1 | tail -10`
Expected: both build.

- [ ] **Step 6: Commit.**
```bash
git add crates/client-app/src/upload.rs crates/client-app/src/state.rs crates/client-app/src/main.rs
git commit -m "feat(ingest): orchestrate probe->plan->GPU ladder with session-cached encoder"
```

---

## Task 6: UI — Disk/Memory control in settings

**Files:** Modify `crates/client-app/ui/src/components/settings-screen.ts`, `crates/client-app/ui/src/core/types.ts`.

**Context:** The performance section already renders `ram_cache_cap_mb` etc. Add a Disk/Memory selector bound to `fragment_cache_location`. Keep innerHTML STATIC (a11y XSS lint) — build the control with static markup + `.value`, not interpolated strings.

- [ ] **Step 1: Extend the TS settings type** in `core/types.ts` — add to the performance settings interface:
```ts
fragment_cache_location: "Disk" | "Memory";
```

- [ ] **Step 2: Add a `<select>`** in the performance section of `settings-screen.ts` mirroring the existing controls' pattern (static `<option>Disk</option><option>Memory</option>`, set `.value` from loaded settings, write back on change through the same `set_settings` path the other performance controls use). Label: "Fragment cache". Helper text: "Memory keeps decrypted-stream fragments in RAM only (nothing on disk)." (Note: fragments are ciphertext, but user-facing copy stays simple; the exact wording is non-normative.)

- [ ] **Step 3: Run the UI unit tests (if the settings screen has one) + typecheck.**

Run: `cd crates/client-app/ui; npm test 2>&1 | tail -20` (and/or `npx tsc --noEmit`)
Expected: PASS / no type errors.

- [ ] **Step 4: Commit.**
```bash
git add crates/client-app/ui/src/components/settings-screen.ts crates/client-app/ui/src/core/types.ts
git commit -m "feat(ui): fragment-cache Disk/Memory setting control"
```

---

## Task 7: e2e gates + security sign-off

**Files:** Modify `crates/client-e2e/tests/video_upload_e2e.rs`; create `docs/security-review-2026-07-05-remux-gpu-ingest.md`.

- [ ] **Step 1: Add a copy-path e2e gate.** Using a small **H.264/AAC** MP4 fixture (transcode a tiny source once with the vendored ffmpeg in a build step, or check in a ~tens-of-KB fixture), call `prepare_video_streams` and assert the plan took the **copy path**: the produced `out.mp4` is playable (existing `parse_fragment_index` round-trip already asserted) AND the run was fast/no-encode. Assert via a probe of the OUTPUT that its video codec is still `h264` (unchanged bitstream) — i.e. copy did not re-encode.

```rust
// GATE C (copy path): an H.264/AAC source is stream-copied, not re-encoded.
let probe_in = maxsecu_media_launcher::probe_source(&ffmpeg, &h264_src, &jobdir).unwrap();
assert_eq!(probe_in.video, maxsecu_media_launcher::VideoCodec::H264);
let plan = maxsecu_media_launcher::plan_ingest(&probe_in, &TranscodeOptions::default());
assert!(!plan.reencode_video, "H.264/AAC original must copy, not re-encode");
```

- [ ] **Step 2: Add a re-encode-path gate.** Using a non-H.264 source (the existing `.y4m` used by the current test is raw → `Other` → re-encode), assert `plan.reencode_video == true` and that the confined **x264** path (`VideoArg::Encode(H264Encoder::X264)`) produces a playable `out.mp4` whose output video probes as `h264`. This runs without a GPU (CI has none).

- [ ] **Step 3: Run the e2e.**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates\client-app\Cargo.toml -p maxsecu-client-e2e video_upload 2>&1 | tail -30`
(If client-e2e is in the inner workspace; otherwise use its correct manifest.) Expected: PASS.

- [ ] **Step 4: Write the security sign-off** `docs/security-review-2026-07-05-remux-gpu-ingest.md` covering, per spec §C: (1) GPU-spawn confinement = AppContainer + low-IL + no-network + mem-cap + `ActiveProcessLimit=1` + GPU device grant only (paste the Task-0 spike result: what grant, keys/network confirmed still blocked); if the spike forced a larger relaxation, document its exact exposure as a separate user-approved decision. (2) No new server-visible data (no duration/plaintext metadata; server sees today's ciphertext). (3) H.264/AAC/fMP4 only. (4) RAM cache preserves the ciphertext-only invariant. Verdict + any residuals.

- [ ] **Step 5: Commit.**
```bash
git add crates/client-e2e/tests/video_upload_e2e.rs docs/security-review-2026-07-05-remux-gpu-ingest.md
git commit -m "test(ingest): copy-path + x264 re-encode e2e gates; security sign-off"
```

---

## Final verification (holistic)

- [ ] **Build everything.** `export PATH="$HOME/.cargo/bin:$PATH"; cargo build -p maxsecu-media-launcher; cargo build --manifest-path crates\client-app\Cargo.toml`
- [ ] **Run all touched tests.** media-launcher (`ffmpeg_args`, `probe`, confine), client-app (`fragment_cache`, `config`), client-e2e (`video_upload`).
- [ ] **Redeploy + real upload (dev machine, manual):** build `--bin maxsecu-client-app`, stop the running process, copy exe to `client\maxsecu-client-app.exe`; user relaunches. Upload (a) an existing H.264/AAC MP4 → confirm it completes in **seconds** (copy path), and (b) a non-H.264 source → confirm GPU engages (Task Manager GPU "Video Encode" active) or, if the spike failed, x264 completes far faster than the old AV1. Verify playback + flat first-frame.
- [ ] **Toggle the Memory fragment cache** in settings, play a video, confirm nothing appears under `<dir>/cache/frag/`.

---

## Self-review notes

- **Spec coverage:** §A.1 flow → Task 1 (`plan_ingest`) + Task 5; §A.2 probe → Task 2; §A.3 GPU ladder → Task 5 `run_reencode_ladder`; §A.4 confinement → Task 0 + Task 4; §A.5 orchestration → Task 5; §B RAM cache → Task 3 (+3d wiring, Task 6 UI); §C sign-off → Task 7. All covered.
- **Type consistency:** `H264Encoder`/`VideoArg`/`IngestPlan`/`ProbeResult`/`VideoCodec`/`AudioCodec`/`Confinement`/`FragmentCacheLocation` are defined once (Tasks 1/2/3a/4) and referenced with the same names throughout. `plan_ingest`/`build_ingest_args`/`build_probe_args`/`probe_source`/`open_located`/`with_confinement` signatures match across tasks.
- **Non-goals honored:** no server/wire/`client-core` changes; no duration/metadata; AV1 emit removed (H.264 only).
