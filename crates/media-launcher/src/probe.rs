//! Source-media classification for the remux-first ingest. Spawns the CONFINED
//! `ffmpeg -i <input>` (no output → ffmpeg prints stream info to stderr and exits
//! non-zero, which is expected) and parses the first Video:/Audio: codec token.
//! `parse_probe` is a pure function; unknown/absent codecs fail toward re-encode.

#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let s = b"  Stream #0:0: Video: av1 (Main)\n  Stream #0:1: Video: h264\n  Stream #0:2: Audio: mp3\n";
        let r = parse_probe(s);
        assert_eq!(r.video, VideoCodec::Av1);
        assert_eq!(r.audio, AudioCodec::Mp3);
    }
}
