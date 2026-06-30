//! Shared test support: drive the **vendored** ffmpeg (UNCONFINED, test-only) to
//! produce a real small canonical-source `out.mp4` (AV1 video + AAC-LC audio) from a
//! synthetic lavfi source, using the same canonical encode flags the production ingest
//! pins (ratification §2). The transcode worker's job is to re-mux THIS into the
//! canonical per-fragment CMAF layout, so the tests need a genuine ffmpeg output to
//! feed it. If the vendored ffmpeg is absent, the helpers return `None` and the
//! ffmpeg-dependent tests skip (they are gated, never failing for a missing binary).
#![allow(dead_code)] // each test binary uses a subset of these helpers.

use std::path::PathBuf;
use std::process::Command;

/// The vendored ffmpeg pinned by the ratification, relative to this crate's manifest.
pub fn vendored_ffmpeg() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor/ffmpeg/ffmpeg.exe");
    p.exists().then_some(p)
}

/// Produce a real `out.mp4` (AV1 + AAC-LC, stereo) from a synthetic `testsrc`+`sine`
/// source via the vendored ffmpeg, returning its bytes. `None` if ffmpeg is absent or
/// the encode failed. Uses the canonical encode flags (`-c:v libsvtav1 -g <gop>
/// -svtav1-params keyint=<gop>:pred-struct=1 -pix_fmt yuv420p -c:a aac -ac 2`).
pub fn make_ffmpeg_source(w: u32, h: u32, dur_s: u32, gop: u32) -> Option<Vec<u8>> {
    let ff = vendored_ffmpeg()?;
    let dir = std::env::temp_dir().join(format!(
        "maxsecu_ingest_test_{}_{w}x{h}_{}",
        std::process::id(),
        gop
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let out = dir.join("out.mp4");
    let _ = std::fs::remove_file(&out);

    let result = Command::new(&ff)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            &format!("testsrc=duration={dur_s}:size={w}x{h}:rate=24"),
            "-f",
            "lavfi",
            "-i",
            &format!("sine=duration={dur_s}"),
            "-shortest",
            "-vf",
            "scale=trunc(iw/2)*2:trunc(ih/2)*2",
            "-pix_fmt",
            "yuv420p",
            "-c:v",
            "libsvtav1",
            "-preset",
            "12",
            "-g",
            &gop.to_string(),
            "-svtav1-params",
            &format!("keyint={gop}:pred-struct=1"),
            "-c:a",
            "aac",
            "-ac",
            "2",
        ])
        .arg(&out)
        .output()
        .ok()?;

    if !result.status.success() {
        eprintln!(
            "vendored ffmpeg encode failed (status {:?}):\n{}",
            result.status.code(),
            String::from_utf8_lossy(&result.stderr)
        );
        return None;
    }
    std::fs::read(&out).ok()
}

/// Produce a real canonical `out.mp4` from a genuinely ANAMORPHIC (SAR≠1) synthetic
/// source: a `w`x`h` `testsrc` whose input sample aspect ratio is set to
/// `sar_num/sar_den`, run through the EXACT production SAR-aware Original scale filter
/// (`scale='trunc(iw*sar/2)*2':'trunc(ih/2)*2',setsar=1`). The output is square-pixel at
/// the true display shape — exactly what the confined ingest emits — so the re-mux test
/// can prove anamorphic sources render at the right aspect. `None` if ffmpeg is absent.
pub fn make_anamorphic_ffmpeg_source(
    w: u32,
    h: u32,
    sar_num: u32,
    sar_den: u32,
    dur_s: u32,
    gop: u32,
) -> Option<Vec<u8>> {
    let ff = vendored_ffmpeg()?;
    let dir = std::env::temp_dir().join(format!(
        "maxsecu_ingest_ana_{}_{w}x{h}_{sar_num}_{sar_den}_{gop}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let out = dir.join("out.mp4");
    let _ = std::fs::remove_file(&out);

    // Inject the source SAR, then apply the production SAR-aware Original filter verbatim.
    let vf = format!(
        "setsar={sar_num}/{sar_den},scale='trunc(iw*sar/2)*2':'trunc(ih/2)*2',setsar=1"
    );
    let result = Command::new(&ff)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            &format!("testsrc=duration={dur_s}:size={w}x{h}:rate=24"),
            "-f",
            "lavfi",
            "-i",
            &format!("sine=duration={dur_s}"),
            "-shortest",
            "-vf",
            &vf,
            "-pix_fmt",
            "yuv420p",
            "-c:v",
            "libsvtav1",
            "-preset",
            "12",
            "-g",
            &gop.to_string(),
            "-svtav1-params",
            &format!("keyint={gop}:pred-struct=1"),
            "-c:a",
            "aac",
            "-ac",
            "2",
        ])
        .arg(&out)
        .output()
        .ok()?;

    if !result.status.success() {
        eprintln!(
            "vendored ffmpeg anamorphic encode failed (status {:?}):\n{}",
            result.status.code(),
            String::from_utf8_lossy(&result.stderr)
        );
        return None;
    }
    std::fs::read(&out).ok()
}
