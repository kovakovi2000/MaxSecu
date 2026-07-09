//! GPU-encode-in-AppContainer spike (2026-07-05). Answers the deferred question
//! from `docs/superpowers/specs/2026-07-05-fast-remux-gpu-ingest-design.md` §A.4:
//! does `h264_nvenc` / `h264_amf` initialize **inside** the capability-free
//! AppContainer + Job Object the app confines ffmpeg with (keys + network blocked),
//! or does the sandbox block GPU device / driver-DLL access?
//!
//! `#[ignore]`d — it needs a working GPU + driver on the host, so it never runs in
//! the normal suite / CI. Run explicitly on a GPU box:
//!   cargo test -p maxsecu-media-launcher --test gpu_confined_spike -- --ignored --nocapture --test-threads=1
//!
//! A PASS (exit 0, non-empty output) means the app can use that GPU encoder with
//! ZERO confinement relaxation. A FAIL means the sandbox blocks the GPU and a
//! device grant (separately user-approved) would be required.
#![cfg(windows)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use maxsecu_media_launcher::FfmpegLauncher;

fn vendored_ffmpeg() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vendor")
        .join("ffmpeg")
        .join("ffmpeg.exe");
    p.exists().then_some(p)
}

fn fresh_job_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "maxsecu_gpu_spike_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).unwrap();
    d
}

/// Run one confined GPU encode (synthetic `lavfi` input → no file/network needed;
/// output into the single granted job dir) and report exit code + output size.
fn confined_gpu_encode(encoder: &str, extra: &[&str]) -> (u32, u64) {
    let ffmpeg = match vendored_ffmpeg() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: vendored ffmpeg not present");
            return (0, 1); // treat as skip-pass
        }
    };
    let dir = fresh_job_dir(encoder);
    let out = dir.join("out.mp4");
    let mut args: Vec<OsString> = vec![
        "-y".into(),
        "-f".into(),
        "lavfi".into(),
        "-i".into(),
        "testsrc=size=320x240:rate=30:duration=1".into(),
        "-pix_fmt".into(),
        "yuv420p".into(),
        "-c:v".into(),
        encoder.into(),
    ];
    for e in extra {
        args.push((*e).into());
    }
    args.push(out.clone().into_os_string());

    let cancel = AtomicBool::new(false);
    let outcome = FfmpegLauncher::new(&ffmpeg)
        .run(&args, &dir, |_p| {}, &cancel)
        .expect("spawn");
    let size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "[{encoder}] confined exit={} out_size={} (cancelled={})",
        outcome.exit_code, size, outcome.cancelled
    );
    let _ = std::fs::remove_dir_all(&dir);
    (outcome.exit_code, size)
}

#[test]
#[ignore = "needs a working NVIDIA GPU + driver on the host"]
fn nvenc_initializes_inside_appcontainer() {
    let (exit, size) = confined_gpu_encode("h264_nvenc", &["-preset", "p5"]);
    assert_eq!(exit, 0, "h264_nvenc must exit 0 inside the AppContainer");
    assert!(
        size > 0,
        "h264_nvenc must produce non-empty output inside the AppContainer"
    );
}

#[test]
#[ignore = "needs a working AMD GPU + AMF runtime on the host"]
fn amf_initializes_inside_appcontainer() {
    let (exit, size) = confined_gpu_encode("h264_amf", &[]);
    assert_eq!(exit, 0, "h264_amf must exit 0 inside the AppContainer");
    assert!(
        size > 0,
        "h264_amf must produce non-empty output inside the AppContainer"
    );
}
