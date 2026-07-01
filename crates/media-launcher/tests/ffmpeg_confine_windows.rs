//! `cfg(windows)` **containment differential** for the confined ffmpeg spawn
//! (Task 2.2, D-2, media-sandbox). Mirrors the `media-worker`
//! `containment_windows.rs` differential pattern: each case asserts the confined
//! `ffmpeg.exe` is DENIED an action that the SAME invocation, run UNCONFINED, is
//! allowed — so the test proves the AppContainer + per-job ACL scoping bites, not
//! merely that ffmpeg happened to fail.
//!
//! Uses the **vendored** ffmpeg at `../../vendor/ffmpeg/ffmpeg.exe` (relative to
//! `CARGO_MANIFEST_DIR`); if it is absent the cases skip with an explicit message
//! (the binary is gitignored and only present on a provisioned dev/build host).
//!
//! Windows-only; run single-threaded (`-- --test-threads=1`): the launcher's
//! AppContainer profile create/derive is shared process-wide, so these cases — and
//! the other containment suites — must not race.
#![cfg(windows)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use maxsecu_media_launcher::FfmpegLauncher;

/// A no-op progress sink for the confinement cases (they assert containment, not the
/// progress contract — that is covered by the pure parser unit tests + the cancel
/// e2e).
fn no_progress() -> impl Fn(maxsecu_media_launcher::FfmpegProgress) + Send {
    |_p| {}
}

/// The pinned vendored ffmpeg, located relative to this crate's manifest dir.
/// `None` (→ skip) when the gitignored binary is not present on this host.
fn vendored_ffmpeg() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vendor")
        .join("ffmpeg")
        .join("ffmpeg.exe");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// A fresh, unique, non-symlinked per-job working directory under the system temp
/// dir (the `run` contract: the CALLER provides this). Removed-then-created so a
/// stale run can't leak ACEs into a reused path.
fn fresh_job_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "maxsecu_ffmpeg_{tag}_{}_{}",
        std::process::id(),
        // a per-call nonce so two cases in one process never collide.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create per-job dir");
    d
}

/// The AV1+AAC transcode argv (a minimal slice of the pinned ratification argv —
/// the full builder is Phase 3): read `input`, write `output`, both as discrete
/// argv elements. `-preset 12` (fastest SVT-AV1) keeps the test quick.
fn transcode_argv(input: &Path, output: &Path) -> Vec<OsString> {
    vec![
        "-y".into(),
        "-i".into(),
        input.into(),
        "-vf".into(),
        "scale=trunc(iw/2)*2:trunc(ih/2)*2".into(),
        "-pix_fmt".into(),
        "yuv420p".into(),
        "-c:v".into(),
        "libsvtav1".into(),
        "-preset".into(),
        "12".into(),
        "-g".into(),
        "10".into(),
        "-svtav1-params".into(),
        "keyint=10:pred-struct=1".into(),
        "-c:a".into(),
        "aac".into(),
        "-b:a".into(),
        "128k".into(),
        "-ac".into(),
        "2".into(),
        output.into(),
    ]
}

/// Generate a tiny synthetic AV1+AAC `input.mp4` at `out` with the vendored ffmpeg
/// run **UNCONFINED** (a plain child) — the source the confined transcode reads.
fn make_synthetic_input(ffmpeg: &Path, out: &Path) {
    let status = Command::new(ffmpeg)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=duration=1:size=64x48:rate=10",
            "-f",
            "lavfi",
            "-i",
            "sine=duration=1:frequency=440",
            "-shortest",
            "-pix_fmt",
            "yuv420p",
            "-c:v",
            "libsvtav1",
            "-preset",
            "12",
            "-c:a",
            "aac",
            "-ac",
            "2",
        ])
        .arg(out)
        .status()
        .expect("spawn unconfined ffmpeg to synthesize input");
    assert!(status.success(), "synthetic input generation failed");
    assert!(out.exists(), "synthetic input.mp4 was not produced");
}

#[test]
fn confined_transcode_succeeds_within_granted_dir() {
    let Some(ffmpeg) = vendored_ffmpeg() else {
        eprintln!("SKIP: vendored ffmpeg.exe not present on this host");
        return;
    };
    let job_dir = fresh_job_dir("ok");
    let input = job_dir.join("input.mp4");
    let output = job_dir.join("output.mp4");

    // Source synthesized UNCONFINED, inside the (soon-to-be-granted) per-job dir.
    make_synthetic_input(&ffmpeg, &input);

    // Confined transcode: reads its granted input, writes its granted output.
    let argv = transcode_argv(&input, &output);
    let cancel = AtomicBool::new(false);
    let outcome = FfmpegLauncher::new(&ffmpeg)
        .run(&argv, &job_dir, no_progress(), &cancel)
        .expect("spawn confined ffmpeg");

    assert_eq!(
        outcome.exit_code,
        0,
        "confined ffmpeg should transcode its granted I/O (exit {}). stderr tail:\n{}",
        outcome.exit_code,
        String::from_utf8_lossy(&outcome.stderr_tail)
    );
    assert!(output.exists(), "confined ffmpeg produced no output.mp4");
    let len = std::fs::metadata(&output).expect("stat output").len();
    assert!(
        len > 256,
        "confined output.mp4 is trivially small ({len} bytes) — likely not a real transcode"
    );

    let _ = std::fs::remove_dir_all(&job_dir);
}

#[test]
fn confined_denies_input_outside_granted_dir_while_unconfined_allows() {
    let Some(ffmpeg) = vendored_ffmpeg() else {
        eprintln!("SKIP: vendored ffmpeg.exe not present on this host");
        return;
    };
    // The source lives in a SEPARATE, NON-granted dir.
    let src_dir = fresh_job_dir("src");
    let input = src_dir.join("input.mp4");
    make_synthetic_input(&ffmpeg, &input);

    // The granted per-job dir is only the OUTPUT workspace; the input is outside it.
    let job_dir = fresh_job_dir("denied");
    let out_unconfined = src_dir.join("out_unconfined.mp4");
    let out_confined = job_dir.join("out_confined.mp4");

    // Sanity: the SAME invocation UNCONFINED reads the outside input and succeeds.
    let argv_unconfined = transcode_argv(&input, &out_unconfined);
    let status = Command::new(&ffmpeg)
        .args(&argv_unconfined)
        .status()
        .expect("spawn unconfined ffmpeg");
    assert!(
        status.success() && out_unconfined.exists(),
        "unconfined ffmpeg should read the outside input (test sanity)"
    );

    // The containment gate: confined, the outside input cannot be opened → fail.
    let argv_confined = transcode_argv(&input, &out_confined);
    let cancel = AtomicBool::new(false);
    let outcome = FfmpegLauncher::new(&ffmpeg)
        .run(&argv_confined, &job_dir, no_progress(), &cancel)
        .expect("spawn confined ffmpeg");
    assert_ne!(
        outcome.exit_code, 0,
        "confined ffmpeg READ an input outside its granted dir — ACL scoping FAILED"
    );
    assert!(
        !out_confined.exists(),
        "confined ffmpeg produced output from a non-granted input — scoping FAILED"
    );

    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&job_dir);
}

/// Generate a LONGER synthetic source (unconfined) so the confined transcode below
/// is still running when the test flips the cancel flag. 15 s of `testsrc`, encoded
/// fast (preset 12) for the SOURCE — the confined re-encode uses a SLOW preset.
fn make_long_input(ffmpeg: &Path, out: &Path) {
    let status = Command::new(ffmpeg)
        .args([
            "-y", "-f", "lavfi", "-i", "testsrc=duration=15:size=640x480:rate=30", "-f", "lavfi",
            "-i", "sine=duration=15:frequency=440", "-shortest", "-pix_fmt", "yuv420p", "-c:v",
            "libsvtav1", "-preset", "12", "-c:a", "aac", "-ac", "2",
        ])
        .arg(out)
        .status()
        .expect("spawn unconfined ffmpeg to synthesize long input");
    assert!(status.success() && out.exists(), "long synthetic input generation failed");
}

/// The transcode argv with a DELIBERATELY slow SVT-AV1 preset so the confined encode
/// runs for several seconds — long enough to be mid-flight when cancel is flipped.
fn slow_transcode_argv(input: &Path, output: &Path) -> Vec<OsString> {
    vec![
        "-y".into(), "-i".into(), input.into(), "-vf".into(),
        "scale=trunc(iw/2)*2:trunc(ih/2)*2".into(), "-pix_fmt".into(), "yuv420p".into(),
        "-c:v".into(), "libsvtav1".into(), "-preset".into(), "2".into(), "-g".into(), "30".into(),
        "-c:a".into(), "aac".into(), "-b:a".into(), "128k".into(), "-ac".into(), "2".into(),
        output.into(),
    ]
}

/// Task C e2e: a `cancel` flag flipped mid-run terminates the confined ffmpeg and
/// yields the DISTINCT `cancelled` outcome — promptly, well before the absolute
/// backstop. This is the confined analogue of the worker-crate cancel/abort cases.
#[test]
fn cancel_mid_run_kills_confined_ffmpeg_and_reports_cancelled() {
    let Some(ffmpeg) = vendored_ffmpeg() else {
        eprintln!("SKIP: vendored ffmpeg.exe not present on this host");
        return;
    };
    let job_dir = fresh_job_dir("cancel");
    let input = job_dir.join("input.mp4");
    make_long_input(&ffmpeg, &input);
    let output = job_dir.join("out.mp4");
    let argv = slow_transcode_argv(&input, &output);

    // Flip the cancel flag shortly after the confined ffmpeg has started encoding.
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_bg = Arc::clone(&cancel);
    let setter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1_200));
        cancel_bg.store(true, Ordering::Relaxed);
    });

    let started = Instant::now();
    let outcome = FfmpegLauncher::new(&ffmpeg)
        .run(&argv, &job_dir, |_p| {}, &cancel)
        .expect("spawn confined ffmpeg");
    let elapsed = started.elapsed();
    let _ = setter.join();

    assert!(
        outcome.cancelled,
        "a set cancel flag must yield the DISTINCT cancelled outcome (exit {})",
        outcome.exit_code
    );
    assert_ne!(outcome.exit_code, 0, "a cancelled (terminated) ffmpeg exits non-zero");
    // Returned promptly after cancel — NOT after the hour-long absolute backstop.
    assert!(
        elapsed < Duration::from_secs(90),
        "cancel should terminate promptly, took {elapsed:?}"
    );

    let _ = std::fs::remove_dir_all(&job_dir);
}
