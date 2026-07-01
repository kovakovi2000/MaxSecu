//! Windows AppContainer + Job Object **containment** tests for the author-side
//! transcode worker (DESIGN §8.1/D30). They prove that
//! (a) the confinement does NOT break the re-mux — a confined run still produces a
//! genuinely canonical clip (every fragment decodes through the real viewer), and
//! (b) the confined worker is DENIED network / child-spawn / key-blob-read while the
//! SAME worker run unconfined is allowed. So the test proves the confinement bites,
//! not merely that the action happened to fail — even a parser 0-day in the confined
//! re-mux worker cannot exfiltrate, shell out, or read the user's keys.
//!
//! Mirrors `media-worker/tests/containment_windows.rs`. The functional proof feeds the
//! confined worker a REAL ffmpeg output mp4 (built by the vendored ffmpeg, test-only)
//! and decodes every produced fragment through the unmodified `media-worker::VideoSession`
//! — no `unsafe` in this test at all. Per CF-2 the decode runs on a 64 MiB-stack thread.
//!
//! Run ISOLATED single-threaded (`-- --test-threads=1`): the AppContainer profile name
//! is shared with the decode worker, a known parallel-only flake source.
#![cfg(windows)]

#[path = "common/mod.rs"]
mod common;

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::thread;
use std::time::Duration;

use maxsecu_client_core::media::TranscodeRequest;
use maxsecu_client_core::video::{ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_launcher::TranscodeLauncher;
use maxsecu_media_worker::VideoSession;

const WORKER: &str = env!("CARGO_BIN_EXE_media-transcode-worker");

/// Prime the freshly-built worker exe ONCE before any real confined spawn. On a clean
/// build the FIRST `CreateProcessW` against the just-written binary can hit a
/// COLD-START transient — `ERROR_FILE_NOT_FOUND` (code 2) — while Defender's real-time
/// scan / the AppContainer profile cold-start still holds the new file busy. It fails
/// CLOSED (a failed confined spawn `.expect()`-panics, never a false-ALLOWED), but
/// would otherwise flake this gate single-threaded on a clean build. So before the
/// assertions run we do one confined `--selftest-noop` spawn through the SAME
/// `win32::spawn_confined` path (confinement code untouched), retrying ONLY that
/// specific code-2 transient a few times; once it lands the binary is warm and every
/// later spawn is deterministic. Any OTHER spawn error is surfaced immediately (a real
/// confinement-setup regression is never masked); the noop verdict is discarded.
static WARM: Once = Once::new();
fn warm_up_worker() {
    WARM.call_once(|| {
        let launcher = TranscodeLauncher::new(WORKER);
        for attempt in 0..16 {
            match launcher.selftest(&["--selftest-noop"]) {
                Ok(_) => return, // binary is warm — done.
                Err(e) if e.ctx == "CreateProcessW" && e.code == 2 && attempt < 15 => {
                    // Cold-start ERROR_FILE_NOT_FOUND only — back off briefly and retry.
                    thread::sleep(Duration::from_millis(200));
                }
                Err(e) => panic!("warm-up confined spawn failed unexpectedly: {e}"),
            }
        }
    });
}

/// Run `f` on a 64 MiB-stack thread (CF-2): rav1d's single-threaded decode inside
/// `VideoSession` overflows Windows' default 1 MiB main-thread stack.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .expect("spawn 64 MiB decode thread")
        .join()
        .expect("decode thread panicked")
}

// ===========================================================================
// (1) Functional confined: the AppContainer/Job confinement does NOT break the
// re-mux — a confined run still produces a genuinely canonical, viewer-decodable clip.
// ===========================================================================

#[test]
fn appcontainer_transcode_still_produces_a_canonical_clip() {
    let (w, h) = (64u32, 48u32);
    let Some(source) = common::make_ffmpeg_source(w, h, 1, 12) else {
        eprintln!(
            "SKIP appcontainer_transcode_still_produces_a_canonical_clip: vendored ffmpeg.exe \
             not found at <crate>/../../vendor/ffmpeg/ffmpeg.exe"
        );
        return;
    };
    warm_up_worker();

    // Drive the REAL confined worker (AppContainer + Job Object) end-to-end: framed
    // request in, framed result out, over the confined stdio pipes.
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let out = TranscodeLauncher::new(WORKER)
        .transcode(
            &TranscodeRequest {
                source,
                bounds: VideoBounds::default(),
            },
            &cancel,
        )
        .expect("confined transcode worker should still produce a result");

    assert!(!out.fragments.is_empty(), "confined run produced fragments");

    // Slice each chunk-aligned fragment straight out of `cmaf` by its index range and
    // decode it through the unmodified viewer — i.e. the confined output is a genuinely
    // canonical clip, confinement did NOT corrupt it.
    let frags: Vec<Vec<u8>> = out
        .fragments
        .iter()
        .map(|fr| {
            let s = fr.chunk_start as usize * 4096;
            let e = (fr.chunk_start + fr.chunk_len) as usize * 4096;
            out.cmaf[s..e].to_vec()
        })
        .collect();
    let n = frags.len();

    let frames = on_big_stack(move || {
        let mut session = VideoSession::new();
        assert_eq!(
            session.feed(ClientMsg::Open {
                bounds: VideoBounds::default()
            }),
            vec![WorkerMsg::Ready]
        );
        let mut frames = 0usize;
        for (i, frag) in frags.iter().enumerate() {
            for m in session.feed(ClientMsg::Fragment {
                seq: i as u32,
                bytes: frag.clone(),
            }) {
                match m {
                    WorkerMsg::Video(f) => {
                        assert_eq!((f.width, f.height), (w, h), "confined fragment geometry");
                        frames += 1;
                    }
                    WorkerMsg::EndOfFragment { .. } => {}
                    WorkerMsg::Error(e) => panic!("confined fragment decode error: {e:?}"),
                    other => panic!("unexpected worker message: {other:?}"),
                }
            }
        }
        session.feed(ClientMsg::Close);
        frames
    });
    assert!(
        frames >= n,
        "every confined fragment decoded ({frames} frames, {n} fragments)"
    );
}

// ===========================================================================
// (2) Differential containment: the SAME worker is DENIED net/spawn/read when
// confined, yet allowed when run unconfined — so the confinement is what blocks
// them, not a general inability. (Source-format-independent: uses --selftest probes.)
// ===========================================================================

/// Run a worker `--selftest-*` probe WITHOUT confinement (plain child) and return its
/// verdict (`true` = the action SUCCEEDED). The differential against the confined
/// `TranscodeLauncher::selftest` is what proves confinement bites.
fn unconfined_selftest(args: &[&str]) -> bool {
    let out = Command::new(WORKER)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("spawn unconfined worker");
    out.stdout.first().copied() == Some(1)
}

#[test]
fn appcontainer_blocks_network_while_unconfined_allows() {
    warm_up_worker();
    // A loopback listener the worker will try to reach (offline, deterministic).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || loop {
        if listener.accept().is_err() {
            break;
        }
    });
    let ports = port.to_string();
    let args = ["--selftest-net", ports.as_str()];

    // Sanity: the same worker unconfined DOES reach loopback.
    assert!(
        unconfined_selftest(&args),
        "unconfined worker should reach loopback (test sanity)"
    );

    // The containment gate: the AppContainer worker cannot reach the network.
    let confined = TranscodeLauncher::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    assert!(
        !confined,
        "AppContainer transcode worker reached the network — confinement FAILED"
    );
}

#[test]
fn appcontainer_blocks_reading_the_key_blob_while_unconfined_allows() {
    warm_up_worker();
    // A stand-in for the user's `local_key_blob`: a file in the user profile that does
    // not grant access to app packages.
    let mut path = std::env::temp_dir();
    path.push(format!(
        "maxsecu_transcode_secret_{}.bin",
        std::process::id()
    ));
    std::fs::write(&path, b"PRETEND-KEY-MATERIAL").unwrap();
    let p = path.to_string_lossy().to_string();
    let args = ["--selftest-read", p.as_str()];

    let unconfined = unconfined_selftest(&args);
    let confined = TranscodeLauncher::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    let _ = std::fs::remove_file(&path);

    assert!(
        unconfined,
        "unconfined worker can read the user file (test sanity)"
    );
    assert!(
        !confined,
        "AppContainer transcode worker read the user's key blob — confinement FAILED"
    );
}

#[test]
fn appcontainer_blocks_child_spawn_while_unconfined_allows() {
    warm_up_worker();
    let args = ["--selftest-spawn"];

    assert!(
        unconfined_selftest(&args),
        "unconfined worker can spawn a child (test sanity)"
    );

    let confined = TranscodeLauncher::new(WORKER)
        .selftest(&args)
        .expect("spawn confined worker");
    assert!(
        !confined,
        "Job Object (active-process=1) must block child spawn"
    );
}
