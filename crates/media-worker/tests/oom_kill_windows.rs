//! **Confined Job-memory-cap OOM-kill regression** for fuzz finding **F2**
//! (MaxSecu Media App Phase 7, Task 3.7; media-sandbox §3, ratification M-2).
//!
//! Task 3.6's fuzzer found a 697-byte MP4 with a malformed `stsz` (sample-size
//! `0xFFFF0000` ≈ 4.29 GB) that drives symphonia's demux to allocate multiple GB
//! **before any decode** — a tiny-input → huge-allocation OOM that passes the
//! 16 MiB per-fragment byte cap (`VideoBounds::max_fragment_bytes`). The committed
//! reproducer is `fuzz/crash-repros/oom_stsz_overalloc.bin`.
//!
//! **What the in-process fuzz corpus CANNOT exercise:** `fuzz_replay` and the
//! libFuzzer target run `VideoSession::feed` IN-PROCESS — there is no Job Object,
//! so they only SURFACE the over-allocation (as a raw OOM). They do NOT prove the
//! production backstop: the **Job Object `PROCESS_MEMORY` cap kills the
//! over-allocating CONFINED worker** before it exhausts host memory. That claim
//! previously rested on win32 launcher code review alone (ratification M-2).
//!
//! This test closes that gap. It drives the real F2 repro through a genuinely
//! confined [`AppContainerVideoSession`] with a deliberately SMALL memory cap
//! (256 MiB, well under the 4.29 GB the input would allocate) and asserts the
//! security property holds end-to-end: the call returns **BOUNDED** (no hang,
//! under a wall-clock guard) and **no `WorkerMsg::Video` frame ever crosses the
//! confinement boundary**. The over-allocating worker dies — either Job-killed on
//! the memory cap or aborted on allocation failure (Rust's alloc-error handler);
//! BOTH are acceptable bounded outcomes (worker dies, launcher returns bounded, no
//! frame escapes), so this asserts the SECURITY PROPERTY, not a specific exit
//! mechanism (which would be flaky).
#![cfg(windows)]

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use maxsecu_client_core::video::{ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_worker::{AppContainerVideoSession, SessionError, VideoSessionDecoder};

/// Absolute path to the built worker binary (cargo provides it for the bin target).
const WORKER: &str = env!("CARGO_BIN_EXE_media-worker");

/// A SMALL per-worker memory cap (256 MiB) — far below the ~4.29 GB the F2 input
/// would allocate, so the cap is genuinely the thing that stops the worker, yet
/// generous enough for a clean confined launch. The production default is 512 MiB
/// (`DEFAULT_WORKER_MEMORY_CAP_BYTES`); the kill behaviour is the same class.
const SMALL_CAP_BYTES: u64 = 256 * 1024 * 1024;

/// Generous wall-clock bound: if the confined session does not finish within this,
/// the worker HUNG (the cap failed to bound it) and the test FAILS rather than
/// blocking forever. Sized far above a legitimate launch+kill (sub-second) yet
/// finite; also covers the launcher's own 120s spin-backstop wait.
const BOUND: Duration = Duration::from_secs(180);

/// Run `f` on a worker thread under a wall-clock bound (the `run_bounded` guard
/// pattern from `bombs_video.rs`). Returns `f`'s value if it finishes in time; a
/// **timeout** → HANG → test failure; a **panic** inside `f` is re-raised here so
/// the test fails loudly (never swallowed).
fn run_bounded<T: Send + 'static>(label: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let r = f();
            let _ = tx.send(r);
        })
        .expect("spawn bounded worker thread");

    match rx.recv_timeout(BOUND) {
        Ok(v) => {
            let _ = handle.join();
            v
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => match handle.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("oom-kill case '{label}': worker thread ended without a result"),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("oom-kill case '{label}' did not finish within {BOUND:?} — HANG (test failure)")
        }
    }
}

/// Load the committed F2 reproducer. `fuzz/` is its own (workspace-excluded) crate,
/// but the repro is a plain file resolved relative to this crate's manifest dir.
fn oom_repro() -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("fuzz");
    path.push("crash-repros");
    path.push("oom_stsz_overalloc.bin");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read F2 repro {}: {e}", path.display()))
}

/// **The deliverable:** drive the real F2 over-allocation repro through a CONFINED
/// `AppContainerVideoSession` with a small (256 MiB) Job memory cap and prove the
/// production backstop bites — the over-allocating worker is KILLED/aborted and
/// the launcher returns BOUNDED with **zero** `WorkerMsg::Video` escaping. This is
/// the M-2 (ratification) in-demux over-allocation memory-cap kill that the
/// in-process fuzz/replay cannot exercise (they run with no Job Object).
#[test]
fn f2_oom_overalloc_killed_confined_no_frame_escapes() {
    let repro = oom_repro();
    // Sanity: the repro passes the per-fragment byte cap (tiny input → huge alloc).
    assert!(
        (repro.len() as u64) <= VideoBounds::default().max_fragment_bytes,
        "F2 repro must be under max_fragment_bytes (it is the tiny-input→huge-alloc bomb)"
    );

    let out = run_bounded("f2-confined-oom-kill", move || {
        let script = vec![
            ClientMsg::Open {
                bounds: VideoBounds::default(),
            },
            ClientMsg::Fragment {
                seq: 0,
                bytes: repro,
            },
            ClientMsg::Close,
        ];
        AppContainerVideoSession::with_memory_cap(WORKER, SMALL_CAP_BYTES).run_session(&script)
    });

    // The confined worker must actually have LAUNCHED: a `SessionError::Spawn`
    // means the AppContainer + Job Object setup itself failed, so the worker never
    // spawned / fed / over-allocated — `videos == 0` would then pass with ZERO real
    // coverage. Make spawn+feed a HARD requirement so this can't silently pass via a
    // setup failure on a future host/CI (where it would be a coverage gap, not a
    // pass). A genuine over-allocation kill surfaces as the in-stream Err/Ok below.
    assert!(
        !matches!(&out, Err(SessionError::Spawn(_))),
        "the confined worker must have LAUNCHED — a SessionError::Spawn means the \
         AppContainer/Job setup failed and the OOM-kill path was never exercised: {out:?}"
    );

    // The security property — independent of HOW the worker died:
    //  * BOUNDED: `run_bounded` already proved no hang (it returned at all).
    //  * NO FRAME ESCAPES: whether `run_session` returns Err(SessionError::Io) (the
    //    worker died mid-stream → pipe I/O error) OR Ok(msgs) (the worker aborted
    //    after emitting only non-Video messages, e.g. Ready then a clean EOF), there
    //    must be ZERO `WorkerMsg::Video`. A decoded frame here would mean the
    //    over-allocation completed and a frame crossed the boundary — i.e. the cap
    //    did NOT contain F2 (a real finding). The test tolerates BOTH exit paths.
    //
    // On THIS host the bounded outcome arrives as `Err(Io "frame length exceeds
    // ceiling")`: the worker's alloc-failure ABORT text is merged onto the stdout
    // pipe (win32 `hStdError = child_stdout`) and the parent's frame-ceiling guard
    // trips on it. That is one acceptable bounded path; `Ok(msgs)` with only
    // non-Video messages is the other — the asserted property is "bounded + zero
    // Video escapes", not a specific exit mechanism (which would be flaky).
    let videos = match &out {
        Ok(msgs) => msgs
            .iter()
            .filter(|m| matches!(m, WorkerMsg::Video(_)))
            .count(),
        Err(_) => 0, // worker killed mid-session before any frame; bounded error.
    };
    assert_eq!(
        videos, 0,
        "F2 over-allocation must NOT yield a frame across the confined boundary \
         (the Job memory cap / alloc-failure abort must kill the worker first); \
         outcome was: {out:?}"
    );
}
