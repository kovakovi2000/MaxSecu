//! **Confined per-fragment respawn proof** — the end-to-end demonstration that one
//! aborting fragment in a play window drops ONLY itself, not the whole window
//! (MaxSecu Media App Phase 7, per-fragment-crash-resilience addendum, Task B).
//!
//! `oom_kill_windows.rs` already proves the F2 stsz-over-allocation kills the
//! CONFINED worker (the Job memory cap / alloc-abort backstop) and that NO frame
//! escapes. This test goes one step further: it proves the **resilient** session
//! driver ([`VideoSessionDecoder::run_session_resilient`]) RECOVERS around that
//! killed fragment — a window `[good0, F2-oom, good1]` decodes good0 and good1 to
//! validated I420 while the middle (worker-aborting) fragment is skipped and a
//! FRESH confined worker is respawned for the rest.
//!
//! The good fragments are real canonical AV1/CMAF clips from the SAME fixture
//! generator the other session tests use (so they genuinely decode), and the middle
//! fragment is the committed F2 reproducer
//! (`fuzz/crash-repros/oom_stsz_overalloc.bin`). The worker is genuinely confined
//! (AppContainer + Job, small memory cap) and genuinely killed mid-fragment — the
//! recovery is real, not simulated.
#![cfg(windows)]

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use maxsecu_client_core::video::{validate_i420, ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_worker::{
    AppContainerVideoSession, SessionError, TerminalReason, VideoSessionDecoder,
    MAX_RESPAWNS_PER_WINDOW,
};

#[path = "support/mod.rs"]
mod support;
use support::make_canonical_clip;

/// Absolute path to the built worker binary (cargo provides it for the bin target).
const WORKER: &str = env!("CARGO_BIN_EXE_media-worker");

/// A SMALL per-worker memory cap (256 MiB), well below the ~4.29 GB the F2 input
/// would allocate — the same cap `oom_kill_windows.rs` uses, so the over-allocating
/// worker is genuinely killed mid-fragment, yet a legitimate good fragment decodes
/// comfortably within it.
const SMALL_CAP_BYTES: u64 = 256 * 1024 * 1024;

/// Generous wall-clock bound: a respawn window (good0 → kill → respawn → good1) is
/// sub-second; if it does not finish within this the worker HUNG and the test FAILS
/// rather than blocking forever.
const BOUND: Duration = Duration::from_secs(180);

/// Run `f` on a worker thread under a wall-clock bound (the `run_bounded` guard
/// pattern from `oom_kill_windows.rs`). A timeout → HANG → failure; a panic inside
/// `f` is re-raised here so the test fails loudly.
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
            Ok(()) => panic!("resilient case '{label}': worker thread ended without a result"),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("resilient case '{label}' did not finish within {BOUND:?} — HANG (test failure)")
        }
    }
}

/// Load the committed F2 reproducer (the tiny-input → huge-allocation stsz bomb).
fn oom_repro() -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("fuzz");
    path.push("crash-repros");
    path.push("oom_stsz_overalloc.bin");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read F2 repro {}: {e}", path.display()))
}

/// **The deliverable:** a window of `[Open, good0, F2-oom, good1, Close]` driven
/// through a CONFINED `AppContainerVideoSession::run_session_resilient` recovers the
/// two good fragments to validated I420 frames while the middle aborting fragment is
/// skipped + a fresh confined worker is respawned — one aborting fragment drops only
/// itself, not the window.
#[test]
fn confined_oom_fragment_is_skipped_and_window_recovers() {
    // Two real canonical single-keyframe AV1/CMAF fragments (genuinely decodable to
    // 64x48 I420), encoded on this (default-stack) parent thread — the rav1d decode
    // runs inside the worker, so the parent only muxes (rav1e).
    let clip = make_canonical_clip(64, 48, 2, false);
    let good0 = clip.fragments[0].clone();
    let good1 = clip.fragments[1].clone();
    let repro = oom_repro();

    // Sanity: the repro passes the per-fragment byte cap (it is the tiny-input → huge
    // alloc bomb, not an over-large fragment that the bound would reject up front).
    assert!(
        (repro.len() as u64) <= VideoBounds::default().max_fragment_bytes,
        "F2 repro must be under max_fragment_bytes (tiny-input→huge-alloc bomb)"
    );

    let out = run_bounded("confined-oom-resilient", move || {
        let script = vec![
            ClientMsg::Open {
                bounds: VideoBounds::default(),
            },
            ClientMsg::Fragment {
                seq: 0,
                bytes: good0,
            },
            ClientMsg::Fragment {
                seq: 1,
                bytes: repro,
            },
            ClientMsg::Fragment {
                seq: 2,
                bytes: good1,
            },
            ClientMsg::Close,
        ];
        AppContainerVideoSession::with_memory_cap(WORKER, SMALL_CAP_BYTES)
            .run_session_resilient(&script, MAX_RESPAWNS_PER_WINDOW)
    });

    // The FIRST confined worker must actually have LAUNCHED: `run_session_resilient`
    // returns `Err` only when the first AppContainer + Job spawn itself failed (so the
    // OOM-kill/respawn path was never exercised). Make that a hard requirement so this
    // can't silently pass with zero coverage on a future host.
    let outcome = match out {
        Ok(o) => o,
        Err(SessionError::Spawn(e)) => panic!(
            "the confined worker must have LAUNCHED — a SessionError::Spawn means the \
             AppContainer/Job setup failed and the respawn path was never exercised: {e}"
        ),
        Err(e) => panic!("first confined worker launch failed: {e}"),
    };

    // The middle fragment (seq 1) is the one the confined worker aborted on — it must
    // be SKIPPED, and at least one fresh confined worker respawned for the rest.
    assert!(
        outcome.skipped.contains(&1),
        "the OOM fragment (seq 1) must be skipped; skipped = {:?}",
        outcome.skipped
    );
    assert!(
        outcome.respawns >= 1,
        "a fresh confined worker must have been respawned after the abort; respawns = {}",
        outcome.respawns
    );

    // The window recovered cleanly: the run ended Completed (the respawned worker
    // finished the remaining good fragment), NOT a parent-side Protective cutoff.
    assert_eq!(
        outcome.terminal,
        TerminalReason::Completed,
        "the resilient run must complete after skipping the lone aborting fragment"
    );

    // EXACTLY the two good fragments completed, in order — proving the killed
    // fragment's frame never escaped (no EndOfFragment{1}) and BOTH good0 (before the
    // abort) and good1 (after the respawn) decoded to their EndOfFragment.
    let eofs: Vec<u32> = outcome
        .msgs
        .iter()
        .filter_map(|m| match m {
            WorkerMsg::EndOfFragment { seq } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(
        eofs,
        vec![0, 2],
        "exactly the two good fragments (seq 0 then seq 2) complete; the aborting \
         seq 1 produces no EndOfFragment"
    );

    // Both surviving frames re-validate as 64x48 I420 — the real confined worker was
    // killed mid-fragment, respawned, and decoded good0 AND good1 across the abort.
    let bounds = VideoBounds::default();
    let mut videos = 0usize;
    for m in &outcome.msgs {
        if let WorkerMsg::Video(f) = m {
            assert_eq!((f.width, f.height), (64, 48), "decoded good-fragment dims");
            validate_i420(f, &bounds).expect("surviving frame must validate as I420");
            videos += 1;
        }
    }
    assert_eq!(
        videos, 2,
        "exactly two surviving frames (good0 + good1); the aborting fragment yields none"
    );
}
