//! **Decompression-bomb / oversize / garbage rejection** suite for the persistent
//! video decode session (MaxSecu Media App Phase 7, Task 3.5; media-sandbox §3,
//! spec §7).
//!
//! The bytes fed to [`VideoSession`] are **attacker-authored** — the AV1-decode
//! surface is the system's top RCE risk. This suite crafts malicious / degenerate
//! fragments and proves that EACH one is:
//! * **REJECTED** — the session emits `WorkerMsg::Error(DecodeError::..)` (or, for
//!   the confined launcher, returns an error / a `WorkerMsg::Error`), and **no
//!   `WorkerMsg::Video` ever escapes** to the renderer;
//! * **BOUNDED, not hung** — every case runs on a worker thread guarded by a
//!   generous wall-clock ([`run_bounded`]); a HANG is a test FAILURE, never an
//!   infinite wait;
//! * **panic-free** — a panic inside the session propagates out of the worker
//!   thread and FAILS the test (it is never swallowed). A real session
//!   panic/hang surfaced here is a genuine finding, not something to paper over.
//!
//! Cases (driven through the in-process [`VideoSession`], cross-platform &
//! deterministic, on the CF-2 64 MiB stack):
//! 1. **over-`max_fragment_bytes`** — pre-decode byte-cap reject (no decode happens);
//! 2. **oversize-dimension** — post-decode cap reject (closes the Task-3.2 residual:
//!    the dimension cap is enforced AFTER rav1d allocates the frame, by
//!    `validate_i420`/`extract_i420`; the Job Object memory cap is the bomb backstop
//!    for inputs that would over-allocate *during* decode — see ratification M-2);
//! 3. **truncated fragment** — demux fails → `DecodeFailed`;
//! 4. **trailing-data fragment** — deterministic, bounded outcome (clean decode or
//!    clean error), never UB / hang;
//! 5. **pure-garbage / all-zero bytes** — demux fails → `DecodeFailed`;
//! 6. **fragment-before-Open** — fail-closed (`DecodeFailed`, no decoder yet).
//!
//! Scoping: `VideoSession` enforces only the per-fragment, per-frame caps
//! (`max_fragment_bytes` + the post-decode dimension/pixel caps). The other
//! `VideoBounds` ceilings — `max_fragments`, `max_total_bytes`, and the
//! duration/framerate limits — are NOT a session concern: they are enforced one
//! level up by the launcher / fragment-index layer (Gate 4), which decides which
//! and how many fragments to feed. Their absence from this session-level bomb
//! suite is therefore correct scoping, not a coverage gap.
//!
//! Plus a `#[cfg(windows)]` confined case driving a bomb through the OS-isolated
//! [`AppContainerVideoSession`] (the launcher returns bounded — does not hang —
//! and no frame escapes the confined boundary) and a cross-platform
//! [`VideoSubprocessSession`] garbage case over a real process boundary. (Neither
//! confined case triggers an actual worker KILL — both inputs are rejected
//! cleanly and the worker exits 0; the in-decode over-allocation Job-memory-cap
//! kill path is the launcher's concern, exercised by the Task-3.6 fuzz corpus.)

#[path = "support/mod.rs"]
mod support;

use std::sync::mpsc;
use std::time::Duration;

use maxsecu_client_core::sandbox::{DecodeError, OutputReject};
use maxsecu_client_core::video::{ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_worker::VideoSession;

use support::make_canonical_clip;

/// Generous wall-clock bound: a bomb that does not finish within this is a HANG and
/// FAILS the test (rather than blocking the suite forever). Sized far above any
/// legitimate single-fragment decode (milliseconds) yet finite.
const BOUND: Duration = Duration::from_secs(60);

/// Run `f` on a **64 MiB-stack** worker thread (CF-2: rav1d's single-threaded decode
/// overflows Windows' default 1 MiB stack) under a wall-clock bound. Returns `f`'s
/// value if it finishes in time. A **timeout** → the case HUNG → test failure. A
/// **panic** inside `f` is re-raised on this thread → the test FAILS with the panic
/// (never swallowed). This is the "bounded — not hung, no panic" guard every bomb
/// case below runs under.
fn run_bounded<T: Send + 'static>(label: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let r = f();
            // If the receiver already gave up (timeout) this send fails harmlessly.
            let _ = tx.send(r);
        })
        .expect("spawn 64 MiB bounded worker thread");

    match rx.recv_timeout(BOUND) {
        Ok(v) => {
            let _ = handle.join();
            v
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // The worker thread ended WITHOUT sending a result → it panicked.
            // Re-raise the panic on this thread so the test fails loudly (a real
            // session panic is a finding, surfaced — not masked).
            match handle.join() {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(()) => panic!("bomb case '{label}': worker thread ended without a result"),
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("bomb case '{label}' did not finish within {BOUND:?} — HANG (test failure)")
        }
    }
}

/// One independently-decodable closed-GOP fragment (a self-contained tiny MP4 with
/// one AV1 keyframe) at `w`×`h`.
fn one_fragment(w: u32, h: u32) -> Vec<u8> {
    make_canonical_clip(w, h, 1, false)
        .fragments
        .into_iter()
        .next()
        .expect("a 1-frame clip has exactly one fragment")
}

/// Deterministic "garbage": a reproducible LCG byte stream (NO `rand` dep, so the
/// test is byte-for-byte reproducible). `seed` varies the pattern.
fn lcg_garbage(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        // Numerical Recipes LCG constants — deterministic, dependency-free.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

/// Count `WorkerMsg::Video` frames in a message stream — the renderer-escape gauge.
/// Every bomb asserts this is `0`: NO unvalidated/oversize frame ever escapes.
fn count_videos(msgs: &[WorkerMsg]) -> usize {
    msgs.iter()
        .filter(|m| matches!(m, WorkerMsg::Video(_)))
        .count()
}

/// Collect the `DecodeError`s the session emitted (the rejection reasons).
fn errors(msgs: &[WorkerMsg]) -> Vec<DecodeError> {
    msgs.iter()
        .filter_map(|m| match m {
            WorkerMsg::Error(e) => Some(e.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Over-`max_fragment_bytes` — PRE-decode byte-cap reject (no decode happens).
// ---------------------------------------------------------------------------
#[test]
fn bomb_over_max_fragment_bytes_rejected_pre_decode() {
    let msgs = run_bounded("over-max-fragment-bytes", || {
        // A real, legitimately-shaped fragment — but the bounds set a TINY
        // per-fragment byte cap, so it is refused BEFORE the demuxer/decoder is
        // ever touched (media-sandbox §3: the byte cap precedes any allocation).
        let frag = one_fragment(64, 48);
        let bounds = VideoBounds {
            max_fragment_bytes: 10,
            ..VideoBounds::default()
        };
        assert!(
            frag.len() as u64 > bounds.max_fragment_bytes,
            "fixture must exceed the tiny byte cap to exercise the guard"
        );

        let mut session = VideoSession::new();
        assert_eq!(
            session.feed(ClientMsg::Open { bounds }),
            vec![WorkerMsg::Ready]
        );
        session.feed(ClientMsg::Fragment {
            seq: 0,
            bytes: frag,
        })
    });

    // Exactly the pre-decode reject: TooLarge{0,0} (no picture dims — nothing
    // decoded), and NOTHING else (no EndOfFragment, no Video — the byte cap short
    // -circuits before any demux). This proves the pre-allocation guard.
    assert_eq!(
        msgs,
        vec![WorkerMsg::Error(DecodeError::TooLarge {
            width: 0,
            height: 0,
        })],
        "oversized fragment must be rejected pre-decode with TooLarge{{0,0}} only"
    );
    assert_eq!(
        count_videos(&msgs),
        0,
        "no frame may decode past the byte cap"
    );
}

// ---------------------------------------------------------------------------
// 2. Oversize-dimension — POST-decode cap reject (closes the Task-3.2 residual).
// ---------------------------------------------------------------------------
#[test]
fn bomb_oversize_dimension_rejected_post_decode() {
    let msgs = run_bounded("oversize-dimension", || {
        // The fragment passes the byte cap and DECODES to a real 64×48 frame, but
        // the bounds cap width at 32 — so the decoded frame is rejected AFTER
        // rav1d allocates it (extract_i420 / validate_i420 OverCap). This is the
        // documented post-decode cap; the Job Object memory cap is the bomb
        // backstop for inputs that would over-allocate DURING decode (M-2).
        let frag = one_fragment(64, 48);
        let bounds = VideoBounds {
            max_width: 32,
            ..VideoBounds::default()
        };
        let mut session = VideoSession::new();
        assert_eq!(
            session.feed(ClientMsg::Open { bounds }),
            vec![WorkerMsg::Ready]
        );
        session.feed(ClientMsg::Fragment {
            seq: 7,
            bytes: frag,
        })
    });

    assert_eq!(
        count_videos(&msgs),
        0,
        "no over-cap frame may escape to the renderer"
    );
    assert_eq!(
        errors(&msgs),
        vec![DecodeError::OutputRejected {
            reason: OutputReject::OverCap,
        }],
        "the 64×48 frame must be rejected by the post-decode dimension cap (OverCap)"
    );
    assert!(
        matches!(msgs.last(), Some(WorkerMsg::EndOfFragment { seq: 7 })),
        "the fragment still closes with its EndOfFragment marker"
    );
}

// ---------------------------------------------------------------------------
// 3. Truncated fragment — demux fails → DecodeFailed (bounded, no panic).
// ---------------------------------------------------------------------------
#[test]
fn bomb_truncated_fragment_rejected() {
    let msgs = run_bounded("truncated-fragment", || {
        let frag = one_fragment(64, 48);
        // Cut to a small prefix that lands INSIDE the `moov` box (which follows the
        // 28-byte `ftyp` and is several hundred bytes): the isomp4 reader cannot
        // finish parsing the truncated `moov`, so the demux fails cleanly rather
        // than yielding a half-sample. 80 bytes is well past `ftyp` and well short
        // of the full `moov` for every fixture this generates.
        //
        // NOTE: `cut = 80` is coupled to the current 64×48 fixture's `moov` size
        // (it must land inside that `moov`). If the fixture/muxer changes such that
        // 80 no longer falls inside `moov`, this assertion FAILS LOUDLY (the demux
        // would succeed and the expected `DecodeFailed` would not appear) rather
        // than silently passing — acceptable, but fixture-coupled by design.
        let cut = 80.min(frag.len());
        let truncated = frag[..cut].to_vec();

        let bounds = VideoBounds::default();
        let mut session = VideoSession::new();
        assert_eq!(
            session.feed(ClientMsg::Open { bounds }),
            vec![WorkerMsg::Ready]
        );
        session.feed(ClientMsg::Fragment {
            seq: 0,
            bytes: truncated,
        })
    });

    assert_eq!(
        count_videos(&msgs),
        0,
        "a truncated fragment yields no frame"
    );
    assert_eq!(
        errors(&msgs),
        vec![DecodeError::DecodeFailed],
        "a truncated (undemuxable) fragment must fail closed with DecodeFailed"
    );
    assert!(
        matches!(msgs.last(), Some(WorkerMsg::EndOfFragment { seq: 0 })),
        "the fragment still closes with EndOfFragment"
    );
}

// ---------------------------------------------------------------------------
// 4. Trailing-data fragment — deterministic, bounded outcome, never UB/hang.
// ---------------------------------------------------------------------------
#[test]
fn bomb_trailing_data_fragment_bounded_and_deterministic() {
    // A valid fragment with garbage appended after its `mdat`. symphonia may
    // tolerate the trailing slack (clean decode) or reject it (clean error) — the
    // ONLY contract is: bounded, panic-free, deterministic, and never a malformed
    // frame. We run it twice and assert byte-identical output to pin determinism.
    let build = || {
        let mut frag = one_fragment(64, 48);
        frag.extend_from_slice(&lcg_garbage(4096, 0xDEAD_BEEF));
        let bounds = VideoBounds::default();
        let mut session = VideoSession::new();
        session.feed(ClientMsg::Open { bounds });
        session.feed(ClientMsg::Fragment {
            seq: 3,
            bytes: frag,
        })
    };
    let first = run_bounded("trailing-data-a", build);
    let second = run_bounded("trailing-data-b", build);

    assert_eq!(
        first, second,
        "trailing-data outcome must be deterministic across runs"
    );
    // Whatever the outcome, it is a CLEAN one: either a single valid 64×48 frame
    // with no error, or an error with no frame — never both, never a malformed
    // frame, always closed by EndOfFragment.
    let videos = count_videos(&first);
    let errs = errors(&first);
    assert!(
        matches!(first.last(), Some(WorkerMsg::EndOfFragment { seq: 3 })),
        "the fragment must close with EndOfFragment regardless of outcome"
    );
    if videos > 0 {
        assert_eq!(videos, 1, "at most the one real keyframe may decode");
        assert!(
            errs.is_empty(),
            "a clean decode must not also emit an error"
        );
        for m in &first {
            if let WorkerMsg::Video(f) = m {
                assert_eq!(
                    (f.width, f.height),
                    (64, 48),
                    "any emitted frame must be the real, validated 64×48 frame"
                );
            }
        }
    } else {
        assert_eq!(
            errs,
            vec![DecodeError::DecodeFailed],
            "if no frame decodes, the trailing-data fragment fails closed with DecodeFailed"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Pure-garbage / all-zero bytes — demux fails → DecodeFailed.
// ---------------------------------------------------------------------------
#[test]
fn bomb_pure_garbage_rejected() {
    for (label, bytes) in [
        ("lcg-garbage", lcg_garbage(8192, 0x1234_5678)),
        ("all-zero", vec![0u8; 8192]),
    ] {
        let payload = bytes.clone();
        let msgs = run_bounded(label, move || {
            let bounds = VideoBounds::default();
            let mut session = VideoSession::new();
            session.feed(ClientMsg::Open { bounds });
            session.feed(ClientMsg::Fragment {
                seq: 0,
                bytes: payload,
            })
        });

        assert_eq!(count_videos(&msgs), 0, "{label}: garbage yields no frame");
        assert_eq!(
            errors(&msgs),
            vec![DecodeError::DecodeFailed],
            "{label}: unparseable garbage must fail closed with DecodeFailed"
        );
        assert!(
            matches!(msgs.last(), Some(WorkerMsg::EndOfFragment { seq: 0 })),
            "{label}: still closed by EndOfFragment"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Fragment-before-Open — fail-closed (no decoder yet, no panic).
// ---------------------------------------------------------------------------
#[test]
fn bomb_fragment_before_open_fails_closed() {
    let msgs = run_bounded("fragment-before-open", || {
        // No `Open` → no decoder context. A (legitimately small) fragment must NOT
        // decode; the session fails closed.
        let frag = one_fragment(64, 48);
        let mut session = VideoSession::new();
        session.feed(ClientMsg::Fragment {
            seq: 0,
            bytes: frag,
        })
    });

    assert_eq!(count_videos(&msgs), 0, "no frame may decode before Open");
    assert_eq!(
        msgs,
        vec![
            WorkerMsg::Error(DecodeError::DecodeFailed),
            WorkerMsg::EndOfFragment { seq: 0 },
        ],
        "a fragment before Open must fail closed with DecodeFailed + EndOfFragment"
    );
}

// ===========================================================================
// Confined / cross-process bombs — prove the OS-isolated launcher rejects a bomb
// BOUNDED (does not hang) and that NO frame escapes the process boundary. (Both
// inputs here are rejected cleanly; the worker exits 0, it is not killed — the
// in-decode memory-cap kill path is the launcher's concern, fuzzed in Task 3.6.)
// ===========================================================================

/// Absolute path to the built worker binary (cargo provides it for the bin target).
const WORKER: &str = env!("CARGO_BIN_EXE_media-worker");

/// Cross-platform: drive a garbage bomb through the real worker process over a
/// framed duplex (`VideoSubprocessSession`). The worker rejects it (a
/// `WorkerMsg::Error`), no frame crosses the boundary, and the exchange ends
/// bounded — proving the bomb is contained even across a real address-space split.
#[test]
fn bomb_garbage_over_subprocess_session_bounded() {
    use maxsecu_media_worker::{VideoSessionDecoder, VideoSubprocessSession};

    let out = run_bounded("subprocess-garbage", || {
        let bounds = VideoBounds::default();
        let script = vec![
            ClientMsg::Open { bounds },
            ClientMsg::Fragment {
                seq: 0,
                bytes: lcg_garbage(8192, 0xABCD_1234),
            },
            ClientMsg::Close,
        ];
        VideoSubprocessSession::new(WORKER).run_session(&script)
    });

    let msgs = out.expect("the subprocess session must complete (worker rejects, not crashes)");
    assert_eq!(
        count_videos(&msgs),
        0,
        "no frame may cross the process boundary for a garbage fragment"
    );
    assert!(
        errors(&msgs).contains(&DecodeError::DecodeFailed),
        "the worker must reject the garbage fragment with DecodeFailed"
    );
}

/// Windows-confined: drive the **oversize-dimension** bomb through the
/// AppContainer + Job Object launcher. The worker decodes a *legitimate* 64×48
/// frame inside the confinement, the post-decode cap cleanly rejects it
/// (`OverCap`), and the worker then exits 0 — so what this case proves is: the
/// confined launcher returns BOUNDED (does not hang) and ZERO frames cross the
/// AppContainer boundary, re-proving the Task-3.2 post-decode cap ALSO holds
/// across the OS-isolated worker boundary. This worker is NOT killed (it rejects
/// and exits cleanly).
///
/// NOTE — what this case does NOT exercise: the genuine in-decode over-allocation
/// KILL path (Job Object memory cap, and the 120s timeout → TerminateProcess
/// backstop; ratification M-2) is the launcher's responsibility for inputs that
/// would over-allocate DURING decode. That kill is verified by the win32 launcher
/// code review and exercised by the fuzz corpus (Task 3.6) — not by this case,
/// which only crosses the process boundary and hits the post-decode cap.
#[cfg(windows)]
#[test]
fn bomb_oversize_dimension_confined_appcontainer_bounded() {
    use maxsecu_media_worker::{AppContainerVideoSession, VideoSessionDecoder};

    let out = run_bounded("appcontainer-oversize", || {
        let bounds = VideoBounds {
            max_width: 32,
            ..VideoBounds::default()
        };
        let frag = one_fragment(64, 48);
        let script = vec![
            ClientMsg::Open { bounds },
            ClientMsg::Fragment {
                seq: 0,
                bytes: frag,
            },
            ClientMsg::Close,
        ];
        AppContainerVideoSession::new(WORKER).run_session(&script)
    });

    let msgs = out.expect("the confined session must complete bounded (does not hang)");
    assert_eq!(
        count_videos(&msgs),
        0,
        "no over-cap frame may escape the confined worker boundary"
    );
    assert!(
        errors(&msgs).contains(&DecodeError::OutputRejected {
            reason: OutputReject::OverCap,
        }),
        "the confined worker must reject the 64×48 frame with the post-decode OverCap cap"
    );
}
