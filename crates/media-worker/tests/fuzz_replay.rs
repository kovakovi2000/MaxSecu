//! **Corpus-replay harness** for the persistent video decode session (MaxSecu Media
//! App Phase 7, Task 3.6; media-sandbox §3, spec §7).
//!
//! This is the RUNNABLE local proof that the cargo-fuzz corpus + the fuzz logic
//! actually exercise [`VideoSession::feed`] safely on this host — even when
//! libFuzzer itself cannot run (cargo-fuzz/libFuzzer needs a nightly toolchain +
//! sanitizer support that is frequently unavailable on Windows MSVC; see
//! `fuzz/README.md`). It loads EVERY committed seed in
//! `fuzz/corpus/decode_session/`, generates a few hundred deterministic LCG
//! mutations of them, and feeds each as a single `Fragment` through a fresh
//! `VideoSession` — the exact shape of `fuzz_targets/decode_session.rs`.
//!
//! The contract proven for EVERY input (seed and mutation):
//! * **no panic / UB** — a panic inside `feed` propagates out of the CF-2 decode
//!   thread and FAILS the test (it is never swallowed);
//! * **only `Vec<WorkerMsg>` comes back** — any value is acceptable, including
//!   `WorkerMsg::Error(..)` (fail-closed) and, for the valid seeds,
//!   `WorkerMsg::Video(..)` (a real decode). Garbage simply yields `Error`s.
//! * **bounded** — the message count is hard-capped well above any legitimate
//!   single-fragment session, so a runaway/oscillating decode is caught, not hung.
//!
//! CF-2: the whole replay loop runs on ONE 64 MiB-stack thread — the production
//! decode environment (rav1d's single-threaded decode overflows Windows' default
//! 1 MiB main-thread stack) — under a generous wall-clock bound. Deterministic
//! (LCG only, NO `rand`), so it is byte-for-byte reproducible.
//!
//! Run isolated single-threaded:
//! `cargo test -p maxsecu-media-worker --test fuzz_replay -- --test-threads=1`.

use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use maxsecu_client_core::video::{ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_worker::VideoSession;

/// Generous wall-clock bound for the ENTIRE replay set. A run that does not finish
/// within this has hung → test failure (rather than blocking the suite forever).
const BOUND: Duration = Duration::from_secs(180);

/// Number of deterministic mutations generated per seed. With 8 committed seeds this
/// yields 8 + 8*40 = 328 fed inputs — "a few hundred" deterministic cases.
const MUTATIONS_PER_SEED: usize = 40;

/// Hard ceiling on the number of `WorkerMsg`s one single-fragment `feed` may return.
/// A canonical fragment is ONE keyframe → a handful of messages; this is far above
/// any legitimate session yet finite, so a runaway/oscillating decode is caught as a
/// boundedness failure rather than silently producing an unbounded Vec.
const MAX_MSGS_PER_INPUT: usize = 4096;

/// Deterministic LCG byte stream (NO `rand`, byte-for-byte reproducible) — same
/// constants as `bombs_video.rs` so the two suites share one generator shape.
fn lcg_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

/// One deterministic mutation of `base`, selected by `seed`. Covers the mutation
/// families a fuzzer would explore: multi-byte flips, head/tail truncation, splicing
/// in garbage, and appending garbage — all derived from a single LCG so the set is
/// reproducible.
fn mutate(base: &[u8], seed: u64) -> Vec<u8> {
    let mut state = seed ^ 0x2545_F491_4F6C_DD1D;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };
    let mut out = base.to_vec();

    match (seed % 5) as u8 {
        0 => {
            // Flip a handful of bytes at LCG positions.
            if !out.is_empty() {
                let flips = 1 + (next() as usize % 16);
                for _ in 0..flips {
                    let i = (next() as usize) % out.len();
                    out[i] ^= (next() >> 24) as u8;
                }
            }
        }
        1 => {
            // Tail truncation to a random prefix.
            if !out.is_empty() {
                let keep = (next() as usize) % out.len();
                out.truncate(keep);
            }
        }
        2 => {
            // Head drop (skip a random prefix).
            if !out.is_empty() {
                let drop = (next() as usize) % out.len();
                out = out[drop..].to_vec();
            }
        }
        3 => {
            // Splice a small garbage run over a random region.
            if !out.is_empty() {
                let glen = 1 + (next() as usize % 32);
                let at = (next() as usize) % out.len();
                let g = lcg_bytes(glen, next());
                for (k, b) in g.into_iter().enumerate() {
                    if at + k < out.len() {
                        out[at + k] = b;
                    }
                }
            }
        }
        _ => {
            // Append garbage.
            out.extend_from_slice(&lcg_bytes(1 + (next() as usize % 64), next()));
        }
    }
    out
}

/// Feed one arbitrary fragment through a fresh session, exactly like the fuzz
/// target: Open → Fragment(bytes) → Close. Returns the worker messages.
fn feed_fragment(bytes: Vec<u8>) -> Vec<WorkerMsg> {
    let mut session = VideoSession::new();
    let _ = session.feed(ClientMsg::Open {
        bounds: VideoBounds::default(),
    });
    let out = session.feed(ClientMsg::Fragment { seq: 0, bytes });
    let _ = session.feed(ClientMsg::Close);
    out
}

/// Load every committed seed file under `fuzz/corpus/decode_session/`.
fn load_corpus() -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/decode_session");
    let mut seeds: Vec<(String, Vec<u8>)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", dir.display()))
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.is_file() {
                let name = p.file_name()?.to_string_lossy().into_owned();
                let bytes = fs::read(&p).ok()?;
                Some((name, bytes))
            } else {
                None
            }
        })
        .collect();
    seeds.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic order
    assert!(
        seeds.len() >= 5,
        "expected the committed seed corpus (>=5 files), found {}",
        seeds.len()
    );
    seeds
}

#[test]
fn corpus_and_mutations_replay_safely() {
    // CF-2: run the entire replay set on ONE 64 MiB-stack thread (the production
    // single-decode-thread environment) under a wall-clock bound. A panic inside is
    // re-raised on this thread (loud test failure); a timeout is a HANG failure.
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let seeds = load_corpus();
            let mut fed: usize = 0;

            // (1) Every seed verbatim.
            for (name, bytes) in &seeds {
                let n = bytes.len();
                let msgs = feed_fragment(bytes.clone());
                assert!(
                    msgs.len() <= MAX_MSGS_PER_INPUT,
                    "seed {name} ({n} B) returned {} msgs — exceeds bound",
                    msgs.len()
                );
                fed += 1;
            }

            // (2) A few hundred deterministic LCG mutations of the seeds.
            for (si, (_name, bytes)) in seeds.iter().enumerate() {
                for m in 0..MUTATIONS_PER_SEED {
                    let seed = (si as u64).wrapping_mul(0x100) ^ (m as u64).wrapping_mul(0x9E37);
                    let mutated = mutate(bytes, seed);
                    let msgs = feed_fragment(mutated);
                    // The ONLY contract: it returned (no panic) and is bounded. Any
                    // message mix is acceptable (Error/Video/EndOfFragment).
                    assert!(
                        msgs.len() <= MAX_MSGS_PER_INPUT,
                        "mutation (seed {si}, m {m}) returned {} msgs — exceeds bound",
                        msgs.len()
                    );
                    fed += 1;
                }
            }

            let _ = tx.send(fed);
        })
        .expect("spawn 64 MiB replay thread");

    match rx.recv_timeout(BOUND) {
        Ok(fed) => {
            let _ = handle.join();
            // 8 seeds + 8*40 mutations = 328; assert we actually exercised a few hundred.
            assert!(
                fed >= 300,
                "expected to feed a few hundred inputs, fed only {fed}"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => match handle.join() {
            // Thread ended without sending → it panicked inside `feed`. Re-raise so the
            // test fails loudly (a real session panic is a finding, surfaced).
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("replay thread ended without a result"),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("corpus replay did not finish within {BOUND:?} — HANG (test failure)")
        }
    }
}
