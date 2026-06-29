//! **cargo-fuzz target**: feed arbitrary attacker bytes as a single `Fragment` to
//! a persistent [`VideoSession`] and prove it never panics / UBs (MaxSecu Media App
//! Phase 7, Task 3.6; media-sandbox §3, spec §7).
//!
//! The AV1/CMAF decode surface (`symphonia` demux + `rav1d` decode) is the system's
//! top RCE risk: the bytes here are 100% attacker-authored. The session's contract
//! is fail-closed — for ANY input it returns a (bounded) `Vec<WorkerMsg>` (possibly
//! `Error`), and **never panics, aborts, or executes UB**. libFuzzer treats any
//! panic/abort/UB (caught by the sanitizer it links) as a crash, so the target body
//! itself asserts nothing beyond "did not panic": surviving = pass.
//!
//! ## CF-2 — 64 MiB decode stack
//! rav1d's single-threaded decode overflows Windows' default 1 MiB main-thread
//! stack (and would spuriously "crash" the fuzzer with a stack overflow that is NOT
//! a real bug). We replicate the PRODUCTION 64 MiB-stack decode environment by
//! running the `feed` calls on a `std::thread::Builder::stack_size(64 << 20)`
//! thread and joining it — so we are fuzzing the DECODE LOGIC, not the stack depth.
//! A genuine decode panic on that thread is re-raised here (`resume_unwind`) so it
//! still registers as a libFuzzer crash.
//!
//! Runnable on Linux/nightly (or any host with libFuzzer/ASan); see `fuzz/README.md`.
//! On the project's Windows MSVC host the equivalent corpus replay runs as a normal
//! `cargo test` (`crates/media-worker/tests/fuzz_replay.rs`).
#![no_main]

use libfuzzer_sys::fuzz_target;

use maxsecu_client_core::video::{ClientMsg, VideoBounds};
use maxsecu_media_worker::VideoSession;

fuzz_target!(|data: &[u8]| {
    // Own the bytes so they can move onto the decode thread.
    let bytes = data.to_vec();

    // CF-2: drive the session on a 64 MiB-stack thread — the production decode
    // environment. A shallow default stack would let a deep (but legitimate) rav1d
    // call chain overflow and masquerade as a crash; the enlarged stack means a
    // crash here is a REAL decode bug, which is exactly what we want libFuzzer to
    // catch.
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let mut session = VideoSession::new();
            // Open → Fragment(arbitrary) → Close. We discard the returned
            // `Vec<WorkerMsg>`: any value (including `Error`) is acceptable; only a
            // panic/abort/UB is a finding (libFuzzer detects it).
            let _ = session.feed(ClientMsg::Open {
                bounds: VideoBounds::default(),
            });
            let _ = session.feed(ClientMsg::Fragment { seq: 0, bytes });
            let _ = session.feed(ClientMsg::Close);
        })
        .expect("spawn 64 MiB fuzz decode thread");

    // Propagate a thread panic as a target panic so a genuine decode panic is still
    // a libFuzzer crash (never swallowed).
    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
});
