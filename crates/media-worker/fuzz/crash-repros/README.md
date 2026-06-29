# `decode_session` regression reproducers

Committed reproducers for findings the `decode_session` fuzz target surfaced on
this host. These are **NOT** in the seed corpus (`../corpus/decode_session/`): a
seed that crashes/OOMs would abort `cargo fuzz run` at startup, and the on-host
`tests/fuzz_replay.rs` deliberately replays only the curated corpus (not these),
so the test suite stays green. They are kept here as documented evidence and as
inputs for the follow-up hardening decision.

## `oom_stsz_overalloc.bin` (697 bytes) — over-allocation OOM

A 697-byte crafted MP4 fragment with a malformed `stsz` (sample-size table) that
drives a **multi-GB allocation during demux/decode** — a small-input → huge-alloc
decompression bomb. It passes the per-fragment **byte** cap
(`VideoBounds::max_fragment_bytes` = 16 MiB; the input is only 697 B) and then
over-allocates internally.

**Production containment (by design):** the decode runs in the OS-confined worker
(`AppContainer` + `Job Object`), whose memory cap
(`DEFAULT_WORKER_MEMORY_CAP_BYTES` = 512 MiB) + process isolation stops the worker
long before the >2 GB allocation completes — either the Job `PROCESS_MEMORY` cap
**kills** it or the over-cap commit fails and Rust's alloc-error handler **aborts**
it; the launcher then returns a bounded error (`DecodeError::Worker` /
`SessionError`) and no frame escapes.

**Where this is actually tested:** the in-process fuzz target / `fuzz_replay` run
with **no Job Object**, so they only **surface** the over-allocation as a raw OOM —
they do NOT exercise the confined memory-cap kill. That kill of THIS repro is
proven by the Windows confined regression test
`tests/oom_kill_windows.rs::f2_oom_overalloc_killed_confined_no_frame_escapes`
(drives this file through a 256 MiB-capped `AppContainerVideoSession`; the worker
is bounded — Job-killed or alloc-failure-aborted — and zero frames escape). It is
**not** a memory-safety / RCE issue (AddressSanitizer reported no memory error).
Recommended upstream follow-up: file a symphonia issue for the missing length
bound in `read_raw_boxed_slice_exact` (an attacker-controlled `stsz` sample size
should not drive an unbounded pre-decode allocation).

## Also observed (no committed repro): rav1d decode panic (F1)

A separate run surfaced a Rust `panic` (`Option::unwrap()` on `None`) inside
`rav1d-1.1.0/src/decode.rs:4997` on hostile AV1 bytes. Containment: in production
the panic **aborts** the confined worker → the launcher returns a bounded error
and no frame escapes. A pure-Rust panic, not memory unsafety. (libFuzzer's
Rust-panic-abort path did not write an artifact on Windows, so no byte-exact
reproducer is committed; the finding is recorded here and in the Task 3.6
sign-off.)

**Important — session-level `catch_unwind` is INEFFECTIVE for F1.** The rav1d
panic unwinds out of a plain `extern "C"` frame; an unwind that tries to cross
that boundary triggers `panic_cannot_unwind` and **aborts the process below any
caller's `catch_unwind`**. So a `catch_unwind` around the session cannot turn F1
into a recoverable per-fragment error — the worker dies regardless. Genuine
per-fragment resilience (decode the next fragment after one panics) would require
**launcher-level worker RESPAWN**, a Gate-4 concern, not a session-level catch.
Recommended upstream follow-up: file a rav1d issue for the `decode.rs:4997`
`unwrap` (a hostile bitstream should yield a decode error, not panic).

See `../README.md` and the Task 3.6 security review for the full write-up. The OOM
in particular has **no** clean in-process fix; the Job memory cap (and the
process-abort-on-panic for F1) is the architectural backstop.
