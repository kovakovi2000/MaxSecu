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
(`AppContainer` + `Job Object`), whose **512 MiB memory cap**
(`DEFAULT_WORKER_MEMORY_CAP_BYTES`) + process isolation **kills** the worker long
before the >2 GB allocation completes; the launcher then returns a bounded error
(`DecodeError::Worker` / `SessionError`) and no frame escapes. This is exactly the
"in-decode over-allocation Job-memory-cap KILL path" that `tests/bombs_video.rs`
documents the Task-3.6 fuzz corpus as exercising (media-sandbox §3). The
in-process fuzz target, run without the Job cap, surfaces it as a raw OOM. It is
**not** a memory-safety / RCE issue (AddressSanitizer reported no memory error).

## Also observed (no committed repro): rav1d decode panic

A separate run surfaced a Rust `panic` (`Option::unwrap()` on `None`) inside
`rav1d-1.1.0/src/decode.rs:4997` on hostile AV1 bytes. Same containment story: in
production the panic aborts the confined worker → the Job is killed → the launcher
returns a bounded error. A pure-Rust panic, not memory unsafety. (libFuzzer's
Rust-panic-abort path did not write an artifact on Windows, so no byte-exact
reproducer is committed; the finding is recorded here and in the Task 3.6
sign-off.)

See `../README.md` and the Task 3.6 security review for the full write-up and the
recommended follow-up (a `catch_unwind`/upstream fix is the launcher/decoder
team's call — the OOM in particular has **no** clean in-process fix; the Job
memory cap is the architectural backstop).
