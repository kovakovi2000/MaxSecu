# `media-worker` fuzz — `decode_session`

A [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) / libFuzzer target that
feeds **arbitrary attacker bytes** as a single `Fragment` to a persistent
`VideoSession` (the AV1/CMAF demux + rav1d decode — the system's top RCE surface)
and proves it never panics / aborts / executes UB: for any input it returns a
bounded `Vec<WorkerMsg>` (possibly `Error`). See
`fuzz_targets/decode_session.rs` (CF-2 64 MiB decode stack + panic propagation).

This crate is its **own workspace root** (the empty `[workspace]` in `Cargo.toml`)
so it is **excluded from the main MaxSecu cargo workspace** — `cargo
build/test/clippy --workspace`, `cargo deny check`, and `cargo audit` on the main
workspace never see `libfuzzer-sys` or this `cfg(fuzzing)` target.

## How to run (Linux + nightly, or any host with libFuzzer/ASan)

```sh
cargo install cargo-fuzz            # if not already installed
cd crates/media-worker/fuzz         # (cargo-fuzz also works from crates/media-worker)
cargo +nightly fuzz build decode_session
cargo +nightly fuzz run decode_session -- -max_total_time=60
```

The committed corpus under `corpus/decode_session/` seeds it (3 valid canonical
CMAF fragments + truncated / bit-flipped / trailing-garbage / pure-garbage / zero
blobs). A finding is written to `fuzz/artifacts/decode_session/`.

## Status on this host (Windows 11, MSVC, nightly toolchain)

cargo-fuzz 0.13.2 **builds AND runs** the target here on the installed
`nightly-x86_64-pc-windows-msvc` toolchain, with one host caveat: the
AddressSanitizer-instrumented binary needs `clang_rt.asan_dynamic-x86_64.dll` on
`PATH`. It ships with the MSVC toolchain; add it before running, e.g.

```sh
export PATH="/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/<ver>/bin/Hostx64/x64:$PATH"
cargo +nightly fuzz run decode_session -- -max_total_time=60
```

Without that DLL on `PATH` the binary exits `0xC0000135 STATUS_DLL_NOT_FOUND`.

### Findings (the run was NOT clean — and that is the tool working)

On this host the fuzzer **found genuine decoder DoS inputs** within seconds:

1. a Rust `panic` (`Option::unwrap()` on `None`) inside
   `rav1d-1.1.0/src/decode.rs:4997` on hostile AV1 bytes; and
2. an **over-allocation OOM** from a 697-byte crafted MP4 with a malformed `stsz`
   (small input → multi-GB allocation). Reproducer:
   `crash-repros/oom_stsz_overalloc.bin`.

**Both are contained in production by the OS sandbox, by design:** the decode runs
in the AppContainer + Job-Object worker (512 MiB memory cap + process isolation);
a panic aborts the worker and an over-allocation trips the memory cap (or the
over-cap commit fails and Rust's alloc-error handler aborts the worker), in both
cases killing the worker so the launcher returns a bounded error and no frame
escapes (media-sandbox §3). Neither is memory-unsafety/RCE — AddressSanitizer
reported no memory error; rav1d is pure-Rust.

**What this in-process fuzz/replay does and does NOT prove:** run with **no Job
Object**, it only **surfaces** the over-allocation (as a raw OOM) — it does NOT
exercise the confined memory-cap kill. The actual confined Job-memory-cap kill of
the F2 repro is exercised by the Windows regression test
`tests/oom_kill_windows.rs::f2_oom_overalloc_killed_confined_no_frame_escapes`
(256 MiB-capped `AppContainerVideoSession` → worker bounded, zero frames escape).

For F1 (the rav1d panic), note that a session-level `catch_unwind` is
**ineffective**: the panic unwinds out of a plain `extern "C"` frame, which trips
`panic_cannot_unwind` and aborts the process below any caller `catch_unwind`.
Per-fragment resilience would need launcher-level worker **respawn** (a Gate-4
concern). The OOM (F2) has **no** clean in-process fix — the Job memory cap is the
architectural backstop. Recommended upstream follow-ups: a rav1d issue for the
`decode.rs:4997` `unwrap`, and a symphonia issue for the missing length bound in
`read_raw_boxed_slice_exact`. See `crash-repros/README.md` and the Task 3.6
sign-off for the full triage.

## Runnable local proof on every host

Regardless of whether libFuzzer runs, the SAME corpus + the same fuzz logic are
exercised on the project's Windows MSVC host as a normal test:

```sh
cargo test -p maxsecu-media-worker --test fuzz_replay -- --test-threads=1
```

`tests/fuzz_replay.rs` loads every corpus seed, generates a few hundred
deterministic (LCG, no `rand`) mutations, and feeds each through
`VideoSession::feed` on a 64 MiB thread, asserting **no panic** and a **bounded**
`Vec<WorkerMsg>`. This is the genuine local verification that the corpus + fuzz
logic drive `feed` safely even when libFuzzer cannot run.
