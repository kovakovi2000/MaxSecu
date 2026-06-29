# `rav1d_submit_frame`: panic (`unwrap()` on `None` `frame_hdr`) on a malformed AV1 bitstream → process abort across the C ABI

**Crate / version:** `rav1d` 1.1.0 (crates.io)
**Component:** `src/decode.rs` — `rav1d_submit_frame` / its inner `on_error`
**Severity:** denial of service (panic → abort). **Not** memory-unsafety — AddressSanitizer reported no memory error.

## Summary

Feeding a crafted AV1 bitstream to the decoder can drive `rav1d_submit_frame` down an error path while the frame's `frame_hdr` is `None`. The inner `on_error` helper then calls `Option::unwrap()` on that `None`, panicking:

```
thread '…' panicked at …/rav1d-1.1.0/src/decode.rs:4997:
called `Option::unwrap()` on a `None` value
```

Because `rav1d` is normally consumed across its C ABI (`dav1d_*`, `pub unsafe extern "C"`), this panic unwinds out of an `extern "C"` frame, which triggers `panic_cannot_unwind` and **aborts the whole process** — below any caller's `catch_unwind`. For a host application a single hostile frame is therefore an unrecoverable crash (DoS).

## Where (quoted from 1.1.0)

`src/decode.rs`, inside `pub fn rav1d_submit_frame(...)`:

```rust
4985    f.frame_hdr = mem::take(&mut state.frame_hdr);
4986    let seq_hdr = f.seq_hdr.clone().unwrap();          // sibling unwrap, same class
4987
4988    fn on_error(
4989        fc: &Rav1dFrameContext,
4990        f: &mut Rav1dFrameData,
4991        out: &mut Rav1dThreadPicture,
4992        cached_error_props: &mut Rav1dDataProps,
4993        m: &Rav1dDataProps,
4994    ) {
4995        fc.task_thread.error.store(1, Ordering::Relaxed);
4996        let _ = mem::take(&mut *fc.in_cdf.try_write().unwrap());
4997        if f.frame_hdr.as_ref().unwrap().refresh_context != 0 {   // <-- panics when frame_hdr == None
4998            let _ = mem::take(&mut f.out_cdf);
4999        }
            …
```

`on_error` is invoked from many error sites in the same function (≈ lines 5023, 5044, 5067, 5114, 5155, 5174, 5343). When `state.frame_hdr` is `None` at line 4985, `f.frame_hdr` becomes `None`, so any of those error paths reaches the `unwrap()` at 4997 and panics. (Line 4986’s `f.seq_hdr.clone().unwrap()` is the same hazard for a missing sequence header.)

## Impact

- A crafted bitstream → guaranteed panic → (across the C ABI) process abort. No memory corruption, but a single attacker-authored frame can crash a long-running decoder/service.
- `catch_unwind` does **not** help when the decoder is driven through the C functions: the unwind cannot cross the `extern "C"` boundary, so it aborts instead.

## Expected vs. actual

- **Expected:** a malformed bitstream yields a decode **error** (`Rav1dResult` / `Dav1dResult` non-zero), not a panic/abort.
- **Actual:** `Option::unwrap()` on `None` → panic → abort.

## Suggested fix

In `on_error` (and the line-4986 `seq_hdr` unwrap), treat absent headers as the error condition they are rather than asserting their presence — e.g. guard with `if let Some(fh) = f.frame_hdr.as_ref() { if fh.refresh_context != 0 { … } }` (and similarly for `seq_hdr`), so the error path completes and returns a decode error instead of panicking. These are unwraps on the *error-handling* path, where the headers may legitimately be `None` for a malformed input.

## How it was found / reproducibility

Found by a `cargo-fuzz`/libFuzzer harness that feeds arbitrary bytes as one CMAF fragment through a demuxer (`symphonia` isomp4) into the `dav1d_send_data` / `dav1d_get_picture` path, on a 64 MiB-stack thread (single-threaded decode, `n_threads = 1`). The panic surfaced within seconds.

**No byte-exact minimal reproducer is attached:** on the Windows-MSVC host, libFuzzer's Rust-panic→abort path did not write a crash artifact, so a minimal input was not captured. The offending code path is, however, unambiguous from the source above (an `unwrap()` on an error path that assumes a header that a hostile bitstream can leave `None`). I'm happy to attempt to capture a byte-exact reproducer on request (re-running with artifact capture / a different host).

## Environment

- `rav1d` 1.1.0, `asm` feature **off** (pure-Rust decode path), `n_threads = 1`.
- rustc (stable) on `x86_64-pc-windows-msvc`; also relevant to any `extern "C"` consumer on any target.

## Notes

This is reported as a robustness/DoS hardening issue, not a memory-safety bug — the pure-Rust port is doing its job (no UB); the residual is a missing graceful-error path. In our deployment the decode is sandboxed (OS process isolation + memory cap + per-fragment worker respawn), so the abort is contained to a single dropped frame; we're filing upstream so other consumers get a decode-error instead of an abort.
