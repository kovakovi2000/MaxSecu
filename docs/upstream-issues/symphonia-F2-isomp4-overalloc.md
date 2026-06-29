# `symphonia-format-isomp4`: a crafted `stsz` sample size drives an unbounded up-front `vec![0u8; len]` (4 GiB) in `next_packet` — small-file decompression bomb

**Crate / version:** `symphonia` 0.6.0 → `symphonia-format-isomp4` 0.6.0, `symphonia-core` 0.6.0 (crates.io)
**Component:** `next_packet` → `AtomIterator::read_raw_boxed_slice_exact` → `symphonia_core::io::ReadBytes::read_boxed_slice_exact`
**Severity:** denial of service (uncontrolled memory allocation, CWE-789). **Not** memory-unsafety — AddressSanitizer reported no memory error.

## Summary

A 697-byte crafted MP4 whose sample-size table (`stsz`) declares a sample size of `0xFFFF0000` causes `next_packet` to allocate that many bytes **up front** (`vec![0u8; 0xFFFF0000]` ≈ **4.00 GiB**) for the "sample", *before* discovering the stream only contains 697 bytes. A tiny input thus forces a multi-GiB allocation → OOM/abort. The `stsz` parser itself is correctly bounded; the unbounded allocation is the **packet read** trusting the attacker-controlled sample length.

## Reproducer

`oom_stsz_overalloc.bin` (697 bytes), SHA-256 `d92aed00e9aa985a1cafa1c87ae30b93dfe4eb656cbe8906f96212857bca1ca9`. (Attach the file to the issue; it's committed in our repo at `crates/media-worker/fuzz/crash-repros/oom_stsz_overalloc.bin`.)

Minimal reproduction (mirrors the demux path; trap large allocations so it doesn't actually OOM the host):

```rust
use std::io::Cursor;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::formats::IsoMp4Reader;

fn main() {
    let bytes = std::fs::read("oom_stsz_overalloc.bin").unwrap(); // 697 bytes
    let mss = MediaSourceStream::new(Box::new(Cursor::new(bytes)), MediaSourceStreamOptions::default());
    let mut r = IsoMp4Reader::try_new(mss, FormatOptions::default()).unwrap();
    let _ = r.first_track(TrackType::Video);
    let _ = r.next_packet(); // <-- requests a ~4 GiB Vec here
}
```

`symphonia = { version = "0.6.0", default-features = false, features = ["isomp4", "aac"] }`. Running this with a global-allocator trap that aborts on any request `> 256 MiB` yields a **4294901760-byte (4.00 GiB)** request with this exact backtrace:

```
read_boxed_slice_exact                 symphonia-core-0.6.0/src/io/mod.rs:344   (vec![0u8; len])
AtomIterator::read_raw_boxed_slice_exact   symphonia-format-isomp4-0.6.0/src/atoms/mod.rs:862
demuxer::…::next_packet                symphonia-format-isomp4-0.6.0/src/demuxer.rs:641
```

## Root cause (quoted from 0.6.0)

`symphonia-core/src/io/mod.rs` — the read primitive allocates the full length up front, unconditionally:

```rust
343    fn read_boxed_slice_exact(&mut self, len: usize) -> io::Result<Box<[u8]>> {
344        let mut buf = vec![0u8; len];          // <-- len is attacker-controlled
345        self.read_buf_exact(&mut buf)?;
346        Ok(buf.into_boxed_slice())
347    }
```

`symphonia-format-isomp4/src/demuxer.rs:641` (`next_packet`) reads the next sample via `AtomIterator::read_raw_boxed_slice_exact` (`atoms/mod.rs:862`), passing the sample length taken from the `stsz` table. A crafted `stsz` provides `0xFFFF0000` as the (constant) sample size:

```rust
// atoms/stsz.rs (0.6.0): the table is read with a bounded INITIAL capacity…
let mut entries = Vec::with_capacity(MAX_TABLE_INITIAL_CAPACITY.min(sample_count as usize));
// …but a non-zero `sample_size` is stored verbatim as SampleSize::Constant(sample_size)
```

So `stsz` itself is hardened (bounded initial capacity, EOF-bounded fill loop), but the **stored sample size flows unchecked into the packet read**, where `read_boxed_slice_exact` does `vec![0u8; 0xFFFF0000]` regardless of the bytes actually available.

## Impact

A few hundred bytes → a 4 GiB allocation. On a memory-constrained or many-stream service this is an OOM/abort DoS from a trivially small file.

## Expected vs. actual

- **Expected:** a sample/packet whose declared size exceeds the remaining stream is a format **error**, allocating no more than what's available.
- **Actual:** the full declared size is allocated and zero-filled before any bounds/length check, then the read fails (or the process OOMs first).

## Suggested fix

Bound the up-front allocation by the bytes actually available before allocating, in `next_packet`/`read_raw_boxed_slice_exact` (or at the `read_boxed_slice_exact` boundary):

- Cap the allocation against the remaining stream length (the demuxer knows the enclosing box / stream size), erroring if the declared sample size exceeds it — rather than trusting `stsz`.
- Or grow incrementally (read in capped chunks up to the declared size) so a bogus length cannot pre-allocate gigabytes.
- A general `MAX_*` ceiling on a single packet allocation (analogous to `MAX_TABLE_INITIAL_CAPACITY`) would also bound it.

## Environment

- `symphonia` 0.6.0, `default-features = false`, features `["isomp4", "aac"]`.
- rustc (stable) on `x86_64-pc-windows-msvc`; allocation behavior is platform-independent.

## Notes

Reported as a robustness/DoS hardening issue (uncontrolled allocation), not memory-unsafety — AddressSanitizer reported no memory error. In our deployment the demux runs in an OS-sandboxed worker (process isolation + a hard memory cap + per-fragment respawn), so this is contained to a bounded worker kill; we're filing upstream so other consumers don't OOM on a tiny crafted file.
