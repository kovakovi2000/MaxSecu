# Upstream issue drafts (decoder fuzzing findings)

Paste-ready bug reports for the two decoder DoS findings the MaxSecu media-app
Phase-7 `decode_session` fuzzer surfaced (see
`crates/media-worker/fuzz/README.md` + `…/crash-repros/README.md`). Both are
**contained in production** by the AppContainer + Job-Object sandbox (memory cap +
process isolation; per-fragment respawn) and are **not** memory-unsafety/RCE
(AddressSanitizer reported no memory error). These drafts are for filing upstream
so the underlying crates gain a graceful bound rather than a panic/OOM.

- [`rav1d-F1-decode-panic.md`](rav1d-F1-decode-panic.md) — `rav1d` 1.1.0: `unwrap()`
  on `None` in `rav1d_submit_frame`'s `on_error` (`src/decode.rs:4997`) → panic →
  process abort across the C ABI. File at https://github.com/memorysafety/rav1d.
- [`symphonia-F2-isomp4-overalloc.md`](symphonia-F2-isomp4-overalloc.md) —
  `symphonia` 0.6.0 (`symphonia-format-isomp4`): a crafted `stsz` sample size drives
  an unbounded up-front `vec![0u8; len]` (4 GiB) in `next_packet` →
  `read_boxed_slice_exact`. Reproducer committed
  (`crates/media-worker/fuzz/crash-repros/oom_stsz_overalloc.bin`, 697 B). File at
  https://github.com/pdeljanov/Symphonia.

Root causes were pinpointed against the exact crates.io sources (rav1d 1.1.0,
symphonia* 0.6.0); F2's allocation site was confirmed with an allocator-trap probe
on the committed 697-byte reproducer (4.00 GiB request at the call chain quoted in
the draft). F1 has no byte-exact minimal reproducer (libFuzzer's panic→abort path
wrote no artifact on the Windows MSVC host), but the offending `unwrap` is quoted
verbatim from the source.
