# Vendored static FFmpeg (universal-video-ingest, D-1)

This directory holds the **prebuilt static `ffmpeg.exe`** that the client embeds via
`include_bytes!` (decision **D-1** in
`docs/superpowers/specs/2026-06-30-universal-video-ingest-design.md`). At runtime the
client materializes it to `<appdir>/bin/ffmpeg-<sha8>.exe` and **re-verifies its
SHA-256 every run** (see `crates/client-app/src/ffmpeg_bin.rs`). The decoder runs only
inside the existing AppContainer + Job sandbox (no network, no keys, no child
processes, kill-on-close, memory-capped) — see the security model in the spec §9.

**The binary itself is NOT committed** (it is `.gitignore`d). The **SHA-256 below is the
source of truth**: a fresh checkout runs `scripts/fetch-ffmpeg.ps1` to re-stage the
exact pinned binary, and the build's `include_bytes!` + the runtime verify both check
this hash.

## Pinned build

| Field            | Value |
|------------------|-------|
| File             | `vendor/ffmpeg/ffmpeg.exe` |
| **SHA-256**      | `5899192cfbe74807e8e521e98b5e1dcb08ff7f188a7a3a527d2db7193b92c0f9` |
| Size             | 138066432 bytes (131.67 MiB) |
| FFmpeg version   | `n7.1.5-1-g7d0e842004` (7.1.5 release branch; ≤ 7.x) |
| Source           | BtbN FFmpeg-Builds, GitHub releases |
| Asset            | `ffmpeg-n7.1.5-1-g7d0e842004-win64-gpl-7.1.zip` → `bin/ffmpeg.exe` |
| URL              | <https://github.com/BtbN/FFmpeg-Builds/releases/download/autobuild-2026-07-09-14-21/ffmpeg-n7.1.5-1-g7d0e842004-win64-gpl-7.1.zip> |
| Build type       | **static, self-contained single .exe** (no bundled `*.dll`) |

### Build configuration (relevant flags)

`--enable-gpl --enable-version3 --pkg-config-flags=--static` cross-built with
`x86_64-w64-mingw32-gcc` (mingw, pthreads). Codec support relevant to this feature:

- **Encoders:** `libsvtav1` (AV1 video, canonical output), native `aac` (AAC-LC audio).
- **Decoders:** `libdav1d` (AV1), `h264`, `hevc`, `vp9`, plus the usual MPEG-4 family —
  the broad-input coverage the feature needs (mp4/mov/mkv/webm/avi; H.264/H.265/VP9/AV1/…).

### Self-containment

`dumpbin /dependents ffmpeg.exe` lists **only Windows system DLLs** (KERNEL32, ntdll,
ADVAPI32, bcrypt, CRYPT32, WS2_32, the `api-ms-win-crt-*` universal CRT, etc.) — no
`avcodec-*.dll` / `libsvtav1.dll` / other redistributable, and the release zip's `bin/`
contains no `*.dll`. It is therefore a single embeddable binary. (`WS2_32`/winsock is
*imported* but the AppContainer grants no network capability, so sockets are blocked at
runtime regardless — see spec §9.)

## License / provenance

These BtbN `...-gpl` builds are **GPL** (FFmpeg built with `--enable-gpl`). Aggregating
a GPL binary into a local/personal client build (it is invoked as a separate confined
process, not linked into the Rust binary) is acceptable here. A minimal **LGPL** ffmpeg
compiled from source (only the needed demuxers/decoders + AV1/AAC encoders) is an
explicit **Phase-B** residual (spec §12).

## Re-staging on a fresh checkout

```powershell
pwsh scripts/fetch-ffmpeg.ps1   # downloads + SHA-256-verifies vendor/ffmpeg/ffmpeg.exe
```

> NOTE: the URL above points at a **dated, immutable** BtbN autobuild release
> (`autobuild-2026-07-09-14-21`), NOT the rolling `latest` tag — so the asset is frozen
> and the pinned SHA-256 stays valid. `fetch-ffmpeg.ps1` still **fails loudly** on any
> hash mismatch rather than silently embedding an unpinned binary. BtbN does eventually
> prune very old autobuild releases; if the URL 404s, re-pin to a newer dated release
> (update the URL + SHA-256 here, in `scripts/fetch-ffmpeg.ps1`, and `FFMPEG_SHA256` in
> `crates/client-app/src/ffmpeg_bin.rs`, and re-review).
