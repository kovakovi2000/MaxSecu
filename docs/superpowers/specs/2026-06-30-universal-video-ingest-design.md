# Universal Video Ingest — Design Spec

**Date:** 2026-06-30
**Status:** Approved (brainstorm), pending implementation
**Supersedes/extends:** Phase-7 media-app video path (the deferred R1/R2 "real ffmpeg ingest" residual). See `docs/superpowers/plans/2026-06-29-maxsecu-media-app-phase7-video.md` and `docs/security-review-phase7-mediaapp.md`.

---

## 1. Goal

Let the media app **ingest essentially any common video file** (H.264/H.265/VP9/AV1/MPEG-4/… in mp4/mov/mkv/webm/avi/…, with audio) and transcode it to the **single canonical format the viewer already decodes** — AV1 video + AAC audio in the chunk-aligned CMAF fragment layout — so a clip uploads and plays back **with sound**. Today the confined transcode worker only accepts a bespoke `MXRAWV01` raw-RGB-frames container, so any real file fails with *"That video could not be processed."* (`crates/client-app/src/upload.rs::video_prep_err`).

This is the deferred ffmpeg carve-out (Phase-7 R1 audio + R2 real ingest), done **without weakening the threat model**: the C decoder runs only inside the existing AppContainer+Job sandbox.

## 2. Non-goals (this spec)

- Compiling FFmpeg from source as part of the build (Phase-B hardening — see §12).
- Loudness normalization / advanced audio filters (Phase-B).
- Editing/trimming/rotation UI (duration is never modified).
- Live/streaming ingest.

## 3. Locked decisions

- **D-1 Embedded, integrity-pinned ffmpeg.** A **prebuilt static `ffmpeg.exe`** (single self-contained binary, no DLLs; a recent "latest" build) is **baked into the client** (`include_bytes!`) with its **SHA-256 pinned as a constant**. At runtime it is materialized to `<appdir>/bin/ffmpeg-<sha8>.exe` and **hash-verified every run** (mismatch → re-extract from the in-binary copy). No reliance on the system `PATH`. The bytes ride inside the signed/reproducible client exe, so tampering requires breaking the client binary's own integrity. (Provenance/license: a prebuilt full ffmpeg is GPL — acceptable for a local/personal build; a minimal LGPL-from-source build is Phase-B.)
- **D-2 Decode stays sandboxed.** `media-launcher` spawns `ffmpeg.exe` inside the **existing AppContainer + Job Object** (no network, no keys, `ActiveProcessLimit=1`, kill-on-close, memory cap). The author's **input file** is made readable to the container via an **ACL grant on that one path** (extending the launcher's existing SDDL pipe-grant pattern). ffmpeg writes the transcoded result to **stdout (a pipe)** — no output-file ACL needed. Input is a real **seekable file** (mp4 `moov` may trail), so it is granted as a file, not piped in.
- **D-3 Canonical = AV1 (libsvtav1) video + AAC audio.** ffmpeg decodes anything and re-encodes video to AV1 and audio to AAC-LC. The viewer already links `rav1d` (AV1) + `symphonia` (ISO-MP4 demux + AAC-LC) and has full A/V-sync in the player.
- **D-4 Defaults preserve the source.** **Resolution and bitrate default to the original; duration is NEVER changed.** "Keep original" means no scaling and a bitrate chosen to preserve quality (target the source's measured bitrate; if AV1 at the source bitrate is over-quality, that is acceptable — we do not degrade by default).
- **D-5 Resolution/bitrate menu.** The upload UI exposes a **resolution control** (presets: Original, 2160p, 1440p, 1080p, 720p, 480p, + **Custom W×H**) and a **bitrate control**. Changing resolution **auto-computes a suggested bitrate**; the user may **edit it** or choose **"Original bitrate."** These cross the Tauri seam as `TranscodeOptions` on the stage request.
- **D-6 Keep the canonical layout (fork X).** Re-mux ffmpeg's AV1+AAC into the **existing chunk-aligned, self-contained-MP4-per-fragment** layout the viewer/seek/cache already consume, **extended for multi-frame GOPs + an audio track**, so the tested view/seek/decrypt-while-play path stays stable. A **Phase-0 spike** validates the exact muxing path before committing (and may select a pragmatic variant if X proves disproportionate — see §6 and Plan Phase 0).
- **D-7 Player must not choke on extreme sources.** High bitrate, very high resolution (4K+), and weird/odd aspect ratios must degrade gracefully, never hang or OOM the UI: bounded frame/PCM delivery with backpressure, frame-skip under overload, even-dimension handling for 4:2:0, and display-aspect (SAR) preservation. See §8.

## 4. Architecture & data flow

```
 author picks file (Browse → path)
        │
        ▼
 stage_upload(kind=video, path, options)                      [client-app, codec-free]
        │  grant input-file ACL to the transcode AppContainer SID
        ▼
 media-launcher::TranscodeLauncher                            [confined spawn]
   spawns  ┌─────────────────────────────────────────────┐
           │ AppContainer + Job (no net, no keys,         │
           │ ActiveProcessLimit=1, kill-on-close, mem cap)│
           │   ffmpeg.exe  -i <granted input>             │
           │     -c:v libsvtav1 [scale/bitrate per opts]  │
           │     -c:a aac  -f <intermediate>  pipe:1      │
           └─────────────────────────────────────────────┘
        │  ffmpeg AV1+AAC bytes (stdout)
        ▼
 re-fragment → canonical chunk-aligned self-contained CMAF    [confined / safe component, per spike]
   + fragment index + thumbnail + preview
        │  TranscodeResult { cmaf(A+V), thumbnail, preview, fragments, … }
        ▼
 build_upload (encrypt, self+recovery wrap)  → stage → chunked PUT → finalize   [unchanged TCB]
        ▼
 ── server (zero-knowledge) ──
        ▼
 viewer: fetch → decrypt-while-play → confined decode worker                    [mostly unchanged]
   symphonia demux (A+V) → rav1d (AV1 frames) + symphonia (AAC → PCM)
        │  I420 frames + PCM chunks
        ▼
 <video-player>  WebGL YUV→RGB + Web Audio A/V-sync (with sound)
```

Only `TranscodeOptions`/preview/progress DTOs cross the Tauri seam; keys/wraps/plaintext never do. The decoder is structurally out of the key-holding process (it is `ffmpeg.exe` confined, and the view decoder is `media-worker` confined).

## 5. Components & file map

**New / changed (author side):**
- `crates/client-app/src/ffmpeg_bin.rs` *(new)* — embed the static ffmpeg via `include_bytes!` (from a build-staged path), `ensure_ffmpeg(appdir) -> PathBuf` that materializes + SHA-256-verifies `<appdir>/bin/ffmpeg-<sha8>.exe`. Pinned `FFMPEG_SHA256` constant.
- `crates/media-launcher/src/win32.rs` *(modify)* — add a **confined arbitrary-exe spawn** (program path + argv) and a **file-ACL grant** helper (add the AppContainer SID to a path's DACL, read+execute), reusing the existing capability-SID + Job + pipe machinery. Stdout captured to a bounded buffer.
- `crates/media-launcher/src/lib.rs` *(modify)* — `FfmpegLauncher` (one-shot confined ffmpeg run: program, args, input-file path to ACL, returns captured stdout or a sanitized error).
- `crates/media-transcode-worker/` *(modify)* — replace the rav1e/raw-frame path with the **ffmpeg-driven** transcode: build argv from `TranscodeOptions`, drive `FfmpegLauncher`, then **re-fragment** the AV1+AAC output into canonical chunk-aligned fragments (extend the hand-rolled muxer for multi-frame GOPs + audio; demux of ffmpeg output via the spike-selected method). `loudness_gain_db` stays `None`.
- `crates/client-core/src/media.rs` *(modify)* — `TranscodeRequest` gains `options: TranscodeOptions`; `TranscodeResult` may gain audio metadata as needed; wire codec for the new fields.
- `crates/client-app/src/upload.rs` *(modify)* — `prepare_video_streams` takes a **file path + `TranscodeOptions`** (not raw bytes); ACL + launch + map result; keep the chunk-alignment invariant checks.
- `crates/client-app/src/dto.rs` + `src/commands/upload.rs` *(modify)* — `StageUploadRequest` gains optional `options: TranscodeOptions` for video; auto-bitrate calc lives here or in a small pure module.
- `crates/client-app/src/commands/dialog.rs` — already added (`pick_file`); reuse for the video Browse button.

**UI:**
- `crates/client-app/ui/src/components/upload-screen.ts` *(modify)* — resolution preset + custom W×H + bitrate controls (with auto-calc + "Original" toggles), passed as `options`.
- `crates/client-app/ui/src/core/transcode-opts.ts` *(new)* — pure auto-bitrate calc + option normalization (unit-tested).

**Viewer (mostly verify/extend):**
- `crates/media-worker/src/session.rs` *(verify/extend)* — emit PCM for the AAC track; handle multi-frame fragments (symphonia already demuxes every sample); robustness for large frames.
- `crates/client-app/src/commands/video.rs`, `core/player.ts`, `webgl-yuv.ts` *(verify/extend)* — large-frame transport + backpressure + skip-under-overload (§8).

**Tooling / packaging:**
- `packaging/` + a small fetch/stage script that downloads the pinned static ffmpeg into the build-staged path used by `include_bytes!` (kept out of git; the hash is pinned in source).

## 6. Canonical format & the muxing fork (spike-gated)

The viewer consumes **self-contained MP4 fragments** (`ftyp+moov+mdat` each), **chunk-aligned** to `TRANSCODE_CHUNK_SIZE` (4096), indexed by `FragmentEntry { seq, pts_ms, chunk_start, chunk_len }`. ffmpeg's native fragmented MP4 (`-movflags frag_keyframe+empty_moov`) is an init-segment + `moof/mdat` stream — **not** that layout.

**Fork X (chosen target):** ffmpeg → AV1+AAC in a standard intermediate; **re-mux** into the canonical per-fragment self-contained MP4s (one GOP per fragment, audio interleaved), extending `media-transcode-worker`'s hand-rolled muxer. View/seek/cache untouched.

**Phase-0 spike** must, on a real file from `D:\Images`, prove end-to-end: confined ffmpeg transcode → re-mux → a fragment the **existing** `media-worker::VideoSession` demuxes (symphonia) and decodes (rav1d) to the right geometry **with an AAC track that decodes to PCM**. If the per-GOP self-contained re-mux proves disproportionate, the spike may select **Fork Y** (adopt ffmpeg's standard fragmented MP4 + adapt the fragment-index/seek/cache to init-segment+moof offsets) — recorded in a short ratification note before Phase 1 proceeds. The spike also **pins the exact ffmpeg argv** and the **static ffmpeg binary + SHA-256**.

## 7. UI: resolution / bitrate menu

- **Resolution:** `<select>` — `original` (default), `2160`, `1440`, `1080`, `720`, `480`, `custom`. Custom reveals W and H number inputs. Scaling preserves aspect by default (scale by the chosen *height*, width auto, rounded to even); custom W×H is honored as given (rounded to even).
- **Bitrate:** number input (kbps) + an **"Original bitrate"** checkbox (default on). When the user changes resolution away from `original`, auto-compute a suggested kbps via the bits-per-pixel heuristic in `transcode-opts.ts` and populate the field (unchecking "Original"); the user may edit it.
- All of this is **outside the TCB**; it only shapes the ffmpeg argv built in the worker. Invalid/absurd values are clamped in `transcode-opts.ts` (normalized) and re-clamped server-of-trust-side in the worker against `VideoBounds`.

## 8. Player robustness (D-7)

Extreme sources must not hang/OOM the UI:
- **Even dimensions + SAR:** AV1 4:2:0 needs even width/height; ffmpeg `scale`/`pad` to even, and preserve **display aspect** via SAR so weird/anamorphic sources render at the right shape (the `av01` VisualSampleEntry already carries pixel W/H; document/preserve display aspect).
- **Bounded delivery + backpressure:** frame and PCM emission stay within the existing bounded fragment cache + ring buffers; under decode/transport overload the player **skips** late frames (A/V sync already drops) rather than buffering unboundedly — surfaced as the benign `PlayerPhase::Gap{skipped}` (no oracle).
- **Big frames over the bridge:** 4K I420 frames are large base64 payloads; verify/extend the `maxsecu://video-frame` path to avoid stalling the WebView (chunked/limited in-flight frames; downscale-on-display is a fallback option if needed).
- **Caps:** `VideoBounds` (max_width/height/pixels/framerate/duration/total_bytes/fragment_bytes) bound the worker; choose caps generous enough for 4K but finite. Over-cap → sanitized `video_failed`, never a crash.

## 9. Security model

Running a large C decoder (ffmpeg/libav) on attacker-authored bytes is the system's #1 RCE surface — which is exactly why it runs **only** inside the AppContainer+Job sandbox (no network, no keys, no child processes, kill-on-close, memory-capped), identical to the `media-worker` decode confinement. The input-file ACL grant is **scoped to the single chosen path** for the spawn's lifetime and revoked after. The embedded+hash-pinned ffmpeg removes the "attacker swaps ffmpeg.exe on PATH" vector. A **security-review addendum** (`docs/security-review-universal-video-ingest.md`) must document: the new confined-spawn + file-ACL code, the embed/verify integrity story, the confinement differentials, and bomb/oversize containment — and sign off PASS before the feature is considered done.

## 10. Error handling

All ingest failures (unsupported/corrupt input, ffmpeg nonzero exit, over-cap geometry, re-mux failure, worker abort) collapse to the sanitized `UiError{code:"video_failed", message:"That video could not be processed."}` — no decode oracle, no internal detail. The per-fragment-resilient launcher (`run_session_resilient`) continues to contain a decoder crash mid-playback on the view side.

## 11. Testing

- **Unit:** `transcode-opts.ts` auto-bitrate + clamping; the re-mux/fragment-index invariants (chunk-aligned, contiguous, pts monotonic, audio track present); ffmpeg argv builder from `TranscodeOptions`; `ensure_ffmpeg` materialize+verify (tampered copy → re-extract).
- **Confinement differential (`cfg(windows)`):** the confined ffmpeg spawn is denied network/key-read/child-spawn while an unconfined run is allowed (mirrors `media-worker` containment tests).
- **Bomb/oversize:** garbage/over-cap/decompression-bomb inputs are contained (no panic, no OOM, sanitized error).
- **e2e (real file):** transcode a real clip from `D:\Images` (e.g. the H.264+AAC `ttget-…mp4`) → upload over real TLS → browse → open → assert decoded frame geometry **and** that audio PCM is emitted; back-seek cache hit still works. Plus at least one **odd-aspect / high-res** sample to prove §8.
- **Gates:** `cargo check`/clippy `-D warnings`/`cargo deny`/`cargo audit`; UI `typecheck`+`test`+`test:a11y`+`build`; never `cargo fmt --all`. New crates/UI kept fmt-clean.

## 12. Phasing & residuals

- **Phase A (this spec):** embedded+confined ffmpeg, AV1+AAC canonical, default-preserve + resolution/bitrate menu, audio end-to-end, player robustness, e2e + security sign-off.
- **Phase B (later/residual):** compile a **minimal static ffmpeg from source** (size + reproducibility + LGPL, only the needed demuxers/decoders + AV1/AAC encoders); loudness normalization; broader format/edge-case sweep; large-source (>2 GB) streaming delivery; HDR/10-bit handling review.

## 13. Caps / parameters (initial; tune in the spike)

- Default video encode: `libsvtav1`, preset tuned for a sane speed/quality (e.g. preset 6–8), source resolution + measured-bitrate target.
- `VideoBounds` (worker): max_width 7680, max_height 4320, max_pixels 3840×2160·… (generous 4K+), max_framerate 120, max_duration_ms large, max_total_bytes + max_fragment_bytes finite. Final values set in the spike against real samples.
- `TRANSCODE_CHUNK_SIZE` stays 4096 (must equal the upload `chunk_size`).
