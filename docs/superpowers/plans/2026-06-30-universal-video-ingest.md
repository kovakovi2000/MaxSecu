# Universal Video Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the media app ingest essentially any common video file (H.264/H.265/VP9/AV1/… in mp4/mov/mkv/webm/avi, with audio) and transcode it — inside the existing sandbox — to the one canonical AV1+AAC CMAF format the viewer already plays, with a resolution/bitrate menu and default source-preservation.

**Architecture:** A prebuilt static `ffmpeg.exe` is embedded in the client (`include_bytes!`, SHA-256-pinned) and spawned by `media-launcher` inside the existing AppContainer+Job sandbox (no net/keys/children, kill-on-close, mem-capped). ffmpeg decodes any input + re-encodes to AV1 (libsvtav1) + AAC; the output is re-fragmented into the viewer's chunk-aligned self-contained-MP4-per-fragment canonical layout (extended for multi-frame GOPs + audio). The viewer is mostly unchanged (it already links rav1d + symphonia/AAC).

**Tech Stack:** Rust (Tauri client, `media-launcher` win32 AppContainer/JobObject, `media-transcode-worker`, `client-core`), vanilla TS Web Components UI, static FFmpeg (libsvtav1 + aac), rav1d/symphonia (view side, existing).

**Reference spec:** `docs/superpowers/specs/2026-06-30-universal-video-ingest-design.md` (READ FIRST — decisions D-1..D-7, §6 muxing fork, §8 player robustness, §9 security).

**Environment (CRITICAL):**
- `cargo` is NOT on the tool PATH — prefix shells: PS `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";`, bash `export PATH="$HOME/.cargo/bin:$PATH";`.
- UI: build/test from `crates\client-app\ui` — `npm run build|test|test:a11y|typecheck`. The Tauri exe EMBEDS `ui\dist` at compile time; after UI changes rebuild the exe (`cargo build --release -p maxsecu-client-app`) and copy it into BOTH `dist\MaxSecuClient-root` and `dist\MaxSecuClient-bob`.
- NEVER `cargo fmt --all` (pre-existing repo-wide rustfmt drift). Keep NEW crates/UI fmt-clean; hand-match in-file style elsewhere.
- Worker test suites run isolated single-threaded (`-- --test-threads=1`) — shared AppContainer-profile parallel flake.
- Local commits only on a feature branch; do NOT push or merge. Test files in `D:\Images\*.mp4` (the H.264+AAC `ttget-7604733407821771146-video-hd-ttget.com.mp4` is the canonical sample; pick an odd-aspect/high-res one too).
- Each TCB / sandbox / launcher / muxing task gets a DEDICATED security review in addition to the spec+quality review (project pattern).

---

## Phase 0 — Spike & ratification (no production code kept)

### Task 0.1: Pick + pin the static ffmpeg binary

**Files:**
- Create (gitignored): `vendor/ffmpeg/ffmpeg.exe` (the staged binary `include_bytes!` will read).
- Create: `vendor/ffmpeg/README.md` (source URL, version, build flags, SHA-256, license note).
- Create: `scripts/fetch-ffmpeg.ps1` (download the pinned static build → `vendor/ffmpeg/ffmpeg.exe`, verify SHA-256).

- [ ] **Step 1:** Choose a recent **static** Windows ffmpeg build that includes `libsvtav1` and `aac` encoders (e.g. a BtbN `ffmpeg-master-latest-win64-gpl` static build — confirm `ffmpeg -encoders | grep -E "svtav1|aac"` and that it is a single self-contained exe with no DLL deps via `dumpbin /dependents` showing only system DLLs). Record exact version + URL.
- [ ] **Step 2:** Compute its SHA-256; write it into `vendor/ffmpeg/README.md` and remember it for `FFMPEG_SHA256` (Task 1.1).
- [ ] **Step 3:** Add `vendor/ffmpeg/` and any large binary to `.gitignore` (the binary is fetched, the hash is pinned in source). Verify `git status` does not stage the exe.
- [ ] **Step 4:** Add `scripts/fetch-ffmpeg.ps1` that re-downloads + verifies the SHA so a fresh checkout can stage the binary before building.

### Task 0.2: End-to-end transcode + re-mux spike (throwaway)

**Files:**
- Create (throwaway, delete after): `crates/media-transcode-worker/examples/spike_ingest.rs`.
- Create: `docs/superpowers/ratification/2026-06-30-universal-video-ingest-ratification.md` (the kept output).

- [ ] **Step 1:** Drive the pinned ffmpeg as a normal subprocess (NOT yet confined) on `D:\Images\ttget-...mp4`: decode+encode to AV1+AAC. Determine the **exact argv** that produces a stream you can re-fragment. Try first: standard mp4 to a temp file with `-c:v libsvtav1 -c:a aac -g <gop>`; then read samples back.
- [ ] **Step 2:** Re-mux into the **canonical** per-fragment self-contained MP4 (Fork X): one GOP per fragment, audio interleaved, chunk-aligned to 4096. Reuse `media-transcode-worker`'s `mux_av01_fragment`/`build_moov` as the starting point; extend for (a) multiple video samples per fragment with real `stts`/`stsz`/`stss`/`stsc`/`ctts`, and (b) an AAC audio track (`mp4a`/`esds`).
- [ ] **Step 3:** Feed one produced fragment to the **existing** `maxsecu_media_worker::VideoSession` (Open→Fragment→Close) and assert symphonia demuxes it and rav1d decodes frames at the right geometry, AND that the AAC track decodes to PCM. (Use the `media-worker` test support harness as a reference.)
- [ ] **Step 4:** If Fork X re-mux is disproportionate, evaluate **Fork Y** (adopt ffmpeg's native fragmented MP4 + adapt the fragment index/seek/cache). Decide X vs Y.
- [ ] **Step 5:** Write the ratification doc: chosen ffmpeg version+SHA+argv, chosen fork (X/Y) with rationale, the exact fragment layout, the `VideoBounds` caps validated against ≥3 real files (incl. an odd-aspect + a high-res one), and any view-side changes Fork Y would require. **This doc is the source of truth for Phases 1–7.**
- [ ] **Step 6:** Delete `spike_ingest.rs`. Commit ONLY the ratification doc + `vendor/ffmpeg/README.md` + `scripts/fetch-ffmpeg.ps1` + `.gitignore`.

> **GATE:** Do not start Phase 1 until 0.2 proves a confined-capable transcode→re-mux→existing-viewer-decode round trip (with audio) and the fork is chosen. All later "exact bytes/flags" come from the ratification doc.

---

## Phase 1 — Embedded, integrity-pinned ffmpeg

### Task 1.1: `ffmpeg_bin` module — embed + materialize + verify

**Files:**
- Create: `crates/client-app/src/ffmpeg_bin.rs`
- Modify: `crates/client-app/src/lib.rs` (add `pub mod ffmpeg_bin;`)
- Test: `crates/client-app/src/ffmpeg_bin.rs` `#[cfg(test)] mod tests`

- [ ] **Step 1: Write failing tests** for: (a) `verify_sha256(bytes)==FFMPEG_SHA256` for the embedded bytes; (b) `ensure_ffmpeg(tmpdir)` writes `bin/ffmpeg-<sha8>.exe`, returns its path, and the file's hash matches; (c) calling it again with a **tampered** on-disk copy re-extracts the correct bytes; (d) a second call is a no-op (idempotent, hash matches → no rewrite).

```rust
// sketch
pub const FFMPEG_SHA256: [u8; 32] = /* from Task 0.1 */;
static FFMPEG_BYTES: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../vendor/ffmpeg/ffmpeg.exe"));
pub fn ensure_ffmpeg(appdir: &Path) -> Result<PathBuf, UiError> { /* materialize bin/ffmpeg-<sha8>.exe, verify, re-extract on mismatch */ }
```

- [ ] **Step 2:** Run tests → FAIL (module absent). `export PATH=...; cargo test -p maxsecu-client-app ffmpeg_bin -- --test-threads=1`
- [ ] **Step 3:** Implement `ffmpeg_bin.rs` (embed via `include_bytes!`, SHA-256 via `maxsecu_crypto`'s sha256, atomic temp-then-rename write, hash-verify, re-extract on mismatch).
- [ ] **Step 4:** Run tests → PASS. Confirm the release build links (`cargo build --release -p maxsecu-client-app`) and the exe grows by ≈ the ffmpeg size.
- [ ] **Step 5:** Commit `feat(client-app): embed + integrity-verify a static ffmpeg (D-1)`.

> NOTE: `include_bytes!` requires `vendor/ffmpeg/ffmpeg.exe` present at build time (run `scripts/fetch-ffmpeg.ps1` first). If keeping the build green without the binary matters, gate the embed behind a `video-ingest` cargo feature (default-on) and provide a 0-byte fallback under `#[cfg(not(feature))]` — decide in this task and document.

---

## Phase 2 — Confined ffmpeg launcher

### Task 2.1: File-ACL grant helper (`cfg(windows)`)

**Files:**
- Modify: `crates/media-launcher/src/win32.rs`
- Test: `crates/media-launcher/tests/file_acl_windows.rs` (new, `cfg(windows)`)

- [ ] **Step 1: Write failing test:** create an AppContainer SID (reuse the existing capability-SID helper), grant a temp file read+execute for that SID, assert the DACL now contains the SID; then a `revoke` removes it. (Use the same SDDL/`windows-sys` ACL APIs the pipe-grant path uses.)
- [ ] **Step 2:** Run → FAIL. `export PATH=...; cargo test -p maxsecu-media-launcher --test file_acl_windows -- --test-threads=1`
- [ ] **Step 3:** Implement `grant_path_to_appcontainer(path, sid)` + `revoke_path_grant(...)` (RAII guard preferred) in `win32.rs`, mirroring the existing pipe-SDDL pattern. Keep all `unsafe` inside the audited module.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(media-launcher): scoped AppContainer file-ACL grant for confined ffmpeg input`.

### Task 2.2: Confined arbitrary-exe spawn + stdout capture

**Files:**
- Modify: `crates/media-launcher/src/win32.rs`, `crates/media-launcher/src/lib.rs`
- Test: `crates/media-launcher/tests/ffmpeg_confine_windows.rs` (new, `cfg(windows)`)

- [ ] **Step 1: Write failing differential tests** (mirror the existing `media-worker` containment tests): the pinned ffmpeg, spawned confined, (a) succeeds on a tiny transcode reading a granted input + writing stdout; (b) is DENIED network (a self-test arg or a ffmpeg attempt to read a URL fails); (c) cannot spawn a child; (d) cannot read a non-granted file — each proven against an UNCONFINED run being allowed. Cap stdout to a bounded buffer.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `FfmpegLauncher { ffmpeg_path }` with `run(args: &[OsString], input_to_grant: &Path) -> Result<Vec<u8>, SpawnError>`: grant input ACL (RAII), `setup_confined_child` for `ffmpeg.exe + args` (reuse AppContainer+Job+pipes; ffmpeg stdin = NUL, stdout = captured pipe, stderr = NUL per the existing win32 fix), read stdout to a bounded `Vec`, wait bounded, revoke ACL. Map all failure to a sanitized error.
- [ ] **Step 4:** Run → PASS (single-threaded).
- [ ] **Step 5:** Commit `feat(media-launcher): confined ffmpeg spawn with bounded stdout capture (D-2)`. **DEDICATED security review.**

---

## Phase 3 — Transcode pipeline (video, default settings)

### Task 3.1: `TranscodeOptions` DTO + wire codec

**Files:**
- Modify: `crates/client-core/src/media.rs` (`TranscodeRequest` gains `options`, define `TranscodeOptions`), the media wire codec (`encode_/decode_transcode_*`).
- Test: `crates/client-core/src/media.rs` tests (round-trip the new fields).

- [ ] **Step 1: Write failing test:** `TranscodeOptions { resolution: Resolution, bitrate: Bitrate }` (e.g. `Resolution::Original | Height(u32) | Custom{w,h}`, `Bitrate::Original | Kbps(u32)`) round-trips through the request wire codec.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement the types + serde/wire round-trip; `Default = Original/Original`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(client-core): TranscodeOptions (resolution/bitrate, default Original)`.

### Task 3.2: ffmpeg argv builder (pure)

**Files:**
- Create: `crates/media-transcode-worker/src/args.rs`
- Test: same file `#[cfg(test)] mod tests`

- [ ] **Step 1: Write failing tests** for `build_ffmpeg_args(input, options, bounds) -> Vec<OsString>`: Original → no `scale`, AV1+AAC, source-preserving bitrate target; Height(720) → even-rounded `scale=-2:720` + auto-bitrate; Custom{w,h} → even-rounded; Kbps override honored; absurd values clamped to `bounds`. (Exact flags per the ratification doc.)
- [ ] **Step 2:** Run → FAIL. `cargo test -p maxsecu-media-transcode-worker args`
- [ ] **Step 3:** Implement `args.rs` (pure string building; no process spawn). Encode the §7 scaling/even/SAR rules.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(transcode-worker): pure ffmpeg argv builder from TranscodeOptions`.

### Task 3.3: ffmpeg-driven transcode + canonical re-mux

**Files:**
- Modify: `crates/media-transcode-worker/src/lib.rs` (replace raw-frame path), add `src/remux.rs` (multi-frame GOP + audio canonical muxer, extended from the existing hand-rolled muxer).
- Modify: `crates/media-transcode-worker/Cargo.toml` (add the demuxer needed to read ffmpeg output for re-mux — `symphonia` isomp4, matching the view side — unless the ratification chose a layout ffmpeg emits directly).
- Test: `crates/media-transcode-worker/tests/ingest_remux.rs` (uses the pinned ffmpeg + a tiny generated/real clip).

- [ ] **Step 1: Write failing test:** given a real small clip path + `FfmpegLauncher`, `transcode(path, options)` returns a `TranscodeResult` whose `cmaf` is chunk-aligned + contiguous, `fragments` validate (pts monotonic, contiguous chunk ranges), thumbnail/preview are real PNGs, and the canonical `cmaf` demuxes back via symphonia to AV1 frames + an AAC track. (Reuse the Phase-0 spike assertions.)
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement: build argv (3.2) → `FfmpegLauncher.run` (confined) → demux ffmpeg output → `remux.rs` into canonical fragments + index; derive thumbnail/preview from the first decoded frame (reuse `RustImageCodec`). Keep the `TRANSCODE_CHUNK_SIZE`/alignment invariants. Audio carried in `content` (interleaved A+V); `loudness_gain_db = None`.
- [ ] **Step 4:** Run → PASS (single-threaded).
- [ ] **Step 5:** Commit `feat(transcode-worker): ffmpeg-driven AV1+AAC ingest → canonical CMAF (D-3/D-6)`. **DEDICATED security review** (muxing of decoder-adjacent bytes).

### Task 3.4: Wire `prepare_video_streams` to file + options

**Files:**
- Modify: `crates/client-app/src/upload.rs` (`prepare_video_streams(input_path, ffmpeg_path, options, bounds, title, tags)`).
- Modify: `crates/client-app/src/commands/upload.rs` (`stage_upload` video branch: call `ensure_ffmpeg`, pass the picked file PATH + `options`).
- Modify: `crates/client-app/src/dto.rs` (`StageUploadRequest` gains optional `options`; video uses `path`).
- Test: `crates/client-app/src/upload.rs` tests + extend `crates/client-app/tests/video_upload_e2e.rs`.

- [ ] **Step 1: Write failing test:** `stage_upload(kind=video, path=<real clip>, options=Original)` produces a preview with `file_type=video`, fragments present, and content non-empty; chunk-alignment invariant holds.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement: input is now a PATH (no 64 MiB message limit on source); `ensure_ffmpeg` once; map result → `PlaintextStreams`; keep the existing `parse_fragment_index` + coverage checks.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(client-app): stage real video files via confined ffmpeg ingest`.

---

## Phase 4 — Resolution/bitrate menu (UI)

### Task 4.1: Pure auto-bitrate + normalization (TS)

**Files:**
- Create: `crates/client-app/ui/src/core/transcode-opts.ts`
- Test: `crates/client-app/ui/src/core/transcode-opts.test.ts` (add to `package.json` test list)

- [ ] **Step 1: Write failing tests:** `suggestKbps(w,h,fps)` via a bits-per-pixel heuristic; `normalizeOptions` clamps absurd W/H/kbps; `Original` resolution ⇒ no bitrate suggestion (keep Original); changing to 720p ⇒ a sane suggested kbps.
- [ ] **Step 2:** Run → FAIL. (from `crates/client-app/ui`) `npm test`
- [ ] **Step 3:** Implement `transcode-opts.ts` (pure). Add the test file to `package.json`'s `test` script.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(ui): pure transcode-options (auto-bitrate + clamp)`.

### Task 4.2: Upload-screen resolution/bitrate controls

**Files:**
- Modify: `crates/client-app/ui/src/components/upload-screen.ts`
- Modify: `crates/client-app/ui/src/core/types.ts` (mirror `TranscodeOptions`)
- Possibly modify: `crates/client-app/ui/src/a11y.test.ts` (keep green; new controls labelled)

- [ ] **Step 1:** Add (static innerHTML + DOM, no `${}` in innerHTML) a resolution `<select>` (original/2160/1440/1080/720/480/custom), custom W/H inputs (revealed on `custom`), a bitrate number input + "Original bitrate" checkbox. On resolution change → `suggestKbps` populates bitrate (unchecks Original); user can edit. These appear only for `kind=video`.
- [ ] **Step 2:** Build `options` from the controls and pass on `stage_upload` (`{ req: { kind, path, options, title, tags } }`).
- [ ] **Step 3:** `npm run typecheck && npm test && npm run test:a11y` → all green (extend a11y lint if needed; never weaken).
- [ ] **Step 4:** `npm run build`, rebuild exe, restage to both client dirs.
- [ ] **Step 5:** Commit `feat(ui): resolution + bitrate menu for video upload (D-5)`.

---

## Phase 5 — Audio end-to-end (viewer)

### Task 5.1: Verify/extend the decode worker emits AAC PCM

**Files:**
- Modify (if needed): `crates/media-worker/src/session.rs`
- Test: `crates/media-worker/tests/` (a fragment WITH an AAC track → frames + PCM)

- [ ] **Step 1: Write failing test:** feed a canonical A+V fragment (from Task 3.3 output) to `VideoSession`; assert it emits I420 frames AND ≥1 `PcmChunk` with the right channel/sample-rate. (The `has_audio` path + symphonia `aac` exist; this proves the new author output drives them.)
- [ ] **Step 2:** Run → FAIL or reveal the gap.
- [ ] **Step 3:** Implement/extend the session's audio-sample demux+decode (symphonia AAC) → `PcmChunk` emission interleaved with video, monotonic pts.
- [ ] **Step 4:** Run → PASS (single-threaded).
- [ ] **Step 5:** Commit `feat(media-worker): emit AAC PCM for canonical A+V fragments (R1 audio)`. **DEDICATED security review.**

### Task 5.2: Viewer A/V playback smoke

**Files:**
- Modify (if needed): `crates/client-app/src/commands/video.rs`, `ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/core/player.test.ts` (extend)

- [ ] **Step 1:** Confirm `on_audio`/`maxsecu://video-audio` → player Web Audio path plays PCM in A/V sync (unit-level where possible).
- [ ] **Step 2–5:** Fix any gaps; tests green; commit `feat(ui): play AAC audio in A/V sync`.

---

## Phase 6 — Player robustness for extreme sources (D-7)

### Task 6.1: Even-dimension / SAR / odd-aspect handling

**Files:**
- Modify: `crates/media-transcode-worker/src/args.rs` + `remux.rs`
- Test: `args.rs` tests + a real odd-aspect clip in `ingest_remux.rs`

- [ ] **Step 1: Write failing test:** an odd-width (e.g. 1079) or anamorphic source → argv pads/scales to even dims; the canonical `av01` entry preserves display aspect; decode geometry is even and renders at the correct shape.
- [ ] **Step 2–4:** Implement even-rounding + SAR preservation; PASS.
- [ ] **Step 5:** Commit `fix(transcode-worker): even-dimension + display-aspect handling for odd sources`.

### Task 6.2: Bounded delivery + skip-under-overload + big-frame transport

**Files:**
- Modify: `crates/client-app/src/commands/video.rs` (frame/PCM in-flight bound + skip), `ui/src/core/player.ts` (drop late frames), `webgl-yuv.ts` (large frame upload).
- Test: relevant unit tests + a high-res clip in the e2e (Task 7.1).

- [ ] **Step 1: Write failing test / reproduce:** a high-bitrate/4K sample must not stall the bridge or grow memory unboundedly; assert in-flight frames are bounded and late frames are dropped (surfaced as benign `PlayerPhase::Gap{skipped}`).
- [ ] **Step 2–4:** Implement backpressure/skip + verify the bounded fragment cache + worker memory caps cover 4K; PASS.
- [ ] **Step 5:** Commit `fix(player): bounded frame delivery + skip-under-overload for extreme sources`.

---

## Phase 7 — e2e + security sign-off

### Task 7.1: Real-file end-to-end (with audio + an extreme sample)

**Files:**
- Modify: `crates/client-app/tests/video_upload_e2e.rs` (or a new `universal_video_e2e.rs`)

- [ ] **Step 1:** Drive the REAL modules over real loopback TLS: `ensure_ffmpeg` → confined transcode of `D:\Images\ttget-...mp4` (Original options) → `build_upload` → stage → chunked PUT → finalize → fetch → decode: assert decoded frame geometry matches (post even-rounding) AND ≥1 PCM chunk emitted; back-seek cache hit still works. Add a second case with an **odd-aspect / high-res** file and a **resolution-change** (e.g. 720p) case.
- [ ] **Step 2:** Run → iterate to green (single-threaded). `cargo test -p maxsecu-client-app --test <name> -- --test-threads=1`
- [ ] **Step 3:** Commit `test(client-app): universal-video ingest e2e (real file, audio, extreme sample)`.

### Task 7.2: Gates + security review addendum

**Files:**
- Create: `docs/security-review-universal-video-ingest.md`

- [ ] **Step 1:** Run all gates: `cargo check`/clippy `-D warnings`/`cargo deny check`/`cargo audit`; UI `typecheck`+`test`+`test:a11y`+`build`. Resolve any new advisory/ban (note the GPL-ffmpeg aggregation; the embedded exe is not linked into Rust).
- [ ] **Step 2:** Write `docs/security-review-universal-video-ingest.md`: the confined-spawn + file-ACL code, embed/verify integrity story, confinement differentials, bomb/oversize containment, the muxing-of-decoder-adjacent-bytes review, residuals (Phase B). Sign off PASS (no Critical/High/Medium) before "done".
- [ ] **Step 3:** Rebuild the release exe, restage to both `dist\MaxSecuClient-*`, and do a GUI smoke (upload a real clip, watch it play with sound; try a resolution change).
- [ ] **Step 4:** Commit `docs: universal-video-ingest security review (PASS) + memory/spec sync`.

---

## Self-review notes (coverage vs spec)

- D-1 embed+pin → Task 0.1, 1.1. D-2 confined spawn+ACL → 2.1, 2.2. D-3 AV1+AAC → 3.3, 5.1. D-4 default-preserve → 3.2 (Original path). D-5 menu → 3.1, 4.1, 4.2. D-6 keep-canonical/fork-X → 0.2, 3.3. D-7 player robustness → 6.1, 6.2. §9 security → dedicated reviews + 7.2. §11 testing → per-task + 7.1.
- **Spike-derived specifics** (exact ffmpeg version/SHA/argv, the precise fragment/muxing bytes, final `VideoBounds` caps, X-vs-Y) are produced by Task 0.2's ratification doc and consumed by Phases 1–7 — intentionally not fabricated here.
- **Phase B residuals** (compile minimal ffmpeg from source, loudnorm, >2 GB streaming, HDR/10-bit) are explicitly out of this plan.
