# Native `<video>` Player — Fragmented-MP4 Fix + Streaming/Preview/Cleanup

> **For agentic workers:** Execute with **superpowers:subagent-driven-development** — a FRESH general-purpose subagent per task (model: sonnet), and the CONTROLLER (Opus 4.8, high effort) reviews each committed diff before dispatching the next. Two-stage review (spec, then a security pass) for the TCB/protocol/format/cleanup tasks (1, 3, 4, 7, 10).

**Branch:** `feat/universal-video-ingest` (local only; do NOT push/merge).
**Supersedes/continues:** `docs/superpowers/plans/2026-07-01-native-video-streaming-player.md` (Tasks 0–9 of that plan are already committed; Task 10 GUI smoke exposed the format wall below).

## Why this plan exists (root cause, from the Task-10 smoke)

The native `<video>` player was wired up (previous plan, committed) but a real clip **plays ~1 second then stops**. Root cause: the stored canonical video content is a **concatenation of self-contained MP4s — one `ftyp`+`moov`+`mdat` per GOP fragment** (`crates/media-transcode-worker/src/remux.rs`, `build_av_fragment`, each `pad_to_chunk`-padded). A native `<video>` needs ONE continuous **fragmented-MP4** (single `ftyp`+`moov` init, then `moof`+`mdat`). Fed the concat, WebView2 plays the first GOP then hits the 2nd `ftyp` and stops.

Two more issues surfaced in the same smoke (both real, both fixed here):
- **Per-range `reauth` → 500s.** WebView2 issues OVERLAPPING range reads; each `serve_range` called `reauth`, contending on the shared `ConnectLock` (`try_lock` → `busy` → 500 → stall).
- **CSP blocks Media Chrome's inline styles** (`style-src-elem/attr blocked=inline`) → huge unstyled controls. Tauri v2 nonces styles, which nullifies `'unsafe-inline'`.

## Approved decisions (user, 2026-07-01)

1. **fMP4 via ffmpeg directly:** the confined embedded ffmpeg emits a real fragmented-MP4; store THAT as the content, **bypassing/removing the custom Rust re-mux worker** (`media-transcode-worker`). (The exact format Task 0 proved WebView2 plays.)
2. **Remove the old confined-decode engine now** — one native path. Because the format change forces the author PREVIEW to native too (the old per-GOP decoder cannot play a continuous fMP4), the entire confined-decode path becomes dead: `core/player.ts`, `core/webgl-yuv.ts`, the `media-worker` decode wiring, and the `decode_and_emit`/`preview_video` machinery.
3. **Include upload progress feedback** (the "Confirm upload hangs silently for minutes" gap).

**Consequence:** after this plan the ONLY confined child spawned at runtime is **ffmpeg** (author transcode). Both worker exes (`media-worker`, `media-transcode-worker`) are no longer invoked. Existing videos uploaded in the old format will not play and must be **re-uploaded** (accepted).

## Already committed this session (do NOT redo; verify they survive)

- `da21fe5` — `open_content` returns video metadata via a header-only open (was: downloaded the whole clip then `codec_unavailable`) so `media-viewer` mounts the player.
- serial `cancelPending` now KEEPS priority jobs (viewer open no longer cancelled by feed teardown — the "cancelled"/"Could not open" race).
- **stream URL is `http://stream.localhost/media/<id>`** — Tauri v2 serves custom URI schemes at `http://<scheme>.localhost/...` on Windows; `stream://…` fails. `video-src.ts::streamSrc` emits this form. KEEP it.
- Bounded busy-retry on `reauth` in `stream_media_inner` (`076f31a`) — a STOPGAP; Task 3 replaces it with the persistent connection and this retry loop should be removed.
- **TEMP diagnostics to REMOVE in Task 7:** `commands/video.rs` `stream_log` + `stream_debug_log` command (+ its `main.rs` handler entry) writing `<appdir>/logs/stream.log`; `video-player.ts` `dlog` helper + the `securitypolicyviolation` listener + the extra `video.addEventListener` trace lines.

---

## Environment (put in EVERY subagent prompt)

- `cargo` is NOT on the tool PATH. Prefix: PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo ...` / bash `export PATH="$HOME/.cargo/bin:$PATH"; cargo ...`
- **NEVER** run `cargo fmt --all` (pre-existing repo-wide rustfmt drift). Match in-file style.
- Rust crate under test: `-p maxsecu-client-app` (also `-p maxsecu-media-launcher` for Task 1a). Lib tests: `cargo test -p maxsecu-client-app --lib <path>`.
- UI from `crates/client-app/ui`: `npm run typecheck | build | test | test:a11y`. Single UI test: `node --experimental-strip-types --test src/<path>.test.ts`.
- The Tauri exe EMBEDS `ui/dist` at compile time. After UI changes: `npm run build`, then `cargo build --release -p maxsecu-client-app`.
- **Staging (controller does this for GUI smokes):** `Stop-Process -Name maxsecu-client-app -Force`; copy `target/release/maxsecu-client-app.exe` to BOTH `dist/MaxSecuClient-root` and `dist/MaxSecuClient-bob`; relaunch via `Start-Process`. `media-transcode-worker.exe`/`media-worker.exe` currently sit beside it (Task 7 drops the need). The controller CAN close/relaunch the client itself (user granted this).
- Platform: Windows (win32), PowerShell primary; Bash tool also available.
- TDD per task: failing test → run/fail → implement → pass → commit. One commit per task (messages provided). End commit messages with the standard Co-Authored-By/Claude-Session trailer.

---

## Task 1a: ffmpeg emits a fragmented-MP4

**Files:** `crates/media-launcher/src/ffmpeg_args.rs` (`build_ffmpeg_args` + tests).

The pinned argv currently muxes `out.mp4` as a normal MP4 (`-c:v libsvtav1 … -c:a aac …`). Add the fragmented-MP4 muxer flags so `out.mp4` is a single continuous fMP4 (init `moov` + `moof`/`mdat` fragments) — the exact form Task 0 proved WebView2 plays.

- [ ] **Step 1:** Add a failing test to `ffmpeg_args.rs` asserting the built args contain `-movflags` with the value `+frag_keyframe+empty_moov+default_base_moof` (adapt to the crate's arg-inspection helpers, e.g. `value_after(&args, "-movflags")`).
- [ ] **Step 2:** In `build_ffmpeg_args`, before the output path, emit `-movflags` `+frag_keyframe+empty_moov+default_base_moof`. Keep everything else (SAR-aware scale, even dims, `-c:v libsvtav1`, GOP `-g`, `-c:a aac -b:a 128k -ac 2`, `-protocol_whitelist file`). Ensure a closed-GOP keyframe interval (the existing `-g`) so fragments start on keyframes.
- [ ] **Step 3:** `cargo test -p maxsecu-media-launcher` → PASS. Commit: `feat(video): ffmpeg emits a fragmented-MP4 (movflags frag_keyframe+empty_moov+default_base_moof)`.

## Task 1b: store ffmpeg's fMP4 as the content (drop the re-mux worker); chunk-grouped fragment index

**Files:** `crates/client-app/src/upload.rs` (`prepare_video_streams` + a new index builder + tests).

`prepare_video_streams` currently: runs ffmpeg → reads `out.mp4` → **re-muxes via `TranscodeLauncher`** into per-GOP self-contained MP4s (`result.cmaf`) → builds a fragment index from `result.fragments` → requires `cmaf.len() % 4096 == 0`. Change it so **`out.mp4` (the fMP4) IS the content**, with NO re-mux and NO inter-fragment padding.

- [ ] **Step 1 (failing test):** The **ffmpeg-driven** single-fragmented-MP4 structural assertion over a real `prepare_video_streams` run (one `ftyp`, one `moov`, ≥1 `moof`) is **delegated to Task 8's e2e guard** (`tests/video_e2e.rs`, where the crate's vendored-ffmpeg discovery already lives) — do NOT duplicate that fragile ffmpeg infra inside the `--lib` unit tests. Task 1b's REQUIRED tests are **pure**: a unit test for the new chunk-grouped index builder asserting it is **contiguous-from-0, covers exactly `ceil(content_len/4096)` chunks, and the last fragment is short** when the chunk count isn't a multiple of `FRAG_CHUNKS`; plus a round-trip that feeds the built fragments through `build_metadata_with_fragments` → `parse_fragment_index` and confirms it validates. (The real fMP4 byte-structure is guaranteed by Task 1a's `-movflags` + Task 8's e2e + the Task 2 smoke.)
- [ ] **Step 2 (implement):**
  - Remove the `TranscodeLauncher::transcode` re-mux step (Step 6) and the `transcode_worker_path` parameter (update callers — `commands/upload.rs` `stage_upload`). `content = out_mp4_bytes` (the fMP4).
  - Drop the `cmaf.len() % 4096 == 0` requirement (a continuous fMP4 is arbitrary length; `build_upload` chunks it and the last chunk is short).
  - Build the fragment index directly from the chunk count: `n = ceil(content.len()/VIDEO_CHUNK_SIZE)`; group chunks into fragments of a fixed `FRAG_CHUNKS` (choose so a fragment is ~256 KiB–1 MiB, e.g. 64), each `{seq, pts_ms: 0, chunk_start, chunk_len}`, contiguous, covering all `n` chunks (last fragment short). This keeps `parse_fragment_index` happy and lets the EXISTING `serve_range`/`assemble_range`/`feed_fragment` fetch per-fragment. (pts is unused by native playback.) Put this in a small pure helper with unit tests (contiguity + coverage + last-fragment-short).
  - `StagedVideoPreview.cmaf` (the author-preview bytes) = the same fMP4 content bytes; keep `StagedVideoPreview.index` only if Task 4's preview path needs it (native preview ranges over raw bytes, so it likely does NOT — drop it if unused).
  - Keep thumbnail/preview derivation from `thumb.png` via `RustImageCodec`.
  - The re-mux worker keeps the `MAX_FRAME_BYTES` output ceiling today; keep an equivalent bound on `out.mp4` size (fail-closed `video_failed` over the cap) so a huge source can't OOM (large-file streaming stays a documented residual).
- [ ] **Step 3:** `cargo test -p maxsecu-client-app --lib upload::` → PASS. Commit: `feat(video): store ffmpeg fMP4 as content directly + chunk-grouped fragment index (no re-mux worker)`.

## Task 2: GUI smoke checkpoint — native VIEW plays (controller + user)

After Tasks 1a/1b + 3 + 5 the view path should work. Sequence Task 2 AFTER Task 5 (it needs the connection + CSP fixes). Controller builds+stages; user **re-uploads** a clip and confirms the POST player: plays with sound, no 1-second stop, Pause works, timer + correct duration, scrubber seeks forward/back, and the Media Chrome controls are properly styled (not giant). Controller reads `<appdir>/logs/stream.log` (until Task 7 removes it). **STOP and fix before proceeding if it fails.**

## Task 3: Persistent per-session authed connection (kill per-range reauth 500s)

**Files:** `crates/client-app/src/jobs.rs` (`VideoJob`), `crates/client-app/src/commands/video.rs` (`open_video_inner`, `serve_range`, `probe_total_len`, `stream_media_inner`), `crates/client-app/tests/video_e2e.rs` (adapt the range test).

**TCB/protocol task — two-stage review.** WebView2 issues overlapping range reads; per-range `reauth` contends on `ConnectLock`. Establish ONE authed channel at `open_video` and reuse it for all ranges of that session.

- [ ] **Step 1:** Add to `VideoJob` a `channel: std::sync::Arc<tokio::sync::Mutex<AuthedChannel>>` where `AuthedChannel { sender: SendRequest<Full<Bytes>>, host: String, token: String }`. Populate it in `open_video_inner` from the ONE `reauth` the command already does (reauth stays serialized via the UI's `serial()` at open — fine).
- [ ] **Step 2:** Rework `serve_range` to take `jobs` + `file_id_hex` only (drop the `sender/host/token` params): Phase A under the global `VideoJobs` lock → plan + `fetch_indices` + clone the `channel` Arc + read `chunk_size/total_len/index/version`, release the global lock. Phase B → lock the CHANNEL mutex, fetch missing ciphertext over `channel.sender`; on a send/connection error, **rebuild the channel once** (`reauth`) and retry the fetch, else fail closed. Phase C under the global lock → `assemble_range`. This holds neither lock across unrelated work and serializes a session's fetches over its one HTTP/1.1 connection (correct: HTTP/1.1 can't multiplex).
- [ ] **Step 3:** `probe_total_len` uses the session channel too (not a fresh reauth). `stream_media_inner` no longer calls `reauth`/`server_of` per request and DROPS the bounded busy-retry loop (`076f31a`) — it just resolves the session + calls the new `serve_range`.
- [ ] **Step 4:** Adapt `video_e2e.rs`'s `range_streaming_reassembles_plaintext_over_real_tls`: build the `VideoJob` with an `AuthedChannel` wrapping the harness's authed `c.sender`/host/token, and call the new `serve_range(&jobs, &fid_hex, first, last)`. Keep all four assertions (byte-exact reassembly, `total_len`, cache re-read, ciphertext-only on disk). `cargo test -p maxsecu-client-app --test video_e2e range_streaming_reassembles_plaintext_over_real_tls` → PASS.
- [ ] **Step 5:** Commit: `feat(video): one persistent authed connection per open video (drop per-range reauth; reconnect-on-failure)`.

## Task 4: Namespace routing + native author PREVIEW over `stream://preview`

**Files:** `crates/client-app/src/commands/video.rs` (`stream_media_inner`, new `serve_preview_range`), `crates/client-app/src/jobs.rs` (UploadJobs access), `crates/client-app/ui/src/components/video-player.ts` (preview branch → native), `crates/client-app/ui/src/components/video-src.ts` (a `previewSrc` helper + test).

**TCB/protocol task — two-stage review.** Serve the author's STAGED fMP4 (plaintext, in `UploadJobs`' `StagedVideoPreview.cmaf`) to a native `<video>` by byte range — NO decrypt, NO auth, NO network.

- [ ] **Step 1:** On Windows the stream URL is `http://stream.localhost/<path>` (host = `stream.localhost`), so the FIRST path segment is a reliable namespace. In `stream_media_inner`, parse `/<ns>/<id>`: `ns == "media"` → the existing verified/decrypted view path (id = `hex16` file id); `ns == "preview"` → `serve_preview_range(job_id)`. Reject anything else → 404. (Keep the id-validation fail-closed.)
- [ ] **Step 2:** Add `serve_preview_range(jobs: &UploadJobs, job_id, first, last) -> Result<RangeResponse, UiError>`: look up the job's `StagedVideoPreview.cmaf`, `resolve_range(first, last, cmaf.len(), MAX_RANGE_BODY)`, slice, return. Unknown job → the 404 mapping. No decryptor, no fetch. Unit-test `resolve_range` slicing over an in-memory buffer.
- [ ] **Step 3:** `video-src.ts`: add `previewSrc(jobId) => `http://stream.localhost/preview/${jobId}`` + a `node:test`. In `video-player.ts`, the `previewJob` branch becomes NATIVE: build the same Media Chrome `<video>` and set `src = previewSrc(this.previewJob)`; do NOT call `preview_video`/`preview_seek`/`open_video`/`cancel_video` (the staged job is owned by the upload flow). Remove the old confined-preview code from the component (its confined branch dies with Task 7; here just stop using it).
- [ ] **Step 4:** `npm run typecheck && npm test && npm run test:a11y`; `cargo test -p maxsecu-client-app --lib`. Commit: `feat(video): native author preview over stream://preview (staged fMP4, no decrypt) + namespace routing`.

## Task 5: CSP — let Media Chrome render

**Files:** `crates/client-app/tauri.conf.json`.

Media Chrome injects runtime inline styles; Tauri v2 nonces `style-src`, nullifying `'unsafe-inline'`, so they're blocked (huge unstyled controls). Fix by telling Tauri NOT to CSP-modify `style-src` so `'unsafe-inline'` is effective.

- [ ] **Step 1:** In `tauri.conf.json` `app.security`, add `"dangerousDisableAssetCspModification": ["style-src"]` (keep the `csp` string with `style-src 'self' 'unsafe-inline'` and `media-src 'self' http://stream.localhost https://stream.localhost`). Document in the commit body that this disables Tauri's style-nonce injection for a local, CSP-locked app so a bundled component library can style its shadow DOM — the accepted tradeoff (scripts stay nonced; no remote origins allowed).
- [ ] **Step 2:** Verified by the Task 2 smoke (controls render correctly). Commit: `fix(ui): allow Media Chrome shadow-DOM styles (disable Tauri style-src nonce injection)`.

## Task 6: Upload progress feedback (no silent hang on Confirm)

**Files:** `crates/client-app/src/commands/upload.rs` (`confirm_upload` / `run_pipeline` emits), `crates/client-app/ui/src/components/upload-tray.ts` (+ `upload-screen.ts` if needed).

`confirm_upload` currently appears to hang for minutes before any tray feedback. Make progress visible from the first instant.

- [ ] **Step 1:** Emit an immediate `UploadPhase` (e.g. `Staging`/`Encrypting`) synchronously at the very start of `confirm_upload`, BEFORE any network, so the tray shows at once. Ensure `run_pipeline` emits `Uploading{done,total}` per chunk (it should already) and `Finalizing`. Investigate + close the specific gap that delayed the first feedback (likely the stage POST of a large body or the initial reauth).
- [ ] **Step 2:** `<upload-tray>` shows a percentage/ETA throughout (it has a progress-meter — ensure it appears on the first phase, not only once `Uploading` starts). Keep it WCAG-AA (aria-live, non-color-only).
- [ ] **Step 3:** `cargo test -p maxsecu-client-app --lib`; `npm run typecheck && npm test && npm run test:a11y`. Commit: `feat(upload): immediate + continuous progress feedback during confirm (no silent hang)`.

## Task 7: Remove the old confined-decode engine + temp diagnostics (cleanup)

**Files (delete/modify):** `crates/client-app/ui/src/core/player.ts`(+`.test.ts`), `crates/client-app/ui/src/core/webgl-yuv.ts`(+`.test.ts`); `crates/client-app/ui/src/components/video-player.ts` (drop the confined branch + all old imports/events); `crates/client-app/src/commands/video.rs` (remove `video_seek`, `video_set_volume`, `preview_video`, `preview_seek`, `play_window_command`, `decrypt_window`, `decode_and_emit`, `window_offset_ms`, `push_bounded`, frame/PCM DTOs, `ScriptGuard`, `make_decoder`/`SessionDecoder`/`worker_path`, the TEMP `stream_log`/`stream_debug_log`); `crates/client-app/src/state.rs` (`EVT_VIDEO_FRAME/AUDIO/PLAYER/INFO`, `PlayerPhase`, `VideoInfo` + tests); `crates/client-app/src/main.rs` (drop deleted handler entries incl. `stream_debug_log`); `crates/client-app/src/jobs.rs` (`VideoJob.gain`, `StagedVideoPreview.index` if unused); `crates/client-app/ui/src/components/video-player.ts` remove `dlog`/CSP-listener/trace lines; `crates/client-app/ui/package.json` (drop deleted tests from the `test` script); packaging/staging (stop shipping `media-worker.exe`; `media-transcode-worker.exe` no longer invoked).

**Cleanup task — two-stage review (confirm nothing live references a removed symbol).**

- [ ] **Step 1:** Grep-confirm each removed symbol has ZERO remaining references (view=native, preview=native, so all decode/old-engine code is dead). Remove them. Resolve dead-code by DELETION, not `#[allow]`.
- [ ] **Step 2:** Decide crate disposition: `media-worker` (decode) and `media-transcode-worker` (re-mux) are no longer invoked. Leave the crates in the workspace but unwired, OR remove — record the choice. Update `packaging/*` + the staging note so only the client (with embedded ffmpeg) needs shipping.
- [ ] **Step 3:** `cargo test -p maxsecu-client-app` (+ `cargo build --release -p maxsecu-client-app`); `npm run typecheck && npm test && npm run test:a11y`. Commit: `refactor(video): remove the hand-rolled decode engine + confined workers from the view/preview path (native is the one path) + drop temp diagnostics`.

## Task 8: Automated fMP4-structure guard e2e

**Files:** `crates/client-app/tests/video_e2e.rs`.

Guard against the "concatenated MP4s" regression that this whole plan fixes.

- [ ] **Step 1:** Extend/add an e2e that produces content the way the author path does (or drives `prepare_video_streams` if reachable over the vendored ffmpeg; `#[ignore]` if ffmpeg-gated) and asserts the uploaded content stream is a SINGLE fragmented-MP4 — exactly one `ftyp`, exactly one `moov`, ≥1 `moof` — via a tiny box scanner. Keep the range-reassembly + ciphertext-only assertions from Task 3.
- [ ] **Step 2:** `cargo test -p maxsecu-client-app --test video_e2e` → PASS (ignored ffmpeg tests run with `--ignored --test-threads=1`). Commit: `test(video): assert stored content is a single fragmented-MP4 (regression guard)`.

## Task 9: Full GUI smoke (controller + user)

Controller builds+stages the release exe to both dist dirs and relaunches. User confirms end-to-end on BOTH real clips (`D:\Images\00168.mp4`, `D:\Images\Car crash call #skit #funny #comedy.mp4`):
- **Upload** shows continuous progress (no silent hang).
- **Author preview** (before confirm) plays smoothly with sound + working native controls + seek.
- **Post player** plays fully with sound, correct duration, seek forward/back, styled Media Chrome, no 1-second stop, 59 s clip streams without hanging.
- No console/CSP errors.

Fix before proceeding on any failure (invoke **superpowers:systematic-debugging**). On PASS, proceed to Task 10.

## Task 10: Security sign-off (update the reversal doc)

**Files:** `docs/security-review-native-video-mediaapp.md`.

- [ ] Record honestly: native WebView2 codecs (fMP4 demux + AV1 + AAC) now decode in the key-holding WebView for BOTH view and author preview; the confined decode worker + custom re-mux worker are retired from the runtime path; content is an **ffmpeg-produced** fMP4 (trusting ffmpeg's container muxer output, produced inside the AppContainer sandbox) that stays AEAD-authenticated + manifest-bound + D5-author-verified (view path). Residual surface = a malicious/compromised VERIFIED author crafting an adversarial-but-valid bitstream (unchanged from the reversal's accepted posture). Note the CSP `dangerousDisableAssetCspModification: [style-src]` tradeoff (scripts stay nonced; no remote origins). Content **key never leaves the Rust process**; only per-range plaintext crosses (bounded; the transport connection is per-session). Author preview serves the author's OWN staged plaintext (no keys). Verified by: Task 2/9 smokes, Task 3 range e2e (bytes == plaintext, ciphertext-only on disk), Task 8 fMP4-structure guard. State the >64 MiB large-source residual.
- [ ] No "PASS theater" — this is a reduction of the Phase-7 confine-decode posture for the view+preview paths; say so plainly. Commit: `docs(security): native-video fMP4 + preview reversal sign-off (residual-risk narrowing)`.

---

## Controller self-review (coverage)

- fMP4 format (ffmpeg-direct) → Tasks 1a/1b. ✓  Regression guard → Task 8. ✓
- Persistent connection (no per-range reauth 500s) → Task 3. ✓
- Namespace routing + native preview → Task 4. ✓
- CSP / Media Chrome → Task 5. ✓
- Upload progress → Task 6. ✓
- Remove old engine + diagnostics → Task 7. ✓
- Smokes → Tasks 2, 9. ✓  Security doc → Task 10. ✓
- Re-upload requirement + large-file residual: documented. ✓
