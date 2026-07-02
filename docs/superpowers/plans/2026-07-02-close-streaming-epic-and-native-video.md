# Plan — Close the streaming epic, retire the confined-decode viewer, + follow-ups

**Created:** 2026-07-02
**Branch:** work DIRECTLY on local `main` (user choice — no feature branch, no push). `main` HEAD is the streaming-epic merge `1cb3eea`, ~253 commits ahead of `origin/main` (unpushed).
**Execution model:** subagent-driven-development. Controller = **Opus 4.8, high effort**. Dispatch a FRESH `general-purpose` subagent per task (**model: sonnet**) with task text the controller composes FROM THE LIVE CODE (do NOT make subagents read this plan). After each task commits, the controller reviews the committed diff for spec-compliance THEN quality before the next task. Tasks marked **[two-stage]** get a spec-compliance review THEN a dedicated security pass.
**GUI smokes are USER-DRIVEN** — the controller cannot drive WebView2. Stop and ask the user at each smoke gate.

## Settled decisions (from the user this session)
1. **Native `<video>` (WebView2 decoder) is the accepted video-playback path** — the confined pure-Rust rav1d decode sandbox is retired for viewing (accepted RCE-surface trade-off). See memory `video-native-decode-decision`.
2. **Full removal** of the confined-decode VIEWER path + TEMP diagnostics.
3. Also include: **verify_* DRY refactor**, **drop vestigial `Store::user_roles`**, **zstd encoder (P3.10)**, **Media Chrome Stage 2 chrome**.
4. Author-side ffmpeg→AV1/AAC **fMP4 transcode stays** (content is AV1; WebView2/Chromium decodes it natively). `media-transcode-worker` is KEPT (dev audio fixtures).

## Environment gotchas (put these in every subagent prompt as relevant)
- `cargo` is NOT on the tool PATH — prefix `export PATH="$HOME/.cargo/bin:$PATH";` (bash) / `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";` (PS).
- **NEVER** `cargo fmt --all` — `client-core`/`server`/`media-worker`/`media-launcher` carry pre-existing rustfmt drift; keep new lines in-file style only.
- UI lives in `crates/client-app/ui`; build/test there: `npm run typecheck | build | test | test:a11y`. The Tauri exe **embeds `ui/dist` at compile time** — after any UI change: `npm run build` THEN rebuild the client, THEN restage to `dist\MaxSecuClient-{root,bob}`.
- Confined/worker tests run single-threaded: `-- --test-threads=1` (shared AppContainer-profile parallel flake).
- If server code changes, **rebuild the `dist\MaxSecuServer` binary** and restart it — a stale dist server was the cause of the `upload_chunk_failed` smoke failure this session.
- Running client/server LOCK their dist exe — stop the process before restaging.

---

## Task 1 — Map the confined-decode surface (investigation, NO code change)
**Goal:** produce an authoritative KEEP/REMOVE manifest so the removal tasks don't break the live native path.
**Grounding:** the native path is `renderNative()` in `crates/client-app/ui/src/components/video-player.ts` (`<media-controller>` + `<video slot="media">` + `streamSrc`/`previewSrc` from `video-src.ts`); backend range path is `crates/client-app/src/stream.rs` + `commands/video.rs::stream_media`/`serve_range`; `open_video` is retained ONLY to register the decrypt-while-stream session (verify this). The DEAD path is `renderCanvas()` (WebGL) + `core/player.ts` frame sync + `core/webgl-yuv.ts` + `EVT_VIDEO_FRAME` + backend `decode_and_emit` + `VideoSessionDecoder`/`AppContainerVideoSession` (media-launcher) + the `media-worker` decode binary + `stream_log`/`stream_debug_log`/`dlog`.
**Steps:** trace every symbol; confirm (a) exactly what `open_video`/`preview_video` must still do for the native path (registration/probe only), (b) whether `media-worker` and the `media-launcher` decode-session/resilient-session code become fully unused, (c) which UI modules/tests (`player.test.ts`, `webgl-yuv.test.ts`, `video-player.test.ts`) go, (d) whether removing `media-worker` orphans its `media-transcode-worker` dev-dep usage. Write the manifest into this plan file (append a "Task 1 output" section) and commit it.
**Acceptance:** a concrete file/symbol-level KEEP vs REMOVE list; no code changed. **[plan-doc commit]**

## Task 2 — Backend: strip the confined-decode path [two-stage]
**Goal:** remove `decode_and_emit`, the `VideoSessionDecoder`/`AppContainerVideoSession` usage, the resilient-session driver wiring, and the `media-worker` decode binary — per the Task-1 manifest — while KEEPING `open_video` as a register-only command and the `stream://`/`stream.rs` range path intact.
**Grounding:** `commands/video.rs` (`open_video`, `open_video_inner`, `decode_and_emit`, `preview_video`/`preview_video_inner` legacy branch, `PlayerPhase` emission), `jobs.rs::VideoJob`, `media-launcher` (`VideoSessionDecoder`, `AppContainerVideoSession`, `run_session_resilient`, `resilient_session`), the `media-worker` crate + workspace `Cargo.toml` members.
**Steps (TDD):** adjust/retire the tests that pin the decode path; make `open_video` register-only; delete dead code + crate members; ensure the native range path e2e still passes. Keep `media-transcode-worker` (dev fixtures) — if orphaned by `media-worker` removal, document it.
**Acceptance:** `cargo build --workspace --tests` clean; native video e2e green; `cargo tree` shows `rav1d` no longer pulled by `client-app`; no `decode_and_emit`/`AppContainerVideoSession` left. **Security pass:** confirm no decrypt/identity regression in the retained `open_video`/range path (DEK stays in-core; no new oracle).

## Task 3 — Backend: remove TEMP diagnostics
**Goal:** delete `stream_log`/`stream_debug_log` (and the `main.rs` registration) + any `dlog` backend hooks. (May be merged into Task 2's commit if cleaner.)
**Acceptance:** no `stream_log`/`stream_debug_log` symbols; build clean; range path unaffected.

## Task 4 — UI: native-only `<video-player>` [two-stage]
**Goal:** make `video-player.ts` native-only — drop `renderCanvas()`, `createYuvRenderer`, `createPlayer`, `EVT_VIDEO_FRAME`, the I420 frame plumbing, the HW-decode waiver, and `core/webgl-yuv.ts` + the frame-sync half of `core/player.ts` + `dlog`. Keep `renderNative()` (`<media-controller>`/`<video>`/`streamSrc`/`previewSrc`/`openNative`).
**Grounding:** `crates/client-app/ui/src/components/video-player.ts`, `core/player.ts`, `core/webgl-yuv.ts`, `core/types.ts` (I420FrameDto/VideoInfo), tests `player.test.ts`/`webgl-yuv.test.ts`/`video-player.test.ts`, `a11y.test.ts`.
**Steps (TDD):** update/remove the WebGL+player unit tests; keep a11y (focusable region, labelled controls, non-color-only status) for the native player. `npm run typecheck|test|test:a11y|build` green.
**Acceptance:** typecheck + all UI + a11y suites green; bundle builds; no WebGL/frame code remains; video still plays via native `<video>`. **Security pass:** confirm no keys/plaintext cross the seam via the removed events; CSP `media-src http://stream.localhost` intact.
**USER SMOKE (gate):** ask the user to view a video (playback + seek) and preview an upload after Task 2+4 are staged.

## Task 5 — client-core: verify_* DRY refactor [two-stage]
**Goal:** factor the shared `verify_header` + small-stream loop duplicated across `verify_and_open` / `verify_and_stream_content` / `verify_and_open_headers` in `crates/client-core/src/download.rs` into one reviewed helper. Pure refactor, no behavior change.
**Acceptance:** client-core lib tests + the browse/view + streaming e2e green; behavior byte-identical. **Security pass:** the header-verification TCB invariants unchanged (requested-id binding, signature checks, no oracle).

## Task 6 — Drop vestigial `Store::user_roles`
**Goal:** remove `user_roles` from the `Store` trait + `pg`/`store`/memory/faulty impls + any callers/tests (confirm truly unused first).
**Acceptance:** `cargo build --workspace --tests` + server tests green.

## Task 7 — zstd encoder (P3.10) [two-stage]  ⚠ DECISION REQUIRED
**Goal:** implement the `Compression::Zstd` path (encode on upload, decode on download) so `download.rs`'s `compression != None` branches are exercised.
**⚠ Blocking sub-decision the controller MUST surface to the user before coding:** the project is deliberately **no-C** in the crypto/TCB. The mainstream `zstd` crate is a C binding; a pure-Rust encoder option is limited. Options: (a) accept a C `zstd` dep as an app-layer (non-TCB) codec; (b) use a pure-Rust zstd (decode `ruzstd` + a pure-Rust encoder if acceptable); (c) DEFER zstd and drop this task. Do not pick silently.
**Acceptance (if built):** round-trip test (compress→upload→download→decompress == original); `cargo deny`/`audit` reviewed for the new dep. **Security pass:** decompression is bounds-capped (no zip-bomb), runs outside the DEK path.

## Task 8 — Media Chrome Stage 2 chrome
**Goal:** overlaid controls / fullscreen / keyboard shortcuts / auto-hide (+ buffered bar) on the native `<video>` via Media Chrome, replacing the bespoke transport controls where Media Chrome covers them. UI-only, outside the TCB.
**Grounding:** `video-player.ts` `renderNative()`, `media-chrome` (already a dep), `styles.css`.
**Acceptance:** typecheck + UI + a11y green (keyboard-operable, labelled, non-color-only, reduced-motion respected); build OK.
**USER SMOKE (gate):** controls/fullscreen/keyboard work.

## Task 9 — Task 14: streaming security sign-off [two-stage]
**Goal:** write `docs/security-review-streaming-upload.md` honestly documenting: streaming seal+PUT from disk (O(one 6 MiB chunk) client+server), DEK never crosses the Tauri seam (recovered in-core from the self-wrap on resume), no DEK/ciphertext at rest (only signed manifest/genesis/wraps + small-stream ciphertext + the author's own plaintext `out.mp4` in a Low-IL staging dir, wiped on success/cancel/24h sweep), append-only-safe server discard, the removed hard transcode cap (stall watchdog + 1h backstop residual), AND the **native-`<video>` / WebView2 decode surface as an accepted, documented trade-off** (not a gap) with the confined decoder retired.
**Acceptance:** doc committed; PASS with no Critical/High/Medium, or any finding logged honestly. **Security pass:** the doc's claims match the code as it now stands post-removal.

## Task 10 — Final verification + holistic review
**Steps:** `cargo test --workspace` (unit) + targeted e2e (streaming upload + native video) + UI unit/a11y + `cargo build --tests`; rebuild the release client + restage `dist\MaxSecuClient-{root,bob}`; dispatch a final holistic reviewer over the whole set of commits.
**USER SMOKE (final gate):** full run — upload (streaming, MB/s, resume), native playback + seek + Media Chrome, RAM gauge read-out.
**Acceptance:** all green; user confirms the final smoke.

## Notes
- Update memory (`streaming-upload-epic`, `video-native-decode-decision`, `media-app-plan`, MEMORY.md) as tasks land.
- Keep commits scoped per task; conventional-commit messages with the Co-Authored-By + Claude-Session trailers.

---

## Task 1 output — Confined-decode KEEP/REMOVE manifest

**Method:** traced every symbol from the grounding pointers outward (UI `video-player.ts`
→ Tauri commands `commands/video.rs` → `crate::video.rs` feeder → `stream.rs` range core →
`jobs.rs` registries → `media-launcher`/`media-worker` crates → workspace `Cargo.toml` →
`main.rs` registration → e2e tests → packaging scripts). No code changed.

### `open_video` / `preview_video` disposition (Investigation 1)

**`open_video` (`crates/client-app/src/commands/video.rs::open_video_inner`, lines
776-899) is ALREADY register-only + probe-only — it never calls the decode path today.**
It does, in order: (1) fetch + D5-verify the file view/author/self, (2) build the header,
(3) under the session lock, synchronously build the in-TCB `ContentDecryptor` + parse the
authenticated fragment index (`open_video_job_core`), (4) open the `FragmentCache`, (5)
move the authed connection into a persistent `AuthedChannel` and insert the `VideoJob` into
`VideoJobs`, (6) call `probe_total_len` (decrypts ONLY the last content chunk to learn
`total_len`, caching its ciphertext as a side effect) and store it. **It never calls
`decrypt_window`/`decode_and_emit`/`play_window_command`.** The exact code comment to
preserve verbatim (already in the docstring, `commands/video.rs:728-730`):

> `` `open_video` — open + verify a video, register its decrypt-while-play session, and
> play the initial bounded window. `` ← **this docstring is STALE** ("play the initial
> bounded window" is not what the function does); Task 2 should correct it to say
> register + probe only.

The UI confirms this is the intended contract: `video-player.ts::openNative()` (line
330-350) awaits `open_video`, then does `video.src = streamSrc(this.reqId)` — it never
expects frame/audio events back. The comment at line 334-335 states the invariant to
preserve: *"open_video registers the decrypt-while-stream session (register-only + total-
length probe). Only decrypted plaintext crosses the stream:// seam."*

`preview_video`/`preview_seek` (commands) are **decode-path-only and fully removable**:
the native preview path (`video-player.ts::connectNative()`, previewJob branch, line
319-324) points `video.src` straight at `previewSrc(jobId)` (served by
`serve_preview_range`/`preview_slice_file`, byte-range from disk) and never calls
`preview_video`/`preview_seek` at all. Those two commands, and their `_inner`s
(`preview_video_inner`, `preview_window_inner`, `build_preview_window_script`), are only
reachable from the DEAD legacy branch of `video-player.ts` (see UI section below).

`video_seek` / `video_set_volume` are **also decode-path-only and fully removable**: they
are called only from `video-player.ts`'s dead legacy code (`requestWindow` callback line
216-222, and `applyVolume` line 475-482). The native path never calls them — it lets the
browser own seek (native `<video>` scrubbing over `stream://` ranges) and volume
(`<video>.volume`/Media Chrome). `VideoJob.gain` (`jobs.rs:105`) is written only by
`video_set_volume` and read nowhere — dead data once that command is removed.

`cancel_video` **MUST be kept** — it is called from `video-player.ts::disconnectedCallback`
(line 270-272) for BOTH the native and legacy paths (guarded by `this.opened && this.reqId
&& !this.previewJob`, which is true for the native view session too). It is the only
teardown that drops `VideoJob` from `VideoJobs` (zeroizing the `ContentDecryptor`). No
decode-path code inside it — pure registry removal + a benign `PlayerPhase::Error{code:
"cancelled"}` emit (the native UI does not listen for `EVT_PLAYER` at all, so this emit is
currently a no-op fire-and-forget from the native UI's perspective — harmless to leave,
optional future simplification, NOT required for this removal).

### KEEP — native path + shared code that must survive

**UI:**
- `crates/client-app/ui/src/components/video-player.ts` — `connectNative()`, `openNative()`,
  `connectedCallback()`'s two-line native dispatch (`this.connectNative(); return;`),
  `phaseCode()`, `fmt()` (used by the dead code too but harmless/tiny — no action needed),
  the class fields `native`, `_fileId`/`reqId`, `_previewJob`, `opened`, `disposed`, the
  `disconnectedCallback` skeleton (audio/opened teardown), `customElements.define`.
- `crates/client-app/ui/src/components/video-src.ts` — `streamSrc`, `previewSrc` (both
  pure, side-effect-free, unit-tested by `video-player.test.ts`, unrelated to decode).
- `crates/client-app/ui/src/components/video-player.test.ts` — **already native-only**; it
  only imports/tests `video-src.ts` helpers, contains ZERO references to the legacy
  decode-chrome class internals. No change needed for Task 4 (a pleasant surprise —
  verify this doesn't regress).

**Backend (`crates/client-app/src`):**
- `commands/video.rs::open_video` + `open_video_inner` + `open_video_job_core` +
  `probe_total_len` — register-only + probe-only TCB path (see disposition above). Trim
  `open_video_inner`'s unused `_emit`/`_on_frame`/`_on_audio`/`_on_info` params only if
  convenient; `open_video`'s outer `emit` closure stays (used for the `PlayerPhase::Error`
  on failure + job cleanup).
- `commands/video.rs::cancel_video` — session teardown (see disposition above).
- `commands/video.rs::serve_range`, `stream_media`, `stream_media_inner`,
  `preview_slice_file`, `serve_preview_range`, `parse_byte_range`, `RangeResponse` —
  the entire `stream://` range-protocol core (native `<video>` + author preview).
- `commands/video.rs::cached_fragment_valid`, `deframe_count`, `read_u32_le` — SHARED
  helpers; `serve_range`'s Phase A window-plan loop calls `cached_fragment_valid` directly
  (`commands/video.rs:~1240`), independent of the decode path's `play_window_command`.
- `commands/video.rs::transcode_worker_path` — author-side transcode (unrelated to decode
  viewer removal; used by `upload.rs`).
- `commands/video.rs::MAX_RANGE_BODY`, `RangeResponse` — range-path constants/types.
- `stream.rs` — **entire file unchanged**. `resolve_range`, `plan_range`, `assemble_range`,
  `slice_range`, `total_len`, plus its whole `#[cfg(test)]` module. Confirmed by direct
  read: it imports only `ContentDecryptor`/`FragmentCache`/`FragmentEntry`/`UiError` — no
  `ClientMsg`/`WorkerMsg`/media-launcher/media-worker symbol anywhere in the file
  (Investigation 6 — confirmed safe).
- `crate::video.rs` (root, NOT `commands/video.rs`) — **entire production code KEEP**:
  `FragmentEntry`, `parse_fragment_index`, `fragment_for_time`, `chunks_for_fragment`,
  `feed_fragment`, `frame_chunks`/`deframe_chunks`. This is the shared ciphertext-feeder
  used by BOTH `serve_range` (native, KEEP) and the old decode path (REMOVE); it is
  decoder-agnostic by design (see its module doc: "Task 4.3 wires the sink to the
  sandboxed `media-worker`; this layer is decoder-agnostic"). Only its
  `#[cfg(test)] launcher_types_are_importable_decoder_free` test goes (see REMOVE/Task 2).
- `jobs.rs::VideoJob` (struct, minus `gain` field) — `decryptor`, `index`, `cache`,
  `file_id_hex`, `version`, `chunk_size`, `total_len`, `channel` are all read by
  `serve_range`/`stream_media_inner`. `jobs.rs::VideoJobs`, `AuthedChannel` — KEEP.
  `jobs.rs::UploadJobs`, `StagedContent`, `StagedVideoPreview`, `StagedUpload`,
  `VideoPrepareCancel` — KEEP (upload/preview-staging, unrelated to decode-viewer removal).
- `fragment_cache.rs` (`crate::fragment_cache::FragmentCache`) — the ciphertext cache,
  shared by native range serving and (formerly) decode; untouched either way.
- `state.rs::EVT_PLAYER`, `PlayerPhase::Error` variant — still emitted by `open_video`
  (failure) and `cancel_video` (cancelled). Other `PlayerPhase` variants (`Buffering`,
  `Playing`, `Gap`, `Stalled`, `CodecUnavailable`) become **unreachable** once the decode
  path is removed (verified: `CodecUnavailable` is ALREADY never emitted anywhere in the
  backend today; `Buffering`/`Playing`/`Gap` are emitted only inside
  `decrypt_window`/`decode_and_emit`/`preview_window_inner`, all REMOVE). Task 2's
  controller should decide whether to trim the enum to just `Error` (nothing currently
  listens for the others — confirmed the native UI never subscribes to `EVT_PLAYER` at
  all) — optional, not required for correctness.
- `main.rs` — the `stream` URI-scheme protocol registration
  (`register_asynchronous_uri_scheme_protocol("stream", …)`), `.manage(VideoJobs::new())`,
  `.manage(VideoPrepareCancel::default())`, the `commands::video::open_video` and
  `commands::video::cancel_video` lines in `generate_handler!`.
- `crates/client-app/tests/video_e2e.rs::range_streaming_reassembles_plaintext_over_real_tls`
  (line 940) — builds a `VideoJob` and drives `serve_range` directly over real TLS; this
  is the correct native-path e2e and should become (or be promoted to) the file's sole
  test after Task 2.
- `crates/client-app/tests/video_upload_e2e.rs` — **zero references** to any decode symbol
  (`VideoSessionDecoder`/`decode_and_emit`/`video_seek`/`preview_video`/`serve_range`
  all absent, confirmed by grep). Fully unaffected by this removal.
- `media-launcher` crate — KEEP as a crate (client-app's Cargo.toml dependency stays,
  comment at `client-app/Cargo.toml:25-31` about being codec-free is still accurate).
  Transcode-shared symbols (see the dedicated caution section below) survive.

### REMOVE — grouped by later task

**Task 2 (backend, `commands/video.rs` + `jobs.rs` + `video.rs` root + `main.rs` + e2e):**
- `commands/video.rs::decode_and_emit` (the async fn, lines 403-519) — the off-runtime
  confined-decode-and-re-validate core.
- `commands/video.rs::decrypt_window`, `ScriptGuard` (+ its `Drop` zeroize impl) — the
  in-TCB window-decrypt-into-script step (used only by the decode path;
  `serve_range`/`assemble_range` use `feed_fragment` directly, not `ScriptGuard`).
- `commands/video.rs::play_window_command`, `WindowPlan` — the decode-path window driver
  (distinct from `stream.rs::RangePlan`/`plan_range`, which stay).
- `commands/video.rs::video_seek` (command) + `video_seek_inner`.
- `commands/video.rs::video_set_volume` (command), `MAX_GAIN` const.
- `commands/video.rs::preview_video` (command) + `preview_video_inner`.
- `commands/video.rs::preview_seek` (command) + `preview_window_inner`.
- `commands/video.rs::build_preview_window_script`, `duration_ms_from_index`.
- `commands/video.rs::worker_path`, `make_decoder`, `SessionDecoder` type alias (both
  `#[cfg(windows)]` and `#[cfg(not(windows))]` arms) — the confined-decoder resolver.
- `commands/video.rs::I420FrameDto`, `PcmDto`, `frame_dto`, `pcm_dto` — the frame/PCM DTOs
  (only produced by `decode_and_emit`).
- `commands/video.rs::window_offset_ms`, `frame_bytes`, `push_bounded`,
  `MAX_FRAME_BUF_BYTES`, `PLAY_WINDOW` const — decode-and-emit internals (`PLAY_WINDOW`
  has no other caller once `video_seek_inner`/`preview_window_inner` are gone).
- `commands/video.rs` test module: `FrameDecoder`, `MalformedDecoder`, `ErrorDecoder`,
  `AudioDecoder`, `RealPtsDecoder`, `BurstDecoder`, `ok_frame`/`bad_frame`/`big_frame`
  test fixtures, and every test that calls `decrypt_window`/`decode_and_emit`/
  `build_preview_window_script` directly: `play_window_emits_buffering_then_playing_…`,
  `play_window_rejects_malformed_worker_frame`, `play_window_fails_closed_on_worker_error`,
  `play_window_emits_revalidated_audio`,
  `emitted_pts_are_window_relative_and_monotonic_across_fragments`,
  `push_bounded_caps_the_buffer_and_drops_oldest`,
  `push_bounded_keeps_at_least_one_frame`,
  `decode_and_emit_bounds_inflight_frames_and_surfaces_gap`,
  `seek_refeeds_from_mapped_fragment_and_back_seek_hits_cache` (uses `decrypt_window`;
  its cache-hit assertion is still valuable but needs REWRITING against `feed_fragment`/
  cache primitives directly if kept), `set_volume_clamps_and_requires_a_session`,
  `preview_script_slices_each_fragment_range_out_of_staged_cmaf`,
  `preview_script_fails_closed_on_out_of_range_index`,
  `preview_decodes_staged_cmaf_into_revalidated_frames`, `dto_helpers_base64_planes_…`.
  **KEEP** from that same test module: `core_opens_with_the_d5_verified_author`,
  `core_fails_closed_for_a_forged_author` (test `open_video_job_core`, KEEP-worthy),
  `cached_fragment_valid_mirrors_the_feeder_hit_condition` (tests a KEEP helper but
  currently populates the cache via `decrypt_window` — needs a small rewrite to populate
  via `feed_fragment`/`cache.put` instead), `cancel_drops_the_job_and_its_decryptor`,
  `parse_byte_range_forms`, `preview_slice_file_reads_bounded_range`,
  `preview_window_slice_covers_only_the_requested_fragments` — wait, this last one calls
  `build_preview_window_script` (REMOVE target) — **re-verify at Task-2 time**: if
  `preview_slice_file`/`serve_preview_range` (KEEP, disk-range) fully replace what this
  test covers, it can go with `build_preview_window_script`; flagged as ambiguous below.
- `jobs.rs::VideoJob.gain` field (dead once `video_set_volume` is gone).
- `crate::video.rs` (root) test: `launcher_types_are_importable_decoder_free` (asserts
  `VideoSubprocessSession`/`VideoSessionDecoder` are importable decoder-free — both types
  are themselves being removed).
- `main.rs`: the `commands::video::preview_video`, `commands::video::preview_seek`,
  `commands::video::video_seek`, `commands::video::video_set_volume` lines in
  `generate_handler!`.
- `crates/client-app/tests/video_e2e.rs::phase7_video_author_to_view_over_real_tls`
  (GATE 3/4/5 directly call `VideoSessionDecoder::run_session` via the test's own
  `play_window` helper, line ~430-498) — this whole test validates the confined-decode
  view path end-to-end; remove or rewrite to drop GATE 3-5's decode assertions, keeping
  GATE 1/2/6 (upload + browse + forged-author-fails-closed) if those are judged worth
  preserving standalone, OR remove the whole test and rely on
  `range_streaming_reassembles_plaintext_over_real_tls` (KEEP) as the view-path e2e.
- `crates/client-app/tests/universal_video_e2e.rs` — **entire file**. Its own doc header
  states its purpose is to exercise `decode_and_emit`'s production emission path
  (`window_offset_ms`, `push_bounded`, `run_session_resilient`) via a verbatim
  `decode_and_emit_mirror`; every gate (A/B/C) asserts on `I420FrameDto`/`PcmDto`/
  `PlayerPhase` from the confined decoder. Fully superseded by native `<video>` decode.

**Task 2 or Task 2-adjacent (media-launcher — decode-session-only symbols; SHARED symbols
must NOT be touched, see caution notes below):**
- `crates/media-launcher/src/lib.rs::VideoSessionDecoder` (trait), `VideoSubprocessSession`
  (cross-platform), `AppContainerVideoSession` (`#[cfg(windows)]`).
- `resilient_session`, `resilient_session_inner`, `run_resilient_over`, `ResumeMaterial`,
  `wipe_fragment_plaintext`, `DriveEnd`, `TerminalReason`, `ResilientOutcome`,
  `MAX_RESPAWNS_PER_WINDOW`, `MAX_SESSION_MSGS`, `MAX_SESSION_BYTES`.
- `drive_framed_session`, `drive_framed_session_partial` — used ONLY by
  `VideoSubprocessSession`/`AppContainerVideoSession` (verified: `TranscodeLauncher` does
  NOT use these; it does one-shot stdin-write/stdout-capture via `spawn_confined_cancellable`,
  not the framed duplex driver).
- `framing` module — **CAUTION, do NOT remove wholesale**: `framing::write_frame`/
  `read_frame`/`MAX_FRAME_BYTES` ARE used by `TranscodeLauncher::transcode`/
  `parse_framed_result` (KEEP) in addition to the decode session (REMOVE). Keep the
  module; only its decode-only *callers* go.
- `win32.rs::spawn_confined_session` — used ONLY by `AppContainerVideoSession` (verified
  by symbol search: no other caller). Safe to remove alongside it.
- `win32.rs::spawn_confined` — **CAUTION, KEEP**: also called by
  `TranscodeLauncher::selftest` (`lib.rs:1346`), not decode-exclusive despite also being
  used by `AppContainerVideoSession::selftest_with_fragment` and (the separately-flagged,
  see below) `AppContainerDecoder::decode_image`.
- `AppContainerVideoSession::selftest_with_fragment`, `selftest_duplex` — decode-session
  selftest helpers, REMOVE with the type.
- `crates/media-launcher/tests/*` and `crates/media-worker/tests/{video_session,
  video_subprocess,containment_video_windows,oom_kill_windows,resilient_oom_windows,
  bombs_video,audio_session}.rs` — all decode-session/confinement tests; go with the
  decoder they test (media-worker's — see below).

**Task 3 (TEMP diagnostics, backend + the UI call sites that invoke them):**
- `commands/video.rs::stream_debug_log` (command), `stream_log` (fn) — remove the fn and
  every `stream_log(...)` call site inside `stream_media`/`stream_media_inner`.
- `main.rs`: the `commands::video::stream_debug_log` line in `generate_handler!`.
- UI: `video-player.ts::dlog()` (the private fn at line 518-520) and **every call site**
  (lines 302, 304, 309, 317, 323, 333, 340, 343 — all inside `connectNative`/`openNative`,
  i.e. the LIVE native code, not the dead legacy block). This is a live-code edit, not
  dead-code deletion — the CSP-violation listener and video `error`/`loadstart`/etc.
  listeners can either lose just their `dlog(...)` bodies or be removed entirely if no
  longer needed for debugging (controller's call; the `video.addEventListener("error", …)`
  handler's user-facing status-text branch must stay regardless of whether `dlog` is kept).

**Task 4 (UI, `video-player.ts` + `core/*`):**
- `video-player.ts`: the entire DEAD block from `connectedCallback`'s
  `// ---- existing confined-preview setup continues UNCHANGED below ----` comment
  (line 111) through the end of `open()` (line 367) — i.e. `this.reqId = this.fileId`
  (dup), the legacy `innerHTML` chrome template (canvas/scrub/mute/volume/rate/HW-waiver),
  the WebGL renderer setup (`createYuvRenderer`/`WebglUnavailable`/`WebglProgramError`
  handling), the `AudioContext` setup, `drawSink`, `this.player = createPlayer(...)`, the
  `EVT_VIDEO_FRAME`/`maxsecu://video-info` subscriptions, `this.wireControls()`, the
  `ticker`, and `private async open()`. Also: `setPhase`, `STATE_LABEL`, `hideBadge`,
  `disableControls`, `wireControls`, `applyVolume`, `setPlayGlyph`, `refreshScrubber`,
  `updateTime` — all reachable ONLY from that dead block (verified: `connectedCallback`
  unconditionally `return`s after `connectNative()`, so none of this is live). Class
  fields to drop alongside: `player`, `renderer`, `audio`, `unframe`, `ticker`,
  `playedMs`, `loadedMs`, `fragments`, `dragging`, `hwWaiver`, `lastVol`, `uninfo`,
  `durationMs`. `disconnectedCallback` needs a trim (drop the `player`/`renderer`/`audio`
  teardown lines) but MUST KEEP the `cancel_video` call + `this.audio` guard IF audio is
  removed, or just drop the now-always-null `audio` cleanup entirely.
- `video-player.ts` imports to drop: `createYuvRenderer`, `WebglUnavailable`,
  `WebglProgramError`, `YuvRenderer` (from `core/webgl-yuv.ts`); `createPlayer`,
  `EVT_VIDEO_FRAME`, `Player`, `PlayerPhase`, `YuvFrame`, `I420FrameDto`,
  `AudioContextLike` (from `core/player.ts`); `VideoInfo` (from `core/types.ts`, unless
  still used elsewhere in types.ts — it is video-decode-specific, safe to drop).
- `core/webgl-yuv.ts` — **entire file** (`WebglUnavailable`, `WebglProgramError`,
  `planeSizes`, `YuvFrame`, `YuvRenderer`, `buildProgramSources`, `createYuvRenderer`).
  Sole consumer is `video-player.ts`'s dead block.
- `core/webgl-yuv.test.ts` — **entire file** (exists, confirmed; tests only the above).
- `core/player.ts` — **entire file** (frame-sync engine: `EVT_PLAYER_STATE`,
  `EVT_VIDEO_FRAME`, `EVT_VIDEO_AUDIO`, `I420FrameDto`, `PcmDto`, `PlayerPhase`,
  `YuvFrame`, `GainLike`, `AudioBufferLike`, `AudioBufferSourceLike`, `AudioContextLike`,
  `FrameSink`, `Subscribe`, `PlayerOptions`, `Player`, `createPlayer`). Sole consumer is
  `video-player.ts`'s dead block; verified no other file imports from `core/player.ts`.
- `core/player.test.ts` — **entire file** (750+ lines, exhaustively tests `createPlayer`).
- `core/types.ts::VideoInfo` interface (line 113) — only consumer was the dead
  `maxsecu://video-info` listener; confirm no other reference before deleting.
- `a11y.test.ts` — **two assertions need removal/rewrite**, one is safe as-is:
  - REMOVE/REWRITE: the `${vpPath}: non-color-only state text + decode-worker-pending
    badge` test (line 105-111) — asserts `/Decode worker pending/i` appears in
    `video-player.ts`'s SOURCE TEXT; that string lives only in the dead legacy `innerHTML`
    template and disappears once it's deleted.
  - REMOVE/REWRITE: the `${vpPath}: HW-decode waiver default-off + prominent warning`
    test (line 114-118) — asserts `/hardware|hw-decode|hwDecode/i` and `/not recommended/i`
    appear in source text; both strings live only in the dead legacy `#vp-hw` block/
    `hwWaiver` code, which is being deleted.
  - **KEEP AS-IS** (verified still true post-removal — the native chrome also has these):
    the focusable-region/`.focus()`/`aria-live` test (line 84-86, `connectNative`'s HTML
    has `tabindex="-1"` + `.focus()` + `aria-live="polite"` too) and the
    no-unescaped-innerHTML-interpolation XSS guard (line 126, both blocks use static
    template literals with no `${}` interpolation of untrusted data).
- `video-player.ts::video-player.test.ts` — **no change needed** (see KEEP section;
  already native-only).

**Task 2 (media-worker crate + workspace + packaging):**
- `crates/media-worker` — **the entire crate becomes fully unused by `client-app` once
  the confined-decode viewer is removed**, confirmed two ways: (a) `client-app`'s
  `Cargo.toml` has NO dependency (direct or dev) on `maxsecu-media-worker` today — it is
  spawned as an external binary resolved by path (`worker_path()`/`AppDir`), and the e2e
  tests locate it via a workspace-target-dir scan helper (`find_worker`, `video_e2e.rs`
  line ~115), not a Cargo edge; (b) grepping all client-app source for `media-worker`/
  `media_worker` after the Task-2 REMOVE list above shows zero remaining call sites (the
  only spawn sites were `make_decoder`/`worker_path`, both REMOVE targets). **BUT it is
  NOT orphan-free for the workspace as a whole** — see the dedicated coupling note below.
- Cargo.toml workspace `members`: remove `"crates/media-worker"` (line 16). Keep
  `"crates/media-launcher"` and `"crates/media-transcode-worker"`.
- `packaging/package.ps1` (lines 18-22, 40) and `packaging/package.sh` (lines 13-15, 31)
  — stop building/staging `media-worker.exe`; keep `media-transcode-worker.exe`.

### Shared-crate caution notes

**media-launcher — decode-only vs transcode-shared, at symbol granularity:**

| Symbol | Disposition | Why |
|---|---|---|
| `VideoSessionDecoder`, `VideoSubprocessSession`, `AppContainerVideoSession` | REMOVE | decode-session only |
| `resilient_session*`, `DriveEnd`, `TerminalReason`, `ResilientOutcome`, `MAX_RESPAWNS_PER_WINDOW`, `MAX_SESSION_*` | REMOVE | decode-session only |
| `drive_framed_session`, `drive_framed_session_partial` | REMOVE | decode-session only (verified: `TranscodeLauncher` uses `spawn_confined_cancellable`, not this) |
| `win32::spawn_confined_session` | REMOVE | sole caller is `AppContainerVideoSession` |
| `framing` module (`write_frame`/`read_frame`/`MAX_FRAME_BYTES`) | **KEEP** | also used by `TranscodeLauncher::transcode`/`parse_framed_result` |
| `win32::spawn_confined` | **KEEP** | also used by `TranscodeLauncher::selftest` |
| `win32::spawn_confined_cancellable` | **KEEP** | used by `TranscodeLauncher::run_worker` (Windows) |
| `win32::spawn_confined_exe`, `setup_confined_exe_child`, `FfmpegProgress`, `FfmpegOutcome` | **KEEP** | `FfmpegLauncher` (author-side ffmpeg confinement) only |
| `TranscodeLauncher`, `FfmpegLauncher`, `parse_framed_result` | **KEEP** | author-side transcode, explicitly kept per plan decision #4 |
| `GrantAccess`, `PathGrant`, `grant_path_to_appcontainer`, `appcontainer_sid_string`, `SpawnError`, `ConfinedOutput`, `ConfinedExeOutput` | **KEEP** | shared confinement primitives used by transcode |
| `ffmpeg_args::build_ffmpeg_args`, `transcode_opts::{Bitrate,Resolution,TranscodeOptions}` | **KEEP** | author-side transcode option types |
| `proto` module (`DecodeRequest`, `encode_request`/`decode_request`, `encode_response`/`decode_response`), `run_decode`, `SubprocessDecoder`, `AppContainerDecoder`, `SandboxedDecoder` (from client-core, re-used here) | **OUT OF SCOPE / already dead** — see open risk below | this is the single-shot IMAGE decode sandbox (not video); grepped and found **zero callers anywhere in `client-app`** already, independent of this task |

**Is `media-worker` fully removable? YES for client-app, but with a coupling to
document:** `media-transcode-worker`'s own dev-dependencies and TWO integration tests
(`crates/media-transcode-worker/tests/ingest_remux.rs`,
`crates/media-transcode-worker/tests/containment_transcode_windows.rs`) **dev-depend on
`maxsecu-media-worker` to round-trip-verify their re-mux output**: both tests import
`maxsecu_media_worker::VideoSession` and feed every produced canonical fragment through
the REAL, unmodified `VideoSession` (Open→Fragment*→Close) to prove the transcode output
decodes into valid I420 frames — i.e. they use the confined AV1/AAC decoder as a
**verification oracle**, not as production wiring. `media-transcode-worker/Cargo.toml`
lines 44-49 document this explicitly ("the REAL viewer decode session... does NOT depend
on this worker (no cycle)"). **Deleting the `media-worker` crate breaks these two tests'
compile** (`use maxsecu_media_worker::VideoSession` becomes unresolvable). Task 2 must
choose one of:
  (a) Keep the `media-worker` crate/lib (rav1d+symphonia decode) as a **dev-only**
      verification dependency for `media-transcode-worker`'s tests, but drop it from
      `packaging/*` (no shipped `media-worker.exe`) and from client-app's spawn path —
      i.e. it stops being a *product* binary but survives as a *test* library. This keeps
      the workspace member but changes its role.
  (b) Rewrite `ingest_remux.rs`/`containment_transcode_windows.rs` to verify re-mux
      correctness WITHOUT a real AV1 decode — e.g. structural CMAF/ISO-BMFF validation via
      `symphonia`'s demux-only path (already a dep) plus fragment-index/byte-count checks
      — and then delete `media-worker` from the workspace entirely.
  (c) Accept the loss of decode-verified re-mux testing and just delete both the crate and
      the two test files' decode-verification sections (weakens transcode test coverage).
  The plan's own Task 2 text anticipates this ("if orphaned by `media-worker` removal,
  document it") — **this is that documentation; the choice is NOT made here.**

### Open risks / ambiguities for the removal tasks to watch

1. **The image-decode sandbox (`proto`/`SubprocessDecoder`/`AppContainerDecoder`/
   `run_decode` in media-launcher, and `media-worker`'s default no-arg stdin/stdout mode
   in `main.rs`) is unrelated to VIDEO and already has zero callers in `client-app`.**
   It will be deleted as a side effect if `media-worker` is fully removed (option (b)/(c)
   above), which is fine, but it is technically a separate (image) concern outside this
   task's stated scope. Flag to the controller: confirm this is intentional collateral
   removal, not scope creep needing its own review.
2. **`video_e2e.rs::phase7_video_author_to_view_over_real_tls`** mixes a KEEP-worthy
   upload+browse+forged-author gate (1/2/6) with REMOVE-worthy decode gates (3/4/5) in
   ONE test function — it cannot be deleted-vs-kept as a whole file; needs surgical
   splitting or full removal in favor of the already-separate
   `range_streaming_reassembles_plaintext_over_real_tls` (which independently covers
   view+seek+back-seek-cache over the real native range path). Recommend: remove the
   whole `phase7_...` test, since `range_streaming_...` plus `video_upload_e2e.rs`
   plus `universal_video_e2e.rs`'s replacement (if any) already cover upload+browse+range;
   verify GATE 6 (forged-author-fails-closed over the FULL open flow) isn't uniquely
   covered elsewhere before deleting it, though `commands/video.rs`'s
   `core_fails_closed_for_a_forged_author` unit test covers the same TCB invariant at
   the `open_video_job_core` level.
3. **`PlayerPhase` enum trim** (`Buffering`/`Playing`/`Gap`/`Stalled`/`CodecUnavailable`
   becoming unreachable) is optional cleanup, not required — leaving them costs nothing
   (serde derive on an enum with unused variants compiles fine) but Task 2's controller
   should decide once, not leave it ambiguous per-reviewer.
4. **`preview_window_slice_covers_only_the_requested_fragments`** test (`commands/video.rs`,
   near line 2440) calls `build_preview_window_script` (a REMOVE target) but tests window
   SLICING logic that has no equivalent in the KEPT `preview_slice_file`/
   `serve_preview_range` (which serve raw byte ranges, not fragment-windowed slices) —
   confirm there is no remaining behavior this test protects before deleting it outright;
   if `build_preview_window_script` truly has no successor, the test goes with it.
5. **`cached_fragment_valid_mirrors_the_feeder_hit_condition`** and
   **`seek_refeeds_from_mapped_fragment_and_back_seek_hits_cache`** tests exercise KEEP
   logic (`cached_fragment_valid`, cache-hit/miss semantics that `serve_range` also relies
   on) but are currently wired through `decrypt_window` (REMOVE) to populate the cache —
   these need REWRITING to populate via `crate::video::feed_fragment` or
   `cache.put(...)` directly, not blanket deletion (deleting them would silently drop
   coverage of a still-live cache-hit invariant `serve_range` depends on).
6. **`stream.rs`'s own test module already has an equivalent cache-hit assertion**
   (`assemble_returns_exact_plaintext_range_across_fragments`, asserting a warm second
   `assemble_range` call performs zero fetches) — Task 2 should check whether this makes
   risk #5's rewritten tests redundant before investing effort in the rewrite.
7. **`dlog`/`stream_debug_log` removal (Task 3) touches LIVE native-path code**, not dead
   code — unlike the rest of the UI removal, this is an edit to `connectNative`/
   `openNative` themselves. Do it carefully and re-verify the native smoke still passes
   after stripping the diagnostic calls (the CSP-violation and `video` element event
   listeners exist BECAUSE this path was flaky to debug without them — removing the
   logging doesn't remove the underlying fragility, just the visibility into it).
8. **`cargo tree -i rav1d` was not run** (deferred per the task's own suggestion — "you
   may run cargo tree if quick; otherwise infer and note it as verify at removal time").
   Inferred from Cargo.toml instead: `rav1d`/`symphonia` are dependencies of
   `maxsecu-media-worker` ONLY (its `Cargo.toml` lines 39-48); `media-launcher` and
   `client-app` do not depend on them directly or transitively (media-launcher's own
   Cargo.toml has no rav1d/symphonia line, confirmed by reading it in full). **Task 2
   should run `cargo tree -i rav1d` and `cargo tree -i symphonia` after removal** to
   confirm neither reaches `client-app` (expect: not found, or found only under
   `media-transcode-worker`'s dev-deps if option (a)/(b) above keeps `media-worker` as a
   dev-only verification lib).
