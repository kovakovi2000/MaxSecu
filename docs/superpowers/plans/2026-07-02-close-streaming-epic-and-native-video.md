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
