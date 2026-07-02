# Plan — Loose-ends cleanup + Dropbox + big-feature specs (parallel, one-go)

**Created:** 2026-07-02
**Branch:** work on local `main` (no push). Parallel tasks run in **isolated git worktrees** (Agent `isolation: "worktree"`), each committing on its own branch; the controller reviews then merges each back to `main`.
**Execution model:** subagent-driven, **PARALLEL**. Controller = **Opus 4.8, high effort**. Implementers = **fresh `general-purpose` subagents, model `sonnet`**, one per task, dispatched **simultaneously** (each in its own worktree, `run_in_background: true`). After each finishes, the controller reviews the committed diff: **spec-compliance THEN quality**; tasks marked **[two-stage]** get spec-compliance THEN a dedicated **security** pass. Compose each subagent's task text FROM THE LIVE CODE — do NOT make subagents read this plan.

## Scope (from the user's 4 answers, 2026-07-02)
- **BUILD (code):** the dead-code cleanups + the **real Dropbox tier adapter**.
- **SPEC ONLY (design docs, no code):** the three big features — multi-recipient sharing UI, Tor transport, Shamir K-of-N recovery UI.
- **SKIP:** all ops/environment-blocked chores (signing, PG bundling, CI, transparency-log vendor) and the self-contained features NOT chosen (search-index cache, de-admin tombstone honoring, KT-gated browse, a11y polish, Authenticode-update verify) — left deferred, untouched.

## Environment gotchas (put in every subagent prompt as relevant)
- `cargo` NOT on tool PATH — prefix `export PATH="$HOME/.cargo/bin:$PATH";` (bash) / `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";` (PS).
- **NEVER `cargo fmt --all`** — `client-core`/`server`/`media-launcher` carry pre-existing rustfmt drift; new/edited lines match in-file style only.
- Confined/worker tests run `-- --test-threads=1`.
- Commit per task with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` + `Claude-Session: …` trailers. Do NOT push.
- Each worktree agent commits on its own branch; the controller merges (resolving only trivial `Cargo.lock` overlaps).

## No GUI smoke needed
None of these tasks change the WebView UI runtime (cleanups are backend/TCB/docs; Dropbox is server-side; the big features are docs). The only user-side step is the **optional Dropbox live-verify** (needs the user's test creds at runtime — never committed). No `/clear`-blocking smoke gates.

---

## Parallel batch — dispatch ALL of these at once (each its own worktree)

### T1 — Remove the orphaned `client-core::media` transcode proto  [two-stage: TCB]
**Why:** the confined transcode worker was deleted; its client-core wire proto is now dead scaffolding (twin of the Task-12 sandbox removal).
**Grounding (verified live/dead split):**
- **REMOVE** from `crates/client-core/src/media.rs` (+ the `pub use media::{…}` list in `crates/client-core/src/lib.rs`): `FfmpegVideo` (struct + impl + the `ffmpeg_video_is_deferred` test), `TranscodeRequest`, `TranscodeResult`, `TranscodeProtoError`, `CanonicalStreams` (+ its `into_plaintext_streams` if it has no live consumer — VERIFY), and the proto fns `encode_transcode_request`/`decode_transcode_request`/`encode_transcode_result`/`decode_transcode_result` (+ their tests). All confirmed zero external consumers (the one `TranscodeRequest` hit is a doc comment in `media-launcher/src/transcode_opts.rs` — reword it).
- **KEEP byte-intact:** `RustImageCodec`, `Transcoder` trait, `MediaBounds`, `FragmentEntry`, `PlaintextStreams`, and the caps consts (`MEDIA_MAX_*`, `THUMBNAIL_MAX_DIM`, `PREVIEW_MAX_DIM`, `MAX_TRANSCODE_BYTES`, `MAX_TRANSCODE_FRAGMENTS`) — all live (used by client-app upload).
- Update stale doc comments that reference the removed items (e.g. `client-core/src/error.rs:75` "deferred C carve-out behind the `Transcoder` trait" / the `FfmpegVideo` mention).
**Method:** compiler-guided — remove the confirmed-dead items + fix the lib.rs export list, then `cargo build -p maxsecu-client-core` and remove anything newly flagged unused; NEVER remove a KEEP symbol.
**Acceptance:** `cargo build --workspace --tests` clean (0 warnings); `cargo test -p maxsecu-client-core --lib` green; `grep` shows no live ref to any removed symbol. **Security pass:** diff touches only `media.rs`/`lib.rs` (+ the one doc-comment file); no crypto/verification path changed; KEEP symbols byte-intact; behavior of the live upload/transcode path unchanged (spot: `upload_e2e`/`video_upload_e2e`).

### T2 — Misc cleanup: stale comment + delete moot upstream-issue drafts  [light review]
**Grounding:**
- Fix the stale doc comment at `crates/client-app/src/video.rs:163` referencing the deleted `ClientMsg::Fragment` (reword to reflect the native `<video>` path).
- Delete `docs/upstream-issues/rav1d-F1-decode-panic.md` and `docs/upstream-issues/symphonia-F2-isomp4-overalloc.md` (moot — MaxSecu no longer ships rav1d/symphonia). If `docs/upstream-issues/README.md` only indexes those two, delete the dir; else update the README.
**Acceptance:** `cargo build -p maxsecu-client-app` clean; the drafts are gone; no dangling references.

### T3 — Build the real Dropbox tier adapter  [two-stage: security — external egress]
**Why:** `crates/server/src/tier.rs` has the `Tier` trait + fakes only; the user wants the real Dropbox adapter built.
**Grounding:** `crates/server/src/tier.rs` (the `Tier` trait, its fakes, and the `//!` doc noting Dropbox is "a deferred plug-in behind this [trait]"; direct-link brokering api §9.4 lands here). Read the trait shape + how blobs flow (blobs are **client-encrypted ciphertext** — the server/tier never sees plaintext or keys).
**Build:** a real `DropboxTier` impl behind the `Tier` trait — upload/download/exists/delete of **ciphertext blobs** + direct-link brokering (api §9.4). Use an async HTTPS client consistent with the workspace TLS stack (aws-lc-rs; **no `ring`/`openssl`** — check `deny.toml`). OAuth/token from **config/env at runtime only**; **NEVER commit any credential** (the user's test creds are test-only — see memory `dropbox-test-creds`). Unit-test against a **mock HTTP layer** (no network in CI); add a `#[ignore]` live round-trip test gated on an env var (`DROPBOX_TEST_TOKEN`) the user runs manually.
**Acceptance:** `cargo build -p maxsecu-server --tests` clean; unit tests (mock) green; `cargo deny`/`cargo audit` reviewed for any new dep (prefer an already-pinned HTTP client; if a new dep is needed, justify + check no `ring`/`openssl`). **Security pass:** ONLY ciphertext blobs egress to Dropbox (no keys, no plaintext, no manifest secrets); credentials never logged/committed and are zeroized where feasible; direct-link brokering can't leak a decryptable artifact; failures are fail-closed; the zero-knowledge model is preserved (Dropbox is an untrusted blob store). Document the live-verify step (user-supplied token) in the module doc + a short runbook note.

### T4 — Spec: multi-recipient sharing UI  [spec-review]
**Deliverable:** `docs/superpowers/specs/2026-07-02-multi-recipient-sharing-design.md` — a ready-to-build design for post-upload sharing to additional recipients. Ground it in the EXISTING core: `client-core::build_reshare` + `POST /v1/files/{id}/wraps` (already reviewed), the D5 directory verification of recipients, and the media-app UI patterns (serial queue, reauth-per-call, WCAG-AA). Cover: recipient picker + D5-verify-before-wrap, the reshare command/DTO seam (owner-only; identity under session lock), tray/feedback UX, revocation interplay (tombstones), and edge cases. NO code.

### T5 — Spec: Tor transport  [spec-review]
**Deliverable:** `docs/superpowers/specs/2026-07-02-tor-transport-design.md` — a ready-to-build design to make the Phase-5 "use Tor" toggle real. Ground it in the existing pinned TLS-1.3 transport (`transport.rs`, aws-lc-rs, RFC5705 channel binding) and `SettingsConfig.connection.use_tor`. Cover: how connections route through Tor (bundled tor vs system SOCKS), how channel-binding/pinning survives a SOCKS proxy, failure/fallback UX, the security trade-offs (metadata protection vs added trust surface), and what stays deferred (bundling a real tor binary is an ops step). NO code.

### T6 — Spec: Shamir K-of-N recovery UI  [spec-review]
**Deliverable:** `docs/superpowers/specs/2026-07-02-shamir-recovery-ui-design.md` — a ready-to-build design for a recovery-key UI on top of the ALREADY-IMPLEMENTED core (`crypto::shamir` + `admin-core::recovery` split/reconstruct, Phase 7). Cover: the split ceremony UX (choose K-of-N, distribute shares safely), the reconstruct/recover flow, how it relates to the existing `export_keystore` backup path, share custody guidance, and accessibility. NO code.

---

## After all parallel tasks are reviewed + merged
1. Merge each worktree branch into `main` (docs branches trivially; T1 client-core + T3 server touch different crates — resolve only `Cargo.lock`).
2. Controller final verification on `main`: `cargo build --workspace --tests` (0 warnings), `MAXSECU_PG_OPTIONAL=1 cargo test --workspace --lib`, targeted e2e (`upload_e2e`, `video_upload_e2e`, `file_e2e`, `browse_view_e2e`), UI `npm run typecheck|test|test:a11y|build` (should be untouched but confirm), `cargo deny`/`cargo audit`.
3. Dispatch one final holistic reviewer over the merged commit range.
4. Update memory (`close-streaming-native-video`, MEMORY.md): record the cleanups done, the Dropbox adapter built (+ live-verify pending user creds), and the 3 specs written (awaiting user review before any build).
5. Report; the specs (T4–T6) and the Dropbox live-verify are the only user-facing follow-ups.

## Notes
- Parallel safety: the 6 tasks touch mostly disjoint paths (client-core / client-app+docs / server / three separate spec docs); worktree isolation prevents working-tree collisions. Merge sequentially.
- If any task reports BLOCKED (e.g. Dropbox needs a design choice, or a "dead" symbol turns out live), the controller resolves it (fix the plan, re-dispatch) before merging that branch — the others proceed independently.
