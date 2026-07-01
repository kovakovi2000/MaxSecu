# Streaming Large-File Video Upload — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use **superpowers:subagent-driven-development** — a FRESH
> general-purpose subagent per task (model: sonnet), and the CONTROLLER (Opus 4.8, high effort) reviews each
> committed diff for spec-compliance + quality BEFORE dispatching the next. For TCB/protocol/format/cleanup
> tasks (marked **[two-stage review]**) do a TWO-STAGE review: spec-compliance first, then a security pass.
> The controller reads the live code and writes each subagent's exact prompt (files, behaviors, tests, env
> gotchas, commit message) — do NOT make subagents read this plan file.

**Goal:** Upload arbitrarily large videos by streaming the transcoded content chunk-by-chunk from disk
(never whole-file in RAM on client or server), resumable across an app restart, with MB/s progress and 24h
auto-cleanup of abandoned staging — removing the 64 MiB `over_cap` blocker and fitting the server in 4 GB RAM.

**Architecture:** Approach A — re-seal on demand. A new client-core `ContentStreamSealer` seals content
deterministically by chunk index and reproduces `seal_stream`'s digest incrementally, so we compute the
signed-manifest digest in one pass then stream/PUT chunks in a second pass, both O(one chunk). Only a small
staging record (manifest + genesis + wraps + `out.mp4` path + progress) is persisted — no DEK, no ciphertext
at rest; resume recovers the DEK by unwrapping the self-wrap. Only **video** content uses the disk-backed
6 MiB-chunk path; images/blogs are unchanged.

**Tech Stack:** Rust (client-core TCB crypto; `maxsecu-client-app` Tauri v2; `maxsecu-media-launcher`
confinement; `maxsecu-server` axum), vanilla TypeScript UI, Postgres (metadata) + FsBlobStore (disk).

**Spec:** `docs/superpowers/specs/2026-07-01-streaming-large-file-upload-design.md` (read it first).

---

## THIS PLAN PAUSES the native-video fMP4 plan at Tasks 6–10

`docs/superpowers/plans/2026-07-01-native-video-fmp4-fix.md` has Tasks 1a–5 committed
(fMP4 content, persistent connection, native preview, CSP) and a passing Task-2 view smoke (the Car crash
clip plays). Tasks 6 (upload progress), 7 (cleanup), 8 (fMP4 guard), 9 (full smoke), 10 (security sign-off)
are **DEFERRED**. After THIS streaming plan completes, RESUME that plan at Task 6 — but note **Task 6
(upload progress) is subsumed here** (MB/s + continuous progress land in Task 12 below), and Task 9's smoke
should include a large-file run. Reconcile at that time.

## Approved decisions (brainstorm 2026-07-01) — do NOT relitigate

- **Mechanism:** Approach A (re-seal on demand); persist only a staging record (no DEK, no ciphertext at rest).
- **Chunk size:** video content = **6 MiB** (within `[4 KiB, 8 MiB]`); images/blogs/metadata unchanged.
- **No client file-size cap.** Server quota is **configurable, default OFF (unlimited)**; "too large" only if set+exceeded.
- **Transcode timeout:** drop the hard 10-min kill; keep the 90s stall watchdog + user-cancel.
- **Resume:** **prompt** "Resume upload of `<title>`?" on launch.
- **Abandoned cleanup:** 24h since last progress; **swept on app launch**.
- **Server orphans:** client **discards the unfinalized staged file** (new endpoint) on give-up / during the sweep, respecting append-only immutability.
- **Preview-before-upload:** kept, served by byte-range from the on-disk `out.mp4`.
- **Server 4 GB:** no RAM increase; the only server change is raising the request **body limit** to ≥ 8 MiB.

## Environment (put in EVERY subagent prompt)

- `cargo` is NOT on the tool PATH. Prefix: PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo ...`
  / bash `export PATH="$HOME/.cargo/bin:$PATH"; cargo ...`
- **NEVER** run `cargo fmt --all` (pre-existing repo-wide rustfmt drift). Match in-file style.
- Crates: `-p maxsecu-client-core`, `-p maxsecu-client-app`, `-p maxsecu-media-launcher`, `-p maxsecu-server`.
  Lib tests e.g. `cargo test -p maxsecu-client-core --lib upload::`. UI from `crates/client-app/ui`:
  `npm run typecheck | build | test | test:a11y`.
- The Tauri exe EMBEDS `ui/dist` at compile time. After UI changes: `npm run build`, then
  `cargo build --release -p maxsecu-client-app`, then stage the exe to `dist/MaxSecuClient-{root,bob}`
  (CLOSE the running client first: `Stop-Process -Name maxsecu-client-app -Force`).
- The persistent-DEV server runs from `dist/MaxSecuServer` (WSL Postgres + FsBlobStore under `data/`).
- The crate does NOT deny warnings. TDD per task: failing test → run/fail → implement → pass → commit.
  One commit per task; end every commit with the standard `Co-Authored-By: Claude Opus 4.8` /
  `Claude-Session:` trailer.
- Platform: Windows (win32), PowerShell primary; Bash tool also available.

## File structure (what changes)

- `crates/client-core/src/upload.rs` (+ maybe `upload_stream.rs`): `ContentStreamSealer`, records-without-content builder, DEK-recovery-from-self-wrap; `seal_stream` refactored onto the sealer.
- `crates/client-app/src/upload.rs`: `prepare_video_streams` → disk-backed handle; streaming `run_pipeline`; MB/s.
- `crates/client-app/src/upload_staging.rs` (new): staging-record persist/load, resume, 24h sweep.
- `crates/client-app/src/jobs.rs`: `StagedVideoPreview` → file-backed (path, not RAM bytes).
- `crates/client-app/src/commands/upload.rs`: `stage_upload`/`confirm_upload`/`cancel_upload`/`resume_uploads`.
- `crates/client-app/src/commands/video.rs`: `serve_preview_range` reads from the on-disk `out.mp4`; view-path 6 MiB tuning (`MAX_RANGE_BODY`).
- `crates/media-launcher/src/lib.rs`: drop the hard ffmpeg timeout; keep the stall watchdog.
- `crates/server/src/{serve.rs,http.rs,store.rs,pg.rs,files.rs}`: request body limit; discard-unfinalized endpoint; configurable quota.
- `crates/client-app/ui/src/components/upload-tray.ts` (+ upload-screen): MB/s + resume prompt.
- `crates/client-app/src/commands/app_memory.rs` (new) + `quick-settings.ts` + `styles.css`: left-edge rainbow RAM gauge (Task 11b).
- Tests: `crates/client-core` lib tests; `crates/client-app/tests/*` e2e; `crates/server/tests/*`.

---

## Task 1: client-core `ContentStreamSealer` + refactor `seal_stream` **[two-stage review]**

**Files:** `crates/client-core/src/upload.rs` (or new `upload_stream.rs`), tests in the same crate.

The heart of the feature: seal content chunk-at-a-time from disk while reproducing `seal_stream`'s `digest`
byte-identically, so the whole content need never be in memory — **and keep the DEK/content-subkey inside
client-core** (client-app only ever gets ciphertext chunks via a callback).

> **Reuse the tested TCB primitive — do NOT reinvent it.** `maxsecu_crypto` ALREADY exposes
> `seal_stream_streaming(ck, file_id, version, stream_type, chunk_size, reader, emit) -> (chunk_count, digest)`
> (`crates/crypto/src/aead.rs`), which seals one `chunk_size` frame at a time from a `Read`er, calls
> `emit(index, &ciphertext)` per chunk (O(one chunk) RAM), determines `is_last` via one-frame **lookahead**,
> and returns the `(chunk_count, digest)` that is **byte-identical to `seal_stream`** for the same input.
> A crypto-crate parity test (`stream_streaming_matches_whole`) already guards that equivalence, so the DRY
> requirement is met at the crypto layer — there is **no cross-crate `seal_stream` refactor to do** (an
> index-only `seal(index, chunk)` API is deliberately NOT used: it cannot compute the final chunk's `is_last`
> AAD without the total count, which a reader with lookahead gets for free). Task 1 is a thin **client-core
> wrapper that owns the content subkey and delegates to this primitive.**

- [ ] **Step 1 (failing parity test):** In `crates/client-core/src/upload.rs` tests, add a test that, for a
  content plaintext of several sizes (1 byte, exactly N×`chunk_size`, and N×`chunk_size`+short, and empty),
  seals it two ways over a fixed `Dek` seed: (a) the existing `seal_stream(&dek.stream_subkey(Content),
  file_id, version, Content, chunk_size, plaintext)`; (b) a new `ContentStreamSealer` (constructed from the
  same `Dek` + `(file_id, version, Content, chunk_size)`) driven over a `std::io::Cursor` of the same
  plaintext, collecting every emitted `(index, ciphertext)`. Assert the per-chunk ciphertext bytes are
  IDENTICAL and the returned `(chunk_count, digest)` are IDENTICAL to `seal_stream`'s.
- [ ] **Step 2:** Run it → FAIL (`ContentStreamSealer` missing).
- [ ] **Step 3 (implement):** Add `ContentStreamSealer` to client-core holding the **content subkey**
  (derived internally via `dek.stream_subkey(stream_type)` — the raw `Dek` is never stored here and never
  returned) + `(file_id, version, stream_type, chunk_size)`. Give it `new(dek: &Dek, file_id, version,
  stream_type, chunk_size)` and a reader/emit method
  `seal_from_reader<R: Read, E: FnMut(u64, &[u8]) -> Result<(), CryptoError>>(&self, reader: &mut R, emit: E)
  -> Result<(u64, [u8; 32]), CryptoError>` that simply calls `maxsecu_crypto::seal_stream_streaming` with the
  held subkey + framing. The subkey field should be zeroized on drop (reuse the crate's existing zeroize
  pattern). Do NOT expose the subkey bytes and do NOT change `seal_stream`/`seal_streams`' public API.
- [ ] **Step 4:** Run `cargo test -p maxsecu-client-core --lib upload::` → PASS (incl. the existing
  `per_stream_digest_matches_sealed_chunks`).
- [ ] **Step 5:** Commit: `feat(core): ContentStreamSealer — client-core reader/emit content sealer over crypto::seal_stream_streaming (DEK stays in core)`.

**Security pass:** the content subkey never leaves the sealer (no getter; zeroized on drop) and the raw DEK is
never stored/returned; the `(chunk_count, digest)` is byte-identical to `seal_stream` (delegates to the
already-parity-tested `seal_stream_streaming`, so nonce derivation + `is_last` framing are unchanged, no nonce
reuse); no plaintext is retained/logged; sealing is a pure function of
`(subkey, file_id, version, stream_type, chunk_size, reader-bytes)`.

## Task 2: client-core records-without-content builder + DEK-recovery-from-self-wrap **[two-stage review]**

**Files:** `crates/client-core/src/upload.rs`, tests same crate.

Build the signed manifest/genesis/wraps + the SMALL sealed streams given the streamed content's
`(digest, chunk_count)` — without ever materializing the content ciphertext — and expose recovering the DEK
from a self-wrap for resume.

> **`Dek` is not `Clone`** (it wraps `Zeroizing<[u8;32]>`), so a byte-identical A/B test must drive BOTH paths
> from the **same `&Dek`**. Refactor `build_upload` to delegate to a `pub(crate) fn build_upload_inner(dek:
> &Dek, params, streams) -> UploadBundle` (public `build_upload` = `build_upload_inner(&Dek::generate(), …)`),
> and give the streaming path a matching `pub(crate) fn build_records_inner(dek: &Dek, params, small: &SmallStreams,
> content_digest, content_chunk_count) -> UploadRecords`. DRY the manifest/genesis/wrap assembly into ONE shared
> private helper both call (so the two can never diverge). The small-stream sealing loop of `seal_streams`
> should be factored so the streaming path seals only metadata/thumbnail/preview (content is NOT sealed here —
> its manifest `Stream` entry is `{Content, None, content_chunk_count, content_digest}`, prepended first since
> Content sorts lowest).

- [ ] **Step 1 (failing test A — byte-identical records):** Over one `let dek = Dek::generate();` and one
  `params`, call (a) `build_upload_inner(&dek, &params, &full_streams)` and (b) the streaming path: seal the
  content with `ContentStreamSealer::new(&dek, file_id, FIRST_VERSION, Content, chunk_size)` over a `Cursor`
  to get `(content_chunk_count, content_digest)`, then `build_records_inner(&dek, &params, &small_streams,
  content_digest, content_chunk_count)`. Assert the DETERMINISTIC outputs are byte-IDENTICAL: `manifest`
  (encoded bytes), `manifest_sig`, `genesis`, `genesis_sig`, and per wrap the `recipient_id`, `recipient_type`,
  `granted_by`, `grant`, and `grant_sig` (Ed25519 is deterministic; the grant binds `dek_commit`, not the
  wrap). Do NOT assert `wrapped_dek` bytes equal — HPKE uses a fresh random ephemeral per call, so those bytes
  differ; instead assert each path's self-`wrapped_dek` **opens to the same committed DEK**
  (`recovered.commit() == manifest.dek_commit.0`). Assert the small `SealedStreamOut`s
  (metadata/thumbnail/preview) match (a)'s byte-for-byte. (Content chunks are absent from the streaming path by
  design.) Do this for a V1 build (no ML-KEM) at minimum.
- [ ] **Step 2 (failing test B — DEK recovery round-trips, V1 AND V2):** From a build's self-`WrapOut`, recover
  the `Dek` and show a `ContentStreamSealer` from it reproduces the original content ciphertext + digest.
  Cover both suites: **V1** via `recover_dek(self_enc_secret: &EncSecretKey, &wrapped_dek, &WrapContext) ->
  Result<Dek, CryptoError>` (reuse `unwrap_dek`); **V2** via `recover_dek_hybrid(self_hybrid_secret:
  &HybridEncSecretKey, &wrapped_dek, &WrapContext) -> Result<Dek, CryptoError>` (reuse `unpack_hybrid_wrap` +
  `unwrap_dek_hybrid`). Also test the client-app-facing `resume_content_sealer(owner: &Identity,
  self_wrapped_dek, ctx, suite, file_id, version, chunk_size) -> Result<ContentStreamSealer, UploadError>`
  (branches on `suite`, recovers the `Dek` INTERNALLY, returns only a sealer — the `Dek` never leaves the
  crate) reproduces the original content ciphertext for both a V1 and a V2 upload.
- [ ] **Step 3:** Run → FAIL.
- [ ] **Step 4 (implement):** Add the `build_upload_inner`/`build_records_inner` refactor + shared assembly
  helper, `SmallStreams { metadata, thumbnail, preview }`, `UploadRecords { file_id, file_type, genesis,
  genesis_sig, manifest, manifest_sig, wraps, small_streams }`, and a `StreamingUploadBuilder` (public;
  OWNS a freshly-generated `Dek`, never returns it) with `content_sealer(file_id, chunk_size) ->
  ContentStreamSealer` and `finish(&params, &small, content_digest, content_chunk_count) -> UploadRecords`
  (delegates to `build_records_inner(&self.dek, …)`). Add `recover_dek`/`recover_dek_hybrid` (pub(crate)) and
  the public `resume_content_sealer`. Keep the existing self-wrap pre-check inside `wrap_and_grant[_hybrid]`
  (§12.2 step 7) — the streaming path reuses those unchanged.
- [ ] **Step 5:** Run `cargo test -p maxsecu-client-core --lib upload::` → PASS (all existing tests too).
- [ ] **Step 6:** Commit: `feat(core): streaming upload records (manifest/genesis/wraps without content) + DEK recovery from self-wrap (V1+V2)`.

**Security pass:** the `Dek` never leaves the crate — the builder owns it, `resume_content_sealer` recovers it
internally and returns only a `ContentStreamSealer` (holding just the content subkey); only wraps + records +
ciphertext cross the seam. The deterministic records (manifest/sigs/genesis/grants) are byte-identical to the
monolithic path via the shared assembly helper, and the (randomized) wraps open to the same committed DEK.
`recover_dek*` fail closed on a wrong secret/ctx/suite. No key material is logged. The self-wrap pre-check
still runs on build.

## Task 3: media-launcher — drop the hard transcode timeout (keep stall watchdog)

**Files:** `crates/media-launcher/src/lib.rs` (+ the ffmpeg run path), tests same crate.

- [ ] **Step 1 (failing/guard test):** Add/adjust a test asserting the confined ffmpeg run is NOT killed by
  a fixed wall-clock cap while it keeps making progress, but IS killed after `FFMPEG_STALL_TIMEOUT_MS` of no
  progress (mirror the existing confinement tests; `#[ignore]` if it needs a real spawn). At minimum,
  assert the hard-timeout constant is no longer applied on the ffmpeg ingest path.
- [ ] **Step 2:** Implement: remove the `DEFAULT_FFMPEG_TIMEOUT_MS` hard kill from the ffmpeg ingest
  (`FfmpegLauncher::run`/`run_ffmpeg_confined`); keep the progress-stall watchdog + `cancel`. Update the
  constant's doc (or delete it if unused elsewhere). Do NOT touch AppContainer/no-net/mem-cap/RAII cleanup.
- [ ] **Step 3:** `cargo test -p maxsecu-media-launcher` → PASS.
- [ ] **Step 4:** Commit: `feat(video): confined ffmpeg ingest has no fixed wall-clock cap; the 90s stall watchdog + cancel are the sole time bounds`.

## Task 4: client-app `prepare_video_streams` → disk-backed (6 MiB, no over_cap)

**Files:** `crates/client-app/src/upload.rs`, `crates/client-app/src/commands/upload.rs`.

- [ ] **Step 1 (failing unit test):** Add a pure unit test for a new `content_chunk_count(len, chunk)` /
  chunk-grouped index over the 6 MiB chunk size (contiguity + coverage + short-last), and assert
  `VIDEO_CHUNK_SIZE` is now `6 * 1024 * 1024`.
- [ ] **Step 2:** Change `VIDEO_CHUNK_SIZE` to 6 MiB. Rework `prepare_video_streams` to (a) NOT
  `fs::read(out.mp4)`, (b) NOT delete the per-job dir (the `out.mp4` must persist through confirm), (c)
  REMOVE the `over_cap`/`MAX_FRAME_BYTES` ceiling, (d) return a disk-backed handle
  `PreparedVideo { out_mp4_path, output_size, chunk_size, fragment_index, thumbnail, preview }` instead of a
  `PlaintextStreams` whose `content` holds the bytes. Derive thumbnail/preview from `thumb.png` as today
  (small, RAM). The job dir is now owned by the staging lifecycle (Task 5), not `JobDirGuard`.
- [ ] **Step 3:** Update `stage_upload`'s video branch to consume the new handle. `cargo test -p
  maxsecu-client-app --lib upload::` → PASS; `cargo build -p maxsecu-client-app`.
- [ ] **Step 4:** Commit: `feat(video): prepare_video_streams keeps the transcode on disk (6 MiB chunks, no 64 MiB cap) for streaming upload`.

## Task 5: staging-record module + file-backed preview **[two-stage review]**

**Files:** `crates/client-app/src/upload_staging.rs` (new), `crates/client-app/src/jobs.rs`, `lib.rs`.

- [ ] **Step 1 (failing test):** Round-trip test: build a `StagingRecord { file_id, manifest+sig,
  genesis+sig, wraps, file_type, title, out_mp4_path, chunk_size, content_chunk_count,
  small_stream_ciphertext, progress:0, created_ms, last_progress_ms, finalized:false }`, persist to a temp
  staging dir, load it back, assert equality; assert it contains **no DEK and no content ciphertext**.
- [ ] **Step 2:** Implement `upload_staging.rs`: the record type (serde), `persist`/`load`/`list_pending`/
  `remove`, a per-upload staging dir under the app dir holding the record + the (moved/linked) `out.mp4` +
  the small-stream ciphertext. Change `StagedVideoPreview` to be **file-backed** (holds `out_mp4_path`, not
  `Zeroizing<Vec<u8>>`); update `UploadJobs`/`StagedUpload` accordingly.
- [ ] **Step 3:** `cargo test -p maxsecu-client-app --lib` → PASS.
- [ ] **Step 4:** Commit: `feat(video): disk-backed upload staging record (no DEK/ciphertext at rest) + file-backed preview`.

**Security pass:** the record persists NO DEK and NO content ciphertext; the `out.mp4` sits in a
Low-IL/AppContainer-ACL staging dir; file perms are least-privilege; load fails closed on a corrupt record.

## Task 6: server — body limit + discard-unfinalized endpoint + configurable quota **[two-stage review]**

**Files:** `crates/server/src/{serve.rs,http.rs,store.rs,pg.rs,files.rs}`, tests `crates/server/tests/*`.

- [ ] **Step 1 (failing tests):** (a) a 6 MiB chunk PUT succeeds (body limit) where an 8 MiB+1 body is
  rejected; (b) `DELETE /v1/files/{id}` on a NEVER-finalized version removes it (its chunks gone, absent
  from listings) while a FINALIZED file is left immutable (rejected/no-op, genesis intact); (c) with a
  configured quota, staging a manifest whose `chunk_count×chunk_size` exceeds it is rejected, and with no
  quota (default) a large manifest stages fine.
- [ ] **Step 2:** Implement: set an explicit `DefaultBodyLimit` (≥ 8 MiB + slack) covering the chunk-PUT
  route; add the owner-only discard endpoint respecting append-only (if `file_genesis` is written at stage,
  use an **abandoned** marker + blob GC rather than deleting the immutable row — resolve against the actual
  stage/finalize model; a never-staged-genesis version can be hard-removed); add an optional
  `max_file_bytes` config (default `None` = unlimited) checked in `stage_version`.
- [ ] **Step 3:** `cargo test -p maxsecu-server` → PASS.
- [ ] **Step 4:** Commit: `feat(server): 8 MiB chunk body limit + owner discard of unfinalized uploads (append-only-safe) + optional file-size quota (default off)`.

**Security pass:** discard cannot touch a finalized/immutable version or its genesis; owner-only; the quota
is fail-closed when set; per-PUT RAM stays one chunk (no whole-file buffering introduced).

## Task 7: client-app streaming stage/confirm pipeline + MB/s **[two-stage review]**

**Files:** `crates/client-app/src/upload.rs`, `crates/client-app/src/commands/upload.rs`, `state.rs`.

- [ ] **Step 1 (failing e2e-lite / unit):** A test driving `run_pipeline` against an in-memory/loopback
  sink that asserts: content is uploaded by streaming from the on-disk `out.mp4` (pass-2 seal-by-index ==
  the manifest digest), only O(one-chunk) buffers are held, progress callbacks report `{done,total,
  bytes_per_s}`, and finalize is called once. (Use a small `out.mp4` fixture.)
- [ ] **Step 2:** Implement: `stage_upload` runs **pass 1** (`ContentStreamSealer` over `out.mp4` → content
  digest+count), builds `UploadRecords` (Task 2), persists the staging record (Task 5), returns the preview
  — NO network. `confirm_upload` → `POST /v1/files` (Task-2 records) → PUT small streams → **pass 2**
  (re-open `out.mp4`, `seal(index, chunk)` → PUT, retry-per-chunk, persist `progress` after each) →
  finalize → delete staging dir+record. Emit `UploadPhase`/progress with **MB/s** (rolling ~2s window).
- [ ] **Step 3:** `cargo test -p maxsecu-client-app --lib` + `cargo build` → PASS.
- [ ] **Step 4:** Commit: `feat(video): streaming stage/confirm — pass-1 digest + pass-2 seal-and-PUT from disk, O(one-chunk) RAM, MB/s progress`.

**Security pass:** the DEK stays in client-core across both passes; only ciphertext chunks + sliced-plaintext
preview cross the seam; progress persistence writes no secret; retry is idempotent by index.

## Task 8: resume-on-launch + 24h sweep + cancel/abandon + server discard **[two-stage review]**

**Files:** `crates/client-app/src/upload_staging.rs`, `crates/client-app/src/commands/upload.rs`, `main.rs`.

- [ ] **Step 1 (failing tests):** (a) given a staging record with `progress=k<n` (<24h), a `resume` path
  recovers the DEK from the self-wrap, re-seals + PUTs chunks `k..n`, finalizes, and cleans up; (b) a record
  >24h since last progress is swept (local deleted + server discard called); (c) cancel deletes local +
  calls discard.
- [ ] **Step 2:** Implement: `resume_uploads` command — on launch, `list_pending`; for each unfinalized
  record <24h prompt-to-resume (UI, Task 11) then resume (recover DEK, continue pass 2, finalize, clean up);
  for each >24h, sweep (delete local + best-effort server `DELETE`). Wire the launch scan in `main.rs`
  (surface pending to the UI, do not auto-run). `cancel_upload` deletes local + discards server.
- [ ] **Step 3:** `cargo test -p maxsecu-client-app --lib` → PASS.
- [ ] **Step 4:** Commit: `feat(video): resume interrupted uploads (prompt, DEK-from-self-wrap) + 24h sweep + cancel/abandon with server discard`.

**Security pass:** DEK recovery requires the unlocked identity; sweep/cancel reliably remove the plaintext
`out.mp4`; server discard only targets the caller's own unfinalized upload.

## Task 9: preview-from-disk (serve_preview_range over the on-disk `out.mp4`) **[two-stage review]**

**Files:** `crates/client-app/src/commands/video.rs`, `crates/client-app/src/jobs.rs`.

- [ ] **Step 1 (failing test):** Unit-test a `preview_slice_file(path, first, last)` (or adapt
  `serve_preview_range`) that reads the requested byte range directly from a file, over a temp fixture:
  bounded range == the file bytes, open-ended caps to `MAX_RANGE_BODY`, `first==len` ⇒ None(416). Bounded
  read buffers (seek+read the slice, not the whole file).
- [ ] **Step 2:** Implement: `serve_preview_range` looks up the file-backed `StagedVideoPreview`
  (`out_mp4_path`, Task 5) and serves the range from disk (seek+read), NO in-RAM `cmaf`, NO decrypt.
- [ ] **Step 3:** `cargo test -p maxsecu-client-app --lib` → PASS; `npm run typecheck` (no UI change expected).
- [ ] **Step 4:** Commit: `feat(video): author preview served by range from the on-disk transcode (no in-RAM buffer)`.

**Security pass:** only the author's own plaintext range crosses; bounded reads; unknown job ⇒ 404; path is
the staged one (no traversal from client input).

## Task 10: view-path tuning for 6 MiB chunks

**Files:** `crates/client-app/src/commands/video.rs`, `crates/client-app/src/upload.rs` (`FRAG_CHUNKS`).

- [ ] **Step 1:** Raise `MAX_RANGE_BODY` to ≥ the max chunk size (e.g. 8 MiB) so a range response can span a
  full 6 MiB chunk; adjust/confirm `resolve_range` tests. Retune `FRAG_CHUNKS` for 6 MiB chunks (likely 1).
  Confirm `FragmentCache` cap (settings) comfortably holds several 6 MiB fragments.
- [ ] **Step 2:** `cargo test -p maxsecu-client-app --lib stream:: video::` → PASS.
- [ ] **Step 3:** Commit: `feat(video): tune range serving + fragment grouping for 6 MiB video chunks`.

## Task 11: UI — upload tray MB/s + resume prompt

**Files:** `crates/client-app/ui/src/components/upload-tray.ts` (+ `upload-screen.ts`), tests.

- [ ] **Step 1 (failing test):** `node:test` for a pure `formatRate(bytesPerSec)` (e.g. `1572864 → "1.5 MB/s"`)
  and for a resume-prompt view-model (pending record → prompt text).
- [ ] **Step 2:** Implement: show MB/s (from the progress event) + %/ETA in `<upload-tray>`, WCAG-AA
  (aria-live, non-color-only); add a resume prompt ("Resume upload of `<title>`?" accept/dismiss) fed by the
  `resume_uploads` pending list. `npm run build`.
- [ ] **Step 3:** `npm run typecheck && npm test && npm run test:a11y` → PASS.
- [ ] **Step 4:** Commit: `feat(upload): MB/s throughput in the tray + resume-interrupted-upload prompt`.

## Task 11b: quick-settings live RAM gauge (rainbow bar)

**Why:** with large streaming uploads + video decode buffers, give the user an at-a-glance sense of how much of
the app's memory budget is in use. **Added by user request (2026-07-01).**

**Files:** `crates/client-app/src/commands/` (a small memory-stats command, e.g. `app_memory.rs`; register in
`main.rs`), `crates/client-app/src/state.rs` or `config.rs` (budget derivation), `crates/client-app/ui/src/components/quick-settings.ts`, `crates/client-app/ui/src/styles.css`, UI + a11y tests.

**What:** a thin **vertical bar pinned to the LEFT edge of `<quick-settings>`** that fills bottom→top in
proportion to how much of the app's allocated memory budget is currently **occupied**, painted with a **rainbow
gradient** (fixed full-spectrum hue sweep, masked to the fill height so more usage ⇒ more of the spectrum
shows). **Metric (documented assumption — confirm at the GUI smoke):** `occupied` = the process's current
working-set/resident bytes; `budget` = the app's configured memory budget = the two-tier caps
(decoded-frame-buffer cap + `FragmentCache` byte cap from `SettingsConfig`) + a fixed base allowance. The gauge
shows `occupied / budget`.

- [ ] **Step 1 (failing tests):** (a) `node:test` for a pure `ramGaugeModel(usedBytes, budgetBytes) ->
  { pct: number, fillFraction: number, label: string, hidden: boolean }` — clamps `pct` to `0..100`,
  `fillFraction` to `0..1`, `label` like `"420 / 512 MB (82%)"`, and `hidden: true` when `usedBytes == null`
  (OS query unavailable). (b) a Rust unit test that the budget is derived from settings caps + base and that
  the command's return shape (`{ used_bytes: Option<u64>, budget_bytes: u64 }`) serializes.
- [ ] **Step 2:** Backend: add a `memory_stats` command returning `{ used_bytes, budget_bytes }`. `used_bytes`
  = process working set (Windows `GetProcessMemoryInfo`→`WorkingSetSize`; use a minimal cross-platform helper
  or a tiny crate like `memory-stats`; **fail-soft** ⇒ `None` when unavailable, never panic). `budget_bytes`
  from the settings-derived budget above. Do NOT put this on any crypto/TCB path.
- [ ] **Step 3:** UI: render the left-edge rainbow bar in `<quick-settings>`, polling `memory_stats` every
  ~1.5s (clear the timer on disconnect/teardown). WCAG-AA: `role="meter"` + `aria-valuemin/max/now` + a visible
  numeric `label` (non-color-only); respect reduced-motion (no animated shimmer — static fill). Hide the bar
  when `hidden`. `npm run build`.
- [ ] **Step 4:** `npm run typecheck && npm test && npm run test:a11y`; `cargo test -p maxsecu-client-app --lib`
  → PASS.
- [ ] **Step 5:** Commit: `feat(ui): live RAM-usage rainbow gauge on the left edge of quick settings`.

## Task 12: end-to-end tests over real TLS

**Files:** `crates/client-app/tests/streaming_upload_e2e.rs` (new), reuse the video e2e harness.

- [ ] **Step 1:** e2e: upload a multi-6-MiB-chunk video via the streaming stage/confirm path over real TLS;
  download+decrypt == original plaintext; assert the client held O(one-chunk) buffers (structural: the
  pipeline reads from disk, no `content: Vec<u8>` of the whole file); ciphertext-only at rest.
- [ ] **Step 2:** e2e: interrupt after `k` chunks, drop + reload the staging record, resume (DEK from
  self-wrap) to completion, download == original. e2e: abandoned record >24h swept + server discard removes
  the orphan.
- [ ] **Step 3:** `cargo test -p maxsecu-client-app --test streaming_upload_e2e -- --test-threads=1`
  (ffmpeg-gated parts `#[ignore]`, run with `--ignored`). → PASS.
- [ ] **Step 4:** Commit: `test(video): streaming upload + resume + sweep/discard e2e over real TLS`.

## Task 13: GUI smoke (controller + user)

Controller builds+stages the release exe to both dist dirs + relaunches; user drives the WebView.
- Upload the previously-failing **`D:\Images\2024-06-26_12-06-30.mp4`** (305 MB → 159 MiB) end-to-end:
  continuous progress with **MB/s**, no OOM, completes, then plays (view path) with sound + seek.
- **Quit the app mid-upload**, relaunch → the **resume prompt** appears; accept → it finishes; the file plays.
- Confirm the author **preview** (before confirm) plays from disk; no console/CSP errors.
- Confirm the **quick-settings left-edge rainbow RAM gauge** (Task 11b) renders, moves as memory changes
  (e.g. rises during upload/decode), and its numeric label is sensible — and **confirm the intended metric**
  (occupied working-set vs. app budget) reads right to you (adjust if you meant something else).
Fix before proceeding on any failure (invoke **superpowers:systematic-debugging**). STOP if it fails.

## Task 14: security sign-off **[two-stage review]**

**Files:** `docs/security-review-streaming-upload.md`.

- [ ] Record honestly: content is streamed sealed/PUT from the on-disk transcode with O(one-chunk) RAM
  client + server; the DEK never crosses the Tauri seam and is recovered inside client-core from the
  self-wrap on resume; **no DEK and no ciphertext are persisted at rest** — only the signed manifest/genesis/
  wraps + small-stream ciphertext + the author's own plaintext `out.mp4` (Low-IL/AppContainer-ACL temp,
  reliably deleted on success/cancel/24h-sweep). Discard respects append-only immutability. The hard
  transcode cap is removed (stall watchdog + cancel remain); confinement unchanged. State residuals: local
  temp disk + server storage are the natural bounds; no parallel uploads; server-side orphan GC beyond the
  client discard is out of scope. No "PASS theater".
- [ ] Commit: `docs(security): streaming large-file upload sign-off (at-rest posture, DEK-in-core, append-only-safe discard)`.

---

## Controller self-review (coverage vs. spec)

- Streaming sealer + digest parity (TCB) → Task 1. ✓  Records-without-content + DEK recovery → Task 2. ✓
- Drop hard transcode timeout → Task 3. ✓  Disk-backed prepare + 6 MiB + no cap → Task 4. ✓
- Staging record (no DEK/ct at rest) + file-backed preview → Task 5. ✓
- Server body limit + discard + quota (4 GB-frugal) → Task 6. ✓
- Streaming stage/confirm + MB/s → Task 7. ✓  Resume + 24h sweep + cancel/discard → Task 8. ✓
- Preview-from-disk → Task 9. ✓  6 MiB view tuning → Task 10. ✓  UI MB/s + resume prompt → Task 11. ✓
- Quick-settings left-edge rainbow RAM gauge (user request) → Task 11b. ✓ (verified at the Task 13 smoke)
- e2e (upload/resume/sweep) → Task 12. ✓  GUI smoke → Task 13. ✓  Security sign-off → Task 14. ✓
- No client cap / configurable server quota default-off → Tasks 4 (no cap) + 6 (quota). ✓
- Pauses fMP4 Tasks 6–10; resume after. ✓
