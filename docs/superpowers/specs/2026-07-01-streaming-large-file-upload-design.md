# Streaming Large-File Video Upload (Resumable, Disk-Backed) — Design

**Status:** Approved design (brainstormed 2026-07-01). Ready for an implementation plan.
**Branch context:** `feat/universal-video-ingest` (local only; do NOT push/merge).
**Relationship to the current plan:** This work **PAUSES the native-video fMP4 plan at Tasks 6–10**
(`docs/superpowers/plans/2026-07-01-native-video-fmp4-fix.md`, Tasks 1a–5 done). After this streaming
feature lands, resume that plan at Task 6 (upload progress), 7 (cleanup), 8 (fMP4 guard), 9 (full smoke),
10 (security sign-off).

## Problem

The upload pipeline holds the **entire** video in RAM from transcode through confirm:
`prepare_video_streams` does `fs::read(out.mp4)` → `PlaintextStreams.content: Vec<u8>`; the preview keeps a
full second copy (`StagedVideoPreview.cmaf`); `build_upload` produces **all** ciphertext chunks in RAM
(`UploadBundle.streams[].chunks`); `run_pipeline` copies each chunk again per PUT. Peak client RAM ≈ 3–4× the
file size, so anything beyond a few hundred MiB is infeasible. A vestigial 64 MiB `over_cap`
(`MAX_FRAME_BYTES`, the removed re-mux worker's IPC frame size) rejects normal 5-min 1080p videos
(measured: a 305 MB source → **159 MiB** AV1 output, transcode succeeds in ~4 min but is then rejected).

## Goal

Upload arbitrarily large videos by **streaming the transcoded content chunk-by-chunk from disk** — never
holding the whole file in RAM on either side. Resumable across an app restart. Show upload throughput
(MB/s). Auto-clean abandoned staging after 24h. Remove the 64 MiB blocker. Fit the server in **4 GB RAM
total** (OS + Postgres + server process).

## Constraints

- **Client RAM:** O(one chunk) during seal + upload. No whole-file, no whole-ciphertext, no preview copy in RAM.
- **Server RAM (4 GB total):** never buffer the whole file or many chunks; chunks stream to disk one at a
  time (already true); per-PUT RAM = one chunk; Postgres holds only metadata. PG tuned by ops (small
  `shared_buffers`); not our code.
- **No arbitrary file-size cap** (see Decisions). Natural limits: local temp disk (transcode) + server storage.
- **Zero-knowledge posture preserved:** the content DEK never crosses the Tauri seam; nothing weakens the
  existing AEAD / manifest-binding / D5-author model. New at-rest exposure is limited and mitigated (below).

## Decisions (brainstorm, 2026-07-01)

| Topic | Decision |
|---|---|
| Mechanism | **Approach A — re-seal on demand.** Seal the content twice from the on-disk `out.mp4` (pass 1 = compute the manifest digest; pass 2 = re-seal each chunk and PUT). Persist only a small **staging record** (manifest + genesis + wraps + `out.mp4` path + progress). **No ciphertext copy, no DEK at rest.** |
| Resume | On restart, **prompt** "Resume upload of `<title>`?"; on accept, recover the DEK by unwrapping the persisted **self-wrap** (unlocked identity), re-seal remaining chunks from `out.mp4`, finish PUTs. |
| Video chunk size | **6 MiB** (within the protocol `[4 KiB, 8 MiB]` bound). Only **video content** uses it; images/blogs/metadata unchanged. 10 GB ⇒ ~1,707 chunks. |
| File-size cap | **No client-side cap.** Server-side guard is a **configurable quota, default OFF (unlimited).** "video too large" appears only if an operator sets a quota and it is exceeded. |
| Transcode timeout | **Drop the hard 10-min kill.** Keep the progress-based 90s **stall watchdog** + user-cancel. Confinement (no net/keys/children, mem cap) unchanged. |
| Abandoned cleanup | Keep leftover staging for **24h since last progress** (last successful chunk PUT, or stage time if none); **sweep on app launch** (delete local record + on-disk transcode; discard the server orphan). |
| Server orphans | On give-up / during the sweep, the client **discards the unfinalized staged file** via a new server endpoint (respecting append-only immutability — see below). |
| Preview-before-upload | **Kept**, served by byte-range from the on-disk `out.mp4` (no in-RAM `cmaf`). |
| Progress | Upload tray shows **MB/s** (rolling average) + %/ETA. |

## Data flow (video upload, end to end)

```
[pick source] → confined ffmpeg transcode (no hard timeout; stall watchdog)
             → out.mp4 persists in a per-job STAGING DIR (plaintext, Low-IL/AppContainer-ACL temp)
             → thumbnail/preview derived (RustImageCodec, small, RAM)
STAGE (preview-before-confirm):
  pass 1: stream out.mp4 in 6 MiB chunks → StreamSealer.seal(index, chunk) → fold digest (discard ct)
        → content digest + chunk_count
  seal small streams (metadata incl. fragment index, thumbnail, preview) in RAM (existing seal_streams)
  build + sign manifest (all stream digests) + genesis; wrap DEK to self + recovery
  persist STAGING RECORD to disk (manifest+sig, genesis+sig, wraps, out.mp4 path, chunk_size,
        content_chunk_count, small-stream ciphertext, progress=0, created/last_progress ts)
  show native preview from out.mp4 (serve_preview_range by range from the file)
CONFIRM:
  POST /v1/files (stage: manifest + wraps + stream metadata)   [server quota check if configured]
  PUT small-stream chunks (from the record)
  pass 2: for index in 0..n: seal(index, read 6 MiB from out.mp4) → PUT → update+persist progress (+MB/s)
  POST .../finalize
  delete staging dir + record   [O(1) server RAM throughout]
RESUME (on launch, record present, <24h, not finalized):
  prompt → unlock → recover DEK from self-wrap → resume pass 2 from last progress → finalize → cleanup
SWEEP (on launch): records >24h since last progress → delete local + discard server orphan
CANCEL/ABANDON: delete local staging + discard server orphan
```

## Component design

### 1. client-core (TCB) — streaming content sealer + records builder

New, security-critical. Two-stage review (spec, then security) mandatory.

- **`ContentStreamSealer`** (owns the content subkey; the DEK never leaves client-core):
  - Constructed from the file's `Dek` + `(file_id, version, StreamType::Content, chunk_size)`; it derives and
    holds only the content subkey (zeroized on drop), never the raw DEK.
  - `seal_from_reader(reader, emit) -> (chunk_count, [u8;32])` — reads one `chunk_size` frame at a time from a
    `Read`er, seals it, and calls `emit(index, &ciphertext)` (O(one chunk) RAM); `is_last` is resolved by
    one-frame lookahead, so the returned `(chunk_count, digest)` is **byte-identical to `seal_stream`**.
  - **Delegates to the existing, parity-tested `maxsecu_crypto::seal_stream_streaming`** (a crypto-crate test
    already asserts it matches `seal_stream` chunk-for-chunk + digest), so there is no cross-crate
    `seal_stream` refactor and no reimplemented nonce/framing to drift. The wrapper's job is purely to keep
    the subkey inside client-core. An index-only `seal(index, chunk)` API is intentionally avoided (it cannot
    compute the final chunk's `is_last` without the total count). Pass 1 (digest) drives it with a no-op
    `emit`; pass 2/resume drive it with an `emit` that PUTs (skipping indices already uploaded).
- **Records-without-content builder:** a `build_upload`-style path that takes the small `PlaintextStreams`
  (no content) + the **content digest/chunk_count** (from the sealer) + `UploadParams`, and returns the
  signed `manifest`/`genesis`, `wraps` (self + recovery), and the small streams' `SealedStreamOut` — but
  **not** the content ciphertext (that is streamed separately). The DEK stays internal; the sealer for the
  content pass is obtained from the same builder so both share the one DEK.
- **DEK recovery for resume:** expose recovering the file DEK from a persisted **self-wrap** using the
  unlocked identity (reuse the existing `unwrap_dek` + `WrapContext`), returning a sealer for the remaining
  content chunks. No new secret at rest.

*Feasibility confirmed:* the manifest commits a per-stream `digest` that is a deterministic function of
`(subkey, file_id, version, stream_type, chunk_size, plaintext)` and is signed **before** upload — so one
seal pass to learn the digest, then stream the chunks, with O(one chunk) memory.

### 2. client-app — disk-backed streaming pipeline

- **`prepare_video_streams` → disk-backed:** do **not** `fs::read(out.mp4)`, do **not** delete the per-job
  dir. Remove the 64 MiB `over_cap` on `out.mp4`. Return a handle `{ out_mp4_path, output_size,
  fragment_index (6 MiB chunk-grouped), thumbnail, preview_source=out_mp4_path }`. Thumbnail/preview derived
  as today (small, RAM). Chunk size = **6 MiB** for the content stream.
- **Staging record** (new module, e.g. `upload_staging.rs`): persist/load a per-upload record to a staging
  area under the app dir: `{ file_id, manifest+sig, genesis+sig, wraps (incl self-wrap), file_type, title,
  out_mp4_path, chunk_size, content_chunk_count, small_stream_ciphertext, progress(last_put_index),
  created_ms, last_progress_ms, finalized:false }`. **No DEK, no content ciphertext.** The `out.mp4` lives in
  the staging dir until success/cancel/sweep.
- **`stage_upload`** (preview-before-confirm): transcode → pass-1 seal (content digest) → build records →
  persist staging record → return preview handle. **No network yet.**
- **`confirm_upload` / streaming `run_pipeline`:** `POST /v1/files` → PUT small streams → **pass-2**
  stream-seal-and-PUT content from `out.mp4` (idempotent by index; retry per chunk) updating + persisting
  progress → finalize → delete staging dir + record. Emit progress `{done,total,bytes_per_s}` (MB/s over a
  short rolling window).
- **Resume** (`resume_uploads` on launch): scan the staging area; for each unfinalized record <24h since
  `last_progress_ms`, prompt "Resume upload of `<title>`?"; on accept, recover the DEK from the self-wrap,
  resume pass-2 from `progress`, finalize, clean up.
- **Sweep** (on launch): records >24h since last progress → delete local staging + call the server discard
  endpoint (best-effort).
- **Cancel/abandon:** delete local staging + server discard.
- **Preview from disk:** `serve_preview_range` reads the requested byte range **from `out_mp4_path`** (the
  staging record supplies it) instead of an in-RAM `cmaf`. `StagedVideoPreview` becomes file-backed; the
  RAM `Zeroizing<Vec<u8>>` content buffer is removed for video. Range reads use bounded buffers.

Images/blogs keep the existing in-RAM path (always small; their content is not a file on disk). Only **video**
uses the streaming/disk-backed path — one video path, no size branch.

### 3. media-launcher — retire the dead hard-cap constant (keep stall watchdog)

**Reconciled against live code:** the fixed 10-min hard kill is **already gone** — a prior increment replaced
it with the progress-based `FFMPEG_STALL_TIMEOUT_MS` (90s) stall watchdog (the primary bound) **plus a 1-hour
absolute backstop** `FFMPEG_MAX_TOTAL_MS`. `DEFAULT_FFMPEG_TIMEOUT_MS` (10-min) is now dead code. So: delete
the dead constant and tidy docs; **keep** the 90s stall watchdog + `cancel` AND the 1-hour DoS backstop.
Confinement (AppContainer, no net/keys/children, memory cap, RAII grant/cleanup) is **unchanged**. The primary
time bounds are the stall watchdog + user-cancel; the 1-hour backstop is a termination guarantee well above any
in-scope transcode (the 305 MB target transcodes in ~4 min) — see residuals.

### 4. server — RAM-frugal for 4 GB; discard endpoint; optional quota

- **Request body limit:** ensure the chunk-PUT route accepts bodies up to **max chunk_size + AEAD tag**
  (≥ 8 MiB). axum's default body limit is 2 MB — set an explicit `DefaultBodyLimit` (scoped to the chunk-PUT
  route, or global at ~8 MiB + slack) so 6 MiB PUTs are not rejected. Per-PUT RAM stays one chunk.
- **Already RAM-frugal (verify, no change):** `FsBlobStore::put_chunk` writes one chunk to disk; `finalize`
  is O(1) (no whole-file read); download serves one chunk at a time; Postgres stores only metadata.
- **Discard-unfinalized endpoint (new):** `DELETE /v1/files/{file_id}` (or `.../abandon`) that removes a
  **never-finalized** staged version — free its partial chunk blobs from disk and exclude it from listings —
  **without violating append-only immutability** (finalized versions and their genesis stay immutable; this
  only affects a version that was staged but never finalized). Owner-only. The exact mechanism (hard-remove
  a pre-finalize row vs. an abandoned flag) is resolved against the server's stage/finalize state model
  during implementation; if `file_genesis` is written at stage time, use an **abandoned** marker + blob GC
  rather than deleting the immutable row.
- **Configurable quota (default OFF):** a server config value; if set, `stage_version` rejects a manifest
  whose declared content size (`chunk_count × chunk_size`) exceeds it with a distinct "too large" status.
  Default unlimited ⇒ no cap for the single-user deployment.

### 5. view-path tuning for 6 MiB chunks

The range player reads `chunk_size` dynamically, so `serve_range`/`FragmentCache`/`plan_range` adapt. Tune:
- `MAX_RANGE_BODY` (currently 4 MiB) → **≥ chunk size** (e.g. 8 MiB) so a range response can span a full chunk.
- `FRAG_CHUNKS` (author fragment grouping) → retune for 6 MiB chunks (likely **1** chunk/fragment).
- Confirm the `FragmentCache` byte cap comfortably holds several 6 MiB fragments (settings-driven).

### 6. UI — tray MB/s + resume prompt

- `<upload-tray>`: show **MB/s** (rolling) alongside %/ETA; WCAG-AA (aria-live, non-color-only).
- Resume prompt on launch ("Resume upload of `<title>`?" accept/dismiss), driven by a `resume_uploads`
  command surfacing pending records.

## Security posture

- **New at-rest exposure:** the plaintext `out.mp4` persists in a Low-IL/AppContainer-ACL temp staging dir
  from transcode → confirm/cleanup (vs. today's RAM-only). It is the **author's own** pre-encryption
  plaintext on the author's machine; reliably deleted on success/cancel/sweep/abandon (RAII + the 24h
  sweep). **No DEK and no content ciphertext are persisted** (Approach A) — the only persisted secrets-bearing
  artifacts are the signed manifest/genesis/wraps (destined for the server anyway) and the small-stream
  ciphertext.
- **Content key never crosses the Tauri seam**; only sliced plaintext ranges cross for playback/preview
  (unchanged). The DEK lives in client-core; on resume it is recovered inside client-core from the self-wrap.
- **Discard respects immutability:** finalized versions/genesis remain append-only; discard only affects
  never-finalized staging.
- **Confinement unchanged**; dropping the hard transcode cap keeps the stall watchdog + mem cap + user-cancel.

## Testing

- **client-core (TCB):** `ContentStreamSealer` produces byte-identical chunks + digest to `seal_stream`
  (property/parity test over several sizes incl. short last chunk); records-without-content builds the same
  manifest a monolithic `build_upload` would; DEK-recovery-from-self-wrap round-trips.
- **client-app:** staging record persist/load round-trip; streaming `run_pipeline` uploads == plaintext on
  the server and streams with O(one-chunk) buffers; resume-from-progress finishes a partially-uploaded file;
  24h sweep deletes local + discards server orphan; preview-by-range from disk == the file bytes.
- **e2e over real TLS:** upload a multi-6-MiB-chunk video, download+decrypt == original; interrupt mid-upload
  and resume to completion; abandoned upload swept + server orphan discarded. (Large multi-GB runs are
  `#[ignore]`-gated manual smokes.)
- **server:** 6 MiB PUT accepted (body limit); discard removes a never-finalized version without touching
  finalized/immutable state; quota (when set) rejects at stage.
- **GUI smokes (user-driven):** upload the previously-failing 305 MB / 159 MiB file end-to-end with MB/s;
  quit mid-upload and resume; confirm playback + preview.

## Out of scope / residuals

- Parallel/multiplexed chunk uploads (single serialized HTTP/1.1 connection stays; simpler + RAM-frugal).
- Server-side background GC of orphans beyond the client-driven discard (documented).
- Postgres tuning for 4 GB (ops runbook, not code).
- Truly enormous files remain bounded by **local temp disk** (transcode output), **server storage**, and the
  **1-hour ffmpeg transcode backstop** (`FFMPEG_MAX_TOTAL_MS`) — a genuinely multi-hour progressing transcode
  would hit it. Far above any in-scope source; lift it (Task 3 follow-up) only if such sources are needed.
  All fail closed and are resumable/cleanable.
