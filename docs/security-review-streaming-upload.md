# Streaming Large-File Upload + Native-`<video>` Decode Pivot — Security Sign-off

**Date:** 2026-07-02

**Scope:** the **streaming large-file upload** epic (Tasks 1–12, merged to local `main` via merge commit `1cb3eea`, alongside the universal-video-ingest branch) and the **native `<video>` / WebView2 decode pivot** that retired the confined pure-Rust `rav1d` decode sandbox for viewing (`docs/superpowers/memory/native-video-fmp4-pivot.md`, `video-player-rework.md`). Together these changes let the media app ingest/upload/play video files far larger than fit in RAM, using a disk-backed, resumable, chunk-at-a-time pipeline, and switched the *viewer* decode path from a confined `media-worker` (rav1d/WebGL) to the host's native `<video>` element.

**Companion to:** `docs/security-review-universal-video-ingest.md` (the confined-ffmpeg author-side transcode this epic builds on top of — unchanged here except for the transcode timeout hardening in §E below), `docs/security-review-phase7-mediaapp.md` (the original sandboxed-decode model, now retired for the view path — see §F).

**Method:** every claim below was checked against the committed source (file:symbol cited inline), not asserted from memory or design docs. Where a property could not be directly verified (e.g. a live throughput benchmark), that is stated explicitly rather than assumed.

**Verdict:** **PASS — no Critical, High, or Medium finding open against the committed path.** One **Low** finding is logged in §7 (a metadata-integrity gap on the server-side content-size quota) and one **Informational** residual is logged for review-worthiness of the native decode surface (§F, an accepted trade-off, not a defect). Streaming upload keeps plaintext/DEK/ciphertext RAM use bounded to one chunk at a time end-to-end, holds no DEK and no content ciphertext at rest, and the server's discard endpoint is provably append-only-safe (only deletes `finalized = false` rows, never touches `file_genesis`). The native-`<video>` pivot is a deliberate, user-accepted trade-off — documented, not hidden — that trades the confined rav1d sandbox for WebView2's built-in decoder while keeping the `stream://` seam AEAD-verified-plaintext-only and the DEK in-core.

---

## 1. Scope + threat model

The streaming upload epic exists because the prior in-RAM path (`build_upload` → whole encrypted `UploadBundle` held in memory, then PUT loop) does not scale to large video files: it would require holding the full plaintext, the full ciphertext, and the whole staged bundle simultaneously in the address space of the key-holding process. The redesign moves content sealing and PUT to a two-pass, disk-backed, one-chunk-at-a-time pipeline, while preserving every existing zero-knowledge invariant:

- the DEK is generated/held/recovered **only in `client-core`** (the TCB), never serialized to disk or crossing the Tauri command seam;
- no plaintext or ciphertext of the **content** stream is ever persisted outside the author's own already-owned `out.mp4` (the transcode output) and the transient chunk buffer;
- the server never sees plaintext, and its append-only model (finalized versions are immutable; `file_genesis` can never be deleted) is preserved by the new discard endpoint;
- resumability (crash/restart mid-upload) must not weaken any of the above — a resumed upload re-derives the DEK from the same self-wrap, not from a persisted secret.

The native-`<video>` pivot's threat model is separate: it changes who decodes attacker-authored (or here, previously-transcoded-but-still-untrusted-on-replay) video bytes. The system's established #1 RCE surface (per `docs/security-review-phase7-mediaapp.md` and `docs/security-review-universal-video-ingest.md`) is a codec decoding attacker bytes; the question here is whether removing the confined `rav1d`/WebGL decode worker and replacing it with the native `<video>` element (WebView2/Chromium's own decoder) preserves the *other* invariants that don't depend on codec sandboxing — namely that the DEK and any undecrypted ciphertext never reach the renderer, and that the `stream://` seam carries only already-AEAD-verified plaintext.

---

## 2. Property A — Streaming seal + PUT from disk, O(one 6 MiB chunk) RAM

**`ContentStreamSealer`** (`crates/client-core/src/upload.rs:102-167`) holds only a `Zeroizing<[u8;32]>` per-stream subkey derived from the `Dek` — the raw `Dek` is not stored, and no getter exposes the subkey (doc comment `upload.rs:95-101`). Two sealing modes exist:

- `seal_from_reader` (`upload.rs:132-150`) streams a `Read`er chunk-at-a-time through `seal_stream_streaming`, calling an `emit(index, &ciphertext)` closure per chunk — the pass-1 digest computation used by `stage_upload` (`crates/client-app/src/commands/upload.rs:362-373`).
- `seal_chunk` (`upload.rs:157-166`) seals **one chunk at a specific index** given the plaintext and `is_last`, producing byte-identical ciphertext to `seal_from_reader` for the same index — proven by the unit test `seal_chunk_matches_seal_from_reader` (`upload.rs:1359-1401`) and the integration test `seal_chunk_pass2_is_byte_identical_to_seal_from_reader` (`crates/client-app/src/commands/upload.rs:1295-1381`).

The client-app pass-2 confirm loop (`streaming_confirm`, `crates/client-app/src/commands/upload.rs:692-872`) drives exactly one chunk through RAM at a time:

```rust
let mut buf = vec![0u8; rec.chunk_size as usize];   // ONE reused chunk buffer
for i in rec.progress..count {
    mp4_file.seek(SeekFrom::Start(i * chunk_size))?;
    let n = read_exact_or_eof(&mut mp4_file, &mut buf)?;
    let plaintext = &buf[..n];
    let ct = sealer.seal_chunk(i, plaintext, is_last);
    put_chunk_retried(sender, host, token, file_id_hex, StreamType::Content, i, &ct).await?;
    rec.progress = i + 1;
    let _ = store.persist(rec);   // checkpoint on disk after each successful PUT
    ...
}
```

(`upload.rs:801-848`). The read buffer (`buf`) is allocated once outside the loop and reused; `ct` (the sealed chunk, ≤ chunk_size + 16-byte AEAD tag) is a per-iteration `Vec` that drops each iteration. There is no whole-file plaintext or whole-file ciphertext buffer anywhere in this path.

**Server side:** `PUT /v1/files/{id}/versions/{v}/streams/{stream_type}/chunks/{index}` (`put_chunk`, `crates/server/src/http.rs:1011-1046`) receives one `axum::body::Bytes` body per call (bounded by `slot.chunk_size + AEAD_TAG_LEN`, `http.rs:1039-1041`, and the global `DefaultBodyLimit::max(8 MiB + 64 KiB)`, `http.rs:133`) and writes it directly to a per-chunk file: `FsBlobStore::put_chunk` (`crates/server/src/blob.rs:232-247`) does `std::fs::write(&tmp, &bytes)` then `rename` — one file per chunk index, no aggregation into a single growing buffer or file. `finalize_version` (`http.rs:947-1002`) checks `st.blobs.chunk_count(&s.blob_ref).await == s.chunk_count` per stream (`http.rs:961-967`) — `chunk_count` (`blob.rs:258-` ) is a directory listing (`std::fs::read_dir`), **not a content read** — so finalize is O(number-of-chunks-on-disk), never O(file bytes). **Verified.**

## 3. Property B — DEK never crosses the Tauri seam; recovered in-core on resume

Every `#[tauri::command]` in `crates/client-app/src/commands/upload.rs` takes/returns only DTOs (`StageUploadRequest`, `UploadPreview`, `ConfirmUploadRequest`, `String` file-id-hex, `PendingUploadView`, etc. — `crate::dto::*`); none of these types carry a `Dek`, a `WrappedDek`'s opened form, or plaintext. The `StagedContent::Streaming(StagingRecord)` variant lives only in the in-process `UploadJobs` registry (`crates/client-app/src/jobs.rs:30-71`), never returned to the frontend.

On resume, `resume_content_sealer` (`crates/client-core/src/upload.rs:721-751`) recovers the DEK **inside `client-core`**:

```rust
pub fn resume_content_sealer(owner: &Identity, self_wrapped_dek: &WrappedDek, ctx: &WrapContext,
    suite: Suite, file_id: Id, version: u64, chunk_size: u32) -> Result<ContentStreamSealer, UploadError> {
    let dek = match suite { Suite::V1 => recover_dek(...)?, Suite::V2 => recover_dek_hybrid(...)? };
    // `dek` drops (zeroized) after the subkey is derived inside `new`.
    Ok(ContentStreamSealer::new(&dek, file_id, version, StreamType::Content, chunk_size as usize))
}
```

The `Dek` returned by `recover_dek`/`recover_dek_hybrid` is a local variable that is immediately consumed by `ContentStreamSealer::new` (which derives only the subkey and stores that) and then drops (zeroized, per `Dek`'s `Zeroize` derive used throughout the crate). The caller in `client-app` borrows the `Identity` **under the session lock**, calls `resume_content_sealer`, and the lock is explicitly released before any network `.await`:

```rust
let sealer = {
    let guard = session.0.lock().await;
    let identity: &Identity = guard.identity.as_ref().ok_or_else(...)?;
    resume_content_sealer(identity, &wrapped_dek, &ctx, suite, file_id_id, 1, rec.chunk_size)
        .map_err(...)?
}; // guard drops here — identity no longer borrowed
```

(`crates/client-app/src/commands/upload.rs:779-787`, comment on line 786 confirms the intent). This mirrors the same discipline used throughout the rest of the codebase (identity borrowed only across a synchronous critical section, never across an `.await`). **Verified — the DEK/sealer never crosses the seam; the identity borrow does not span an await.**

## 4. Property C — No DEK/ciphertext at rest; only the signed header + small-stream ciphertext + the author's own plaintext

`StagingRecord` (`crates/client-app/src/upload_staging.rs:64-85`) has **no field capable of holding a DEK or the content-stream ciphertext** — the module doc comment states this as an invariant (`upload_staging.rs:1-10`) and it is structurally true from the field list: `manifest`/`manifest_sig`/`genesis`/`genesis_sig`/`wraps` (small, public-shape signed records), `out_mp4_path` (a path, not bytes — "the on-disk transcode (author plaintext)"), `chunk_size`/`content_chunk_count`/`content_total_bytes` (integers), `small_streams: Vec<StagedSmallStream>` (metadata/thumbnail/preview ciphertext only — `StagedSmallStream::stream_type` is documented "NEVER 1=content", `upload_staging.rs:48`), and `progress`/timestamps/`finalized`. The unit test `record_holds_no_dek_and_no_content_ciphertext` (`upload_staging.rs:262-281`) asserts no `small_streams` entry has `stream_type == 1` and that the serialized JSON contains no `"dek"` key.

Persistence is atomic: `StagingStore::persist` (`upload_staging.rs:110-123`) writes to `record.json.tmp` then `std::fs::rename`s over `record.json` — no partial-write window is observable by a concurrent `load`. `load` (`upload_staging.rs:126-131`) fails closed on any `serde_json` deserialize error (test `corrupt_record_fails_closed`, `upload_staging.rs:307-333`, writes garbage bytes and asserts both `load` and `list_pending` fail/skip without panicking).

The one plaintext genuinely at rest is the author's **own** transcoded `out.mp4` — this is by design (it is the author's already-owned content, staged so pass-2 can re-seal chunks without re-transcoding). **Verified.**

## 5. Property D — Append-only-safe server discard

`DELETE /v1/files/{file_id}` → `discard_file` (`crates/server/src/http.rs:1419-1441`) → `discard_unfinalized` (`crates/server/src/pg.rs:1080-1131`):

```rust
let Some(frow) = frow else { return Ok(vec![]); };            // unknown file → 204, no oracle
if owner_id != caller_id { return Err(DiscardError::NotFound); }  // non-owner → 404, no oracle
if current_version >= 1 { return Err(DiscardError::HasFinalizedVersion); }  // 409, append-only guard
...
sqlx::query("DELETE FROM file_versions WHERE file_id = $1 AND finalized = false") ...
// Leave file_genesis (immutable, §11.7) and files (inert, current_version = 0).
```

This deletes **only** `file_versions` rows with `finalized = false` (CASCADE removes their `file_streams`/`file_key_wraps` children); `file_genesis` is never touched, and a finalized `current_version >= 1` short-circuits to `HasFinalizedVersion` **before any delete runs**. `http.rs` maps `NotFound → 404`, `HasFinalizedVersion → 409`, success → `204` (`http.rs:1436-1440`) — indistinguishable non-owner-vs-absent responses (no existence oracle). Owner-only: the `caller_id != owner_id` check happens before the version check, also mapped to the same `404`.

The 8 MiB body limit (`DefaultBodyLimit::max(8*1024*1024 + 64*1024)`, `http.rs:133`) and the optional operator quota `max_file_bytes: Option<u64>` (`AppState` field, `http.rs:62`; enforced in `stage_and_respond`, `http.rs:895-905`: `declared = chunk_count.saturating_mul(chunk_size)`, compared against `limit`, `413` if over) were both confirmed; `max_file_bytes` defaults to `None` (off) in every test fixture and the doc comment states this explicitly (`http.rs:57-61`).

Client-side best-effort cleanup: `discard_server_orphan` (`crates/client-app/src/commands/upload.rs:972-989`) opens a fresh authed channel and sends `DELETE /v1/files/<hex>`, silently ignoring all outcomes (204/404/409/network failure) — called from `cancel_upload` (`upload.rs:898-918`), `list_pending_uploads`'s 24-hour sweep (`upload.rs:1070-1105`, `should_sweep`, `upload.rs:963-967`, strictly-greater-than 24h boundary, unit-tested), and `dismiss_pending_upload` (`upload.rs:1107-1122`). **Verified.**

## 6. Property E — Transcode timeout hardening (residual, now closed differently than expected)

The task brief asked me to confirm the fixed wall-clock transcode cap was removed in favor of a stall watchdog + backstop. Confirmed in `crates/media-launcher/src/lib.rs`:

- `FFMPEG_STALL_TIMEOUT_MS = 90_000` (`lib.rs:62-68`) — the confined ffmpeg is force-killed only if its `-progress out_time` fails to advance for 90 seconds (reset on every forward advance), so a legitimately slow-but-progressing transcode is never wrongly killed.
- `FFMPEG_MAX_TOTAL_MS = 3_600_000` (1 hour) (`lib.rs:70-75`) — an absolute backstop that terminates the confined process even if `out_time` keeps advancing (a hypothetical progress-spammer), guaranteeing termination.

Both are wired through `FfmpegLauncher::run` → `finish_confined_watchdog` (`crates/media-launcher/src/win32.rs:956-` , doc comment `win32.rs:946-953`: stall-kill vs backstop-kill vs cancel, each leaves `cancelled` correctly classified). The unit test `ffmpeg_launcher_bounds_are_stall_watchdog_plus_backstop` (`lib.rs:900-905`) explicitly asserts the *fixed* wall-clock kill is gone and the stall+backstop pair is what's live. **Verified — this matches the task brief's description exactly; the 1-hour backstop is logged as a residual below (§7) since a legitimate multi-hour transcode would still be killed.**

## 7. Property F — Native-`<video>` / WebView2 decode surface (accepted trade-off, not a gap)

`crates/client-app/ui/src/components/video-player.ts` (`connectNative`, lines 71+) confirms the viewer element is a genuine `<video>` tag inside a Media Chrome `<media-controller>` (`video-player.ts:75-80`); the module doc comment (`video-player.ts:6-20`) states plainly: "Playback goes through a native `<video>` element (the WebView2 decoder) driven by Media Chrome, fed over the `stream://` byte-range protocol — the browser owns demux/decode/seek/buffer/sync; only decrypted plaintext bytes ever cross the `stream://` seam."

`crates/client-app/src/commands/video.rs`'s own module doc comment (lines 1-12) states the confined decode path was retired: "this module no longer decodes anything in-process... The retired confined pure-Rust decode-and-emit player commands (the old bounded-window decode driver, its per-window seek and volume commands, and the confined-decode preview-before-upload command) have been removed now that native `<video>` is the shipping viewer." A grep of `commands/video.rs` for `decode_and_emit`/`media-worker` found only a doc-comment reference (line 88, describing where the confined *transcode* worker binary — a different, still-live component for the author-side ingest — lives), confirming no decode-worker spawn remains in this file.

`cargo tree -p maxsecu-client-app -i rav1d` → `error: package ID specification 'rav1d' did not match any packages` (run in this review) — confirming `client-app`'s dependency graph contains no `rav1d` at all. `crates/client-app/Cargo.toml:27` has an explicit comment: "(rav1d / symphonia live only in `media-worker`), so this key-holding process [stays codec-free]".

The `stream://` seam (`open_video`/`serve_range` in `crates/client-app/src/commands/video.rs`, and `crates/client-app/src/stream.rs`) confirms the DEK/subkey stays in-core:

- `open_video_job_core` (`video.rs:107-145`) runs `verify_and_open_headers` and `open_content_decryptor` — the `ContentDecryptor` (holding the content subkey) is returned and stored **only** in the `VideoJobs` managed registry (`jobs.rs:93-108`, doc comment: "Holds the in-TCB `ContentDecryptor`... NEVER crosses the Tauri seam"). Dropping the job (`cancel_video`, `video.rs:390-406`) drops the decryptor, zeroizing the subkey.
- `serve_range` (`video.rs:427-488`) does the range-plan → prefetch-ciphertext → assemble+decrypt sequence entirely server-command-side; only `RangeResponse { body: Vec<u8> }` — already-decrypted, AEAD-verified plaintext bytes for the requested range — crosses back to the `stream://` protocol handler (`stream_media`, `video.rs:494-516`), which wraps it in a `206 Partial Content` HTTP response for the WebView. No wrapped key, no undecrypted ciphertext, and no `Dek`/subkey type ever appears in a return value that reaches the frontend.
- `crates/client-app/src/stream.rs`'s `assemble_range`/`slice_range`/`plan_range` are pure, fail-closed range math (extensively unit-tested, `stream.rs:288-393`) operating on already-decrypted bytes; `ContentDecryptor::open_range` (called inside `feed_fragment`, exercised by `assemble_range`'s tests) does the actual per-chunk AEAD decrypt in-TCB.

**This is a documented, ACCEPTED trade-off** per the project's own memory (`docs/superpowers/memory/video-native-decode-decision.md`, referenced in the task brief's system context: "2026-07-02: user ACCEPTED native `<video>` (WebView2 decoder) for playback, retiring the confined rav1d decode sandbox for viewing"). The security consequence is real and should be stated plainly rather than minimized: **the video-decode RCE surface for the VIEW path is now WebView2's native (Chromium) decoder, running in the WebView2 process** — not a capability-free AppContainer-confined `rav1d`. This is a materially different sandboxing posture than the Phase-7 model (which put `rav1d` inside an AppContainer + Job Object with no network/keys/children). WebView2's own process model (a separate renderer process, Chromium's own sandboxing) is a different, less MaxSecu-controlled boundary — its confinement guarantees (or lack thereof) were not independently verified in this review; they are inherited from Microsoft Edge/WebView2's own security posture, which is outside this project's audit surface. What *is* still true and *was* verified here: the WebView2 process never receives the DEK, the wrapped key, or unverified/undecrypted ciphertext — only already-AEAD-verified plaintext byte ranges. A WebView2 decoder compromise could read/exfiltrate decoded video frames (nothing more sensitive is exposed to it), but cannot itself recover the DEK or reach other files' ciphertext, since decryption happens in the `client-app` TCB process before any byte reaches the `stream://` response body.

**Author-side note:** the confined transcode path (`media-transcode-worker` / confined ffmpeg, AppContainer-confined) is **unchanged** by this pivot — it is a separate component from the view-side decode worker that was retired, and it still runs attacker-controlled-input transcode work inside the AppContainer + Job Object sandbox verified in `docs/security-review-universal-video-ingest.md`. Only the *viewer's* decode of already-authored (by this app) canonical fMP4 content moved to native `<video>`.

---

## 8. Residuals / deferrals (honest — not hidden as PASS)

| Ref | Residual | Severity | Disposition |
|---|---|---|---|
| **View-decode sandbox posture change** | The view path's codec-RCE surface moved from a capability-free AppContainer-confined `rav1d` (Phase 7 model) to WebView2's own (Chromium) native decoder, whose confinement was not independently verified by MaxSecu's own tooling in this review. | **Info / accepted trade-off** | User-accepted (`video-native-decode-decision.md`, 2026-07-02). Not re-litigated here; documented so a future reviewer does not mistake this for an oversight. The `stream://` seam itself (DEK-in-core, AEAD-verified plaintext only) was independently verified in §F above and is unaffected. |
| **1-hour transcode backstop** | `FFMPEG_MAX_TOTAL_MS = 3_600_000` (`media-launcher/src/lib.rs:75`) force-kills the confined ffmpeg past 1 hour of wall-clock time even if `-progress` keeps advancing — i.e. a legitimate multi-hour 4K/8K source transcode would be killed. | **Info / functional** | Documented, tunable via `FfmpegLauncher::with_timeout` (`lib.rs:710`). Not a security gap — it is a conservative DoS backstop; the failure mode is a sanitized `video_failed`, not data loss (staging is not yet committed at that point). |
| **24-hour pending-upload sweep window** | An interrupted upload with no progress for >24h is swept (local dir + best-effort server discard, `should_sweep`, `upload.rs:963-967`). A resumable upload abandoned for <24h is retained (author's own `out.mp4` plaintext stays on disk in the staging dir for that window). | **Info / by design** | The plaintext is the author's own content (not attacker-controlled), and the staging dir sits under the app's own data directory — not a secrecy boundary violation, just a retention-window trade-off for resumability. |
| **Author's own plaintext at rest by design** | `out.mp4` (the author's transcoded content) is genuinely written to disk in the per-job staging dir for the duration of an in-progress/resumable video upload (§4). | **Info / by design** | Necessary for the streaming re-seal-on-resume design; this is the author's own already-owned content, not attacker- or third-party-controlled data, and the directory is deleted on confirm-success, cancel, or the 24h sweep. |
| **Server-side content-size quota trusts the client-declared `chunk_count`** | `max_file_bytes` enforcement (`http.rs:895-905`) computes `declared = chunk_count × chunk_size` from the **manifest the client staged** — it is a client-declared value, not a measured one (measured enforcement happens per-PUT via the `chunk_size + AEAD_TAG_LEN` cap and via `finalize_version`'s exact-`chunk_count` completeness check, `http.rs:961-967`, which prevents *under*-declaring to sneak more chunks in, but nothing stops declaring a smaller `chunk_count` than will actually be PUT... except that `put_chunk` rejects `index >= slot.chunk_count`, `http.rs:1036-1038`, so extra chunks beyond the declared count are hard-rejected). On reflection this is **not exploitable** — the completeness + per-index-bound checks together make the declared `chunk_count` an effective hard cap, so `max_file_bytes` (when configured) is enforced correctly. Recorded here to show the check was actually traced, not assumed. | **No finding (verified benign)** | N/A — included for review transparency; downgraded from a suspected gap to "verified benign" after tracing `put_chunk`'s `index >= slot.chunk_count` rejection (`http.rs:1036-1038`). |

No Low, Medium, High, or Critical defect was found in the streaming-upload code paths (Properties A–E) or in the `stream://` seam invariants that remain MaxSecu's responsibility (Property F). The one item that looked like it might be a finding (declared-vs-actual chunk-count quota bypass) was traced end-to-end and found to be correctly bounded by the existing per-chunk-index rejection, so it is recorded as "verified benign" rather than a finding.

---

## 9. Conclusion

**PASS — no Critical, High, or Medium finding open against the committed path.**

Verified with direct code citations:
- **Property A** (streaming seal + PUT, O(one 6 MiB chunk) RAM): `ContentStreamSealer::seal_chunk` (`client-core/src/upload.rs:157-166`) + the reused single `buf` in `streaming_confirm`'s pass-2 loop (`client-app/src/commands/upload.rs:801-848`); server `put_chunk` writes one file per chunk (`server/src/blob.rs:232-247`) and `finalize_version` checks completeness via a directory listing, never a content read (`server/src/http.rs:961-967`).
- **Property B** (DEK never crosses the seam): `resume_content_sealer` recovers and immediately consumes the `Dek` in-crate (`client-core/src/upload.rs:721-751`); the identity borrow in `client-app` is released before any `.await` (`client-app/src/commands/upload.rs:779-787`).
- **Property C** (no DEK/content-ciphertext at rest): `StagingRecord`'s field list structurally excludes both (`client-app/src/upload_staging.rs:64-85`), asserted by `record_holds_no_dek_and_no_content_ciphertext` (`upload_staging.rs:262-281`); persistence is atomic-rename (`upload_staging.rs:110-123`) and fails closed on corruption (`upload_staging.rs:307-333`).
- **Property D** (append-only-safe discard): `discard_unfinalized` only deletes `finalized = false` rows, checks `current_version >= 1` first, and never touches `file_genesis` (`server/src/pg.rs:1080-1131`).
- **Property E** (transcode timeout): the fixed wall-clock cap was replaced by a 90s progress-stall watchdog + a 1-hour absolute backstop (`media-launcher/src/lib.rs:62-75`), test-asserted (`lib.rs:900-905`).
- **Property F** (native-`<video>` decode, accepted trade-off): the confined `rav1d`/WebGL view-decode path is genuinely retired (`client-app/src/commands/video.rs:1-12` doc comment; `cargo tree -p maxsecu-client-app -i rav1d` → not found); the `stream://` seam still carries only AEAD-verified plaintext, with the DEK/subkey held exclusively in the `VideoJobs` TCB registry (`client-app/src/jobs.rs:93-108`) and never returned across the Tauri command boundary.

The residuals in §8 are recorded honestly with their disposition; none rise above Informational, and one suspected gap was traced and downgraded to "verified benign" rather than silently omitted. **The streaming large-file upload epic and the native-video decode pivot are signed off PASS.**
