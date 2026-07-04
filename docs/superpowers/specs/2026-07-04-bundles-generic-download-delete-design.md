# Bundles, Generic type, Download, Delete & Parallel decode — design

**Date:** 2026-07-04
**Status:** Approved (brainstorm) — ready for implementation planning
**Scope:** client-app (Rust + vanilla-TS UI), client-core (verify/build reuse), encoding (new file types), server (schema + listing + delete endpoint), api.md.

---

## 1. Motivation

Today every image/video/text is its own independent "post" (a server *file*: signed manifest
+ streams + per-recipient wraps, `FileType` ∈ {Video, Image, Blog}). Users want to group
multiple media into a single **bundle** that appears as one feed entry, be able to arrange the
members, view a bundle two different ways, share/delete it as a unit, upload arbitrary
("generic") files, download any post's decrypted original, and decode the feed faster.

This design adds all of that **without weakening the TCB**: the untrusted server still cannot
read content, and it cannot add/drop/reorder/substitute a bundle's members (the member list is
covered by the author's signed manifest, exactly like any content stream).

## 2. Decisions (from brainstorm)

- **Model:** bundles and standalone posts **coexist**. A standalone post works exactly as today.
  A bundle's members appear **only inside the bundle**, never as their own top-level feed items.
- **Server-visible membership:** members carry a `bundle_id` + `listed=false` flag so the feed
  can hide them reliably (even members of bundles the viewer cannot decrypt). The server flag is
  **untrusted** — authoritative membership comes only from the signed bundle content. The flag
  drives feed-hiding and delete-cascade only. Member **order** stays private inside the signed,
  encrypted bundle manifest (the server only learns the unordered grouping).
- **Two view modes:** *Gallery* (member cards, decrypt-on-tap) and *Stacked* (all members
  unlocked and rendered inline, in order). A toggle switches them; both are available while
  composing (preview). The default is **remember-last-choice** (first-ever open = Gallery).
- **Composer:** each member has its **own optional title/tags** (defaults to filename); bundle
  also has its own title/tags. Reorder via **drag handle AND ▲/▼ buttons**; remove via ✕.
  **Per-video transcode options** (resolution/quality) stay, per video member.
- **Generic type:** `FileType::Generic` — anything not image/video/text. **Icon + filename,
  download-only**, no in-app render, no custom thumbnail. Original filename+extension preserved
  in encrypted metadata.
- **Download:** a Download button on **every** post, for **any viewer** who can open it (holds a
  wrap). Saves the decrypted **plaintext** original (image→.png, video→.mp4, text→.txt,
  generic→original name). Bundles also offer **Download all** (→ a chosen folder). Members
  download individually.
- **Delete:** **full permanent delete + cascade**, **owner-only**, with a confirm prompt.
  Removes all versions/streams/blob chunks (local **and** cold-tier Dropbox)/wraps. Deleting a
  bundle cascades to its members. Standalone post delete removes just it.
- **Parallel decode + thread settings:** three independently-configurable knobs:
  - **Feed concurrency** (in-flight card decodes): default **4**, range 1–8.
  - **Transcode threads** (upload pipeline): default **= physical cores**, range 1–cores.
  - **Decode threads** (video-playback confined decoder + parallel per-chunk AEAD crypto):
    default **= physical cores**, range 1–cores.

## 3. Data model & encoding

### 3.1 `FileType` (crates/encoding/src/types.rs)

Extend the `enum8`:

```
Video   = 0x01
Image   = 0x02
Blog    = 0x03
Generic = 0x04   // NEW
Bundle  = 0x05   // NEW
```

Update `Field::get` decode arms + every exhaustive `match FileType` in the workspace
(`shape_content`, `file_type_name`, `bundle_file_type_str`, feed filter maps, etc.). These
compile-error at each site — walk them all.

### 3.2 Bundle as a file

A bundle **is a file**; its `file_id` **is** the bundle id. Streams:

- **content** — the *bundle manifest*: a canonical encoding of the ordered member list
  `[{ file_id: [u8;16], file_type: u8 }, …]` (a small new `encoding` struct, e.g.
  `BundleBody`). Sealed + digested + covered by the signed `Manifest` exactly like any content
  stream, so the server cannot tamper with the membership or order. This is the **only**
  authoritative source of membership.
- **metadata** — bundle title/tags (JSON `{title, tags}`, same as other posts).
- **thumbnail** — bundle cover = the first visual (image/video) member's thumbnail, copied at
  compose time. `None` if the bundle has no visual member.
- No **preview** stream.

Members are ordinary `Image`/`Video`/`Blog`/`Generic` files, wrapped to owner+recovery as today.

## 4. Server changes

### 4.1 Listing / membership

- Add `listed BOOLEAN NOT NULL DEFAULT true` and `bundle_id BYTEA NULL` (16 bytes) to the file
  (or file-version) record in `Store` + the Postgres and Memory stores.
- `POST /v1/files` accepts optional `listed` (default true) and `bundle_id`. A member upload
  sends `listed:false, bundle_id:<hex>`; the bundle file sends `listed:true` (no `bundle_id`).
- `GET /v1/files` (D35 listing, §8.6) returns only rows with `listed = true`. Bundle files are
  listed; members are hidden. The type filter still applies (add `generic`, `bundle` values).
- **Untrusted-flag note:** the client never trusts `bundle_id`/`listed` for membership or
  security decisions — only for what the server shows in the feed. A malicious server flipping a
  standalone file to `listed=false` is an availability issue only (consistent with the
  untrusted-server model).

### 4.2 Delete a finalized file (new)

Today `DELETE /v1/files/{id}` → `discard_file` → `Store::discard_unfinalized` only removes an
*unfinalized* upload (409 `HasFinalizedVersion` otherwise). Add a **finalized** delete:

- New `Store::delete_file(file_id, owner_id) -> Result<Vec<BlobRef>, DeleteError>`: owner-checked
  (return `NotFound` for a non-owner — no oracle, mirrors `list_recipients`), removes all
  versions, streams, wraps, and returns the blob refs to purge. Cascade: if the target is a
  bundle, also delete every file with `bundle_id = target` (owner-checked) and include their blob
  refs.
- HTTP: extend the existing `DELETE /v1/files/{id}` (or add `DELETE /v1/files/{id}?purge=1`) to
  route finalized deletes to `delete_file`. Purge blobs via `st.blobs.delete_stream(r)` for each
  ref — this already cascades to the cold tier (`WriteBackTier`/`dropbox_tier` `delete_stream`).
- Returns `204 No Content` on success, `404` for missing/non-owner.
- Update **api.md** for the listing flags and the delete semantics.

## 5. Client — bundle crypto & upload

### 5.1 Build / open (client-core reuse)

- **Build:** the bundle content is `encode(BundleBody{ members })`; then reuse the existing
  `build_upload` (in-RAM path — the member list is tiny) with `FileType::Bundle`. No new crypto
  primitive; the member list is just content bytes under the standard seal+sign.
- **Open:** reuse `verify_and_open` / `verify_and_open_headers`. After a verified open of the
  bundle content, `decode::<BundleBody>` yields the ordered member ids. Each member is then
  fetched **by that id** and opened via the normal per-file ladder (author binding under pinned
  D5, KT transparency gate, manifest sig, wrap unwrap, content digest) — the requested-id ==
  signed-id content-substitution defense (`run_open`'s `file_id` discipline) carries over
  unchanged.

### 5.2 Upload orchestration (`commands/upload.rs`, `upload.rs`, `jobs.rs`)

New `stage_bundle` / `confirm_bundle` (or extend the staged-job model):

1. Client generates `bundle_id` up front (= the bundle file's `file_id`).
2. Stage every member exactly like today's single upload (reuse `prepare_blog_streams`,
   `prepare_image_streams`, `prepare_video_streams`, and the new generic streaming prep — §6).
   Members are held as staged jobs.
3. On **Post bundle**: upload each member finalized with `listed=false, bundle_id`; then build +
   upload the bundle file (`listed=true`) whose content is the ordered member list; finalize.
4. **Partial failure:** reuse the staging/resume machinery. If the bundle file fails after some
   members uploaded, offer retry (members are already finalized but invisible — `listed=false`).
   On cancel, cascade-delete the uploaded members (§7) so nothing orphans.
5. Progress: the upload tray shows aggregate bundle progress (sum of member + bundle chunks).

Only DTOs cross the Tauri seam; identity/DEK/plaintext never leave the TCB (unchanged rules).

## 6. Generic type

- **Upload:** route through the **streaming (disk-backed, resumable)** content path (the video
  path minus transcode) so arbitrary/large files work with O(one chunk) RAM. Seal the raw file
  from disk; metadata JSON carries `{title, tags, filename}` (original name+extension). No
  thumbnail/preview.
- **`shape_content(Generic, …)`** returns no inline body — the viewer shows filename + Download.
- **Feed/gallery card:** generic file icon + filename, single **Download** action.

## 7. Feed & bundle viewing (`commands/feed.rs`, `commands/viewer.rs`, UI)

- **Bundle card counts:** in `decrypt_card`, for `FileType::Bundle`, additionally open the
  (tiny) content list and compute the type histogram → `CardDto` gains `member_counts`
  (e.g. `{video:1, image:4, blog:1, generic:0}`) + `member_total`. The card renders the
  `VID n · IMG n · TXT n` badge. Non-bundle cards are unchanged.
- **`open_bundle(file_id)`** command → verified `BundleView { members: [{file_id, file_type,
  title, thumbnail_b64}] }` in order. Member title/thumbnail come from each member's header
  (metadata+thumbnail) — fetched lazily (Gallery) or eagerly (Stacked) through the parallel pool.
- **UI `<bundle-screen>`** (new): a mode toggle (▦ Gallery / ≡ Stacked) bound to the persisted
  `bundle_view_mode` setting.
  - *Gallery:* render N `<media-card>`s keyed by member id (reuses the existing decrypt-on-tap
    card + `<media-viewer>` open flow).
  - *Stacked:* render N `<media-viewer>`-style blocks inline, fully opened, in order.
- The composer's **Preview gallery / Preview stacked** buttons render the same two views over the
  locally-staged (not-yet-uploaded) members.

## 8. Download (`commands/download`? new command + UI)

- **`download_content(file_id, save_path)`**: open+verify+decrypt (reuse the viewer open path);
  write plaintext to `save_path`. Streaming types (video/generic) decrypt chunk-by-chunk to disk
  (O(one chunk) RAM); image/blog whole-buffer. Suggested filename from metadata.
- **UI:** a Download button on every `<media-viewer>` and card overflow menu (any viewer).
  Bundle screen adds **Download all** → pick a folder, download each member into it (filenames
  from member metadata; de-dup collisions). Uses the existing dialog plugin (`commands/dialog.rs`).

## 9. Delete (`commands/*` + UI)

- **`delete_content(file_id)`**: owner-only; calls the new server delete (§4.2). For a bundle the
  server cascades to members; the client just deletes the bundle id. Confirm dialog surfaces the
  **irreversible** + **"copies others already downloaded can't be reached"** caveats.
- After success: invalidate the retained feed views + content cache; toast; navigate back.
- Delete button shown only when `card.mine` / owner (already computed as `my_id ==
  author.user_id`).

## 10. Sharing a bundle (`commands/share.rs`, share UI)

- **`reshare_bundle(bundle_id, recipients)`**: enumerate members from the **verified signed
  content**, then run the existing per-recipient, fail-isolated reshare (`reshare_inner` /
  `run_reshare_batch`) over the **bundle file + every member file**. The share UI (existing
  contacts checklist picker) drives it; aggregate progress + per-recipient outcomes as today.
  Re-share stays idempotent server-side.

## 11. Parallel decode & thread settings

### 11.1 Settings (`config::SettingsConfig` → settings.json)

Add three normalized/clamped fields (no secrets):

- `feed_concurrency: u8` — default 4, clamp 1–8.
- `transcode_threads: u16` — default = physical cores (`std::thread::available_parallelism`),
  clamp 1–cores.
- `decode_threads: u16` — default = physical cores, clamp 1–cores.

Surface all three in `<settings-screen>` (and the settings a11y lint). Persisted like the
existing settings.

### 11.2 Feed concurrency (UI `core/`)

- Replace the single-flight `serial()` for **card decodes** with a **bounded pool** (semaphore of
  size `feed_concurrency`). Introduce `decodePool` (new `core/pool.ts`) alongside the existing
  `serial.ts` (which other single-flight callers keep using).
- **Viewer-open stays prioritized:** it bypasses the pool (runs immediately on its own channel),
  preserving today's `serialPriority` behavior (open a card while a backlog decodes).
- `cancelPending` equivalent cancels queued (not-yet-started) pool jobs on feed teardown;
  in-flight jobs run to completion (or are abandoned by the caller).
- **Backend already tolerates concurrency:** `reauth` opens a fresh channel with no shared lock
  (the `ConnectLock` is only taken by `connect`/`login`/recovery, not `reauth`); the `Session`
  identity borrow is brief and read-only (a short async-mutex hold during the synchronous verify).
  Verify no data race is introduced; the content cache is already mutex-guarded.

### 11.3 Transcode threads

- Thread `transcode_threads` through the upload transcode pipeline: ffmpeg `-threads N`
  (universal-video-ingest path), rav1e/rav1e-equivalent encode thread pool, symphonia re-mux.
  Read the setting in `stage_upload`'s video prep.

### 11.4 Decode threads

- Thread `decode_threads` through the confined video-playback decode worker (rav1d thread count)
  and any rayon-style parallel per-chunk AEAD crypto used during download/stacked-open.

## 12. Testing & security review

- **Unit:** `BundleBody` encode/decode roundtrip; `FileType` new-variant decode; settings
  clamp/normalize; card histogram computation; download filename derivation.
- **e2e (client-workspace, real TLS):** bundle create → feed lists bundle (not members) → open
  (Gallery + Stacked) → member content verifies → share bundle → delete bundle cascades (members
  + blobs gone, feed empty). Generic upload → download roundtrip (bytes identical). Server
  delete-finalized owner-auth (non-owner → 404) + blob purge. Parallel-decode correctness (N
  cards decode concurrently, no identity race, results correct).
- **Security review sign-off doc** `docs/security-review-bundles.md` (matches the project's
  per-feature discipline): covers the new destructive server endpoint (owner-auth, no oracle,
  cascade correctness, cold-tier purge), the bundle content-verify path (member list is
  signed; requested-id discipline for members; server flags untrusted), and the new concurrency
  (no identity/DEK race, seam still DTO-only).

## 13. Implementation shape (multi-subagent workstreams)

**WS1 — Foundation (blocking, do first).** encoding `FileType::Generic/Bundle` + `BundleBody`
struct; server `listed`/`bundle_id` schema + `POST /v1/files` accept + `GET /v1/files` filter;
server finalized-delete endpoint + `Store::delete_file` + cascade + blob purge; api.md updates;
`SettingsConfig` three new fields (clamp/normalize). Unblocks everything.

Then, largely in parallel:

- **WS2 — Bundle crypto & upload orchestration** (client-core reuse; `stage/confirm_bundle`;
  jobs/staging; partial-failure/cancel cascade).
- **WS2b — Generic streaming upload** (disk-backed no-transcode path; metadata filename).
- **WS3 — Feed & bundle viewing** (`decrypt_card` histogram; `open_bundle`; `<bundle-screen>`
  with Gallery/Stacked + remember-last setting; reuse media-card/viewer).
- **WS4 — Composer UI** (bundle mode in `<upload-screen>`: add media/text, drag+▲▼ reorder,
  remove, per-member title, per-video transcode opts, Preview gallery/stacked, Post bundle).
- **WS5 — Download** (`download_content`; per-post + Download-all buttons; generic view; dialog).
- **WS6 — Delete UI** (`delete_content`; confirm dialog with caveats; cache invalidation).
- **WS7 — Parallel decode pool + thread settings** (`core/pool.ts`; settings-screen knobs;
  thread wiring for transcode/decode).
- **WS8 — Bundle sharing** (`reshare_bundle` fan-out; share UI). Depends on WS2/WS3.
- **WS9 — Tests + security-review sign-off.** Depends on all.

## 14. Reuse & gotchas (from repo memory)

- **cargo not on tool PATH** — prefix `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";` (PS)
  or `export PATH="$HOME/.cargo/bin:$PATH";` (bash).
- **NEVER `cargo fmt --all`** — client-core/server carry pre-existing rustfmt drift; match
  in-file style for new lines only.
- Client-app is its **own cargo workspace** (arti/SQLite split); server changes rebuild the
  server bin — **rebuild the dist server binary after server changes** (a stale dist server bin
  was a past `upload_chunk_failed` root cause).
- Modules live in client-app `lib.rs`; commands are registered in `main.rs`.
- Only DTOs cross the Tauri seam; identity/DEK/plaintext stay in the TCB; borrow identity only
  across synchronous verify, never across `.await`.
- The a11y XSS lint flags any `${` inside an `innerHTML` template — keep templates static, set
  dynamic text via `textContent`.
