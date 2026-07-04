# Bundles, Generic type, Download, Delete & Parallel decode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users post multiple media as a single arrangeable **bundle** (two view modes, share/delete as a unit), upload arbitrary **generic** files (download-only), **download** any post's decrypted original, **delete** their own published posts, and decode the feed with configurable **parallelism** and **CPU-thread** budgets.

**Architecture:** A bundle is itself a server *file* (`FileType::Bundle`) whose encrypted, author-signed content is the ordered member list; members are ordinary files flagged `listed=false` + `bundle_id` so the server hides them from the feed and cascades delete/share. The untrusted server never learns member order and can never tamper with membership (it's under the signed manifest digest). All existing verify/seal/wrap/reshare machinery is reused; no new crypto primitive.

**Tech Stack:** Rust (encoding/server/client-core/client-app Tauri v2), vanilla TypeScript UI (web components + `node:test`), Postgres/Memory stores, existing streaming-upload + reshare + KT/D5 verify stacks.

**Spec:** `docs/superpowers/specs/2026-07-04-bundles-generic-download-delete-design.md`

---

## Conventions (read once before any task)

- **cargo is not on PATH in tools.** Prefix every cargo command:
  - PowerShell: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo …`
  - bash: `export PATH="$HOME/.cargo/bin:$PATH"; cargo …`
- **`client-app` is its own cargo workspace** (arti/SQLite split). Run its tests from `crates/client-app/`. The `server`/`encoding`/`client-core` crates are the outer workspace.
- **NEVER run `cargo fmt --all`.** `client-core`/`server` carry intentional pre-existing rustfmt drift. Match in-file style for new lines only.
- **After ANY server change, rebuild the dist server binary** before a GUI/e2e smoke (a stale dist server bin was a prior `upload_chunk_failed` root cause).
- **Tauri seam rule:** only DTOs cross `#[tauri::command]` boundaries — never `Identity`, `Dek`, `WrapOut`, `UploadBundle`, or plaintext. Borrow `Identity` only across *synchronous* verify/seal, never across `.await`.
- **UI a11y XSS lint** flags any `${` inside an `innerHTML` template. Keep templates static; set dynamic text via `textContent`.
- New client-app modules are declared in `crates/client-app/src/lib.rs`; new commands are registered in `crates/client-app/src/main.rs` `invoke_handler!`.
- UI unit tests run with `node --test` (see existing `*.test.ts`); the UI has no framework — plain custom elements.

**Dependency order:** **WS1 (foundation) must land first.** Then WS2, WS2b, WS3, WS4, WS5, WS6, WS7 can proceed in parallel; WS8 depends on WS2+WS3; WS9 (tests + sign-off) depends on all.

---

## WS1 — Foundation (encoding + server + settings)

### Task 1.1: Add `FileType::Generic` and `FileType::Bundle`

**Files:**
- Modify: `crates/encoding/src/types.rs:405-428`
- Reference (must update every exhaustive match): `crates/client-app/src/commands/viewer.rs` (`shape_content`), `crates/client-app/src/commands/feed.rs` (`file_type_name`), `crates/client-app/src/commands/upload.rs` (`bundle_file_type_str`)

- [ ] **Step 1: Write the failing test** in `crates/encoding/src/types.rs` tests module:

```rust
#[test]
fn file_type_generic_and_bundle_roundtrip() {
    use crate::{encode_field, decode_field}; // if helpers exist; else encode via Writer/Reader as siblings do
    for ft in [FileType::Video, FileType::Image, FileType::Blog, FileType::Generic, FileType::Bundle] {
        let mut w = Writer::new();
        ft.put(&mut w);
        let mut r = Reader::new(&w.into_bytes());
        assert_eq!(FileType::get(&mut r).unwrap(), ft);
    }
    // Unknown byte still fails closed.
    let mut r = Reader::new(&[0xFF]);
    assert!(FileType::get(&mut r).is_err());
}
```
(Match the exact `Writer`/`Reader` construction used by other tests in this file — read the file's existing test helpers first.)

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-encoding file_type_generic_and_bundle`
Expected: FAIL (no `Generic`/`Bundle` variant).

- [ ] **Step 3: Implement** — extend the enum and decode:

```rust
pub enum FileType {
    Video = 0x01,
    Image = 0x02,
    Blog = 0x03,
    Generic = 0x04,
    Bundle = 0x05,
}
```
And in `get`, add arms:
```rust
0x04 => Ok(FileType::Generic),
0x05 => Ok(FileType::Bundle),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p maxsecu-encoding file_type_generic_and_bundle`
Expected: PASS.

- [ ] **Step 5: Fix the now-broken exhaustive matches** so the workspace compiles. In `shape_content` (viewer.rs) add:
```rust
FileType::Generic => Ok((None, None)), // download-only: no inline render
FileType::Bundle => Err(UiError::new("verify_failed", "A bundle has no direct content.")),
```
In `file_type_name` (feed.rs) add `FileType::Generic => "generic"`, `FileType::Bundle => "bundle"`. In `bundle_file_type_str` (upload.rs) add the same two arms. Run `cargo build -p maxsecu-encoding` and `cargo build` in `crates/client-app` to find any remaining non-exhaustive matches and fix each.

- [ ] **Step 6: Commit**
```bash
git add crates/encoding/src/types.rs crates/client-app/src/commands/
git commit -m "feat(encoding): add FileType::Generic and FileType::Bundle"
```

### Task 1.2: `BundleBody` — the ordered member list codec

**Files:**
- Create struct in: `crates/encoding/src/structs.rs` (alongside `Manifest`)
- Test: same file's test module

The body carried in a bundle file's **content** stream: an ordered list of members. Each entry = 16-byte `file_id` + 1-byte `file_type`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn bundle_body_roundtrips_and_preserves_order() {
    let body = BundleBody {
        members: vec![
            BundleMember { file_id: Id([0x01; 16]), file_type: FileType::Video },
            BundleMember { file_id: Id([0x02; 16]), file_type: FileType::Image },
            BundleMember { file_id: Id([0x03; 16]), file_type: FileType::Generic },
        ],
    };
    let bytes = encode(&body);
    let back: BundleBody = decode(&bytes).unwrap();
    assert_eq!(back.members.len(), 3);
    assert_eq!(back.members[0].file_type, FileType::Video);
    assert_eq!(back.members[2].file_id, Id([0x03; 16]));
    // Order is preserved (it is authoritative).
    assert_eq!(back.members[1].file_id, Id([0x02; 16]));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p maxsecu-encoding bundle_body_roundtrips`
Expected: FAIL (types undefined).

- [ ] **Step 3: Implement** `BundleMember` + `BundleBody` with `Field`/encode-decode following the exact pattern of a neighboring struct in `structs.rs` (read `Manifest`'s `Field` impl to match the length-prefixed vec + fixed-array conventions). Members vec is length-prefixed; each member = `Id` (16 bytes) then `FileType`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p maxsecu-encoding bundle_body_roundtrips`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/encoding/src/structs.rs
git commit -m "feat(encoding): BundleBody ordered member-list codec"
```

### Task 1.3: Server store — `listed` + `bundle_id` on files

**Files:**
- Modify: `crates/server/src/store.rs` (the `Store` trait + `MemoryStore`), the Postgres store impl, and the stage/create path
- Modify: `crates/server/src/http.rs` (`POST /v1/files` handler — accept optional `listed`, `bundle_id`)
- Test: server store unit tests + an http-level test

- [ ] **Step 1: Write the failing test** (memory store): a file staged with `listed=false, bundle_id=Some(X)` is retrievable with those fields; default when omitted is `listed=true, bundle_id=None`.

```rust
#[tokio::test]
async fn stage_records_listed_and_bundle_id() {
    let store = MemoryStore::new();
    // ... stage a file version with listed=false, bundle_id=Some([9u8;16]) via the
    // store's create/stage method (read the existing stage signature first).
    let rec = store.get_file_meta([1u8;16]).await.unwrap();
    assert!(!rec.listed);
    assert_eq!(rec.bundle_id, Some([9u8;16]));
}
```
(Adapt to the real store API names — read `store.rs` for the existing stage/create-version method and the file-meta getter.)

- [ ] **Step 2: Run to verify it fails** — `cargo test -p maxsecu-server stage_records_listed`. FAIL (fields don't exist).

- [ ] **Step 3: Implement** — add `listed: bool` (default true) and `bundle_id: Option<[u8;16]>` to the file/version record struct, thread them through the stage/create method signature (default via an `Option`), persist in `MemoryStore`, and add the Postgres columns + migration (`listed BOOLEAN NOT NULL DEFAULT true`, `bundle_id BYTEA NULL`) and read/write in the PG store. Add a `get_file_meta` accessor if none exists.

- [ ] **Step 4: Run to verify it passes** — `cargo test -p maxsecu-server stage_records_listed`. PASS.

- [ ] **Step 5: Wire the HTTP body** — in `POST /v1/files`, parse optional `"listed"` (default true) and `"bundle_id"` (hex→[u8;16]) and pass them to the stage call. Add an http test asserting a stage body with `listed:false` round-trips.

- [ ] **Step 6: Commit**
```bash
git add crates/server/src/store.rs crates/server/src/http.rs crates/server/migrations/ 2>/dev/null; git add -A crates/server
git commit -m "feat(server): files carry listed + bundle_id; POST /v1/files accepts them"
```

### Task 1.4: Feed listing hides members

**Files:**
- Modify: `crates/server/src/store.rs` (the `list_files` query used by `GET /v1/files`) and/or `crates/server/src/http.rs` listing handler
- Test: server test

- [ ] **Step 1: Write the failing test** — after staging one `listed=true` bundle file and two `listed=false` members, `GET /v1/files` (the store `list_files`) returns only the bundle.

```rust
#[tokio::test]
async fn listing_excludes_bundle_members() {
    // stage bundle (listed=true) + 2 members (listed=false) for the same owner...
    let out = store.list_files(owner_id, None, 50).await.unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].file_id, bundle_id);
}
```

- [ ] **Step 2: Run to verify it fails.** FAIL (members included).

- [ ] **Step 3: Implement** — add `WHERE listed = true` (PG) / filter (Memory) to the listing. Add `generic`/`bundle` to the `type=` filter parse.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit**
```bash
git add -A crates/server; git commit -m "feat(server): GET /v1/files lists only listed=true (hides bundle members)"
```

### Task 1.5: Server — delete a finalized file (owner-only) + cascade

**Files:**
- Modify: `crates/server/src/store.rs` (new `delete_file`), `crates/server/src/http.rs` (`discard_file` at ~1590, extend to finalized delete), `crates/server/src/error.rs` or the `DiscardError`/`DeleteError` enum
- Test: server unit + http test

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn delete_file_owner_only_and_cascades_bundle() {
    // owner O1 stages+finalizes: bundle B (listed=true) + members M1,M2 (bundle_id=B).
    // delete_file(B, O1) removes B, M1, M2 and returns all their blob refs.
    let refs = store.delete_file(bundle_b, owner_o1).await.unwrap();
    assert!(store.get_file_meta(bundle_b).await.is_none());
    assert!(store.get_file_meta(member_m1).await.is_none());
    // Non-owner gets NotFound (no oracle).
    assert!(matches!(store.delete_file(other_file, owner_o2).await, Err(DeleteError::NotFound)));
}
```

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** `Store::delete_file(file_id, owner_id) -> Result<Vec<BlobRef>, DeleteError>`: owner-check (return `NotFound` for missing OR non-owner — no oracle, mirrors `list_recipients`/`discard_file`); delete all versions/streams/wraps; if the target's own type is a bundle, additionally delete every file with `bundle_id == file_id` (owner-checked) and include their blob refs. Return every removed blob ref.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Wire HTTP** — extend `discard_file` (the `DELETE /v1/files/{id}` handler): try `discard_unfinalized` first; on `HasFinalizedVersion`, call `delete_file(file_id, session.user_id)` and purge each returned ref via `st.blobs.delete_stream(r)` (this cascades to the cold tier). Return `204`; `404` for NotFound. Add an http test: non-owner delete → 404; owner delete of a finalized bundle → 204 and members gone from listing.

- [ ] **Step 6: Update `api.md`** — the delete semantics (finalized delete, owner-only, cascade) and the `listed`/`bundle_id` fields on `POST /v1/files` + listing filter.

- [ ] **Step 7: Commit**
```bash
git add -A crates/server docs/api.md 2>/dev/null; git add -A
git commit -m "feat(server): owner-only finalized file delete with bundle cascade + blob purge"
```

### Task 1.6: Three new settings fields (concurrency + thread budgets)

**Files:**
- Modify: `crates/client-app/src/config.rs:244-365` (`PerformanceSettings` + `normalized_with_ram`)
- Test: same file's test module

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn performance_thread_settings_default_and_clamp() {
    let cores = std::thread::available_parallelism().map(|n| n.get() as u16).unwrap_or(1);
    let d = PerformanceSettings::default();
    assert_eq!(d.feed_concurrency, 4);
    assert_eq!(d.transcode_threads, cores);
    assert_eq!(d.decode_threads, cores);
    // Clamp: feed_concurrency 1..=8; threads 1..=cores.
    let mut bad = SettingsConfig::default();
    bad.performance.feed_concurrency = 99;
    bad.performance.transcode_threads = 9999;
    bad.performance.decode_threads = 0;
    let limits = crate::ram::compute_ram_limits(crate::ram::system_total_mb_public());
    let n = bad.normalized_with_ram(&limits).performance;
    assert_eq!(n.feed_concurrency, 8);
    assert_eq!(n.transcode_threads, cores);
    assert_eq!(n.decode_threads, 1);
}
```

- [ ] **Step 2: Run to verify it fails** — from `crates/client-app/`: `cargo test performance_thread_settings`. FAIL.

- [ ] **Step 3: Implement** — add to `PerformanceSettings`:
```rust
#[serde(default = "default_feed_concurrency")] pub feed_concurrency: u8,
#[serde(default = "default_cpu_threads")]      pub transcode_threads: u16,
#[serde(default = "default_cpu_threads")]      pub decode_threads: u16,
```
with `fn default_feed_concurrency() -> u8 { 4 }`, `fn default_cpu_threads() -> u16 { std::thread::available_parallelism().map(|n| n.get() as u16).unwrap_or(1) }`, and update the `Default` impl. In `normalized_with_ram`, clamp: `feed_concurrency.clamp(1,8)`; `transcode_threads.clamp(1, cores)`; `decode_threads.clamp(1, cores)` where `cores = default_cpu_threads()`.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/client-app/src/config.rs
git commit -m "feat(settings): configurable feed_concurrency + transcode/decode thread budgets"
```

---

## WS2 — Bundle crypto & upload orchestration (depends on WS1)

### Task 2.1: DTOs for bundle staging/preview

**Files:**
- Modify: `crates/client-app/src/dto.rs`
- Test: dto serde round-trip test in the same file

- [ ] **Step 1: Write the failing test** — a `StageBundleRequest { title, tags, members: Vec<BundleMemberInput> }` and `BundleMemberInput { kind: UploadKind, path?, content?, title, tags, options? }` and a `BundlePreview { job_id, member_previews: Vec<UploadPreview>, counts: MemberCounts }` all serde round-trip. `MemberCounts { video, image, blog, generic }`.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** the DTOs (mirror the existing `StageUploadRequest`/`UploadPreview` shapes in dto.rs; add `UploadKind::Generic`). Add `MemberCounts` + `member_counts` field to `CardDto` (default zeros, `#[serde(default)]`).

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(client): bundle staging + preview DTOs"`.

### Task 2.2: Generic upload prep (no transcode, streaming)

**Files:**
- Modify: `crates/client-app/src/upload.rs` (add `prepare_generic_streams` or route generic through the streaming path), `crates/client-app/src/commands/upload.rs` (`UploadKind::Generic` arm in `stage_upload`)
- Test: `crates/client-app/src/upload.rs` unit test

- [ ] **Step 1: Write the failing test** — `prepare_generic_metadata(filename, title, tags)` yields metadata JSON containing `{"filename":"itinerary.pdf", ...}`; and the generic stage path uses the streaming (disk-backed) sealer, not in-RAM (assert via a small integration in the command test, or unit-test the metadata builder).

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** — a `UploadKind::Generic` arm in `stage_upload` that: reads file metadata, rejects nothing on type, builds metadata JSON with the original `filename`, and reuses the **video streaming path** (`StreamingUploadBuilder` + `seal_from_reader` over the raw file) with `file_type = FileType::Generic` and no thumbnail/preview. Factor the streaming seal so both video and generic share it (DRY — extract the pass-1/finish block from the video arm into a helper taking an input path + optional small streams).

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(client): generic file upload via streaming path, filename in metadata"`.

### Task 2.3: `BundleJobs` registry + `stage_bundle`

**Files:**
- Modify: `crates/client-app/src/jobs.rs` (new `BundleJob`/`BundleJobs` holding a `Vec<StagedUpload>` + bundle title/tags + generated `bundle_id`), `crates/client-app/src/commands/upload.rs` (`stage_bundle` command), `crates/client-app/src/lib.rs`, `crates/client-app/src/main.rs`
- Test: `jobs.rs` unit test (insert/take round-trip, mirroring the existing `insert_then_take_round_trips`)

- [ ] **Step 1: Write the failing test** — insert a `BundleJob` with 2 staged members, retrieve it, assert member count + generated 16-byte `bundle_id` present.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** `BundleJob { bundle_id: [u8;16], title, tags, members: Vec<StagedUpload>, member_meta: Vec<MemberMeta> }` and `BundleJobs(Mutex<HashMap<String, BundleJob>>)`; register as Tauri managed state in `main.rs`. Implement `stage_bundle`: generate `bundle_id`; for each `BundleMemberInput`, run the same per-type staging as `stage_upload` (reuse the extracted helpers) but DO NOT insert into `UploadJobs`; collect into the `BundleJob`; compute `MemberCounts`; return `BundlePreview` (with a `member_previews` list reusing `UploadPreview` per member). No network.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(client): stage_bundle assembles staged members (no network)"`.

### Task 2.4: `confirm_bundle` — upload members then the bundle file

**Files:**
- Modify: `crates/client-app/src/commands/upload.rs` (`confirm_bundle`), reuse `run_pipeline`/`streaming_confirm`, `crate::upload`
- Test: covered by the e2e in WS9; add a focused unit test for the member-list content builder

- [ ] **Step 1: Write the failing test** — a pure helper `build_bundle_content(members: &[(Id, FileType)]) -> Vec<u8>` produces bytes that `decode::<BundleBody>` reads back in order (reuse Task 1.2). Test order preservation.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** `confirm_bundle(job_id)`:
  1. `reauth` once.
  2. For each staged member: POST `/v1/files` with `listed=false, bundle_id`, PUT chunks, finalize (reuse `run_pipeline`/`streaming_confirm`). Emit aggregate `UploadPhase` progress.
  3. Build the bundle content via `build_bundle_content` over the finalized member `(file_id, file_type)`s in order; build the bundle `UploadBundle` (in-RAM `build_upload`, `FileType::Bundle`, thumbnail = first visual member's thumbnail, metadata = bundle title/tags); POST `/v1/files` with `listed=true`; PUT; finalize.
  4. On success remove the `BundleJob`; emit `Done { file_id: bundle_id }`.
  5. On failure retain the job for retry; if the bundle file step failed after members uploaded, the members are `listed=false` (invisible) — retry re-posts only what's missing (idempotent).

- [ ] **Step 4: Run to verify** the content-builder test passes; full flow validated in WS9 e2e.

- [ ] **Step 5: Commit** — `git commit -m "feat(client): confirm_bundle uploads members then the signed bundle file"`.

### Task 2.5: `cancel_bundle` cascades member cleanup

**Files:**
- Modify: `crates/client-app/src/commands/upload.rs` (`cancel_bundle`)
- Test: unit test that cancel removes the `BundleJob` and issues member discards

- [ ] **Step 1–4:** TDD `cancel_bundle(job_id)`: drop the `BundleJob`; for any member already finalized on the server (tracked in the job), issue best-effort `DELETE /v1/files/{member}` (reuse `discard_server_orphan` pattern; finalized members need the new finalized-delete from Task 1.5). Members never uploaded need no server call. Test asserts the job is gone and delete requests are attempted for finalized members (use a recording stub or assert via the e2e in WS9 if a stub is impractical — then make this a step in the WS9 e2e instead).

- [ ] **Step 5: Commit** — `git commit -m "feat(client): cancel_bundle cascades cleanup of uploaded members"`.

---

## WS2b — (folded into WS2.2; generic upload) — no separate tasks

---

## WS3 — Feed & bundle viewing (depends on WS1; DTO from WS2.1)

### Task 3.1: `decrypt_card` computes bundle member counts

**Files:**
- Modify: `crates/client-app/src/commands/feed.rs` (`decrypt_card`)
- Test: feed.rs unit test for a count helper

- [ ] **Step 1: Write the failing test** — `histogram(&[FileType::Video, FileType::Image, FileType::Image]) == MemberCounts { video:1, image:2, blog:0, generic:0 }`.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** the `histogram` helper; in `decrypt_card`, when `manifest.file_type == FileType::Bundle`, additionally fetch+open the bundle content (small) via the existing bundle-open path (Task 3.2's `open_bundle_members`), `decode::<BundleBody>`, compute counts, set `CardDto.member_counts` + a `member_total`. Non-bundle cards leave counts zeroed. Cache the counts alongside the card in `content_cache`.

- [ ] **Step 4: Run to verify it passes.** PASS (unit for helper; integration in WS9).

- [ ] **Step 5: Commit** — `git commit -m "feat(client): bundle cards carry VID/IMG/TXT member counts"`.

### Task 3.2: `open_bundle` command

**Files:**
- Create: `crates/client-app/src/commands/bundle.rs`; declare in `lib.rs`, register in `main.rs`
- Modify: `crates/client-app/src/dto.rs` (`BundleView { members: Vec<BundleMemberView> }`, `BundleMemberView { file_id, file_type, title, thumbnail_b64 }`)
- Test: unit test for the member-list parse; full open in WS9

- [ ] **Step 1: Write the failing test** — given a verified `BundleBody`, `member_views_from_body` maps to `BundleMemberView`s in order with correct `file_type` strings.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** `open_bundle(file_id)`: run the standard verify+open (reuse the viewer's `open_content_inner` verify ladder) to decrypt the bundle content; `decode::<BundleBody>`; return `BundleView` with member ids + types (title/thumbnail filled lazily by the UI via `decrypt_card` per member, so `open_bundle` itself returns ids+types + an empty title/thumbnail, OR eagerly resolves each member header — choose lazy for Gallery speed). The member id passed to any subsequent per-member open MUST be the id from the signed `BundleBody` (content-substitution discipline).

- [ ] **Step 4: Run to verify it passes.** PASS (unit; integration WS9).

- [ ] **Step 5: Commit** — `git commit -m "feat(client): open_bundle returns the verified ordered member list"`.

### Task 3.3: `<bundle-screen>` with Gallery/Stacked toggle + remember-last

**Files:**
- Create: `crates/client-app/ui/src/components/bundle-screen.ts`
- Modify: `crates/client-app/ui/src/core/router.ts` (route `#/bundle/:id`), `crates/client-app/ui/src/core/settings-store.ts` (persist `bundleViewMode`), reuse `media-card.ts` + `media-viewer.ts`
- Test: `crates/client-app/ui/src/components/bundle-screen.test.ts` (structural, node:test + jsdom-lite as siblings do)

- [ ] **Step 1: Write the failing test** — mounting `<bundle-screen>` renders a mode toggle with two buttons (Gallery/Stacked), reads the persisted default, and in Gallery mode creates N `<media-card>`s for the returned members; switching to Stacked creates N viewer blocks. Assert `aria` roles + that switching persists the choice.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** the component: call `open_bundle`; render the toggle (default from `settings-store` `bundleViewMode`, first-ever = `gallery`); Gallery = grid of `<media-card file-id=… file-type=…>` (decrypt-on-tap, uses the WS7 pool); Stacked = for each member call the viewer-open flow and render inline in order. Persist the toggle choice on change. Keep templates static (a11y lint).

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): bundle screen with Gallery/Stacked toggle (remember-last)"`.

### Task 3.4: Feed card renders the bundle badge + counts

**Files:**
- Modify: `crates/client-app/ui/src/components/media-card.ts` (bundle badge + `VID n · IMG n · TXT n` strip; click routes to `#/bundle/:id`)
- Test: `media-card` test asserting a `bundle` card shows the badge + count strip and routes to the bundle screen

- [ ] **Step 1–4:** TDD the bundle branch in `media-card`: when `file-type === "bundle"`, show the purple `◆ BUNDLE` badge + counts (from `CardDto.member_counts`), and on click navigate to `#/bundle/:id` instead of the viewer. Generic cards show a file icon + filename and a Download action (WS5 wires the action).

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): media-card renders bundle badge + counts and routes to bundle screen"`.

---

## WS4 — Composer UI (depends on WS2 DTOs)

### Task 4.1: Bundle composer in `<upload-screen>`

**Files:**
- Modify: `crates/client-app/ui/src/components/upload-screen.ts` (add a "New bundle" mode), possibly split a `bundle-composer.ts`
- Test: `crates/client-app/ui/src/components/bundle-composer.test.ts`

- [ ] **Step 1: Write the failing test** — the composer supports: Add media (multi), Add text, a reorderable member list where ▲/▼ reorder and ✕ removes, per-member title inputs, and Preview gallery / Preview stacked buttons that call `stage_bundle` then render the two preview modes. Assert reorder via ▲/▼ changes DOM order; assert ✕ removes a row; assert keyboard-operability of the reorder buttons.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** the composer: local member list state; Add media opens the file dialog (multi-select) → each becomes a row with auto-detected type (image/video/blog/generic by extension/mime; unknown → generic); Add text inserts a text member with an inline editor; drag handle (pointer reorder) + ▲/▼ buttons + ✕; per-member title/tags; per-video transcode options (reuse `transcode-opts.ts`). Preview buttons call `stage_bundle` and mount `<bundle-screen>`-style previews over the staged (not-uploaded) members. Post bundle calls `confirm_bundle`. Keep templates static.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): bundle composer (add/reorder/remove/preview/post)"`.

---

## WS5 — Download (depends on WS1; independent of bundles for single posts)

### Task 5.1: `download_content` command

**Files:**
- Create: `crates/client-app/src/commands/download_cmd.rs` (name to avoid clashing with `download.rs`), declare in `lib.rs`, register in `main.rs`
- Modify: reuse the viewer open path + `commands/dialog.rs` for the save dialog
- Test: unit test for `suggested_filename(file_type, metadata)`

- [ ] **Step 1: Write the failing test** — `suggested_filename` returns `"<title>.png"` for image, `".mp4"` for video, `".txt"` for blog, and the original filename for generic (from metadata).

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** `download_content(file_id, save_path)`: open+verify+decrypt via the existing viewer ladder; for streaming types (video/generic) decrypt chunk-by-chunk writing to `save_path` (O(one chunk) RAM); for image/blog write the whole plaintext. Any wrap-holder may call it (open succeeds ⇒ authorized). Return the written path. Add `suggested_filename` used by the UI to prefill the save dialog.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(client): download_content writes the decrypted original to disk"`.

### Task 5.2: Download buttons (per-post + Download all)

**Files:**
- Modify: `crates/client-app/ui/src/components/media-viewer.ts` (Download button, any viewer), `media-card.ts` (generic card Download), `bundle-screen.ts` (Download all)
- Test: viewer + bundle-screen tests assert the buttons exist and invoke `download_content` (mock rpc)

- [ ] **Step 1–4:** TDD: a Download button on every `<media-viewer>` that opens a save dialog then calls `download_content`; the generic card's Download action; a "Download all" on `<bundle-screen>` that picks a folder and downloads each member (filenames from metadata; de-dup collisions with ` (2)` suffixes). Assert calls via a mocked `call`.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): per-post Download + bundle Download-all"`.

---

## WS6 — Delete (depends on WS1.5)

### Task 6.1: `delete_content` command

**Files:**
- Create/modify: `crates/client-app/src/commands/` (add `delete_content`), declare/register
- Test: unit test for request validation (rejects malformed id); full delete in WS9

- [ ] **Step 1: Write the failing test** — `delete_content` with a malformed hex id returns a `bad_request`/`fetch_failed` error before any network.

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** `delete_content(file_id)`: validate id via `hex16`; `reauth`; `DELETE /v1/files/{file_id}`; map `204`→Ok, `404`→`not_found`/`forbidden` (sanitized), other→`delete_failed`. Server cascades bundle members. On success, invalidate the retained feed views + content cache entries for the id.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(client): delete_content removes an owned post/bundle"`.

### Task 6.2: Delete button + confirm dialog

**Files:**
- Modify: `crates/client-app/ui/src/components/media-viewer.ts` + `bundle-screen.ts` (owner-only Delete), reuse the toast/dialog + `BehaviorSettings.confirm_destructive`
- Test: viewer test — Delete shows only when `mine`, requires confirm, calls `delete_content`, then navigates back + invalidates feed

- [ ] **Step 1–4:** TDD: Delete button gated on `mine`/owner; a confirm dialog surfacing "permanent" + "copies others already downloaded cannot be reached"; on confirm call `delete_content`, toast, navigate to feed, force a feed refresh (clear retained view). Respect `confirm_destructive` setting.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): owner-only Delete with confirm + caveat"`.

---

## WS7 — Parallel decode + thread wiring (depends on WS1.6)

### Task 7.1: `decodePool` bounded-concurrency runner

**Files:**
- Create: `crates/client-app/ui/src/core/pool.ts`
- Test: `crates/client-app/ui/src/core/pool.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// At most `size` tasks run concurrently; all resolve; cancelPending rejects queued.
test("pool runs at most N concurrently and drains", async () => {
  const pool = makePool(2);
  let active = 0, maxActive = 0;
  const mk = () => pool.run(async () => {
    active++; maxActive = Math.max(maxActive, active);
    await new Promise(r => setTimeout(r, 10));
    active--; return "ok";
  });
  await Promise.all([mk(), mk(), mk(), mk()]);
  assert.ok(maxActive <= 2);
});
```

- [ ] **Step 2: Run to verify it fails** — from `crates/client-app/ui/`: `node --test src/core/pool.test.ts` (or the repo's test runner). FAIL.

- [ ] **Step 3: Implement** `makePool(size)` with `.run(task)`, a priority lane (`runPriority` bypasses the semaphore for viewer-open), and `cancelPending()` rejecting queued-not-started tasks with the existing `CancelledError`. Read `feed_concurrency` from settings to size it.

- [ ] **Step 4: Run to verify it passes.** PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): bounded decodePool for parallel card decode"`.

### Task 7.2: Route feed-card decodes through the pool

**Files:**
- Modify: `crates/client-app/ui/src/components/feed-screen.ts` + `media-card.ts` (use `decodePool.run` instead of `serial`), keep `serialPriority` semantics for viewer-open via `runPriority`
- Test: update `card-retry.test.ts`/feed tests; assert concurrent decode + that leaving the feed cancels queued jobs

- [ ] **Step 1–4:** TDD: cards decode via the pool sized from `feed_concurrency`; viewer-open uses the priority lane; `disconnectedCallback` cancels queued. Verify backend tolerates concurrency (it does — `reauth` is lock-free; identity borrow is brief) by an e2e in WS9.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): feed decodes cards in parallel via decodePool"`.

### Task 7.3: Wire transcode/decode thread budgets

**Files:**
- Modify: `crates/client-app/src/commands/upload.rs` (pass `transcode_threads` to the video prep → ffmpeg `-threads` + encoder), the confined decode worker launch (`decode_threads`), and any parallel per-chunk crypto
- Test: unit — the ffmpeg arg builder includes `-threads N`

- [ ] **Step 1–4:** TDD the transcode arg builder to include `-threads <transcode_threads>`; thread `decode_threads` into the decode worker spawn (rav1d thread count) — read `SettingsConfig` at `stage_upload`/`open_video`. Where a value flows into a confined worker, pass it as an argument (not an env var) consistent with the existing launcher.

- [ ] **Step 5: Commit** — `git commit -m "feat(client): honor transcode/decode thread-budget settings"`.

### Task 7.4: Settings-screen controls for the three knobs

**Files:**
- Modify: `crates/client-app/ui/src/components/settings-screen.ts`, `core/settings.ts`, `a11y.test.ts`
- Test: settings-screen test — the three controls render, clamp, and persist

- [ ] **Step 1–4:** TDD three labeled controls (feed concurrency 1–8; transcode threads 1–cores; decode threads 1–cores) with the physical-core max surfaced; persist via `set_settings`; keep them in the a11y structural lint.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): settings controls for concurrency + thread budgets"`.

---

## WS8 — Bundle sharing (depends on WS2 + WS3)

### Task 8.1: `reshare_bundle` fan-out

**Files:**
- Modify: `crates/client-app/src/commands/share.rs` (add `reshare_bundle`), reuse `reshare_inner`/`run_reshare_batch`
- Modify: `crates/client-app/ui/src/components/share-dialog.ts` (detect a bundle target → share fans out)
- Test: unit — enumerating members from a `BundleView` yields the bundle id + all member ids as the reshare target set

- [ ] **Step 1: Write the failing test** — `bundle_share_targets(bundle_id, &BundleView)` returns `[bundle_id, m1, m2, …]` (bundle first).

- [ ] **Step 2: Run to verify it fails.** FAIL.

- [ ] **Step 3: Implement** `reshare_bundle(bundle_id, recipients)`: `open_bundle` to get the verified member list; run the existing per-recipient fail-isolated reshare over the bundle file + each member; aggregate outcomes. UI: when the share target is a bundle, call `reshare_bundle`; show aggregate progress.

- [ ] **Step 4: Run to verify it passes.** PASS (unit; integration WS9).

- [ ] **Step 5: Commit** — `git commit -m "feat(client): reshare_bundle shares the bundle and all its members"`.

---

## WS9 — End-to-end tests + security review (depends on all)

### Task 9.1: Bundle lifecycle e2e

**Files:**
- Create: `crates/client-app/tests/bundle_e2e.rs` (mirror `upload_e2e.rs`/`browse_view_e2e.rs` harness over real TLS)

- [ ] **Steps:** create a 3-member bundle (video/image/generic) → assert `GET /v1/files` lists the bundle but NOT the members → `open_bundle` returns members in order and each member verifies+decrypts → download a member (bytes identical to source) → `reshare_bundle` to a second user who can then open it → owner `delete_content(bundle)` → assert bundle + all members gone from listing and blobs purged; non-owner delete of a file → 404. Commit.

### Task 9.2: Generic + download + parallel-decode e2e

**Files:**
- Create: `crates/client-app/tests/generic_download_parallel_e2e.rs`

- [ ] **Steps:** generic upload → download → byte-identical roundtrip; feed with N items decodes correctly with `feed_concurrency>1` (results correct, no identity race — assert all cards resolve with expected titles). Commit.

### Task 9.3: Security review sign-off

**Files:**
- Create: `docs/security-review-bundles.md`

- [ ] **Steps:** review + document: (1) the new destructive server endpoint — owner-auth (no oracle), cascade correctness, cold-tier purge, no cross-owner deletion; (2) bundle content-verify path — member list under the signed manifest digest, requested-id discipline for members, server `listed`/`bundle_id` treated as untrusted; (3) concurrency — no identity/DEK race, seam still DTO-only, pool cancellation safe. Record PASS/finding list. Commit.

---

## Self-review notes (author)

- **Spec coverage:** model coexistence (WS1.3/1.4/3.4), server-visible membership (WS1.3/1.4), signed member list (WS1.2/2.4/3.2), two view modes + remember-last (WS3.3), composer reorder/remove/preview + per-member title + per-video opts (WS4.1), generic download-only + filename (WS2.2/5.x), download any-viewer + download-all (WS5), owner-only permanent delete + cascade + cold-tier (WS1.5/6), parallel decode + 3 configurable knobs incl. cores (WS1.6/7), bundle sharing (WS8), tests + sign-off (WS9). All spec sections map to a task.
- **Placeholder scan:** where full code depends on unread store internals (WS1.3–1.5) or large UI siblings (WS3/4/5), the task gives the exact contract + test + the sibling file to match; these are dispatched to subagents that read those files during TDD. No `TODO`/`TBD` left as behavior.
- **Type consistency:** `BundleBody`/`BundleMember` (1.2) reused by 2.4/3.2; `MemberCounts` (2.1) produced by 3.1 and rendered by 3.4; `feed_concurrency`/`transcode_threads`/`decode_threads` (1.6) consumed by 7.1/7.3/7.4; `delete_file` (1.5) called by 6.1; `open_bundle`/`BundleView` (3.2) consumed by 3.3/5.2/8.1.
