# MaxSecu Media App — Phase 4: Upload — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the create-a-post upload pipeline — choose + describe (title/tags/type) → **preview-before-upload confirm** → transcode (image) → encrypt (`client-core::build_upload`, self + recovery recipients) → **resumable** chunked staged upload with per-stage progress/ETA/retry → finalize — surfaced through an Upload screen and an active-uploads tray, with an e2e that uploads an image and a blog from the **real client** over real TLS and reads them back.

**Architecture:** Phase 4 introduces **no new server crypto and no new server endpoints** — it drives the existing `POST /v1/files` (stage v1), idempotent `PUT …/chunks/{i}`, and `POST …/finalize`. The `client-app` backend transcodes the user's own chosen file (images via the pure-Rust `RustImageCodec`; blogs are sanitized text), writes metadata as the JSON `{"title","tags"}` form the Phase-3 viewer reads, calls `client-core::build_upload` (which wraps to **self + the standing recovery recipient**, owner-only write D29), then stages + uploads + finalizes over the channel-bound connection, emitting a typed `UploadPhase` state machine. Preview-before-upload means `build_upload` runs and the bundle is held in a job registry **before** any network write; the user confirms, then the pipeline uploads. The UI stays outside the TCB — it sends a chosen file path + metadata and receives progress/preview DTOs; it never sees keys, the DEK, wraps, or grant interiors.

**Tech Stack:** Rust (Tauri command boundary, `hyper` over the pinned TLS 1.3 transport), `maxsecu-client-core` (`build_upload`, `UploadParams`, `PlaintextStreams`, `RustImageCodec`/`Transcoder`/`MediaBounds`, `DirectoryVerifier`), `maxsecu-encoding`/`maxsecu-crypto`, vanilla TS + Web Components, the existing `MemoryStore`/`FsBlobStore` e2e harness (no Postgres).

---

## Backend facts this plan is grounded in (read before coding)

- **`client-core::build_upload`** (`crates/client-core/src/upload.rs`, re-exported): `build_upload(&UploadParams, &PlaintextStreams) -> Result<UploadBundle, UploadError>`. Wraps to **self + recovery** (the only two recipients; multi-recipient sharing is out of scope for this phase — see §Deferred). `UploadParams { owner: &Identity, owner_id: Id, owner_key_version: u64, file_id: Id, file_type: FileType, chunk_size: u32 (4 KiB–8 MiB), recovery_pub: EncPublicKey, recovery_mlkem_pub: Option<[u8;1184]>, created_at: Timestamp }`. `PlaintextStreams { content: Vec<u8>, metadata: Option<Vec<u8>>, thumbnail: Option<Vec<u8>>, preview: Option<Vec<u8>> }`. `UploadBundle { file_id, file_type, genesis, genesis_sig:[u8;64], manifest, manifest_sig:[u8;64], streams: Vec<SealedStreamOut>, wraps: Vec<WrapOut> }`. `SealedStreamOut { stream_type, compression, chunk_size, chunk_count, digest, total_bytes, chunks: Vec<Vec<u8>> }`. `WrapOut { recipient_id, recipient_type, wrapped_dek: WrappedDek, granted_by, grant: Grant, grant_sig:[u8;64] }`. Wire wrap form is `enc(32) ‖ ct` (`file_e2e.rs::wrap_bytes`).
- **Image transcode** (`crates/client-core/src/media.rs`, re-exported): `RustImageCodec.transcode(&src_bytes, &MediaBounds::default()) -> Result<CanonicalStreams, TranscodeError>` (via the `Transcoder` trait); `CanonicalStreams { file_type: FileType, content: Vec<u8>, ... }` with `.into_plaintext_streams(metadata: Option<Vec<u8>>) -> PlaintextStreams` (sets content + thumbnail + preview from the canonical transcode and attaches the given metadata). See `file_e2e.rs::phase4b_media_exit_gates_over_real_tls` for the exact usage (JPEG source → canonical PNG content + thumb + preview). Transcoding the **user's own chosen file** is the upload path; the sandboxed-decode concern (`docs/media-sandbox.md`) is about *downloaded untrusted* bytes (Phase 4b), not the uploader's own file.
- **Server stage/upload/finalize** (`crates/server/src/http.rs`, all authed `AuthedSession`, owner-only):
  - `POST /v1/files` (`create_file`): body `{ file_id: hex, file_type: "image"|"blog", genesis_b64, genesis_sig_b64, manifest_b64, manifest_sig_b64, streams: [{ stream_type, chunk_count, chunk_size, total_bytes }], wraps: [{ recipient_id (hex or "recovery"), recipient_type ("user"|"recovery"), wrapped_dek_b64, wrap_alg (1), granted_by (hex), grant_b64, grant_sig_b64 }] }` → `201 { upload_token, version }`. `400` malformed/inconsistent; `413` size bound; `403` non-owner; `409` already finalized.
  - `PUT /v1/files/{id}/versions/{v}/streams/{stream_type}/chunks/{i}` (raw octet body): `200` ok; **idempotent by index** (re-PUT is safe → resumable); `403` non-owner; `404` no such stream; `409` finalized; `413` index past framing or oversized chunk.
  - `POST /v1/files/{id}/versions/{v}/finalize`: verifies each staged stream holds exactly its `chunk_count` chunks → `200`; `400` incomplete stream; `404` no such version; `409` conflict/finalized.
- **Resumability:** the server has no "which chunks present" endpoint; PUT is idempotent by index, so the client tracks its own per-chunk progress and re-PUTs failed/missing indices (retry with backoff). `finalize` is the completeness gate.
- **Directory (recovery recipient + author):** `GET /v1/directory/by-id/{id}` / `/{username}` → `{ binding_b64, directory_signature_b64 }`; re-verified under the pinned D5 via `client-app::directory` (Phase 3). The standing **recovery recipient**'s `enc_pub` (+ optional ML-KEM) is resolved this way.
- **Reuse from Phases 1–3 (do NOT reimplement):** `commands::connection::{open_conn, reauth(dir,&server,&session,&connect_lock)->(sender,host,token), server_of(dir)}`; `http_client::{post_json,get_json,get_bytes}(sender,uri,[body,]bearer,host)` (4-arg/5-arg); `config::load_directory_pub`; `directory::{resolve_and_verify_author, resolve_my_user_id, verify_author_binding, VerifiedAuthor}`; `download::wrap` helpers pattern; the `FetchPhase`/`serial()`/`state-badge`/`progress-meter` feedback layer; `commands::auth::{AppDir, Session, ConnectLock}`; `error::UiError`. UI: `core/{rpc,router,serial,types}.ts`, `app-shell.ts`. The Phase-3 e2e `crates/client-app/tests/browse_view_e2e.rs` + `crates/server/tests/file_e2e.rs` show the full stage→PUT→finalize→GET→verify flow to mirror.

## Environment (tell every subagent)

- **cargo is NOT on the tool PATH.** Prefix every shell command: bash `export PATH="$HOME/.cargo/bin:$PATH"; ` / PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; `. Rust 1.96 MSVC.
- **No PostgreSQL.** `MAXSECU_PG_OPTIONAL=1` for the workspace test; e2e uses MemoryStore + FsBlobStore.
- **Tauri GUI not available** — verify via `cargo build`/`tsc`/`npm run build`/e2e only.
- **fmt:** `client-app` + `ui` are kept fmt-clean (`cargo fmt -p maxsecu-client-app -- --check`); `client-core`/`server` carry pre-existing Phase 0–7 drift (OUT OF SCOPE — never `cargo fmt --all`; if you touch client-core, match the in-file style).
- **clippy:** `cargo clippy -p <crate> --all-targets -- -D warnings`, no blanket `#[allow]`.
- **deny/audit:** `ring`/`openssl` banned; no new external prod deps expected (`image` is already a dev-dep from Phase 3; `RustImageCodec` is in client-core already).
- **Known flake (NOT yours):** media-worker `containment_windows` under parallel `cargo test --workspace`.

## Security model for Phase 4 (honor exactly)

- **Owner-only, self+recovery.** `build_upload` signs as the owner and wraps only to self + the directory-resolved recovery recipient — exactly the existing core. No new wrap path.
- **The recovery recipient is directory-verified** under the pinned D5 before its `enc_pub` is used as a wrap target (a forged recovery binding must not become a recipient).
- **Preview-before-upload** runs `build_upload` and holds the bundle in the in-process job registry (TCB); nothing is written to the server until the user confirms. The plaintext source bytes and the bundle never cross the Tauri seam — the UI gets only a preview DTO (title, type, byte size, a thumbnail) and progress events.
- **UI outside the TCB:** the UI passes a chosen file path + metadata (title/tags/type) and receives preview/progress DTOs. It never receives the DEK, wraps, grants, manifest/genesis interiors, or the identity. The owner's unlocked identity is borrowed under the session lock for the synchronous `build_upload`, never `take()`n across an await.
- **Sanitized errors / fail-closed:** transcode/stage/PUT/finalize failures surface sanitized `UiError` codes (no oracle, no path/crypto detail). A path the user chose is read into RAM bounded by the existing media bounds; an oversized/over-bound input is rejected before encryption.

---

## File structure

```
crates/client-app/src/
  config.rs        MODIFY — recovery_recipient_username() (reads <dir>/config/recovery_recipient.txt).
  directory.rs     MODIFY — resolve_recovery_recipient(sender, host, username, &verifier, &mut trust, now)
                            -> RecoveryRecipient { enc_pub:[u8;32], mlkem_pub: Option<[u8;1184]> }.
  upload.rs        NEW — metadata JSON builder; transcode/streams prep; the stage→PUT(resumable,
                          progress)→finalize pipeline over a sender; request-body shaping (streams/wraps).
  state.rs         MODIFY — UploadPhase typed state machine + EVT_UPLOAD.
  jobs.rs          NEW — UploadJobs managed state (job_id -> staged UploadBundle + meta, pre-confirm).
  dto.rs           MODIFY — UploadKind, StageUploadRequest, UploadPreview, ConfirmUploadRequest,
                            CancelUploadRequest, UploadJobView.
  commands/upload.rs   NEW — stage_upload (transcode+build_upload+preview, no network),
                              confirm_upload (run the pipeline, emit UploadPhase), cancel_upload,
                              upload_jobs (list).
  commands/mod.rs  MODIFY — pub mod upload;
  lib.rs           MODIFY — pub mod upload; pub mod jobs;
  main.rs          MODIFY — manage UploadJobs; register the new commands.
  ui/src/core/types.ts          MODIFY — UploadKind/UploadPreview/UploadMsg TS mirrors.
  ui/src/components/upload-screen.ts  NEW — choose+describe → preview → confirm.
  ui/src/components/upload-tray.ts    NEW — active uploads: per-stage progress/ETA/retry (EVT_UPLOAD).
  ui/src/components/app-shell.ts MODIFY — Upload nav → <upload-screen>; mount <upload-tray> in the shell.
  ui/src/core/router.ts          MODIFY — add "upload" route.
crates/client-app/tests/
  upload_e2e.rs    NEW — the Phase-4 exit gate: client uploads an image + a blog over real TLS, finalizes,
                          GET round-trips + verifies the exact plaintext; a dropped chunk is resumed.
docs/
  security-review-phase4-mediaapp.md  NEW — Phase-4 sign-off.
```

---

## Task 1: Recovery-recipient config + directory resolution

**Files:** Modify `crates/client-app/src/config.rs`, `crates/client-app/src/directory.rs`.

The upload wraps to the standing recovery recipient; the client resolves its directory-verified `enc_pub` under the pinned D5. The recovery recipient is identified by a configured username (`<dir>/config/recovery_recipient.txt`, one line).

- [ ] **Step 1: config accessor (failing test)** — add to `config.rs` tests:

```rust
    #[test]
    fn recovery_recipient_username_reads_config() {
        let tmp = std::env::temp_dir().join(format!("mxcfg-rr-{}", n()));
        std::fs::create_dir_all(tmp.join("config")).unwrap();
        assert_eq!(recovery_recipient_username(&tmp).unwrap_err().code, "no_recovery_recipient");
        std::fs::write(tmp.join("config").join("recovery_recipient.txt"), "  recovery-1\n").unwrap();
        assert_eq!(recovery_recipient_username(&tmp).unwrap(), "recovery-1");
        let _ = std::fs::remove_dir_all(&tmp);
    }
```

- [ ] **Step 2: implement** in `config.rs`:

```rust
/// The configured standing **recovery recipient** username (`<dir>/config/
/// recovery_recipient.txt`, one line, trimmed). The upload resolves its
/// directory-verified `enc_pub` as the mandatory recovery wrap target (§6.3).
pub fn recovery_recipient_username(dir: &std::path::Path) -> Result<String, UiError> {
    let path = dir.join("config").join("recovery_recipient.txt");
    let raw = std::fs::read_to_string(&path)
        .map_err(|_| UiError::new("no_recovery_recipient", "No recovery recipient is configured."))?;
    let name = raw.trim();
    if name.is_empty() {
        return Err(UiError::new("no_recovery_recipient", "No recovery recipient is configured."));
    }
    Ok(name.to_owned())
}
```

- [ ] **Step 3: directory resolver (failing test)** — add to `directory.rs` tests a unit test that a recovery binding (User role, with an enc_pub) verifies + extracts `enc_pub`/`mlkem_pub`. Reuse the existing `signed_binding`/`SigningKey` test helpers; assert `resolve` of a locally-signed binding yields the enc_pub (factor the pure part like `verify_author_binding`).

- [ ] **Step 4: implement** in `directory.rs`:

```rust
/// A directory-verified recovery recipient: the wrap-target keys only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecipient {
    pub enc_pub: [u8; 32],
    pub mlkem_pub: Option<[u8; 1184]>,
}

/// Resolve + D5-verify the configured recovery recipient by username
/// (`GET /v1/directory/{username}`). Fail-closed `untrusted` if unpublished/forged.
pub async fn resolve_recovery_recipient(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    username: &str,
    verifier: &DirectoryVerifier,
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<RecoveryRecipient, UiError> {
    let (status, json) = get_json(sender, &format!("/v1/directory/{username}"), None, host).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("untrusted", "The recovery recipient is not published."));
    }
    let (bytes, sig) = parse_binding(&json)?;
    // verify_binding gives us enc_pub + mlkem_pub directly.
    let binding: maxsecu_encoding::structs::DirBinding =
        maxsecu_encoding::decode(&bytes).map_err(|_| UiError::new("untrusted", "Malformed directory record."))?;
    let v = verifier
        .verify_binding(&binding, &sig, now_ms, trust)
        .map_err(|_| UiError::new("untrusted", "The recovery recipient could not be verified."))?;
    Ok(RecoveryRecipient { enc_pub: v.enc_pub, mlkem_pub: v.mlkem_pub })
}
```

(`VerifiedBinding` carries `enc_pub` + `mlkem_pub` — confirm in `client-core/src/directory.rs`.)

- [ ] **Step 5:** `cargo test -p maxsecu-client-app config:: directory::` ; `cargo build -p maxsecu-client-app` ; fmt/clippy clean.
- [ ] **Step 6: commit** `feat(client-app): recovery-recipient config + D5 resolution`.

---

## Task 2: Upload prep — metadata JSON + transcode/streams

**Files:** Create `crates/client-app/src/upload.rs` (first half); Modify `lib.rs` (`pub mod upload;`).

Pure helpers: build the metadata JSON (the form `parse_title_tags` reads), and turn a chosen file's bytes + kind into `PlaintextStreams` (image → `RustImageCodec` transcode; blog → text content + metadata).

- [ ] **Step 1: failing tests** in `upload.rs`:

```rust
//! Upload preparation + pipeline (DESIGN §12.2). Transcodes the user's OWN chosen
//! file (images via the pure-Rust codec; blogs are sanitized text), writes metadata
//! as the JSON {"title","tags"} form the viewer reads, builds the signed/encrypted
//! bundle via client-core, then stages + resumably uploads + finalizes. Only
//! preview/progress DTOs cross the Tauri seam — never keys/wraps/plaintext.

use maxsecu_client_core::{PlaintextStreams, RustImageCodec, Transcoder, MediaBounds};
use maxsecu_encoding::types::FileType;
use crate::error::UiError;

/// Build the canonical metadata blob: JSON `{"title","tags"}` (UTF-8).
pub(crate) fn build_metadata(title: &str, tags: &[String]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "title": title, "tags": tags })).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrips_through_parse_title_tags() {
        let meta = build_metadata("Sunset", &["beach".into(), "2026".into()]);
        // The viewer's parser must read it back.
        let (t, tags) = crate::commands::feed::parse_title_tags(&meta);
        assert_eq!(t, "Sunset");
        assert_eq!(tags, vec!["beach".to_owned(), "2026".to_owned()]);
    }

    #[test]
    fn blog_streams_carry_content_and_metadata() {
        let s = prepare_blog_streams(b"hello world".to_vec(), "T", &[]);
        assert_eq!(s.content, b"hello world");
        assert!(s.metadata.is_some());
        assert!(s.thumbnail.is_none());
    }
}
```

- [ ] **Step 2: implement** the prep:

```rust
/// Blog: content is the (already sanitized by the caller / plain) UTF-8 bytes;
/// metadata is the JSON title/tags; no thumbnail/preview.
pub(crate) fn prepare_blog_streams(content: Vec<u8>, title: &str, tags: &[String]) -> PlaintextStreams {
    PlaintextStreams { content, metadata: Some(build_metadata(title, tags)), thumbnail: None, preview: None }
}

/// Image: transcode the user's chosen bytes to canonical streams (content +
/// thumbnail + preview), then attach the metadata JSON. Fail-closed on a bad image.
pub(crate) fn prepare_image_streams(src: &[u8], title: &str, tags: &[String]) -> Result<(FileType, PlaintextStreams), UiError> {
    let canonical = RustImageCodec
        .transcode(src, &MediaBounds::default())
        .map_err(|_| UiError::new("bad_image", "That image could not be processed."))?;
    let file_type = canonical.file_type;
    let streams = canonical.into_plaintext_streams(Some(build_metadata(title, tags)));
    Ok((file_type, streams))
}
```

- [ ] **Step 3:** `cargo test -p maxsecu-client-app upload::tests` (needs `pub mod upload;` in lib.rs); build; fmt/clippy clean.
- [ ] **Step 4: commit** `feat(client-app): upload prep (metadata JSON + image transcode/streams)`.

---

## Task 3: Upload pipeline — stage → resumable PUT → finalize

**Files:** Modify `crates/client-app/src/upload.rs` (second half).

The transport pipeline over an authenticated sender: POST `/v1/files` (stage), PUT every chunk with a progress callback + per-chunk retry (idempotent → resumable), POST finalize.

- [ ] **Step 1: failing test** — the request-body shaper is pure/testable. Add a test that `stage_body(&bundle)` produces a JSON with `file_id`, `file_type`, `streams[]` (with stream_type/chunk_count/chunk_size/total_bytes), and `wraps[]` (recipient_id/recipient_type/wrapped_dek_b64/grant_b64/grant_sig_b64) matching the `file_e2e.rs` shape. Build a tiny `UploadBundle` via `build_upload` (reuse a generated identity + generated recovery keypair, like the client-core download tests) and assert the shaped JSON's structure.

- [ ] **Step 2: implement** `stage_body` + the pipeline:

```rust
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hyper::client::conn::http1::SendRequest;
use http_body_util::Full;
use hyper::body::Bytes;

use maxsecu_client_core::{UploadBundle, WrapOut};
use maxsecu_encoding::encode;
use maxsecu_encoding::types::{RecipientType, StreamType};
use crate::http_client::{get_bytes, post_json};

fn stream_name(s: StreamType) -> &'static str { /* content/metadata/thumbnail/preview */ }
fn wrap_wire(w: &WrapOut) -> Vec<u8> { let mut v = w.wrapped_dek.enc.to_vec(); v.extend_from_slice(&w.wrapped_dek.ct); v }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// Shape the §8.1 `POST /v1/files` JSON body from a built bundle.
pub(crate) fn stage_body(b: &UploadBundle) -> serde_json::Value {
    let streams: Vec<_> = b.streams.iter().map(|s| serde_json::json!({
        "stream_type": stream_name(s.stream_type), "chunk_count": s.chunk_count,
        "chunk_size": s.chunk_size, "total_bytes": s.total_bytes,
    })).collect();
    let wraps: Vec<_> = b.wraps.iter().map(|w| {
        let rid = if w.recipient_type == RecipientType::Recovery { "recovery".to_owned() } else { hex(&w.recipient_id.0) };
        serde_json::json!({
            "recipient_id": rid,
            "recipient_type": if w.recipient_type == RecipientType::Recovery { "recovery" } else { "user" },
            "wrapped_dek_b64": B64.encode(wrap_wire(w)), "wrap_alg": 1,
            "granted_by": hex(&w.granted_by.0),
            "grant_b64": B64.encode(encode(&w.grant)), "grant_sig_b64": B64.encode(w.grant_sig),
        })
    }).collect();
    serde_json::json!({
        "file_id": hex(&b.file_id.0), "file_type": match b.file_type { FileType::Image => "image", FileType::Blog => "blog", FileType::Video => "video" },
        "genesis_b64": B64.encode(encode(&b.genesis)), "genesis_sig_b64": B64.encode(b.genesis_sig),
        "manifest_b64": B64.encode(encode(&b.manifest)), "manifest_sig_b64": B64.encode(b.manifest_sig),
        "streams": streams, "wraps": wraps,
    })
}

/// Total ciphertext chunks across all streams (for progress denominators).
pub(crate) fn total_chunks(b: &UploadBundle) -> u64 { b.streams.iter().map(|s| s.chunk_count).sum() }

/// Stage → PUT every chunk (idempotent; retried up to `MAX_RETRY` per chunk) →
/// finalize. `on_progress(done, total)` is called after each successful chunk PUT.
/// Fail-closed sanitized errors. `host`/`token` from `reauth`.
pub(crate) async fn run_pipeline<F: FnMut(u64, u64)>(
    sender: &mut SendRequest<Full<Bytes>>, host: &str, token: &str,
    bundle: &UploadBundle, mut on_progress: F,
) -> Result<(), UiError> {
    let fid = hex(&bundle.file_id.0);
    let (st, _res) = post_json(sender, "/v1/files", &stage_body(bundle), Some(token), host).await?;
    if st != hyper::StatusCode::CREATED {
        return Err(UiError::new("stage_failed", "Could not start the upload."));
    }
    let total = total_chunks(bundle);
    let mut done = 0u64;
    for s in &bundle.streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            put_chunk_retried(sender, host, token, &fid, s.stream_type, i as u64, chunk).await?;
            done += 1;
            on_progress(done, total);
        }
    }
    let (st, _res) = post_json(sender, &format!("/v1/files/{fid}/versions/1/finalize"), &serde_json::Value::Null, Some(token), host).await?;
    if st != hyper::StatusCode::OK {
        return Err(UiError::new("finalize_failed", "Could not finalize the upload."));
    }
    Ok(())
}
```

Add `put_chunk_retried` (a raw PUT via a new `http_client::put_bytes(sender, uri, body, token, host) -> StatusCode` — add that helper mirroring `get_bytes`, sending `application/octet-stream`; retry on a transport error or non-200 up to `MAX_RETRY=3` with a short backoff; resumability is free because PUT is idempotent by index). `200` on each.

- [ ] **Step 3:** add `http_client::put_bytes`; build; `cargo test -p maxsecu-client-app upload::` (the stage_body test passes); fmt/clippy clean.
- [ ] **Step 4: commit** `feat(client-app): upload pipeline (stage, resumable chunk PUT, finalize)`.

---

## Task 4: `UploadPhase` state machine + EVT_UPLOAD

**Files:** Modify `crates/client-app/src/state.rs`.

- [ ] **Step 1: failing test** (kebab-tagged, mirrors `FetchPhase`):

```rust
pub const EVT_UPLOAD: &str = "maxsecu://upload-state";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum UploadPhase {
    Transcoding { job_id: String },
    Encrypting { job_id: String },
    Staging { job_id: String },
    Uploading { job_id: String, done: u64, total: u64 },
    Finalizing { job_id: String },
    Done { job_id: String, file_id: String },
    Failed { job_id: String, code: String },
}

#[cfg(test)]
mod upload_phase_tests {
    use super::*;
    #[test] fn serializes_kebab_tagged() {
        let s = serde_json::to_string(&UploadPhase::Uploading { job_id: "j".into(), done: 2, total: 5 }).unwrap();
        assert!(s.contains("\"phase\":\"uploading\"") && s.contains("\"done\":2"));
    }
}
```

- [ ] **Step 2:** `cargo test -p maxsecu-client-app state::upload_phase_tests`; commit `feat(client-app): UploadPhase feedback state machine`.

---

## Task 5: Upload jobs registry (managed state)

**Files:** Create `crates/client-app/src/jobs.rs`; Modify `lib.rs`, `main.rs`.

Holds staged-but-not-confirmed uploads (preview-before-upload): `job_id -> StagedUpload { bundle: UploadBundle, kind, title }`. A `tokio::Mutex<HashMap<String, StagedUpload>>`.

- [ ] **Step 1:** write `jobs.rs` with `UploadJobs(pub Mutex<HashMap<String, StagedUpload>>)`, `StagedUpload { pub bundle: UploadBundle, pub file_type: String, pub title: String, pub total_chunks: u64, pub byte_size: u64 }`, `impl UploadJobs { new(); }` (+ `Default`). A unit test that insert/remove by job_id round-trips a dummy entry is sufficient (construct a real bundle via build_upload, or test the map mechanics with a minimal struct). Add `pub mod jobs;` to lib.rs.
- [ ] **Step 2:** `main.rs` `.manage(UploadJobs::new())`.
- [ ] **Step 3:** build/test; commit `feat(client-app): upload jobs registry (pre-confirm staging)`.

---

## Task 6: `stage_upload` command (transcode + build_upload + preview, NO network)

**Files:** Create `crates/client-app/src/commands/upload.rs`; Modify `dto.rs`, `commands/mod.rs`, `main.rs`.

Reads the chosen file from `path`, transcodes/prepares streams, resolves the recovery recipient under the pinned D5, generates a random `file_id`, runs `build_upload` (identity borrowed UNDER the session lock across the synchronous build), stores the bundle in `UploadJobs`, and returns an `UploadPreview` — **no network write yet**.

- [ ] **Step 1: DTOs** in `dto.rs`:

```rust
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UploadKind { Image, Blog }

#[derive(Debug, Clone, Deserialize)]
pub struct StageUploadRequest { pub kind: UploadKind, pub path: String, pub title: String, #[serde(default)] pub tags: Vec<String> }

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UploadPreview { pub job_id: String, pub file_type: String, pub title: String, pub tags: Vec<String>, pub byte_size: u64, pub total_chunks: u64, pub thumbnail_b64: Option<String> }

#[derive(Debug, Clone, Deserialize)]
pub struct ConfirmUploadRequest { pub job_id: String }
#[derive(Debug, Clone, Deserialize)]
pub struct CancelUploadRequest { pub job_id: String }
```

- [ ] **Step 2: command** (read the chosen file with a size bound; blog path reads UTF-8 text; image path reads bytes → transcode). `file_id = Id(random_array::<16>())`. `owner_id` = the session's resolved `user_id` (resolve via `resolve_my_user_id` under D5, like decrypt_card). `owner_key_version = 1` (Phase-4 single-key; confirm the binding's key_version via the resolved author and use it). `chunk_size = 4096`. The preview thumbnail (image) = base64 of the bundle's thumbnail stream's *plaintext* — but the bundle holds ciphertext chunks, so instead carry the thumbnail plaintext from the prepared `PlaintextStreams` (capture it before `build_upload` consumes the streams) for the preview. Store the bundle + meta in `UploadJobs` keyed by a random `job_id`. Return `UploadPreview`. **No POST/PUT.** Identity borrowed under the session lock across the synchronous `build_upload` (no take/None-window).

> Engineer notes: a chosen file path is host-trusted (the user picked it via the OS dialog in a later wiring) but still read with a max-size guard (reject > a sane cap, e.g. `MediaBounds`/a constant, with `too_large`). The preview must NOT expose key material — only title/type/size/thumbnail. Confirm `owner_key_version` from the resolved own binding (`resolve_my_user_id` gives user_id; resolve the binding for key_version, or reuse `resolve_and_verify_author` on your own id to get `key_version` via a small extension — simplest: extend `VerifiedAuthor` with `key_version` OR add a resolver that returns it; pick the minimal clean option and note it).

- [ ] **Step 3:** register `stage_upload`; build/test; fmt/clippy clean; commit `feat(client-app): stage_upload (preview-before-upload, no network)`.

---

## Task 7: `confirm_upload` / `cancel_upload` / `upload_jobs` commands

**Files:** Modify `crates/client-app/src/commands/upload.rs`, `main.rs`.

- [ ] **Step 1: confirm_upload** — pull the `StagedUpload` from `UploadJobs` by `job_id`; `reauth` → `(sender, host, token)`; emit `UploadPhase::Staging` → run `upload::run_pipeline` with an `on_progress` closure emitting `UploadPhase::Uploading { done, total }` (throttle to avoid event spam — e.g. emit every chunk or every N) → `Finalizing` → `Done { file_id }`; on any error emit `Failed { code }` and keep the job (so the user can retry) OR remove it (decide: keep on failure for retry). Remove the job from the registry on `Done`. The `UploadPhase::Transcoding`/`Encrypting` phases are emitted in `stage_upload` (or just `Staging`→… in confirm; keep honest — transcoding/encrypting already happened in stage_upload, so confirm emits Staging→Uploading→Finalizing→Done).
- [ ] **Step 2: cancel_upload** — remove the job from `UploadJobs` (pre-confirm cancel; an in-flight confirm is best-effort and not interrupted in Phase 4 — note as a limitation). `upload_jobs` — list current `UploadJobView { job_id, title, file_type, total_chunks }`.
- [ ] **Step 3:** register all three; build/test; fmt/clippy clean; commit `feat(client-app): confirm/cancel/list upload commands`.

---

## Task 8: UI — `<upload-screen>` (choose + describe → preview → confirm)

**Files:** Create `ui/src/components/upload-screen.ts`; Modify `app-shell.ts`, `core/router.ts`, `core/types.ts`.

- [ ] **Step 1: TS types** (UploadKind/UploadPreview/UploadMsg mirrors) in `types.ts`.
- [ ] **Step 2: `<upload-screen>`** — a form (kind select image/blog, a file path input — for now a text path field, since the OS file dialog wiring is a Tauri plugin deferred; OR use a `<input type=file>` and pass the path/bytes — KEEP IT SIMPLE: a text input for the path + a blog `<textarea>` for blog content, deciding by kind), title, tags (comma-split), a "Preview" button → calls `stage_upload` → renders the `UploadPreview` (title/type/size/thumbnail via `data:` URL) with a "Confirm upload" button → calls `confirm_upload` (routed through `serial()`), then shows the tray status. Accessible: landmark, labelled controls, role=status. Strict TS (errMsg narrowing).

> For blog, the screen sends `{ kind:"blog", path:"", title, tags }` won't carry content — adjust: add an optional `content` field to `StageUploadRequest` for blogs (blog content comes from the textarea, not a path), and for images use `path`. Update the Task-6 DTO + command accordingly (blog: use `req.content` bytes; image: read `req.path`). Make this consistent end to end.

- [ ] **Step 3:** route `upload` → `<upload-screen>`; make the shell "Upload" nav a real `#/upload` link; add `"upload"` to the router tuple. Typecheck + build clean. Commit `feat(ui): upload screen (preview-before-upload)`.

---

## Task 9: UI — `<upload-tray>` (active uploads: progress/ETA/retry)

**Files:** Create `ui/src/components/upload-tray.ts`; Modify `app-shell.ts`.

- [ ] **Step 1: `<upload-tray>`** — subscribes to `EVT_UPLOAD`; per `job_id` shows a row with a `<progress-meter>` (done/total → %, + a simple ETA from elapsed/throughput) and the phase via `<state-badge>`; on `failed` shows a Retry button that re-invokes `confirm_upload(job_id)` (the job is retained on failure). On `done` the row shows ✓ then auto-clears after a few seconds. Mount it in `app-shell` (a persistent region, e.g. in the status strip). Non-color-only, ARIA live region.
- [ ] **Step 2:** typecheck + build clean. Commit `feat(ui): active-uploads tray (progress/ETA/retry)`.

---

## Task 10: End-to-end — client uploads image + blog over real TLS, round-trips

**Files:** Create `crates/client-app/tests/upload_e2e.rs`; Modify `Cargo.toml` if needed.

Mirror `browse_view_e2e.rs`/`file_e2e.rs` for the harness. Drive the REAL `client-app::upload` pipeline (and `directory::resolve_recovery_recipient`) — register+login an author, publish the author + a recovery-recipient D5 binding, then: prepare streams (image transcode + blog), `build_upload`, run `upload::run_pipeline` over `c.sender`, GET the file back + `verify_and_open` → assert the exact plaintext round-trips. Include a **resume** gate: drop one chunk PUT (simulate a transport failure once), confirm `put_chunk_retried` recovers and finalize still succeeds; and a gate that the recovery recipient wrap is present.

- [ ] **Step 1:** write the test (5 gates: image round-trips; blog round-trips; recovery wrap present; a transiently-failed chunk is retried and finalize succeeds; a finalize before all chunks → the server 400 is surfaced as `finalize_failed`). Use MemoryStore + FsBlobStore.
- [ ] **Step 2:** run until PASS (real debugging; no weakened asserts). fmt/clippy clean. Commit `test(client-app): e2e client upload (image+blog) round-trip + resume`.

---

## Task 11: Phase-4 gates green + security-review note

**Files:** Create `docs/security-review-phase4-mediaapp.md`.

- [ ] fmt (client-app + ui clean; client-core untouched/in-style), clippy `-D warnings` (client-app), `cargo deny`, `cargo audit`, UI `npm run build`+typecheck, `MAXSECU_PG_OPTIONAL=1 cargo test --workspace`.
- [ ] Write the note: no new server crypto/endpoints; owner-only self+recovery upload; recovery recipient D5-verified before use; preview-before-upload holds the bundle in the TCB (no plaintext/keys cross the seam); identity borrowed under lock across the synchronous build; resumable idempotent PUT; sanitized errors; the e2e round-trip + resume gates. Conclude PASS if green; note deferrals (multi-recipient sharing; OS file-dialog plugin; mid-flight cancel).
- [ ] Commit `chore(phase4): gates green + security-review note`.

---

## Self-review checklist (done while writing)

- **Spec coverage (Phase 4 row of §10 + §5 Upload + §6):** choose+describe (Tasks 6, 8) ✓; preview-before-upload confirm (Tasks 6, 8 — bundle held pre-network) ✓; transcode/encrypt (Tasks 2, 6) ✓; resumable chunked upload progress/ETA/retry (Tasks 3, 4, 9) ✓; active-uploads tray (Task 9) ✓; UploadPhase state machine emitting events (Tasks 4, 7) ✓; recovery recipient D5-resolved (Task 1) ✓; e2e upload+round-trip+resume (Task 10) ✓; WCAG-AA screens (Tasks 8, 9) ✓; UI outside TCB — only preview/progress cross (all UI tasks + note) ✓; sanitized errors (all commands) ✓.
- **Type consistency:** `recovery_recipient_username`/`resolve_recovery_recipient`→`RecoveryRecipient{enc_pub,mlkem_pub}` (T1) used by `stage_upload` (T6); `build_metadata`/`prepare_{blog,image}_streams` (T2) used by T6; `stage_body`/`run_pipeline`/`total_chunks`/`put_bytes` (T3) used by T7 + the e2e (T10); `UploadPhase`/`EVT_UPLOAD` (T4) emitted by T7, consumed by `<upload-tray>` (T9); `UploadJobs`/`StagedUpload` (T5) used by T6/T7; DTOs `UploadKind`/`StageUploadRequest`(+content for blog)/`UploadPreview`/`ConfirmUploadRequest` (T6) mirrored in types.ts (T8). Endpoints: `POST /v1/files`, `PUT …/chunks/{i}`, `POST …/finalize`, `GET /v1/directory/{username}`.
- **Known fill-ins flagged (real-codebase confirmations):** `CanonicalStreams::into_plaintext_streams`/`RustImageCodec::transcode` exact names (read `client-core/src/media.rs` — T2); `VerifiedBinding.{enc_pub,mlkem_pub,key_version}` (T1/T6); the blog-content path in `StageUploadRequest` (`content` vs `path` — settle in T6/T8 consistently); `owner_key_version` source (T6). Each names the file to read.

## Deferred (documented, not gaps)

- **Multi-recipient sharing** (post-upload reshare via `client-core::build_reshare` → `POST /v1/files/{id}/wraps`) — a thin add-on after the core upload slice; Phase-4 uploads are self+recovery.
- **OS file-picker plugin** — Phase 4 takes a path/textarea; the Tauri dialog plugin wiring is deferred.
- **Mid-flight cancel/pause** — Phase 4 cancels only pre-confirm jobs; interrupting an in-flight upload is a later refinement.
- **Rotation (new versions of an existing post)** — `POST /v1/files/{id}/versions` exists; editing/rotating a post is a later slice.
