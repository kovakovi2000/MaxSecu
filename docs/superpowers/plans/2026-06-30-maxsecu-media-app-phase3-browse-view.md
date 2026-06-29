# MaxSecu Media App — Phase 3: Browse + View — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the feed/library browse experience — list accessible content, decrypt per-item cards (title + thumbnail), client-side title+tag search/sort over a local **encrypted** index, an image + blog **viewer**, the "only my uploads" filter, and the full real-time **fetch/decrypt feedback layer** — all as UI + `client-app` orchestration on top of the existing MaxSecu backend, with a Phase-3 e2e that drives the real stack over real TLS.

**Architecture:** Phase 3 introduces **no new server crypto**. The server already serves the D35 listing (`GET /v1/files`), the per-version file view (`GET /v1/files/{id}`), the raw ciphertext chunks, and the directory bindings (`GET /v1/directory/by-id/{id}`). The `client-app` backend orchestrates the channel-bound HTTP fetch, resolves+verifies the author's directory binding against the **pinned offline D5 key**, rebuilds a `DownloadBundle`/`StreamHeader`, and runs the existing `client-core` verify/decrypt ladder (`verify_and_open` / a new header-only `verify_and_open_headers`). Every confidentiality/integrity guarantee continues to rest on `client-core`; the UI stays strictly **outside the TCB** — it receives only render-ready DTOs (card metadata, a thumbnail image, the viewed content to display, verification ticks), never keys, tokens, DEKs, signed-record interiors, or grant/wrap bytes.

**Tech Stack:** Rust (Tauri 2 command boundary, `hyper`/`hyper-util`/`http-body-util` over the Phase-1 pinned TLS 1.3 transport), `maxsecu-client-core` (`verify_and_open`, `DirectoryVerifier`, `MemoryTrustStore`, `version_memory`), `maxsecu-encoding`/`maxsecu-crypto`, vanilla TypeScript + Web Components UI, the existing `MemoryStore`/`FsBlobStore` e2e harness (no Postgres).

---

## Backend facts this plan is grounded in (read before coding)

- **Listing (D35), api.md §8.6** — `GET /v1/files?type=<image|video|blog>&limit=<n>` (authed, `AuthedSession`). Response `ListRes { files: [ListEntryRes { file_id: hex, file_type: "image"|"video"|"blog", version: u64, updated_at: u64(ms), streams: { "<stream_name>": { "size": u64 } } }], next_cursor: Option<String> }`. Only structure/sizes — never values. An unknown `type` returns an empty list, not an error. `limit` defaults to 50, capped at 200. Source: `crates/server/src/http.rs::list_files` + `ListEntryRes`/`ListRes`.
- **File view, api.md §8.5** — `GET /v1/files/{file_id_hex}?version=latest|<n>` (authed). Response `FileRes { version, manifest_b64, manifest_sig_b64, genesis_b64, genesis_sig_b64, my_wrap: { wrapped_dek_b64, grant_b64, grant_sig_b64, ancestor_grants: [{ grant_b64, grant_sig_b64 }] }, recovery_grant?: { grant_b64, grant_sig_b64 }, streams: [{ stream_type: "content"|"metadata"|"thumbnail"|"preview", chunk_count, chunk_size, blob_ref }] }`. `404` for missing file/version **or** a caller with no wrap (no access oracle). Source: `crates/server/src/http.rs::get_file` + `file_view_to_res`/`FileRes`.
- **Chunk download, api.md §9.2** — `GET /v1/files/{file_id_hex}/versions/{v}/streams/{stream_type}/chunks/{index}` (authed) → raw `application/octet-stream` body (the ciphertext chunk). `404` for missing-or-forbidden (no oracle). Source: `crates/server/src/http.rs::get_chunk`.
- **Cold-fetch progress, api.md §9.3** — `GET …/chunks/{index}/status` (authed) → `{ source: "cache"|"cold-fetching"|"cold-ready", fetched_bytes: u64, total_bytes: u64 }`. Same access gate as the chunk download. Source: `crates/server/src/http.rs::chunk_status`.
- **Directory binding, api.md §6.1** — `GET /v1/directory/by-id/{user_id_hex}` and `GET /v1/directory/{username}` (UNauthenticated; the D5 signature is the authority). Response `BindingRes { binding_b64: canonical(DirBinding), directory_signature_b64: Ed25519-by-D5 }`. `404` ⇒ unsigned/pending ⇒ not a recipient. The client re-verifies under the **pinned D5 public key**. Source: `crates/server/src/http.rs::directory_by_id`/`binding_response`/`BindingRes`.
- **The download / verify / decrypt core (`crates/client-core/src/download.rs`, re-exported from `maxsecu_client_core`):**
  - `verify_and_open(ctx: &VerifyContext, bundle: &DownloadBundle) -> Result<OpenedFile, DownloadError>` — whole-buffer: runs the §12.5 header ladder then decrypts **every** manifest stream (it requires all streams' chunks present in `bundle.streams`).
  - `verify_and_stream_content(ctx, header: &StreamHeader, fetch, sink) -> Result<OpenedHeader, DownloadError>` — O(chunk) streaming of the `content` stream; decodes small streams whole. It **always** streams the content stream (calls `fetch` for every content chunk), so it is **not** a header-only path.
  - `DownloadBundle { manifest_bytes, manifest_sig: [u8;64], genesis_bytes, genesis_sig, wrapped_dek: WrappedDek, grant_bytes, grant_sig, ancestor_grants: Vec<(Vec<u8>,[u8;64])>, recovery_grant_bytes, recovery_grant_sig, streams: Vec<StreamChunks> }`; `StreamChunks { stream_type: StreamType, chunks: Vec<Vec<u8>> }`.
  - `WrappedDek { enc: [u8;32], ct: Vec<u8> }`. The server stores+serves the wire form `enc(32) ‖ ct`; rebuild with `enc = bytes[..32]`, `ct = bytes[32..]` (see `file_e2e.rs::wrap_from_bytes`).
  - `VerifyContext<'a>` fields used in Phase 3: `file_id: Id`, `author_sig_pub: [u8;32]`, `owner_sig_pub: [u8;32]` (in Phase 3 author == owner, so the same resolved key), `recipient_id: Id`, `recipient_type: RecipientType::User`, `recipient_secret: &EncSecretKey` (`identity.enc_secret()`), `recipient_mlkem_seed: None`, `seen_max_version: Option<u64>`, `granter_sig_pub: &NO_GRANTERS`, `admin_sig_pub: &NO_ADMINS`, `tombstones: None`, `compromise: None`.
  - `OpenedFile { version, file_type: FileType, content_digest: [u8;32], recovery_grant_ok: bool, streams: Vec<OpenedStream> }`; `OpenedStream { stream_type, plaintext: Vec<u8> }`.
- **Directory verification (`crates/client-core/src/directory.rs`):** `DirectoryVerifier::new(pinned_dir_pub: [u8;32])`; `.verify_binding(&DirBinding, &[u8;64], now_ms, &mut dyn TrustStore) -> Result<VerifiedBinding, VerifyError>` (TOFU pin on first contact); `VerifiedBinding { user_id:[u8;16], enc_pub:[u8;32], sig_pub:[u8;32], key_version, roles, fingerprint:[u8;32], mlkem_pub }`. `MemoryTrustStore::new()` is an in-RAM `TrustStore`.
- **Binding decode:** `maxsecu_encoding::decode::<DirBinding>(&bytes)` and `decode::<Manifest>(&bytes)`/`decode::<Genesis>(&bytes)`; `DirBinding`/`Manifest`/`Genesis` live in `maxsecu_encoding::structs`. `Manifest.author_id: Id` and `Genesis.owner_id: Id` identify whose directory key to resolve. `Id([u8;16])`, hex via the existing `hex_encode`/`hex16` helpers.
- **Existing client-app to reuse (do NOT reimplement):** `crates/client-app/src/commands/connection.rs::{open_conn(dir,&server)->(SendRequest, host, exporter), reauth(dir,&server,&Session,&ConnectLock)->(SendRequest, host, token)}`; `crates/client-app/src/http_client.rs::{post_json,get_json}(sender,uri,&body?,bearer)`; `crates/client-app/src/commands/auth.rs::{AppDir, Session(SessionInner{identity,server_id,token,username}), ConnectLock}`; `error.rs::UiError`; `dto.rs`; `state.rs` (kebab-tagged enums + `maxsecu://…` event names); `transport.rs`; `config.rs`.
- **Canonical e2e template:** `crates/server/tests/file_e2e.rs` — shows the exact out-of-band staging the Phase-3 e2e reuses: register+login over TLS, `build_upload`, `POST /v1/files` (stage), `PUT …/chunks/{i}` (every ciphertext chunk), `POST …/finalize`, then `GET /v1/files/{id}` + chunk GETs → rebuild `DownloadBundle` → `verify_and_open`. Mirror its TLS harness (`test_pki`/`connect`/`post`/`put_raw`/`get_json`/`get_raw`/`hex`/`hex16`/`wrap_bytes`/`wrap_from_bytes`/`stream_name`).

## Environment (tell every subagent)

- **cargo is NOT on the tool PATH.** Prefix every shell command: PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; ` / bash `export PATH="$HOME/.cargo/bin:$PATH"; `. Rust 1.96 MSVC.
- **No PostgreSQL on the host.** Run the workspace test gate with `MAXSECU_PG_OPTIONAL=1` (sanctioned skip). e2e uses `MemoryStore` + `FsBlobStore` (no Postgres). Upload-from-the-client is Phase 4 — the Phase-3 e2e stages content **out of band** via the server file endpoints (mirror `file_e2e.rs`).
- **Tauri CLI / GUI is not available** — verify the client via `cargo build`, `tsc`/`npm run build`, and the e2e; never launch the window.
- **`cargo fmt --all --check` fails on pre-existing Phase 0–7 drift** — keep only the files you touch fmt-clean (`cargo fmt -p <crate>`); do not mass-reformat. `maxsecu-server` carries pre-existing drift that is OUT OF SCOPE.
- **deny.toml:** `ring`/`openssl` are HARD-banned (keep). No new external deps are expected — all crates here are already in-tree. Add only a narrow, justified entry if genuinely required.
- **Known pre-existing flake (NOT yours):** `maxsecu-media-worker --test containment_windows` fails under parallel `cargo test --workspace` (shared AppContainer profile name); passes isolated single-threaded. Unrelated to the media app — don't chase it.

## Security model for Phase 3 (honor exactly)

- **The UI stays outside the TCB.** Only render-ready DTOs cross the Tauri boundary: card metadata (title, tags, file_type, version, verification ticks), a decoded **thumbnail image**, and — in the viewer — the **content the user is viewing** (a canonical PNG to display, or sanitized blog text). Never a private key, a session token, a DEK, a `WrappedDek`, a grant/manifest/genesis interior, or `ancestor_grants`. The decrypted content reaching the WebView to be *displayed* is the product, not a TCB leak; what never leaves the TCB is all **key/crypto material and signed-record interiors**. Large content (video) uses the streaming path with a bounded window — Phase 7; Phase 3 content (images/blog) is small.
- **Every served binding is re-verified client-side** against the **pinned D5 public key** before its `sig_pub` is trusted to verify a manifest/genesis (`DirectoryVerifier`). The server is only the transport; it cannot forge a binding (it holds only D5's public half) and cannot make the client accept a non-D5-signed author.
- **Fail-closed decode.** The download core strict-decodes every record, bound-checks framing before allocation, verifies every signature, and self-validates the DEK against the manifest commitment. Phase 3 adds no bypass — `decrypt_card`/`open_content` surface a **sanitized** `UiError` on any failure (no oracle, no internal detail), mirroring `error.rs`/the server's sanitized model.
- **Local search index is encrypted at rest** (D-F): titles/tags are plaintext content, so the persisted index (`<dir>/index/search.idx`) is sealed with a key derived from the unlocked identity. Search runs in the TCB; the UI receives only card DTOs of matches.

---

## File structure

```
crates/client-core/src/
  download.rs    MODIFY — add verify_and_open_headers (header + small streams, NO content fetch),
                          factored on the existing private verify_header. Pure/transport-agnostic.
  lib.rs         MODIFY — export verify_and_open_headers.
crates/client-app/src/
  config.rs      MODIFY — load_directory_pub(dir) reads the pinned D5 pubkey at config/directory_pub.der.
  http_client.rs MODIFY — get_bytes(sender, uri, bearer) raw octet-stream GET (chunk download).
  directory.rs   NEW — resolve_and_verify_author(sender, host, user_id_hex, &DirectoryVerifier,
                        &mut TrustStore, now_ms) -> VerifiedAuthor; resolve_my_user_id(...).
  download.rs    NEW — fetch_file_view + build a DownloadBundle / a small-streams bundle + a
                        VerifyContext from a FileRes + a VerifiedAuthor (the shared orchestration).
  index.rs       NEW — the local ENCRYPTED title+tag search index (in-RAM + sealed persistence).
  dto.rs         MODIFY — FeedFilter/FeedSort, FeedEntryDto, CardDto, OpenedContentDto, SearchHit.
  state.rs       MODIFY — FetchPhase typed state machine + EVT_FETCH event name.
  commands/feed.rs    NEW — list_feed(filter, sort), decrypt_card(file_id) commands.
  commands/viewer.rs  NEW — open_content(file_id) command (emits FetchPhase events).
  commands/search.rs  NEW — search_local(query), reindex() commands.
  commands/mod.rs     MODIFY — re-export feed/viewer/search.
  commands/stubs.rs   MODIFY — remove the list_feed stub (now real).
  main.rs        MODIFY — declare modules; register the new commands; drop the stub registration.
  lib.rs         MODIFY — declare the new modules (directory, download, index).
  ui/src/core/types.ts      MODIFY — TS DTO mirrors (FeedEntry, Card, OpenedContent, SearchHit, FetchMsg).
  ui/src/core/router.ts     MODIFY — add "viewer" route; keep "feed".
  ui/src/components/state-badge.ts   NEW — non-color-only per-item status badge.
  ui/src/components/progress-meter.ts NEW — %, speed/ETA, retry; ARIA.
  ui/src/components/feed-screen.ts   NEW — feed/library grid: filter, sort, "my uploads", search box.
  ui/src/components/media-card.ts    NEW — <media-card> decrypts its card + shows title/thumbnail/badge.
  ui/src/components/media-viewer.ts  NEW — <media-viewer> image (data: URL) + blog (sanitized text).
  ui/src/components/app-shell.ts     MODIFY — route feed→<feed-screen>, viewer→<media-viewer>;
                                              make "My Content" a real link; subscribe EVT_FETCH.
  ui/index.html (or the CSP source)  MODIFY — img-src 'self' data: so decrypted PNGs render.
crates/client-app/tests/
  browse_view_e2e.rs   NEW — the Phase-3 exit-gate e2e over real TLS.
docs/
  security-review-phase3-mediaapp.md  NEW — Phase-3 sign-off.
```

---

## Task 1: `client-core` header-only open (`verify_and_open_headers`)

**Files:**
- Modify: `crates/client-core/src/download.rs`
- Modify: `crates/client-core/src/lib.rs`

A feed **card** needs only the small streams (metadata → title/tags, thumbnail → image) — never the (potentially large) `content` stream. `verify_and_open` requires every stream's chunks; `verify_and_stream_content` always streams content. Add a pure header-only path that runs the **same** §12.5 header ladder (via the existing private `verify_header`) and decrypts only the **non-content** streams, fully digest-checked. This is strictly *less* than the streaming path (no content fetch, no content release) and reuses the audited header verifier, so the access proof is identical.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `crates/client-core/src/download.rs` (reuse the existing `build()`, `self_bundle()`, `ctx()`, `StreamChunks`, `OpenedHeader` helpers already in that module):

```rust
    #[test]
    fn open_headers_decodes_small_streams_without_content() {
        let built = build();
        let db = self_bundle(&built.bundle);
        // A header-only bundle: the same records + wrap, but ONLY the non-content
        // streams supplied (content chunks deliberately withheld).
        let small: Vec<StreamChunks> = db
            .streams
            .iter()
            .filter(|s| s.stream_type != StreamType::Content)
            .map(|s| StreamChunks { stream_type: s.stream_type, chunks: s.chunks.clone() })
            .collect();
        let header = StreamHeader {
            manifest_bytes: db.manifest_bytes.clone(),
            manifest_sig: db.manifest_sig,
            genesis_bytes: db.genesis_bytes.clone(),
            genesis_sig: db.genesis_sig,
            wrapped_dek: db.wrapped_dek.clone(),
            grant_bytes: db.grant_bytes.clone(),
            grant_sig: db.grant_sig,
            ancestor_grants: vec![],
            recovery_grant_bytes: db.recovery_grant_bytes.clone(),
            recovery_grant_sig: db.recovery_grant_sig,
            small_streams: small,
        };
        let opened = verify_and_open_headers(&ctx(&built), &header).expect("header opens");
        assert_eq!(opened.version, 1);
        assert!(opened.recovery_grant_ok);
        // The metadata small-stream decrypts; content is NOT among the returned streams.
        let meta = opened
            .small_streams
            .iter()
            .find(|s| s.stream_type == StreamType::Metadata)
            .unwrap();
        assert_eq!(meta.plaintext, b"title=fox");
        assert!(opened.small_streams.iter().all(|s| s.stream_type != StreamType::Content));
        // The content framing count is still reported from the verified manifest.
        assert!(opened.content_chunk_count >= 1);
    }

    #[test]
    fn open_headers_rejects_a_forged_manifest() {
        let built = build();
        let db = self_bundle(&built.bundle);
        let header = StreamHeader {
            manifest_bytes: db.manifest_bytes.clone(),
            manifest_sig: { let mut s = db.manifest_sig; s[0] ^= 0x01; s },
            genesis_bytes: db.genesis_bytes.clone(),
            genesis_sig: db.genesis_sig,
            wrapped_dek: db.wrapped_dek.clone(),
            grant_bytes: db.grant_bytes.clone(),
            grant_sig: db.grant_sig,
            ancestor_grants: vec![],
            recovery_grant_bytes: db.recovery_grant_bytes.clone(),
            recovery_grant_sig: db.recovery_grant_sig,
            small_streams: vec![],
        };
        assert_eq!(
            verify_and_open_headers(&ctx(&built), &header),
            Err(DownloadError::ManifestSignature)
        );
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p maxsecu-client-core download::tests::open_headers_decodes_small_streams_without_content`
Expected: FAIL (no function `verify_and_open_headers`).

- [ ] **Step 3: Implement `verify_and_open_headers`**

Add to `crates/client-core/src/download.rs`, right after `verify_and_stream_content` (it reuses the private `verify_header` + the `StreamHeader`/`OpenedHeader` types already defined). It mirrors the small-stream loop of `verify_and_stream_content` but skips the content stream entirely:

```rust
/// Run the §12.5 header ladder, then decrypt **only the non-content (small)
/// streams** — never fetching or releasing the `content` stream. Same fail-closed
/// header proof as [`verify_and_open`] / [`verify_and_stream_content`] (it calls the
/// shared [`verify_header`]); it just does strictly less work, for callers (a feed
/// card) that need a verified `metadata`/`thumbnail` without the (possibly large)
/// content (DESIGN §12.5 / §8.6). `content_chunk_count` is reported from the
/// verified manifest so the caller can later stream the content with the same proof.
pub fn verify_and_open_headers(
    ctx: &VerifyContext,
    header: &StreamHeader,
) -> Result<OpenedHeader, DownloadError> {
    use DownloadError::*;

    let (manifest, dek, recovery_grant_ok) = verify_header(
        ctx,
        &header.manifest_bytes,
        &header.manifest_sig,
        &header.genesis_bytes,
        &header.genesis_sig,
        &header.grant_bytes,
        &header.grant_sig,
        &header.ancestor_grants,
        &header.recovery_grant_bytes,
        &header.recovery_grant_sig,
        &header.wrapped_dek,
    )?;

    let mut small = Vec::new();
    let mut content_ms: Option<&maxsecu_encoding::structs::Stream> = None;
    for ms in &manifest.streams {
        if ms.compression != Compression::None {
            return Err(CompressionUnsupported);
        }
        if ms.stream_type == StreamType::Content {
            content_ms = Some(ms);
            continue;
        }
        let provided = header
            .small_streams
            .iter()
            .find(|s| s.stream_type == ms.stream_type)
            .ok_or(StreamMissing(ms.stream_type))?;
        if provided.chunks.len() as u64 != ms.chunk_count {
            return Err(FramingBoundsExceeded("chunk_count mismatch"));
        }
        if stream_digest(&provided.chunks) != ms.digest.0 {
            return Err(StreamDigestMismatch(ms.stream_type));
        }
        let ck = dek.stream_subkey(ms.stream_type);
        let plaintext = open_stream(&ck, ctx.file_id, manifest.version, ms.stream_type, &provided.chunks)
            .map_err(|_| StreamFraming(ms.stream_type))?;
        small.push(OpenedStream {
            stream_type: ms.stream_type,
            plaintext,
        });
    }

    // The content stream must be declared in the manifest (DESIGN §12.3), even
    // though we do not fetch it here — its framing count is reported back.
    let content_ms = content_ms.ok_or(StreamMissing(StreamType::Content))?;
    match content_ms.chunk_count.checked_mul(manifest.chunk_size as u64) {
        Some(b) if b <= MAX_ADDRESSABLE_BYTES => {}
        _ => return Err(FramingBoundsExceeded("addressable size")),
    }

    Ok(OpenedHeader {
        version: manifest.version,
        file_type: manifest.file_type,
        content_digest: content_ms.digest.0,
        recovery_grant_ok,
        content_chunk_count: content_ms.chunk_count,
        small_streams: small,
    })
}
```

Export it in `crates/client-core/src/lib.rs` by adding `verify_and_open_headers` to the existing `pub use download::{ … }` list.

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p maxsecu-client-core download::tests::open_headers`
Expected: PASS (both new tests).

- [ ] **Step 5: Confirm the whole crate still builds + tests green**

Run: `cargo test -p maxsecu-client-core`
Expected: PASS (no regression).

- [ ] **Step 6: Commit**

```bash
git add crates/client-core/src/download.rs crates/client-core/src/lib.rs
git commit -m "feat(client-core): verify_and_open_headers (header + small streams, no content fetch)"
```

---

## Task 2: `client-app` pins the D5 directory key (`config::load_directory_pub`)

**Files:**
- Modify: `crates/client-app/src/config.rs`

The client must verify served bindings against the **pinned offline D5 public key** (§7.3). Mirror the existing pinned-cert source (`<dir>/config/server_cert.der`): read the 32-byte D5 public key from `<dir>/config/directory_pub.der`. (Prod would compile this in; the testable build reads it from config so the e2e/ceremony can provide it.)

- [ ] **Step 1: Read the current `config.rs`** to match its style (it already has `ConnectionConfig` load/save). Note the `AppDir` layout: config lives under `<dir>/config/`.

- [ ] **Step 2: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `crates/client-app/src/config.rs`:

```rust
    #[test]
    fn load_directory_pub_reads_pinned_key() {
        let tmp = std::env::temp_dir().join(format!(
            "mxcfg_{}",
            maxsecu_crypto::random_array::<8>().iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(tmp.join("config")).unwrap();
        // Missing → a sanitized "untrusted" error (fail closed; no admin/browse
        // without a pinned root).
        assert_eq!(load_directory_pub(&tmp).unwrap_err().code, "untrusted");
        // Present (exactly 32 bytes) → returned verbatim.
        let key = [0x7Du8; 32];
        std::fs::write(tmp.join("config").join("directory_pub.der"), key).unwrap();
        assert_eq!(load_directory_pub(&tmp).unwrap(), key);
        // Wrong length → fail closed.
        std::fs::write(tmp.join("config").join("directory_pub.der"), [0u8; 31]).unwrap();
        assert_eq!(load_directory_pub(&tmp).unwrap_err().code, "untrusted");
        let _ = std::fs::remove_dir_all(&tmp);
    }
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test -p maxsecu-client-app config::tests::load_directory_pub_reads_pinned_key`
Expected: FAIL (no function `load_directory_pub`).

- [ ] **Step 4: Implement**

Add to `crates/client-app/src/config.rs`:

```rust
use std::path::Path;

use crate::error::UiError;

/// Load the pinned offline **directory-signing (D5) public key** (§7.3) from
/// `<dir>/config/directory_pub.der` (32 raw bytes). The trust root the client
/// verifies every served binding against; absent or malformed ⇒ fail closed with
/// a sanitized `untrusted` error (no browse/admin without a pinned root). Mirrors
/// the pinned server-cert source used by `commands::connection::open_conn`.
pub fn load_directory_pub(dir: &Path) -> Result<[u8; 32], UiError> {
    let path = dir.join("config").join("directory_pub.der");
    let bytes = std::fs::read(&path)
        .map_err(|_| UiError::new("untrusted", "This server's directory key is not pinned."))?;
    bytes
        .try_into()
        .map_err(|_| UiError::new("untrusted", "The pinned directory key is malformed."))
}
```

(If `config.rs` does not already use `maxsecu_crypto` in tests, the test uses it for a random temp-dir suffix — `maxsecu-crypto` is already a dependency of `client-app`. If not, replace the suffix with `std::process::id()` + a counter; keep the behavioral assertions.)

- [ ] **Step 5: Run it to verify it passes**

Run: `cargo test -p maxsecu-client-app config::tests::load_directory_pub_reads_pinned_key`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/config.rs
git commit -m "feat(client-app): pin the offline D5 directory key (config::load_directory_pub)"
```

---

## Task 3: `http_client::get_bytes` (raw octet-stream chunk GET)

**Files:**
- Modify: `crates/client-app/src/http_client.rs`

Chunk downloads return a raw `application/octet-stream` body, not JSON. Add a sibling to `get_json` that returns `(StatusCode, Vec<u8>)`.

- [ ] **Step 1: Read `http_client.rs`** to match the exact `send`/`get_json` shape (the `SendRequest<Full<Bytes>>` type, the `host` header, the `ready()` call, the `UiError` mapping).

- [ ] **Step 2: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `crates/client-app/src/http_client.rs` (the module is exercised live by the e2e; this guards the surface like the existing `module_compiles` test):

```rust
    #[test]
    fn get_bytes_is_exposed() {
        // Compile-time guard that the raw-bytes accessor exists with the expected
        // signature; behavior is exercised over live TLS by the Phase-3 e2e.
        fn _assert_sig(
            s: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
        ) {
            let _f = super::get_bytes(s, "/x", None);
            let _ = _f; // future, not awaited here
        }
        assert_eq!(2 + 2, 4);
    }
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test -p maxsecu-client-app http_client::tests::get_bytes_is_exposed`
Expected: FAIL (no function `get_bytes`).

- [ ] **Step 4: Implement**

Add to `crates/client-app/src/http_client.rs` (reuse the same imports already in the file: `BodyExt`/`Full`, `Bytes`, `SendRequest`, `Request`/`StatusCode`, `UiError`):

```rust
/// GET a raw `application/octet-stream` body (a ciphertext chunk); return
/// `(status, bytes)`. `bearer` adds the channel-bound `Authorization` header.
pub async fn get_bytes(
    sender: &mut SendRequest<Full<Bytes>>,
    uri: &str,
    bearer: Option<&str>,
) -> Result<(StatusCode, Vec<u8>), UiError> {
    sender
        .ready()
        .await
        .map_err(|_| UiError::new("offline", "Lost connection to the server."))?;
    let mut builder = Request::builder().method("GET").uri(uri).header("host", "localhost");
    if let Some(tok) = bearer {
        builder = builder.header("authorization", format!("MaxSecu-Session {tok}"));
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|_| UiError::new("internal", "Could not build the request."))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|_| UiError::new("offline", "The server did not respond."))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|_| UiError::new("offline", "The response was interrupted."))?
        .to_bytes()
        .to_vec();
    Ok((status, bytes))
}
```

> Note: the existing helpers hardcode `host: localhost` (matching the loopback test cert SAN). Keep that for parity; the real `host` is carried by the TLS SNI/pin (see `session.rs`'s note). If `get_json` already takes/uses a `host`, match its signature instead — read the file first.

- [ ] **Step 5: Run it to verify it passes (and the crate builds)**

Run: `cargo test -p maxsecu-client-app http_client::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/http_client.rs
git commit -m "feat(client-app): http_client::get_bytes (raw chunk download)"
```

---

## Task 4: `client-app` directory resolution + verification (`directory.rs`)

**Files:**
- Create: `crates/client-app/src/directory.rs`
- Modify: `crates/client-app/src/lib.rs` (`pub mod directory;`)

Resolve an author/owner `user_id` to a **directory-verified** `sig_pub`/`enc_pub` by fetching `GET /v1/directory/by-id/{id}`, decoding the `DirBinding`, and verifying it under the pinned D5 via `DirectoryVerifier`. Also resolve *my own* `user_id` (needed for the "only my uploads" filter) from `GET /v1/directory/{username}`. The HTTP is exercised by the e2e; the pure verify+extract logic is unit-tested here against a locally-signed binding (no network).

- [ ] **Step 1: Write the failing test**

`crates/client-app/src/directory.rs`:

```rust
//! Directory resolution for the download path: turn an author/owner `user_id`
//! into a D5-VERIFIED `sig_pub`/`enc_pub` (the keys the verify ladder trusts).
//! The server is only the transport — every served binding is re-verified here
//! against the pinned D5 root (§7.2). Only verified key bytes leave this module;
//! grant/manifest interiors never do.

use hyper::client::conn::http1::SendRequest;
use http_body_util::Full;
use hyper::body::Bytes;

use maxsecu_client_core::{DirectoryVerifier, TrustStore};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::DirBinding;

use crate::error::UiError;
use crate::http_client::get_json;

/// A directory-verified author/owner: exactly the key bytes the §12.5 ladder
/// needs. No signed-record interior is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthor {
    pub user_id: [u8; 16],
    pub sig_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    pub fingerprint: [u8; 32],
}

/// Verify an already-fetched `(binding_bytes, signature)` under the pinned D5 and
/// extract the trusted keys. Factored out of the network path so it is unit-
/// testable without TLS. Any failure ⇒ a sanitized `untrusted` error.
pub fn verify_author_binding(
    verifier: &DirectoryVerifier,
    trust: &mut dyn TrustStore,
    binding_bytes: &[u8],
    signature: &[u8; 64],
    now_ms: u64,
) -> Result<VerifiedAuthor, UiError> {
    let binding: DirBinding =
        decode(binding_bytes).map_err(|_| UiError::new("untrusted", "Malformed directory record."))?;
    let v = verifier
        .verify_binding(&binding, signature, now_ms, trust)
        .map_err(|_| UiError::new("untrusted", "The author's identity could not be verified."))?;
    Ok(VerifiedAuthor {
        user_id: v.user_id,
        sig_pub: v.sig_pub,
        enc_pub: v.enc_pub,
        fingerprint: v.fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::MemoryTrustStore;
    use maxsecu_crypto::SigningKey;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::labels;
    use maxsecu_encoding::structs::DirBinding;
    use maxsecu_encoding::types::{Bytes32, Id, Role, RoleSet, Text, Timestamp};

    const NOW: u64 = 1_719_500_000_000;

    fn signed_binding(d5: &SigningKey) -> (Vec<u8>, [u8; 64]) {
        let b = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([0x0A; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let sig = d5.sign_canonical(labels::DIRBINDING, &b);
        (encode(&b), sig)
    }

    #[test]
    fn verifies_a_genuine_binding_and_extracts_keys() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, sig) = signed_binding(&d5);
        let a = verify_author_binding(&verifier, &mut trust, &bytes, &sig, NOW).unwrap();
        assert_eq!(a.user_id, [0x0A; 16]);
        assert_eq!(a.sig_pub, [0x51; 32]);
        assert_eq!(a.enc_pub, [0xE1; 32]);
    }

    #[test]
    fn rejects_a_binding_signed_by_the_wrong_key() {
        let d5 = SigningKey::generate();
        let attacker = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, _good) = signed_binding(&d5);
        let forged = attacker.sign_canonical(labels::DIRBINDING, &decode::<DirBinding>(&bytes).unwrap());
        assert_eq!(
            verify_author_binding(&verifier, &mut trust, &bytes, &forged, NOW).unwrap_err().code,
            "untrusted"
        );
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod directory;` to `crates/client-app/src/lib.rs`.
Run: `cargo test -p maxsecu-client-app directory::tests`
Expected: FAIL first (module/fn missing), then PASS once the module compiles. (If `maxsecu-encoding`/`maxsecu-crypto` are not yet direct deps of `client-app`, add them to `[dependencies]` in `crates/client-app/Cargo.toml` — they are already in the workspace; both are needed by the download orchestration in Task 5 too.)

- [ ] **Step 3: Add the network resolvers**

Append to `crates/client-app/src/directory.rs`:

```rust
/// Decode a §6.1 `BindingRes` JSON body into `(binding_bytes, signature)`.
fn parse_binding(json: &serde_json::Value) -> Result<(Vec<u8>, [u8; 64]), UiError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let untrusted = || UiError::new("untrusted", "Malformed directory record.");
    let bytes = B64
        .decode(json["binding_b64"].as_str().ok_or_else(untrusted)?)
        .map_err(|_| untrusted())?;
    let sig_vec = B64
        .decode(json["directory_signature_b64"].as_str().ok_or_else(untrusted)?)
        .map_err(|_| untrusted())?;
    let sig: [u8; 64] = sig_vec.try_into().map_err(|_| untrusted())?;
    Ok((bytes, sig))
}

/// Fetch + D5-verify the binding for `user_id_hex` (`GET /v1/directory/by-id/…`).
/// `404` ⇒ the author is unsigned/pending ⇒ not a recipient (sanitized error).
pub async fn resolve_and_verify_author(
    sender: &mut SendRequest<Full<Bytes>>,
    user_id_hex: &str,
    verifier: &DirectoryVerifier,
    trust: &mut dyn TrustStore,
    now_ms: u64,
) -> Result<VerifiedAuthor, UiError> {
    let (status, json) =
        get_json(sender, &format!("/v1/directory/by-id/{user_id_hex}"), None).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("untrusted", "The author's identity is not published."));
    }
    let (bytes, sig) = parse_binding(&json)?;
    verify_author_binding(verifier, trust, &bytes, &sig, now_ms)
}

/// Resolve MY own `user_id` from my published binding (`GET /v1/directory/{username}`),
/// used to compute the "only my uploads" flag. Verified under the pinned D5 too.
pub async fn resolve_my_user_id(
    sender: &mut SendRequest<Full<Bytes>>,
    username: &str,
    verifier: &DirectoryVerifier,
    trust: &mut dyn TrustStore,
    now_ms: u64,
) -> Result<[u8; 16], UiError> {
    let (status, json) = get_json(sender, &format!("/v1/directory/{username}"), None).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("pending", "Your account is not yet approved."));
    }
    let (bytes, sig) = parse_binding(&json)?;
    Ok(verify_author_binding(verifier, trust, &bytes, &sig, now_ms)?.user_id)
}
```

> `get_json`'s exact signature — confirm whether it takes a `host` param (read `http_client.rs`); the calls above assume `(sender, uri, bearer)` like the Phase-2 commands. Adapt if the real signature differs. `serde_json` + `base64` are already `client-app` deps.

- [ ] **Step 4: Build + test**

Run: `cargo test -p maxsecu-client-app directory::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/directory.rs crates/client-app/src/lib.rs crates/client-app/Cargo.toml
git commit -m "feat(client-app): D5-verified directory resolution for the download path"
```

---

## Task 5: `client-app` download orchestration (`download.rs`)

**Files:**
- Create: `crates/client-app/src/download.rs`
- Modify: `crates/client-app/src/lib.rs` (`pub mod download;`)

The shared plumbing both `decrypt_card` and `open_content` use: GET the file view, decode the wraps/streams into a `DownloadBundle` (or a header-only `StreamHeader`), and build a `VerifyContext` from a resolved author. This isolates all the wire-shape parsing in one tested place.

- [ ] **Step 1: Write the failing test**

`crates/client-app/src/download.rs`:

```rust
//! Download orchestration: turn the server's opaque §8.5 file view + a D5-verified
//! author into the `client-core` `DownloadBundle`/`StreamHeader` + `VerifyContext`
//! the verify ladder consumes. Pure parsing/assembly here; the verify ladder lives
//! in client-core. Only verified, render-ready results ever reach a command.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_crypto::WrappedDek;
use maxsecu_encoding::types::StreamType;

use crate::error::UiError;

/// One stream's wire descriptor from a §8.5 file view (no values).
#[derive(Debug, Clone)]
pub struct StreamSpec {
    pub stream_type: StreamType,
    pub chunk_count: u64,
}

/// The parsed, non-secret framing of a file view: which streams exist + the
/// verification records, ready to drive header/content fetches. The wrap and
/// grant bytes are inert (the recipient re-verifies them); they never reach the UI.
pub struct ParsedView {
    pub version: u64,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
    pub wrapped_dek: WrappedDek,
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
    pub recovery_grant_bytes: Vec<u8>,
    pub recovery_grant_sig: [u8; 64],
    pub streams: Vec<StreamSpec>,
}

fn stream_type_from_name(s: &str) -> Option<StreamType> {
    match s {
        "content" => Some(StreamType::Content),
        "metadata" => Some(StreamType::Metadata),
        "thumbnail" => Some(StreamType::Thumbnail),
        "preview" => Some(StreamType::Preview),
        _ => None,
    }
}

fn dec(json: &serde_json::Value, key: &str) -> Result<Vec<u8>, UiError> {
    B64.decode(json[key].as_str().ok_or_else(|| bad())?).map_err(|_| bad())
}
fn dec64(json: &serde_json::Value, key: &str) -> Result<[u8; 64], UiError> {
    dec(json, key)?.try_into().map_err(|_| bad())
}
fn bad() -> UiError {
    UiError::new("fetch_failed", "The server sent a malformed file record.")
}

/// Rebuild the `enc(32) ‖ ct` wire wrap into a `WrappedDek`.
fn wrap_from_bytes(b: &[u8]) -> Result<WrappedDek, UiError> {
    if b.len() < 32 {
        return Err(bad());
    }
    Ok(WrappedDek {
        enc: b[..32].try_into().map_err(|_| bad())?,
        ct: b[32..].to_vec(),
    })
}

/// Parse a §8.5 `FileRes` JSON body into a `ParsedView` (no network, no decrypt).
pub fn parse_file_view(json: &serde_json::Value) -> Result<ParsedView, UiError> {
    let mw = &json["my_wrap"];
    let ancestor_grants = mw["ancestor_grants"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|g| Ok((dec(g, "grant_b64")?, dec64(g, "grant_sig_b64")?)))
                .collect::<Result<Vec<_>, UiError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let (recovery_grant_bytes, recovery_grant_sig) = match json.get("recovery_grant") {
        Some(rg) if !rg.is_null() => (dec(rg, "grant_b64")?, dec64(rg, "grant_sig_b64")?),
        _ => (Vec::new(), [0u8; 64]),
    };
    let mut streams = Vec::new();
    for s in json["streams"].as_array().ok_or_else(bad)? {
        let name = s["stream_type"].as_str().ok_or_else(bad)?;
        let st = stream_type_from_name(name).ok_or_else(bad)?;
        streams.push(StreamSpec {
            stream_type: st,
            chunk_count: s["chunk_count"].as_u64().ok_or_else(bad)?,
        });
    }
    Ok(ParsedView {
        version: json["version"].as_u64().ok_or_else(bad)?,
        manifest_bytes: dec(json, "manifest_b64")?,
        manifest_sig: dec64(json, "manifest_sig_b64")?,
        genesis_bytes: dec(json, "genesis_b64")?,
        genesis_sig: dec64(json, "genesis_sig_b64")?,
        wrapped_dek: wrap_from_bytes(&dec(mw, "wrapped_dek_b64")?)?,
        grant_bytes: dec(mw, "grant_b64")?,
        grant_sig: dec64(mw, "grant_sig_b64")?,
        ancestor_grants,
        recovery_grant_bytes,
        recovery_grant_sig,
        streams,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view_json() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "manifest_b64": B64.encode([1u8; 8]),
            "manifest_sig_b64": B64.encode([2u8; 64]),
            "genesis_b64": B64.encode([3u8; 8]),
            "genesis_sig_b64": B64.encode([4u8; 64]),
            "my_wrap": {
                "wrapped_dek_b64": B64.encode([9u8; 64]), // 32 enc + 32 ct
                "grant_b64": B64.encode([5u8; 8]),
                "grant_sig_b64": B64.encode([6u8; 64]),
                "ancestor_grants": []
            },
            "recovery_grant": { "grant_b64": B64.encode([7u8; 8]), "grant_sig_b64": B64.encode([8u8; 64]) },
            "streams": [
                { "stream_type": "content", "chunk_count": 3, "chunk_size": 4096, "blob_ref": "x" },
                { "stream_type": "metadata", "chunk_count": 1, "chunk_size": 4096, "blob_ref": "y" }
            ]
        })
    }

    #[test]
    fn parses_a_well_formed_view() {
        let p = parse_file_view(&view_json()).unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.wrapped_dek.enc, [9u8; 32]);
        assert_eq!(p.wrapped_dek.ct, vec![9u8; 32]);
        assert_eq!(p.streams.len(), 2);
        assert_eq!(p.streams[0].stream_type, StreamType::Content);
        assert_eq!(p.streams[0].chunk_count, 3);
    }

    #[test]
    fn missing_recovery_grant_is_tolerated() {
        let mut j = view_json();
        j["recovery_grant"] = serde_json::Value::Null;
        let p = parse_file_view(&j).unwrap();
        assert!(p.recovery_grant_bytes.is_empty());
    }

    #[test]
    fn malformed_view_is_a_sanitized_error() {
        let bad = serde_json::json!({ "version": "nope" });
        assert_eq!(parse_file_view(&bad).unwrap_err().code, "fetch_failed");
    }
}
```

- [ ] **Step 2: Run it to verify it fails, then passes**

Add `pub mod download;` to `crates/client-app/src/lib.rs`.
Run: `cargo test -p maxsecu-client-app download::tests`
Expected: PASS once the module compiles.

- [ ] **Step 3: Add the chunk-fetch + bundle/header builders**

Append to `crates/client-app/src/download.rs`:

```rust
use hyper::client::conn::http1::SendRequest;
use http_body_util::Full;
use hyper::body::Bytes;

use maxsecu_client_core::{DownloadBundle, StreamChunks, StreamHeader};

use crate::http_client::get_bytes;

fn stream_name(st: StreamType) -> &'static str {
    match st {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
}

/// GET every ciphertext chunk of one stream (authed) for `file_id_hex`/`version`.
pub async fn fetch_stream_chunks(
    sender: &mut SendRequest<Full<Bytes>>,
    token: &str,
    file_id_hex: &str,
    version: u64,
    spec: &StreamSpec,
) -> Result<StreamChunks, UiError> {
    let mut chunks = Vec::with_capacity(spec.chunk_count as usize);
    for i in 0..spec.chunk_count {
        let uri = format!(
            "/v1/files/{file_id_hex}/versions/{version}/streams/{}/chunks/{i}",
            stream_name(spec.stream_type)
        );
        let (status, bytes) = get_bytes(sender, &uri, Some(token)).await?;
        if status != hyper::StatusCode::OK {
            return Err(UiError::new("fetch_failed", "A content chunk could not be fetched."));
        }
        chunks.push(bytes);
    }
    Ok(StreamChunks { stream_type: spec.stream_type, chunks })
}

/// Build a header-only `StreamHeader` (NON-content streams only) from a parsed
/// view — for `decrypt_card`. Fetches only `metadata`/`thumbnail`/`preview`.
pub async fn build_stream_header(
    sender: &mut SendRequest<Full<Bytes>>,
    token: &str,
    file_id_hex: &str,
    view: &ParsedView,
) -> Result<StreamHeader, UiError> {
    let mut small = Vec::new();
    for spec in view.streams.iter().filter(|s| s.stream_type != StreamType::Content) {
        small.push(fetch_stream_chunks(sender, token, file_id_hex, view.version, spec).await?);
    }
    Ok(StreamHeader {
        manifest_bytes: view.manifest_bytes.clone(),
        manifest_sig: view.manifest_sig,
        genesis_bytes: view.genesis_bytes.clone(),
        genesis_sig: view.genesis_sig,
        wrapped_dek: view.wrapped_dek.clone(),
        grant_bytes: view.grant_bytes.clone(),
        grant_sig: view.grant_sig,
        ancestor_grants: view.ancestor_grants.clone(),
        recovery_grant_bytes: view.recovery_grant_bytes.clone(),
        recovery_grant_sig: view.recovery_grant_sig,
        small_streams: small,
    })
}

/// Build a full `DownloadBundle` (ALL streams) from a parsed view — for the viewer.
pub async fn build_download_bundle(
    sender: &mut SendRequest<Full<Bytes>>,
    token: &str,
    file_id_hex: &str,
    view: &ParsedView,
) -> Result<DownloadBundle, UiError> {
    let mut streams = Vec::new();
    for spec in &view.streams {
        streams.push(fetch_stream_chunks(sender, token, file_id_hex, view.version, spec).await?);
    }
    Ok(DownloadBundle {
        manifest_bytes: view.manifest_bytes.clone(),
        manifest_sig: view.manifest_sig,
        genesis_bytes: view.genesis_bytes.clone(),
        genesis_sig: view.genesis_sig,
        wrapped_dek: view.wrapped_dek.clone(),
        grant_bytes: view.grant_bytes.clone(),
        grant_sig: view.grant_sig,
        ancestor_grants: view.ancestor_grants.clone(),
        recovery_grant_bytes: view.recovery_grant_bytes.clone(),
        recovery_grant_sig: view.recovery_grant_sig,
        streams,
    })
}
```

- [ ] **Step 4: Build + test**

Run: `cargo test -p maxsecu-client-app download::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/download.rs crates/client-app/src/lib.rs
git commit -m "feat(client-app): download orchestration (parse view, build bundle/header)"
```

---

## Task 6: `list_feed` command (real D35 listing)

**Files:**
- Create: `crates/client-app/src/commands/feed.rs`
- Modify: `crates/client-app/src/dto.rs`, `crates/client-app/src/commands/mod.rs`, `crates/client-app/src/commands/stubs.rs`, `crates/client-app/src/main.rs`

Replace the `list_feed` stub with the real listing: GET `/v1/files?type=&limit=` over a re-authenticated channel, map to `FeedEntryDto` (no values — file_id, type, version, updated_at, whether a thumbnail stream exists), and apply the client-side sort. The type filter is passed to the server; sort + "my uploads" are client-side (the latter computed per-card in Task 7).

- [ ] **Step 1: Add the DTOs**

In `crates/client-app/src/dto.rs` add:

```rust
/// Feed type filter (D35). `All` omits the server `type` param.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FeedFilter {
    All,
    Image,
    Video,
    Blog,
}

/// Client-side sort over the listing.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FeedSort {
    NewestFirst,
    OldestFirst,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListFeedRequest {
    pub filter: FeedFilter,
    pub sort: FeedSort,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One feed entry — listing metadata only (no decrypted values). The card is
/// decrypted separately by `decrypt_card`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FeedEntryDto {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub updated_at: u64,
    pub has_thumbnail: bool,
}
```

- [ ] **Step 2: Write the failing test (the sort/map helper)**

`crates/client-app/src/commands/feed.rs`:

```rust
//! Feed/browse commands: the D35 listing (`list_feed`) and per-item card
//! decryption (`decrypt_card`). Listing carries no values; card decryption runs
//! the verify ladder in the TCB and returns only render-ready metadata + a
//! thumbnail. The UI never sees keys, grants, or the content stream here.

use tauri::State;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::dto::{FeedEntryDto, FeedFilter, FeedSort, ListFeedRequest};
use crate::error::UiError;

/// Map one `ListEntryRes` JSON object to a `FeedEntryDto`. Pure — unit-tested.
fn entry_from_json(j: &serde_json::Value) -> Option<FeedEntryDto> {
    let streams = j.get("streams")?;
    Some(FeedEntryDto {
        file_id: j["file_id"].as_str()?.to_owned(),
        file_type: j["file_type"].as_str()?.to_owned(),
        version: j["version"].as_u64()?,
        updated_at: j["updated_at"].as_u64()?,
        has_thumbnail: streams.get("thumbnail").is_some(),
    })
}

/// Apply the client-side sort (the server returns listing order).
fn sort_entries(entries: &mut [FeedEntryDto], sort: FeedSort) {
    match sort {
        FeedSort::NewestFirst => entries.sort_by(|a, b| b.updated_at.cmp(&a.updated_at)),
        FeedSort::OldestFirst => entries.sort_by(|a, b| a.updated_at.cmp(&b.updated_at)),
    }
}

/// The server `type` query value for a filter, or `None` for `All`.
fn filter_param(filter: FeedFilter) -> Option<&'static str> {
    match filter {
        FeedFilter::All => None,
        FeedFilter::Image => Some("image"),
        FeedFilter::Video => Some("video"),
        FeedFilter::Blog => Some("blog"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(id: &str, ty: &str, ver: u64, upd: u64, thumb: bool) -> serde_json::Value {
        let mut streams = serde_json::Map::new();
        streams.insert("metadata".into(), serde_json::json!({ "size": 10 }));
        if thumb {
            streams.insert("thumbnail".into(), serde_json::json!({ "size": 20 }));
        }
        serde_json::json!({ "file_id": id, "file_type": ty, "version": ver, "updated_at": upd, "streams": streams })
    }

    #[test]
    fn maps_and_sorts_entries() {
        let raw = vec![j("aa", "image", 1, 100, true), j("bb", "blog", 2, 300, false), j("cc", "image", 1, 200, true)];
        let mut entries: Vec<FeedEntryDto> = raw.iter().filter_map(entry_from_json).collect();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].has_thumbnail && !entries[1].has_thumbnail);
        sort_entries(&mut entries, FeedSort::NewestFirst);
        assert_eq!(entries.iter().map(|e| e.updated_at).collect::<Vec<_>>(), vec![300, 200, 100]);
        sort_entries(&mut entries, FeedSort::OldestFirst);
        assert_eq!(entries.iter().map(|e| e.updated_at).collect::<Vec<_>>(), vec![100, 200, 300]);
    }

    #[test]
    fn filter_param_maps_types() {
        assert_eq!(filter_param(FeedFilter::All), None);
        assert_eq!(filter_param(FeedFilter::Image), Some("image"));
        assert_eq!(filter_param(FeedFilter::Blog), Some("blog"));
    }
}
```

- [ ] **Step 3: Run it to verify it fails, then passes**

Add `pub mod feed;` to `crates/client-app/src/commands/mod.rs`.
Run: `cargo test -p maxsecu-client-app commands::feed::tests`
Expected: PASS once the module compiles.

- [ ] **Step 4: Add the command**

Append the command to `crates/client-app/src/commands/feed.rs` (it re-auths on a fresh channel — the listing is authed; mirror how the Phase-2 admin commands call `connection::reauth`):

```rust
use crate::commands::connection::reauth;
use crate::http_client::get_json;

/// `list_feed` — the D35 listing (api.md §8.6). Authed; carries no values. The
/// type filter is applied server-side; sort is client-side. `server_id` doubles
/// as the connect host the channel was opened against (Phase-1 connect stored it).
#[tauri::command]
pub async fn list_feed(
    req: ListFeedRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<FeedEntryDto>, UiError> {
    let server = {
        let s = session.0.lock().await;
        s.server_id.clone()
    };
    if server.is_empty() {
        return Err(UiError::new("offline", "Connect to a server first."));
    }
    let (mut sender, _host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let limit = req.limit.unwrap_or(50).min(200);
    let uri = match filter_param(req.filter) {
        Some(t) => format!("/v1/files?type={t}&limit={limit}"),
        None => format!("/v1/files?limit={limit}"),
    };
    let (status, json) = get_json(&mut sender, &uri, Some(&token)).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("feed_failed", "Could not load the feed."));
    }
    let mut entries: Vec<FeedEntryDto> = json["files"]
        .as_array()
        .map(|a| a.iter().filter_map(entry_from_json).collect())
        .unwrap_or_default();
    sort_entries(&mut entries, req.sort);
    Ok(entries)
}
```

> Confirm `reauth`'s signature/return tuple (`(sender, host, token)`) and the `server_id`/connect-host relationship by reading `commands/connection.rs` (the Phase-2 admin commands already use this exact pattern). The connect host the channel is opened against is what Phase-1 stored — reuse it; do not re-derive.

- [ ] **Step 5: Remove the stub + register the command**

In `crates/client-app/src/commands/stubs.rs` delete the `list_feed` stub fn + its test (the module may become empty; if so, leave a doc comment or delete the module and its `mod stubs;` declaration — check `main.rs`/`commands/mod.rs`). In `main.rs` change the registration from `commands::stubs::list_feed` to `commands::feed::list_feed`.

- [ ] **Step 6: Build + test**

Run: `cargo test -p maxsecu-client-app commands::feed::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 7: Commit**

```bash
git add crates/client-app/src
git commit -m "feat(client-app): real list_feed (D35 listing) replacing the stub"
```

---

## Task 7: `decrypt_card` command (title + tags + thumbnail, verified)

**Files:**
- Modify: `crates/client-app/src/commands/feed.rs`, `crates/client-app/src/dto.rs`, `crates/client-app/src/main.rs`

Decrypt one feed item's **card**: fetch the §8.5 view, resolve+verify the author binding under the pinned D5, build a header-only `StreamHeader`, run `verify_and_open_headers`, then parse the `metadata` plaintext into a **title + tags** and pass the `thumbnail` plaintext (a small canonical PNG) as a base64 image. Compute `mine` by comparing the author to my resolved `user_id`. No content stream is fetched.

- [ ] **Step 1: Decide the metadata encoding + add the DTO**

The upload metadata stream is a small plaintext blob (see `file_e2e.rs`, which used `b"title=fox"` / `FILENAME`). Phase 3 standardizes it as **UTF-8 JSON** `{"title": "...", "tags": ["..."]}` with a tolerant fallback: if the bytes are not that JSON, treat the whole UTF-8 string as the title and no tags (so older `title=…`/filename blobs still render a title). This same shape is what Phase 4's upload will write.

In `crates/client-app/src/dto.rs` add:

```rust
/// A decrypted, verified feed card — render-ready, no key material.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CardDto {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub title: String,
    pub tags: Vec<String>,
    /// A small canonical-PNG thumbnail as standard base64, or `None` if the item
    /// has no thumbnail stream (e.g. a blog). The UI renders it via a `data:` URL.
    pub thumbnail_b64: Option<String>,
    /// `true` if this user authored the file (drives the "only my uploads" filter).
    pub mine: bool,
    /// A short fingerprint hex (first 8 bytes) of the verified author identity —
    /// a non-secret verification tick for the UI.
    pub author_fp: String,
    /// Whether a valid author recovery grant was present (anomaly flag, not fatal).
    pub recovery_ok: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardRequest {
    pub file_id: String,
}
```

- [ ] **Step 2: Write the failing test (the metadata parser)**

Add to `crates/client-app/src/commands/feed.rs` tests:

```rust
    #[test]
    fn parses_metadata_json_then_falls_back() {
        let (t, tags) = super::parse_title_tags(br#"{"title":"Sunset","tags":["beach","2026"]}"#);
        assert_eq!(t, "Sunset");
        assert_eq!(tags, vec!["beach".to_owned(), "2026".to_owned()]);
        // Non-JSON ⇒ whole string is the title, no tags.
        let (t2, tags2) = super::parse_title_tags(b"title=fox");
        assert_eq!(t2, "title=fox");
        assert!(tags2.is_empty());
        // Invalid UTF-8 ⇒ a safe placeholder title.
        let (t3, tags3) = super::parse_title_tags(&[0xff, 0xfe]);
        assert_eq!(t3, "(untitled)");
        assert!(tags3.is_empty());
    }
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test -p maxsecu-client-app commands::feed::tests::parses_metadata_json_then_falls_back`
Expected: FAIL (no `parse_title_tags`).

- [ ] **Step 4: Implement the parser + the command**

Add the parser + the command to `crates/client-app/src/commands/feed.rs`:

```rust
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_client_core::{verify_and_open_headers, DirectoryVerifier, Identity, MemoryTrustStore, VerifyContext, NO_ADMINS, NO_GRANTERS};
use maxsecu_encoding::structs::{Genesis, Manifest};
use maxsecu_encoding::types::{Id, RecipientType, StreamType};
use maxsecu_encoding::decode;

use crate::config::load_directory_pub;
use crate::directory::resolve_and_verify_author;
use crate::download::{build_stream_header, parse_file_view};
use crate::dto::{CardDto, CardRequest};

/// Parse the metadata plaintext into `(title, tags)`. Tolerant: JSON
/// `{title,tags}` preferred; any other UTF-8 ⇒ that string is the title; non-UTF-8
/// ⇒ `(untitled)`. (Phase 4 uploads write the JSON form.)
pub(crate) fn parse_title_tags(meta: &[u8]) -> (String, Vec<String>) {
    #[derive(serde::Deserialize)]
    struct Meta {
        title: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
    }
    match std::str::from_utf8(meta) {
        Ok(s) => match serde_json::from_str::<Meta>(s) {
            Ok(m) if m.title.is_some() => (m.title.unwrap(), m.tags),
            _ => (s.to_owned(), Vec::new()),
        },
        Err(_) => ("(untitled)".to_owned(), Vec::new()),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex16(s: &str) -> Result<[u8; 16], UiError> {
    let bad = || UiError::new("fetch_failed", "Malformed file id.");
    if s.len() != 32 {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `decrypt_card` — fetch + verify one item's card (title/tags/thumbnail), header-
/// only (no content fetch). Verifies the author binding under the pinned D5, runs
/// the §12.5 header ladder, and returns render-ready metadata. Sanitized errors.
#[tauri::command]
pub async fn decrypt_card(
    req: CardRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<CardDto, UiError> {
    let file_id = hex16(&req.file_id)?;
    let pinned = load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();

    let (server, username) = {
        let s = session.0.lock().await;
        (s.server_id.clone(), s.username.clone())
    };
    if server.is_empty() {
        return Err(UiError::new("offline", "Connect to a server first."));
    }
    let username = username.ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    let (mut sender, _host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;

    // The §8.5 view (carries the manifest/genesis/wrap/streams).
    let (status, view_json) =
        get_json(&mut sender, &format!("/v1/files/{}?version=latest", req.file_id), Some(&token)).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("fetch_failed", "That item is not available."));
    }
    let view = parse_file_view(&view_json)?;

    // Resolve the author + owner under the pinned D5 (Phase 3: author == owner).
    let manifest: Manifest =
        decode(&view.manifest_bytes).map_err(|_| UiError::new("untrusted", "Malformed record."))?;
    let author = resolve_and_verify_author(&mut sender, &hex(&manifest.author_id.0), &verifier, &mut trust, now).await?;

    // Who am I? (for the "mine" flag). Best-effort: a failure leaves mine=false.
    let my_id = crate::directory::resolve_my_user_id(&mut sender, &username, &verifier, &mut trust, now)
        .await
        .ok();

    // Identity to unwrap my own wrap (I am the recipient of my_wrap).
    let identity = {
        let mut s = session.0.lock().await;
        s.identity.take().ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?
    };
    let result = decrypt_card_inner(&identity, file_id, &author, &view, &mut sender, &token, my_id).await;
    session.0.lock().await.identity = Some(identity); // restore on every path
    let (title, tags, thumb, recovery_ok, mine) = result?;

    Ok(CardDto {
        file_id: req.file_id,
        file_type: file_type_name(manifest.file_type),
        version: view.version,
        title,
        tags,
        thumbnail_b64: thumb,
        mine,
        author_fp: hex(&author.fingerprint[..8]),
        recovery_ok,
    })
}

fn file_type_name(t: maxsecu_encoding::types::FileType) -> String {
    use maxsecu_encoding::types::FileType;
    match t {
        FileType::Image => "image",
        FileType::Video => "video",
        FileType::Blog => "blog",
    }
    .to_owned()
}

#[allow(clippy::too_many_arguments)]
async fn decrypt_card_inner(
    identity: &Identity,
    file_id: [u8; 16],
    author: &crate::directory::VerifiedAuthor,
    view: &crate::download::ParsedView,
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
    token: &str,
    my_id: Option<[u8; 16]>,
    file_id_hex_dummy: (),
) -> Result<(String, Vec<String>, Option<String>, bool, bool), UiError> {
    let _ = file_id_hex_dummy;
    let header = build_stream_header(sender, token, &hex(&file_id), view).await?;
    let ctx = VerifyContext {
        file_id: Id(file_id),
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id.unwrap_or(author.user_id)),
        recipient_type: RecipientType::User,
        recipient_secret: identity.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened = verify_and_open_headers(&ctx, &header)
        .map_err(|_| UiError::new("verify_failed", "This item failed verification."))?;
    let title_tags = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .map(|s| parse_title_tags(&s.plaintext))
        .unwrap_or_else(|| ("(untitled)".to_owned(), Vec::new()));
    let thumb = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Thumbnail)
        .map(|s| B64.encode(&s.plaintext));
    let mine = my_id.map(|id| id == author.user_id).unwrap_or(false);
    Ok((title_tags.0, title_tags.1, thumb, opened.recovery_grant_ok, mine))
}
```

> **Engineer note:** the `recipient_id` for the verify ctx must be **my own** `user_id` (I am the recipient of `my_wrap`). The `decrypt_card_inner` signature above carries a stray `file_id_hex_dummy: ()` purely to keep the example arg list explicit — **remove it** and the `let _ =` line when implementing; it is not part of the design. Confirm `Identity::enc_secret()` returns `&EncSecretKey` (it does — see `client-core` `download.rs` tests) and that `FileType`/`Manifest.author_id`/`Genesis.owner_id` field names match `maxsecu_encoding::structs`/`types` (read them). The `Genesis` import is unused if you don't cross-check owner==author; you may drop it.

- [ ] **Step 5: Register + build + test**

Register `commands::feed::decrypt_card` in `main.rs`'s `invoke_handler!`.
Run: `cargo test -p maxsecu-client-app commands::feed::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds. Fix the `decrypt_card_inner` signature (drop the dummy arg) so it compiles cleanly.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src crates/client-app/src/main.rs
git commit -m "feat(client-app): decrypt_card (verified title/tags/thumbnail, header-only)"
```

---

## Task 8: Local encrypted search index + `search_local`/`reindex`

**Files:**
- Create: `crates/client-app/src/index.rs`, `crates/client-app/src/commands/search.rs`
- Modify: `crates/client-app/src/dto.rs`, `crates/client-app/src/commands/mod.rs`, `crates/client-app/src/lib.rs`, `crates/client-app/src/main.rs`

Client-side title+tag search over a **local encrypted index** (D-F). The index lives in the TCB; it is persisted to `<dir>/index/search.idx` **sealed** with a key derived from the unlocked identity, and searched in the backend (the UI gets only `SearchHit`s). `reindex()` rebuilds it from the decrypted cards the session has seen; `search_local(query)` runs a case-insensitive substring match over titles + tags.

- [ ] **Step 1: Read `crates/crypto/src/lib.rs`** to find the existing symmetric AEAD seal/open + a key-derivation helper (the same primitives `keyblob` uses). Bind the index crypto to those exact functions — do **not** introduce a new cipher. Note the names you will use (e.g. an `seal(key, aad, plaintext)`/`open(...)` pair and a labeled `derive`/HKDF). If no general AEAD is exposed, reuse `keyblob::{seal,open}` with an index-specific label, or `Dek`/`stream_subkey`. Record the chosen primitive in a one-line comment at the top of `index.rs`.

- [ ] **Step 2: Add the DTO + write the failing test (pure index logic)**

In `crates/client-app/src/dto.rs` add:

```rust
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SearchHit {
    pub file_id: String,
    pub title: String,
    pub file_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchRequest {
    pub query: String,
}
```

`crates/client-app/src/index.rs`:

```rust
//! The local title+tag search index (D-F). In-RAM in the TCB; persisted to
//! `<dir>/index/search.idx` ENCRYPTED with a key derived from the unlocked
//! identity (see Step 1 for the exact crypto primitive). Only `SearchHit`s of
//! matches ever leave the TCB — never the whole index.

use serde::{Deserialize, Serialize};

use crate::dto::SearchHit;

/// One indexed item: the searchable title + tags + the type, keyed by file id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexEntry {
    pub file_id: String,
    pub file_type: String,
    pub title: String,
    pub tags: Vec<String>,
}

/// The in-RAM index (also the on-disk plaintext-before-sealing shape).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchIndex {
    pub entries: Vec<IndexEntry>,
}

impl SearchIndex {
    /// Insert or replace the entry for `file_id`.
    pub fn upsert(&mut self, entry: IndexEntry) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.file_id == entry.file_id) {
            *e = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Case-insensitive substring match over title + tags. Empty query ⇒ all.
    pub fn search(&self, query: &str) -> Vec<SearchHit> {
        let q = query.trim().to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                q.is_empty()
                    || e.title.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .map(|e| SearchHit {
                file_id: e.file_id.clone(),
                title: e.title.clone(),
                file_type: e.file_type.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx() -> SearchIndex {
        let mut i = SearchIndex::default();
        i.upsert(IndexEntry { file_id: "aa".into(), file_type: "image".into(), title: "Sunset Beach".into(), tags: vec!["beach".into(), "2026".into()] });
        i.upsert(IndexEntry { file_id: "bb".into(), file_type: "blog".into(), title: "My Notes".into(), tags: vec!["draft".into()] });
        i
    }

    #[test]
    fn searches_title_and_tags_case_insensitively() {
        let i = idx();
        assert_eq!(i.search("sunset").len(), 1);
        assert_eq!(i.search("BEACH")[0].file_id, "aa");
        assert_eq!(i.search("draft")[0].file_id, "bb");
        assert_eq!(i.search("").len(), 2); // empty ⇒ all
        assert!(i.search("nonexistent").is_empty());
    }

    #[test]
    fn upsert_replaces_by_file_id() {
        let mut i = idx();
        i.upsert(IndexEntry { file_id: "aa".into(), file_type: "image".into(), title: "Renamed".into(), tags: vec![] });
        assert_eq!(i.entries.len(), 2);
        assert_eq!(i.search("renamed")[0].file_id, "aa");
        assert!(i.search("sunset").is_empty());
    }
}
```

- [ ] **Step 3: Run it to verify it fails, then passes**

Add `pub mod index;` to `crates/client-app/src/lib.rs`.
Run: `cargo test -p maxsecu-client-app index::tests`
Expected: PASS once the module compiles.

- [ ] **Step 4: Add sealed persistence (round-trip test first)**

Add to `crates/client-app/src/index.rs` a `load`/`save` pair using the crypto primitive chosen in Step 1, plus a round-trip test. Concretely (adapt the fn names to the real crypto API found in Step 1):

```rust
use std::path::Path;

use maxsecu_client_core::Identity;

use crate::error::UiError;

/// Derive the 32-byte index-sealing key from the unlocked identity (a stable TCB
/// secret), domain-separated by a fixed label so it is unrelated to any wrap key.
fn index_key(identity: &Identity) -> [u8; 32] {
    // Use the crypto crate's labeled derivation found in Step 1, e.g.:
    //   maxsecu_crypto::derive_subkey(identity.enc_secret_bytes(), b"MaxSecu-search-index-v1")
    // Bind to the REAL helper name; this must be deterministic for the identity.
    todo!("bind to the crypto derive primitive from Step 1")
}

/// Load + decrypt the index from `<dir>/index/search.idx`, or an empty index if
/// absent. A decryption failure is a sanitized error (corrupt/foreign index).
pub fn load(dir: &Path, identity: &Identity) -> Result<SearchIndex, UiError> {
    let path = dir.join("index").join("search.idx");
    let sealed = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return Ok(SearchIndex::default()),
    };
    let key = index_key(identity);
    let plain = maxsecu_crypto_open(&key, &sealed)
        .map_err(|_| UiError::new("index_failed", "The search index could not be read."))?;
    serde_json::from_slice(&plain).map_err(|_| UiError::new("index_failed", "Corrupt search index."))
}

/// Encrypt + persist the index to `<dir>/index/search.idx` (creates `index/`).
pub fn save(dir: &Path, identity: &Identity, index: &SearchIndex) -> Result<(), UiError> {
    let idx_dir = dir.join("index");
    std::fs::create_dir_all(&idx_dir).map_err(|_| UiError::new("index_failed", "Could not write the index."))?;
    let plain = serde_json::to_vec(index).map_err(|_| UiError::new("index_failed", "Could not encode the index."))?;
    let key = index_key(identity);
    let sealed = maxsecu_crypto_seal(&key, &plain);
    std::fs::write(idx_dir.join("search.idx"), sealed)
        .map_err(|_| UiError::new("index_failed", "Could not write the index."))
}
```

Replace `maxsecu_crypto_seal`/`maxsecu_crypto_open`/`index_key`'s body with the **real** crypto primitives from Step 1 (delete the `todo!`). Then add the round-trip test:

```rust
    #[test]
    fn sealed_index_round_trips_and_is_not_plaintext() {
        let id = maxsecu_client_core::Identity::generate();
        let tmp = std::env::temp_dir().join(format!("mxidx_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut i = SearchIndex::default();
        i.upsert(IndexEntry { file_id: "aa".into(), file_type: "blog".into(), title: "SECRET_TITLE_MARKER".into(), tags: vec!["t".into()] });
        save(&tmp, &id, &i).unwrap();
        // On-disk bytes must not contain the plaintext title.
        let raw = std::fs::read(tmp.join("index").join("search.idx")).unwrap();
        assert!(!raw.windows(b"SECRET_TITLE_MARKER".len()).any(|w| w == b"SECRET_TITLE_MARKER"));
        // A fresh load with the same identity reproduces the index.
        let back = load(&tmp, &id).unwrap();
        assert_eq!(back, i);
        // A different identity cannot read it.
        let other = maxsecu_client_core::Identity::generate();
        assert!(load(&tmp, &other).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }
```

> If the crypto AEAD requires a nonce, generate a random nonce, prepend it to the sealed bytes, and split it back off on `open` (document this in a comment). If you reuse `keyblob::{seal,open}`, follow its exact in/out shape. The behavioral contract is: round-trips for the same identity, unreadable by another, and the plaintext title never appears in the file.

- [ ] **Step 5: Add the commands**

`crates/client-app/src/commands/search.rs`:

```rust
//! Search commands over the local encrypted index (D-F). `reindex` rebuilds the
//! index from the current feed (decrypting each card in the TCB); `search_local`
//! returns only `SearchHit`s of matches.

use tauri::State;

use crate::commands::auth::{AppDir, Session};
use crate::dto::{SearchHit, SearchRequest};
use crate::error::UiError;
use crate::index;

/// `search_local` — case-insensitive title+tag search over the local index.
#[tauri::command]
pub async fn search_local(
    req: SearchRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
) -> Result<Vec<SearchHit>, UiError> {
    let identity_present = { session.0.lock().await.identity.is_some() };
    if !identity_present {
        return Err(UiError::new("locked", "Unlock your keystore first."));
    }
    // Borrow the identity transiently to derive the index key, then restore.
    let id = { session.0.lock().await.identity.take() }
        .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
    let result = index::load(&dir.0, &id).map(|idx| idx.search(&req.query));
    session.0.lock().await.identity = Some(id);
    result
}
```

> `reindex` (rebuilding the index by decrypting every feed card) is heavier and can be added as a follow-up command if convenient; the core deliverable is the encrypted index + `search_local` over what `decrypt_card` upserts. If you wire `decrypt_card` (Task 7) to also `index::load` → `upsert` → `index::save` after a successful decode, the index fills as the user browses — add a one-line call there guarded so an index failure never fails the card (log/ignore, return the card). Keep that addition minimal and covered by the e2e.

`commands/mod.rs`: add `pub mod search;`. `main.rs`: register `commands::search::search_local`.

- [ ] **Step 6: Build + test**

Run: `cargo test -p maxsecu-client-app index:: commands::search::` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 7: Commit**

```bash
git add crates/client-app/src
git commit -m "feat(client-app): local encrypted title+tag search index + search_local"
```

---

## Task 9: Fetch/decrypt feedback state machine + `open_content` viewer command

**Files:**
- Modify: `crates/client-app/src/state.rs`, `crates/client-app/src/dto.rs`, `crates/client-app/src/main.rs`
- Create: `crates/client-app/src/commands/viewer.rs`
- Modify: `crates/client-app/src/commands/mod.rs`

`open_content` is the viewer command: it fetches the full file, verifies+decrypts via `verify_and_open`, and returns the **content to display** — for an image, the canonical PNG bytes (base64, rendered via a `data:` URL); for a blog, the sanitized UTF-8 text. It drives a typed `FetchPhase` state machine emitted over `EVT_FETCH` so the UI shows fetching/verifying/decrypting/ready/failed.

- [ ] **Step 1: Add the state machine (failing test)**

Add to `crates/client-app/src/state.rs`:

```rust
/// The fetch/decrypt feedback channel (spec §6) — per-file progress for the
/// viewer + cards. Emitted over the Tauri event bus; the UI binds a progress
/// meter + per-item badge. Non-color-only: each variant carries a stable code.
pub const EVT_FETCH: &str = "maxsecu://fetch-state";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase")]
pub enum FetchPhase {
    /// Fetching ciphertext (optionally with cold-fetch progress from §9.3).
    Fetching {
        file_id: String,
        fetched: u64,
        total: u64,
    },
    /// Running the §12.5 verify ladder.
    Verifying { file_id: String },
    /// Decrypting the verified streams.
    Decrypting { file_id: String },
    /// Done — the content is ready to render.
    Ready { file_id: String },
    /// Failed with a sanitized code (no oracle).
    Failed { file_id: String, code: String },
}

#[cfg(test)]
mod fetch_tests {
    use super::*;

    #[test]
    fn fetch_phase_serializes_kebab_tagged() {
        let v = FetchPhase::Verifying { file_id: "aa".into() };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"phase\":\"verifying\""));
        assert!(s.contains("\"file_id\":\"aa\""));
    }
}
```

- [ ] **Step 2: Run it to verify it passes**

Run: `cargo test -p maxsecu-client-app state::fetch_tests`
Expected: PASS.

- [ ] **Step 3: Add the viewer DTO**

In `crates/client-app/src/dto.rs` add:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct OpenContentRequest {
    pub file_id: String,
}

/// The verified, decrypted content to display. Exactly one of `image_png_b64` /
/// `blog_text` is set per `file_type`. No key material; the content shown is the
/// product, not a TCB leak.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OpenedContentDto {
    pub file_id: String,
    pub file_type: String,
    pub version: u64,
    pub title: String,
    pub tags: Vec<String>,
    /// For an image: the canonical PNG as standard base64 (UI → `data:image/png`).
    pub image_png_b64: Option<String>,
    /// For a blog: the sanitized UTF-8 text.
    pub blog_text: Option<String>,
    pub author_fp: String,
    pub recovery_ok: bool,
}
```

- [ ] **Step 4: Write the failing test (the content shaper)**

The pure "shape opened streams into a DTO body" logic is unit-testable without network. Add to `crates/client-app/src/commands/viewer.rs`:

```rust
//! The viewer command: verify + decrypt a file's content and return it render-
//! ready (image PNG to display, or sanitized blog text). Drives the FetchPhase
//! feedback machine. The content shown is the product; no keys/grants cross.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_client_core::{sanitize_blog_text_or_self, OpenedStream}; // see note on the sanitizer
use maxsecu_encoding::types::{FileType, StreamType};

use crate::error::UiError;

/// Shape the decrypted streams into the content body for `file_type`. For an
/// image, the content stream is the canonical PNG (base64). For a blog, the
/// content is sanitized UTF-8 text. Pure — unit-tested.
pub(crate) fn shape_content(
    file_type: FileType,
    streams: &[OpenedStream],
) -> Result<(Option<String>, Option<String>), UiError> {
    let content = streams
        .iter()
        .find(|s| s.stream_type == StreamType::Content)
        .ok_or_else(|| UiError::new("verify_failed", "Missing content."))?;
    match file_type {
        FileType::Image => Ok((Some(B64.encode(&content.plaintext)), None)),
        FileType::Blog => {
            let text = String::from_utf8(content.plaintext.clone())
                .map_err(|_| UiError::new("verify_failed", "Unreadable blog content."))?;
            Ok((None, Some(sanitize_blog(&text))))
        }
        FileType::Video => Err(UiError::new("codec_unavailable", "Video playback is not enabled yet.")),
    }
}

/// Minimal blog sanitization for display: strip control chars except newlines/
/// tabs. (The viewer renders this as TEXT, never as HTML — see media-viewer.ts.)
fn sanitize_blog(s: &str) -> String {
    s.chars().filter(|c| *c == '\n' || *c == '\t' || !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(t: StreamType, p: &[u8]) -> OpenedStream {
        OpenedStream { stream_type: t, plaintext: p.to_vec() }
    }

    #[test]
    fn image_content_is_base64_png() {
        let png = [0x89, 0x50, 0x4E, 0x47, 1, 2, 3];
        let (img, blog) = shape_content(FileType::Image, &[stream(StreamType::Content, &png)]).unwrap();
        assert_eq!(img.unwrap(), B64.encode(png));
        assert!(blog.is_none());
    }

    #[test]
    fn blog_content_is_sanitized_text() {
        let (img, blog) = shape_content(FileType::Blog, &[stream(StreamType::Content, b"Hello\x07 world\n")]).unwrap();
        assert!(img.is_none());
        assert_eq!(blog.unwrap(), "Hello world\n"); // the BEL control char stripped
    }

    #[test]
    fn video_is_codec_unavailable() {
        let err = shape_content(FileType::Video, &[stream(StreamType::Content, b"x")]).unwrap_err();
        assert_eq!(err.code, "codec_unavailable");
    }
}
```

> **Sanitizer note:** the import `sanitize_blog_text_or_self` is illustrative — `client-core` already exposes `sanitize`/`safe_export_path`/`sanitize_filename` (see `client-core` `lib.rs`). Check whether a blog-text sanitizer exists there and prefer it; otherwise the local `sanitize_blog` above is the Phase-3 path (text-only render, never HTML — the real defense is that the UI sets `textContent`, not `innerHTML`). Remove the unused import if you use the local helper.

- [ ] **Step 5: Run it to verify it fails, then passes**

Add `pub mod viewer;` to `crates/client-app/src/commands/mod.rs`.
Run: `cargo test -p maxsecu-client-app commands::viewer::tests`
Expected: PASS once the module compiles.

- [ ] **Step 6: Add the command (full fetch + verify + emit events)**

Append the command to `crates/client-app/src/commands/viewer.rs`. It mirrors `decrypt_card` but builds a **full** `DownloadBundle` and calls `verify_and_open`, emitting `FetchPhase` over `EVT_FETCH` at each stage:

```rust
use tauri::{Emitter, State};

use maxsecu_client_core::{verify_and_open, DirectoryVerifier, Identity, MemoryTrustStore, VerifyContext, NO_ADMINS, NO_GRANTERS};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::Id;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::reauth;
use crate::commands::feed::file_type_name; // reuse (make it pub(crate) in feed.rs)
use crate::config::load_directory_pub;
use crate::directory::resolve_and_verify_author;
use crate::download::{build_download_bundle, parse_file_view};
use crate::dto::{OpenContentRequest, OpenedContentDto};
use crate::http_client::get_json;
use crate::state::{FetchPhase, EVT_FETCH};

#[tauri::command]
pub async fn open_content(
    req: OpenContentRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<OpenedContentDto, UiError> {
    let emit = |p: FetchPhase| { let _ = app.emit(EVT_FETCH, p); };
    let fid = req.file_id.clone();
    let out = open_content_inner(&req, &dir, &session, &connect_lock, &emit).await;
    if let Err(e) = &out {
        emit(FetchPhase::Failed { file_id: fid, code: e.code.clone() });
    }
    out
}

async fn open_content_inner(
    req: &OpenContentRequest,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    emit: &impl Fn(FetchPhase),
) -> Result<OpenedContentDto, UiError> {
    let pinned = load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);

    let (server, username) = { let s = session.0.lock().await; (s.server_id.clone(), s.username.clone()) };
    if server.is_empty() {
        return Err(UiError::new("offline", "Connect to a server first."));
    }
    let username = username.ok_or_else(|| UiError::new("locked", "Sign in first."))?;
    let (mut sender, _host, token) = reauth(&dir.0, &server, session, connect_lock).await?;

    emit(FetchPhase::Fetching { file_id: req.file_id.clone(), fetched: 0, total: 0 });
    let (status, view_json) = get_json(&mut sender, &format!("/v1/files/{}?version=latest", req.file_id), Some(&token)).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("fetch_failed", "That item is not available."));
    }
    let view = parse_file_view(&view_json)?;
    let manifest: Manifest = decode(&view.manifest_bytes).map_err(|_| UiError::new("untrusted", "Malformed record."))?;
    let author = resolve_and_verify_author(&mut sender, &hex(&manifest.author_id.0), &verifier, &mut trust, now).await?;
    let my_id = crate::directory::resolve_my_user_id(&mut sender, &username, &verifier, &mut trust, now).await.ok();

    let bundle = build_download_bundle(&mut sender, &token, &req.file_id, &view).await?;

    let identity = { session.0.lock().await.identity.take() }
        .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
    emit(FetchPhase::Verifying { file_id: req.file_id.clone() });
    let opened_res = run_open(&identity, &manifest, &author, my_id, &bundle);
    session.0.lock().await.identity = Some(identity);
    emit(FetchPhase::Decrypting { file_id: req.file_id.clone() });
    let opened = opened_res?;

    let (img, blog) = shape_content(manifest.file_type, &opened.streams)?;
    let (title, tags) = opened
        .streams
        .iter()
        .find(|s| s.stream_type == maxsecu_encoding::types::StreamType::Metadata)
        .map(|s| crate::commands::feed::parse_title_tags(&s.plaintext))
        .unwrap_or_else(|| ("(untitled)".to_owned(), Vec::new()));

    emit(FetchPhase::Ready { file_id: req.file_id.clone() });
    Ok(OpenedContentDto {
        file_id: req.file_id.clone(),
        file_type: file_type_name(manifest.file_type),
        version: opened.version,
        title,
        tags,
        image_png_b64: img,
        blog_text: blog,
        author_fp: hex(&author.fingerprint[..8]),
        recovery_ok: opened.recovery_grant_ok,
    })
}

fn run_open(
    identity: &Identity,
    manifest: &Manifest,
    author: &crate::directory::VerifiedAuthor,
    my_id: Option<[u8; 16]>,
    bundle: &maxsecu_client_core::DownloadBundle,
) -> Result<maxsecu_client_core::OpenedFile, UiError> {
    let ctx = VerifyContext {
        file_id: manifest.file_id,
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id.unwrap_or(author.user_id)),
        recipient_type: maxsecu_encoding::types::RecipientType::User,
        recipient_secret: identity.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    verify_and_open(&ctx, bundle).map_err(|_| UiError::new("verify_failed", "This item failed verification."))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
```

> Make `parse_title_tags` and `file_type_name` `pub(crate)` in `feed.rs` so `viewer.rs` reuses them (DRY). Confirm `Manifest.file_id`/`author_id` field names and `OpenedFile`/`OpenedStream` shapes against `client-core`. The `now` access pattern is duplicated across feed/viewer — optionally factor a `crate::util::now_ms()`; keep it tiny.

- [ ] **Step 7: Register + build + test**

Register `commands::viewer::open_content` in `main.rs`.
Run: `cargo test -p maxsecu-client-app` then `cargo build -p maxsecu-client-app`
Expected: PASS / builds.

- [ ] **Step 8: Commit**

```bash
git add crates/client-app/src
git commit -m "feat(client-app): open_content viewer + FetchPhase feedback state machine"
```

---

## Task 10: UI — DTO types, shared feedback components, CSP for images

**Files:**
- Modify: `crates/client-app/ui/src/core/types.ts`
- Create: `crates/client-app/ui/src/components/state-badge.ts`, `crates/client-app/ui/src/components/progress-meter.ts`
- Modify: the UI CSP source (`crates/client-app/ui/index.html` or wherever the `Content-Security-Policy` meta/tauri config lives — grep for `Content-Security-Policy` / `img-src`)

- [ ] **Step 1: Add TS DTO mirrors**

In `crates/client-app/ui/src/core/types.ts` add (match the Rust serde shapes exactly — kebab-case enums, snake_case fields):

```ts
export type FeedFilter = "all" | "image" | "video" | "blog";
export type FeedSort = "newest-first" | "oldest-first";

export interface FeedEntry {
  file_id: string;
  file_type: string;
  version: number;
  updated_at: number;
  has_thumbnail: boolean;
}

export interface Card {
  file_id: string;
  file_type: string;
  version: number;
  title: string;
  tags: string[];
  thumbnail_b64: string | null;
  mine: boolean;
  author_fp: string;
  recovery_ok: boolean;
}

export interface OpenedContent {
  file_id: string;
  file_type: string;
  version: number;
  title: string;
  tags: string[];
  image_png_b64: string | null;
  blog_text: string | null;
  author_fp: string;
  recovery_ok: boolean;
}

export interface SearchHit { file_id: string; title: string; file_type: string }

export type FetchMsg =
  | { phase: "fetching"; file_id: string; fetched: number; total: number }
  | { phase: "verifying"; file_id: string }
  | { phase: "decrypting"; file_id: string }
  | { phase: "ready"; file_id: string }
  | { phase: "failed"; file_id: string; code: string };
```

- [ ] **Step 2: Write `state-badge.ts`** (non-color-only: icon glyph + text; ARIA)

```ts
// A per-item status badge. Non-color-only (WCAG 1.4.1): a text label + a glyph,
// not color alone. `state` is one of the FetchMsg phases or a card state.
export class StateBadge extends HTMLElement {
  static get observedAttributes() { return ["state", "label"]; }
  attributeChangedCallback() { this.render(); }
  connectedCallback() { this.render(); }
  private render() {
    const state = this.getAttribute("state") ?? "idle";
    const label = this.getAttribute("label") ?? state;
    const glyph: Record<string, string> = {
      idle: "•", fetching: "⏳", verifying: "🔎", decrypting: "🔐",
      ready: "✓", failed: "⚠", verified: "✓",
    };
    this.setAttribute("role", "status");
    this.setAttribute("data-state", state);
    this.textContent = `${glyph[state] ?? "•"} ${label}`;
  }
}
customElements.define("state-badge", StateBadge);
```

- [ ] **Step 3: Write `progress-meter.ts`** (%, optional ETA/speed text; ARIA `progressbar`)

```ts
// A progress meter with a textual percentage (non-color-only) and an ARIA
// progressbar. Set `value`/`max` (and optional `detail` text). 0/0 ⇒ indeterminate.
export class ProgressMeter extends HTMLElement {
  static get observedAttributes() { return ["value", "max", "detail"]; }
  attributeChangedCallback() { this.render(); }
  connectedCallback() { this.render(); }
  private render() {
    const value = Number(this.getAttribute("value") ?? "0");
    const max = Number(this.getAttribute("max") ?? "0");
    const detail = this.getAttribute("detail") ?? "";
    const pct = max > 0 ? Math.round((value / max) * 100) : null;
    this.setAttribute("role", "progressbar");
    if (pct !== null) {
      this.setAttribute("aria-valuenow", String(pct));
      this.setAttribute("aria-valuemin", "0");
      this.setAttribute("aria-valuemax", "100");
      this.textContent = `${pct}%${detail ? ` — ${detail}` : ""}`;
    } else {
      this.removeAttribute("aria-valuenow");
      this.textContent = detail || "Working…";
    }
  }
}
customElements.define("progress-meter", ProgressMeter);
```

- [ ] **Step 4: Allow `data:` images in the CSP**

Grep the UI for the CSP source: `Content-Security-Policy`. Update `img-src` to include `data:` (so decrypted PNGs render as `data:image/png;base64,…`), keeping everything else as restrictive as it is. E.g. `img-src 'self' data:;`. If the CSP lives in `tauri.conf.json`'s `app.security.csp`, edit it there; if in `ui/index.html` `<meta http-equiv="Content-Security-Policy">`, edit there. Do NOT broaden `script-src`.

- [ ] **Step 5: Typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: clean bundle (esbuild + tsc).

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/ui
git commit -m "feat(ui): feedback components (state-badge, progress-meter), DTO types, img-src data: CSP"
```

---

## Task 11: UI — `<feed-screen>` (grid, filter, sort, my-uploads, search)

**Files:**
- Create: `crates/client-app/ui/src/components/feed-screen.ts`
- Modify: `crates/client-app/ui/src/components/app-shell.ts`

Replace the placeholder `<feed-empty>` route with a real feed: a search box (title+tags), a Type filter, a Sort control, an "Only my uploads" toggle, and a grid of `<media-card>`s (Task 12). Accessible: landmark `#main`, labelled controls, `role="status"` for loading/empty/error, focus to `#main` on mount.

- [ ] **Step 1: Write `feed-screen.ts`**

```ts
import { call } from "../core/rpc.ts";
import type { FeedEntry, FeedFilter, FeedSort, SearchHit } from "../core/types.ts";
import "./media-card.ts";
import "./state-badge.ts";

// Feed / Library (spec §5). Lists accessible content; filter by type, sort, search
// titles+tags (client-side over the local index), and "only my uploads". Each item
// is a <media-card> that decrypts itself. Empty/loading/error are first-class.
export class FeedScreen extends HTMLElement {
  private filter: FeedFilter = "all";
  private sort: FeedSort = "newest-first";
  private mineOnly = false;

  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="fd-h">
        <h1 id="fd-h">Feed</h1>
        <form id="controls" role="search">
          <label>Search <input name="q" type="search" autocomplete="off"
            aria-describedby="fd-status" /></label>
          <label>Type
            <select name="type">
              <option value="all">All</option>
              <option value="image">Images</option>
              <option value="blog">Blogs</option>
              <option value="video">Video</option>
            </select></label>
          <label>Sort
            <select name="sort">
              <option value="newest-first">Newest first</option>
              <option value="oldest-first">Oldest first</option>
            </select></label>
          <label><input type="checkbox" name="mine" /> Only my uploads</label>
        </form>
        <p id="fd-status" role="status" aria-live="polite">Loading…</p>
        <div id="grid" role="list"></div>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();
    const form = this.querySelector("#controls") as HTMLFormElement;
    form.addEventListener("change", () => {
      const d = new FormData(form);
      this.filter = (d.get("type") as FeedFilter) ?? "all";
      this.sort = (d.get("sort") as FeedSort) ?? "newest-first";
      this.mineOnly = !!d.get("mine");
      this.load();
    });
    const q = form.querySelector('input[name="q"]') as HTMLInputElement;
    q.addEventListener("input", () => this.runSearch(q.value));
    this.load();
  }

  private async load() {
    const status = this.querySelector("#fd-status")!;
    const grid = this.querySelector("#grid") as HTMLElement;
    status.textContent = "Loading…";
    try {
      const entries = await call<FeedEntry[]>("list_feed", {
        req: { filter: this.filter, sort: this.sort },
      });
      grid.replaceChildren();
      if (entries.length === 0) {
        status.textContent = "No content yet.";
        return;
      }
      status.textContent = `${entries.length} item(s).`;
      for (const e of entries) {
        const card = document.createElement("media-card");
        card.setAttribute("file-id", e.file_id);
        card.setAttribute("file-type", e.file_type);
        card.setAttribute("role", "listitem");
        if (this.mineOnly) card.setAttribute("mine-only", "");
        grid.appendChild(card);
      }
    } catch (x) {
      status.textContent = errMsg(x, "Could not load the feed.");
    }
  }

  private async runSearch(query: string) {
    const status = this.querySelector("#fd-status")!;
    if (query.trim() === "") { this.load(); return; }
    try {
      const hits = await call<SearchHit[]>("search_local", { req: { query } });
      const grid = this.querySelector("#grid") as HTMLElement;
      grid.replaceChildren();
      status.textContent = `${hits.length} match(es).`;
      for (const h of hits) {
        const card = document.createElement("media-card");
        card.setAttribute("file-id", h.file_id);
        card.setAttribute("file-type", h.file_type);
        card.setAttribute("role", "listitem");
        grid.appendChild(card);
      }
    } catch (x) {
      status.textContent = errMsg(x, "Search failed.");
    }
  }
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("feed-screen", FeedScreen);
```

> **Strict-TS error narrowing:** use the `errMsg(x: unknown, …)` helper above — do NOT use `catch (x: any)`. This matches the established strict-tsconfig idiom (the Phase-2 screens used `x?.message ?? …`; the explicit `unknown`-narrowing helper is the cleaner form — reuse it across Tasks 11–13). If a shared `errMsg` already exists in the UI core, import it instead of redefining.

- [ ] **Step 2: Route it**

In `app-shell.ts`: import `"./feed-screen.ts";`; change the `feed` route to render `<feed-screen></feed-screen>` instead of `<feed-empty>`; you may delete the `feed-empty.ts` import + file (and its `customElements.define`) since it is superseded — or leave it unused. Keep the existing focus-on-route-change logic.

- [ ] **Step 3: Typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/ui
git commit -m "feat(ui): feed/library screen (filter, sort, my-uploads, search)"
```

---

## Task 12: UI — `<media-card>` (decrypts itself; title + thumbnail + badge)

**Files:**
- Create: `crates/client-app/ui/src/components/media-card.ts`

Each card lazily calls `decrypt_card` for its `file-id`, shows a skeleton while decrypting, then renders the title, tags, a thumbnail (`data:` URL), a verification badge, and links to the viewer. Honors the `mine-only` attribute (hides itself if `decrypt_card` returns `mine: false`).

- [ ] **Step 1: Write `media-card.ts`**

```ts
import { call } from "../core/rpc.ts";
import type { Card } from "../core/types.ts";
import "./state-badge.ts";

// One feed item. Decrypts itself (title/tags/thumbnail) via decrypt_card, shows a
// skeleton meanwhile, a sanitized error on failure, and links to the viewer.
export class MediaCard extends HTMLElement {
  connectedCallback() {
    const id = this.getAttribute("file-id") ?? "";
    this.innerHTML = `
      <article aria-busy="true">
        <state-badge state="decrypting" label="Decrypting…"></state-badge>
        <h3 class="title">…</h3>
      </article>`;
    this.decrypt(id);
  }

  private async decrypt(id: string) {
    const article = this.querySelector("article")!;
    try {
      const card = await call<Card>("decrypt_card", { req: { file_id: id } });
      if (this.hasAttribute("mine-only") && !card.mine) {
        this.remove(); // filtered out by the "only my uploads" toggle
        return;
      }
      article.setAttribute("aria-busy", "false");
      article.replaceChildren();

      const badge = document.createElement("state-badge");
      badge.setAttribute("state", "verified");
      badge.setAttribute("label", `Verified · ${card.author_fp}`);
      article.appendChild(badge);

      if (card.thumbnail_b64) {
        const img = document.createElement("img");
        img.src = `data:image/png;base64,${card.thumbnail_b64}`;
        img.alt = card.title ? `Thumbnail: ${card.title}` : "Thumbnail";
        img.loading = "lazy";
        article.appendChild(img);
      }

      const h = document.createElement("h3");
      h.className = "title";
      h.textContent = card.title || "(untitled)";
      article.appendChild(h);

      if (card.tags.length) {
        const tags = document.createElement("p");
        tags.className = "tags";
        tags.textContent = card.tags.map((t) => `#${t}`).join(" ");
        article.appendChild(tags);
      }

      const open = document.createElement("a");
      open.href = `#/viewer?id=${encodeURIComponent(id)}`;
      open.textContent = "View";
      article.appendChild(open);
    } catch (x) {
      article.setAttribute("aria-busy", "false");
      article.replaceChildren();
      const badge = document.createElement("state-badge");
      badge.setAttribute("state", "failed");
      badge.setAttribute("label", cardErr(x));
      article.appendChild(badge);
    }
  }
}

function cardErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "Could not decrypt this item.";
}

customElements.define("media-card", MediaCard);
```

- [ ] **Step 2: Typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/client-app/ui
git commit -m "feat(ui): media-card (self-decrypting title/thumbnail/verification badge)"
```

---

## Task 13: UI — `<media-viewer>` (image + blog) with the feedback layer

**Files:**
- Create: `crates/client-app/ui/src/components/media-viewer.ts`
- Modify: `crates/client-app/ui/src/components/app-shell.ts`, `crates/client-app/ui/src/core/router.ts`

The viewer reads `?id=` from the hash, subscribes to `EVT_FETCH` for live fetch/verify/decrypt status, calls `open_content`, and renders: an image via a `data:` URL, or blog text via `textContent` (never `innerHTML` — the XSS defense), plus the title, tags, and verification ticks. Accessible: landmark, status live-region, focus management.

- [ ] **Step 1: Add the `viewer` route**

In `crates/client-app/ui/src/core/router.ts` add `"viewer"` to the `routes` tuple. (The router strips `#/`; the `?id=` query is read from `location.hash` directly in the component.)

- [ ] **Step 2: Write `media-viewer.ts`**

```ts
import { call, on } from "../core/rpc.ts";
import type { OpenedContent, FetchMsg } from "../core/types.ts";
import "./progress-meter.ts";
import "./state-badge.ts";

// Viewer (spec §5): renders one decrypted post. Image → data: URL <img>; blog →
// textContent (NEVER innerHTML). Subscribes to EVT_FETCH for live status. The
// decrypted content shown is the product; no keys cross the boundary.
export class MediaViewer extends HTMLElement {
  private unlisten: (() => void) | null = null;

  async connectedCallback() {
    const id = new URLSearchParams(location.hash.split("?")[1] ?? "").get("id") ?? "";
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="vw-h">
        <a href="#/feed">← Back to feed</a>
        <h1 id="vw-h">Loading…</h1>
        <p id="vw-status" role="status" aria-live="polite"></p>
        <progress-meter id="vw-meter"></progress-meter>
        <div id="vw-body"></div>
        <dl id="vw-meta"></dl>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const status = this.querySelector("#vw-status")!;
    const meter = this.querySelector("#vw-meter") as HTMLElement;
    this.unlisten = await on<FetchMsg>("maxsecu://fetch-state", (m) => {
      if (m.file_id !== id) return;
      if (m.phase === "fetching") {
        meter.setAttribute("value", String(m.fetched));
        meter.setAttribute("max", String(m.total));
        status.textContent = "Fetching…";
      } else if (m.phase === "verifying") {
        status.textContent = "Verifying…";
      } else if (m.phase === "decrypting") {
        status.textContent = "Decrypting…";
      } else if (m.phase === "ready") {
        status.textContent = "Ready.";
      } else if (m.phase === "failed") {
        status.textContent = `Failed: ${m.code}`;
      }
    });

    try {
      const c = await call<OpenedContent>("open_content", { req: { file_id: id } });
      this.render(c);
    } catch (x) {
      (this.querySelector("#vw-h") as HTMLElement).textContent = "Could not open this item";
      status.textContent = viewerErr(x);
    }
  }

  disconnectedCallback() { this.unlisten?.(); }

  private render(c: OpenedContent) {
    (this.querySelector("#vw-h") as HTMLElement).textContent = c.title || "(untitled)";
    const body = this.querySelector("#vw-body") as HTMLElement;
    body.replaceChildren();
    if (c.image_png_b64) {
      const img = document.createElement("img");
      img.src = `data:image/png;base64,${c.image_png_b64}`;
      img.alt = c.title || "Image";
      body.appendChild(img);
    } else if (c.blog_text !== null) {
      const pre = document.createElement("pre");
      pre.textContent = c.blog_text; // textContent: blog text is never HTML
      body.appendChild(pre);
    }
    const meta = this.querySelector("#vw-meta") as HTMLElement;
    meta.replaceChildren();
    const add = (dt: string, dd: string) => {
      const d1 = document.createElement("dt"); d1.textContent = dt;
      const d2 = document.createElement("dd"); d2.textContent = dd;
      meta.append(d1, d2);
    };
    add("Verified author", c.author_fp);
    add("Version", String(c.version));
    if (c.tags.length) add("Tags", c.tags.map((t) => `#${t}`).join(" "));
    if (!c.recovery_ok) add("Note", "No recovery grant present.");
  }
}

function viewerErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "This item could not be opened.";
}

customElements.define("media-viewer", MediaViewer);
```

- [ ] **Step 3: Route it**

In `app-shell.ts`: import `"./media-viewer.ts";`. The router currently maps known routes to elements; add a `viewer` branch rendering `<media-viewer></media-viewer>`. Because the viewer reads its own `?id=` from the hash, build it via `document.createElement("media-viewer")` and `replaceChildren` (consistent with how `pending` is built), or via innerHTML — either works since no attribute carries untrusted markup. Also make the header "My Content" entry a real link to `#/feed` filtered to mine (or leave as Phase 4); minimally make "Feed" and the new viewer reachable. Keep the focus-on-route-change behavior.

- [ ] **Step 4: Typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui
git commit -m "feat(ui): media-viewer (image + blog) with live fetch/verify feedback"
```

---

## Task 14: End-to-end — stage content → list → decrypt card → open content (real TLS)

**Files:**
- Create: `crates/client-app/tests/browse_view_e2e.rs`
- Modify: `crates/client-app/Cargo.toml` (dev-deps, if any are missing)

The Phase-3 exit gate. It (1) stands up the real server over loopback TLS with a `FsBlobStore`, pins a ceremony D5, (2) **stages content out of band** (register+login, `build_upload` an image and a blog, `POST /v1/files`, PUT chunks, finalize — mirroring `file_e2e.rs`), then (3) publishes the author's D5-signed binding, and (4) drives the **client-app** orchestration: parse the listing, resolve+verify the author under the pinned D5, `verify_and_open_headers` for the card, and `verify_and_open` for the content — asserting the exact title/thumbnail/content come back and that a forged author binding is rejected.

> Driving the actual Tauri `#[tauri::command]` fns requires Tauri `State`, which is awkward in a plain integration test. Instead, exercise the **same orchestration modules** the commands call (`maxsecu_client_app::{directory, download, config, index}` + `client-core`'s `verify_and_open_headers`/`verify_and_open`) over a real connection — this is exactly what the commands do, minus the Tauri `State` plumbing (which Task 6–9 unit tests already cover for mapping/sort/shape). This mirrors how `connect_login_e2e.rs`/`bootstrap_admin_e2e.rs` drive `transport`/`session` directly.

- [ ] **Step 1: Confirm dev-deps**

`crates/client-app/Cargo.toml` `[dev-dependencies]` should already have (from Phase 2) `maxsecu-ceremony-harness`, `maxsecu-server`, `maxsecu-client-core`, `maxsecu-encoding`, `maxsecu-crypto`, `rcgen`, `base64`, `hyper`, `hyper-util`, `http-body-util`, `tokio`, `serde_json`, `tokio-rustls`. Add any missing. (`maxsecu-client-core` exposes `build_upload`, `verify_and_open`, `verify_and_open_headers`, `Identity`, `PlaintextStreams`, `UploadParams`, `RustImageCodec`/`Transcoder`/`MediaBounds` for the image, `DirectoryVerifier`, `MemoryTrustStore`.)

- [ ] **Step 2: Write the failing e2e**

`crates/client-app/tests/browse_view_e2e.rs` — reuse the TLS harness + staging helpers from `crates/server/tests/file_e2e.rs` (copy `test_pki`/`Conn`/`connect`/`post`/`put_raw`/`get_json`/`get_raw`/`hex`/`hex16`/`stream_name`/`wrap_bytes` — they are test scaffolding, copying is fine) and the ceremony from `bootstrap_admin_e2e.rs`. The new assertions exercise the client-app modules:

```rust
//! Phase-3 exit gate: stage an image + a blog out of band, publish the author's
//! D5 binding, then drive the REAL client-app browse/view orchestration over
//! loopback TLS — listing, D5-verified author resolution, header-only card open,
//! and full content open — proving title/thumbnail/content round-trip and that a
//! forged author binding is rejected. (No Postgres; MemoryStore + FsBlobStore.)

// ... copy the TLS harness + staging helpers from file_e2e.rs (test_pki, Conn,
// connect, post, put_raw, get_json, get_raw, hex, hex16, stream_name, wrap_bytes) ...

use maxsecu_ceremony_harness::Ceremony;
use maxsecu_client_app::directory::{resolve_and_verify_author, verify_author_binding};
use maxsecu_client_app::download::{build_download_bundle, build_stream_header, parse_file_view};
use maxsecu_client_core::{
    build_upload, verify_and_open, verify_and_open_headers, DirectoryVerifier, Identity,
    MemoryTrustStore, PlaintextStreams, UploadParams, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_encoding::types::{FileType, Id, RecipientType, StreamType, Timestamp};
use maxsecu_server::{serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore};

const VOUCHER: &str = "in-person-code-001";
const TS: u64 = 1_719_500_000_000;
const TITLE_JSON: &[u8] = br#"{"title":"Sunset","tags":["beach"]}"#;
const BLOG_BODY: &[u8] = b"Dear diary, this is a Phase-3 blog post.";

#[tokio::test]
async fn phase3_browse_view_over_real_tls() {
    // ---- Ceremony pins D5; server pins its public key. ----
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();

    let blob_dir = std::env::temp_dir().join(format!("mxp3_{}", hex(&maxsecu_crypto::random_array::<8>())));
    let store = MemoryStore::new();
    store.add_voucher(maxsecu_crypto::sha256(VOUCHER.as_bytes()));
    let cfg = AuthConfig::default().with_directory_pub(pinned);
    let state = AppState {
        auth: std::sync::Arc::new(AuthService::new(store, cfg)),
        blobs: std::sync::Arc::new(FsBlobStore::new(&blob_dir)),
        audit: std::sync::Arc::new(maxsecu_server::NullAuditSink),
        direct_links_enabled: false,
    };
    let pki = test_pki();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), maxsecu_server::router(state)));
    let mut c = connect(addr, pki.client_config.clone()).await;

    // ---- Register + login the author (copy the proof flow from file_e2e.rs). ----
    let owner = Identity::generate();
    // ... POST /v1/users, /v1/session/challenge, /v1/session/proof → token, user_id ...
    // (reuse file_e2e.rs's exact sequence; bind `token` and `user_id`)

    // ---- Stage an IMAGE and a BLOG out of band. ----
    // Image: a tiny transcoded PNG via RustImageCodec (see file_e2e phase4b), with
    // metadata = TITLE_JSON. Blog: build_upload(FileType::Blog) with content =
    // BLOG_BODY, metadata = b"{\"title\":\"My Diary\",\"tags\":[]}".
    // For each: build_upload → POST /v1/files → PUT every chunk → finalize.
    // (mirror file_e2e.rs stage/PUT/finalize; capture each file_id)

    // ---- Publish the author's D5 binding (so directory resolution succeeds). ----
    let pb = ceremony.sign_binding(
        "alice", user_id, owner.enc_pub_bytes(), owner.sig_pub_bytes(),
        &[maxsecu_encoding::types::Role::User], 1,
    );
    let (st, _) = post(&mut c, "/v1/directory", serde_json::json!({
        "binding_b64": B64.encode(&pb.binding_bytes),
        "directory_signature_b64": B64.encode(pb.signature),
    }), None).await;
    assert_eq!(st, StatusCode::CREATED);

    // ---- GATE: D35 listing shows both items. ----
    let (st, list) = get_json(&mut c, "/v1/files?limit=50", &token).await;
    assert_eq!(st, StatusCode::OK);
    assert!(list["files"].as_array().unwrap().len() >= 2);

    // ---- GATE: header-only CARD open of the image (title + thumbnail), under the
    //      PINNED D5, with no content fetch. ----
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let (st, view_json) = get_json(&mut c, &format!("/v1/files/{image_fid_hex}?version=latest"), &token).await;
    assert_eq!(st, StatusCode::OK);
    let view = parse_file_view(&view_json).unwrap();
    let author = resolve_and_verify_author_over(&mut c, &hex(&user_id), &verifier, &mut trust, TS).await; // small wrapper over the test conn
    // Build the header from the small streams fetched via the test conn, then:
    //   let ctx = VerifyContext { file_id, author_sig_pub: author.sig_pub, owner_sig_pub: author.sig_pub,
    //       recipient_id: Id(user_id), recipient_type: RecipientType::User,
    //       recipient_secret: owner.enc_secret(), recipient_mlkem_seed: None, seen_max_version: None,
    //       granter_sig_pub: &NO_GRANTERS, admin_sig_pub: &NO_ADMINS, tombstones: None, compromise: None };
    //   let opened = verify_and_open_headers(&ctx, &header).unwrap();
    //   assert the metadata small-stream parses to title "Sunset"; a thumbnail stream exists.

    // ---- GATE: full CONTENT open of the blog returns the exact text. ----
    //   build a DownloadBundle for the blog file (all streams via the test conn),
    //   verify_and_open, assert the content stream plaintext == BLOG_BODY and the
    //   metadata title parses.

    // ---- GATE: a FORGED author binding is rejected (security). ----
    let attacker = maxsecu_crypto::SigningKey::generate();
    let forged_sig = attacker.sign_canonical(
        maxsecu_encoding::labels::DIRBINDING,
        &maxsecu_encoding::decode::<maxsecu_encoding::structs::DirBinding>(&pb.binding_bytes).unwrap(),
    );
    assert_eq!(
        verify_author_binding(&verifier, &mut MemoryTrustStore::new(), &pb.binding_bytes, &forged_sig, TS).unwrap_err().code,
        "untrusted"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
}
```

> The skeleton above marks the staging + per-gate blocks you must fill from the concrete `file_e2e.rs` flow (it is fully worked there — register/login/stage/PUT/finalize/GET/rebuild-bundle). The **client-app modules under test** are `parse_file_view`, `resolve_and_verify_author`/`verify_author_binding`, `build_stream_header`/`build_download_bundle`, and the client-core `verify_and_open_headers`/`verify_and_open`. Because `build_stream_header`/`build_download_bundle`/`resolve_and_verify_author` take a `hyper` `SendRequest`, drive them with `c.sender` directly (the test `Conn` holds it). For the chunk fetches inside those helpers, the helpers call `http_client::get_bytes` which needs the bearer — pass `&token`. Assert the **decrypted plaintext equals the staged plaintext** for both items and that the forged binding is refused. Do NOT weaken an assertion to make it pass (use `systematic-debugging`).

- [ ] **Step 3: Run it to verify it fails, then passes**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app --test browse_view_e2e`
Expected: compiles and PASSES end-to-end.

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/tests/browse_view_e2e.rs crates/client-app/Cargo.toml
git commit -m "test(client-app): e2e stage -> list -> decrypt card -> open content under pinned D5"
```

---

## Task 15: Phase-3 gates green + security-review note

**Files:**
- Create: `docs/security-review-phase3-mediaapp.md`
- Modify: any files needing fmt/clippy fixes.

- [ ] **Step 1: Format only the touched crates**

Run: `cargo fmt -p maxsecu-client-core -p maxsecu-client-app`
Then: `cargo fmt -p maxsecu-client-core -p maxsecu-client-app -- --check`
Expected: clean. (Do NOT run `cargo fmt --all` — pre-existing Phase 0–7 drift would dirty unrelated files. `client-core` is touched only in `download.rs`/`lib.rs`; keep those lines conformant — if `cargo fmt -p maxsecu-client-core --check` flags pre-existing drift elsewhere, format only your changed lines by hand and skip the crate-wide reformat.)

- [ ] **Step 2: Clippy (warnings are errors) on the touched crates**

Run: `cargo clippy -p maxsecu-client-core -p maxsecu-client-app --all-targets -- -D warnings`
Expected: no warnings. Fix in place; no blanket `#[allow]` (the existing `too_many_arguments` allows on `verify_header`/`verify_grant_chain` are pre-existing and scoped — match that style only where genuinely needed).

- [ ] **Step 3: UI typecheck**

Run: `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cd crates/client-app/ui; npm run build`
Expected: clean bundle.

- [ ] **Step 4: Supply-chain gates**

Run: `cargo deny check` then `cargo audit`
Expected: pass (no new external deps were introduced). If `deny.toml` flags anything new, it shouldn't — add only a narrow, justified entry if genuinely required.

- [ ] **Step 5: Full workspace test (PG optional)**

Run: `$env:MAXSECU_PG_OPTIONAL=1; cargo test --workspace`
Expected: all pass (existing + new; the PG suite runs as the sanctioned skip; ignore the known media-worker `containment_windows` parallel flake — re-run that crate single-threaded if needed: `cargo test -p maxsecu-media-worker -- --test-threads=1`).

- [ ] **Step 6: Write the security-review note**

Create `docs/security-review-phase3-mediaapp.md` summarizing: (a) Phase 3 adds **no new server crypto** — it reuses the existing file/chunk/directory endpoints; (b) every served binding is **re-verified client-side under the pinned D5** before its `sig_pub` is trusted (`directory.rs` + the forged-binding e2e gate); (c) the verify ladder is unchanged and fail-closed — `verify_and_open_headers` is strictly a subset of the audited header+small-stream path (same `verify_header`), adding no bypass; (d) the **UI/TCB boundary**: the viewer necessarily delivers the *content being displayed* to the WebView (canonical PNG / sanitized blog text) — this is the product, not a leak; what never crosses are keys, tokens, DEKs, `WrappedDek`, and grant/manifest/genesis interiors; the blog path renders via `textContent` (never `innerHTML`) and the CSP allows only `img-src 'self' data:`; (e) the **local search index is encrypted at rest** with an identity-derived key (round-trip + not-plaintext-on-disk + foreign-identity-cannot-read tests); (f) sanitized errors throughout (no oracle). Conclude **PASS** with no Critical/High/Medium if the gates are green; note any residual/deferral (e.g. cold-fetch progress is wired but exercised only via the status endpoint shape since the e2e uses an always-cache-hit blob store; "reindex over the whole feed" if deferred).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore(phase3): gates green (fmt/clippy/deny/audit/test) + security-review note"
```

---

## Self-review checklist (done while writing)

- **Spec coverage (Phase 3 row of §10 + §5 Feed/Library/Viewer + §6 feedback layer):** feed/library browse (Tasks 6, 11) ✓; "only my uploads" filter (Tasks 7 `mine`, 11/12) ✓; client-side title+tag **search** over a **local encrypted index** — D-F (Tasks 8, 11) ✓; **image + blog viewer** — images now, video gated (Tasks 9, 13; `codec_unavailable` for video) ✓; the full **fetch/decrypt feedback layer** as a typed state machine emitting progress/state events — §6 (Tasks 9 `FetchPhase`/`EVT_FETCH`, 10 components, 13 subscription) ✓; **D5 client-side re-verification** of every author (Tasks 2, 4, 14 forged-binding gate) ✓; header-only card open to avoid fetching content (Tasks 1, 7) ✓; WCAG-AA screens — landmarks, labelled controls, `role="status"`/`aria-live`, focus management, non-color-only badges (Tasks 10–13) ✓; sanitized non-oracle errors (all commands) ✓; UI strictly outside the TCB — only DTOs cross (all UI tasks + the security note) ✓; e2e over real TLS staging content out of band (Task 14) ✓.
- **No new server crypto / additive-only:** Phase 3 touches no server file; the only TCB change is the pure, subset `verify_and_open_headers` in client-core (Task 1), reusing the audited `verify_header` (security note) ✓.
- **Type consistency:** `verify_and_open_headers(ctx, &StreamHeader) -> OpenedHeader` (T1) consumed by `decrypt_card` (T7) + e2e (T14); `config::load_directory_pub(dir) -> [u8;32]` (T2) used by `decrypt_card`/`open_content` (T7, T9); `http_client::get_bytes(sender, uri, bearer)` (T3) used by `download::fetch_stream_chunks` (T5); `directory::{VerifiedAuthor, verify_author_binding, resolve_and_verify_author, resolve_my_user_id}` (T4) used by T7/T9/T14; `download::{ParsedView, StreamSpec, parse_file_view, build_stream_header, build_download_bundle, fetch_stream_chunks}` (T5) used by T7/T9/T14; DTOs `FeedFilter`/`FeedSort`/`FeedEntryDto`/`CardDto`/`SearchHit`/`OpenedContentDto` (T6–T9) mirrored in `types.ts` (T10); `FetchPhase`/`EVT_FETCH` (T9) consumed by `<media-viewer>` (T13); `index::{SearchIndex, IndexEntry, load, save}` + `search_local` (T8) used by `<feed-screen>` (T11). Endpoint paths consistent: `GET /v1/files`, `GET /v1/files/{id}`, chunk GET, `GET /v1/directory/by-id/{id}`, `GET /v1/directory/{username}`.
- **Known fill-ins flagged for the engineer (real-codebase confirmations, not placeholders):** the exact `get_json`/`reauth` signatures + the `server_id`↔connect-host relationship (read `connection.rs`/`http_client.rs` — T6/T7/T9); the crypto AEAD/derive primitive names for the sealed index (read `crates/crypto/src/lib.rs` — T8 Step 1); the blog-text sanitizer in `client-core` if one exists (T9); the `Manifest`/`Genesis`/`FileType`/`OpenedStream` field names (read `maxsecu_encoding::structs`/`types` + `client-core` — T7/T9); the CSP source location (`tauri.conf.json` vs `index.html` — T10); the `decrypt_card_inner` example's stray dummy arg MUST be removed (T7). Each names the exact file to read.

## Next phases (separate plan docs, written when reached)

Phase 4 (upload: preview-before-upload, active-uploads tray, resumable progress/ETA/retry) · 5 (settings + a11y: Quick-settings, RAM cache controls, behavior toggles, CI a11y checks) · 6 (packaging: client portable exe + server self-extracting exe with bundled Postgres). Each follows this same TDD/bite-sized structure and reuses the command-boundary, state-machine, directory-verification, and feedback patterns established here.
