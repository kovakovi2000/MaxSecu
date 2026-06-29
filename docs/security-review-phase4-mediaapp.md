# Phase 4 (Media App) — Security Review & Sign-off (Upload)

**Scope:** the Phase-4 change set on branch `media-app` — commit range `b07c0de..HEAD` (`b07c0de` = the Phase-3 baseline). Phase 4 adds the create-a-post upload pipeline: choose + describe (title/tags/type) → **preview-before-upload** → transcode (image) / sanitize (blog) → encrypt (`client-core::build_upload`, self + recovery) → **resumable** chunked staged upload (stage → idempotent `PUT` → finalize) → an Upload screen + active-uploads tray, with an e2e that uploads an image and a blog from the **real client** over real TLS and reads them back.

**Method:** TDD, subagent-driven on Opus, per-task two-stage review (spec then code-quality), all findings fixed before acceptance, plus a final holistic review. Verification artifacts: the per-file unit tests; `crates/client-app/tests/upload_e2e.rs` (5 gates over loopback TLS 1.3, MemoryStore + FsBlobStore); and the green gate suite (client-app clippy `-D warnings`, `cargo deny`, `cargo audit`, `MAXSECU_PG_OPTIONAL=1 cargo test --workspace`, UI typecheck + build).

**Verdict:** **PASS** — no Critical, High, or Medium findings. Phase 4 introduces **no new server cryptography and no new server endpoints**; it drives the existing stage/PUT/finalize + directory endpoints and preserves the secret-free / zero-knowledge / client-re-verified model. Documented residuals (§4) are security-neutral.

---

## 1. What Phase 4 added (and did not)

- **No server change.** Phase 4 reuses the existing, already-reviewed `POST /v1/files` (stage v1), idempotent `PUT …/chunks/{i}`, `POST …/finalize`, and `GET /v1/directory/*`. No new route, no new server-held secret, no new server crypto.
- **No `client-core` change.** Upload encryption is the existing `client-core::build_upload` (owner-only, self + recovery, fresh per-file DEK). Phase 4 is `client-app` orchestration + UI only.
- **`client-app`:** recovery-recipient resolution under the pinned D5; metadata-JSON + transcode/streams prep (the user's own file); the stage→resumable-PUT→finalize pipeline; a pre-confirm jobs registry; the `stage_upload`/`confirm_upload`/`cancel_upload`/`upload_jobs` commands; the `UploadPhase` feedback machine.
- **UI:** `<upload-screen>` (preview-before-upload) and a persistent `<upload-tray>` (progress/ETA/retry).

## 2. Per-area findings & dispositions

| # | Area | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | **TCB boundary (what crosses the Tauri seam)** | **Sound (✓).** The upload commands return only render-ready DTOs: `UploadPreview` (job_id, file_type, title, tags, byte_size, total_chunks, a small canonical-PNG thumbnail), `UploadJobView`, the `UploadPhase` progress events, and on success the file_id hex `String`. The `UploadBundle` (fresh DEK, wraps, signed grants, ciphertext chunks), the unlocked `Identity`, and the source plaintext **never** cross the seam — the bundle is held in the in-process `UploadJobs` registry (TCB) between preview and confirm, and the identity stays in the session. The preview thumbnail is the user's own canonical-PNG (acceptable to display). | Info | Accepted (correct). |
| 2 | **Owner-only, self + recovery wraps** | **Sound (✓).** Uploads use `build_upload` unchanged — owner-signed `genesis`/`manifest`/grants, one fresh DEK, wrapped to **self + the recovery recipient only**. The recovery recipient's `enc_pub` (+ optional ML-KEM) is taken **only** from `directory::resolve_recovery_recipient`, which D5-verifies the served binding under the pinned key before use — a forged/unpublished recovery binding fails closed (`untrusted`) and cannot become a wrap target (e2e gate E). `owner_id`/`owner_key_version` come from the D5-verified own binding (`resolve_my_binding`), never from request input. | Info | Accepted (correct). |
| 3 | **Preview-before-upload** | **Sound (✓).** `stage_upload` performs the transcode/encrypt and holds the resulting bundle in `UploadJobs` with **no network write** (only unauthenticated directory GETs to resolve recipients). Nothing reaches the server until the user confirms; `confirm_upload` then runs the stage→PUT→finalize pipeline. A cancelled or never-confirmed job is simply dropped — no server-side trace. | Info | Accepted (correct). |
| 4 | **Unlocked-identity handling** | **Sound (✓).** `stage_upload` borrows the unlocked `Identity` **under the session lock** across the **synchronous** `build_upload` (no `take()`, no transient `None` window, no `await` held while borrowed) — matching the Phase-3 decrypt/viewer pattern. The async recipient resolves happen before the lock block. `confirm_upload` never touches the identity directly; `reauth` does, under its own lock with restore-on-every-path. | Info | Accepted (correct). |
| 5 | **Resumable / fail-closed transport** | **Sound (✓).** `run_pipeline` stages (expects `201`), PUTs each ciphertext chunk via `put_chunk_retried` (≤3 idempotent re-PUTs by index — the server's idempotent-by-index `PUT` makes a retry a safe resume, no duplication), then finalizes (expects `200`). On any failure `confirm_upload` **retains** the staged job so the tray can retry; on success it removes it. The server's finalize completeness gate (every stream must hold its full `chunk_count`) is exercised: a premature finalize returns `400`, surfaced as a sanitized `finalize_failed` (e2e gate D). | Info | Accepted (correct). |
| 6 | **Input bounds / DoS** | **Sound (✓).** Both the chosen image file (`fs::metadata` length) and the blog text are size-bounded (`MAX_UPLOAD_BYTES` = 64 MiB) **before** transcoding/encryption; a bad image fails closed (`bad_image`). The transcode output is additionally bounded by `MediaBounds`. | Info | Accepted (correct). |
| 7 | **Sanitized errors / no oracle** | **Sound (✓).** Every failure path returns a stable sanitized `UiError` code (`no_recovery_recipient`/`untrusted`/`pending`/`bad_image`/`bad_request`/`too_large`/`stage_failed`/`upload_chunk_failed`/`finalize_failed`/`encrypt_failed`); `UploadPhase::Failed` carries the code, never internal detail. No path/crypto internals leak. | Info | Accepted (correct). |
| 8 | **UI rendering (XSS) + concurrency** | **Sound (✓).** The upload screen + tray render all dynamic content (title, tags, sizes, phase labels, error codes) via `textContent`/`createElement`; the only `innerHTML` is static shells. The thumbnail renders via a `data:image/png;base64,…` URL under the existing CSP (`img-src 'self' data:`). All authenticated upload calls (`confirm_upload`, retry) route through the shared `serial()` FIFO queue so the backend's single `ConnectLock`/non-`Clone` identity is never contended (no spurious "busy"). | Info | Accepted (correct). |

## 3. Threat-model coverage (Phase-4-relevant)

- **Forged recovery recipient becoming a wrap target:** closed — `resolve_recovery_recipient` D5-verifies before use; e2e gate E.
- **Server tampering with the uploaded record:** the records are owner-signed and the recipient re-verifies on download (Phase 3 ladder, unchanged); the upload itself signs as the owner with a fresh DEK.
- **Key/plaintext leak across the UI seam:** closed — only render-ready DTOs cross; the bundle/identity/plaintext stay in the TCB.
- **Client DoS via a huge chosen file:** mitigated — size-bounded before encryption.
- **Partial/corrupt upload committed:** closed — the server finalize completeness gate rejects an incomplete version (`400`); idempotent re-PUT makes resume safe.
- **XSS via attacker-influenced title/tags:** closed — `textContent` rendering; scoped CSP.

## 4. Residuals / deferrals (intentional, security-neutral)

- **Multi-recipient sharing** (post-upload reshare via `client-core::build_reshare` → `POST /v1/files/{id}/wraps`) is deferred; Phase-4 uploads are self + recovery. The reshare path is already reviewed at the core level (Phases 0–7).
- **OS file-picker plugin** deferred — the upload screen takes a filesystem path (image) / textarea (blog). The path is host-trusted (operator-chosen) and read with a size bound.
- **Mid-flight cancel/pause** deferred — `cancel_upload` drops pre-confirm or retained-after-failure jobs; interrupting an in-flight upload is a later refinement.
- **Rotation (new versions of an existing post)** — `POST /v1/files/{id}/versions` exists server-side; editing/rotating a post is a later slice.
- **UI a11y polish** (upload-tray: a `default: never` exhaustiveness guard on the `UploadMsg` union; a per-row "Retry upload" `aria-label` to disambiguate multiple simultaneous failed rows) — non-blocking follow-ups.
- **`client-core` rustfmt drift** unchanged and out of scope (Phase 4 did not touch client-core); `client-app` + UI are fmt-clean.

## 5. Conclusion

**PASS.** Phase 4 adds no server cryptography or endpoints and keeps the secret-free, zero-knowledge, client-re-verified model intact. Uploads are owner-only, wrapped to self + a D5-verified recovery recipient, encrypted entirely in the client TCB; preview-before-upload holds the bundle locally until the user confirms; the identity is borrowed under the session lock across the synchronous build; the resumable transport is idempotent and fail-closed; and only render-ready DTOs cross the UI seam. No Critical/High/Medium issues; the residuals are documented and security-neutral.
