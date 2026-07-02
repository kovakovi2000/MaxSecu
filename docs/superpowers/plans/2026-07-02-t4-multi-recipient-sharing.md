# T4 — Post-Upload Multi-Recipient Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let any wrap-holder of an already-uploaded file extend read access to N additional directory-verified recipients from the running app — no re-upload, no ceremony — with fail-closed verification anchored to the out-of-band sink.

**Architecture:** New `client-app` command + UI layer on top of the **already-built and tested** `client-core::build_reshare` primitive and server `POST /v1/files/{id}/wraps` endpoint (see spec §2). The only genuinely new subsystem is the **first authenticated-`TombstoneSet` path in client-app**, anchored via `HttpSinkClient` (which client-app does not use today). Everything else is additive plumbing mirroring the existing upload/viewer command patterns.

**Tech Stack:** Rust (Tauri commands, `client-core`, `client-app`), vanilla-TS web components (`client-app/ui`), `tokio`/`hyper` HTTP, real-TLS e2e tests.

**Authoritative spec:** `docs/superpowers/specs/2026-07-02-multi-recipient-sharing-design.md` — **read §0 (locked decisions) and §2 (grounding) before starting.** This plan decomposes that spec into subagent-sized tasks; when a task says "per spec §X", the spec is the source of truth for exact wire shapes, error mappings, and the security checklist (§9).

**Branch:** create a feature branch off `main` (e.g. `feat/t4-multi-recipient-sharing`) before Task 1 (use `superpowers:using-git-worktrees`).

**Locked decisions (from spec §0):** secure sink anchor (D-OQ1); any wrap-holder may share (D-OQ3, so no `mine`-gate); no batch cap (D-OQ5); new `<share-dialog>` + `<share-tray>` (D-OQ2); `VerifiedAuthor.mlkem_pub` as its own step (D-OQ4).

**Dependency graph (for parallel dispatch):**
- Independent, parallelizable first wave: **T1, T2, T3, T4, T7**
- **T5** depends on T4. **T6** independent. **T8** depends on T2+T5+T6+T7. **T9** small/independent.
- **T10, T11** depend on T7+T8 (DTOs/events). **T12** depends on T8. **T13** depends on T10+T11. **T14** last (needs everything).

---

### Task 1: Forward `mlkem_pub` into `VerifiedAuthor` (D-OQ4)

**Files:**
- Modify: `crates/client-app/src/directory.rs` (the `VerifiedAuthor` struct + `verify_author_binding`/`resolve_and_verify_author` that build it)
- Test: same file's `#[cfg(test)]` module (mirror existing directory tests)

- [ ] **Step 1:** Read `directory.rs` fully. Confirm `verify_binding(...)` already returns `v.mlkem_pub` (it does for `RecoveryRecipient`) and that `VerifiedAuthor` currently drops it.
- [ ] **Step 2:** Write a failing test: resolving/verifying an author whose directory binding carries an ML-KEM key exposes it on `VerifiedAuthor.mlkem_pub: Option<[u8;1184]>`; one without it yields `None`.
- [ ] **Step 3:** Add `pub mlkem_pub: Option<[u8; 1184]>` to `VerifiedAuthor`; populate it from the same `verify_binding` result already used, in both constructors. Keep all existing callers compiling (the field is additive; existing sites set/ignore it).
- [ ] **Step 4:** Run the directory test module; confirm green.
- [ ] **Step 5:** Commit: `feat(client-app): carry mlkem_pub on VerifiedAuthor (T4 step)`.

**Acceptance:** `VerifiedAuthor` exposes the recipient's optional ML-KEM key; no behavior change for V1 flows.

---

### Task 2: Third-party recipient resolver by username

**Files:**
- Modify: `crates/client-app/src/directory.rs`
- Test: same file's test module

- [ ] **Step 1:** Study `resolve_recovery_recipient` (`directory.rs:~86`) and `resolve_my_binding` — both do `GET /v1/directory/{username}` → `parse_binding` → `DirectoryVerifier::verify_binding` under the pinned D5, failing closed to `untrusted`.
- [ ] **Step 2:** Write a failing test: `resolve_recipient(username, sender, host, dir)` returns a struct carrying `{ user_id: [u8;16], enc_pub: EncPublicKey, mlkem_pub: Option<[u8;1184]>, sig_pub }` on a valid published binding; returns an `untrusted`/`not-published` error for a `404` or a signature/expiry failure. **No partial trust.**
- [ ] **Step 3:** Implement `resolve_recipient` mirroring `resolve_recovery_recipient` but generic (not the recovery sentinel; reject the recovery id defensively per spec §3 step 5). Reuse Task 1's `mlkem_pub` forwarding.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): D5-verified third-party recipient resolver (T4 step)`.

**Acceptance:** an arbitrary username resolves to a fully D5-verified recipient binding (incl. ML-KEM key) or a fail-closed error — never an unverified placeholder.

---

### Task 3: `list_recipients` client-app wrapper

**Files:**
- Modify: `crates/client-app/src/directory.rs` or a small new `crates/client-app/src/recipients.rs` (follow the module placement the codebase already uses for http helpers)
- Test: same

- [ ] **Step 1:** Confirm the server endpoint `GET /v1/files/{file_id}/recipients` shape from spec §2.2 (owner-only; `404` no-oracle on missing/non-owner; returns each `recipient_id`, `granted_by`, `grant_b64`/`grant_sig_b64`, `ancestor_grants`).
- [ ] **Step 2:** Write a failing test (against an in-process loopback stub like `direct_link.rs::StubServer`) that a `200` yields the parsed recipient `user_id` set and a `404` yields an empty/`no-access` result (for duplicate-awareness only, never a hard error).
- [ ] **Step 3:** Implement the 4-arg `(sender, uri, bearer, host)` helper returning `Vec<RecipientRow>` (at minimum `user_id`).
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): list_recipients wrapper for share duplicate-awareness (T4 step)`.

**Acceptance:** the picker can learn who already holds a wrap; a non-owner/`404` degrades to "unknown", never blocks sharing.

---

### Task 4: Sink client integration + pinned sink config (the big new subsystem)

**Files:**
- Modify: `crates/client-app/src/config.rs` (add pinned sink `addr`/`server_name`/TLS-root, alongside the existing pinned D5 pubkey pin)
- Create: `crates/client-app/src/sink.rs` (thin adapter constructing `client_core::sink::HttpSinkClient` and returning a **validated** `anchored_head`)
- Test: `crates/client-app/src/sink.rs` test module + a loopback sink (reuse `client_core::sink::FakeSink` / the sink-server test harness patterns)

- [ ] **Step 1:** Read `crates/client-core/src/sink.rs` (`HttpSinkClient::{new, fetch_head_all_proofs, fetch_control_pos}`, `verify_anchor_proof`, `AnchoredHead`, `AnchorProof`, `SinkError`) and how `phase7_hardening_e2e.rs` + `sink-server/tests/sink_e2e.rs` exercise them. **client-app has no sink caller today — this is net-new.**
- [ ] **Step 2:** Decide the pin surface: sink socket addr + `server_name` + pinned TLS root + the custodian/transparency allowlist that `verify_anchor_proof` checks against. Put these in `config.rs` next to the D5 pin (offline-pinned, not server-served — same trust model).
- [ ] **Step 3:** Write a failing test: `fetch_anchored_head(cfg)` returns a `[u8;32]` head **only after** `verify_anchor_proof` passes against the pinned allowlist; a bad/absent proof fails closed (`SinkError::Unreachable`-equiv → a `UiError` with a sanitized code). Use a loopback `FakeSink` anchoring a known head.
- [ ] **Step 4:** Implement `crate::sink::fetch_anchored_head`: build `HttpSinkClient`, `fetch_head_all_proofs`, run `verify_anchor_proof` under the pin, return the validated head or fail closed.
- [ ] **Step 5:** Run tests; green.
- [ ] **Step 6:** Commit: `feat(client-app): pinned sink client + validated anchored-head fetch (T4 step)`.

**Acceptance:** client-app can obtain a cryptographically-validated anchored control-log head **from the sink, bypassing the app server** — the foundation of D-OQ1. A forged/withheld anchor fails closed.

---

### Task 5: Authenticated `TombstoneSet` in client-app

**Files:**
- Create: `crates/client-app/src/revocations.rs`
- Test: same module (loopback stub for `GET /v1/revocations`, `FakeSink` for the head, real `client_core::revocation` verification)

- [ ] **Step 1:** Read `crates/client-core/src/revocation.rs` — `TombstoneSet::verify_authenticated(records: &[ControlRecordIn], anchored_head: [u8;32], issuer: &dyn Fn(Id)->Option<IssuerInfo>)`, `ControlRecordIn`, `IssuerInfo`, `TombstoneError`. Note `GET /v1/revocations` (server-served, untrusted) supplies the records; the chain-verify + Task 4's anchored head make them safe.
- [ ] **Step 2:** Write a failing test: given a loopback server serving a contiguous control-log record set reaching a `FakeSink`-anchored head, `build_tombstones(...)` returns a `TombstoneSet` for which a known account-wide-revoked id reports `is_account_revoked == true`; a **withheld** trailing record makes it fail closed (`TombstoneError::Gap`); a record signed by a non-admin fails closed.
- [ ] **Step 3:** Implement `build_tombstones`: fetch `GET /v1/revocations` records, take the anchored head from Task 4, build the `issuer` resolver (resolve each `issued_by` id to `IssuerInfo` via the pinned-D5 directory lookup from Task 2/`directory.rs`), call `verify_authenticated`. Map every `TombstoneError` to a sanitized `UiError`.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): authenticated TombstoneSet built against the sink anchor (T4 step)`.

**Acceptance:** the first real, chain-verified, admin-authenticated revocation state in the shipped app, anchored to the sink — satisfies spec §9's TombstoneSet checklist item.

---

### Task 6: Recover the caller's own DEK outside the upload pipeline

**Files:**
- Create/Modify: a helper in `crates/client-app/src/download.rs` or `commands/share.rs` (co-locate with Task 8)
- Test: same module

- [ ] **Step 1:** Read `client-core/src/download.rs:304-318` (`verify_header`'s unwrap step) and `client-app/src/upload.rs::streaming_confirm`'s DEK recovery via `unwrap_dek`/`unwrap_dek_hybrid` + `WrapContext`. Confirm `OpenedFile`/`OpenedHeader` do **not** expose the DEK (by design).
- [ ] **Step 2:** Write a failing test: given a file view whose served wrap for `recipient_id == Id(my_id)` is a valid V1 self-wrap, `recover_own_dek(view, identity, my_id)` returns a `Dek` whose `dek.commit() == manifest.dek_commit`; a caller with **no** matching wrap gets a fail-closed error (proves the any-wrap-holder boundary — no wrap ⇒ no DEK). Add a V2/hybrid case.
- [ ] **Step 3:** Implement `recover_own_dek`: fetch `GET /v1/files/{id}?version=latest` (reuse `parse_file_view`), select the served wrap addressed to the authenticated `my_id`, `unwrap_dek` (V1) or hybrid-unwrap (V2, mirroring `client-core::upload::unpack_hybrid_wrap`) under the identity borrow, assert the commitment. **Borrow the identity only for the synchronous unwrap — never across `.await`.**
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): recover caller's own DEK from served self-wrap (T4 step)`.

**Acceptance:** any wrap-holder can recover the DEK from their own served wrap; a non-holder cannot — this is where "any wrap-holder, in practice" is enforced (spec §4 owner-only-enforcement note, generalized by D-OQ3).

---

### Task 7: DTOs + `EVT_RESHARE`/`SharePhase` events

**Files:**
- Modify: `crates/client-app/src/dto.rs` (add `ResolveRecipientRequest`, `ResolvedRecipientDto`, `ReshareRequest`, `ReshareOutcomeDto` — spec §4)
- Modify: `crates/client-app/src/state.rs` (add `EVT_RESHARE = "maxsecu://reshare-state"` + `SharePhase` enum — spec §6)
- Test: dto serde round-trip test

- [ ] **Step 1:** Copy the DTO shapes verbatim from spec §4 and the `SharePhase` enum from spec §6. Honor the `dto.rs` file-level rule: **no `WrapOut`/`Dek`/`Identity`/`TombstoneSet` in any DTO** — only usernames, hex ids, booleans, sanitized codes.
- [ ] **Step 2:** Write a failing serde round-trip test for each DTO (matches the existing dto test style).
- [ ] **Step 3:** Add the DTOs + event constant + phase enum (kebab-tagged variants, mirroring `UploadPhase`).
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): reshare DTOs + EVT_RESHARE/SharePhase (T4 step)`.

**Acceptance:** the seam types exist and only carry non-secret data.

---

### Task 8: The `reshare_file` command (ties T2+T5+T6+T7 together)

**Files:**
- Create: `crates/client-app/src/commands/share.rs`
- Modify: `crates/client-app/src/commands/mod.rs`, `crates/client-app/src/lib.rs` (module), `crates/client-app/src/main.rs` (register the command)
- Test: unit-level test in `share.rs` where feasible; full flow covered by Task 12 e2e

- [ ] **Step 1:** Re-read spec §4 (command flow, 1–9) and §5 (per-recipient, idempotent, no all-or-nothing). Signature per spec §4: `async fn reshare_file(req: ReshareRequest, app, dir, session, connect_lock) -> Result<Vec<ReshareOutcomeDto>, UiError>`.
- [ ] **Step 2:** Write a failing test covering the batch-isolation contract: a mixed batch (one unresolvable username, one valid) returns exactly one `ok:false` + one `ok:true`, never aborts the batch, never drops a row.
- [ ] **Step 3:** Implement the flow: **one** `reauth` for the whole batch → `recover_own_dek` (T6) → `build_tombstones` (T5) → per recipient: `resolve_recipient` re-verify (T2, TOCTOU re-check at share-time) → `build_reshare(&params, &dek, &tombstones)` → `POST /v1/files/{id}/wraps` (reuse `wrap_wire`) on the same `sender`/`token`. Map `ReshareError::{RecipientRevoked→"revoked", ResharePqKeyMissing→"pq_key_missing", ...}`. Emit `SharePhase` per recipient over `EVT_RESHARE`. Identity borrowed only for synchronous unwrap/grant-sign steps (never across `.await`). No batch cap (D-OQ5).
- [ ] **Step 4:** Register in `main.rs`; run tests + `cargo build -p client-app`; green.
- [ ] **Step 5:** Commit: `feat(client-app): reshare_file command (T4)`.

**Acceptance:** the command re-shares to N recipients, per-recipient fail-isolated, idempotent, fail-closed on every verification step (spec §9 checklist).

---

### Task 9: Expose `can_share` display metadata on the viewer (optional gate)

**Files:**
- Modify: `crates/client-app/src/commands/viewer.rs` (`open_content_inner` already computes `my_id == author.user_id` at ~line 334) + `OpenedContentDto` in `dto.rs`
- Test: existing viewer test extended

- [ ] **Step 1:** Per D-OQ3, Share shows for **any wrap-holder** (anyone who can open the item), so this is display metadata, not a hard gate. Add `pub can_share: bool` (true whenever the viewer successfully opened, i.e. the caller holds a wrap).
- [ ] **Step 2:** Failing test: opened content sets `can_share = true`.
- [ ] **Step 3:** Populate it in `open_content_inner`.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): expose can_share on OpenedContentDto (T4 step)`.

**Acceptance:** the UI can show the Share affordance to any viewer without a separate ownership query.

---

### Task 10: `<share-dialog>` component

**Files:**
- Create: `crates/client-app/ui/src/components/share-dialog.ts`
- Modify: `crates/client-app/ui/src/components/media-viewer.ts` (add the "Share…" action, gated on `can_share`), register the element
- Test: covered structurally by Task 13 a11y lint + manual smoke

- [ ] **Step 1:** Re-read spec §3 (picker UX) and §5/§8 (idempotency note, edge cases). Model the modal a11y bar from the existing app: `role="dialog"`, `aria-modal`, labelled by heading, focus trap + return, `Escape` closes, `:focus-visible`.
- [ ] **Step 2:** Build the picker: "Add recipient by username" input → call `resolve_recipient` (T2) via the `serial()` FIFO queue → show Verified/rejected rows with fingerprint + non-color-only `<state-badge>`; cross-check `list_recipients` (T3) for an "Already has access" note (informational, not blocking); reject self and the recovery sentinel (spec §3 steps 4–5). "Share" enabled only once ≥1 row is Verified.
- [ ] **Step 3:** On Share: call `reshare_file` (T8) through `serial()`, render per-row `ReshareOutcomeDto` results, offer per-row Retry (single-element batch).
- [ ] **Step 4:** `cargo build`/`npm`-equivalent UI check + manual load; commit: `feat(ui): share-dialog recipient picker (T4 step)`.

**Acceptance:** an owner/holder can pick, verify, and share to recipients with fail-closed per-row feedback.

---

### Task 11: `<share-tray>` passive surface

**Files:**
- Create: `crates/client-app/ui/src/components/share-tray.ts`
- Modify: `crates/client-app/ui/src/components/app-shell.ts` (mount it, like `<upload-tray>`)
- Test: Task 13 a11y lint

- [ ] **Step 1:** Mirror `upload-tray.ts`: one `aria-live="polite"` section, subscribe to `EVT_RESHARE` (`maxsecu://reshare-state`), one `<li>` per file being shared with a per-recipient summary ("3 of 5 shared · 2 failed"), `<state-badge>` echoing `ReshareOutcomeDto.code`, `role="alert"` only for terminal all-failed. Progress is a **count**, not a byte-rate (no ETA math — spec §6).
- [ ] **Step 2:** Wire subscription + render; auto-clear on success after ~4s (match upload-tray).
- [ ] **Step 3:** Build/load; commit: `feat(ui): share-tray passive reshare feedback (T4 step)`.

**Acceptance:** background reshares surface progress even after the dialog is dismissed.

---

### Task 12: e2e `reshare_e2e.rs`

**Files:**
- Create: `crates/client-app/tests/reshare_e2e.rs` (mirror `upload_e2e.rs` — real TLS server, real directory ceremony, real control-log, real sink; no mocked crypto)

- [ ] **Step 1:** Implement spec §10 scenarios 1–8 as `#[test]` cases: (1) share to a fresh recipient → their download verifies; (2) idempotent re-share → still exactly one recipient row; (3) unpublished recipient → `code:"untrusted"`, no wrap POST; (4) tombstoned recipient rejected while a co-batch valid one succeeds; (5) batch partial-failure + targeted retry; (6) V2/hybrid round-trip incl. `pq_key_missing` fail-closed; (7) non-holder cannot reshare (DEK recovery fails before any POST); (8) `GrantAction::Reshare` audit edge asserted via the existing `MemoryAuditSink` harness.
- [ ] **Step 2:** Run the suite (over real TLS); all green.
- [ ] **Step 3:** Commit: `test(client-app): reshare_e2e covering spec §10 gates (T4)`.

**Acceptance:** all eight spec gates pass end-to-end over real transport.

---

### Task 13: a11y lint additions

**Files:**
- Modify: `crates/client-app/ui/src/a11y.test.ts`

- [ ] **Step 1:** Extend the existing dependency-free `node:test` structural suite (spec §10 item 9) to cover `<share-dialog>`/`<share-tray>`: labelled dialog, `aria-live` region present, no color-only status, focus trap/return, all interactive elements keyboard-reachable.
- [ ] **Step 2:** Run the a11y suite; green.
- [ ] **Step 3:** Commit: `test(ui): a11y lint for share dialog/tray (T4 step)`.

---

### Task 14: Security review + sign-off

- [ ] **Step 1:** Run `superpowers:requesting-code-review` and `/security-review` on the branch diff. Verify **every** box in spec §9 (only DTOs cross the seam; D5-verify before any wrap; real chain-verified TombstoneSet against the sink anchor; owner/holder-only-in-practice via own-self-wrap DEK recovery; no plaintext/DEK in events/logs; fail-closed on every step; per-recipient never drops a row; genuine idempotency; V2/PQ path exercised; `reauth`/`ConnectLock` discipline).
- [ ] **Step 2:** Write `docs/security-review-t4-multi-recipient-sharing.md` (PASS gate, mirroring prior sign-offs). Address any finding before sign-off.
- [ ] **Step 3:** Commit: `docs(security): T4 multi-recipient sharing sign-off`.
- [ ] **Step 4:** `superpowers:finishing-a-development-branch` to merge into `main`.

**Acceptance:** signed-off PASS, no Critical/High/Medium; merged.

---

## Self-review notes (author)

- **Spec coverage:** §2.4 gaps 1–7 → T1 (gap 2), T2 (gap 3), T3 (gap 7), T5 (gap 4), T6 (gap 5), T9 (gap 6); gap 1 (no command) → T8. §3 picker → T10. §4 command → T8. §5 batching → T8/T10. §6 tray → T11. §7 revocation interplay → covered by T5+T8 (no new audit code). §9 checklist → T14. §10 tests → T12/T13. D-OQ1 sink anchor → T4+T5.
- **Type consistency:** `resolve_recipient` (T2) feeds both T8 and T10; `recover_own_dek` (T6) and `build_tombstones` (T5) are consumed only by T8; DTO names (T7) match spec §4 exactly.
- **No placeholders:** each task names exact files, the concrete signature/contract, a first failing test, and a commit. Deep wire/error detail is delegated to the cited spec sections by design (spec is authoritative), not left as "TBD".
