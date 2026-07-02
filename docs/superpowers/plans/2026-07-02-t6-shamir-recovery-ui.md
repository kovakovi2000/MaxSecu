# T6 — Shamir K-of-N Recovery-Key UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the recovery-key custodian an offline (air-gapped), accessible UI to split the recovery private key into K-of-N Shamir shares and later reconstruct it from ≥K shares — on top of the already-shipped Phase-7 crypto, adding **zero new cryptography** beyond a passphrase-sealed load format.

**Architecture:** New offline-only Tauri screens + commands in `client-app`, wrapping the already-tested `crypto::shamir` and `admin-core::recovery::{split,reconstruct}_recovery_key`. **No network I/O anywhere in the ceremony path** (grep-checkable). The reconstructed key never crosses the Tauri seam — commands return an opaque `ceremony_handle` into Rust-held `CeremonySession` state. One new sealed-file format (Argon2id+AEAD) is the only added crypto-adjacent code.

**Tech Stack:** Rust (Tauri commands, `crypto`, `admin-core`, `client-app`), `Zeroizing`/zero-on-drop secret types, vanilla-TS web components, dependency-free `node:test`.

**Authoritative spec:** `docs/superpowers/specs/2026-07-02-shamir-recovery-ui-design.md` — **read §0 (locked decisions) and §2 (grounding) before starting.** When a task says "per spec §X", the spec is the source of truth for exact copy, error mappings, custody guidance, and the security checklist (§11).

**Branch:** create a feature branch off `main` (e.g. `feat/t6-shamir-recovery-ui`) before Task 1.

**Locked decisions (from spec §0):** Tauri GUI, offline-only (D-A); load the recovery secret from a new **Argon2id+AEAD sealed file** (D-B); **classical X25519 only** for v1, ML-KEM deferred (D-C); shares as **text + save-to-file, no QR** (D-D); advisory `n≥3` + hard `k≤n` (D-E); discourage same-key re-split (D-F); minimal non-secret local ceremony log (D-G).

**Dependency graph (for parallel dispatch):**
- Independent first wave: **T1** (sealed-file), **T2** (MSHARE1 encoding), **T3** (CeremonySession + DTOs).
- **T4** (split cmd) depends on T1+T2+T3. **T5** (add-share) depends on T2+T3. **T6** (reconstruct) depends on T2+T3. **T7** (prove) depends on T3+T6. **T8** (discard + register) depends on T4–T7. **T9** (ceremony log) depends on T4/T6.
- **T10** (split screen) depends on T4. **T11** (reconstruct screen) depends on T5+T6+T7. **T12** a11y depends on T10+T11. **T13** e2e depends on T4–T7. **T14** last.

---

### Task 1: Sealed-file format for the recovery secret (D-B)

**Files:**
- Create: `crates/admin-core/src/recovery_seal.rs` (co-locate with `recovery.rs`; place per the crate's module layout)
- Modify: `crates/admin-core/src/lib.rs` (module export)
- Test: same module

- [ ] **Step 1:** Study `keyblob::seal`/`open` (Argon2id + AEAD) as the pattern; confirm `EncSecretKey` (`crypto/src/wrap.rs:32`) exposes bytes only via `expose_bytes()` and is zero-on-drop.
- [ ] **Step 2:** Write a failing round-trip test: `seal_recovery_secret(&EncSecretKey, passphrase) -> Vec<u8>` then `open_recovery_secret(&sealed, passphrase) -> Result<EncSecretKey, _>` returns byte-identical scalar; a wrong passphrase fails closed (AEAD auth failure, no partial output); the sealed bytes never contain the plaintext scalar (assert no substring match).
- [ ] **Step 3:** Implement seal/open: passphrase → Argon2id KDF → AEAD (same primitives `keyblob` uses) over `expose_bytes()`, with a versioned header. All transient buffers `Zeroizing`.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(admin-core): Argon2id+AEAD sealed-file for the recovery secret (T6 step)`.

**Acceptance:** the recovery secret is loadable from a passphrase-sealed file; at-rest bytes are never a bare scalar; wrong passphrase fails closed.

---

### Task 2: `MSHARE1` share wire-encoding + integrity checksum (spec §5)

**Files:**
- Create: `crates/client-app/src/recovery_share.rs` (encode/parse/checksum — pure, no network)
- Modify: `crates/client-app/src/lib.rs`
- Test: same module

- [ ] **Step 1:** Re-read spec §5. Format: `MSHARE1:<label-b64url>:<k>:<n>:<index>:<body-b64url>:<checksum-hex8>` where checksum = first 8 hex of `sha256(label ‖ k ‖ n ‖ index ‖ body)` (use `crypto::sha256`).
- [ ] **Step 2:** Write failing tests: (a) `encode(share, label, k, n)` → parse → byte-identical `index`/`body`/`k`/`n`/`label`; (b) a single-character mutation in **every** field position (label, k, n, index, body, checksum) is rejected by `parse_and_verify`; (c) a wrong version tag / bad base64 / wrong field count is rejected with a specific error, never a raw parse dump.
- [ ] **Step 3:** Implement encode + `parse_and_verify` returning `{label, k, n, index, body}` or a specific `ShareParseError`. Treat body as sensitive (no `Debug` that prints it).
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): MSHARE1 share encoding + checksum (T6 step)`.

**Acceptance:** shares survive typing/filing and a transcription typo is caught before `combine` (spec §5 — a UX corruption check, explicitly not an authenticity guarantee).

---

### Task 3: `CeremonySession` Tauri state + DTOs (spec §8)

**Files:**
- Create: `crates/client-app/src/ceremony.rs` (the `CeremonySession` state holding the in-progress secret/shares, `Zeroizing`, zero-on-drop)
- Modify: `crates/client-app/src/dto.rs` (add the §8 DTOs), `crates/client-app/src/lib.rs`, `crates/client-app/src/main.rs` (manage the state, like `Session`/`ConnectLock`)
- Test: dto serde round-trip; session add/reset unit test

- [ ] **Step 1:** Copy the DTO shapes verbatim from spec §8 (`SplitRecoveryKeyRequest` incl. `recovery_secret_path` **and a passphrase field** per D-B, `SplitRecoveryKeyResponse`, `AddShareRequest`, `AddShareResponse`, `ReconstructResponse` with opaque `ceremony_handle`, `ProveRequest`, `ProveResponse`). **DTO rules (spec §8):** individual shares (MSHARE1 text) may cross the seam; the **reconstructed whole key never does**; the initial secret is loaded by path, not by value.
- [ ] **Step 2:** Failing tests: DTO serde round-trips; `CeremonySession` accumulates shares and exposes `have`/`need`; `reset`/drop zeroizes.
- [ ] **Step 3:** Implement `CeremonySession` (a small `tokio::sync::Mutex`-guarded struct holding the collected `Vec<Share>` + label + optionally the reconstructed `EncSecretKey` keyed by handle) and the DTOs. No `Debug` that dumps secret/share bytes.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): CeremonySession state + recovery DTOs (T6 step)`.

**Acceptance:** the seam types exist; the whole key never appears in a DTO; session state is zeroizing.

---

### Task 4: `split_recovery_key` command (depends T1+T2+T3)

**Files:**
- Create: `crates/client-app/src/commands/recovery_custody.rs`
- Modify: `commands/mod.rs`, `lib.rs`, `main.rs` (register)
- Test: same module

- [ ] **Step 1:** Re-read spec §4. Signature (spec §8): `fn split_recovery_key(req: SplitRecoveryKeyRequest) -> Result<SplitRecoveryKeyResponse, UiError>` — **synchronous, no network, no State needed** (loads its own file).
- [ ] **Step 2:** Failing tests: valid `k`/`n` over a sealed test secret returns `n` MSHARE1 strings; `BadThreshold` inputs (`k==0 || n==0 || k>n`) rejected client-side-equivalently **and** by the command (defense in depth, D-E); a wrong passphrase surfaces a fail-closed `UiError`.
- [ ] **Step 3:** Implement: `open_recovery_secret(path, passphrase)` (T1) → validate `k`/`n` (D-E hard checks) → `admin_core::recovery::split_recovery_key(&secret, k, n)` → encode each `Share` via MSHARE1 (T2) with the operator label → return `SplitRecoveryKeyResponse`. Secret + shares are `Zeroizing`, dropped on return; nothing written to disk by this command (file export is a separate operator action in the UI).
- [ ] **Step 4:** Register; run tests + build; green.
- [ ] **Step 5:** Commit: `feat(client-app): split_recovery_key command (T6 step)`.

**Acceptance:** produces `n` shares from a sealed secret; fails closed on bad threshold/passphrase; no network, no disk write.

---

### Task 5: `add_recovery_share` command (depends T2+T3)

**Files:**
- Modify: `crates/client-app/src/commands/recovery_custody.rs`
- Test: same module

- [ ] **Step 1:** Re-read spec §6 step 1. Signature: `fn add_recovery_share(req: AddShareRequest, state: State<'_, CeremonySession>) -> Result<AddShareResponse, UiError>`.
- [ ] **Step 2:** Failing tests — four **distinct** `UiError` codes asserted individually: malformed text, wrong checksum, duplicate `index` already in session, label mismatch vs the session's first-accepted label. A valid share increments `have`.
- [ ] **Step 3:** Implement: `parse_and_verify` (T2) → check index uniqueness + label consistency against session → push to `CeremonySession`. Never redisplay share bytes; return only `{have, need, label}`.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): add_recovery_share with fail-closed validation (T6 step)`.

**Acceptance:** shares accumulate; every corruption/duplicate/foreign-label case is rejected at add-time with a specific code (spec §6).

---

### Task 6: `reconstruct_recovery_key` command (depends T2+T3)

**Files:**
- Modify: `crates/client-app/src/commands/recovery_custody.rs`
- Test: same module

- [ ] **Step 1:** Re-read spec §6 steps 2–3. Signature: `fn reconstruct_recovery_key(state: State<'_, CeremonySession>) -> Result<ReconstructResponse, UiError>`. Returns an opaque `ceremony_handle` bound to the session's now-reconstructed `EncSecretKey` — **never the key bytes**.
- [ ] **Step 2:** Failing tests: below-`k` shares → command rejects (maps `RecoveryError::ThresholdCombineFailed(InsufficientShares)`), no partial secret exposed; exactly-`k` and all-`n` both succeed and return a handle.
- [ ] **Step 3:** Implement: `admin_core::recovery::reconstruct_recovery_key(k, &shares)` → store the `EncSecretKey` in `CeremonySession` under a fresh handle → return `ReconstructResponse{ceremony_handle, label}`.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): reconstruct_recovery_key → opaque handle (T6 step)`.

**Acceptance:** reconstruct never returns key bytes; below-`k` fails closed; the whole key stays inside Rust state.

---

### Task 7: `prove_reconstructed_key` command (depends T3+T6)

**Files:**
- Modify: `crates/client-app/src/commands/recovery_custody.rs`
- Test: same module

- [ ] **Step 1:** Re-read spec §6 step 4 — success MUST be gated on a **real proof**, not `combine` returning `Ok`. Signature: `fn prove_reconstructed_key(req: ProveRequest, state: State<'_, CeremonySession>) -> Result<ProveResponse, UiError>`.
- [ ] **Step 2:** Failing test: split a real `EncSecretKey`, reconstruct from a `k`-subset, build a real recovery wire-wrap (mirror `recovery_wire_wrap` in `recovery.rs`), and `prove_reconstructed_key` reports `verified:true`; against a wrap built for a **different** DEK it reports `verified:false` (never panics, never a generic error swallowing the distinction).
- [ ] **Step 3:** Implement: look up the handle's `EncSecretKey` → `admin_core::recovery::validate_recovery_wrap(&secret, wrap, dek_commit, ctx)` → `ProveResponse{verified}`.
- [ ] **Step 4:** Run tests; green.
- [ ] **Step 5:** Commit: `feat(client-app): prove_reconstructed_key real-wrap proof (T6 step)`.

**Acceptance:** a reconstruction is only ever reported "verified" after opening something real — the load-bearing fail-closed property from spec §2.2.

---

### Task 8: `discard_ceremony_session` + registration + zeroization

**Files:**
- Modify: `crates/client-app/src/commands/recovery_custody.rs`, `main.rs`
- Test: same module

- [ ] **Step 1:** Signature: `fn discard_ceremony_session(state: State<'_, CeremonySession>) -> Result<(), UiError>`.
- [ ] **Step 2:** Failing test: after `discard`, session `have == 0` and any stored key/shares are gone (zeroized); a subsequent `reconstruct` fails (nothing to combine).
- [ ] **Step 3:** Implement discard (reset + zeroize). Confirm all five commands are registered in `main.rs`. Grep-assert no `hyper`/`http_client` import in `recovery_custody.rs` (spec §11 no-network gate).
- [ ] **Step 4:** Run tests + build; green.
- [ ] **Step 5:** Commit: `feat(client-app): discard_ceremony_session + register recovery-custody commands (T6 step)`.

**Acceptance:** session secrets are reliably zeroized on discard/exit; the command module performs zero network I/O.

---

### Task 9: Minimal non-secret ceremony log (D-G)

**Files:**
- Modify: `crates/client-app/src/commands/recovery_custody.rs` (write on explicit completion)
- Test: same module

- [ ] **Step 1:** Failing test: completing a split writes a log line with who/when, `k`/`n`, issued custodian indices, and the label — and asserts **no share/secret bytes** appear in it.
- [ ] **Step 2:** Implement an append-only local log write, only on explicit completion (mirrors §4 step 5's non-secret summary). Never logs share bytes.
- [ ] **Step 3:** Run tests; green.
- [ ] **Step 4:** Commit: `feat(client-app): non-secret ceremony log (T6 step)`.

**Acceptance:** an ordinary (non-secret) ceremony record exists; it never leaks secret material.

---

### Task 10: `<recovery-split-screen>` (wizard) — depends T4

**Files:**
- Create: `crates/client-app/ui/src/components/recovery-split-screen.ts`
- Modify: app navigation to add a "Recovery custody" entry (mirror the "Admin" entry)
- Test: Task 12 a11y lint + manual smoke

- [ ] **Step 1:** Re-read spec §4 + §9 (custody guidance copy). Build the flow: load sealed secret (file path + passphrase) → choose `k`/`n` with live guidance + warnings (`k=1` degenerate, `k=n` fragile; advisory `n≥3`, D-E) → Generate → present each share **one at a time** (§4.4) as copyable text + save-to-file (**no QR**, D-D), with the persistent "shown once" banner → completion summary with **no secret bytes**.
- [ ] **Step 2:** Wire `split_recovery_key` (T4) via a `serial()`-style single-flight; move focus to each new step's heading (wizard focus discipline, spec §10). Show the §9 custody guidance persistently; state re-split invalidation (D-F) explicitly.
- [ ] **Step 3:** Build/load; commit: `feat(ui): recovery-split-screen ceremony wizard (T6 step)`.

**Acceptance:** an operator can split offline, one share at a time, with custody guidance and no secret in the summary.

---

### Task 11: `<recovery-reconstruct-screen>` — depends T5+T6+T7

**Files:**
- Create: `crates/client-app/ui/src/components/recovery-reconstruct-screen.ts`
- Test: Task 12 a11y lint + a `node:test` state-machine test (mirror `settings-store.test.ts`)

- [ ] **Step 1:** Re-read spec §6. Build: add shares one at a time (paste text or pick file) → each goes through `add_recovery_share` (T5), showing count only ("3 of 5 needed"), never redisplaying bytes; reject malformed/corrupt/duplicate/foreign-label with specific `role=alert` copy. "Reconstruct" is `aria-disabled` until `have ≥ k` (no "try anyway").
- [ ] **Step 2:** On Reconstruct → `reconstruct_recovery_key` (T6) → **do not show success yet**; gate the green state on `prove_reconstructed_key` (T7) against a real wrap the operator supplies (spec §6 step 4). Add a frontend state-machine `node:test`: adding a duplicate index doesn't change `have`; Reconstruct disabled below `k`, enabled at exactly `k`.
- [ ] **Step 3:** Build/load; commit: `feat(ui): recovery-reconstruct-screen with prove-gated success (T6 step)`.

**Acceptance:** reconstruction UI is fail-closed end-to-end; "success" only after a real proof; shares never redisplayed.

---

### Task 12: a11y lint additions

**Files:**
- Modify: `crates/client-app/ui/src/a11y.test.ts`

- [ ] **Step 1:** Extend the dependency-free `node:test` suite (spec §10) to cover both new screens: labelled `<main>` focused on mount, `role=status`/`role=alert` split present, no icon-only buttons, QR-absence not required, focus order on wizard steps.
- [ ] **Step 2:** Run a11y suite; green.
- [ ] **Step 3:** Commit: `test(ui): a11y lint for recovery ceremony screens (T6 step)`.

---

### Task 13: e2e-shaped command-layer integration test (spec §12)

**Files:**
- Create: `crates/client-app/tests/recovery_custody_e2e.rs` (no Tauri runtime needed — exercise the command/crypto layer like `recovery.rs`'s own tests)

- [ ] **Step 1:** Implement spec §12's five scenarios: (1) split 3-of-5 → collect 3 valid → reconstruct → prove against a real wrap → **pass**; (2) only 2 shares → reconstruct unavailable/rejected, **InsufficientShares, no partial exposure**; (3) one flipped `body` char → **rejected at add-time by checksum**; (4) foreign-label share → **rejected at add-time**, plus belt-and-braces that a bypassed label check still fails the real-wrap proof; (5) reconstruct with all `n` shares still succeeds (DTO layer doesn't hardcode exactly-`k`).
- [ ] **Step 2:** Run; all green.
- [ ] **Step 3:** Commit: `test(client-app): recovery_custody_e2e covering spec §12 (T6)`.

**Acceptance:** all five spec gates pass.

---

### Task 14: Security review + sign-off

- [ ] **Step 1:** Run `superpowers:requesting-code-review` + `/security-review`. Verify **every** box in spec §11: whole secret only in `Zeroizing`/zero-on-drop for minimum span, never disk/log/Debug; share-holding types don't dump bytes; any `k-1` shares reveal nothing (inherited property, confirm no code concatenates/caches below `k`); checksum is UX-only (no path treats it as security); reconstruct fail-closed on all `ShamirError`/length cases; UI success never from `combine` alone; **no network in the module** (grep-checkable); `discard`/exit zeroizes; re-split invalidation documented in UI copy.
- [ ] **Step 2:** Write `docs/security-review-t6-shamir-recovery-ui.md` (PASS gate). Address any finding first.
- [ ] **Step 3:** Commit: `docs(security): T6 Shamir recovery UI sign-off`.
- [ ] **Step 4:** `superpowers:finishing-a-development-branch` to merge into `main`.

**Acceptance:** signed-off PASS, no Critical/High/Medium; merged.

---

## Self-review notes (author)

- **Spec coverage:** §2 grounding → T1 (D-B companion is new), T2 (§5), rest reuse shipped crypto. §3 architecture (offline, no-network) → T4–T8 + T8 grep-gate. §4 split UX → T4+T10. §5 encoding → T2. §6 reconstruct → T5+T6+T7+T11. §7 taxonomy → UI copy in T10/T11. §8 seam → T3. §9 custody copy → T10. §10 a11y → T12. §11 checklist → T14. §12 tests → T13. D-A→T10/T11, D-B→T1/T3/T4, D-C→scope (classical only, no PQ task), D-D→T10, D-E→T4/T10, D-F→T10 copy, D-G→T9.
- **Type consistency:** `open_recovery_secret` (T1) consumed by T4; `parse_and_verify`/`encode` (T2) by T4/T5; `CeremonySession` (T3) by T5/T6/T7/T8; `ceremony_handle` (T6) by T7. DTO names match spec §8 (with the D-B passphrase field added to `SplitRecoveryKeyRequest`).
- **No placeholders:** each task names exact files, a concrete signature, a first failing test with the specific assertion, and a commit. Exhaustive copy/error detail delegated to the cited spec sections (spec is authoritative).
- **Scope note:** D-C keeps this to zero-new-crypto except the T1 sealed-file companion; the ML-KEM half is explicitly out.
