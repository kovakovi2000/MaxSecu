# Trusted-Server Recovery + Registration-Key Enrollment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement
> this plan task-by-task (fresh implementer per task + two-stage spec→quality review). Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the offline-ceremony / bootstrap-secret / pending-queue / per-user-buddy / Shamir
model with a single **trusted-server** design: one embedded-pinned **recovery account**, **registration-
key-only** enrollment (first key = admin), a **channel-bound challenge-response** recovery login, and a
**fail-closed trust alarm** (embedded recovery pin + TOFU user keys + transparency).

**Architecture:** The server signs/serves bindings and authorizes enrollment; clients never blindly
trust served keys — the recovery pubkey is compiled into the client, user keys are TOFU-pinned, and all
issuance is logged to the existing key-transparency log. A new `maxsecu-setup` CLI generates the recovery
account once. See spec: `docs/superpowers/specs/2026-07-03-trusted-server-recovery-registration-design.md`
(read **§0 locked decisions** + **§2 grounding** first).

**Tech Stack:** Rust (server, client-core, client-app own workspace, admin-core, crypto), Tauri 2,
vanilla-TS UI, real-TLS e2e. `cargo` NOT on PATH — prefix `export PATH="$HOME/.cargo/bin:$PATH"`.
NEVER `cargo fmt --all`. Only DTOs cross the Tauri seam. client-app is its own workspace (build/test
from `crates/client-app` with `--no-default-features --lib` for lib tests).

---

## Dependency graph (dispatch order)

```
Wave 1 (parallel, file-disjoint):
  T1  Retire Shamir/escrow-recovery + T6 stack (fix Phase-7 gate)
  T2  Server: registration-key store + first-admin flag
  T3  Server: recovery-account store (once-only) + serve pubkey
  T7  client-app: embedded recovery-pin module + build.rs + compare helper

Wave 2 (depends on Wave 1):
  T4  Server: registration-key-only enrollment endpoint (needs T2,T3)   [removes bootstrap/vouchers/pending]
  T5  Server: recovery register/challenge/verify endpoints (needs T3)
  T8  client-app: retarget upload auto-wrap to embedded pin + alarm-A (needs T7)
  T9  client-app: TOFU user-key store + fingerprint + alarm-B

Wave 3 (depends on Wave 2):
  T6  Server: wire enrollment into transparency log (needs T4)
  T11 client-app: recovery challenge-response login (needs T5,T7)
  T12 client-app: registration-key startup mode + panel (needs T4)
  T14 tools/maxsecu-setup CLI (needs T4,T5,T7)

Wave 4 (integration):
  T10 client-app: transparency verification wiring + alarm-C (needs T6)
  T13 client-app: startup precedence + shared trust-alarm modal (needs T8–T12)
  T15 Remove portable-server bootstrap-secret; supersede demo-seed; runbook/scripts (needs T4,T5,T14)

Wave 5:
  T16 Holistic e2e + security-review sign-off (PASS gate)
```

Create the feature branch **`feat/trusted-server-recovery`** before Task 1.

---

## File structure

- **Remove:** `crates/crypto/src/shamir.rs`, `crates/admin-core/src/recovery.rs`,
  `crates/admin-core/src/recovery_seal.rs`, `crates/client-app/src/{ceremony.rs,recovery_share.rs}`,
  `crates/client-app/src/commands/recovery_custody.rs`,
  `crates/client-app/ui/src/components/recovery-{split,reconstruct}-screen.ts`,
  `crates/client-app/ui/src/core/recovery-reconstruct-store.ts(+.test.ts)`,
  `crates/client-app/tests/recovery_custody_e2e.rs`.
- **Server new:** `crates/server/src/reg_keys.rs` (store trait ext usage), `recovery.rs` (recovery
  endpoints); modify `http.rs`, `store` trait + `MemoryStore`/`PgStore`.
- **client-app new:** `src/recovery_pin.rs` (+ `build.rs`), `src/tofu.rs`, `src/commands/recovery_login.rs`,
  `src/commands/register.rs`; modify `upload.rs`, `directory.rs`, `config.rs`, `dto.rs`, `state.rs`,
  `lib.rs`, `main.rs`.
- **UI new:** `components/recovery-login-screen.ts`, `components/register-screen.ts`,
  `components/trust-alarm.ts`; modify `app-shell.ts`, `core/*`.
- **Tool new:** `tools/maxsecu-setup/` (own crate; member of the client-app workspace like `demo-seed`).

---

## Task 1: Retire Shamir / escrow-recovery / T6 stack

**Files:** delete the "Remove" list above; update all callers.

**Context:** T6 (this repo's Shamir *UI*) sits atop Phase-7 escrow-recovery (`crypto::shamir`,
`admin-core::recovery`). Spec §0/§8 retire the whole Shamir idea. The Phase-7 exit-gate e2e
(`crates/server/tests/phase7_hardening_e2e.rs`) exercises K-of-N recovery — that gate must be
**removed/trimmed** too. Everything else in Phase-7 (PQ-hybrid wrap, transparency) stays.

- [ ] **Step 1 — Inventory callers.** Run `export PATH="$HOME/.cargo/bin:$PATH"` then
  `grep -rn "shamir\|admin_core::recovery\|recovery_seal\|recovery_custody\|recovery_share\|ceremony::" crates tools`
  (Grep tool). Record every file. Expected: T6 client-app modules, admin-core/crypto modules, the
  phase7 recovery gate, and re-exports in `lib.rs` files.
- [ ] **Step 2 — Delete the modules** and their `mod`/`pub use` lines in each crate's `lib.rs`.
- [ ] **Step 3 — Trim the Phase-7 gate.** In `phase7_hardening_e2e.rs` remove the K-of-N recovery gate
  and its imports; keep the PQ-hybrid and transparency gates. If a helper is now unused, delete it.
- [ ] **Step 4 — Remove T6 DTOs** from `crates/client-app/src/dto.rs` (Split/AddShare/Reconstruct/Prove/
  SplitCeremonyLog types) and the T6 command registrations in `main.rs`, and the split/reconstruct routes
  + nav entries in `ui/src/components/app-shell.ts`, and their `a11y.test.ts` checks.
- [ ] **Step 5 — Build the whole tree green.** Run (repo root) `cargo build --workspace` and
  `cd crates/client-app && cargo build`. Then `cargo test -p maxsecu-crypto -p maxsecu-admin-core` and
  `cargo test -p maxsecu-server --test phase7_hardening_e2e` and `cd crates/client-app && cargo test --no-default-features --lib`.
  Expected: all green, **zero** dangling references to the removed items.
- [ ] **Step 6 — Commit.** `docs`+code: `refactor(retire): remove Shamir escrow-recovery + T6 UI stack`.

---

## Task 2: Server — registration-key store + first-admin flag

**Files:** Create `crates/server/src/reg_keys.rs`; modify the `Store` trait + `MemoryStore` + `PgStore`
(wherever they live, e.g. `crates/server/src/store*.rs`), `docs/schema.sql`.

**Context:** Registration keys are strong single-use secrets. Store only `sha256(key)`. Track whether
any user exists yet (for first-admin).

- [ ] **Step 1 — Failing test** (`reg_keys.rs` unit tests, `MemoryStore`): issue a key hash →
  `consume_registration_key(hash)` returns `true` once then `false` (single-use); an unknown hash →
  `false`; `any_user_exists()` is `false` before the first user and `true` after.
- [ ] **Step 2 — Run, verify FAIL** (`cargo test -p maxsecu-server reg_keys`).
- [ ] **Step 3 — Implement** `Store` methods: `issue_registration_key(hash:[u8;32], ttl_ms)`,
  `consume_registration_key(hash) -> Result<bool>` (atomic delete-on-consume, mirror `consume_voucher`),
  `any_user_exists() -> Result<bool>`. Add the `registration_keys` table to `schema.sql` + `PgStore`
  impl (mirror the existing voucher table).
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(server): single-use registration-key store + first-admin flag`.

---

## Task 3: Server — recovery-account store (once-only) + serve pubkey

**Files:** modify `Store` trait + impls; `docs/schema.sql`.

- [ ] **Step 1 — Failing test:** `set_recovery_account(enc_pub, sig_pub)` succeeds once and returns the
  stored pubkeys via `recovery_account() -> Option<...>`; a second `set_recovery_account` returns
  `Err(AlreadyExists)` / `Ok(false)` and does NOT overwrite.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the once-only setter + getter in `MemoryStore` + `PgStore`
  (`recovery_account` single-row table). Encryption pubkey is what challenges wrap to and clients
  compare to the embedded pin.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(server): once-only recovery-account store`.

---

## Task 4: Server — registration-key-only enrollment (replaces bootstrap/vouchers/pending)

**Files:** modify `crates/server/src/http.rs` (rewrite `POST /v1/users`; delete `/v1/bootstrap`,
`/v1/vouchers`, `/v1/pending` + `list_pending` + `bootstrap_*`); add admin `POST /v1/registration-keys`.
Depends: T2, T3.

**Context:** The server now holds the binding **signing key** (the portable server already persists a
dev signing seed at `config/d5_secret.bin`; `admin-core::DirectorySigner` signs). Spec §5/§0-D5.

- [ ] **Step 1 — Failing e2e** (`crates/server/tests/enrollment_e2e.rs`, over real TLS, mirror existing
  server e2e): issue a registration key (admin path or seeded) → `POST /v1/users` with it + fresh
  identity → `201`, and immediately `GET /v1/directory/<user>` returns a **server-signed** binding
  (verifiable under the served signing pubkey). The **first** such user has role `[User,Admin]`; a
  **second** user (second key) has `[User]`. Re-using a consumed key → `403`. `POST /v1/bootstrap`,
  `/v1/vouchers`, `/v1/pending` → `404`.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement:** in `POST /v1/users` consume the reg key first (single-use); on success
  create the user, compute roles (`any_user_exists()==false` → `[User,Admin]` else `[User]`), build the
  binding, **sign it server-side** with `DirectorySigner`, store it (so `GET /v1/directory` serves it),
  delete the key. Add admin-gated `POST /v1/registration-keys` that mints a **user-role** single-use key
  (returns the plaintext key once; stores only its hash). Delete the removed routes/handlers.
- [ ] **Step 4 — Run, verify PASS** + `cargo test -p maxsecu-server` green.
- [ ] **Step 5 — Commit** `feat(server): registration-key-only enrollment; server-signed bindings; first=admin`.

---

## Task 5: Server — recovery register / challenge / verify endpoints

**Files:** create `crates/server/src/recovery.rs`; wire routes in `http.rs`. Depends: T3.

**Context:** Spec §6. Challenge = fresh random, single-use, TTL, wrapped to the recovery **enc** pubkey.
Verify is **channel-bound** to the connection's RFC-5705 exporter (mirror the login proof labels used in
`client-app/src/session.rs` / server login verify).

- [ ] **Step 1 — Failing e2e** (`crates/server/tests/recovery_login_e2e.rs`): with a recovery account set,
  `POST /v1/recovery/register` again → `409`. `POST /v1/recovery/challenge` → returns a blob that unwraps
  with the recovery private key to a nonce; `POST /v1/recovery/verify` with a correct **channel-bound**
  proof over `(nonce, server_id, exporter)` → `200` + a session token whose role is admin. A replayed
  challenge → rejected; a proof from a different exporter → rejected; wrong key → rejected.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** `register_recovery` (once-only via T3), `issue_challenge` (random nonce,
  store `sha256(nonce)`+expiry single-use, wrap to recovery enc-pub), `verify_challenge` (consume nonce,
  verify the channel-bound proof, mint an admin session). Add `GET /v1/recovery/pubkey`.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(server): channel-bound one-time recovery challenge login`.

---

## Task 6: Server — wire enrollment into the transparency log

**Files:** modify `http.rs` enrollment path to append each new binding to the `sink-server::dirlog`
producer; ensure the position/consistency endpoints the client needs are reachable. Depends: T4.

- [ ] **Step 1 — Failing e2e** (extend `enrollment_e2e.rs`): after enrolling two users, the transparency
  log contains both bindings; an inclusion proof for user 1 verifies; a consistency proof between the two
  tree heads verifies (reuse `crypto::merkle` verify).
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the append-on-enrollment + expose/confirm the inclusion/consistency read
  path (reuse the existing dirlog + `GET` position endpoints from Phase-7).
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(server): append enrollments to the key-transparency log`.

---

## Task 7: client-app — embedded recovery-pin module + build.rs + compare helper

**Files:** create `crates/client-app/src/recovery_pin.rs` + `crates/client-app/build.rs` addition;
add a `unpinned-dev` cargo feature. Depends: none.

**Context:** Spec §0-A/§3. The recovery **enc** pubkey is a compile-time constant. Mirror the
`ffmpeg_bin.rs` `include_bytes!` pattern: `build.rs` reads a gitignored `recovery_pin.bin` (written by
`maxsecu-setup`, T14) and generates a const; if absent AND `unpinned-dev` is off → **build fails**.

- [ ] **Step 1 — Failing test** (`recovery_pin.rs`, under `--features unpinned-dev`): `embedded_pin()`
  returns the test pin; `compare_served(served) -> Result<(), TrustAlarm>` returns `Ok` on equal and a
  `TrustAlarm::RecoveryPinMismatch` on differing input.
- [ ] **Step 2 — Run, verify FAIL** (`cd crates/client-app && cargo test --no-default-features --features unpinned-dev recovery_pin`).
- [ ] **Step 3 — Implement** the `build.rs` codegen (present-file → `const`; absent+`unpinned-dev` →
  a labelled zero/test pin; absent+no-feature → `panic!`/`cargo:warning`+compile_error), `embedded_pin()`,
  and `compare_served`. Add `recovery_pin.bin` to `.gitignore`.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(client): embedded recovery-pin (compile-time) + compare`.

---

## Task 8: client-app — retarget upload auto-wrap to the embedded pin + trust-alarm A

**Files:** modify `crates/client-app/src/commands/upload.rs`, `directory.rs`, `config.rs`; remove
`recovery_recipient_username` + `resolve_recovery_recipient`. Depends: T7.

**Context:** Spec §3/§7. Uploads wrap to `self` + the **embedded** recovery pin. Before wrapping, fetch
`GET /v1/recovery/pubkey` and `compare_served` against the pin; mismatch → return a `server_untrusted`
error (no wrap, no upload).

- [ ] **Step 1 — Failing test/e2e** (`crates/client-e2e/tests/upload_recovery_wrap_e2e.rs`): an upload
  wraps to self + the embedded pin (assert the recovery wrap decrypts with the pin's private key); when
  the served recovery pubkey ≠ pin, `confirm_upload` fails closed with `server_untrusted` and no bytes are
  stored.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the retarget + the pre-wrap compare gate; delete the buddy config reader +
  `resolve_recovery_recipient` and their callers/tests.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(client): wrap uploads to embedded recovery pin; block on pin mismatch`.

---

## Task 9: client-app — TOFU user-key store + fingerprint + trust-alarm B

**Files:** create `crates/client-app/src/tofu.rs`; modify `directory.rs` (resolve path) + `commands/share.rs`.

**Context:** Spec §0-B/§7. First sight of a username→key pins it locally (sealed store beside the
keystore); a later differing key → `server_untrusted`. Expose a short fingerprint for display.

- [ ] **Step 1 — Failing test** (`tofu.rs`): `check_or_pin(username, key)` returns `Pinned` first time,
  `Match` on the same key, `Changed` on a different key; `fingerprint(key)` is stable + short.
- [ ] **Step 2 — Run, verify FAIL** (`cd crates/client-app && cargo test --no-default-features --lib tofu`).
- [ ] **Step 3 — Implement** the sealed on-disk TOFU map + `check_or_pin` + `fingerprint`; wire it into
  the recipient-resolve used by share/browse so a `Changed` result raises alarm-B and blocks the action.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(client): TOFU user-key pinning + fingerprint + change alarm`.

---

## Task 10: client-app — transparency verification wiring + trust-alarm C

**Files:** modify the browse/open path (`directory.rs`/`download.rs`/`feed.rs`) to verify inclusion +
consistency via `client-core::transparency`. Depends: T6.

- [ ] **Step 1 — Failing e2e** (`crates/client-e2e/tests/transparency_alarm_e2e.rs`): a normally-served
  binding verifies (inclusion + consistency) and the action proceeds; a tampered/inconsistent log head
  → `server_untrusted` and the open is blocked.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the verification calls (reuse `client-core::transparency` + the Phase-7
  `fetch_*_pos` sink helpers) at the resolve/open boundary; failure → alarm-C + block.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(client): verify transparency proofs on open; alarm on inconsistency`.

---

## Task 11: client-app — recovery challenge-response login (D6)

**Files:** create `crates/client-app/src/commands/recovery_login.rs`; modify `dto.rs`, `state.rs`,
`lib.rs`, `main.rs`; load the recovery key file. Depends: T5, T7.

**Context:** Spec §6. Reuse `session.rs` exporter + proof labels. The recovery private key is loaded from
the file beside the exe; it **never** crosses the Tauri seam (opaque handle / stays in Rust).

- [ ] **Step 1 — Failing e2e** (`crates/client-app/tests/recovery_login_e2e.rs`): with the recovery key
  file present, `request_recovery_challenge` + `answer_recovery_challenge` yield an admin session over
  real TLS; a wrong key file → fail closed; a replayed challenge → rejected.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the two commands (load key → request challenge → unwrap → channel-bound
  proof → verify → store admin session), returning only DTOs.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(client): recovery challenge-response login`.

---

## Task 12: client-app — registration-key startup mode + panel

**Files:** create `crates/client-app/src/commands/register.rs` + `ui/.../register-screen.ts`; modify
`dto.rs`, `main.rs`, `app-shell.ts`. Depends: T4.

- [ ] **Step 1 — Failing e2e** (`crates/client-app/tests/register_e2e.rs`): with a `register.key` file
  present, `register_with_key(username, passphrase)` creates the account (server `201`), seals the new
  identity into the keystore, and **deletes** the local key file; a second run with the same (now
  consumed) key → fail closed. First registrant lands as admin.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the command (generate identity → `POST /v1/users` with the key → seal
  keystore → delete local key file) + the `<register-screen>` panel.
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(client): registration-key enrollment panel`.

---

## Task 13: client-app — startup precedence + shared trust-alarm modal

**Files:** modify `ui/src/components/app-shell.ts` + boot logic; create `components/trust-alarm.ts`;
add a `startup_mode` command. Depends: T8–T12.

**Context:** Spec §5/§7/§0-D7. Precedence recovery-key file → register-key file → normal. One shared
modal renders any `server_untrusted`-class error (A/B/C) and blocks.

- [ ] **Step 1 — Failing tests** (UI unit + a `startup_mode` unit test): `startup_mode()` returns
  `recovery` when the recovery file is present (even if a register file also is), `register` when only the
  register file is, else `normal`. UI test: a `server_untrusted` error opens `<trust-alarm>` and the
  action does not proceed.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** `startup_mode()` precedence + route selection at boot; the shared
  `<trust-alarm>` modal wired to the A/B/C error class.
- [ ] **Step 4 — Run, verify PASS** (`cd crates/client-app/ui && npm test`; lib test as above).
- [ ] **Step 5 — Commit** `feat(client): startup precedence + shared fail-closed trust alarm`.

---

## Task 14: tools/maxsecu-setup CLI

**Files:** create `tools/maxsecu-setup/` (own crate; add to the client-app workspace `members` like
`demo-seed`). Depends: T4, T5, T7.

**Context:** Spec §4. One-shot: generate recovery identity → `POST /v1/recovery/register` (abort on
`409`) → write the **sealed** private-key file (`--out`, passphrase) → write `recovery_pin.bin` for the
build (`--pin-out`) → obtain + write the first registration key (`--first-key-out`). Zeroize transients.

- [ ] **Step 1 — Failing e2e** (`tools/maxsecu-setup/tests/setup_e2e.rs` or a client-e2e test): against a
  fresh server the tool writes all three artifacts and exits 0; running it again → `409`, exits non-zero,
  writes nothing new. The emitted `recovery_pin.bin` equals the server's stored recovery enc-pub.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the CLI (reuse `client-app` transport/keystore sealing like `demo-seed`
  does) + the first-registration-key issuance (server issues it as part of recovery register, OR the tool
  calls the admin mint path using the recovery session — pick the simplest that keeps first-user=admin).
- [ ] **Step 4 — Run, verify PASS.**
- [ ] **Step 5 — Commit** `feat(setup): maxsecu-setup CLI (recovery account + first key + pin)`.

---

## Task 15: Remove portable-server bootstrap-secret; supersede demo-seed; runbook/scripts

**Files:** modify `crates/portable-server/src/{bootstrap.rs,run.rs,config.rs,main.rs}`; delete
`tools/demo-seed` (or convert to a thin wrapper over `maxsecu-setup`); update
`docs/local-demo-runbook.md`, `dist/*.ps1`. Depends: T4, T5, T14.

- [ ] **Step 1 — Failing test** (`portable-server` boot smoke, updated): the server boots with **no**
  bootstrap secret printed; recovery-registration is open until used, then closed. Old `boot_smoke.rs`
  bootstrap-secret assertions are replaced.
- [ ] **Step 2 — Run, verify FAIL.**
- [ ] **Step 3 — Implement** the removal of the secret generation/marker + the DEV-profile banner update;
  retire `demo-seed`; update the runbook to the new `maxsecu-setup` → rebuild-client → run flow.
- [ ] **Step 4 — Run, verify PASS** (`cargo test -p maxsecu-portable-server`).
- [ ] **Step 5 — Commit** `chore: remove bootstrap secret; supersede demo-seed with maxsecu-setup`.

---

## Task 16: Holistic e2e + security-review sign-off

**Files:** create `docs/security-review-trusted-server-recovery.md`; add any missing cross-cutting e2e.

- [ ] **Step 1 — Full-flow e2e** over real TLS: `maxsecu-setup` (recovery + first key) → rebuild client
  with pin → first user registers = admin → admin mints a user key → second user registers = user →
  user uploads → recovery login decrypts the upload → each trust-alarm (A/B/C) trips and blocks.
- [ ] **Step 2 — Run all suites** green (`cargo test --workspace`; `cd crates/client-app && cargo test
  --no-default-features --lib` + the e2e tests; `cd ui && npm test`).
- [ ] **Step 3 — Adversarial review** of the whole diff against spec §0/§9 (embedded-pin fail-closed,
  once-only recovery, single-use keys deleted, channel-bound one-time challenge, session≠key, no key
  material across the seam/logs, zeroization). Write the sign-off doc. Fix any Critical/High/Medium.
- [ ] **Step 4 — Commit** `docs(security): trusted-server recovery sign-off (PASS)`.
- [ ] **Step 5 — Finish** via superpowers:finishing-a-development-branch (merge `--no-ff` to local `main`).

---

## Self-review notes (plan ↔ spec coverage)

- Spec §0 A/B/C → T7/T8 (A), T9 (B), T6/T10 (C); D2 alarm → T8/T9/T10/T13; D3 recovery account → T3/T5/
  T8/T14; D4 CLI → T14; D5 registration → T2/T4; D6 recovery login → T5/T11; D7 precedence → T13;
  D8 remove recovery_seal → T1.
- §8 removal list → T1 (Shamir/T6), T4 (bootstrap/vouchers/pending), T15 (bootstrap secret/demo-seed/buddy
  — buddy also in T8).
- §10 testing rows each map to a task's Step-1 e2e.
- **Risk flagged:** T1 must trim the Phase-7 K-of-N gate (not just T6 UI). **Risk:** T7/T14 build-embed
  loop — the client must be rebuilt after `maxsecu-setup`; tests use `--features unpinned-dev`.
