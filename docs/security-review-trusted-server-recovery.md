# Trusted-Server Recovery + Registration-Key Enrollment — Security Review & Sign-off

**Scope:** the entire `feat/trusted-server-recovery` change set — `git diff main..HEAD`
(base `main` = `7f54274`; HEAD = `1b0660e`; 25 task commits `093dc0a..1b0660e`, 104 files,
~9.7k insertions / ~7.2k deletions). This is the redesign that makes the single-operator
server **trusted for availability + authorization but never for the keys that decide who can
read data** (spec `docs/superpowers/specs/2026-07-03-trusted-server-recovery-registration-design.md`,
§0 locked decisions / §9 security considerations).

Reviewer: T16 final adversarial pass over the new identity / enrollment / recovery / trust-alarm
surface, reading the actual code (server `http.rs`/`recovery.rs`/`auth.rs`/`store.rs`/`pg.rs`/
`reg_keys.rs`/`recovery_account.rs`; client `recovery_pin.rs`/`build.rs`/`directory.rs`/`tofu.rs`/
`transparency.rs`/`commands/{recovery_login,register,startup,admin,bootstrap}.rs`; `tools/maxsecu-setup`)
against an adversary who controls the server, the wire, and arbitrary attacker-supplied bytes.
Per-task quality reviews were done at implementation time; this is the cumulative gate before merge.

**Verdict:** **PASS** — **no Critical, High, or Medium findings**. One **Low** (dead retired
client surface — the pre-existing bootstrap/glass-break Tauri commands were not deleted; they are
inert, 404/422 fail-closed, no auth bypass) plus Info-level observations and the documented,
independently-confirmed accepted residuals below. No fix commit is required to pass the gate;
the Low is a recommended cleanup.

---

## 1. Trust model (what this review is protecting)

The server is trusted to admit accounts and confer admin, but **not** to hold the keys that gate
reads. Three fail-closed layers enforce that; any trip raises the shared `server_untrusted` modal
and **blocks the in-flight action** (no partial upload/share/login/open):

| Layer | Protects | Mechanism | Trip → |
|-------|----------|-----------|--------|
| **A** | The crown-jewel recovery wrap target | Recovery pubkey **compiled into the client** (embedded pin); served key only ever **compared** | block + `server_untrusted` |
| **B** | User↔user keys (sharing/authorship) | TOFU pin of the D5 fingerprint (`SHA-256(enc‖sig)`) | block + `server_untrusted` |
| **C** | Server equivocation about keys | Directory KT log inclusion/consistency under a pinned log key + gossip | block + `server_untrusted` |

The one truly load-bearing secret is the **recovery private key**, kept cold by the operator as a
single Argon2id-sealed file; a stolen recovery *session* decrypts nothing. **Non-goal (spec §9):**
hiding data from a malicious operator — the operator holds the recovery key by design; A/B/C make
operator *equivocation about keys* detectable, they do not provide operator confidentiality.

---

## 2. Per-invariant findings & dispositions

| # | Invariant (spec §0/§9) | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | **Embedded pin fail-closed (A)** | **Sound (✓).** `build.rs` `panic!`s the build when `recovery_pin.bin` is absent **unless** `--features unpinned-dev` (a non-default, clearly-labelled, `cargo:warning`-emitting NON-SECURE test pin); the real path is `include_bytes!` of the operator file — no silent zero/empty pin. `directory::resolve_recovery_pin` fetches `GET /v1/recovery/pubkey`, canonicalizes the served halves, and `compare_served` **constant-time full-blob** compares them to the pin; on any mismatch it returns `server_untrusted` **before any wrap/stage/byte** and wraps to the **embedded** pin's halves (never the served bytes). The canonical pin covers X25519 **and** the optional ML-KEM-768 half (enc32‖tag‖mlkem1184), so a swapped ML-KEM half trips the alarm (`ct_compare_covers_mlkem_half`). `parse_pin` fail-closes on every malformed length/tag. | — | Accepted (correct). |
| 2 | **Recovery account once-only + PUBLIC-only** | **Sound (✓).** `set_recovery_account` is once-only: Pg via the singleton PK `INSERT … ON CONFLICT (id) DO NOTHING`, Memory via an `is_some()` guard under the single lock — a second attempt returns `false`/`409` and **never overwrites** (`second_set_does_not_overwrite`). The server persists **only** public keys (enc/sig/optional ML-KEM). The private key exists solely as `maxsecu-setup`'s Argon2id-sealed cold file; it seals **before** the once-only register (`seal_recovery_blob` is pure-CPU, computed first) so a seal failure can't orphan a committed account, artifacts are written create-new, and a post-commit write failure triggers `emergency_dump` (prints the **passphrase-encrypted** sealed blob + the first key — never the passphrase or a bare private key). A second `maxsecu-setup` run 409s at register and writes nothing (pre-flight guards run first). | — | Accepted (correct). |
| 3 | **Recovery-login blast radius (§9)** | **Sound (✓).** A successful `POST /v1/recovery/verify` mints a session whose principal is the reserved `RECOVERY_ID` (all-zero `Id`). `AuthedSession` (every file/content endpoint) **explicitly rejects `RECOVERY_ID` → 403** — barred structurally, not merely "owns no files". `AdminSession` admits `RECOVERY_ID` for admin **server** actions only (mint user-role keys); it builds on the shared `resolve_session`, **not** on `AuthedSession`, and the normal D5-verified user-admin path (stored binding verifies under the pinned D5 key, in-window, `Role::Admin`) is unchanged. The challenge is channel-bound (RFC-5705 exporter folded into the signed `AuthProofContext`) and single-use (nonce consumed before the token is minted); every failure is a uniform 401 (no oracle). It yields **only** an opaque token — never a private key; the cold recovery `Identity` is loaded in Rust, held in module-private managed state, and zeroized on drop. `RECOVERY_ID` is unreachable as a real user (ids are server-assigned 16-byte random; the all-zero sentinel has 2⁻¹²⁸ collision odds — see residual R1). | — | Accepted (correct). |
| 4 | **Registration keys single-use + atomic enrollment** | **Sound (✓).** Keys are stored `sha256`-only and consumed atomically. `Store::enroll` is one all-or-nothing unit: Pg wraps consume-key → create-user → claim-first-admin → store-binding in a single transaction with `rollback` on every early exit (`KeyInvalid`/`UsernameTaken`), Memory checks all preconditions before mutating under one lock. First-ever registrant = admin via an atomic claim (`INSERT INTO first_admin_claim … ON CONFLICT DO NOTHING` / the flag under the lock) — no TOCTOU. Admin-minted keys are structurally **user-role only**: by the time any admin exists to mint, a user already exists, so `claim_first_admin` returns `false`. `POST /v1/users` builds+signs **both** role bindings pure (server holds the D5 private seed; only signatures cross into the store) and `enroll` stores exactly the one matching its admin decision, so role and signed binding can never diverge. A malformed request is validated **before** any store I/O, so it can't burn a key. | — | Accepted (correct). |
| 5 | **No key material across the seam / in logs / Debug** | **Sound (✓).** Only DTOs cross the Tauri seam (`dto.rs` carries no `Identity`/private/wrapped/nonce field; `RecoveryChallengeDto`/`RecoveryLoginDto` are status+public `server_id` only). The only secret-shaped inputs are keystore `passphrase: String` (register/recovery-login), each wrapped in `Zeroizing` and scrubbed on every path. The recovery nonce is `Zeroizing`; the recovery `Identity` + nonce are dropped/zeroized before touching shared state; the admin token is stored server-side in managed `Session` state and never returned to the UI. The D5 `dir_signer` private seed lives only in `AuthService` (behind `Arc<SigningKey>`), never in a DTO/response/log. No `println!/log/tracing/dbg!/Debug` prints key material in the new server or client recovery/reg code; `maxsecu-setup`'s emergency dump is operator-local and prints only the sealed (passphrase-encrypted) blob + the intended-anyway first key. | — | Accepted (correct). |
| 6 | **TOFU (B) + transparency (C) sealed + fail-closed** | **Sound (✓).** Both stores are sealed on disk under an **identity-derived** HKDF key (domain-separated labels), atomic-replace on write, and **fail closed** (`server_untrusted`) on any decrypt/parse error or a foreign identity (`corrupt_store_fails_closed_on_open`, `A DIFFERENT identity cannot read`). TOFU: a first sighting pins; a **changed** fingerprint → `UserKeyChanged` → block (pin not overwritten). KT: reuses the shipped `client-core::transparency` + `crypto::merkle` (`verify_inclusion` / `verify_binding_in_log`) — **no re-implemented merkle**; the checkpoint **signature is verified under the pinned KT key BEFORE** the O(tree_size) index-discovery scan, plus a `MAX_KT_TREE_SIZE` cap, so a forged/oversized `tree_size` can't drive unbounded fetches (DoS guard). Every `KtError` (bad-checkpoint / split-view / rollback / not-included) maps to one `server_untrusted` block; the gossip checkpoint advances+persists only after the full verify succeeds. | — | Accepted (correct). |
| 7 | **Retirement safety** | **Mostly sound.** `crypto/shamir.rs` (−382) and `admin-core/recovery_seal.rs` (−271) deleted; the Shamir K-of-N portion of `admin-core/recovery.rs` removed (−148, leaving only the pre-existing §12.7 offline recovery-grant issuance); `client-app/recovery_share.rs`, the T6 split/reconstruct UI + stores, `tools/demo-seed`, the per-user `recovery_recipient.txt` reader, the server `/v1/bootstrap`+`/v1/vouchers`+`/v1/pending` routes, and the portable-server bootstrap-secret are all gone. **Phase-7 PQ-hybrid wrap + KT transparency are KEPT** (`crypto::hybrid` exports intact, `phase7_hardening_e2e.rs` present). **GAP → Finding L-1 (Low):** the client-app's pre-existing bootstrap/glass-break Tauri commands were left registered (see below). | Low (L-1) | Recommend cleanup; **not a PASS-blocker** (inert). |
| 8 | **Test-only surface excluded from production** | **Sound (✓).** `maxsecu-client-app/unpinned-dev` and `maxsecu-client-core/test-support` are both **non-default** (`= []`) features, enabled **only** by `crates/client-e2e`. `Identity::from_test_seeds` is behind `test-support`; the fixed-seed test pin is behind `unpinned-dev` (build emits a `cargo:warning`). Neither the test seed path nor the test pin is reachable in a shipped build (a real build embeds the operator pin or fails closed). | — | Accepted (correct). |
| 9 | **Crypto discipline** | **Sound (✓).** New flows are exercised e2e over real TLS with real crypto (`register_e2e`, `recovery_login_e2e`, `upload_recovery_wrap_e2e`, `transparency_alarm_e2e`, `enrollment_e2e`, `enrollment_transparency_e2e`, `full_flow_e2e` capstone setup→enroll→upload→recovery-decrypt). Transient key material is `Zeroizing`. PQ `Suite::V2` is preserved for recovery-wrapped uploads: `maxsecu-setup` always registers a hybrid recovery account, the challenge wraps V2 (`wrap_dek_hybrid`), and uploads emit V2 when self+recovery are PQ. | — | Accepted (correct). |

---

## 3. Findings by severity

| ID | Severity | Finding | Location | Disposition |
|----|----------|---------|----------|-------------|
| **L-1** | **Low** | The retirement did not delete the client-app's **legacy bootstrap/glass-break commands**: `commands::bootstrap::{register_glassbreak, create_first_admin, register_user, account_status}` are still registered in `main.rs`, and `register_glassbreak`/`create_first_admin` still `POST /v1/bootstrap` (route removed) while `register_user` posts an `enrollment_voucher` to `/v1/users` (which now **requires** `registration_key`). The `bootstrap.rs` module (`generate_glassbreak`) and the `BootstrapRequest`/`GlassbreakResponse`/`FirstAdminRequest` DTOs (with `bootstrap_secret`) also remain. **Verified inert:** `/v1/bootstrap` returns 404 and the local keystore is sealed **only after** a 201, so nothing is created or written on the dead path; `register_user`'s body omits the now-mandatory `registration_key`, so serde rejects it (422) — **no account creation, no privilege, no auth bypass, no key leak.** It is dead attack surface that contradicts the §8 "no dangling references" retirement mandate. | `crates/client-app/src/commands/bootstrap.rs`; `src/main.rs:55-58`; `src/bootstrap.rs`; `src/dto.rs:32-51` | **Recommended cleanup** (delete the module + DTOs + `invoke_handler` entries + the `pub mod bootstrap`). Non-blocking. |

**No Critical, High, or Medium findings.**

### Info-level observations (no action required)

- **Uniform hex hardening.** `http.rs::hex_fixed` now ASCII-gates before slicing (`if !s.is_ascii() || s.len() != 2*N { return None }`), closing the non-ASCII multibyte slice-panic class (same as T6 M-1) across every hex JSON field, including the attacker-reachable `recovery_verify` `challenge_id`. `hex16` in the client recovery-login mirrors it. (✓)
- **No recovery-login rate limiter.** Recovery register/challenge/verify are not behind the anti-automation limiter (operator-only, low volume); replay/relay are covered by the single-use nonce + exporter binding, and `verify` is a uniform 401 with no oracle. Acceptable as documented in carry-forward.
- **`enroll` role/binding coupling.** Because the server signs both role bindings for the assigned `user_id` and `enroll` persists exactly the one matching its atomic first-admin decision, the *logged* KT leaf (`is_admin ? admin_binding : user_binding`) byte-matches the *served/stored* binding — the transparency leaf and the directory can't diverge. (✓)

---

## 4. Accepted residuals (independently re-confirmed acceptable)

Each item below was flagged and accepted in a per-task review; this pass re-checked the code and
confirms each is genuinely acceptable and non-blocking.

- **R1 — `RECOVERY_ID` has no explicit guard in `register`.** User ids are `random_array::<16>()`;
  the all-zero recovery sentinel is reachable only with 2⁻¹²⁸ probability. **Confirmed acceptable** —
  a collision is cryptographically negligible, and even if it occurred the colliding user would only
  gain the recovery principal's *admin-server* capabilities (mint user-role keys), never content
  decryption. (Optional hardening: reject an all-zero assigned id and re-roll.)
- **R2 — Enrollment → KT-log append is best-effort.** A sink-publish failure still returns 201; the
  fail-closed authority is the **client-side** inclusion check (alarm-C). **Confirmed acceptable** —
  a server that never logs a binding is caught at the client open, which blocks. Append failure is
  currently swallowed (`let _ = …`); a `tracing::warn!` for ops observability would be a nice-to-have,
  not a security fix.
- **R3 — alarm-C is active only when the KT log key is pinned.** With no `config/kt_log.der` pin the
  gate is a D5-only no-op (spec §9: witness/gossip is a deferred ops item; the in-repo `sink-server`
  is the witness). **Confirmed acceptable** — the operator must provision the KT log pubkey pin (and
  ideally `maxsecu-setup`/packaging should emit it) for alarm-C teeth; A and B remain fully active
  regardless. Documented posture.
- **R4 — TOFU (alarm-B) fingerprint = `SHA-256(enc‖sig)`, not the ML-KEM half.** A compromised-directory
  ML-KEM-only swap for a *peer* user wouldn't trip alarm-B. **Confirmed acceptable** — X-Wing hybrid
  means an ML-KEM-only swap is not a classical-adversary confidentiality break, whole peer bindings are
  D5-signature-verified before TOFU, and the **recovery** account's ML-KEM half **is** covered (alarm-A's
  full-canonical-pin compare). PQ residual documented.
- **R5 — TOFU wired into the SHARE resolver only.** Browse/feed use the separate D5-verified,
  content-substitution-protected resolver (which now also runs the alarm-C KT gate). **Confirmed
  acceptable** per task scope.
- **R6 — `maxsecu-setup` post-register seal/write failure.** After the once-only register + mint commit
  server-side, a local file-write failure makes a re-run 409. **Confirmed acceptable** — mitigated by
  computing the seal first, writing create-new, and the `emergency_dump` that prints the two
  irreplaceable secrets (sealed blob + first key) for manual recovery; never the passphrase/bare key.
- **R7 — Air-gapped §12.7 recovery-grant code remains in `admin-core`.** Only the Shamir additions were
  removed from `admin-core/recovery.rs`; the pre-existing offline recovery-operator grant issuance
  predates this epic and is out of scope. **Confirmed acceptable** — not security-relevant dangling
  from this change.
- **Deferred ops (unchanged from Phase 7):** real third-party KT witness/gossip + long-lived pinned KT
  key (in-repo sink is the swap-in), client-distribution/code-signing integrity (embedded-pin strength
  = binary integrity, spec §9), Postgres as the durable store for reg-key/recovery/TOFU/log state.

---

## 5. Methodology / gate

The review read the actual code for each invariant against a server-controlling adversary, looking
for: auth bypass / privilege escalation via the recovery principal, embedded-pin bypass (empty/served
"validates"), suite-downgrade of the recovery wrap, key-burning or partial-enrollment windows,
error/existence oracles, attacker-length panics (fail-open), key material crossing the seam or into
logs, KT DoS via forged `tree_size`, and dangling retired surface. The controller confirmed all
workspace suites green (Windows `cargo test --workspace` with `MAXSECU_PG_OPTIONAL=1`, clippy
`-D warnings`, plus the client-e2e crate under `--features unpinned-dev`); this pass did not re-run
the full suite.

**PASS gate = no unaddressed Critical/High/Medium.** Met: the sole non-Info finding is Low (L-1,
inert dead code) and every §0/§9 invariant holds. The accepted residuals are re-confirmed acceptable.

---

## 6. Sign-off

The trusted-server-recovery + registration-key-enrollment redesign meets its spec §0/§9 security
bar: the recovery wrap target is a compile-time pin the server can only be *compared* to (fail-closed
build + fail-closed upload, X25519+ML-KEM covered); the recovery account is once-only and public-only
with the private key cold and Argon2id-sealed; the recovery session is channel-bound, single-use,
admin-server-only (barred from every file endpoint) and yields no key; enrollment is registration-key-only,
single-use, sha256-stored, and atomic with an atomic first-admin claim; TOFU and key-transparency are
sealed, fail-closed, and block on any equivocation; no key material crosses the Tauri seam or reaches
logs; and the retired Shamir/T6/bootstrap/voucher/pending stack is gone while the Phase-7 PQ-hybrid +
transparency guarantees are preserved.

**VERDICT: PASS** — no Critical/High/Medium findings. The one **Low** (L-1, dead retired bootstrap
commands) is a recommended, non-blocking cleanup. **Approved to merge `feat/trusted-server-recovery`.**
