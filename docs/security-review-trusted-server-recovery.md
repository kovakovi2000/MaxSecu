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

**Verdict:** **PASS** — **no Critical, High, or Medium findings**. The one **Low** originally
raised (L-1 — dead retired client surface: the pre-existing bootstrap/glass-break Tauri commands
were not deleted; inert, 404/422 fail-closed, no auth bypass) has since been **REMEDIATED** (the
module, DTOs, command registrations, and orphaned UI are deleted — see the L-1 row below). What
remains are Info-level observations and the documented, independently-confirmed accepted residuals
below. No fix commit was required to pass the gate; the Low cleanup was applied on top.

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
| 7 | **Retirement safety** | **Mostly sound.** `crypto/shamir.rs` (−382) and `admin-core/recovery_seal.rs` (−271) deleted; the Shamir K-of-N portion of `admin-core/recovery.rs` removed (−148, leaving only the pre-existing §12.7 offline recovery-grant issuance); `client-app/recovery_share.rs`, the T6 split/reconstruct UI + stores, `tools/demo-seed`, the per-user `recovery_recipient.txt` reader, the server `/v1/bootstrap`+`/v1/vouchers`+`/v1/pending` routes, and the portable-server bootstrap-secret are all gone. **Phase-7 PQ-hybrid wrap + KT transparency are KEPT** (`crypto::hybrid` exports intact, `phase7_hardening_e2e.rs` present). **Finding L-1 (Low), now REMEDIATED:** the client-app's pre-existing bootstrap/glass-break Tauri commands were left registered; they have since been deleted (see below). | Low (L-1) — **remediated** | Cleanup applied; was **not a PASS-blocker** (inert). |
| 8 | **Test-only surface excluded from production** | **Sound (✓).** `maxsecu-client-app/unpinned-dev` and `maxsecu-client-core/test-support` are both **non-default** (`= []`) features, enabled **only** by `crates/client-e2e`. `Identity::from_test_seeds` is behind `test-support`; the fixed-seed test pin is behind `unpinned-dev` (build emits a `cargo:warning`). Neither the test seed path nor the test pin is reachable in a shipped build (a real build embeds the operator pin or fails closed). | — | Accepted (correct). |
| 9 | **Crypto discipline** | **Sound (✓).** New flows are exercised e2e over real TLS with real crypto (`register_e2e`, `recovery_login_e2e`, `upload_recovery_wrap_e2e`, `transparency_alarm_e2e`, `enrollment_e2e`, `enrollment_transparency_e2e`, `full_flow_e2e` capstone setup→enroll→upload→recovery-decrypt). Transient key material is `Zeroizing`. PQ `Suite::V2` is preserved for recovery-wrapped uploads: `maxsecu-setup` always registers a hybrid recovery account, the challenge wraps V2 (`wrap_dek_hybrid`), and uploads emit V2 when self+recovery are PQ. | — | Accepted (correct). |

---

## 3. Findings by severity

| ID | Severity | Finding | Location | Disposition |
|----|----------|---------|----------|-------------|
| **L-1** | **Low** — **REMEDIATED** | The retirement did not delete the client-app's **legacy bootstrap/glass-break commands**: `commands::bootstrap::{register_glassbreak, create_first_admin, register_user, account_status}` were still registered in `main.rs`, and `register_glassbreak`/`create_first_admin` still `POST /v1/bootstrap` (route removed) while `register_user` posted an `enrollment_voucher` to `/v1/users` (which now **requires** `registration_key`). The `bootstrap.rs` module (`generate_glassbreak`) and the `BootstrapRequest`/`GlassbreakResponse`/`FirstAdminRequest` DTOs (with `bootstrap_secret`) also remained. **Verified inert:** `/v1/bootstrap` returned 404 and the local keystore was sealed **only after** a 201, so nothing was created or written on the dead path; `register_user`'s body omitted the now-mandatory `registration_key`, so serde rejected it (422) — **no account creation, no privilege, no auth bypass, no key leak.** It was dead attack surface that contradicted the §8 "no dangling references" retirement mandate. **Remediation (this change set):** deleted `src/commands/bootstrap.rs` and the now-orphaned `src/bootstrap.rs` (glass-break generator); dropped the `pub mod bootstrap` declarations (`commands/mod.rs`, `lib.rs`); removed the four `invoke_handler` registrations; deleted the `BootstrapRequest`/`GlassbreakResponse`/`FirstAdminRequest`/`RegisterUserRequest`/`AccountStatusRequest` DTOs and the now-dead `AccountState` enum + `EVT_ACCOUNT` channel; and removed the orphaned legacy UI — `bootstrap-screen.ts`, the approval-flow `pending-screen.ts`, their `bootstrap`/`pending` routes + shell branches, the `account_status` poll in `connect-screen.ts` (which now routes straight to the feed, since registration-key enrollment grants a signed binding immediately), the `GlassbreakResponse`/`AccountStateMsg` `types.ts` mirrors, the dead CSS selector, and the a11y-check entries. Verified: `cargo build`/`test`/`clippy` (no new warnings), UI `npm test`/`typecheck`/`test:a11y`, and `cargo check --bins` all green; a repo-wide grep confirms **zero remaining references**. | `crates/client-app/src/commands/bootstrap.rs`; `src/main.rs:55-58`; `src/bootstrap.rs`; `src/dto.rs:32-51`; `ui/src/components/{bootstrap-screen,pending-screen}.ts` | **REMEDIATED** — legacy module + DTOs + `invoke_handler` entries + `pub mod bootstrap` + orphaned UI deleted; no dangling references remain. Was non-blocking. |

**No Critical, High, or Medium findings.**

### ADDENDUM 2026-08-01 — invariant #3 is **SUPERSEDED** by an operator decision

The row above is left exactly as it was ratified: it was true of the code it reviewed. It is **no
longer a description of the shipped system**, and this addendum supersedes it.

> **Corrected 2026-08-01 — an earlier revision of this addendum said recovery is "a universal grant
> issuer BY CONSTRUCTION" and listed `add_wrap` among the admitted handlers. That was written against
> a design that was REVERTED before it landed, and it is FALSE of the shipped system: `add_wrap` runs
> on `AuthedSession` and still `403`s the recovery principal.** The grant-issuer analysis itself is
> **correct and is kept below**, moved out of "what shipped" and into *"why the route is shut"* —
> it is precisely the reason nobody may quietly admit `add_wrap` later. The read half of the finding
> is unchanged and is not softened by the correction.

**What changed.** The operator decided the recovery identity should behave like an ordinary account
that happens to be a recipient on everything (spec §0 D6, *AMENDED 2026-08-01*). `AuthedSession` still
hard-`403`s `RECOVERY_ID` and is still the deny-by-default rule — but **five** handlers now
deliberately opt out of it via a second extractor, `RecoveryOkSession` (`server/http.rs`):
`list_files`, `get_file`, `get_chunk`, `chunk_status` and `logout`. It is **always on**; there is no
config flag. `crates/server/tests/recovery_login_e2e.rs` asserts both halves — the admitted routes
answer `200`/`404` rather than `403`, and `create_file`, `stage_version`, `finalize_version`,
`add_wrap`, `delete_wrap`, `discard_file`, `list_recipients` and `direct_link` still answer `403`.

So the shipped recovery session **browses** every file, **opens/streams/downloads** every file, **ends
itself**, and — as before today, unchanged since T5 — **mints user-role registration keys**. It cannot
upload, cannot delete, cannot revoke, cannot mint a session-outliving direct link, cannot enumerate a
file's other recipients, and **cannot share**.

**Residual risk, restated honestly.** "A stolen recovery *session* decrypts nothing" (§1, §6) is no
longer the operative bound. The delta is **reach, not identity**: a session token is TLS-exporter-bound
and can only be minted by a holder of the recovery *private* keys, so every holder of a live recovery
session already held the cold key — but that key-holder previously had to convene the air-gapped
§12.7 ceremony to read a single file. **Now: recovery key + network reach yields complete, remote
plaintext of every file, with no operator involvement and no ceremony.** That is the full cost and it
is not reduced by the sharing revert. Two consequences that are easy to miss:

- **Reads are neither audited nor rate-limited** — no read path in this server is, for any principal —
  so a bulk escrow browse leaves no trace. Sessions are also not behind the anti-automation limiter
  (see the Info observation above), so the only real bound on volume is the operator's own restraint.
- **`get_chunk` is not side-effect-free** when a cold tier is configured: it rehydrates and may offload
  capacity victims, exactly as for an ordinary caller. A bulk escrow browse therefore *moves the
  operator's cold-tier working set*, which is the one externally visible trace it does leave.

**Why `add_wrap` is shut — a CLOSED DECISION (owner, 2026-08-02), and the grant-issuer analysis that
is exactly why it stays shut.** Sharing from a recovery session **does not ship and is not pending**.
The analysis below is the reason the decision is final; it is not a list of prerequisites anyone is
working through. *(Earlier revisions of this section framed it as "blocked on a protocol decision,
not on willingness". That framing is retired — the operator declined to take on either of the two
candidate designs, and reason 3 below makes the route unsafe even with both.)*

- **Admitting `add_wrap` would make recovery a universal grant issuer BY CONSTRUCTION.** `add_wrap`'s
  only authorization is "the caller already holds a wrap for this version" (`store.rs::add_wrap`), and
  the recovery principal holds one on **every** finalized version. So admitting the extractor is not a
  narrow widening — it hands the escrow the power to make any account a permanent reader of any file,
  with a single unprivileged-looking `POST`. (The grant edge *would* be audited — `GrantEdge` — which
  is the one mitigating property, and the only one.)
- **And today it would do that *destructively*, costing an existing user their data.** `add_wrap` is
  idempotent **by REPLACE**: the store drops any existing row for that `recipient_id` before inserting.
  The replacement grant is **unopenable** — `client-core`'s download path field-binds the ancestor
  before the chain walk and rejects any ancestor whose `recipient_type` is not `User`
  (`crates/client-core/src/download.rs:448-450`), and `granted_by = RECOVERY_ID` resolves to **no
  CLIENT-TRUSTED signing key**, so the walk ends in `GrantChainBroken`. A recovery "share" to somebody
  who **already had working access** would therefore swap their good grant for a dead one, silently
  and irreversibly. That is a backward-compatibility break of the worst kind (`CLAUDE.md`;
  `docs/compat/LEDGER.md` 2026-08-01) — worse than `2a626d6`, because no re-enroll repairs it. **This
  is the reason the decision is permanent** rather than a feature awaiting a protocol: the failure
  mode is not "sharing is unbuilt", it is "sharing on this route strands an existing user".
- **CORRECTION (2026-08-02) — "no signing key exists" is WRONG; "no client-trusted path to it" is
  right.** The recovery account **does** hold an Ed25519 `sig_pub` server-side
  (`crates/server/src/store.rs:47-51`, `RecoveryAccount { enc_pub, sig_pub, mlkem_pub }`). What is
  missing is any way for a client to *trust* it: `GET /v1/recovery/pubkey` serves only `enc_pub_b64`
  and `mlkem_pub_b64` (`crates/server/src/http.rs:667-686`), the embedded recovery pin omits
  `sig_pub`, and every client open path passes no-op granter/admin resolvers. Wherever this document
  or its siblings previously said the key does not exist, read it as **no trusted path to the key**.
  The conclusion is unchanged; the reason is more precise, and the imprecise version invites the wrong
  fix (minting a key server-side would change nothing).
- **The two candidate designs, and why they are not a plan.** Lifting the trust-anchor half would take
  either a published directory binding for `RECOVERY_ID` carrying a real Ed25519 signing key, or
  `sig_pub` added to the recovery pin (frozen surface #7 — itself a format change) with the chain
  terminating at the `DESIGN.md` §12.7 admin key; the REPLACE half would take a server-side refusal
  when `granted_by == RECOVERY_ID`. **The operator declined to take either on**, so neither is
  scheduled and this document does not track them. The client refuses too
  (`recovery_share_unsupported`, `client-app/commands/share.rs`), but a client-side refusal is not a
  security boundary and must not be mistaken for one — the bar is the extractor, and
  `crates/server/tests/recovery_login_e2e.rs` posts a well-formed body so that admitting it breaks the
  build.

**What still holds.** Invariants #1, #2 and #4–#9 are untouched, and invariant #3 is **narrowed, not
deleted** — recovery is still not a *file-writing* or *grant-issuing* principal; what it lost is the
"decrypts nothing online" read bound. Specifically: (a) **deny-by-default
survives** — the bar stays on `AuthedSession`, so a file endpoint added tomorrow is closed to recovery
until someone deliberately names `RecoveryOkSession`; deleting the check instead would have opened
every present *and future* handler silently; (b) the session still yields **no private key** — it is
an opaque token and the cold key stays in the operator's Argon2id-sealed keyblob; (c) uploading,
deleting, revoking, **sharing**, minting a session-outliving bearer cold-tier URL, enumerating a file's
other recipients, and minting admins are all still refused; (d) the challenge is still single-use and
channel-bound, and every failure is still a uniform `401`. **Non-goal (spec §9) is unchanged and now
simply more visible:** this system never claimed to hide data from the operator — the operator holds
the recovery key by design.

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
commands) has been **REMEDIATED** in this change set (legacy module, DTOs, command registrations, and
orphaned UI deleted; no dangling references remain; all builds/tests/clippy/UI checks green).
**Approved to merge `feat/trusted-server-recovery`.**
