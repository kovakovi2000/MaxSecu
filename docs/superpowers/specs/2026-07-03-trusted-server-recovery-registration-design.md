# Design — Trusted-Server Recovery Account + Registration-Key-Only Enrollment

**Date:** 2026-07-03
**Status:** Approved (brainstormed + locked with the operator). Ready for planning.
**Supersedes / retires:** T6 Shamir recovery-key UI; the per-user "recovery recipient" buddy; the
bootstrap-secret first-run flow; the pending/approval queue; the offline-D5 "ceremony" split and
`tools/demo-seed`.
**Keeps:** T4 file *sharing* (the Share button), the key-transparency machinery, all upload/wrap
crypto, TLS cert pinning, and the channel-bound login mechanism.

---

## §0 Locked decisions (do NOT re-litigate)

These were decided with the operator during brainstorming. Implement them as written.

- **D1 — Identity authority = the server, hardened by A+B+C.** The server signs/serves directory
  bindings and authorizes enrollment. Clients never blindly trust served keys:
  - **A. Embedded recovery pin.** The recovery account's **public** key is a **compile-time constant
    baked into the client binary** (an `include`d/`const` value, NOT a loose file). Uploads wrap to the
    *embedded* pin; any server-served recovery key is only ever **compared** to it.
  - **B. TOFU user keys.** Other users' keys are trust-on-first-use pinned locally; a short fingerprint
    is shown for optional out-of-band comparison.
  - **C. Transparency.** Every binding the server issues is appended to the existing key-transparency
    log (`crypto::merkle` + `client-core::transparency` + `sink-server::dirlog`); clients verify
    inclusion/consistency.
- **D2 — Trust alarm, fail-closed.** Any A/B/C trip (served recovery key ≠ embedded pin; a TOFU'd key
  changed; a transparency inclusion/consistency/split-view failure) raises a prominent modal
  ("this server may be compromised — stop") **and blocks the in-flight action** (no upload, no share,
  no login). Warn *and* block, never warn-and-continue.
- **D3 — One recovery method: the system recovery account.** A single escrow identity. Its keypair is
  generated **once** by a CLI setup tool. Private key → an operator-held cold file. Public key →
  embedded pin + stored server-side + logged. **Every upload auto-wraps to it** (this replaces the old
  per-user buddy). The private key **never leaves the setup machine** except as the one cold file.
- **D4 — Recovery generation lives in a CLI setup tool (`maxsecu-setup`), not the GUI.** The GUI is
  always the pinned "user" build. The CLI does: generate → register recovery pubkey with the server →
  write the private-key file → emit the pubkey for the build to embed → receive + write the first
  registration key.
- **D5 — Registration is registration-key-only.** No pending queue, no approval, no bootstrap secret,
  no offline ceremony. `POST /v1/users` requires a valid **single-use** registration key. On success
  the **server signs the binding**, stores it, appends it to the transparency log, and **deletes the
  key on both sides**. The **first-ever** registrant becomes **admin**; all admin-minted keys are
  **user-role only**.
- **D6 — Recovery login = channel-bound, one-time challenge-response.** The recovery panel's single
  "Request Challenge" button asks the server for a **fresh random, single-use, expiring** challenge
  wrapped to the recovery pin. The client decrypts it with the recovery file and returns a response
  **bound to the live TLS session** (RFC-5705 exporter), reusing the existing login channel-binding.
  A recovery *session* grants admin server actions (mint registration keys) but **not** the private
  key — content decryption still requires the cold key file.

  > **AMENDED 2026-08-01 (operator decision).** The last sentence above is **superseded on its
  > *reach* half**. The operator decided the recovery identity should behave like an ordinary account
  > that happens to be a recipient on everything — *"I want to use the recovery key just like if it
  > were any user, the only difference that it have access to all of the uploaded file by default. So
  > just like if I were to login but everything is shared, so I can look at the feed and everything, I
  > can click share and share it with anyone."*
  >
  > **What changed.** `RECOVERY_ID` is now admitted on an explicit **five-handler allowlist** of file
  > endpoints (`server/http.rs`, extractor `RecoveryOkSession`): `list_files`, `get_file`,
  > `get_chunk`, `chunk_status` and `logout`. It is **always on** — there is no
  > config flag. Everything else still runs on `AuthedSession`, which continues to hard-`403` the
  > recovery principal, so deny-by-default is preserved: a file endpoint added tomorrow is shut to
  > recovery until someone deliberately names the new extractor.
  >
  > So the shipped session **browses** every file, **opens/streams/downloads** every file, **ends
  > itself**, and — as before this amendment — **mints user-role registration keys**.
  >
  > **⚠️ SHARING DID NOT SHIP — the quoted goal is only PARTLY met.** *"I can click share and share it
  > with anyone"* is **not** delivered. `add_wrap` (`POST /v1/files/{id}/wraps`) was admitted in a
  > draft of this amendment and then **reverted** to `AuthedSession`; the client refuses the action
  > with `recovery_share_unsupported` (`client-app/commands/share.rs`) and the share affordance is
  > hidden for a recovery principal. **This is a CLOSED DECISION (owner, 2026-08-02): sharing from a
  > recovery session does not ship, is not pending, and is not scheduled** — see the sub-section
  > below for why it is unsafe, not merely unbuilt. Do not treat the gap as an oversight and do not
  > "fix" it by admitting the extractor.
  >
  > **What did NOT change.** The session is still an opaque, TLS-exporter-bound token and still yields
  > **no private key**; minting one still requires the recovery *private* keys, so every holder of a
  > live recovery session already holds the cold key. Recovery still cannot upload
  > (`create_file`/`stage_version`/`put_chunk`/`finalize_version`), **share** (`add_wrap`), delete or
  > revoke (`discard_file`/`delete_wrap`), mint a bearer cold-tier URL that outlives the session
  > (`direct_link`), enumerate a file's other recipients (`list_recipients`), or mint admins (D5:
  > user-role keys only).
  >
  > **The security cost, stated plainly.** The delta is **reach, not identity**: recovery key +
  > network reach now yields complete, remote plaintext of every file, with **no operator
  > involvement** and no ceremony. Previously the same key-holder had to convene the air-gapped §12.7
  > ceremony to read a single file. Holding sharing back does not reduce that: **reads are neither
  > audited nor rate-limited** — no read path in this server is, for any principal — so a bulk escrow
  > browse of the whole corpus leaves no trace. This is a deliberate, accepted trade, not an
  > oversight. See §5 item 1 and §9.
  >
  > **Why `add_wrap` is shut — CLOSED DECISION, owner, 2026-08-02.** Three reasons, each verified
  > against code. **(a)** A recovery-issued grant is structurally unopenable: `client-core`'s download
  > path rejects any ancestor whose `recipient_type` is not `User`
  > (`crates/client-core/src/download.rs:448-450`), and the server serves exactly the recovery wrap's
  > grant as that ancestor. **(b)** `granted_by = RECOVERY_ID` resolves to **no CLIENT-TRUSTED signing
  > key**, so the walk ends in `GrantChainBroken`. *(Precisely: the recovery account **does** hold an
  > Ed25519 `sig_pub` server-side, `crates/server/src/store.rs:47-51`. What is missing is a trusted
  > path to it — `GET /v1/recovery/pubkey` serves only `enc_pub`/`mlkem_pub`
  > (`crates/server/src/http.rs:667-686`), the recovery pin omits `sig_pub`, and every client open
  > path passes no-op granter/admin resolvers. Earlier revisions of this spec said "no signing key
  > exists"; that wording is **wrong** and invites the wrong fix.)* **(c)** `add_wrap` is idempotent
  > **by REPLACE** in both stores (`crates/server/src/store.rs:1228`; `crates/server/src/pg.rs:1184-1203`),
  > so a recovery "share" to someone who already had access would **destroy that access**, silently and
  > irreversibly — the one thing `CLAUDE.md` forbids outright. **(c) is what makes this permanent
  > rather than a missing feature.** Admitting the route would also make recovery a **universal grant
  > issuer by construction** (its only authorization is "the caller already holds a wrap for this
  > version", and recovery holds one on every finalized version). Two candidate designs would be
  > needed to lift (a)/(b) — a published directory binding for `RECOVERY_ID` carrying a real Ed25519
  > signing key, or `sig_pub` added to the recovery pin (a frozen surface, so itself a format change)
  > with the chain terminating at the `DESIGN.md` §12.7 admin key — plus a server-side REPLACE refusal
  > for (c). **The operator declined to take either on**, so none of it is scheduled. Pinned by
  > `crates/server/tests/recovery_login_e2e.rs`, which asserts the `403` with a well-formed body.
- **D7 — Startup precedence.** If more than one is present beside the exe: **recovery-key file →
  registration-key file → normal keystore login**.
- **D8 — `recovery_seal` is removed** (it existed only for the retired T6).

---

## §1 Overview & trust model

The product is a single-operator "everyone trusts this server" media app. The server is trusted for
**availability and authorization** (who may enroll, who is admin) — but **never** for the *keys* that
decide who can read data. Three layers enforce that:

| Layer | Protects | Mechanism | Failure handling |
|-------|----------|-----------|------------------|
| **A** | The crown-jewel recovery wrap | Recovery pubkey **compiled into the client** | Served ≠ embedded → block + alarm |
| **B** | User↔user keys (sharing, authorship) | TOFU pin + fingerprint | Changed key → block + alarm |
| **C** | Detecting any server equivocation | Transparency log inclusion/consistency | Proof failure/split-view → block + alarm |

The residual power the server keeps — admitting accounts and conferring admin — is benign: a
server-minted account is not a wrap target (so it can read nothing) and cannot impersonate a
pinned/TOFU'd key. The one truly load-bearing secret is the **recovery private key file**, kept cold
by the operator; a stolen recovery *session* cannot decrypt anything.

**Scope guard:** this change is confined to the identity / enrollment / recovery / trust-alarm layers.
It does **not** touch the file-encryption, chunking, upload-pipeline, wrap, or TLS-transport crypto,
except to (a) retarget the upload auto-wrap to the recovery pin and (b) enforce the trust alarm at the
upload/share/login boundaries.

---

## §2 Grounding in the current code

What exists today (files the implementation will change or remove):

- **Server enrollment/authority** — `crates/server/src/http.rs`:
  - `POST /v1/bootstrap` (line ~245): bootstrap-secret first-admin. **Remove.**
  - `POST /v1/users` (line ~199): voucher-gated enrollment, leaves user *pending*. **Replace** with
    registration-key-only enrollment that also signs+serves+logs the binding and admits the first
    registrant as admin.
  - `POST /v1/vouchers`, `GET /v1/pending`, `list_pending` (~589+): voucher issuance + approval queue.
    **Replace/remove** (vouchers → registration-keys; pending queue deleted).
  - `POST /v1/directory` (verify at ~463, authority note at ~1615): binding published only if signed by
    the offline D5 key. **Change** so the server holds the signing key and signs at enrollment; keep the
    client-side "verify served binding against the pinned key" path unchanged.
  - `DirectorySigner` / `sign_binding` (`admin-core`) already exists and is used in tests (~1881+);
    the portable server already persists a dev signing seed (`config/d5_secret.bin`).
- **Transparency (C)** — `crypto::merkle`, `client-core::transparency`, `sink-server::dirlog` already
  exist (Phase-7). **Wire** binding issuance into the log; **wire** client verification into the
  browse/share/upload paths with the trust alarm.
- **Channel-bound login (reuse for D6)** — `crates/client-app/src/session.rs`
  (`build_login_proof`/`make_proof`, RFC-5705 `exporter`, per-connection binding). The recovery
  challenge-response reuses this exporter binding.
- **Old recovery to retire** —
  - `crates/crypto/src/shamir.rs`, `crates/admin-core/src/recovery.rs`,
    `crates/admin-core/src/recovery_seal.rs`.
  - `crates/client-app/src/{ceremony.rs, recovery_share.rs}`,
    `crates/client-app/src/commands/recovery_custody.rs`.
  - UI `recovery-split-screen.ts`, `recovery-reconstruct-screen.ts`,
    `core/recovery-reconstruct-store.ts` (+ tests); their app-shell routes/nav entries; their DTOs.
  - `crates/client-app/tests/recovery_custody_e2e.rs`.
- **Old buddy recovery to retarget** — `crates/client-app/src/config.rs::recovery_recipient_username`,
  `directory.rs::resolve_recovery_recipient`, and `commands/upload.rs`'s use of them → replace the
  per-user buddy with the embedded recovery pin.
- **Portable server** — `crates/portable-server/src/bootstrap.rs` (bootstrap secret). **Remove** the
  secret; add recovery-account state (persisted pubkey, once-only registration) + registration-key
  store. `tools/demo-seed` → **superseded** by `tools/maxsecu-setup`.
- **Keep intact** — `crates/client-app/src/commands/share.rs` + `ui .../share-dialog.ts`,
  `share-tray.ts` (T4 sharing), all upload/wrap/transport crypto, TLS pinning.

---

## §3 The recovery account, keys, and the embedded pin

- **Keypair:** the recovery identity uses the same key types as a normal `Identity` (encryption keypair
  for wrap/unwrap + signing keypair), generated by `maxsecu-setup` (§4).
- **Private key** → written **once** to an operator-chosen path as a sealed file (passphrase-protected,
  reuse the existing keyblob sealing so the cold file is not bare key bytes). This is the operator's
  "recover everything" file. It never leaves the setup machine otherwise.
- **Public (encryption) key** → the **embedded pin**. The build embeds it as a compile-time constant in
  `client-app` (mirror the `include_bytes!` pattern used for the embedded ffmpeg): a generated
  `recovery_pin` module or a `build.rs` reading a gitignored `recovery_pin.bin` that `maxsecu-setup`
  writes. If the pin is absent at build time, the client build must **fail closed** (no "empty pin"
  default that would silently disable protection) — except an explicit `--features unpinned-dev` escape
  hatch used only by tests/CI, which must be clearly labelled and never shipped.
- **Upload wrap:** `commands/upload.rs` wraps every upload to `self` **and** the embedded recovery pin
  (replacing `resolve_recovery_recipient`). Before wrapping, if the server serves a recovery pubkey that
  disagrees with the embedded pin → **trust alarm + block** (D2/A).
- **Server-side:** stores the recovery public key once; a `GET` endpoint serves it (for the
  compare-to-pin check and for the challenge wrap); a persisted flag makes recovery registration
  **once-only**.

---

## §4 `maxsecu-setup` CLI (new crate `tools/maxsecu-setup`)

One-shot, operator-run, against a freshly-started server. Configuration via flags/env (mirror
`demo-seed`'s env style). Steps:

1. Connect over pinned TLS (the server's cert pin is provided the same way `demo-seed` reads it).
2. Generate the recovery `Identity`.
3. `POST /v1/recovery/register` with the recovery public keys. Server accepts **iff** no recovery
   account exists yet; otherwise `409` and the tool aborts without writing anything.
4. On `201`: write the **sealed** recovery private-key file to `--out` (prompt/flag for the sealing
   passphrase); write the **recovery pubkey** to the build-embed path (`recovery_pin.bin`); receive and
   write the **first registration key** file to `--first-key-out`.
5. Print a clear summary: where each artifact landed, that the operator must (a) move the private-key
   file to cold storage, (b) rebuild/repackage the client so the pin is embedded, (c) hand the first
   registration-key file to the first admin.

The tool never uploads, never logs the private key, and zeroizes transient key material.

---

## §5 Client startup modes & UX

On launch, `client-app` checks, in **precedence order (D7)**, for files beside the exe:

1. **Recovery-key file** (e.g. `recovery.key`) → **recovery panel**: a single **"Request Challenge"**
   button and status text. On click → §6. On success → a recovery **admin** session (nav exposes admin
   actions incl. minting registration keys). **AMENDED 2026-08-01 (§0 D6):** the session also **browses
   every file, opens/streams/downloads any of them, and can end itself** — it is a
   standing recipient on every upload, so every wrap it fetches opens with the loaded key. It **cannot
   upload, cannot delete, cannot revoke, and CANNOT SHARE**; those endpoints still `403` the recovery
   principal. **Corrected 2026-08-01 — an earlier draft of this item said the session "shares any of
   them to any account". It does not:** `add_wrap` was reverted to `AuthedSession` because a
   recovery-issued grant is unopenable by the recipient *and* `add_wrap` replaces destructively, so
   sharing would cost an existing user their access (§0 D6, §9). The UI reflects the truth — the share
   affordance is hidden for a recovery principal and the command refuses with
   `recovery_share_unsupported` (`client-app/commands/share.rs`).
2. **Registration-key file** (e.g. `register.key`) → **registration panel**: choose username +
   passphrase → generate a local `Identity` → `POST /v1/users` with the key → on success seal the new
   identity into the local keystore, and the panel deletes the local key file (server deletes its copy).
   First-ever registrant is admin.
3. **Neither** → the existing **unlock + connect** login (keystore-based).

Only DTOs cross the Tauri seam (no key material / `Identity` / wrapped keys in any command signature).
The trust alarm (§7) is a shared modal component reused by all three paths.

---

## §6 Recovery challenge-response protocol (channel-bound, one-time)

Reuses the RFC-5705 per-connection exporter already used by normal login (`session.rs`).

1. Client opens a pinned-TLS connection; presses "Request Challenge".
2. `POST /v1/recovery/challenge` → server generates a **fresh random** challenge nonce, marks it
   **single-use** with a short TTL, **wraps it to the stored recovery encryption pubkey**, returns the
   wrapped blob + an opaque challenge id.
3. Client **unwraps** the challenge with the loaded recovery private key. If unwrap fails → fail closed
   ("wrong/corrupt recovery key"), no oracle detail.
4. Client builds a **channel-bound response** = a proof over `(challenge, server_id, this-connection
   exporter)`, mirroring `make_proof`. `POST /v1/recovery/verify` with the response.
5. Server verifies the response is bound to **this** connection's exporter and consumes the challenge
   (one-time). On success → issues a recovery **admin** session token. Any mismatch/expiry/replay →
   fail closed.

Properties: replay-proof (single-use random challenge), relay-hardened (channel-bound), and a stolen
session cannot decrypt content (no private key in the session).

---

## §7 Trust alarm (D2) — unified, fail-closed

A single shared UI modal + a backend result surface. It is raised — and the triggering action blocked —
on any of:

- **A:** an upload/share is about to use a server-served recovery key that ≠ the embedded pin.
- **B:** a served user key differs from the locally TOFU-pinned value for that username.
- **C:** a transparency inclusion/consistency check fails, or a split-view is detected.

Behaviour: the in-flight action (upload / share / login / browse-open) returns a distinct
`server_untrusted`-class error; the UI shows the modal with plain-language guidance and does **not**
proceed. No partial upload, no partial wrap, no fallback to the served key.

---

## §8 What is removed (explicit retirement list)

- **Crypto/admin:** `crates/crypto/src/shamir.rs`; `crates/admin-core/src/recovery.rs`;
  `crates/admin-core/src/recovery_seal.rs` (D8). Prune their re-exports/tests.
- **Client-app:** `src/ceremony.rs`, `src/recovery_share.rs`, `src/commands/recovery_custody.rs`; the
  T6 DTOs; the split/reconstruct routes + nav entries.
- **UI:** `recovery-split-screen.ts`, `recovery-reconstruct-screen.ts`,
  `core/recovery-reconstruct-store.ts` (+ their tests); a11y checks referencing them.
- **Server:** `POST /v1/bootstrap`, `POST /v1/vouchers`, `GET /v1/pending` + `list_pending` + pending
  store methods; the voucher store surface (replaced by registration-keys).
- **Portable server:** the bootstrap-secret generation/marker in `bootstrap.rs`.
- **Tools:** `tools/demo-seed` (superseded by `tools/maxsecu-setup`); update the demo runbook/scripts
  that referenced it.
- **Client config:** the per-user `recovery_recipient.txt` reader and `resolve_recovery_recipient`.

Retiring must keep the workspace compiling at each step (feature-flag or delete-with-callers-updated,
not leave dangling references).

---

## §9 Security considerations & non-goals

- **Non-goal:** preventing a malicious operator from reading data. The operator holds the recovery key
  by design and can decrypt everything. A/B/C protect *users* from a server that lies about *keys*, and
  make operator equivocation detectable — they do not hide data from the operator.
- **Embedded-pin integrity** is only as strong as binary integrity; document that shipped clients should
  be distributed over a trusted channel (out of scope to enforce here).
- **Transparency teeth (C)** require a witness/gossip to be fully meaningful; the in-repo `sink-server`
  is the witness. Full third-party witness/gossip remains a deferred ops item; the log + inclusion
  proofs + TOFU still provide strong detection meanwhile.
- **Recovery session blast radius** (**AMENDED 2026-08-01** — see §0 D6 for the operator decision and
  the security cost) covers admin server actions (mint user-role keys) **plus an explicit five-handler
  allowlist on the file surface**: `list_files` (`GET /v1/files`), `get_file` (`GET /v1/files/{id}`),
  `get_chunk` and `chunk_status` (`GET …/chunks/{i}` and `…/status`), and `logout`
  (`POST /v1/session/logout`). A recovery session therefore **browses every file, fetches and decrypts
  its ciphertext, and can end itself** — the ciphertext opens because the recovery wrap is on every
  upload (§3). It **cannot** upload
  (`create_file`/`stage_version`/`put_chunk`/`finalize_version`), **share** (`add_wrap` — see below),
  delete or revoke
  (`discard_file`/`delete_wrap`), mint a bearer cold-tier URL that outlives the session
  (`direct_link`), enumerate a file's other recipients (`list_recipients` — owner-only in the store),
  or mint admins (D5: user-role keys only). It still yields **no private key**: the token is opaque,
  and the cold key stays in the operator's sealed keyblob. Every other file endpoint — including any
  added later — stays barred by `AuthedSession` unless it deliberately opts out.
  - **Corrected 2026-08-01 — an earlier draft of this bullet listed `add_wrap` in the allowlist and
    claimed a recovery session "grants any file to any account". It does not, and the route is
    `403`.** *(Retired claim, kept for provenance — do not act on it.)* ~~`add_wrap`
    (`POST /v1/files/{id}/wraps` — **sharing**) … and grants any file to any account.~~ **Sharing from
    the recovery identity is a CLOSED DECISION (owner, 2026-08-02): it does not ship and is not
    pending.** Admitting `add_wrap` would make recovery a **universal grant issuer by construction**
    (its only authorization is "the caller already holds a wrap for this version", and recovery holds
    one on every finalized version) — and worse, it would do so *destructively*: `add_wrap` is
    idempotent **by REPLACE** in both stores (`crates/server/src/store.rs:1228`;
    `crates/server/src/pg.rs:1184-1203`), while a recovery-issued grant is **unopenable** by the
    recipient (`client-core`'s download path rejects a non-`User` ancestor `recipient_type`,
    `crates/client-core/src/download.rs:448-450`, and `granted_by = RECOVERY_ID` resolves to **no
    client-trusted signing key** — the recovery account does hold an Ed25519 `sig_pub` server-side,
    `crates/server/src/store.rs:47-51`, but no client has a trusted path to it: `GET
    /v1/recovery/pubkey` serves only `enc_pub`/`mlkem_pub`, `crates/server/src/http.rs:667-686` — so
    the walk ends in `GrantChainBroken`). Re-sharing to someone who already had access would replace
    their working grant with a dead one and **destroy data access that already worked**; that is the
    reason the decision is permanent rather than a feature awaiting a protocol. Two candidate designs
    would have been needed — (1) a trust anchor (publish a directory binding for `RECOVERY_ID` carrying
    a real Ed25519 signing key, **or** add `sig_pub` to the recovery pin and terminate the chain at the
    `DESIGN.md` §12.7 admin key) **and** (2) a server-side refusal of a REPLACE when
    `granted_by == RECOVERY_ID` — and **the operator declined to take either on**. The bar stays on the
    extractor (a client-side refusal is not a security boundary), and
    `crates/server/tests/recovery_login_e2e.rs` asserts the `403` with a well-formed body so that
    admitting the route breaks the build.
- Preserve existing crypto discipline: zeroize transient key material; only DTOs cross the Tauri seam;
  no key material in logs/Debug; e2e over real TLS with real crypto.

---

## §10 Testing (all e2e over real TLS, no mocked crypto)

- **Setup:** `maxsecu-setup` against a fresh server writes all three artifacts; a **second** recovery
  registration is rejected (`409`) and writes nothing.
- **Embedded pin:** a build with the pin embedded wraps uploads to it; a served recovery key that
  matches → proceeds; a served key that differs → trust alarm + blocked (no wrap).
- **Registration:** first key → admin; second key → user; a used/invalid key → rejected; a consumed key
  is deleted server-side (reuse fails) and the client deletes its local file.
- **Recovery login (D6):** correct recovery file → admin session; wrong/corrupt file → fail closed;
  a replayed challenge → rejected; a response bound to a different connection → rejected.
- **Recovery decrypts everything:** an upload made by a normal user is decryptable by the recovery
  identity (via the wrap to the pin).
- **Trust alarm (D2):** served recovery ≠ pin → upload blocked; a changed TOFU user key → share blocked;
  a transparency inconsistency → browse-open blocked; each raises the modal.
- **Removal safety:** the workspace builds and all suites pass with T6 / bootstrap / vouchers / pending
  gone; no dangling references.
- Unit tests per new piece (challenge issue/verify, once-only recovery registration, registration-key
  store single-use, pin-compare, TOFU compare).

---

## §11 Open items / deferrals (not blocking)

- Persistence: dev uses `MemoryStore` (state lost on restart, acceptable for dev); Postgres profile is
  the durable path. Registration-key + recovery-account + TOFU + log state must be store-agnostic.
- Full third-party transparency witness/gossip (ops).
- Client distribution integrity / code-signing (ops).
- Fingerprint out-of-band comparison UX polish (B) can start minimal (show the fingerprint) and grow.
