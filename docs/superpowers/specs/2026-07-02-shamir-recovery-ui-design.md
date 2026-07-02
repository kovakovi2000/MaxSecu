# Shamir K-of-N Recovery-Key UI — Design

**Status:** APPROVED — brainstormed and all open questions resolved (2026-07-02), ready for implementation.

## 0. Locked decisions (2026-07-02) — these OVERRIDE any hedging in later sections

- **D-A — Ceremony UI = Tauri GUI screens** inside `client-app` (§3's choice), offline-only:
  the split/reconstruct commands perform ZERO network I/O (grep-checkable: no
  `hyper`/`http_client` import in the new module). CLI alternative rejected for a11y/DTO
  consistency. The larger-TCB trade-off on the air-gapped device is accepted and documented.
- **D-B — Pre-split secret load = NEW SEALED-FILE FORMAT.** The existing recovery private
  key is loaded from a new **Argon2id + AEAD sealed file** (a small companion mirroring
  `keyblob::seal`), NOT a bare 32-byte scalar on disk. This is a companion piece to build
  as part of this feature: a `seal_recovery_secret`/`open_recovery_secret` pair (passphrase
  → Argon2id KDF → AEAD over the `EncSecretKey` bytes). `SplitRecoveryKeyRequest` therefore
  carries `recovery_secret_path` + a passphrase (Zeroizing, loaded/zeroized inside the
  command). The bytes-on-disk are never a plaintext scalar.
- **D-C — Scope = CLASSICAL X25519 ONLY for v1.** Split/reconstruct only the 32-byte
  X25519 scalar that `admin-core::recovery::{split,reconstruct}_recovery_key` already
  supports. The ML-KEM (PQ) half is explicitly DEFERRED (flagged follow-up). Zero new
  cryptography beyond the sealed-file companion (D-B).
- **D-D — Share transport = TEXT + SAVE-TO-FILE, NO QR.** The `MSHARE1` string is shown
  copyable and can be written to a file. No QR code (avoids a new webview JS dependency on
  the air-gapped device). QR is a possible later addition.
- **D-E — `k`/`n` guidance:** advisory floor `n ≥ 3` (warn, do not hard-block) + a hard
  `k ≤ n` / `k ≥ 1` / `n ≥ 1` validation (client-side AND command-side, since
  `split_recovery_key` fails closed on `BadThreshold` anyway). Suggest (not force) `k` = a
  strict majority of `n`.
- **D-F — Same-key re-split:** DISCOURAGE as a distinct flow. Re-splitting invalidates all
  prior shares and must be paired with a full D6 key rotation (§9); the UI states this and
  does not present "re-split, same key" as a lightweight custodian-swap option.
- **D-G — Ceremony logging:** include a MINIMAL non-secret local ceremony log (who/when,
  `k`/`n`, which custodian indices were issued, the label — NEVER share bytes), written
  only on explicit completion, mirroring the non-secret summary in §4 step 5.

**Relationship to Phase 7:** the cryptographic core this UI sits on top of **already shipped** in Phase 7
(P7.6 `crypto::shamir`, P7.7 `admin-core::recovery::{split_recovery_key, reconstruct_recovery_key}` —
see `docs/security-review-phase7.md`, PASS, no Critical/High/Medium). This spec adds **zero new
cryptography**. It is a UX + Tauri command/DTO layer, in the same spirit as the Phase-5 settings UI
(`keystore::change_password`/`export_keystore` wired to `settings-screen.ts`) and the Phase-2 admin screen
(`admin::generate_voucher`/`request_approval` wired to `admin-screen.ts`).

## 1. Goal & scope

**Goal.** Give the recovery-key custodian (an admin operating the **air-gapped recovery device**, DESIGN.md
§16.3) a UI to:

- **(a) Split** — turn the recovery keypair's private half into `n` Shamir shares, any `k` of which
  reconstruct it, and walk the operator through safely distributing each share to a distinct custodian.
- **(b) Reconstruct** — later, at a recovery ceremony, collect `≥k` custodian shares back, validate them, and
  reconstruct the recovery private key in memory — then hand it to the **already-built** recovery-grant /
  wrap-validation code, unchanged.

**In scope:** the split/reconstruct screens, the Tauri command/DTO seam beneath them, share encoding +
integrity-checksum format, custody guidance copy, accessibility, and a test plan.

**Out of scope (explicitly not touched by this spec):**
- The Shamir math itself — `crypto::shamir::{split, combine}` (crates/crypto/src/shamir.rs) is DONE, tested,
  and not modified here.
- The recovery-grant / offline-sweep logic — `admin_core::recovery::{build_recovery_grant,
  validate_recovery_wrap}` (crates/admin-core/src/recovery.rs) is DONE; this UI only produces the
  `EncSecretKey` those functions already consume as an argument.
- **Generating** the recovery keypair itself. This spec assumes a recovery keypair already exists (it is
  produced once, offline, as part of the D6 key-generation ceremony, DESIGN.md §12.1/§16.3) — this is a
  *custody* operation over an existing key, not identity/key generation.
- Splitting/reconstructing the **ML-KEM half** of a hybrid (PQ) recovery key. Today `split_recovery_key`
  only takes the classical 32-byte X25519 scalar (`recovery_secret.expose_bytes()`,
  `admin-core/src/recovery.rs:210`); the recovery keypair's PQ half (a 64-byte ML-KEM seed,
  `MLKEM_SEED_LEN` in `crypto/src/hybrid.rs:51`) is a separate secret not covered by this ceremony. Flagged
  as an open question (§13) — the primitive is generic enough to extend, but that is new scope, not this one.
- Physical transport/custody of the printed/exported shares to the humans holding them — procedural, not
  code (§9 gives the guidance the UI *displays*, not a delivery mechanism).
- Any server-side or networked storage of shares. Shares never touch the server, ever — see §4/§6.

## 2. The existing crypto this builds on (grounding)

### 2.1 `crypto::shamir` — the bare GF(256) primitive (`crates/crypto/src/shamir.rs`)

```rust
pub struct Share { pub index: u8, pub body: Vec<u8> }  // Debug elides `body`
pub enum ShamirError { InsufficientShares, DuplicateIndex, BadThreshold, LengthMismatch }

pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, ShamirError>;
pub fn combine(k: u8, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, ShamirError>;
```

Key properties, quoted from the module doc (shamir.rs:1-20) and tests, that this spec's UX must respect:

- Each byte of the secret is the constant term of an independent random degree-`(k-1)` polynomial over
  GF(256); reconstruction is Lagrange interpolation at `x = 0`. **Any `k-1` shares reveal nothing** — this
  is an information-theoretic (not merely computational) property (`per_byte_independence_32_bytes`,
  `fewer_than_k_cannot_reconstruct` tests).
- `split` requires `1 <= k <= n <= 255` (x-coordinates are the non-zero bytes `1..=n`); `BadThreshold`
  otherwise.
- **It is NOT authenticated:** "a flipped share byte yields a different (wrong) secret without error"
  (shamir.rs:10-12, proven by `tampered_share_reconstructs_wrong_secret`). Any share-integrity check
  (typo/corruption detection) is the UI/DTO layer's job — see §3.
- `combine` fails closed on `DuplicateIndex` (two supplied shares share an x-coordinate) and
  `LengthMismatch` (differing share body lengths), never silently produces a wrong-length secret.
- `Share::body` is `Debug`-elided (prints only length) — a hygiene precedent this spec's own DTOs should
  match (§8).
- All coefficient buffers are `Zeroizing`; `combine`'s output is `Zeroizing<Vec<u8>>`.

### 2.2 `admin_core::recovery` — splitting/reconstructing the recovery key (`crates/admin-core/src/recovery.rs:181-235`)

```rust
pub fn split_recovery_key(
    recovery_secret: &EncSecretKey, k: u8, n: u8,
) -> Result<Vec<Share>, RecoveryError>;

pub fn reconstruct_recovery_key(k: u8, shares: &[Share]) -> Result<EncSecretKey, RecoveryError>;
```

with

```rust
pub enum RecoveryError {
    DekCommitMismatch, WrapFailed,
    ThresholdSplitFailed(ShamirError), ThresholdCombineFailed(ShamirError),
    ReconstructLength,
}
```

What is split: **the recovery keypair's private half — a 32-byte X25519 scalar** (`EncSecretKey`,
`crypto/src/wrap.rs:32`, `struct EncSecretKey(Zeroizing<[u8; 32]>)`, no `Debug`/`PartialEq`, exposed only via
`expose_bytes()` "only for sealing into the on-device blob"). `split_recovery_key` exposes it once
(`Zeroizing::new(recovery_secret.expose_bytes())`), calls `shamir::split`, and the transient copy zeroizes
on drop. `reconstruct_recovery_key` calls `shamir::combine`, requires exactly 32 bytes back
(`ReconstructLength` otherwise), and returns a fresh `EncSecretKey` (zero-on-drop).

**How reconstruct feeds the existing recovery path**, both proven by real code:
- `reconstructed_key_opens_only_for_correct_shares` / `recovery_key_split_reconstruct_unwraps`
  (recovery.rs:347-411) show the reconstructed `EncSecretKey` is a drop-in replacement for the whole-cold-copy
  `recovery_priv` everywhere it is used today:
  - `validate_recovery_wrap(recovery_priv, wrap, dek_commit, ctx)` — the offline sweep (D27/R26,
    recovery.rs:144-179) that opens a sampled `recovery` wrap and checks it against `dek_commit`.
  - `build_recovery_grant(params, dek)` (recovery.rs:67-105) — the last-resort account-recovery ceremony
    (§12.7): the admin first unwraps the current DEK with the (now-reconstructed) `recovery_priv`
    (this step is upstream of and outside this spec — it is exactly `unwrap_dek` against the recovery wrap,
    same as `validate_recovery_wrap` does), then re-wraps to the new recipient and signs a grant under the
    admin's **own** `sig` key (`admin_sig: &SigningKey`, `admin_id: Id`) — a **different** key from the
    recovery key, confirming Shamir custody of D6 is orthogonal to the admin's personal identity/session.
- **Below-threshold and wrong-share reconstructions fail closed**: `recovery_key_below_threshold_fails`
  maps a `k-1`-share combine to `Err(ThresholdCombineFailed(InsufficientShares))`;
  `reconstructed_key_opens_only_for_correct_shares` shows a wrong-`k` combine silently interpolates a
  *different* (wrong) key that then fails to open the real wrap — i.e. Shamir itself is not authenticated
  (§2.1), but the **downstream open is the authentication**: a bad reconstruction never masquerades as a
  working recovery key. This is the load-bearing fail-closed property the reconstruct UX (§6) must preserve
  end to end: never claim success until the reconstructed key is proven against something real (a real
  recovery wrap or the DEK commitment), not merely "combine didn't error."

Documented residual (recovery.rs:189-192, DESIGN.md:897/940): the scalar is reassembled in RAM once at
split, and again at each reconstruction — "a reconstruct-to-use scheme, not a never-reassemble threshold
cryptosystem." This spec inherits that accepted posture; it does not attempt MPC-style never-reassemble
custody.

### 2.3 How the recovery keypair is used upstream (grounds "why this matters")

Every upload wraps its DEK to the recovery recipient's public key, unconditionally — `upload.rs:61`
(`pub recovery_pub: EncPublicKey`) and `upload.rs:495` (`x25519: params.recovery_pub.to_bytes()`), resolved
client-side via `resolve_recovery_recipient` (`client-app/src/directory.rs:86-105`, D5-verified,
fail-closed `untrusted` if unpublished/forged). So **whoever holds the recovery private key can decrypt every
file, past and present** — DESIGN.md:41 states this plainly as a disclosed escrow capability, not an
accident. Splitting that key K-of-N is exactly what turns "one stolen/lost cold copy = totally
compromised/lost" into "a threshold of custodians must collude to decrypt everything, and losing any `n-k`
shares is survivable" (DESIGN.md:111, 897).

## 3. Where this UI runs (architectural decision)

The recovery key is a **breakglass, offline (air-gapped) key** by design (DESIGN.md §16.3/§12.7): "the
recovery wraps to process are hand-carried in..., and the resulting new wraps are hand-carried out — only
ciphertext crosses the air gap... `recovery_priv` never touches a networked machine" (DESIGN.md:757).
`tools/ceremony-harness` (test-only) says outright: "the real ceremony runs the CLIs offline"
(`tools/ceremony-harness/src/lib.rs:3`).

**Decision:** build this as a screen inside the existing `client-app` Tauri binary, reusing its UI/a11y/DTO
conventions, but make the new commands themselves **strictly local — no network call anywhere in the split
or reconstruct path.** This exactly mirrors the existing precedent `request_approval`
(`client-app/src/commands/admin.rs:76-87`): "The running app CANNOT confer admin... `request_approval` only
shapes the data the air-gapped ceremony needs... Pure/local — no network." The split/reconstruct commands
are the same shape: pure, local, offline-safe functions wrapped as Tauri commands, meant to be run *only* on
a machine an operator has physically air-gapped — the app enforces this by construction (nothing it does
requires or performs a network call), not by a runtime "offline mode" flag. The screen's own copy states the
operational requirement plainly ("Run this only on the offline recovery device").

This keeps the ceremony behind the same audited, accessible, tested UI stack the rest of the app uses,
instead of a bespoke CLI with no a11y/DTO discipline. The trade-off — a full Tauri/WebView2 app is a larger
TCB on the air-gapped device than a minimal CLI — is called out as an open question (§13); `ceremony-harness`
already exists as a *test-only* precedent for a narrower CLI if that trade-off is later preferred.

**Gating:** unlike the online admin commands (`list_pending`/`issue_voucher`, which re-auth on a fresh
channel via `reauth`, `commands/admin.rs:23-30`), these commands have **no session/reauth step** — there is
no server involved. Gating is instead: (1) operationally, the screen is only reachable/meaningful on the
offline device; (2) the recovery secret itself is the credential — it must be *supplied* to the split
command (loaded from wherever the existing single cold copy lives today, or, after this ships, never
persisted as a whole copy again) and *reconstructed* only from real custodian shares. There is deliberately
no new "recovery operator" server role (`encoding::types::Role` today is only `User`/`Admin`,
`crates/encoding/src/types.rs:244-247`) — custody of D6 has never been an online-role concept, and this spec
does not add one.

## 4. The split ceremony UX

**Screen:** new `<recovery-split-screen>`, reachable from a (new) "Recovery custody" entry, mirroring the
existing `<admin-screen>`'s "Admin" entry shape (a labelled `<main>`, an `<h1>`, `role=status` regions).

**Flow:**

1. **Load the recovery secret.** The operator supplies the existing recovery private key material (today: a
   single cold copy, DESIGN.md D6 baseline) to seal it into shares. Exact source format is an open question
   (§13) — the safe default is **load from a local file**, never a typed/pasted raw scalar, to avoid it
   transiting the OS clipboard or terminal scrollback. The loaded key is held as `EncSecretKey` (already
   zero-on-drop, no `Debug`) for the lifetime of the ceremony only.
2. **Choose `k` and `n`.** Two number inputs with live guidance text, not silently clamped:
   - `n` (total shares / custodians) — sane range guidance: at least 3 (any single custodian holding both
     shares of a size-2 split defeats the point), practically bounded by how many trusted, geographically
     distinct custodians exist (the codebase caps `n <= 255`, `shamir.rs:147`, far above any realistic
     custody count).
   - `k` (threshold) — the UI warns on both ends: **`k` too low** (e.g. `k = 1`) means a *single* custodian
     is again a full cold copy on their own — cite the degenerate case proven by
     `k_equals_1_is_trivial_sharing` (shamir.rs:354-364: "every share body == secret" when `k=1`) so the
     warning is not hand-wavy; **`k` too high** (e.g. `k = n`) means losing *any one* custodian's share
     permanently loses recoverability — no quorum is possible even with `n-1` shares present. A commonly
     reasonable default to *suggest* (not force) is `k` a strict majority of `n` (e.g. 3-of-5), matching the
     dual-control spirit already used elsewhere in this system for breakglass ops (DESIGN.md:461,
     "recovery-key use... require[s] two distinct admins").
   - `BadThreshold` (`k == 0 || n == 0 || k > n`) is caught client-side before the command is even invoked
     (immediate, non-network validation) *and* re-checked by the command (defense in depth, since
     `split_recovery_key` itself fails closed on it).
3. **Generate.** One "Generate `n` shares" action invokes the split command (§8). Nothing is displayed until
   it returns — the whole secret is only ever resident in the command's local memory (`Zeroizing`), never in
   the frontend/webview process, and the command returns the `n` shares (never the whole secret — see §8 DTO
   rule).
4. **Present each share, one at a time, for safe distribution.**
   - **Display format:** each share is shown as (a) selectable **text** (a labelled, versioned, checksummed
     encoding, §5) the operator can copy, and (b) a **QR code** rendered client-side from that same text (no
     network, no third-party QR service — a local JS QR-encode of the text already computed), and (c) a
     **"save to file"** action that writes the same text to a chosen path. All three encode identical bytes;
     the operator picks whichever suits the custodian.
   - **Copy-once semantics:** each share is shown on its own step ("Share 2 of 5") with an explicit "I have
     recorded this share — next" continue action; the UI does not keep a "show all shares" list view, so
     there is no single screen displaying more than one share at a time (reduces shoulder-surf/screenshot
     blast radius, and discourages storing all shares together, which is the custody anti-pattern §9 warns
     against). Once the operator advances past a share, re-displaying it requires re-running split (which
     **invalidates all previously issued shares** for that recovery key — the UI must say this explicitly,
     since re-splitting silently produces a different, incompatible share set for the same secret with a
     fresh random polynomial per byte, `shamir.rs:161-172`).
   - A persistent, non-dismissable banner across every share-display step: *"This share is shown once. Write
     it down or export it now — store it somewhere separate from the other shares (§9). Do not photograph or
     store it alongside another share."*
5. **Completion.** After the last share is acknowledged, the whole in-memory `EncSecretKey` and the
   generated `Vec<Share>` are dropped (zeroized) by the command's return; the screen shows a final summary
   (which custodian indices were issued, `k`-of-`n`, and the label from §5) with **no secret bytes**, only
   the non-secret metadata, suitable to keep in an ordinary (non-secret) ceremony log.

**Memory handling:** the whole reassembled secret and the freshly generated shares exist only inside the
Rust command's stack/heap for the duration of one command invocation (`Zeroizing` throughout, matching
`split_recovery_key`'s own hygiene, §2.2); nothing is written to disk by the split command itself — file
export (step 4) is an explicit, separate, operator-initiated write per share, exactly one share at a time,
mirroring `export_keystore`'s "only ever writes ciphertext, only on explicit request" shape
(`keystore.rs:107-113`).

## 5. Share representation & integrity

A share crossing the human/custodian boundary needs more than `Share { index, body }` — it needs to survive
being typed, filed, and years later fed back in without the custodian (or the future operator) being able to
tell it apart from a different secret's share, and it needs a way to catch a transcription typo *before*
`combine` silently produces a wrong-but-plausible-looking key (§2.1: Shamir itself will not error on a
corrupt share).

**Proposed wire encoding (new, this spec — not yet code):**

```
MSHARE1:<label-b64url>:<k>:<n>:<index>:<body-b64url>:<checksum-hex8>
```

- `MSHARE1` — a version tag (mirrors the existing `Suite::V2`/keyblob-v2 style of explicit versioning
  elsewhere in this codebase), so a future format change is unambiguous and old shares are never
  misinterpreted under a new scheme.
- `label` — a short, **non-secret** identifying string the operator sets at split time (e.g. "MaxSecu
  recovery key, 2026-07"), so a custodian and a future operator can tell which recovery-key generation a
  share belongs to (D6 rotation, DESIGN.md §16.4, produces a *new* recovery key with a *new* split — old and
  new shares must never be mixed). The label is not secret and does not need integrity protection beyond the
  overall checksum (a corrupted label just shows a garbled label, not a security issue).
- `k`, `n`, `index` — plain integers, carried alongside the share (not just implicit) so a reconstruct UI can
  validate `1 <= index <= n` and display "share 2 of 5, need 3" without out-of-band bookkeeping.
- `body` — the share's payload bytes (`Share::body`), base64url-encoded.
- `checksum` — first 8 hex chars of `sha256(label ‖ k ‖ n ‖ index ‖ body)` (`crypto::sha256`,
  `crates/crypto/src/hash.rs:6`, already used elsewhere for non-secret integrity, e.g. `admin::Voucher`'s
  `hash = sha256(code.as_bytes())`, `client-app/src/admin.rs:20`). **This is explicitly a
  transcription/corruption check, not a cryptographic authenticity guarantee** — it catches "the custodian
  mistyped a character" or "this text file is truncated," the same class of error the module doc for
  `shamir.rs` already flags as *not* covered by Shamir itself (§2.1). It cannot catch a malicious
  *fabricated* share with a self-consistent checksum; that class of attack is caught downstream instead, by
  the reconstructed key's failure to open a real recovery wrap (§2.2, §6) — mirroring exactly how
  `validate_recovery_wrap` is the actual authenticity check for the *whole* recovery key today.
- QR encoding (§4) encodes this same text string verbatim — no separate binary QR format, so there is only
  one encoding to test/validate.

**What the checksum is NOT:** it is not an HMAC (no shared key exists to key it — the whole point is no
single party holds the secret), and it is not a substitute for the downstream real-wrap check. It is cheap,
local, and exists purely to reject obviously-mistyped input **before** wasting a `combine` attempt (§6) —
good UX, not a security boundary.

## 6. The reconstruct / recover flow

**Screen:** new `<recovery-reconstruct-screen>`.

1. **Collect shares.** The operator adds shares one at a time — paste text, scan a QR (camera, local only),
   or pick a file — into a running list. Each added share is:
   - **Parsed** against the §5 format; a malformed string (wrong version tag, bad base64, wrong field count)
     is rejected immediately with a specific, non-scary error ("This doesn't look like a MaxSecu recovery
     share — check for a copy/paste error") — never a raw parse-error dump.
   - **Checksum-verified** (§5); a checksum mismatch is rejected the same way, distinctly ("This share may
     be corrupted or mistyped — re-enter it").
   - **Checked against the running list for `index` uniqueness** *before* it is added (client-side, cheap) —
     this pre-empts `ShamirError::DuplicateIndex` with a clear "you've already added share 3" message rather
     than a generic combine failure later.
   - **Checked for label consistency** against the first accepted share's label — a share from a *different*
     recovery-key generation (§5) is rejected with "this share is from a different recovery key set
     (`<label>` vs `<label>`)" rather than silently mixed in (mixing labels would not be caught by Shamir
     itself — the polynomials are independent per split, so a foreign share simply produces `LengthMismatch`
     at best or a *wrong, plausible-looking* key at worst; catching it at the label level is strictly safer
     than relying on the downstream real-wrap check alone, matching the "obviously foreign" part of Testing
     §10).
   - The running list shows *count only* — "3 of 5 needed" — never share bytes back on screen (a share, once
     entered, is treated the same as a password: accepted, held, never redisplayed).
2. **Reconstruct is disabled** (button `aria-disabled`, with an explanatory `role=status` line) until at
   least the declared `k` shares are present. **Below-threshold reconstruct is not offered as a "try anyway"
   option** — `reconstruct_recovery_key`'s own `InsufficientShares` fail-closed behavior (§2.2) is the
   backstop, but the UI should not invite the operator to attempt (and fail) or, worse, to be tempted to pad
   with a duplicate/foreign share to hit the count.
3. **Reconstruct.** Invokes the reconstruct command (§8) with the collected shares. On success it returns
   an opaque, non-secret **handle** (§8 DTO rule) — not the key bytes — bound to that session's in-memory
   `EncSecretKey`.
4. **Prove it, don't just claim it.** Per the fail-closed property in §2.2 ("a bad reconstruction never
   masquerades as a working recovery key" only if something downstream actually opens something real), the
   reconstruct screen's success state must be gated on a **real proof**, not merely "the combine call didn't
   return `Err`": either (a) immediately running the existing offline sweep check,
   `validate_recovery_wrap`, against a sampled real recovery wrap + its committed `dek_commit` the operator
   already has to hand (the exact same check D27/R26 already performs periodically, recovery.rs:144-179), or
   (b) proceeding directly into the existing `build_recovery_grant` ceremony (§2.2), whose own
   `DekCommitMismatch` check is exactly this proof. The UI must not present a green "Recovery key
   reconstructed" checkmark from `combine` succeeding alone — `reconstructed_key_opens_only_for_correct_shares`
   (recovery.rs:390-411) is the concrete proof this concern is real: a wrong-`k` combine returns `Ok` with a
   *different* key, not an error.
5. **Failure paths, all fail-closed, all with specific `role=status`/`role=alert` text, none exposing partial
   secret material:**
   - Fewer than `k` shares → reconstruct action stays disabled (step 2); no partial-combine attempt exists.
   - A corrupt/mistyped share → rejected at add-time (step 1), never reaches `combine`.
   - A foreign (different recovery-key generation) share → rejected at add-time by label (step 1); if it
     somehow reaches `combine` (e.g. a fabricated label to bypass the client-side check), `combine` itself
     still fails closed on `LengthMismatch`/`DuplicateIndex` where structurally possible, and the §6 step-4
     real-wrap proof catches the remaining case (a same-length, same-label-spoofed, wrong-value share) by
     simply not opening anything real.
   - `ReconstructLength` (the interpolated result isn't 32 bytes — should not occur given the DTO validates
     shares came from a 32-byte-body split, but is still mapped to a clear "these shares don't reconstruct a
     valid recovery key" error, never a panic).

**Identity/secret under session lock:** the reconstructed `EncSecretKey` lives only inside the Rust command
process, keyed to that one ceremony session, the same way `Session`'s `Option<Identity>` is only ever
borrowed under its `tokio::sync::Mutex` for one synchronous operation (`commands/auth.rs:23-35`) — for this
feature there is no long-lived server session at all (§3), so the equivalent discipline is: the reconstructed
key is held in a short-lived, explicitly-scoped ceremony state (not the long-lived `Session`), and is
zeroized as soon as the ceremony (grant-issuance or sweep-check) that consumed it completes or the operator
cancels.

## 7. Relationship to `export_keystore` / password backup

These are **different keys with different purposes** and are not alternatives to each other:

| | `export_keystore` (Phase 5) | K-of-N recovery split (this spec) |
|---|---|---|
| What's protected | **The user's own identity** (`local_key_blob`, Argon2id-wrapped `Identity`) | **The recovery keypair** (D6), a *separate*, breakglass, escrow key that can decrypt everyone's files |
| Who holds the backup | The same user, on their own portable media | `n` distinct custodians, `k` of whom must cooperate |
| Threat it defends against | This device is lost/wiped; the user restores their own account elsewhere with their password | The single recovery cold-copy is stolen (total compromise) or lost (permanent unrecoverability for anyone who ever needed breakglass access) |
| Secrecy model | One password gates one ciphertext blob (`keyblob::seal`, Argon2id + AEAD) | No single party's compromise is total; secrecy is information-theoretic below `k` (§2.1) |
| Who can invoke it | Any user, for their own account (`commands/settings.rs:48-54`) | An admin/recovery custodian, offline, over the D6 key only |

**They coexist and are complementary, not redundant.** `export_keystore` is the *first line* of personal
account recovery — DESIGN.md:751 calls it out as the deliberate, user-initiated, non-server-storage
self-recovery option, used "without it, recovery depends on the admin + recovery key." The K-of-N split is
what happens *behind* that fallback — it hardens the D6 escrow key itself, which is what a user falls back
to when they have **no** `export_keystore` backup and have lost their password (DESIGN.md:755, §12.6/§12.7).
A user who diligently exports their own keystore backup may never need the recovery ceremony at all; the
recovery ceremony exists for everyone else, and for revoking/rotating access when the acting recipient set
changes. Nothing in this spec touches `keystore.rs`/`export_keystore`/`change_password`; they are cited here
purely to place this feature in the existing backup taxonomy for the UI copy (so a user is not confused about
which "recovery" a given screen means — recommend the settings screen and this new screen visually
distinguish "back up your own account" vs. "administer the shared recovery key").

## 8. The command/DTO seam

New Tauri commands, `crates/client-app/src/commands/recovery_custody.rs` (new file; mirrors
`commands/admin.rs`'s narrow, single-purpose module shape), all **local/offline, no network**, matching
`request_approval`'s doc comment style ("Pure/local — no network"):

```rust
#[tauri::command]
pub fn split_recovery_key(req: SplitRecoveryKeyRequest) -> Result<SplitRecoveryKeyResponse, UiError>;

#[tauri::command]
pub fn add_recovery_share(req: AddShareRequest, state: State<'_, CeremonySession>)
    -> Result<AddShareResponse, UiError>;

#[tauri::command]
pub fn reconstruct_recovery_key(state: State<'_, CeremonySession>)
    -> Result<ReconstructResponse, UiError>;

#[tauri::command]
pub fn prove_reconstructed_key(req: ProveRequest, state: State<'_, CeremonySession>)
    -> Result<ProveResponse, UiError>;

#[tauri::command]
pub fn discard_ceremony_session(state: State<'_, CeremonySession>) -> Result<(), UiError>;
```

**New DTOs** (`crates/client-app/src/dto.rs`, following the existing rule at the top of that file — "No key
material, no signed-record interiors, no whole-plaintext buffers ever appear here" — extended for this
feature's specific case):

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct SplitRecoveryKeyRequest {
    pub recovery_secret_path: String, // local file path; loaded + zeroized inside the command
    pub label: String,                // non-secret, operator-chosen (§5)
    pub k: u8,
    pub n: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct SplitRecoveryKeyResponse {
    pub shares: Vec<String>, // §5 wire-encoded MSHARE1 strings — the interchange unit, not raw Share bytes
    pub label: String,
    pub k: u8,
    pub n: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddShareRequest {
    pub share_text: String, // one §5 MSHARE1 string
}

#[derive(Debug, Clone, Serialize)]
pub struct AddShareResponse {
    pub have: u8,
    pub need: u8,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReconstructResponse {
    pub ceremony_handle: String, // opaque id into CeremonySession — NEVER the key bytes
    pub label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProveRequest {
    pub file_id_hex: String,
    pub version: u64,
    pub dek_commit_hex: String,
    pub recovery_wrap_b64: String, // the wire wrap `enc(32) ‖ ct` (recovery.rs:151-162 wire form)
}

#[derive(Debug, Clone, Serialize)]
pub struct ProveResponse {
    pub verified: bool,
}
```

**DTO rules specific to this feature (extending the file-level rule):**
- **Individual shares are the interchange unit and are allowed to cross the seam** as the §5 text encoding
  — this is a deliberate, narrow exception to "no key material," justified by §2.1's information-theoretic
  property: any single share below `k` is, by construction, indistinguishable from random with respect to
  the secret. They are still treated as sensitive (never logged — `SplitRecoveryKeyResponse`/`AddShareRequest`
  derive `Serialize`/`Deserialize` only, no `Debug` impl that would appear in a panic/log; the frontend
  clears the paste/scan field immediately after a share is accepted, mirroring `onChangePassword`'s field-clear
  in `settings-screen.ts:181-182`).
- **The reconstructed whole key never crosses the seam.** `reconstruct_recovery_key` (the command) returns
  only an **opaque `ceremony_handle`** bound to server-side (Rust) state (`CeremonySession`, a small new
  `tauri::State` analogous to `Session`/`ConnectLock`, `commands/auth.rs:23-60`), not the key bytes. Every
  operation that needs the actual key (`prove_reconstructed_key`, and, out of this spec's scope, the
  existing `build_recovery_grant` ceremony) takes the handle and operates entirely inside the Rust process.
- **The initial recovery secret is loaded by path, not by value in the request**, so the raw scalar is never
  serialized through Tauri's IPC/JSON boundary at all — the command reads the file itself.
- `ProveRequest`/`ProveResponse` intentionally carry only hashes/hex ids and a boolean — no key material,
  matching `validate_recovery_wrap`'s own signature shape (it takes `&EncSecretKey` + public commitments,
  returns `Result<(), SweepError>`).

**Owner/identity gating:** as established in §3, there is no server reauth here. The one access-control
statement this seam makes is structural: `split_recovery_key` and `reconstruct_recovery_key`/`add_recovery_share`
are **not reachable without physical possession** of either the existing recovery secret file (split) or
`≥k` custodian shares (reconstruct) — the command layer enforces nothing beyond what `admin_core::recovery`
already fails closed on (§2.2). This mirrors `request_approval`'s own gating note: the app "cannot" do the
sensitive part (there, signing; here, holding a decryptable key) — it only shapes/relays data for an
operation whose real gate is a physical secret, not a session.

## 9. Custody guidance (shipped as in-UI copy)

Static guidance text, shown on the split screen (persistent) and linked from the reconstruct screen:

- **Distribute shares to distinct trusted parties or locations.** A share given to two people who trust each
  other completely, or stored in two backups of the same safe, is one custody point, not two — it does not
  raise the effective threshold.
- **Never store `k` or more shares together.** Storing enough shares together to reconstruct recreates
  exactly the single-point-of-theft risk Shamir splitting exists to remove (DESIGN.md:111). The split screen
  cannot enforce this (it cannot see where a custodian puts their share) — the guidance is the control.
- **Plan for loss.** Any `n-k` shares can be lost and the key still reconstructs (§2.1); losing *more* than
  `n-k` permanently breaks recoverability (no backdoor, no override — the same information-theoretic
  property that keeps `k-1` shares secret also means there is no way to reconstruct from fewer). Choosing
  `k` well below `n` (§4) is the mitigation, not a workaround after the fact.
- **Rotation / re-split if a custodian is lost or compromised.** If a custodian's share is suspected
  compromised, or a custodian is no longer trusted/available, the *only* remedy is a full new split-and-
  redistribute ceremony against a *freshly rotated* recovery key (DESIGN.md §16.4 D6 rotation) — re-splitting
  the *same* key with the *same* compromised share still outstanding does not revoke that old share's
  validity for the old key. This is a deliberate, expensive, planned project, not an emergency toggle
  (DESIGN.md:940: "Plan rotation as a deliberate (expensive) re-wrap project, not an emergency").
- **What an attacker with fewer than `k` shares learns: nothing.** This is stated to custodians explicitly,
  with the citation this spec is built on: Shamir's construction makes any `k-1` shares of a secret exactly
  as likely to interpolate to *any* possible secret value as any other — an information-theoretic guarantee,
  not a computational-hardness assumption, proven in this codebase by `fewer_than_k_cannot_reconstruct` and
  the per-byte-independent-polynomial construction (`shamir.rs:1-20, 149-175`). A custodian holding one share
  can be told plainly: "this piece, on its own, is worthless to anyone who steals it."

## 10. Accessibility (WCAG-AA, mirroring Phase-5 a11y patterns)

Grounded in the shipped `settings-screen.ts`/`admin-screen.ts` patterns (`crates/client-app/ui/src`) and the
Phase-5 structural a11y test (`ui/src/a11y.test.ts`):

- Each screen: a single `<main id="main" tabindex="-1" aria-labelledby="…">`, focused on mount
  (`(this.querySelector("#main") as HTMLElement).focus()`), exactly like `settings-screen.ts:96` and
  `admin-screen.ts:22`.
- **Focus order:** the split ceremony's step-by-step share display (§4.4) must move focus to the new step's
  heading/content on each "next" action (not leave focus stranded on a now-hidden "continue" button) —
  same discipline as a wizard, testable the same way `a11y.test.ts` structurally lints existing screens.
- **Copy/QR affordances:** the "copy to clipboard" and "save to file" buttons are real `<button type=button>`
  elements with explicit text labels ("Copy share 2 text", "Save share 2 to file", "Show share 2 as QR") —
  never icon-only, matching the existing convention of full-text buttons throughout (`admin-screen.ts:13`,
  `59`). The QR code itself gets an `alt`/`aria-label` describing it as a redundant encoding of the visible
  text, not the only way to get the data (screen-reader/no-camera users still have the text + file paths).
- **Error and status text:** transcription/checksum errors (§6) use `role=alert` (interrupting, since they
  block progress and need immediate attention — matching `admin-screen.ts:78`'s `role=alert` for a failed
  ceremony-request); routine progress ("3 of 5 shares added") uses `role=status aria-live=polite` (matching
  `settings-screen.ts:27,73` and `admin-screen.ts:14,18`) — not interrupting, since it's expected, frequent
  feedback.
- **Reduced motion / high contrast:** the ceremony screens use the same shared `data-*` attributes /
  `:root` CSS the rest of the app already applies from `core/settings.ts` (`applySettings`) — no
  screen-specific animation exempt from `reduced_motion`, no color-only distinction between "share accepted"
  and "share rejected" (paired with icon + text, satisfying the existing high-contrast pattern).
- **`:focus-visible`:** every new interactive control (share inputs, copy/QR/save buttons, k/n number
  inputs) picks up the existing global `:focus-visible` styling (`styles.css`) with no screen-local override.
- A new `a11y.test.ts` case (or an addition to the existing suite) structurally lints the two new screens the
  same way existing screens are checked (labelled landmark, focused heading, `role=status`/`role=alert`
  presence, no icon-only buttons) — dependency-free `node:test`, matching the existing 22-check suite's
  approach (full axe-in-jsdom remains deferred, per the existing note in that suite).

## 11. Security review checklist

Properties a reviewer should confirm before this ships (mirrors the checklist shape used in
`docs/security-review-phase7.md` for the underlying primitive):

- [ ] The whole recovery secret (loaded at split, reconstructed at recover) exists only inside
      `Zeroizing`/zero-on-drop types (`EncSecretKey`, `Zeroizing<Vec<u8>>`) for the minimum span needed, and
      is never written to disk, logged, or included in any `Debug`/error/panic output.
- [ ] `SplitRecoveryKeyResponse`/`AddShareRequest`/frontend share-holding state never derive/implement
      `Debug` in a way that would dump share bytes; any log line touching these types is checked by hand.
- [ ] Any single share (or any `k-1` shares) crossing the Tauri IPC boundary, sitting in the webview's JS
      state, or written to a "save share" file is confirmed to reveal nothing about the secret on its own —
      this is inherited from `crypto::shamir`'s proven property (§2.1), not re-derived, but the reviewer
      confirms no UI code path accidentally concatenates/caches shares somewhere reachable below `k`.
- [ ] The §5 checksum is confirmed to be purely a UX corruption check — no code path treats "checksum
      passed" as a security guarantee (e.g., skips the §6-step-4 real-wrap proof because the checksum
      matched).
- [ ] Reconstruct is confirmed fail-closed end to end: below-`k` shares (`InsufficientShares`), a duplicate
      index (`DuplicateIndex`), mismatched share lengths (`LengthMismatch`), and a non-32-byte result
      (`ReconstructLength`) all produce a clear, specific, non-secret-leaking `UiError` and never a panic or
      a silently-wrong "success."
- [ ] The UI never displays a reconstruction "success" state based on `combine`/`reconstruct_recovery_key`
      returning `Ok` alone — success is gated on the §6-step-4 real proof (`validate_recovery_wrap` or entry
      into `build_recovery_grant`), matching the concern proven live by
      `reconstructed_key_opens_only_for_correct_shares` (recovery.rs:390-411).
- [ ] No new server-side or networked code path is introduced by this feature — `split_recovery_key`,
      `add_recovery_share`, `reconstruct_recovery_key`, `prove_reconstructed_key` perform zero network I/O
      (grep-checkable: no `hyper`/`http_client` import in the new module).
- [ ] `discard_ceremony_session` (or app exit) reliably zeroizes any in-memory `CeremonySession` state; no
      share/secret survives an app restart (this is deliberate — unlike the streaming-upload feature's
      staging records, there is no resumability across a restart for a ceremony; restarting means re-
      collecting shares from the physical custodians again, which is the correct, safe behavior for a
      breakglass secret).
- [ ] Re-split invalidation (§4 step 4) is documented clearly enough in the UI copy that an operator cannot
      reasonably believe old and new shares are interchangeable.

## 12. Testing plan

- **Unit (Rust, new `commands/recovery_custody.rs` + `dto.rs` additions):**
  - Split-then-reconstruct round trip through the **DTO layer** (encode `Share` → `MSHARE1` text → parse
    back → `Share`), asserting byte-identical `index`/`body` to what `crypto::shamir::split` produced —
    this is new code (the §5 encoding) sitting on top of the already-tested crypto, so it needs its own
    round-trip test independent of `shamir.rs`'s existing coverage.
  - Checksum rejects a single-character mutation in every field position (label, k, n, index, body) —
    proves the corruption check actually covers the whole encoded string, not just the body.
  - `add_recovery_share` rejects: malformed text, wrong checksum, duplicate index already in the session,
    and a share whose label doesn't match the session's first-accepted label — four distinct `UiError`
    codes, asserted individually (not collapsed to one generic error, matching the `error.rs` convention of
    specific codes over the generic `?`-fallback).
  - `reconstruct_recovery_key` (command) below `k` shares is unreachable from the UI path (the command
    itself should also independently reject it, defense in depth) — assert the `UiError` maps from
    `RecoveryError::ThresholdCombineFailed(ShamirError::InsufficientShares)`.
  - `prove_reconstructed_key` end-to-end: split a real generated `EncSecretKey`-backed keypair, reconstruct
    from a `k`-subset, build a real recovery wire-wrap (mirroring `recovery_wire_wrap` in
    `recovery.rs:244-254`), and confirm `prove_reconstructed_key` reports `verified: true`; confirm it
    reports `verified: false` (never panics, never a generic error swallowing the distinction) for a wrap
    built against a *different* DEK.
- **Frontend (`ui/src`, `node:test` + jsdom, matching `settings-store.test.ts`'s style):**
  - Share-collection state machine: adding shares updates `have`/`need`; adding a duplicate index is
    rejected without changing `have`; the "reconstruct" action is disabled below `k` and enabled at exactly
    `k`.
  - A11y structural checks for both new screens added to `a11y.test.ts`'s existing suite (§10).
- **e2e-shaped scenario (can live as a Rust integration test over the command layer, no Tauri runtime
  needed — mirrors how `recovery.rs`'s own tests exercise the crypto without any network):**
  1. Split 3-of-5 → collect exactly 3 valid shares → reconstruct → prove against a real wrap → **pass**.
  2. Collect only 2 shares → reconstruct action never becomes available (frontend) / command independently
     rejects (backend) → **InsufficientShares, no partial secret exposed**.
  3. Collect 3 shares where one has a single flipped character in `body` → **rejected at add-time by
     checksum**, never reaches `combine`.
  4. Collect 3 shares from a *different* split (different label) → **rejected at add-time by label
     mismatch**; separately, prove that if label-checking were bypassed, the resulting reconstruction still
     fails the real-wrap proof (belt-and-braces test, directly exercising the same property
     `reconstructed_key_opens_only_for_correct_shares` already proves at the crypto layer).
  5. Split → reconstruct with all `n` shares (not just `k`) → still succeeds (mirrors `k_equals_n`-adjacent
     coverage already in `shamir.rs`, confirms the DTO layer doesn't accidentally hardcode "exactly k").

## 13. Open questions / deferred — ALL RESOLVED, see §0

> **Resolved 2026-07-02 (see §0 for the binding decisions):** default k/n & floor → D-E
> (advisory n≥3, hard k≤n, suggest majority); transport format → D-D (text+file, no QR);
> pre-split secret on-disk format → D-B (new Argon2id+AEAD sealed file); same-key re-split
> → D-F (discouraged, distinct from D6 rotation); ML-KEM half → D-C (deferred, classical
> only); CLI vs GUI → D-A (Tauri GUI); ceremony logging → D-G (minimal non-secret local
> log). The original analysis is retained below for context.

- **Default `k`/`n` values / whether to force a minimum `n`.** §4 suggests "majority of `n`" as guidance
  text, not an enforced default — confirm whether the product wants a hard floor (e.g. refuse `n < 3`) or
  purely advisory copy.
- **Share transport format priority.** §4 proposes text + QR + file as co-equal options; confirm whether QR
  is actually wanted (adds a JS QR-encode dependency to the webview bundle — small, but a new dependency)
  or whether text+file alone is sufficient for the initial version.
- **Where the *initial* (pre-split) recovery secret currently lives on disk**, so `SplitRecoveryKeyRequest`'s
  file-load step has a concrete format to target. Today DESIGN.md describes D6 custody only physically
  ("sealed... cold copy"), not as a specific file format this codebase already writes/reads. This spec
  assumed a raw-file load (§4 step 1) as the safe default parameter shape, but the actual bytes-on-disk
  format for that existing cold copy is outside this spec's grounding and needs to be pinned down (or a
  small new sealed-file format, mirroring `keyblob::seal`, may be worth adding as a companion piece — not
  designed here).
- **Whether to support re-splitting the same key as a first-class "rotate custody" flow** (vs. the §9
  guidance that re-splitting invalidates prior shares and should be paired with a full D6 key rotation,
  DESIGN.md §16.4). Decide whether the UI should actively discourage/hide "just re-split, same key" as an
  option, to avoid an operator accidentally treating it as a lightweight custodian swap when the guidance
  says it should not be.
- **Whether/how to extend `split_recovery_key`/`reconstruct_recovery_key` to also cover the ML-KEM half of a
  PQ-hybrid recovery key** (§1's noted gap — `crypto::shamir::split` is generic over `&[u8]`, so a 64-byte
  ML-KEM seed is not a primitive limitation, but wiring it through `admin-core::recovery` and this UI is new
  scope, not assumed here).
- **CLI vs. GUI for the air-gapped device (§3).** This spec chose "reuse client-app's Tauri UI, offline-only
  commands" for a11y/consistency; confirm this is preferred over a minimal, smaller-TCB CLI in the spirit of
  `tools/ceremony-harness`, given the recovery device is explicitly the highest-value target in the whole
  system (whoever compromises it decrypts everything).
- **Ceremony logging.** DESIGN.md:461/931 describes recovery-key use as dual-controlled and audited; this
  spec doesn't design the audit trail for the split/reconstruct ceremony itself (only for the
  already-audited grant-issuance step downstream, `build_recovery_grant`). Decide whether a local,
  non-secret ceremony log (who ran it, when, k/n, which custodian indices were issued — no share bytes)
  should be part of this feature or a separate one.
