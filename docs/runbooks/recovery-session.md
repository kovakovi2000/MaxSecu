# Runbook — Recovery-key session (grant-old-file & account recovery)

**Status:** Phase 6 (ops). Implements `DESIGN.md` §12.7 (grant a file no current recipient can read) and §12.6 (device-loss / account recovery). Custody: §16.3.
**Owner:** the recovery-key (D6) custodian, on the air-gapped recovery machine. Every use is authenticated and audited like any privileged admin action (§6.3).
**Tooling:** `maxsecu-admin-core::recovery::{reconstruct_recovery_key, build_recovery_grant}` (threshold-reconstruct the recovery key, then re-wrap a DEK + admin-signed recovery grant, §12.7 steps 3–5).

> **Threshold custody (Phase 7, §16.3/§19).** D6's private key is **split K-of-N across custodians** (`split_recovery_key`, done once at key generation/rotation). A recovery session now requires **k custodians to convene** — no single share opens anything. The key is reconstructed *only* in air-gapped RAM for the duration of the session and zeroized immediately after (documented residual: the brief reassembly window, §16.3).

> **Why this is breakglass.** D6 is a standing recipient on **every** file; whoever holds the cold copy can decrypt everything (the disclosed escrow, §1.2/§6.3). It is brought out **only** when no current recipient remains to re-share online (prefer §12.6 online re-share first), or for the recovery-wrap sweep (`recovery-wrap-sweep.md`). Minimize sessions; each is a custody event (§16.3).

## Prefer online re-share first (§12.6)
If **any** current recipient still holds the file's DEK, recover the user by an ordinary **online re-share** to their new key (`reshare`, §12.4b) — no D6 needed. Only when *no* current recipient remains does the file require the offline recovery key.

## Grant-old-file session (§12.7)
Preconditions: air-gapped recovery machine; **at least `k` of the `n` custodians present, each bringing their share** (no whole cold copy of `recovery_priv` exists); the target file's manifest + the recovery wrap exported by hand.
0. **Reconstruct the recovery key (threshold).** Each of the `k` present custodians loads their `Share`; call `reconstruct_recovery_key(k, &shares)` to rebuild `recovery_priv` in air-gapped RAM. Below `k` shares (or inconsistent shares) fails closed — abort and reconvene. Hold the reconstructed `EncSecretKey` only for this session; it zeroizes on drop.
1. **Unwrap** the file-version's `recovery` wrap with the reconstructed `recovery_priv` to recover the DEK; confirm it matches the manifest's `dek_commit` (this is exactly the `validate_recovery_wrap` check — a bad wrap here is the R26 finding; see `recovery-wrap-sweep.md`).
2. **Build the grant** with `build_recovery_grant`: re-wrap the DEK to the intended recipient's directory-verified `enc_pub` and emit the admin-signed recovery grant over the same `dek_commit` (§12.7).
3. **Note the R24 boundary.** A recovery-operator (admin-rooted) grant is honored **on download for its own version**, but is **not** carry-forward-eligible at rotation (R24/D25): if a *different* writer rotates the file before the restored user re-roots, the user needs one ordinary re-share afterward — rare and benign.
4. **Publish** the new wrap + grant to the app server; **audit** the session (who, file, recipient, **the `k` custodians who convened**, timestamp) to the external sink (§16.5).
5. **Tear down:** drop/zeroize the reconstructed `recovery_priv` (ends the residual reassembly window, §16.3); each custodian **re-seals their share** and disperses. No whole cold copy is ever written back.

## Account recovery (§12.6) — device loss
1. Re-enroll the user's new device/key at the next **enrollment ceremony** (`enrollment-signing.md`), incrementing `key_version`.
2. For each file the user must regain: prefer online re-share from a current recipient (§12.6); fall back to a §12.7 grant-old-file session for files no one else can read.
3. Re-enrollment does **not** clear any tombstone on the user (R28) — if the user was revoked, restoration is an explicit dual-controlled **reinstatement** (`tombstone-issuance.md`).

## Cross-references
`DESIGN.md` §12.6 / §12.7 / §6.3 / §16.3 / R24(D25) / R28; `recovery-wrap-sweep.md`; `enrollment-signing.md`; `tombstone-issuance.md`; `maxsecu-admin-core::recovery`.
