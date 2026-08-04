# Runbook — Recovery-key session (grant-old-file & account recovery)

**Status:** Phase 6 (ops). Implements `DESIGN.md` §12.7 (grant a file no current recipient can read) and §12.6 (device-loss / account recovery). Custody: §16.3.
**Owner:** the recovery-key (D6) custodian, on the air-gapped recovery machine. Every use is authenticated and audited like any privileged admin action (§6.3).
**Tooling:** `maxsecu-admin-core::recovery::{build_recovery_grant, validate_recovery_wrap}` (re-wrap a DEK + admin-signed recovery grant, §12.7 steps 3–5; and the offline wrap-validation check, §16.1/D27). Those two are the **whole** of the crate's recovery surface — see the correction note below.

---

## Scope — which recovery path is this? (2026-08-01)

There are now **two** ways to use the recovery key, and this runbook covers only the first.

| | **Air-gapped grant ceremony** (this document) | **Online recovery session** (spec §0 D6, *amended 2026-08-01*) |
|---|---|---|
| **What it does** | Re-wraps one file-version's DEK to one new recipient and signs a recovery-operator grant (§12.7). Also the wrap-validation sweep (`recovery-wrap-sweep.md`). | Logs the recovery identity into the running server over pinned TLS: **browse every file, open/stream/download every file, end the session** — plus minting user-role registration keys, as it always could. **It cannot share.** |
| **Where the key goes** | Onto the **air-gapped** machine only. Only ciphertext + the grant cross the air gap. | Into the **networked** client (`<app-dir>/recovery/recovery_key_blob`), unsealed with its passphrase. |
| **Status** | **RECOMMENDED for custody** — still the right way to hold and use the cold key, and the only path when the server is down or the file has no live recipient. | Available and **always on** (no config flag). Fastest path, and the one with the wider blast radius. |
| **Can it restore a user's access to a file?** | **Yes — this is the only path that can.** That is what §12.7 *is*. | **No, and this is a CLOSED DECISION (owner, 2026-08-02) — not a gap awaiting work.** `POST /v1/files/{id}/wraps` is `403` for the recovery principal, and the client refuses with `recovery_share_unsupported`. |
| **Cannot** | — | **Share (`add_wrap` — see below)**, upload, delete, revoke, mint a bearer cold-tier link, or enumerate a file's other recipients. Those all still `403`. |

> **Corrected 2026-08-01 — an earlier revision of this table said the online session could "share any of it to any account". It cannot.** `add_wrap` was admitted in a draft and then **reverted** to the ordinary `AuthedSession` gate, which hard-`403`s the recovery principal. The read/browse half of the table is unchanged and is real.

**Operational consequence — read this before you plan a recovery:** if the job is *"user X lost their device / lost access to file Y, give it back to them"*, the **online session cannot do it.** It will let you *see and download* the file (which is often enough — you can hand the plaintext over out of band), but it cannot put a working wrap in that user's account. Restoring access still means the **air-gapped §12.7 ceremony below**. Use the online session for *reading*; use the ceremony for *regranting*.

**Why sharing is shut — CLOSED DECISION, owner, 2026-08-02** (so nobody "fixes" it in a hurry). Three reasons:

1. A recovery-issued grant is **unopenable by the recipient** — the downloader rejects any ancestor whose `recipient_type` is not `user` (`client-core/src/download.rs:448-450`).
2. `granted_by` = the recovery id resolves to **no client-trusted signing key**. *(Precisely: the recovery account **does** hold an Ed25519 `sig_pub` on the server, `server/src/store.rs:47-51`. What is missing is a trusted path to it — `GET /v1/recovery/pubkey` serves only `enc_pub`/`mlkem_pub`, `server/src/http.rs:667-686`, and the embedded recovery pin omits `sig_pub`. Earlier wording here said "no signing key" and was wrong.)*
3. `add_wrap` **replaces destructively** in both stores (`server/src/store.rs:1228`, `server/src/pg.rs:1184-1203`), so a recovery re-share to a user who already had access would **swap their working grant for a dead one**. That is what makes the decision permanent rather than a feature awaiting a protocol.

Two candidate designs would have been needed to lift 1 and 2 (publish a directory binding for the recovery id carrying a real signing key, **or** add `sig_pub` to the recovery pin — a frozen surface — and terminate the chain at the §12.7 admin key), plus a server-side REPLACE refusal for 3. **The operator declined to take either on.** Use the ceremony below to regrant. See `DESIGN.md` §6.3, the recovery spec §0 D6 / §9, and `docs/api.md` §10.1.

### Starting an online recovery session (the file placement)

The cold blob does **not** land where the client reads it on its own, and the two names differ. `tools/maxsecu-setup` writes it to `<repo-root>/recovery_key.blob` (`scripts/install-client.ps1`: `$RecoveryBlob = Join-Path $Root 'recovery_key.blob'`, passed as `--out "$RecoveryBlob"`); the client reads `<folder holding the exe>/recovery/recovery_key_blob` (`crates/client-app/src/commands/recovery_login.rs:60` — `dir.join("recovery").join("recovery_key_blob")`, probed on launch by `crates/client-app/src/commands/startup.rs:31`). Different directory, different filename. It is **never** in a handout ZIP (`scripts/build-user-zip.ps1`: *"NO register.key, NO recovery blob"* / *"The ZIP holds NO account data, NO recovery key"*), and it must stay that way — both ZIP builders now assert it and refuse to compress a staged tree that contains a `recovery_key_blob`, a `local_key_blob`, a `register.key`, a `recovery_pin.bin` or any `*.blob`.

Use the installer rather than copying by hand — it verifies the file is really the recovery keyblob (`MXKB`, not the `MXD5` directory root), re-checks the SHA-256 after the copy, and restricts the copy to the operator's Windows account:

```powershell
# stage into the admin working client (dist\MaxSecuClient)
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -StageRecoveryKey E:\recovery_key.blob

# or into any unzipped client folder (a fresh PC that only has the handout ZIP)
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 `
    -StageRecoveryKey E:\recovery_key.blob -ClientDir C:\MaxSecuClient
```

The app then opens on the recovery sign-in screen. A never-registered device has no `config/connection.json`, so set the server from the connection code on that screen first (the control exists for exactly this case), then enter the recovery passphrase.

**End of session — remove the copy.** It is a full copy of the master key; the cold original stays authoritative.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -UnstageRecoveryKey
```

`install-client.ps1 -Reset` also removes any staged copy (it clears `dist\`), and never rescues one.

**The trade, plainly:** the online path removes the air gap. Recovery key + network reach now yields **complete, remote plaintext of every file** with no operator involvement — where the ceremony below touches **one recipient, one file-version, once**, and leaves an artefact. Do not read the sharing revert as a mitigation: reads over the online path are **not audited and not rate-limited**, so a bulk browse of the entire corpus leaves **no trace**, and a proxied read rehydrates from the cold tier (and may evict) exactly as an ordinary user's would. Prefer the ceremony when you need to *restore* access; the online session is for when the operator genuinely needs account-like *reach*. Either way, **every session is a custody event** (§16.3).

> **CORRECTION 2026-08-01 — the threshold-custody section below described a RETIRED design.** This runbook previously instructed the operator to call `maxsecu-admin-core::recovery::{reconstruct_recovery_key, split_recovery_key}` over `crypto::shamir`. **Those functions do not exist.** The K-of-N Shamir custody model was retired with T6 (spec `2026-07-03-trusted-server-recovery-registration-design.md` §8; `crypto/src/shamir.rs` is deleted and `admin-core` exports only `build_recovery_grant` / `validate_recovery_wrap`). **What actually exists:** the recovery private key is **one Argon2id-sealed cold file**, `recovery_key.blob`, written once by `tools/maxsecu-setup` and opened with its passphrase — no shares, no custodians, no reconstruction step. Step 0 below is therefore *"unseal the cold blob with its passphrase"*, not *"convene k custodians"*. A threshold split is future work (`DESIGN.md` §19), not a shipped property.

> **Why this is breakglass.** D6 is a standing recipient on **every** file; whoever holds the sealed cold copy and its passphrase can decrypt everything (the disclosed escrow, §1.2/§6.3). Bring it out **only** when no current recipient remains to re-share online (prefer §12.6 online re-share first), or for the recovery-wrap sweep (`recovery-wrap-sweep.md`). Minimize sessions; each is a custody event (§16.3).

## Prefer online re-share first (§12.6)
If **any** current recipient still holds the file's DEK, recover the user by an ordinary **online re-share** to their new key (`reshare`, §12.4b) — no D6 needed. Only when *no* current recipient remains does the file require the offline recovery key.

## Grant-old-file session (§12.7)
Preconditions: air-gapped recovery machine; the sealed cold blob `recovery_key.blob` **and its passphrase**, under whatever dual-custody control the operator applies to it; the target file's manifest + the recovery wrap exported by hand.
0. **Unseal the recovery key.** Open `recovery_key.blob` with its passphrase to recover the recovery `Identity` in air-gapped RAM (the same Argon2id seal `tools/maxsecu-setup` wrote at install — `setup.rs::seal_recovery_blob`). A wrong passphrase or a corrupt blob fails closed — abort. Hold the `EncSecretKey` only for this session; it zeroizes on drop.
1. **Unwrap** the file-version's `recovery` wrap with `recovery_priv` to recover the DEK; confirm it matches the manifest's `dek_commit` (this is exactly the `validate_recovery_wrap` check — a bad wrap here is the R26 finding; see `recovery-wrap-sweep.md`).
2. **Build the grant** with `build_recovery_grant`: re-wrap the DEK to the intended recipient's directory-verified `enc_pub` and emit the admin-signed recovery grant over the same `dek_commit` (§12.7).
3. **Note the R24 boundary.** A recovery-operator (admin-rooted) grant is honored **on download for its own version**, but is **not** carry-forward-eligible at rotation (R24/D25): if a *different* writer rotates the file before the restored user re-roots, the user needs one ordinary re-share afterward — rare and benign.
4. **Publish** the new wrap + grant to the app server; **audit** the session (who, file, recipient, who was present, timestamp) to the external sink (§16.5).
5. **Tear down:** drop/zeroize the unsealed `recovery_priv` (ends the in-RAM exposure window, §16.3); return `recovery_key.blob` to sealed cold custody. Never leave an unsealed copy on disk.

## Account recovery (§12.6) — device loss
1. Re-enroll the user's new device/key at the next **enrollment ceremony** (`enrollment-signing.md`), incrementing `key_version`.
2. For each file the user must regain: prefer online re-share from a current recipient (§12.6); fall back to a §12.7 grant-old-file session for files no one else can read.
3. Re-enrollment does **not** clear any tombstone on the user (R28) — if the user was revoked, restoration is an explicit dual-controlled **reinstatement** (`tombstone-issuance.md`).

## Cross-references
`DESIGN.md` §12.6 / §12.7 / §6.3 / §16.3 / R24(D25) / R28; `recovery-wrap-sweep.md`; `enrollment-signing.md`; `tombstone-issuance.md`; `maxsecu-admin-core::recovery`.
