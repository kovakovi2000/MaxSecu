# Runbook — Release signing & signed/transparency-logged update publication

**Status:** Phase 6 (client integrity & ops, C2). Implements `DESIGN.md` §8 (controls 2 & 4, D1) and `docs/stack.md` §1.5/§5.2.
**Owner:** the release operator (holds the offline code-signing cert + the offline update-manifest signing key).
**Pairs with:** `scripts/reproducible-build.sh` (P6.9), `scripts/sign-release.ps1` (this runbook), `crates/client-core/src/update.rs` (`verify_update`, the client side, P6.8), `docs/reproducible-builds.md`.

> **Goal.** Ship an update that a client can prove is (a) the exact audited source (reproducible build), (b) signed by the real release key (Authenticode + manifest signature), and (c) publicly logged so a *targeted* backdoor served to one victim is detectable (transparency log). `verify_update` fails closed unless all three hold.

---

## 0. Secrets posture (read first)
- The **Authenticode certificate** and the **update-manifest signing key (Ed25519, pinned in clients as a `release_pub`)** are **offline / HSM-backed**. Private keys never touch a networked machine, the repo, CI, or logs (`DESIGN.md` §16.6).
- `scripts/sign-release.ps1` addresses the cert **by thumbprint only** and refuses an inline PFX/password (a 40-hex guardrail). Prefer a USB/HSM token so the private key never leaves it.
- The transparency-log **submission** credential is separate again. A compromise of any one of these must not, by itself, let an attacker ship an accepted update.

---

## 1. Reproducible build
1. Check out the exact release tag; confirm `rust-toolchain.toml` (1.96.0) and `Cargo.lock` are the release pins.
2. Build the reproducible artifact of record (Linux musl, `docs/reproducible-builds.md` §2) and/or run the determinism gate:
   ```bash
   ./scripts/reproducible-build.sh <crate> <bin>      # must print "REPRODUCIBLE: identical SHA-256 ..."
   ```
3. Record `artifact_sha256` (the published hash). This is the value that must agree across the binary, the manifest, and the transparency log.

## 2. Authenticode-sign the Windows client
On the offline signing host (Windows SDK `signtool` present, cert in the store):
```powershell
pwsh scripts/sign-release.ps1 -File .\maxsecu-client.exe -Thumbprint <CERT_THUMBPRINT> -TimestampUrl <rfc3161-url>
```
The script signs (SHA-256, RFC-3161 timestamped) and **verifies** (`signtool verify /pa`); it prints the signed binary's `artifact_sha256`. Abort the release if verify fails.

## 3. Build & sign the update manifest
Construct the `UpdateManifest` the client checks (`crates/client-core/src/update.rs`):

| Field | Value |
|---|---|
| `version` | the new build's monotonic version (strictly greater than the prior release) |
| `min_version` | the lowest prior version permitted to take this update directly |
| `artifact_sha256` | the §1/§2 hash of the **exact** released artifact |

Sign `signing_input(labels::UPDATE_MANIFEST, version‖min_version‖artifact_sha256)` with the **offline update-manifest key** (Ed25519). The resulting `manifest_sig` and the manifest are published together. (The signing key's public half is a pinned `release_pub` baked into the clients, like the D5 directory root, §7.3.)

## 4. Submit to the transparency log
1. Submit the manifest's leaf — `manifest_signing_bytes` (the same bytes signed in §3) — to the append-only transparency log.
2. Obtain the log's **signed checkpoint** `{tree_size, root}` and the **Merkle inclusion proof** (`index`, `path`) for the leaf. These populate the client's `LogInclusion`.
3. The log's public key is a pinned `log_pub` in clients (independent trust domain from the sink's custodian/log keys, P6.2/P6.4). A *targeted* build that is never logged cannot produce a valid inclusion proof ⇒ `verify_update` → `NotLogged` (fail closed).

> **Interim note (Phase-6 deferral).** A real third-party transparency log / notary is an ops dependency deferred behind this interface (like the WORM sink vendor). Until it is provisioned, the in-repo append-only sink's transparency machinery (`crates/sink-server`, `crypto::merkle`) is the reference implementation of the proof shapes; the client verification (`verify_update`) is complete and pins the production `log_pub` when the live log is stood up.

## 5. Publish & client verification
- Publish: the signed binary, the manifest + `manifest_sig`, the `LogInclusion`, and the `artifact_sha256` in the release notes.
- Each client, before applying: downloads the artifact, computes its SHA-256, and calls
  `verify_update(manifest, manifest_sig, inclusion, release_pubs, log_pubs, current_version, artifact_sha256)`.
  It applies the update only on `Ok(Verified)` — fail-closed on downgrade, bad signature, missing log inclusion, or artifact-hash mismatch.
- In-person delivery of the **first** install removes the bootstrap MITM (`DESIGN.md` §8); subsequent updates ride this verified path.

## 6. On verification failure / divergence
A failed `signtool verify`, a non-reproducible hash, or a transparency-log divergence is a **supply-chain alarm**: halt the release, do not publish, and follow the emergency posture (`DESIGN.md` §16.4). A divergence between the published hash and the logged hash means the two pipelines disagree — treat as compromise until proven otherwise.

---

## Cross-references
`DESIGN.md` §8 (D1 client integrity) / §16.4 (emergency runbook) / §16.6 (secrets); `docs/stack.md` §1.5 / §5.2; `docs/reproducible-builds.md`; `crates/client-core/src/update.rs` (P6.8); `crates/sink-server` + `crates/crypto/src/merkle.rs` (transparency-proof shapes, P6.2–P6.4).
