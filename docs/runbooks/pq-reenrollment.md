# Runbook — PQ (post-quantum) re-enrollment to the hybrid wrap

**Status:** Phase 7 (ops). Implements `DESIGN.md` §5 / §5.1 (algorithm agility, current-suite policy) / §6.1 (per-user keys) / §7.1 (binding) and the D20 PQ-hybrid commitment.
**Owner:** the D5 directory-signing custodian (ceremony) + each enrolling user, plus the D6 recovery custodian(s).

> **Scope.** Phase 7 made the **X25519 + ML-KEM-768 hybrid wrap (`Suite::V2`)** real end-to-end: identity keygen produces an ML-KEM keypair (keyblob **v2**), the directory binding carries the ML-KEM public key, and `build_upload` emits `Suite::V2` **iff both the uploader's own identity and the recovery recipient carry an ML-KEM key** — otherwise it falls back to `Suite::V1` (the classical X25519 HPKE wrap) so a partially-enrolled fleet still works (P7.5 policy). This runbook is the operational path that moves the fleet from "V1 fallback" to "V2 current," mitigating harvest-now-decrypt-later (§15.2/§15.3). **It is the only deferred piece of the PQ exit gate — the code emits V2 the moment the relevant bindings are PQ; this runbook is how those bindings come to exist.**

## Why the recovery binding goes first

Recovery is a **mandatory** standing recipient on every file (§6.3). Because V2 requires **both** the author's and the recovery recipient's bindings to carry an ML-KEM key, **no upload can be V2 until the recovery binding is PQ.** Therefore:

1. **Re-enroll the recovery (D6) recipient first.** Until that is done, every upload stays V1 regardless of how many users have PQ keys.
2. Then re-enroll users. A user with a PQ binding uploading to a PQ recovery binding gets V2; until their own binding is PQ they keep uploading V1 (fallback), which is correct and safe.

## Steps

### A. Recovery (D6) PQ re-enrollment (do this first)
1. On the air-gapped recovery machine, generate the recovery recipient's **ML-KEM-768 keypair** alongside its existing X25519 key. The X25519 `enc` key is **reused** as the hybrid classical leg (one X25519 key per binding); only an ML-KEM key is added (`crypto::hybrid::generate_mlkem_keypair`). Custody the new ML-KEM **seed** under the same K-of-N Shamir discipline as the X25519 recovery key (`recovery-key-rotation.md` / §16.3) — the seed is a recovery secret.
2. At the D5 ceremony, re-sign the recovery directory binding **carrying `mlkem_pub`** (`DirectorySigner::sign_binding(binding, Some(mlkem_pub))`). The existing D5 Ed25519 signature covers the new field for free (§7.1); the **fingerprint is unchanged** (it is over `enc_pub ‖ sig_pub` only, so the human-checkable identity does not change).
3. Publish the re-signed recovery binding to the directory **and to the KT log** (`enrollment-signing.md` step 5 — `POST /v1/dir-log/bindings` + `confirm_binding_logged`).

### B. Per-user PQ re-enrollment (rolling, after A)
4. On the user's device, generate the ML-KEM keypair and re-seal the local key blob as **v2** (the blob now stores the 64-byte ML-KEM seed after the X25519/Ed25519 secrets; a v1 blob still loads with no PQ key, P7.4). `Identity::generate()` is PQ from Phase 7 on, so a fresh enrollment is already v2; an **existing** user re-seals to add the ML-KEM key.
5. At the next D5 ceremony, re-sign the user's binding carrying `mlkem_pub`, **re-confirming the fingerprint in person** as for any binding (§12.1) — the fingerprint is unchanged, but the in-person confirm is still the enrollment gate.
6. Publish + KT-log-confirm the re-signed binding (`enrollment-signing.md` step 5).

### C. Make V2 the current suite (after the fleet is substantially PQ)
7. Once the recovery binding and the active fleet carry ML-KEM keys, V2 uploads happen automatically (P7.5 selection). Designate **V2 as the current suite** per §5.1 and turn on the §5.1 **daily update reminder** to pull stragglers forward; after the published grace period, out-of-date (V1-only) clients may be blocked from **writing** (reading still works).
8. **Lazy migration of old V1 files** rides the existing §5.1 path: a V1 file is re-encrypted to V2 on the next write by a PQ-capable writer (owner), or via the recovery key where no writer remains (§12.7). There is no mass re-encryption project unless a primitive becomes *broken* (then the §5.1 eager sweep applies) — V1 X25519 is *dated, not broken*, so lazy migration is acceptable; the harvest-now-decrypt-later residual on un-migrated V1 files is the documented reason to prioritize the sweep for high-sensitivity content.

## Mixed-fleet window (honest residual)
- During rollout, uploads are a **mix of V1 and V2** depending on whether both the author and recovery are PQ. This is correct and safe: V1 is the prior, still-supported classical wrap; V2 adds PQ protection. Download accepts both (dispatch on `manifest.alg`).
- A V2 file **re-shared** to a recipient who has not yet PQ-enrolled fails closed (`ResharePqKeyMissing`) — that recipient must re-enroll (steps 4–6) before they can be granted a V2 file. Likewise a V2 **rotation** that would carry forward a non-PQ survivor fails closed (`RotateError::PqKeyMissing`). Surface these to prompt re-enrollment.
- Harvest-now-decrypt-later is mitigated **only for V2 uploads**; V1 files (and any file uploaded before its recovery binding was PQ) remain classically-protected until migrated (step 8).

## Cross-references
`DESIGN.md` §5 / §5.1 (current suite, fleet currency, lazy/eager migration) / §6.1 / §7.1 / §12.7 / §15.2 / §15.3 / §19 (PQ-hybrid, Phase 7); `enrollment-signing.md` (KT-log publish + inclusion confirm); `recovery-key-rotation.md` / §16.3 (recovery ML-KEM seed custody); `docs/sink-interface.md` §8 (KT log).
