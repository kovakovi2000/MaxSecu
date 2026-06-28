# Runbook — Recovery-key (D6) rotation

**Status:** Phase 6 (ops). Implements `DESIGN.md` §16.4 (recovery-key rotation) / §16.3 (custody) / §6.3.
**Owner:** the D6 custodian, on the air-gapped recovery machine.

> **Scope.** D6 is the all-files escrow (§1.2/§6.3). Rotation is a deliberate, expensive **re-wrap project**, not an emergency action — plan it. Trigger it on suspected D6 compromise/theft, on a custody change, or as scheduled hygiene.

## Steps (from §16.4)
1. **Generate** a new D6 keypair (X25519) on the air-gapped machine, then **immediately split the new private key K-of-N** for custody: `split_recovery_key(&new_recovery_priv, k, n)` → one `Share` per custodian (the scalar is exposed only transiently on the offline device and zeroized; §16.3). Choose `k`/`n` per policy (e.g. 3-of-5). Distribute one share to each custodian under dual-custody witness. **No whole cold copy of the new key is retained.**
2. **Reconstruct the OLD key (threshold)** for the re-wrap work: `k` of the old custodians convene and `reconstruct_recovery_key(k, &old_shares)` rebuilds the old `recovery_priv` in air-gapped RAM (or recover DEKs via current holders).
3. **Re-wrap the recovery recipient across files** as a background project: for each file-version, recover the DEK with the reconstructed **old** `recovery_priv` (or via a current holder) and add a fresh `recovery` wrap to the **new** recovery public key. This reuses the §12.7 re-wrap path (`build_recovery_grant`-style re-wrap) and the sweep machinery to track coverage (`recovery-wrap-sweep.md`).
4. **Validate** new wraps with the **new** `recovery_priv` (threshold-reconstructed from the new shares) via `run_sweep` before retiring the old key — confirm every re-wrapped version opens to its committed DEK (R26 discipline). Zeroize both reconstructed keys when the work is done.
5. **Retire the old key** only once coverage is complete and validated; have each old custodian **destroy their old share** under dual-custody witness (§16.3) — no whole old key need ever be reassembled to retire it.
6. **Re-pin** the new recovery public key as the standing directory recovery entry (verified like any binding, §7.2) so new uploads wrap to it.
7. **Audit** the rotation project (coverage, validation, share distribution, old-share destruction) to the external sink (§16.5).

## Custody (§16.3)
- D6 is **split K-of-N across custodians** (Shamir, Phase 7 / P7.7 — `split_recovery_key`/`reconstruct_recovery_key`, §16.3/§19): each share is kept cold, sealed, dual-custody, access-logged. **No single share — or any `k-1` shares — is total.** The key exists whole only transiently in air-gapped RAM during a session/rotation (documented residual, §16.3) and is zeroized after.
- Keep D5 and D6 on **separate** cold devices (§3.1 M-5). If a single vault that held both is compromised, rotate **both** (this runbook + `emergency-d5-rotation.md`).

## Cross-references
`DESIGN.md` §16.4 / §16.3 / §6.3 / §3.1 (M-5) / §19 (Shamir, Phase 7); `recovery-wrap-sweep.md`; `recovery-session.md`; `emergency-d5-rotation.md`.
