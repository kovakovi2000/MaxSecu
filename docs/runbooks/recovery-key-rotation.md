# Runbook — Recovery-key (D6) rotation

**Status:** Phase 6 (ops). Implements `DESIGN.md` §16.4 (recovery-key rotation) / §16.3 (custody) / §6.3.
**Owner:** the D6 custodian, on the air-gapped recovery machine.

> **Scope.** D6 is the all-files escrow (§1.2/§6.3). Rotation is a deliberate, expensive **re-wrap project**, not an emergency action — plan it. Trigger it on suspected D6 compromise/theft, on a custody change, or as scheduled hygiene.

## Steps (from §16.4)
1. **Generate** a new D6 keypair (X25519) on the air-gapped machine.
2. **Re-wrap the recovery recipient across files** as a background project: for each file-version, recover the DEK with the **old** `recovery_priv` (or via a current holder) and add a fresh `recovery` wrap to the **new** recovery public key. This reuses the §12.7 re-wrap path (`build_recovery_grant`-style re-wrap) and the sweep machinery to track coverage (`recovery-wrap-sweep.md`).
3. **Validate** new wraps with the **new** `recovery_priv` via `run_sweep` before retiring the old key — confirm every re-wrapped version opens to its committed DEK (R26 discipline).
4. **Retire the old key** only once coverage is complete and validated; destroy the old cold copies under dual-custody witness (§16.3).
5. **Re-pin** the new recovery public key as the standing directory recovery entry (verified like any binding, §7.2) so new uploads wrap to it.
6. **Audit** the rotation project (coverage, validation, old-key destruction) to the external sink (§16.5).

## Custody (§16.3)
- Keep D6 cold, sealed, dual-custody, access-logged; a **sealed encrypted backup in separate physical custody**. The Shamir/threshold split is the prioritized Phase-7 hardening (§19) so no single cold copy is total.
- Keep D5 and D6 on **separate** cold devices (§3.1 M-5). If a single vault that held both is compromised, rotate **both** (this runbook + `emergency-d5-rotation.md`).

## Cross-references
`DESIGN.md` §16.4 / §16.3 / §6.3 / §3.1 (M-5) / §19 (Shamir, Phase 7); `recovery-wrap-sweep.md`; `recovery-session.md`; `emergency-d5-rotation.md`.
