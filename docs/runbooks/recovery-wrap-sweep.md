# Runbook — Offline recovery-wrap validation sweep

**Status:** Phase 6 (ops). Implements `DESIGN.md` §16.1 / D27 / review finding R26. Cadence/coverage: `docs/parameters.md` §6.
**Owner:** the recovery-key (D6) custodian, on the air-gapped recovery machine.
**Tooling:** `maxsecu-admin-core::sweep::run_sweep` over `maxsecu-admin-core::recovery::validate_recovery_wrap` (P6.1).

> **The gap this closes.** A downloader can only check that the author *signed a recovery grant* over the right `dek_commit` (§12.5) — it **cannot** prove the recovery *wrap ciphertext* actually opens to that DEK, because only `recovery_priv` can open it. A malicious writer could sign a valid grant yet upload a bad wrap, silently breaking recoverability. This periodic offline sweep is the only thing that catches it (R26).

## Cadence & coverage (parameters §6 defaults — ⚙ confirm)
- **High-sensitivity files: 100% every 30 days.** Mark a file high-sensitivity at upload so this tier is meaningful.
- **General corpus: rolling 10% per monthly cycle** ⇒ full coverage ≈ 10 months.
- **One air-gapped session per month** (each session is a D6 custody event, §16.3).
- **New-upload spot-check:** sweep the most-recent N uploads opportunistically each session (shortens the bad-wrap window for actively-shared new files).

## Steps
1. **Assemble samples** (on the networked side, no key): for each file-version in this cycle's coverage, collect `RecoverySample { file_id, version, wrap (the wire `enc(32)‖ct`), dek_commit (from the signed manifest) }`. Export to the air-gapped machine by hand.
2. **Run the sweep** with `recovery_priv`:
   ```
   let report = run_sweep(&recovery_priv, &samples);   // report.checked, report.bad: Vec<RecoveryWrapCtx>
   ```
   `validate_recovery_wrap` HPKE-opens each wrap under the file-version's recovery context (`RECOVERY_ID`-bound), re-derives `dek_commit'`, and compares: an open failure → `WrapUndecryptable`, a commitment mismatch → `WrapMismatch`. Both land in `report.bad`.
3. **Remediate every `report.bad` entry.** For each bad file-version: have a **current holder re-wrap** the recovery recipient correctly (`reshare`/rotation, §12.4b), or if none remains, schedule an **eager recovery re-wrap**. Re-sweep the remediated versions to confirm `Ok`.
4. **Audit** the session: coverage set, `checked` count, every `bad` file-version, remediation status (§16.5). Alerting watches for files missing a valid recovery grant (`server::detect::MissingRecoveryGrant`, P6.6) as the online-side complement.
5. **Re-seal** D6.

## Notes
- Coverage/cadence trade detection latency against cold-key exposure (parameters §6) — tighten the high-sensitivity tier before the general corpus if exposure budget allows.
- This is the **only** routine reason to bring out D6 short of an actual recovery — keep it batched with any pending §12.7 grants (`recovery-session.md`).

## Cross-references
`DESIGN.md` §16.1 / D27 / §12.3a (intent-vs-wrap) / §16.3; `docs/parameters.md` §6; `maxsecu-admin-core::{sweep, recovery}` (P6.1); `recovery-session.md`.
