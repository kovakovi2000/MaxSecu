# Runbook — Emergency directory-signing-key (D5) rotation

**Status:** Phase 6 (ops). Implements `DESIGN.md` §16.4 (emergency D5 rotation) / §7.2 step 3 (TOFU) / §7.3 (pinning) / §7.4 (equivocation).
**Owner:** the D5 custodian + the release operator (a new pinned client release is part of the response).

> **Threat & bound.** A stolen D5 can forge a directory binding and MITM **future** uploads to a *not-yet-seen* key — but **not** silently where a wrapper previously wrapped to the victim (the TOFU key-change warning surfaces it, §7.2 step 3), and **not** any already-uploaded file. The damage window is **detection → cutover**; keep it short.

## Trigger
Any of: a TOFU key-change alarm (§7.2 step 3), a directory-history/transparency-log divergence alert, or known theft/loss of the D5 device.

## Steps (from §16.4)
1. **Cut over fast.** Ship a **new signed client release** (follow `release-signing.md`) that **pins the NEW D5 public key and drops the OLD one immediately** — accept that bindings must be re-signed; do **not** run a long overlap that keeps the compromised key trusted.
2. **Re-sign legitimately.** At an air-gapped enrollment ceremony (`enrollment-signing.md`), re-sign every current identity binding under the new D5, **re-confirming fingerprints in person** for anything suspect (§12.1/D9).
3. **Hunt forgeries.** Review the directory history for bindings issued under the old key during the exposure window; notify affected users to re-verify. Users who previously wrapped to a victim are already seeing TOFU key-change prompts (§7.2 step 3).
4. **Cross-publish** the new pinned D5 public key (vendor site / release notes, §7.3) so users and auditors confirm it out of band.
5. **Record** the rotation + every re-sign to the external audit sink (§16.5).

## Notes
- D5 and D6 should live on **separate** cold devices: co-locating means one vault theft unlocks *forge-future* (D5) **and** *decrypt-all* (D6) (§3.1 M-5). If D5 theft is suspected and D6 was co-located, treat D6 as compromised too (`recovery-key-rotation.md`).
- First-contact equivocation that the TOFU warning can't cover stays open until the Phase-7 key-transparency log (§7.4) — this runbook is the v1 response.

## Cross-references
`DESIGN.md` §16.4 / §7.2–§7.4 / §3.1 (M-5); `release-signing.md`; `enrollment-signing.md`; `recovery-key-rotation.md`.
