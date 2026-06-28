# Runbook — Enrollment signing ceremony

**Status:** Phase 6 (ops). Implements `DESIGN.md` §12.1 / §7.1 (D5, D9). Cadence: `docs/parameters.md` §7 (**daily** default).
**Owner:** the directory-signing-key (D5) custodian, on the air-gapped ceremony machine.
**Tooling:** `maxsecu-admin-core` — `DirectorySigner` (`sign_enrollment`, fingerprint-gated; `sign_binding`), run via the air-gapped ceremony CLI (`stack.md` §1.6).

> **What this ceremony establishes.** The directory binds `username → (enc_pub, sig_pub, key_version, roles)` with the offline D5 signature (§7.1). The human-checked **fingerprint** (`SHA-256(canonical(enc_pub‖sig_pub))`, full 256-bit, base64/QR) is what binds the *real person* to the *real key* — not the `user_id`, which the untrusted server assigns (D9). A binding signed without a true in-person fingerprint match reintroduces the MITM the whole directory exists to stop.

## Preconditions
- Air-gapped ceremony machine; D5 private key present only here (sealed custody between ceremonies, §16.3).
- The enrollee is **physically present** with their device showing its own freshly-generated fingerprint.
- The candidate binding (the enrollee's `enc_pub`, `sig_pub`, requested `roles`, `key_version`) exported from the enrollee device to the ceremony machine by hand (USB), never over the network.

## Steps
1. **Confirm the fingerprint in person.** Compare the full fingerprint shown on the enrollee's device against the candidate binding on the ceremony machine — side-by-side or QR scan (base64 is case-sensitive; never read aloud, never compare a prefix). Roles (`{user}` vs `{user, admin}`) are confirmed here too — admin is an offline-signed capability ceiling (§10.1).
2. **Sign.** `DirectorySigner::sign_enrollment` is **fingerprint-gated**: it refuses (`CeremonyError::FingerprintMismatch`) unless the supplied expected fingerprint equals the binding's. Pass the fingerprint you just confirmed — do not bypass the gate.
3. **Record** the ceremony event (who, fingerprint match=YES, key_version, roles, timestamp) for the external sink/audit (§16.5). A mismatch or refusal is itself logged.
4. **Publish** the signed binding + `directory_signature` to the app server out of band (the server has no binding-publish endpoint by design — it is loaded via the ceremony publish, matching `docs/api.md`).
5. **Re-seal** D5; the machine returns to air-gapped custody.

## Rotation / re-enrollment
A returning user with a new device/key re-enrolls with an **incremented `key_version`** (§16.4 user-key rotation). Note: re-enrollment does **not** clear any tombstone on that `user_id` — tombstones key on the stable `user_id` (R28); restoring a revoked user is the *reinstatement* ceremony (`tombstone-issuance.md`), not re-enrollment.

## Failure handling
- Fingerprint mismatch → **do not sign**; investigate (wrong device, MITM attempt, stale export). Re-run only after a clean in-person match.
- Published binding rejected by clients (rollback: lower `key_version`) → the client TOFU memory caught a stale binding; ensure the new `key_version` strictly exceeds the prior (§7.5).

## Cross-references
`DESIGN.md` §12.1 / §7.1 / §7.5 (TOFU) / §10.1 (roles); `docs/parameters.md` §7 (cadence) / §4 (`not_after` 365d, `key_version` monotonic); `enrollment` tooling in `maxsecu-admin-core`.
