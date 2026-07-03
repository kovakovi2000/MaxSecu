# Security Review Sign-off — T6 Shamir K-of-N Recovery-Key UI

**Status: PASS** — no Critical / High / Medium findings remain (the one Medium found in review, M-1, was fixed + regression-tested before sign-off).
**Branch:** `feat/t6-shamir-recovery-ui` (`6d2cce8..HEAD`).
**Date:** 2026-07-03.
**Spec:** `docs/superpowers/specs/2026-07-02-shamir-recovery-ui-design.md` (§0 locked decisions, §2 grounding, §6 reconstruct flow, §11 checklist).
**Plan:** `docs/superpowers/plans/2026-07-02-t6-shamir-recovery-ui.md`.

## Scope

An offline (air-gapped), zero-network Tauri UI + command/DTO layer on top of the
**already-shipped** Phase-7 `crypto::shamir` + `admin_core::recovery::{split,reconstruct}_recovery_key`.
Split the 32-byte X25519 recovery scalar into k-of-n Shamir shares; later reconstruct from ≥k
shares. **Zero new cryptography except one small Argon2id+AEAD sealed-file companion**
(`admin-core::recovery_seal`, a faithful mirror of `client-core::keyblob`). The recovery key is the
system's escrow key (whoever reconstructs it can decrypt every file), so the design keeps the whole
key inside Rust state (opaque `ceremony_handle`, never crossing the Tauri seam) and gates
reconstruction "success" on a **real recovery-wrap proof** (`validate_recovery_wrap`), never on
`combine` returning `Ok`.

Implemented across 14 tasks (T1–T14), each landed via TDD with a two-stage subagent review (spec
compliance, then code quality). This document is the T14 holistic security sign-off.

## Review method

- Per-task: fresh implementer + independent spec-compliance review + independent code-quality
  review, with fix loops, for T1–T13.
- Holistic: adversarial read of the entire feature diff (`6d2cce8..HEAD`) against spec §11 plus
  cross-cutting analysis (the new sealed-file crypto, handle randomness, the seam boundary, UI XSS,
  panic surface), verifying against the actual code.
- Verification: `client-app` lib **249 passed / 0 failed**; command-layer e2e `recovery_custody_e2e`
  **5/5** (all spec §12 scenarios, real crypto); UI **67/67** unit + **57/57** a11y structural checks;
  the new sealed-file `recovery_seal` **8/8**.

## Spec §11 checklist — all PASS

| # | Requirement | Result | Key evidence |
|---|---|---|---|
| 1 | Whole secret only in `Zeroizing`/zero-on-drop, minimum span, never disk/log/Debug | PASS | `EncSecretKey(Zeroizing<[u8;32]>)`; `CeremonySessionInner::reset()`+`Drop` zeroize share bodies + clear the key map; share bodies wiped after encode; no `println!`/`log`/`dbg!` of the scalar; `CeremonySessionInner` derives no `Debug`. |
| 2 | No `Debug` dumps share/secret bytes | PASS | Hand-written redacting `Debug` on `SplitRecoveryKeyResponse` (shares→count), `AddShareRequest` (share_text), `SplitRecoveryKeyRequest` (passphrase), `ParsedShare` (body→len); tested. |
| 3 | Any `k-1` shares reveal nothing (inherited) | PASS | No path concatenates/caches/persists shares below `k`; they accumulate only in `CeremonySession` and are combined solely by the shipped `reconstruct_recovery_key`; `save_recovery_share` writes ONE operator-chosen share on explicit request; the UI never redisplays an accepted share. |
| 4 | Checksum is UX-only | PASS | Documented as a transcription check, not authenticity; no path treats "checksum passed" as security; success is gated on the real-wrap proof. |
| 5 | Reconstruct fail-closed on all error cases, no panic | PASS (after M-1 fix) | Exhaustive non-oracle `RecoveryError`→code mapping; below-`k`/empty fail closed; **M-1** (a reachable slice-panic in `parse_hex` on non-ASCII prove input) was found and **fixed** (`is_ascii()` guard + regression test). |
| 6 | UI success ONLY from a real proof (load-bearing) | PASS | `verified:true`/green state set ONLY inside `if (resp.verified)` from `prove_reconstructed_key`; reaching the prove step sets `proveVerified=false` first; backend `verified = validate_recovery_wrap(...).is_ok()`, never from `combine`/reconstruct Ok. |
| 7 | No network in the module (grep-gate) | PASS | `recovery_custody.rs` imports only base64/admin-core/crypto/tauri/zeroize/`std::fs`; the `module_source_performs_zero_network_io` test is non-vacuous (concat!-fragmented needles; verified in review to fail if a `use hyper;` is added). |
| 8 | `discard`/exit zeroizes | PASS | `discard_ceremony_session`→`reset()` zeroizes shares + clears the key map; `Drop` calls `reset()`; the reconstruct screen calls `discard` on `disconnectedCallback`; tested. No secret survives a restart. |
| 9 | Re-split invalidation in UI copy | PASS | Stated in the split screen's custody guidance, the setup note, and the done summary (D-F). |

## Cross-cutting checks

- **`recovery_seal` (the one new crypto piece):** a faithful mirror of `keyblob::seal`/`open` — same
  Argon2id KDF (floor enforced), same AES-256-GCM, 45-byte versioned `"MXRS"` header bound as AEAD
  AAD, fresh random salt+nonce per seal, wrong-passphrase/tamper fail-closed (no partial plaintext),
  sealed bytes never contain the plaintext scalar, all transients `Zeroizing` incl. a DSE-defeating
  `zeroize()` on the stack scalar. No novel/weakened crypto, no nonce/salt reuse.
- **`ceremony_handle`** is 16 bytes from the OS CSPRNG (`random_array`/`getrandom`), hex-encoded — not
  a predictable counter/timestamp.
- **The reconstructed key never crosses the seam:** `ReconstructResponse` = `{ceremony_handle, label}`
  only; no command returns/serializes an `EncSecretKey`.
- **File-I/O helpers** (`save_recovery_share`/`read_recovery_share_file`/`record_split_ceremony`) are
  local `std::fs` only with sanitized errors (no path/OS detail leaked); the ceremony-log DTO carries
  no share/secret field by construction.
- **UI XSS:** operator-controlled strings reach the DOM via `textContent`/`.value`; `innerHTML` is used
  only with static templates; shares are never redisplayed after entry.

## Findings

- **Critical:** none.
- **High:** none.
- **Medium:** **M-1 (FIXED)** — `parse_hex` (`commands/recovery_custody.rs`) sliced `&s[2*i..2*i+2]`
  after only a byte-length check, so a non-ASCII operator-typed `file_id_hex`/`dek_commit_hex` of the
  right byte length (a multi-byte char straddling an even index) could panic the load-bearing
  `prove_reconstructed_key` command. No secret exposure and no proof-gate bypass was possible.
  **Resolved** in commit `bb6992a`: an `is_ascii()` guard (hex is ASCII by definition) makes the
  slicing always land on char boundaries; a regression test (`non_ascii_hex_input_fails_closed_without_panicking`)
  drives a 32-byte non-ASCII input and asserts a fail-closed `bad_file_id` instead of a panic.
- **Low:** none.
- **Informational:** `EncSecretKey::expose_bytes()` returns a bare `[u8;32]` by value (an un-zeroized
  return-slot temporary until moved into `Zeroizing` at the call site) — the pre-existing, audited
  codebase pattern (identical in `keyblob`/`recovery`), out of scope for T6.

## Verdict

**PASS.** The feature is offline/zero-network by construction (grep-gated), keeps the whole recovery
secret in zero-on-drop types for the minimum span and out of the Tauri seam/events/logs, gates
reconstruction success on a real cryptographic proof (never on `combine` alone), adds no novel or
weakened cryptography (the sealed-file companion faithfully mirrors the audited `keyblob`), and is
fail-closed on every error path. The one Medium finding (M-1, a panic-on-bad-input, no secret impact)
was fixed and regression-tested before sign-off. Cleared for merge into `main`.
