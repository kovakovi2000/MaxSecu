# Security Review Sign-off — T4 Post-Upload Multi-Recipient Sharing

**Status: PASS** — no Critical / High / Medium findings.
**Branch:** `feat/t4-multi-recipient-sharing` (`e3ac25b..HEAD`).
**Date:** 2026-07-03.
**Spec:** `docs/superpowers/specs/2026-07-02-multi-recipient-sharing-design.md` (§0 locked decisions, §4 command flow, §7 revocation interplay, §9 checklist).
**Plan:** `docs/superpowers/plans/2026-07-02-t4-multi-recipient-sharing.md`.

## Scope

Lets any wrap-holder of an already-uploaded file extend read access to N directory-verified
recipients from the running app — no re-upload, no ceremony. New client-app command
`reshare_file` (plus display-only `resolve_recipient` / `list_file_recipients`) built on the
already-tested `client-core::build_reshare` primitive and the existing
`POST /v1/files/{id}/wraps` endpoint. The genuinely new subsystem is the **first
authenticated `TombstoneSet` path in the shipped client**, whose revocation anchor is sourced
**out-of-band from the pinned sink** (spec §0 D-OQ1), bypassing the untrusted app server.

Implemented across 14 tasks (T1–T14), each landed via TDD with a two-stage subagent review
(spec compliance, then code quality) before integration; this document is the T14 holistic
security sign-off over the fully-integrated branch.

## Review method

- Per-task: fresh implementer + independent spec-compliance review + independent code-quality
  review, with fix loops, for T1–T13.
- Holistic: adversarial read of the entire feature diff (`e3ac25b..HEAD`) against the spec §9
  checklist plus cross-cutting analysis, verifying against the actual code (not summaries).
- Verification: `client-app` lib suite **175 passed / 0 failed**; UI **60/60** unit + **44/44**
  a11y structural checks; e2e `reshare_e2e` **8/8** over real TLS + real D5 directory ceremony +
  real control-log + real out-of-band sink (no mocked crypto); full `client-e2e` suite
  regression-clean (only the pre-existing `#[ignore]` live-Tor test skipped).

## Spec §9 checklist — all PASS

| # | Requirement | Result | Key evidence |
|---|---|---|---|
| 1 | Only DTOs cross the Tauri seam (no `WrapOut`/`Dek`/`Identity`/`TombstoneSet`/key bytes) | PASS | `commands/share.rs` command signatures + `dto.rs:274-309` carry only usernames/hex ids/bools/sanitized codes; `Dek`/`WrapOut`/`TombstoneSet` are built and dropped inside `reshare_inner`/`run_reshare_batch`. |
| 2 | Every recipient D5-verified at share-time (TOCTOU re-verify, not cached) | PASS | `build_reshare` reached only with `recipient_enc_pub`/`recipient_mlkem_pub` from `directory::resolve_recipient` run **inside** the per-recipient loop; the picker's `resolve_recipient` command result is display-only and never fed to the wrap. |
| 3 | Real, sink-anchored, chain-verified `TombstoneSet` (not the server's advisory head) | PASS | `TombstoneSet::verify_authenticated(records, anchored_head, issuer)` where `anchored_head` = `sink::fetch_anchored_head` over a separate pinned TLS 1.3 channel with an offline-pinned custodian/transparency allowlist; record fetch (`/v1/revocations`) and anchor both fail **closed**. |
| 4 | Owner/holder-only in practice (own self-wrap; authenticated id; requested file_id) | PASS | `recover_own_dek` binds `WrapContext` to the **requested** `file_id` and `recipient_id = Id(my_id)`, where `my_id = resolve_my_user_id(authenticated session username)`; a non-holder fails the unwrap / `dek.commit()` check before any POST (`scenario7`). |
| 5 | No plaintext / DEK / wrap in any `SharePhase` event or log line | PASS | `SharePhase` carries only `file_id`/`username`/`ok`/`code`/counts; no `println!`/`log`/`tracing`/`dbg!` in the production path; all `UiError`s are static sanitized strings; every `unwrap`/`expect` is `#[cfg(test)]`. |
| 6 | Fail-closed on every verification step | PASS | All batch-wide prerequisites `?`-propagate to a whole-command `Err` before any POST; per-recipient failures fail closed to `ok:false` with a sanitized code. The **only** fail-open path is `list_file_recipients` (UX duplicate-awareness), which never gates a wrap. |
| 7 | Per-recipient isolation, never drops a row | PASS | `run_reshare_batch` emits exactly one `ReshareOutcomeDto` per input username via the centralized `push_outcome` + `continue`; unit-proven (`mixed_batch...`, `post_failure_is_isolated...`) + e2e `scenario5`. |
| 8 | Genuine idempotency | PASS | Server `Store::add_wrap` replaces the row; e2e `scenario2` shares twice → exactly one recipient row. |
| 9 | V2/PQ path exercised, no silent classical downgrade | PASS | `build_reshare` branches on `manifest.alg`; a V2 file to a non-PQ recipient returns `ResharePqKeyMissing` (no fallback branch exists); e2e `scenario6` asserts `pq_key_missing` **and** that no wrap row is created for the classical recipient. |
| 10 | `reauth`/`ConnectLock` + identity-borrow discipline | PASS | One `reauth` per batch; the `!Clone` `Identity` is borrowed under the session lock only for the synchronous `recover_own_dek` and each synchronous `build_reshare`, with the guard dropping before every `.await` — the borrow structurally cannot span an await. |

## Cross-cutting checks

- **Server-controlled values cannot redirect the DEK or forge a grant.** Consumed manifest
  fields (`version`/`alg`/`dek_commit`) are constrained by the AEAD-bound unwrap + commit check
  in `recover_own_dek`; grants are signed over the **requested** `file_id`, not `manifest.file_id`.
- **UI XSS:** every dynamic value (`username`/`code`/`message`/`fingerprint`) reaches the DOM via
  `textContent`/`setAttribute`; the only `innerHTML` uses are static templates with no
  interpolation. `<state-badge>` renders its label via `textContent`.
- **Sink pins/TLS:** independent socket + own pinned root, TLS 1.3-only, custodian allowlist
  required (≥1); `verify_anchor_proof` uses `any_key_verifies`, so an empty allowlist authorizes
  no one.
- **Grant signing:** `granted_by` is the authenticated caller; the grant commits
  `file_id`/`version`/`dek_commit` consistent with the wrap — no grant can open a different
  file's DEK.
- **Panic surface:** no `unwrap`/`expect`/panic reachable from server-controlled input in the
  reshare path.

## Findings

- **Critical:** none.
- **High:** none.
- **Medium:** none.
- **Low:** none.
- **Informational (accepted — non-blocking):**
  1. `resolve_my_user_id` does not assert the served binding's `username` equals the requested
     username. Not exploitable — a wrong `my_id` makes `recover_own_dek` fail closed and a grant
     signed with the wrong `granted_by` fails the recipient's grant-sig verification. Accepted as
     a possible future defense-in-depth check.
  2. The reshare flow decodes the manifest but does not independently re-verify `manifest_sig`.
     Safe by construction (fields are cryptographically pinned downstream). **Addressed** by an
     inline explanatory comment in `commands/share.rs` documenting the intentional decision.
  3. The e2e drives the public product primitives (`build_reshare`, `resolve_recipient`,
     `fetch_anchored_head`, `TombstoneSet`, `load_sink_pins`) rather than the `reshare_file`
     Tauri command (which needs a `Wry` `AppHandle`; its orchestration is `pub(crate)`) — the
     same established pattern as `upload_e2e.rs`. The command's batch-loop/borrow orchestration is
     unit-tested in `commands/share.rs`. Coverage is strong; accepted.

## Verdict

**PASS.** The feature is fail-closed on every trust boundary, sources its revocation anchor
out-of-band from the pinned sink (independent of the untrusted app server), performs share-time
D5 re-verification (TOCTOU-safe), keeps all key material off the Tauri seam and out of
events/logs, enforces the PQ path with no silent downgrade, and isolates per-recipient failures
without dropping rows. Cleared for merge into `main`.
