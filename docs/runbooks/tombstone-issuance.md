# Runbook — Tombstone issuance (revocation / role-narrowing / reinstatement / key-compromise)

**Status:** Phase 6 (ops). Implements `DESIGN.md` §7.6 / §11.5 / §11.5a / §12.9b / D22, and `docs/sink-interface.md` §6 (issuer-side anchoring). Staleness bound: `docs/parameters.md` §5.
**Owner:** an admin (signs with their own `sig` key — **not** air-gapped, **not** a separate signing key, §16.1). Mass/`*` revokes, all reinstatements, and all key-compromise records require **dual control** (a second admin co-signature).
**Tooling:** `maxsecu-admin-core::ControlChain` (`revoke` / `reinstate` / `key_compromise`, `CoSign` for dual control); `maxsecu-client-core::sink::confirm_anchored` (the issuer confirm); the app server `POST /v1/revocations|reinstatements|key-compromise` (`api.md` §7.2).

> **The security event is anchoring, not the server append.** The control-log is one append-only hash chain whose head is anchored in the **external sink** (P6.3–P6.5). A revocation is **not effective** until the sink reflects it: clients fail closed on any served chain that doesn't reach the sink-anchored head (D22). A server that refuses to publish can only *deny*, never hide a revocation past one sink-head refresh.

## When to use which record
- **`revoke` (account-wide `*`)** — remove a user as a recipient everywhere. **Dual control.**
- **`revoke` (per-`file_id`)** — remove a user from one file's future versions. (Single admin.)
- **`revoke` with `revoked_capability` (e.g. `admin`)** — role-narrowing (fast de-admin, §7.6/§10.1); effective the moment it is anchored.
- **`reinstate`** — restore a user; **dual control**; must name the exact `(scope, scope_epoch)` it supersedes (R28) — it clears only that revocation, never a different one.
- **`key_compromise`** — cutoff for durable records under a compromised, rotated-away `(user_id, key_version)` (R27/D28); **dual control**. Durable records (genesis) are honored only if anchored *before* the cutoff's sink position.

## Steps
1. **Build the record.** Use `ControlChain` so `prev_head` is taken from the running head and the per-scope `revocation_epoch`/`reinstatement_epoch` is monotonic. For dual-control records, obtain the second admin's `CoSign` before submission (the structural gate refuses a `*`/reinstate/key-compromise without it).
2. **Submit** to the app server (`POST /v1/revocations|…`). The server verifies the **coarse** admin capability (403 otherwise), appends to `control_log`, updates its head, and **publishes the record to the external sink** (`api.md` §7.2; the sink re-derives the head `sha256(canonical(record))`). A `409` means a fork/stale-head — refetch the head and rebuild.
3. **Confirm anchoring (mandatory — §6 step 2).** Run `confirm_anchored(sink_client, custodian_pubs, log_pubs, expected_head)`; it fetches the sink head over the sink's *independent* pinned channel, verifies the anchor proof, and returns `Ok` only if the sink reflects the new head. **Treat the revocation as done only on `Ok`.** If `NotAnchored`/`Unreachable`: the server failed to publish — write to the sink directly with the admin sink-write credential (`sink-interface.md` §6.1) or escalate; the revocation is not effective until anchored.
4. **Record** the issuance + chain-head publication to the audit sink (§16.5). Alert tooling watches for unusual revoke/grant volume and tombstone-set gaps (`server::detect`, P6.6).

## Verification semantics clients apply (for reference)
A user is revoked iff a `revocation` names them (with `from_version ≤` the version in question) and **no** `reinstatement` references that revocation's `scope_epoch` per `(scope, user)` (never by comparing the two independent epoch counters, R28). Effective roles = the binding's offline ceiling **minus** role-narrowing tombstones (§7.6). Every record's issuer signature + `admin` effective role (as of the chain prefix) + dual control are re-verified client-side (`TombstoneSet::verify_authenticated`).

## Cross-references
`DESIGN.md` §7.6 / §11.5 / §11.5a / §12.9b / D22 / R28 / R27(D28); `docs/sink-interface.md` §5–§6; `docs/api.md` §7; `docs/parameters.md` §5 (staleness bound) / §4 (epochs).
