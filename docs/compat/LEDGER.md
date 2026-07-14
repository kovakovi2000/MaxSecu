# Compat ledger

> **The rule:** *Every upgrade must keep existing users' access intact — account/login, keys, and already-uploaded data. No change may force a re-enroll, re-key, re-upload, re-share, or reset.*

The **append-only** record of every intentional change to a frozen surface (see [`CHECKLIST.md`](CHECKLIST.md) for the eleven of them).

**Append only.** Do not edit or delete an existing entry — including the ones that record mistakes. An entry that says "we broke this" is the reason it does not happen twice.

When you change a format, you write an entry here *and* you keep the old fixture *and* you keep a read path that still opens it. The pre-push hook warns when a frozen surface moves without a ledger entry; the corpus lock and the golden tests are the hard gate.

## Entry template

Copy this block, fill it in, append it to the bottom.

```markdown
## YYYY-MM-DD — <surface> — <one-line summary>

| | |
|---|---|
| **Commit** | `<sha>` |
| **Surface** | <which of the eleven frozen surfaces> |
| **What changed** | <the format delta, in bytes/fields> |
| **Why it is backward compatible** | <the argument, not the assertion> |
| **How OLD data is still read** | <the concrete read path: file:function> |
| **Fixture that proves it** | `compat/fixtures/<area>/<name>` (old) + `<name>` (new) |
| **Automatic on upgrade?** | <yes + how; or the migration id> |
```

---

## 2026-07-14 — client on-disk state (#11) — KNOWN WEAK SPOT: `staging/<file_id>/record.json` is unversioned

| | |
|---|---|
| **Commit** | *(none — recorded, not fixed; frozen as-is by the compat gate)* |
| **Surface** | #11, client on-disk state — `client-app/upload_staging.rs` |
| **What changed** | Nothing. This entry records a **liability**, so that the next person to touch it cannot claim they did not know. |
| **The problem** | A resumable upload's `staging/<file_id>/record.json` is **plain, unversioned, unsealed JSON**. It carries no magic bytes and no version tag, so there is no way for a future reader to tell which shape it is looking at, and no way to reject an unknown one. Every other access-critical format in the system fails closed on an unknown version; this one cannot even ask the question. |
| **Blast radius** | An in-flight resumable upload of a large file. A user who is mid-upload across an upgrade loses that upload's staged state — they must re-upload. That is a "re-upload", which is exactly what the rule forbids. |
| **Why it is frozen as-is** | The gate pins the CURRENT shape with a golden fixture, so today's records keep opening. Retro-versioning it is a change to the format, which is the very thing that needs the version tag first. |
| **What the next change to it MUST do** | Add a version tag **before** changing anything else. Concretely: accept the current tag-less shape as v0 forever (a compat-read path), write the new shape with an explicit version, fail closed on unknown versions, add a fixture for the new shape, and append an entry here. Do not "just add a field" — a tag-less format cannot safely gain a required one. |
| **Fixture** | `compat/fixtures/client-state/` (staging record — frozen at its current, unversioned shape) |

---

## 2026-07-11 — directory binding (#5/#10) — HISTORICAL BREAK (pre-gate): `2a626d6` forced a re-enroll

**This entry records a rule violation that already shipped.** It predates the gate. It is here so it is never repeated, and it is the reason the gate exists.

| | |
|---|---|
| **Commit** | `2a626d6` — "PQ-enrollment publish fix" |
| **Surface** | Directory binding / enrollment (`server/http.rs` `RegisterReq`, client `register.rs`) |
| **What changed** | User enrollment (`POST /v1/users`) never published the client's ML-KEM key into the signed directory binding: the client omitted `mlkem_pub_b64` and the server's `RegisterReq` had no such field, hard-coding `mlkem_pub: None`. Every binding was therefore classical while uploads had already moved to V2 hybrid wraps. The fix added the field on both sides. |
| **Why it was NOT backward compatible** | **It was not retroactive.** New enrollments got a hybrid binding; the bindings of everyone who had *already* enrolled were never republished and stayed classical. Every V2 reshare to them failed with `pq_key_missing`. |
| **Cost to users** | **Every already-enrolled recipient had to RE-ENROLL.** A forced re-enroll is a forbidden outcome under the rule. |
| **What should have happened** | Either (a) republish existing bindings automatically as part of the upgrade — a migration, not a manual step — or (b) keep a working reshare path to a classical binding so that old recipients kept receiving shares while their bindings caught up. Either would have satisfied the rule. Both were skipped because nothing was watching. |
| **Why nothing caught it** | Every test round-tripped: it sealed and opened with the same code, so both sides drifted together and the suite stayed green. There was no test that took an OLD binding and asked whether TODAY's code could still reshare to it. |
| **What now catches it** | The interop matrix (`crates/compat/tests/interop_matrix.rs`): every frozen `Suite` (V1 classical, V2 hybrid) × every frozen keyblob version (v1 classical, v2 PQ) must still unwrap, verify and **reshare**. It reproduces the break as its real symptom — *an old classical binding can no longer participate in a reshare* — not as a missing JSON field. |
| **Status** | Not retro-fixed; the affected recipients have already re-enrolled. Out of scope by decision (design spec §8). Recorded permanently. |

---

## 2026-07-14 — deployment env (systemd unit) — the SECOND fresh-install-only hole, closed

| | |
|---|---|
| **Commit** | `feat/compat-gate` |
| **Surface** | Deployment environment — `scripts/install-server.sh`, `scripts/upgrade-server.sh`, `crates/portable-server/src/config.rs` |
| **The hole** | `install-server.sh` writes the unit's `Environment=` lines; `upgrade-server.sh` never rewrote that unit (it only appended a `capacity.conf` drop-in). So **a new `MAXSECU_*` var reached fresh installs only — every already-deployed server kept its original unit forever.** Identical shape to the `docs/schema.sql`-on-fresh-install-only hole. Latent, not yet a live break: every var happened to have a safe default in `LauncherConfig::from_env`. |
| **What changed** | `MAXSECU_ENV_VARS` in `config.rs` is now the single source of truth (15 vars incl. `DATABASE_URL`). Both scripts carry matching tables (`SERVER_ENV_SURFACE` / `SERVER_ENV_RECONCILE`). `upgrade-server.sh` reconciles an existing unit with a `10-maxsecu-env.conf` drop-in containing **only vars missing everywhere**. |
| **Why it is backward compatible** | **Nothing an operator set is ever overwritten.** Drop-ins are applied *after* the base unit, so re-emitting an already-set name would override the operator — the opposite of the goal. We therefore write only names absent from the base unit, every other drop-in, and every `EnvironmentFile`. Every value written equals the compiled-in default, i.e. exactly what that server was already running with. `DATABASE_URL` (per-install random password), `MAXSECU_DATA_DIR` (synthesizing a path would MOVE the data dir → new cert, every pinned client locked out, empty blob store), `MAXSECU_PUBLIC_ADDR` (absence is meaningful) and the Dropbox secrets are **never synthesized** — each `-` in the table carries a written reason. |
| **Automatic on upgrade?** | Yes — step 7b of `upgrade-server.sh`. Idempotent (a second run is byte-identical, "already reconciled — no change"). |
| **Proven by** | `crates/compat/tests/env_surface.rs` (7 `compat_*` tests): a var the server reads that is not declared, or is declared but wired into only one of the two deployment paths, fails the gate. Plus a harness that runs the reconcile block **verbatim** from the shipped script against mock units: operator values survive untouched, a second run is a no-op, secrets never leave the 0600 `EnvironmentFile`. |
| **Also fixed** | `--reset` never removed the drop-in dir (a stale `capacity.conf` survived a "back to zero" reset and silently overrode the reinstall); a re-run of `install-server.sh` now clears the reconcile drop-in (else it would silently override a new `--port`). |

---

## 2026-07-14 — server `file_versions.alg` — records the manifest's real suite (was hardcoded `1`)

| | |
|---|---|
| **Commit** | `feat/compat-gate` |
| **Surface** | Server DB row (not a signed format) — `crates/server/src/files.rs` `parse_stage` |
| **What changed** | `alg: 1` was written unconditionally, so every `Suite::V2` (PQ-hybrid) file was recorded in the server's row as V1/classical — a lie in the database. Now it records the decoded manifest's actual suite, via an exhaustive match (a future `Suite::V3` fails to compile here rather than silently mis-recording). |
| **Why it is backward compatible** | **The column has no authoritative reader.** Traced end to end: it is never `SELECT`ed (every `FROM file_versions` reads `finalized` / `manifest_bytes` / `manifest_sig` / `owner_id`), `MemoryStore` does not even store it, `FileView`/`FileRes` have no `alg` field, no HTTP response body carries it, and the client takes the suite from the **signed manifest** it re-decodes. Old rows stay wrong and new rows are right, but both are inert — so fixing the writer creates no old/new divergence. **Had a reader existed, fixing the writer alone would have created a NEW divergence, and that would have been worse than the bug.** |
| **How OLD data is still read** | Unchanged: `client-core/download.rs:309`, `reshare.rs:139` read `manifest.alg` from the signed bytes. |
| **Not retro-fixed** | Existing rows keep `alg = 1`. Safe per the above; no re-upload, no re-key, no re-share. |
| **Next one of these** | `pg.rs:902` and `pg.rs:1258` hardcode `wrap_alg: 1` on the **read** side — the mirror-image bug. Harmless today for the same reason. Not fixed. |

---

## 2026-07-14 — `POST /v1/session/proof` — reports the configured session TTL (was hardcoded `3600`)

| | |
|---|---|
| **Commit** | `feat/compat-gate` |
| **Surface** | #10, `/v1` HTTP JSON — `crates/server/src/http.rs` |
| **What changed** | Login returned a hardcoded `expires_in_s: 3600` while the recovery path reported the real `session_ttl_ms / 1000`. The two disagreed. Both now share one `session_expires_in_s(ttl_ms)`, so they cannot drift apart again. |
| **Why it is backward compatible** | **Value-only change; the wire shape is identical** — `expires_in_s` is still present and still a JSON number, so every frozen HTTP golden still passes (they pin the key and type). At the default TTL the value is still literally `3600`. The client parses it as `u64` and hard-fails login if it is missing or non-numeric; both still hold. |
| **Rounding** | Floor, clamped to ≥1s for a non-zero TTL. Rounding *up* would re-introduce the very lie being fixed (a client trusting a token the server already killed); a sub-second TTL flooring to `0` reads as "already expired" and could drive a re-auth hot loop. |

---

## 2026-07-14 — GATE HARDENING — the schema-equivalence test could pass VACUOUSLY

**This entry records a bug found *in the gate itself*, on its first run against a live Postgres.**

| | |
|---|---|
| **Commit** | `feat/compat-gate` |
| **Surface** | The gate — `crates/compat/tests/schema_equivalence.rs` |
| **The bug** | Nothing asserted the introspection queries returned any rows. `fresh == upgraded` is **trivially true when both are empty**, so a probe that silently matched nothing — a typo'd predicate, a `search_path` regression, a future PG catalog change — would have produced a green gate that compared *nothing at all*. Worse: `A == B` is also satisfied when **both** paths have LOST the append-only triggers, so equality alone never proved append-only still exists. |
| **Fix** | A per-aspect non-empty guard, plus an explicit presence check for `maxsecu_forbid_update_delete` / `maxsecu_forbid_delete`. Proven by sabotaging a query to match zero rows: it now fails loudly, and **without the guard that sabotage passed silently.** |
| **Why this matters beyond the DB** | It is the same failure the whole gate exists to prevent — a test that is green because it is not looking. Any future compat probe must assert it found something. |
| **Also proven on live PG** | Gutting a trigger's plpgsql body (`RAISE EXCEPTION` → `RETURN NEW`) leaves `pg_get_triggerdef` **byte-identical** — the `TRIGGERS` comparison does not diverge, and only the trigger-function-body comparison catches it. Without that aspect, append-only would silently disappear from upgraded servers while the gate stayed green. |
