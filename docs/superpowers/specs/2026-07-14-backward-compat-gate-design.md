# Backward-Compatibility Gate (the "compat gate")

**Date:** 2026-07-14
**Status:** Approved, implementing
**Rule it enforces:** *Every upgrade must keep existing users' access intact — account/login, keys, and already-uploaded data. No change may force a re-enroll, re-key, re-upload, re-share, or reset.*

---

## 1. Why this exists

MaxSecu is deployed to non-technical users on a real VPS with real data. There is no admin escape hatch by design: if an upgrade makes a user's keyblob, DEK wrap, or directory binding unreadable, that user's data is gone permanently.

We have already shipped one such break. `2a626d6` (PQ-enrollment publish fix) started publishing ML-KEM keys into the directory binding but did **not** republish existing bindings, so every already-enrolled recipient had to re-enroll. That class of break is now forbidden.

Today the rule is unenforceable:

- **Nothing pins yesterday's bytes.** Every round-trip test seals and opens with the *same* code, so both sides can drift together and the suite stays green. The sole exception is `crates/encoding/tests/fixtures/canonical_vectors.tsv`.
- **The DB already violates the rule.** `docs/schema.sql` is applied only by `scripts/install-server.sh` on a fresh install; `scripts/upgrade-server.sh` applies no schema change at all. Any edit to `schema.sql` silently strands every existing deployment.
- **The client workspace is excluded from CI.** `crates/client-app`, `crates/client-e2e`, `tools/maxsecu-setup` and `tools/live-smoke` form a separate Cargo workspace that CI never builds. The keyblob consumer, `settings.json`, TOFU pins, contacts, the search index, the staging records, `recovery_pin.bin` and the entire hand-rolled HTTP client have zero CI coverage.
- **The HTTP seam is untyped on both sides.** Every server DTO in `crates/server/src/http.rs` is private; the client re-implements the wire by hand with `serde_json::json!`. A field rename on either side silently breaks the other and nothing type-checks it.

## 2. Architecture

Two test targets, one shared corpus, because the two Cargo workspaces cannot see each other:

| Component | Path | Workspace |
|---|---|---|
| Compat crate (tests + value locks) | `crates/compat/` | root |
| Client-side compat tests | `crates/client-app/tests/compat.rs` | client |
| Frozen corpus (shared) | `compat/fixtures/` | neither — plain files at repo root |
| Fixture generator | `tools/compat-gen/` | root |
| Ledger of intentional changes | `docs/compat/LEDGER.md` | — |
| Review checklist | `docs/compat/CHECKLIST.md` | — |

Both test targets locate the corpus from `CARGO_MANIFEST_DIR` via a relative path, so no build-script magic and no env vars.

### 2.1 Two mechanisms

**(A) Golden corpus — "yesterday's bytes must still open today."**

Each fixture is an artifact *produced once and frozen*, committed together with the test key material needed to open it and the expected plaintext. The test **opens** it: unlock, unwrap, verify, decode. This is the rule stated as an executable assertion.

It is deliberately not a round-trip. A round-trip proves only self-consistency, which is exactly the property that fails to catch a break.

**(B) Value locks — "the constants that define the format cannot silently move."**

Direct assertions on the constants that *are* the format: type_ids, domain-separation labels, magic bytes, fixed lengths, path schemes. These fail at the line that causes the break with a message naming the blast radius, instead of surfacing as a confusing decode error three layers away.

### 2.2 The escape hatch: add-only corpus + ledger

Fixtures may be **added. Never edited. Never deleted.**

Each fixture area carries its own `corpus.lock` (`<filename> <sha256>`, one per line, sorted) — per-area rather than one global lock so that parallel work does not collide. The gate fails if any hash changes or any entry disappears.

To land an intentional format change you must:

1. Keep the old fixture, and keep a compat-read path that still opens it.
2. Add a new fixture for the new format.
3. Append an entry to `docs/compat/LEDGER.md` (date, commit, surface, what changed, why it is safe, how old data is still read).

This makes "backward compatible" structurally true rather than a promise. A `--no-verify` push can still bypass the local hook; the CI job cannot be bypassed.

## 3. Coverage — the eleven access-critical surfaces

Ordered by blast radius. Each gets a golden fixture *and* a value lock.

| # | Surface | Breakage | Source of truth |
|---|---|---|---|
| 1 | Per-stream HKDF labels + chunk AEAD/AAD framing | Every uploaded chunk undecryptable, forever | `crypto/dek.rs`, `crypto/aead.rs`, `encoding::ChunkAad` |
| 2 | DEK wrap V1 (HPKE) + V2 (1168-byte hybrid) | Every file's key unrecoverable | `crypto/wrap.rs`, `crypto/hybrid.rs` |
| 3 | `MXKB` keyblob v1 **and** v2 | User cannot log in — identity gone | `client-core/keyblob.rs` |
| 4 | `MXD5` seedblob + `recovery_key.blob` | Recovery dead; D5 root unrecoverable | `client-core/seedblob.rs`, `tools/maxsecu-setup` |
| 5 | Canonical encoding: 13 type_ids + 13 `labels::*` | Every signature ever made becomes invalid | `crates/encoding` |
| 6 | 113-byte delegation cert + pinned `.der` layouts | Client rejects the directory → total lockout | `crypto/delegation.rs`, `client-app/config.rs` |
| 7 | `canonical_pin` (33 B classical / 1217 B hybrid) + `pin_fp` | Shipped clients cannot verify their pinned server | `client-app/recovery_pin.rs`, `crypto/pin_fp.rs` |
| 8 | `blob_ref` = `hex(file_id)/version/stream_type` | Every stored chunk orphans | `server/blob.rs` |
| 9 | DB schema | Existing servers strand | `docs/schema.sql` |
| 10 | `/v1` HTTP JSON, both directions | Old client ↔ new server desync | `server/http.rs` |
| 11 | Client on-disk state | Silent data loss; TOFU reset is a **security** downgrade | `client-app/{config,tofu,contacts,index,upload_staging}.rs` |

**Excluded, deliberately:** `cache/frag/*.blob` and the other `SessionSeal` caches are sealed under a per-process ephemeral key and rebuilt on demand — not a compat surface.

**Known weak spot, recorded not fixed:** `staging/<file_id>/record.json` is plain, unversioned, unsealed JSON. The gate freezes it as-is; the ledger records that it needs a version tag before it is next changed.

### 3.1 Interop matrix

Beyond per-format goldens, one matrix test: for every frozen `Suite` (V1 classical, V2 hybrid) × every frozen keyblob version (v1 classical, v2 PQ), today's code must still **unwrap, verify, and reshare**.

This is the test that would have caught the PQ-enrollment break — not as a missing JSON field, but as its actual symptom: *an old classical binding can no longer participate in a reshare.*

## 4. The DB hole, closed

The only part of this work that changes runtime behavior.

- `migrations/0001_baseline.sql`, `migrations/NNNN_<slug>.sql`, applied in numeric order.
- Table `schema_migrations(id INT PRIMARY KEY, applied_at TIMESTAMPTZ, sha256 TEXT)`.
- `scripts/upgrade-server.sh` applies pending migrations idempotently, each in a transaction, and **refuses to run** if an already-applied migration's recorded `sha256` no longer matches the file on disk (someone edited history).
- `scripts/install-server.sh` continues to load `docs/schema.sql` for fresh installs, then records every migration id as applied.

**The load-bearing test** (`crates/compat`, runs in the existing `pg-gate` CI job, skips without `DATABASE_URL`):

> A fresh install and an upgraded install must be the same product.

Build two throwaway PG schemas — one from `docs/schema.sql`, one from `0001_baseline.sql` + every migration — and compare them via `information_schema` + `pg_trigger`: columns, types, nullability, defaults, PK/UNIQUE/FK constraints, and **triggers** (the append-only enforcement lives in triggers, so omitting them would let the gate pass while append-only silently disappears from upgraded servers). Divergence fails the gate.

`compat/schema.lock` pins the sha256 of `docs/schema.sql`, making an edit without a corresponding migration a hard failure.

## 5. The HTTP seam

**Server-side**, in-process against the real `router()` over `MemoryStore` (no network, no PG):

1. **Old request bodies still accepted.** Each frozen golden request is submitted verbatim. A newly-*required* field anywhere makes this fail.
2. **Old response fields still emitted.** Every key an old client reads must still be present in the response, compared recursively as a subset. Additive keys are fine.
3. **Route surface is a superset** of the frozen `(method, path)` list. No endpoint may vanish or move.

**Client-side**, one small refactor: the client builds request JSON inline with `serde_json::json!` inside async command functions doing network I/O, so nothing can test it. Extract pure `build_*_body()` functions for the five access-critical calls — `register`, `recovery_register`, `publish_binding`, session `prove`, `add_wrap` — and assert each emits a superset of the frozen key set. This is the exact seam where `mlkem_pub_b64` went missing; a pure-function extraction is cheap and makes it testable permanently.

## 6. Enforcement

1. **`scripts/hooks/pre-push`** (bash; Git for Windows runs hooks in Git Bash) — runs the compat gate for both workspaces and blocks the push on failure. It also diffs the pushed range against the frozen paths and, when one is touched, prints `docs/compat/CHECKLIST.md`. Installed once with `scripts/install-hooks.ps1` (`git config core.hooksPath scripts/hooks`).
2. **CI job `compat`** in `.github/workflows/ci.yml` — runs the gate in **both** workspaces, finally giving the CI-excluded `client-app` crate coverage of keyblob, pin, settings and TOFU. The schema-equivalence test joins the existing `pg-gate` job.
3. **`docs/compat/CHECKLIST.md`** + a `/compat-check` slash command that reviews the working diff against the rule *before* a push is ever attempted.

The gate is offline and deterministic (no PG, no network) except schema-equivalence, which skips gracefully without `DATABASE_URL` and runs for real in CI — the same pattern as the existing `pg_store` test.

## 7. Conventions all implementation tracks follow

- **Fixture path:** `compat/fixtures/<area>/<name>.<ext>`; areas are `encoding/`, `crypto/`, `keyblob/`, `seedblob/`, `delegation/`, `pin/`, `blobref/`, `http/`, `client-state/`.
- **Per-area lock:** `compat/fixtures/<area>/corpus.lock`, lines of `<filename>  <sha256-hex>`, sorted by filename, LF endings.
- **Every fixture is accompanied by** whatever is needed to open it (test secret keys, passphrase, expected plaintext) as sibling files with the same stem, e.g. `keyblob_v1.blob`, `keyblob_v1.expect.json`, `keyblob_v1.passphrase.txt`.
- **Test key material is test-only** and lives only under `compat/fixtures/`. It must never be named `recovery_pin.bin` or land anywhere `crates/client-app/build.rs` reads, so the existing ship-guard against embedding a test pin stays intact.
- **Fixtures are generated once** by `tools/compat-gen` and committed. The generator is *not* run by the gate; it exists so new fixtures can be added deliberately. Regenerating an existing fixture is a corpus-lock failure by design.
- **Naming:** every compat test name starts with `compat_` so `cargo test compat_` selects the whole gate.
- **Failure messages** must name the blast radius, not just the mismatch. Example: `"MaxSecu-content-v1 HKDF label changed: every chunk ever uploaded becomes undecryptable. See docs/compat/CHECKLIST.md."`

## 8. Out of scope

- Retro-fixing the already-shipped PQ-enrollment non-retroactivity (existing recipients already re-enrolled).
- Versioning `staging/record.json` (recorded in the ledger as the next thing to do when it is touched).
- A capability/version handshake between client and server. The `/v1` prefix plus the additive-field discipline is the contract for now.
