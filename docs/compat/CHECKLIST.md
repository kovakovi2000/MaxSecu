# Backward-compatibility checklist

> **The rule:** *Every upgrade must keep existing users' access intact — account/login, keys, and already-uploaded data. No change may force a re-enroll, re-key, re-upload, re-share, or reset.*

This document is not ceremony. MaxSecu runs on a real VPS with real, non-technical users, and **there is no admin escape hatch by design**. If an upgrade makes a user's keyblob, DEK wrap or directory binding unreadable, that user's data is gone. Permanently. Nobody — not you, not the server operator — can get it back.

Work through this whenever your diff touches a frozen surface. The pre-push hook prints it at you; `/compat-check` walks you through it before you even commit.

---

## The twelve frozen surfaces

Ordered by blast radius. Each one has a golden fixture (yesterday's bytes) **and** a value lock (the constants that *are* the format).

| # | Surface | What breaks if you change it | Source of truth |
|---|---|---|---|
| 1 | Per-stream HKDF labels + chunk AEAD/AAD framing | **Every uploaded chunk undecryptable, forever.** Not "old clients break" — the ciphertext on disk stops opening. | `crypto/dek.rs`, `crypto/aead.rs`, `encoding::ChunkAad` |
| 2 | DEK wrap V1 (HPKE) + V2 (1168-byte hybrid) | Every file's key unrecoverable. The data is intact and unreachable. | `crypto/wrap.rs`, `crypto/hybrid.rs` |
| 3 | `MXKB` keyblob v1 **and** v2 | User cannot log in. Their identity is gone; every wrap addressed to it is dead. | `client-core/keyblob.rs` |
| 4 | `MXD5` seedblob + `recovery_key.blob` | Recovery dead, D5 root unrecoverable. The last resort stops being a resort. | `client-core/seedblob.rs`, `tools/maxsecu-setup` |
| 5 | Canonical encoding: **14** `type_id`s + 13 `labels::*` | **Every signature ever made becomes invalid.** Bindings, certs, receipts — all of them. | `crates/encoding` |
| 6 | 113-byte delegation cert + pinned `.der` layouts | Client rejects the directory and fails closed → total lockout. | `crypto/delegation.rs`, `client-app/config.rs` |
| 7 | `canonical_pin` (33 B classical / 1217 B hybrid) + `pin_fp` | Already-shipped clients cannot verify their pinned server. You cannot patch a binary a user already has. | `client-app/recovery_pin.rs`, `crypto/pin_fp.rs` |
| 8 | `blob_ref` = `hex(file_id)/version/stream_type` | Every stored chunk orphans. The bytes are on disk under a name nothing looks up. | `server/blob.rs` |
| 9 | DB schema | Every existing server strands — `upgrade-server.sh` cannot conjure a column. | `docs/schema.sql`, `migrations/` |
| 10 | `/v1` HTTP JSON, both directions | Old client ↔ new server desync. Users do not upgrade in lockstep with the server. **The freeze covers route existence + JSON shape AND *who may call a route*: loosening a caller check (a principal that used to get `403` now gets an answer) is a **widening** — safe, but ledger it; tightening one (a caller that used to succeed now gets `403`) is a **break**, and no golden fixture will catch it for you.** | `server/http.rs` |
| 11 | Client on-disk state (`config`, `tofu`, `contacts`, `index`, `upload_staging`) | Silent data loss. And a TOFU reset is a **security** downgrade, not just an annoyance — it re-opens the very MITM window the pin closed. | `client-app/{config,tofu,contacts,index,upload_staging}.rs` |
| 12 | `MXBU` sealed server-backup bundle (`type_id 0x000F` index) + migration `0002` tables (`file_tombstones`, `wrap_revocations`) | **A bundle that stops opening = rollback fails exactly when you need it** — the TLS key, the operational signing seed, the Dropbox refresh token and a full `pg_dump` are all sealed inside; nobody can rebuild the box without it. And a merge that misreads the tombstone / revocation tables resurrects a deleted file (a zombie feed entry over ciphertext that is gone) or hands a de-authorized recipient their wrapped DEK back. | `server/backup/format.rs`, `encoding::BackupIndex` (`0x000F`), `migrations/0002_delete_tombstones.sql` |

**Deliberately not frozen:** `cache/frag/*.blob` and the other `SessionSeal` caches — sealed under a per-process ephemeral key and rebuilt on demand. Nothing is lost when their format changes.

**Surface #10 — adding an optional query parameter is a WIDENING.** `ListQuery` and its siblings carry no `#[serde(deny_unknown_fields)]` (`crates/server/src/http.rs:2045-2066`), and `serde_urlencoded` drops what it does not know. So an **old** client's unchanged request still parses against a new server, and a **new** client's extra parameters are silently ignored by an old server. That second half is the dangerous one and it is not automatically safe: a parameter an old server ignores must have a **detectable** absence in the response, or the new client will act on an answer it did not ask for. The 2026-08-02 listing entry is the worked example — `offset` is ignored by prod `41912da`, so the client keys off the absence of the new `total` field and disables paging entirely rather than trusting its own page number.

---

## The deployment surface (not a byte format, same rule)

`scripts/` is not in the twelve, because nothing there is a stored format. It is here anyway, because the two worst near-misses in this project's history came from it: an installer that deleted the TLS identity every client had pinned, and a unit-env reader that silently returned "unset" (see the 2026-07-14 and 2026-08-02 deployment entries in [`LEDGER.md`](LEDGER.md)). The rule applies unchanged: **an operator action must not cost an existing user access.**

**The unit-env parser is duplicated in FIVE scripts and MUST stay byte-identical:**

| script | line |
|---|---|
| `scripts/install-server.sh` | `:461` |
| `scripts/upgrade-server.sh` | `:582` |
| `scripts/backup-server.sh` | `:243` |
| `scripts/restore-server.sh` | `:375` |
| `scripts/fingerprint.sh` | `:79` |

If you change one, change all five, and re-check the md5 of the function body across them. **Why it is not in `scripts/lib/`:** the server tree is delivered to production by SFTP drag-and-drop with **no git**. A partial copy that omitted `scripts/lib/` would make a `. scripts/lib/…` line abort under `set -euo pipefail` — and one of the five callers is `restore-server.sh`, i.e. the **dead-box rebuild** path. A sourcing failure there turns a recoverable box into an unrecoverable one, which is a strictly worse failure than the duplication it would have avoided. *(A test asserting the five copies are identical would be a reasonable addition to `crates/compat/tests/`; none exists today.)*

**KNOWN, DELIBERATE DEVIATION FROM SYSTEMD — carried in all five copies.** Real systemd applies `EnvironmentFile=` **after** `Environment=`, so the **file overrides** the unit line. These scripts consult the file only as a **fallback**. It is documented in-line in every copy (e.g. `scripts/install-server.sh:459-465`) and was left unchanged on purpose: the variable at stake is `DATABASE_URL`, and flipping the precedence could change **which database an upgrade migrates** on a box that sets it in both places. Fixing it is a behaviour change and needs its own decision. Until then: **never set `DATABASE_URL` in both an `Environment=` line and an `EnvironmentFile`.**

**Two smaller, pre-existing limits, recorded so nobody rediscovers them:** the parser does not handle multiple assignments on one `Environment=` line (systemd permits `Environment=A=1 B=2`; it takes everything after the first `NAME=` to end of line — no unit this repo installs is affected, but a hand-edited one could be misread); and `scripts/fingerprint.sh:127` / `scripts/upgrade-server.sh:341` read `ExecStart` from the **base unit only**, so a drop-in that overrides `ExecStart` is missed by both.

---

## The add-only corpus contract

Fixtures may be **ADDED. Never edited. Never deleted.**

A fixture is a recording of bytes that a real user's client already wrote. Editing it to match your new code does not make the new code compatible; it just deletes the evidence that it isn't. **Editing the fixture is never the fix.** The pre-push hook blocks a push that modifies or deletes one, and the per-area `corpus.lock` (`<filename>  <sha256>`) fails the gate in CI if a hash moves or an entry disappears.

To land an **intentional** format change:

1. **Keep the old fixture, and keep a compat-read path that still opens it.** Old bytes stay openable. This is the whole rule, restated.
2. **Add a new fixture** for the new format, and add it to the area's `corpus.lock`.
3. **Append an entry to [`LEDGER.md`](LEDGER.md)**: date, commit, surface, what changed, why it is backward compatible, how old data is still read, which fixture proves it.

Fixtures are generated once by `tools/compat-gen` and committed. The gate never runs the generator — regenerating an existing fixture is a corpus-lock failure *by design*.

---

## How to evolve a format safely

**Add, never repurpose.**
- New field → make it **optional**, with a defined meaning when absent. Old data does not have it and never will.
- Never **hard-require** a field that data written by the previous version lacks.
- Never **repurpose** an existing field, tag, `type_id` or label. The old meaning is still out there on disk, signed.
- Never **renumber**. A `type_id` or version byte is a permanent name, not an index.

**Version bytes fail closed.**
- An unknown version must be a clean, explicit error — never a best-effort parse and never a silent default. But the versions that already exist must keep parsing, forever, through a real read path (not a "we'll migrate it later" TODO).

**Prefer widening over tightening.**
- A stricter check that rejects data the previous version *wrote* is a **break — even when it is more secure.** "We now require X" is the exact shape of a lockout. If a tightening is genuinely necessary for security, it must be paired with an automatic, non-destructive upgrade path for the data that predates it, and recorded in the ledger.
- Widening (accept more, emit the same) is nearly always safe. Tightening (accept less) nearly never is.

**Migrations are automatic, idempotent, crash-safe.**
- A user upgrading a server must not have to *do* anything. No manual step, no "run this once", no reset.
- Every migration is re-runnable and runs in a transaction. A power cut mid-upgrade must leave a working server.
- Editing an already-applied migration is rewriting history: `upgrade-server.sh` refuses to run when a recorded `sha256` no longer matches the file.
- New DB column → nullable, or with a default. Never `NOT NULL` without a default on a table that already has rows.

**The seam cuts both ways.**
- A new server must accept an **old client's** request bodies (a newly-required field is a break).
- An old client must still find every field it reads in a **new server's** response (additive keys are fine; removing or renaming one is not).
- Routes are a superset. No endpoint may vanish or move.

**Republish is not the same as publish.**
- If a change makes newly-written records *better*, ask what happens to the records that already exist. Shipping the new writer without also fixing the old records is the break below.

---

## The precedent (this is not theoretical)

Commit **`2a626d6`** — "PQ-enrollment publish fix" — started publishing ML-KEM keys into the directory binding. It was a genuine, correct security fix. It was **not retroactive**: existing bindings were never republished, so every already-enrolled recipient's binding stayed classical while uploads had moved to V2, and **every already-enrolled recipient had to re-enroll.**

The code was right. The tests were green. Every round-trip test sealed and opened with the same code, so both sides drifted together and nothing noticed. That is precisely the failure mode this gate exists to catch — and why the goldens **open frozen bytes** instead of round-tripping.

That class of break is now forbidden.

---

## Running the gate

```powershell
powershell -File scripts/compat-gate.ps1     # both workspaces, offline, seconds
```

Under the hood — the exact same commands run by `scripts/hooks/pre-push` and the CI `compat` job:

```
cargo test -p maxsecu-compat --locked
cargo test --manifest-path crates/client-app/Cargo.toml --locked \
    --no-default-features --features unpinned-dev --test compat
```

Plus, in the CI `pg-gate` job (needs a real Postgres; skips locally without `DATABASE_URL`):

```
cargo test -p maxsecu-compat --test schema_equivalence --locked
```

Install the hook once: `powershell -File scripts/install-hooks.ps1`.

`SKIP_COMPAT_GATE=1 git push` bypasses the **local hook** only. **CI cannot be bypassed** — the `compat` job runs the same gate on the pushed commits.

---

## When the gate fails

It did not fail because a test is stale. It failed because **bytes an existing user's client already wrote can no longer be opened by your code.**

1. **Do not edit the fixture.** Do not delete it. Do not relax the assertion. Do not add `#[ignore]`. Every one of those turns a real, reproduced, permanent user lockout into a green checkmark.
2. Read the failure message — it names the blast radius, not just the mismatch.
3. Ask: *did I mean to change this format?*
   - **No** → you have an accidental break. Fix the code so the old bytes open again. This is the common case and it is usually a one-liner you did not realise was load-bearing.
   - **Yes** → follow the three steps in the add-only contract above: keep the old read path, add a new fixture, append to the ledger. Your change ships **alongside** the old format, never instead of it.
4. If you believe the fixture itself is wrong — that it records bytes no real client ever wrote — that is a claim about production history, not about the test. Say so explicitly in the PR and in the ledger, with the reasoning. It is not a thing to decide quietly while a test is red.

**The question behind every one of these:** *can a user who enrolled, uploaded and shared on the previous version still log in, still open their files, and still be shared with — after this upgrade, with no action on their part?*

If you cannot answer yes with evidence, do not push.
