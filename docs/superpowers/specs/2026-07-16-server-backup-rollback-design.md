# Server backup & rollback — design

Date: 2026-07-16
Status: approved for implementation

## Goal

Give the operator a way to undo a failed upgrade and to rebuild a dead VPS, without
ever costing an existing user their account, keys, or uploaded data.

Today there is no restore path at all. `upgrade-server.sh` takes a `pg_dump` to
`~/maxsecu-upgrade-backups/db-<stamp>.sql` and explicitly nothing else — its own comment
at line 312 says the data dir "is NOT tarred here". Nothing ever reads that dump back.
There is no `pg_restore`, no tar, no rollback anywhere in `scripts/`.

## The constraint that shapes everything

Every byte that reaches Dropbox today is client-encrypted ciphertext. The module doc at
the top of `crates/server/src/dropbox_tier.rs` asserts a zero-knowledge boundary: no key,
manifest, title, or plaintext ever passes through it.

The data needed to run the server is the exact opposite of that — the TLS private key, the
operational signing seed, the Dropbox refresh token itself, and a `pg_dump` containing every
user's directory binding and DEK key-wraps. **It must be encrypted before it egresses.**
A plaintext bundle in Dropbox would hand the entire server to anyone with the Dropbox account.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Bundle encryption | Passphrase (Argon2id), operator-supplied | No new key file to lose; nothing to bootstrap on existing servers |
| Blob backup | Ride the existing cold tier; upload, **keep local** | Same destination + same tested `put_chunk` path as idle-offload, minus the eviction. A pure read — cannot slow the server or lose data |
| No cold tier configured | **Fail closed** | A backup you wrongly believe is complete is worse than no backup |
| Upgrade integration | Auto-backup, abort on failure | Makes rollback true by default, not by operator discipline |
| Retention | Keep last 10 state bundles; **never** prune blobs | Bundles are small. Blobs are the live cold tier — pruning them destroys user data |
| Restore scope | Same-box rollback **and** dead-box rebuild | Same code path |
| Test sink | `MAXSECU_COLD_FS_DIR` outside the data dir | `FsColdTier` is already a real production path — a credential-free Dropbox. Runs offline and in CI |
| DB restore | **Merge** by default, replace when no live DB | See below |

## Layout

```
{root}/_backup/<stamp>/manifest.json   plaintext hint: stamp, git SHA, counts, per-part digests
{root}/_backup/<stamp>/db/<NNNN>       sealed MXBU — pg_dump -Fc
{root}/_backup/<stamp>/state/<NNNN>    sealed MXBU — unit, drop-ins, dropbox.env, tls/, config/
{root}/<blob_ref>/<index>              blobs — the live cold tier, untouched
```

DB and state are **independently sealed** so `restore --only state` never downloads the dump.
Real blob_refs always begin with 32 hex chars (`hex(file_id)/version/stream_type`), so
`_backup` can never collide; a value-lock test pins that invariant.

The manifest is plaintext so a **dead box can read the git SHA without a binary that can
unseal**. It is an untrusted hint: the SHA is also inside the sealed bundle, and restore
aborts if they disagree.

Parts are ≤8 MiB and uploaded via `ColdTier::put_chunk` — the same call blobs use. This
sidesteps Dropbox's 150 MB single-shot cliff without implementing the upload-session API,
which the repo does not have.

## What goes in the state bundle

| Entry | Why |
|---|---|
| `/etc/systemd/system/maxsecu-server.service` | **the only copy of the DB password on the box** — regenerated per install, stored nowhere else |
| `/etc/systemd/system/maxsecu-server.service.d/*` | capacity + env reconcile drop-ins |
| `/etc/maxsecu/dropbox.env` | the refresh token |
| `<data_dir>/tls/{cert,key}.der` | lose these → new cert → **every pinned client locked out** |
| `<data_dir>/config/*` | the delegation triple — `operational_secret.bin` + `d5_delegation.bin` + `directory_pub.der` only work as a mutually-coherent set |

Blobs are **not** in the bundle. They live in the cold tier, and `WriteBackTier` rehydrates
a copy on read-miss. So a dead-box rebuild needs only the few-KB bundle — the corpus comes
back lazily, per file, on demand.

## MXBU v1 — the sealed bundle format

Modeled on `MXD5` (`crates/client-core/src/seedblob.rs`). `seedblob` itself cannot be reused:
`unseal_seed` hard-rejects anything that is not exactly 93 bytes, because it is built for
32-byte seeds. But `maxsecu-crypto` — which `crates/server` already depends on — has both
halves: `derive_key` (Argon2id, with a below-floor guard) and `seal`/`open` (AES-256-GCM).

45-byte header, used as AEAD AAD:

```
magic "MXBU" (4) | version u8 = 1 | argon m_kib u32 BE | t u32 BE | p u32 BE
  | salt[16] | nonce_base[12]
```

Each part is sealed separately so RAM stays O(part size) for an arbitrarily large dump:

```
part_aad = header ∥ part_index u32 BE ∥ is_last u8
part_ct  = AES-256-GCM(key, nonce_for(nonce_base, part_index), part_aad, part_plaintext)
```

The part index and `is_last` in the AAD defeat truncation and reorder — the same property
`ChunkAad` gives blobs. We do **not** reuse `ChunkAad`: it is hard-wired to
`file_id`/`version`/`StreamType` and lives on frozen surface #1/#5.

- Argon2id at `ARGON2_DESKTOP_TARGET` (256 MiB, t=3, p=1). Params live in the header, so a
  future retune still opens today's bundles.
- Below-floor params rejected before any work (inherited from `derive_key`).
- `MXBU` must be distinct from `MXD5` and `MXKB` — they share an identical header shape and
  KDF, and **only the magic keeps them apart**. Requires a mutual-unopenability test,
  modeled on `compat_keyblob_and_seedblob_magics_stay_distinct` (`value_locks.rs:417`).
- Minimum passphrase length enforced at 12 chars. A bundle in Dropbox faces offline attack.

The container body is a canonical `crates/encoding` struct (new `type_id`), not tar or zip.
The repo has **no** archive crate deps and adding one is avoidable: `pg_dump -Fc` compresses
the dump internally, and every other entry is a few KB.

## DB restore: merge

The live DB is usually **ahead** of the backup, so a blind `pg_restore --clean` would undo
real user state — a user who enrolled since would be stranded holding a keyblob the restored
server has never heard of. That is the `2a626d6` failure mode exactly.

Merge is `INSERT ... ON CONFLICT DO NOTHING` in FK order: add back what is missing, never
touch a live row. It is safe here because PKs are client-generated random values
(`file_id`/`user_id` BYTEA(16)) — there are no sequences to collide.

Use **bare** `ON CONFLICT DO NOTHING` with no conflict target. An explicit target arbitrates
only that one index, so a `users.username` unique violation would abort the restore.

### Per-table verdict

| Tables | Action |
|---|---|
| `users`, `directory_bindings`, `registration_keys`, `first_admin_claim`, `recovery_account`, `sessions`, `auth_nonces` | **Merge.** Never deleted; live row wins on conflict. A consumed registration key cannot be re-opened — PgStore *marks* `used_at` rather than deleting, so the live row survives the conflict |
| `control_log`, `auth_events` | **Skip entirely.** Append-only with no `DELETE FROM` anywhere, so a live DB is always a superset — there is nothing to add. This also avoids `control_log`'s `BEFORE INSERT` append-guard (which fires *before* conflict arbitration and would abort the txn) and takes both IDENTITY-sequence `setval` fixups off the table |
| `files`, `file_genesis`, `file_versions`, `file_streams`, `file_key_wraps` | **Merge, gated on tombstones.** See below |

### Why the file family needs tombstones

Absence is meaningful in two ways, and today the schema records neither:

1. **Delete is a hard delete.** `pg.rs:1331` sets a transaction-local GUC
   (`maxsecu.allow_owner_delete`) to punch through the append-only triggers, then
   `DELETE FROM file_versions/file_genesis/files`, cascading to `file_streams` and
   `file_key_wraps`. The blobs are purged from **both** tiers — `writeback_tier.rs:454`:
   "the only time the cold copy is removed". Re-inserting resurrects the file *broken*:
   a zombie feed entry pointing at ciphertext that no longer exists anywhere.
2. **Revocation is the absence of a wrap.** `docs/schema.sql:222`: *"Server may DELETE wraps
   (deny/soft-revoke)."* Revoke-share is `DELETE FROM file_key_wraps WHERE ...` (`pg.rs:1208`).
   Re-inserting hands the wrapped DEK back to a de-authorized recipient — silently, with no
   log line, on a file that was never deleted.

"Tombstone" in this codebase already means a `control_log` revocation record (kind=6). There
is **no delete tombstone**. Deletion currently leaves no audit record at all, while
revocations are logged — a gap worth closing on its own merits.

### Migration 0002 — two new tables

```sql
CREATE TABLE file_tombstones (
  file_id     BYTEA PRIMARY KEY CHECK (octet_length(file_id) = 16),
  deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- append-only: maxsecu_forbid_update_delete

CREATE TABLE wrap_revocations (
  file_id       BYTEA NOT NULL CHECK (octet_length(file_id) = 16),
  file_version  BIGINT NOT NULL,
  recipient_id  BYTEA NOT NULL,
  revoked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, file_version, recipient_id)
);
-- append-only: maxsecu_forbid_update_delete
```

Write sites, each **inside the existing transaction**:
- `pg.rs delete_file` (~1331) → one `file_tombstones` row per deleted `file_id`
- `pg.rs revoke_share` (~1208) → one `wrap_revocations` row

**Do not** write a `wrap_revocations` row in `finalize_version` (`pg.rs:831-842`). That drops
the *prior version's* wraps and streams — version supersession, not revocation.

No FK to `files` on either table: the parent row is gone by design.

### Merge rule for the file family

Read tombstones from the **live** DB (they are append-only, so they survive), then per
`file_id` in the backup:

- Live has a `file_tombstones` row → **skip the whole subtree.** The owner destroyed it.
- Live has the file → merge only rows for versions **that exist in live**. Skip versions
  live does not have; those are superseded (`finalize_version` dropped them and their blobs).
  Merge `file_key_wraps` only where no `wrap_revocations` row exists.
- Live lacks the file and there is no tombstone → **it was lost. Restore the whole subtree.**
  The backup only ever contains current-version rows (supersession already pruned the rest),
  so this is self-consistent. Its blobs are still in the cold tier — a cold copy is only
  removed on user delete, and there was none.

### Dead-box `--replace`

With no live DB there are no tombstones, so a full replace resurrects files deleted between
the last backup and the crash. That knowledge genuinely died with the DB. Their blobs were
already purged, so restore **verifies every restored file's blobs resolve** and prints the
ones that do not:

```
warning: 3 restored files have missing ciphertext and are likely post-backup deletions:
  a1b2…  b3c4…  d5e6…
their owners can re-delete them.
```

Do **not** auto-drop rows whose blobs are unreachable — that conflates "deleted" with
"Dropbox hiccuped during restore" and would permanently drop live files.

## CLI

```
maxsecu-portable-server backup      [--keep N]
maxsecu-portable-server restore     --from latest|<stamp>
                                    [--only db,state,code,blobs]
                                    [--db-mode merge|replace]
                                    [--dry-run] [--force]
maxsecu-portable-server list-backups
```

Passphrase arrives **on stdin, never argv** — argv is world-readable via `/proc`.

`--db-mode` defaults to `merge` when a live DB exists and `replace` when it does not.
`--dry-run` unseals, verifies, prints the plan, and changes nothing.

`--only` selects components:

| Component | Effect |
|---|---|
| `code` | `git checkout <sha>` + `cargo build --release` + restart |
| `state` | unit, drop-ins, dropbox.env, tls/, config/ → `daemon-reload` |
| `db` | `pg_restore` per `--db-mode` |
| `blobs` | **optional pre-pull only.** Blobs need no restore step — `WriteBackTier` rehydrates a copy on read-miss automatically. This just walks the cold tier and warms local disk up front, trading time for a fast first read |

**`--only code` is the common case.** For a failed upgrade where nothing was deleted, the live
DB is a strict superset of the backup and the merge is a no-op — the right fix was only ever
"roll the code back", and it should not have to download a multi-hundred-MB dump to do it.

## Components

| Path | Role |
|---|---|
| `crates/server/src/backup/format.rs` | MXBU seal/unseal + the canonical container |
| `crates/server/src/backup/mod.rs` | backup/restore plan + execution over `ColdTier`. Unit-tested against `MemoryColdTier`, no network |
| `crates/server/src/writeback_tier.rs` | new `backup_copy_all()` — upload every local chunk, **skip the eviction**. Idempotent via `has_chunk` |
| `crates/server/src/tier.rs` | `ColdTier::list_prefix` — new, **defaulted to Unsupported**. Additive, internal Rust, not a frozen surface |
| `crates/portable-server/src/main.rs` | the three subcommands + env wiring |
| `migrations/0002_delete_tombstones.sql` | the two tables |
| `crates/server/src/pg.rs` | tombstone write sites |
| `scripts/backup-server.sh` / `restore-server.sh` | thin root drivers: `sudo`, `pg_dump`/`pg_restore`, `git`, `cargo`, `systemctl` |
| `scripts/install-server.sh` | `--cold-tier-fs <dir>` |
| `scripts/upgrade-server.sh` | auto-backup replaces the local-pg_dump step |
| `tools/live-smoke` | `--phase seed\|verify` + state file |
| `scripts/lib/wsl-harness.ps1` | helpers extracted from `test-full-install.ps1` |
| `scripts/test-backup-rollback.ps1` | the E2E |

Prefer **CLI flags over new env vars**. A new env var must land in *both* `SERVER_ENV_SURFACE`
(install-server.sh) and `SERVER_ENV_RECONCILE` (upgrade-server.sh) or `env_surface.rs` fails
the build. `MAXSECU_COLD_TIER` / `MAXSECU_COLD_FS_DIR` already exist — only the wiring is new.

## Compat obligations

A bundle written today must be readable by **every future version, forever** — otherwise the
rollback fails exactly when you need it. This is **new frozen surface #12**.

- `docs/compat/CHECKLIST.md` — add surface #12
- `compat/fixtures/backup/` — `backup_v1.bin` + `.passphrase.txt` + `.expect.json` + `corpus.lock`
- `crates/compat/tests/golden_open.rs` — add `backup` to `AREAS` + a `compat_frozen_backup_still_unseals` test
- `crates/compat/tests/value_locks.rs` — MXBU/MXD5/MXKB mutual-unopenability; `_backup` vs blob_ref non-collision
- `docs/compat/LEDGER.md` — one entry covering the new format, the new `encoding` type_id
  (additive to surface #5), and migration 0002 (additive to surface #9)
- `crates/compat/tests/schema_equivalence.rs` — the two new tables

Build the fixture **from the documented byte layout, not by calling `seal`** — copying the
deliberate `build_keyblob` pattern (`golden_open.rs:687`), so the gate proves we can open
*foreign* bytes rather than round-tripping ourselves. Use `ARGON2_FLOOR` in the fixture to
keep the gate fast.

The corpus is add-only. **Editing a fixture is never the fix.**

## The test — `scripts/test-backup-rollback.ps1`

`MAXSECU_COLD_FS_DIR` points **outside** the data dir, making `FsColdTier` a credential-free
Dropbox for both blobs and bundle parts. (The default `<data_dir>/cold/` would be destroyed
by step 3.)

1. Install server in WSL with cold-tier=fs → build the real client →
   `live-smoke --phase seed` enrolls, uploads, records the `file_id` + owner seeds to a state file
2. `backup-server.sh`
3. **Destroy:** `rm -rf ~/maxsecu-server-data` + `DROP DATABASE maxsecu` + delete the unit
4. `restore-server.sh --from latest`
5. `live-smoke --phase verify` — **same** `dist\MaxSecuClient`, no re-enroll, no re-pin,
   byte-compares the file back

Step 5 is the point: it is a direct executable assertion of the CLAUDE.md rule. live-smoke
today enrolls fresh and uses random `file_id`s per run, so it needs the phase split — the
`view_own_blog` + `verify_and_open` + byte-compare machinery in `steps.rs:117-155` is reusable.

Additional cases worth covering: merge-with-live-ahead (nothing stranded), delete-then-restore
(tombstone honored, file stays deleted), revoke-then-restore (wrap not resurrected),
`--only code`, `--dry-run` changes nothing, wrong passphrase fails cleanly.

## Known limitations

- **Rollback loses what happened in between.** Inherent. `--db-mode merge` is the mitigation:
  it adds back what is missing and never removes what is new, so it cannot strand a user.
- **Dead-box replace can resurrect post-backup deletions.** Reported, not silently swallowed.
- **Tombstones only exist going forward.** A file deleted by pre-0002 code left no record, so
  a merge from a bundle predating this feature could resurrect it. Bundles are short-lived
  (retention 10); the window closes on its own.
- **One-shot Argon2id per bundle.** A weak passphrase is the whole security of a bundle sitting
  in Dropbox. 12-char minimum is a floor, not a guarantee.
