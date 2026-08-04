# Server backup & rollback — design

Date: 2026-07-16
Status: approved for implementation — **amended 2026-07-16 after source verification** (see [Corrections](#corrections-2026-07-16))

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
| Blob backup | Ride the existing cold tier; upload, **keep local**. Enumerate from **`file_streams` in the DB** | Same destination + same tested `put_chunk` call as idle-offload, minus the eviction. A pure read — cannot slow the server or lose data. The DB is the only complete, restart-proof list of what exists (see [Blob enumeration](#blob-enumeration-the-db-is-the-only-complete-list)) |
| No cold tier configured | **Fail closed** | A backup you wrongly believe is complete is worse than no backup |
| Upgrade integration | Auto-backup, abort on failure | Makes rollback true by default, not by operator discipline |
| Retention | Keep last 10 state bundles; **never** prune blobs | Bundles are small. Blobs are the live cold tier — pruning them destroys user data |
| Restore scope | Same-box rollback **and** dead-box rebuild | Same code path |
| Test sink | `MAXSECU_COLD_FS_DIR` outside the data dir | `FsColdTier` is already a real production path — a credential-free Dropbox. Runs offline and in CI |
| DB restore | **Merge** by default, replace when no live DB | See below |

## Layout

```
{root}/_backup/<stamp>/manifest/0      plaintext hint: stamp, git SHA, counts, per-part digests
{root}/_backup/<stamp>/db/<NNNN>       sealed MXBU — pg_dump -Fc
{root}/_backup/<stamp>/state/<NNNN>    sealed MXBU — unit, drop-ins, dropbox.env, tls/, config/
{root}/<blob_ref>/<index>              blobs — the live cold tier, untouched
```

> ⚠️ **The manifest path is `manifest/0`, not `manifest.json`.** The only writer is
> `ColdTier::put_chunk(blob_ref, index, bytes)`, which **both** adapters realize as
> `{root}/{blob_ref}/{index}` (`dropbox_tier.rs:236-240`; `FsBlobStore::stream_dir` +
> `dir.join(index.to_string())`). A `blob_ref` of `_backup/<stamp>/manifest.json` therefore
> produces a **directory** named `manifest.json` containing a file `0`. An earlier draft
> documented the "a dead box can read the git SHA without a binary that can unseal" property at
> a path that would never exist.

DB and state are **independently sealed** (separate salt + nonce_base — see the MXBU section) so
`restore --only state` never downloads the dump. Part counts come from
`chunk_count("_backup/<stamp>/db")` — no `list_prefix` call needed.

Real blob_refs always begin with 32 hex chars (`hex(file_id)/version/stream_type`), so
`_backup` can never collide; a value-lock test pins that invariant.

The manifest is plaintext so a **dead box can read the git SHA without a binary that can
unseal**. It is an untrusted hint: the SHA is also inside the sealed bundle, and restore
aborts if they disagree.

⚠️ **Its per-part digests are over the sealed CIPHERTEXT, never the plaintext.** The manifest is
a world-readable file sitting next to the bundle in Dropbox. Plaintext-part digests there would
be a confirmation oracle over the dump — and for the *state* bundle, whose entries are few,
small and highly guessable (a `.service` unit, a `dropbox.env`), close to a direct one.

`<stamp>` flows from operator input (`--from <stamp>`) into a `blob_ref`, so it is validated
against `[0-9A-Za-z-]{1,32}` before use. The containment guards (`blob.rs:210-221`,
`dropbox_tier.rs:208-220`) only reject non-`Component::Normal` path parts — they are a backstop,
not the validation.

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

## Blob enumeration: the DB is the only complete list

**Do not** model `backup_copy_all` on the idle-offload path. Three facts in the source make
"mirror `run_idle_sweep`, minus the eviction" produce a backup that is silently incomplete —
the exact outcome this design's own fail-closed rule calls worse than no backup:

1. **`LocalIndex` is in-memory and empty after a restart.** `writeback_tier.rs:118` —
   `struct LocalIndex { capacity_bytes, total_bytes, tick, entries: HashMap<…> }`. Nothing
   persists it; it is populated lazily as chunks are put or read. `get_chunk` (:384) says so:
   *"adopting it if unseen, e.g. post-restart."* A sweep-shaped backup on a freshly restarted
   server enumerates **zero chunks and reports success.**
2. **The pin filter excludes every thumbnail and preview.** `idle_victims` (:237) filters
   `!e.pinned`; `is_pinned_stream` (:61) pins Thumbnail + Preview, which are *never* offloaded
   and therefore have **no cold copy at all** (test at :697 asserts `chunk_count(THUMB) == 0`).
3. **`BlobStore` has no enumeration method.** All five required methods (`put_chunk`,
   `get_chunk`, `chunk_count`, `delete_stream`, `delete_chunk`) require the caller to already
   know the `blob_ref`. `ColdTier::list_prefix` enumerates the **cold** tier — it does not
   help here.

**Instead, drive the copy from `file_streams`** — the authoritative, committed, restart-proof
record of every stream that exists. It carries both the ref and its length.

⚠️ **The query must be FILTERED. An unfiltered `SELECT blob_ref, chunk_count FROM file_streams`
is wrong** (an earlier draft's sketch had exactly that): it returns **staged, not-yet-finalized**
streams — an in-flight upload's rows — whose `chunk_count` is the *intended* count, not what is
on disk yet. `backup_copy_refs` would then walk indices that do not exist locally and report them
as `missing_local`, turning a user's ordinary in-flight upload into backup noise (or, if the
report is treated as fail-closed, into a **failed backup**). Join to `files.current_version` so
only committed, current streams are copied — the same gate the merge rule uses:

```sql
SELECT s.blob_ref, s.chunk_count
FROM file_streams s
JOIN files f ON f.file_id = s.file_id AND f.current_version = s.version;   -- schema.sql:205-217
```

Superseded versions are excluded for free by the same join — correctly, since `finalize_version`
already purged their chunks from **both** tiers (`http.rs:1450-1457`).

```rust
// crates/server/src/writeback_tier.rs — on WriteBackTier, called by the backup engine
pub async fn backup_copy_refs(&self, refs: &[(String, u64)]) -> Result<CopyReport, BlobError> {
    for (blob_ref, chunk_count) in refs {
        for i in 0..*chunk_count {
            if self.cold.has_chunk(blob_ref, i).await? {
                continue;                                   // idempotent — resumable
            }
            let Some(bytes) = self.local.get_chunk(blob_ref, i).await? else {
                report.missing_local.push((blob_ref.clone(), i));   // already cold-only: fine
                continue;
            };
            self.cold.put_chunk(blob_ref, i, bytes).await?;  // NO eviction, NO pin filter
        }
    }
}
```

No index dependency, no pin filter, survives a restart, and covers thumbnails. A chunk that is
already cold-only (offloaded and evicted from local) is **not** an error — it is already backed
up, which is the whole point of `has_chunk` running first.

**Wiring.** `build_blobs` (`run.rs:34`) returns a type-erased `Arc<dyn BlobStore>` and only
constructs a `WriteBackTier` when `cold_tier != Off` (and `cold_tier` **defaults to Off** —
`config.rs:190`). So an inherent method on `WriteBackTier` is unreachable from `AppState` as
composed. `run.rs:64` already keeps a concrete `tier.clone()` for the idle-sweeper task —
**follow that pattern**: hold the concrete `Arc<WriteBackTier>` alongside the type-erased one.
This is also why "no cold tier configured → fail closed" is load-bearing rather than a nicety:
with `Off` there is no `WriteBackTier` and no `ColdTier` at all.

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

> ⚠️ **ONE HEADER PER *COMPONENT*, NOT PER BUNDLE. Getting this wrong is a two-time pad.**
>
> `nonce_for(nonce_base, part_index)` takes **no component input**. "DB and state are
> independently sealed" and "a 45-byte header" read together are ambiguous, and the wrong
> reading is catastrophic: sharing one header across both components means `db/0003` and
> `state/0003` seal **different plaintexts under the same `(key, nonce)`**. AES-GCM under nonce
> reuse leaks `pt₁ ⊕ pt₂` **and** allows recovery of the GHASH authentication key — i.e. forgery,
> not just confidentiality loss. The bundle's whole threat model is "this sits in Dropbox and
> faces an offline attacker."
>
> **Mandate:** a fresh `salt` **and** a fresh `nonce_base` **per component**. `MxbuSealer::new()`
> generates both, so the rule is simply **one sealer per component, never one per backup**. That
> is the whole of it: distinct salts ⇒ distinct keys ⇒ distinct nonce spaces.
>
> **No component tag is needed, and none is carried.** A `state` part replayed as a `db` part
> already fails at the AEAD, because the two bundles were sealed under different keys. Tagging
> would add a new frozen enum registry for a distinction the key already makes. Pinned by
> `a_part_from_another_bundle_is_rejected` (`backup/format.rs`), which asserts two sealers never
> share a header — the test that stands between this design and a two-time pad.
> *(This supersedes an over-cautious line in the round-2 amendment that called for a container
> `component` field; the implementation's reasoning is better and the code is the authority here.)*

**Every stored part is `header(45) ‖ part_ct` — the header is REPEATED on every part, not carried
by part 0 alone.** Part 0 is still the sealed metadata container (the `BackupIndex`) and parts
`1..P-1` are still payload; part 0 is still written **last**, which makes it the commit point: a
bundle whose part 0 is absent is an incomplete upload, and restore rejects it before touching
anything else. What the repetition buys is self-description — a part fetched off an untrusted
tier states its own `(m,t,p)`, salt and `nonce_base`, so the key can be derived from whichever
part came back first, at a cost of 45 bytes per part.

The splice this paragraph originally reached for — part 3 of bundle A presented as part 3 of
bundle B — is defeated by a **per-part header compare**, not by omitting the header. The opener
is derived once, from part 0 (`read_index`, `backup/mod.rs`), and `MxbuOpener::open_part`
(`backup/format.rs`) rejects any part whose 45-byte prefix is not byte-identical to *that*
opener's header, before the AEAD is reached at all. A spliced part fails closed on the compare —
and would fail again at the AEAD anyway, since the two bundles were sealed under different keys.
*(This supersedes the draft's "the header lives ONLY in part 0", restated in the round-2 R2-3
cell. Same form as the note above: the implementation's reasoning is better, and on a frozen
surface the code is the authority. See **Corrections, round 5**.)*

Each part is sealed separately so RAM stays O(part size) for an arbitrarily large dump:

```
part_aad = header ∥ part_index u32 BE ∥ is_last u8
part_ct  = AES-256-GCM(key, nonce_for(nonce_base, part_index), part_aad, part_plaintext)
```

The part index and `is_last` in the AAD defeat truncation and reorder — the same property
`ChunkAad` gives blobs. We do **not** reuse `ChunkAad`: it is hard-wired to
`file_id`/`version`/`StreamType` and lives on frozen surface #1/#5.

**`nonce_for` must be written fresh — there is nothing to reuse.** The repo's only `nonce_for`
(`crypto/src/aead.rs:27`) is **private**, takes a **single** `chunk_index: u64`, and has no
`nonce_base` concept; `nonce_base` does not exist anywhere in the codebase. Define a local
`fn nonce_for(base: &[u8; 12], part_index: u32) -> [u8; 12]` inside `backup/format.rs` (do
**not** add a second `pub nonce_for` to `aead.rs` — it would collide with the private one).

**The construction is normative — this is frozen surface #12 and must be readable forever:**

```
nonce_for(base, part_index) = base with part_index.to_be_bytes() XORed into bytes 8..12
```

i.e. the TLS 1.3 record-nonce construction. XOR rather than overwrite, because it keeps all 96
bits of `base` influencing the nonce while staying injective in `part_index` — each index maps to
exactly one nonce under a given key. **This must be written down here, not just in the code:**
the compat fixture is minted independently from the documented byte layout, so if the layout
omits the nonce construction, the fixture builder and the reader can silently disagree and the
gate would be testing nothing.
Note this deviates from the repo's established single-shot pattern (every other `seal` call
site — keyblob, seedblob, contacts, tofu, index — uses a **fresh random nonce per seal**);
deriving from a base is deliberate here, because a per-part random nonce would have to be
stored per part, and the base+index construction is what binds part ordering into the nonce as
well as the AAD. Uniqueness holds because `salt` is fresh per bundle, so `key` is unique per
bundle, and each `part_index` is used exactly once under that key.

- Argon2id at `ARGON2_DESKTOP_TARGET` (256 MiB, t=3, p=1). Params live in the header, so a
  future retune still opens today's bundles.
- Below-floor params rejected before any work (inherited from `derive_key`).
- **`unseal` must NOT require `params == ARGON2_DESKTOP_TARGET`.** Read `(m,t,p)` from the
  header and pass them through. A check pinning today's target would both reject the
  `ARGON2_FLOOR`-sealed compat fixture *and* be a textbook CHECKLIST break ("prefer widening
  over tightening") the day the target is retuned.
- **The 12-char passphrase minimum is enforced on SEAL ONLY.** A bundle in Dropbox faces
  offline attack, so refuse to *write* one under a short passphrase — but never gate `unseal`
  on it. Enforcing it on unseal means any future raise of the minimum retroactively bricks
  every bundle already written under a shorter one: "a stricter check that rejects data the
  previous version wrote is a break even when it is more secure." Note keyblob/seedblob
  enforce no minimum at all, so this is new surface with no precedent to copy.
- `MXBU` must be distinct from `MXD5` and `MXKB`. **But "only the magic keeps them apart" is
  false in one direction, and the model test is half-vacuous** — `unseal_seed` checks
  **length before magic** (`seedblob.rs:75-80`), so feeding it a variable-length MXBU bundle
  returns `CorruptBlob` off the length gate having never read `blob[0..4]`. The model,
  `compat_keyblob_and_seedblob_magics_stay_distinct` (`value_locks.rs:417`), has this hole
  already: its 221-byte `keyblob_v2.bin` fails `unseal_seed` at `len != 93`, not on the magic
  its panic message describes.

  ⚠️ **The obvious remedy is ALSO vacuous — use a differential probe.** "Assert the specific
  error variant" does **not** work in the MXBU direction: the reader's length gate and its magic
  gate both return `CorruptPart`, so `assert_eq!(…, Err(CorruptPart))` proves exactly as little
  as the test it replaces. The shape that actually bites:

  > take one buffer, swap **only** the magic, and assert the error **moves off** `CorruptPart`.

  Against MXD5's layout the probe lands on `BelowArgonFloor` (its zeroed `(m,t,p)`); against
  MXKB's it lands on `UnsupportedVersion(2)`. Either proves the length gate was cleared and the
  **magic** did the rejecting. Feed `unseal_seed` a **93-byte** `MXBU`-prefixed buffer for the
  reverse direction, so its length gate cannot mask its magic gate. Phase 5's `value_locks.rs`
  test must use this shape, not variant-assertion alone.

The container body is a canonical `crates/encoding` struct (new `type_id` — **`0x000F`**; see
below), not tar or zip. The repo has **no** archive crate deps and adding one is avoidable:
`pg_dump -Fc` compresses the dump internally, and every other entry is a few KB.

**The container struct lives in `crates/encoding/src/structs.rs`, not in `crates/server`.**
The `Field` trait is `pub(crate)` (`encoding/src/types.rs:14`), so a `Canonical` impl outside
`maxsecu-encoding` cannot use `Id::put` / `Text::get` / `Option<T>` and would have to hand-roll
raw `Writer`/`Reader` calls — bypassing the strict-decode layer that makes the encoding safe.
The private `is_registered()` could never learn an id defined in another crate either.
`backup/format.rs` holds MXBU seal/unseal **only**, and calls `maxsecu_encoding::{encode, decode}`.

**The container body carries per-part metadata and digests — never the part payload bytes.**
`decode()` runs a re-encode guard (`encoding/src/lib.rs:112-121`: `if encode(&v) != bytes`),
allocating a complete second copy of the value. Embedding an N-byte payload costs ~3N RAM and
destroys this design's O(part size) property outright. (Secondary: `Writer::var` does
`self.u32(b.len() as u32)` with **no overflow check** — a >4 GiB field silently truncates its
length prefix rather than erroring.)

## DB restore: merge

The live DB is usually **ahead** of the backup, so a blind `pg_restore --clean` would undo
real user state — a user who enrolled since would be stranded holding a keyblob the restored
server has never heard of. That is the `2a626d6` failure mode exactly.

Merge is `INSERT ... ON CONFLICT DO NOTHING` in FK order: add back what is missing, never
touch a live row. It is safe here because the PKs are random `BYTEA(16)` values with no
`DEFAULT`, no `IDENTITY` and no sequence — **there are no sequences to collide**. (Precision:
`file_id` is *client*-generated (`schema.sql:129`), but `user_id` is **server**-assigned
(`schema.sql:47`, minted by `random_array::<16>()`). The provenance differs; the
no-sequence property — the half the merge safety actually rests on — holds for both.)

Use **bare** `ON CONFLICT DO NOTHING` with no conflict target. An explicit target arbitrates
only that one index, so a `users.username` unique violation would abort the restore. (Note it
suppresses unique/exclusion violations only — **not** FK or CHECK. That is safe here because the
backup was FK-consistent and the `users` merge precedes `files`.)

### Merge needs a scratch database

`pg_dump -Fc` is an **opaque archive** — only `pg_restore` reads it. `INSERT … ON CONFLICT DO
NOTHING` needs actual SQL rows, and cross-database `INSERT..SELECT` is impossible without
`dblink`/`postgres_fdw` — neither is in the repo, and adding a Postgres extension dependency to
the **dead-box recovery path** is a bad trade. An earlier draft never mentioned this step; it is
load-bearing, not an implementation detail:

```
restore --db-mode merge:
  1. server binary : unseal  ->  <staging>/db.dump
  2. driver script : createdb maxsecu_restore_<stamp>
                     pg_restore -d maxsecu_restore_<stamp> <staging>/db.dump
  3. server binary : merge::run(live, staged, &plan)      <- the only cross-DB step, in Rust
  4. driver script : dropdb maxsecu_restore_<stamp>
```

Step 2 is safe against the append-guard: `pg_dump` emits pre-data / data / **post-data**, and
triggers are post-data — the COPY lands before `control_log_append_guard_trg` exists. (Same
reason `--db-mode replace`'s `pg_restore --clean` into live is safe.) The guard only bites on
`INSERT`s into an already-built **live** schema — i.e. exactly the merge path, which is exactly
why `control_log` is skipped.

The gate is forced into Rust regardless: tombstones and `current_version` come from **live**, the
rows come from **staged**, and no single SQL statement can join across two databases.

`--dry-run` needs the scratch DB too — a dry run that cannot tell you *what the merge will do* is
worthless. (As built, dry-run runs the identical insert pass inside the SERIALIZABLE txn and
`ROLLBACK`s it, so the preview numbers are exactly the apply numbers — same code, no second query.)

**Two caller contracts phase 3's driver must honor (found building phase 2):**

- **The live `PgPool` handed to `restore_db_merge` must be `max_connections(1)`.** The stopped-server
  guard is `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <>
  pg_backend_pid()`. A pool with idle sibling connections of its own has `pid <> pg_backend_pid()`
  rows and **self-trips** the guard. This is *why* the scratch DB must be a separate **database**,
  not a schema: `datname = current_database()` is what stops the staged pool's connections from
  counting. Refusal is `BackupError::ServerStillConnected { others }`.
- **The API is a two-invocation flow, not one call.** `restore()` only unseals the dump to
  `<staging>/db.dump`. The driver then `createdb maxsecu_restore_<stamp>` + `pg_restore` into it,
  and calls `restore_db_merge(live, staged, apply)` (`apply = false` for `--dry-run`). The merge
  copies load-bearing timestamps (`used_at`, `revoked_at`, `expires_at`) **verbatim** — a consumed
  registration key or revoked session must not come back looking fresh.

### The server must be STOPPED for a merge

The gate reads tombstones + `current_version` from live, then inserts. A `delete_file` or
`delete_wrap` committing in between resurrects precisely what the gate exists to block — and
**no isolation level fixes it**: a REPEATABLE READ snapshot taken before the delete would still
re-insert the deleted rows, and SERIALIZABLE turns the race into a retry rather than a correct
merge. The driver `systemctl stop`s first, and restore verifies via `pg_stat_activity` that no
other application connection is live. (Worth noting `delete_wrap` is not even atomic against
itself today — three statements on `&self.pool`, which this work fixes.)

### Per-table verdict

| Tables | Action |
|---|---|
| `users`, `directory_bindings`, `registration_keys`, `first_admin_claim`, `recovery_account`, `sessions`, `auth_nonces` | **Merge.** Never deleted; live row wins on conflict. A consumed registration key cannot be re-opened — PgStore *marks* `used_at` rather than deleting, so the live row survives the conflict |
| `control_log`, `auth_events` | **Skip entirely.** The reason is `control_log`'s `BEFORE INSERT` append-guard (it fires *before* conflict arbitration, so `DO NOTHING` cannot save the txn) plus taking both IDENTITY-sequence `setval` fixups off the table. ⚠️ An earlier draft justified this with *"no `DELETE FROM` anywhere, so a live DB is always a superset."* **That argument proves too much** — `grep` finds no `DELETE FROM` for `sessions`/`auth_nonces`/`registration_keys`/`users`/`directory_bindings` either, so the same reasoning would skip every table and delete the feature. "Live is a superset" holds only for the same-box rollback; the dead-box / partial-loss case is the entire reason merge exists. See Known limitations — a merge can never repair a partially-lost `control_log` |
| `files`, `file_genesis`, `file_versions`, `file_streams`, `file_key_wraps` | **Merge, gated on tombstones.** See below |
| `file_tombstones`, `wrap_revocations` | **Merge, whole and first.** *(added during implementation — the draft's table omitted them entirely, which read as "skip".)* These are the gate's own inputs, and they are append-only *records of an absence*: merging them can only ever ADD a reason to withhold something, never resurrect anything. They go in **before** the gate reads live facts, in the same transaction, so a bundle's delete/revocation history is carried into a rebuilt live DB and still gates the NEXT merge. Safe to bulk-insert despite the shared append-only guard, because that guard is `BEFORE UPDATE OR DELETE` — unlike `control_log`'s `BEFORE INSERT` guard, which is exactly why `control_log` cannot be merged |

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
-- NB: writers MUST use `ON CONFLICT (file_id) DO NOTHING` — a deleted file_id can be
--     re-created by stage_version, and a plain INSERT would abort the delete txn.

CREATE TABLE wrap_revocations (
  file_id       BYTEA NOT NULL CHECK (octet_length(file_id) = 16),
  file_version  BIGINT NOT NULL,
  recipient_id  BYTEA NOT NULL CHECK (octet_length(recipient_id) = 16),
  revoked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, file_version, recipient_id)
);
-- append-only: maxsecu_forbid_update_delete
-- NB: `ON CONFLICT DO NOTHING` here too — re-revoking an already-revoked recipient
--     (or a retry) must not abort the caller's transaction.
```

`recipient_id` gets the same `octet_length = 16` CHECK the live `file_key_wraps` column carries
(`schema.sql:228`) — the draft omitted it. Copy the trigger attachment verbatim from an
existing append-only table (`schema.sql:78`) rather than re-deriving it.

Both tables get the **shared** `maxsecu_forbid_update_delete` guard. Worth banking explicitly:
that shared trigger **ignores** `maxsecu.allow_owner_delete` entirely (`schema.sql:27-31` — it
raises unconditionally; only the dedicated `file_genesis_guard()` / `file_versions_guard()`
consult the GUC). So a tombstone stays immutable **even inside `delete_file`'s own GUC-enabled
transaction**. The guard is `BEFORE UPDATE OR DELETE` only, so INSERT is unaffected.

Write sites:

- **`pg.rs delete_file` (~1331)** → one `file_tombstones` row per deleted `file_id`, inside the
  transaction it already opens (`self.pool.begin()` at :1338).
  **The INSERT must be `ON CONFLICT (file_id) DO NOTHING`.** A deleted `file_id` can be
  re-created: `stage_version` (:663, :675) re-inserts `files`/`file_genesis` with
  `ON CONFLICT DO NOTHING` and consults no tombstone, and `file_id`s are client-generated. A
  plain INSERT would hit the PK on the *second* delete of a reused id → `DeleteError::Store` →
  HTTP 500 (`http.rs:1934`), and **the owner could never delete their own file again.**
- **`pg.rs delete_wrap` (~1208)** → one `wrap_revocations` row.
  ⚠️ **The function is `delete_wrap` (`pg.rs:1170`), not `revoke_share` — no such function
  exists in the repo.** (Trait decl `store.rs:446`; handler `http.rs:1852`.)
  ⚠️ **It has NO transaction to be "inside".** All three of its statements run on `&self.pool`
  (autocommit, possibly different pooled connections), with no row lock. **This write site
  requires introducing a transaction** wrapping the DELETE + the INSERT. Without one they
  commit separately, and a crash between them leaves the wrap deleted with no revocation row —
  so a later restore re-inserts it and **hands a de-authorized recipient their wrapped DEK
  back.** That is precisely the failure this table exists to prevent. (While there: the
  `files.current_version` read is TOCTOU-racy against a concurrent `finalize_version`; a
  `FOR UPDATE` on that SELECT is the natural fix once a txn exists.)

**Do not** write a `wrap_revocations` row in `finalize_version` (`pg.rs:828-843`). That drops
the *prior version's* wraps and streams — version supersession, not revocation.

No FK to `files` on either table: the parent row is gone by design.

### Merge rule for the file family

> ⚠️ **Correction.** An earlier draft asserted *"the backup only ever contains current-version
> rows (supersession already pruned the rest)"* and gated the merge on **"versions that exist
> in live."** Both are wrong. `finalize_version` (`pg.rs:828-843`) deletes only the prior
> version's `file_streams` and `file_key_wraps` — its own comment says *"genesis + the prior
> manifest are retained"*, and `file_versions_guard()` makes a finalized row undeletable
> outside `delete_file`. **The prior `file_versions` row survives forever.** So "version exists
> in live" is a no-op gate: back up at version N → owner rotates to N+1 → live still has the
> `file_versions` row for N → restore re-inserts version N's `file_key_wraps`, which finalize
> deliberately deleted, and the FK accepts it because the parent row is still there. A
> recipient revoked **by rotation** gets their wrap back, and `GET /v1/files/{id}?version=N`
> serves it (`http.rs:1788`, `pg.rs:873-882`, `pg.rs:959-963`). Bounded (that version's
> ciphertext is gone) but a silent resurrection of a wrap the owner removed.
>
> **The gate is `files.current_version`, not version existence.**

Read tombstones from the **live** DB (they are append-only, so they survive), then per
`file_id` in the backup:

- Live has a `file_tombstones` row **and** no live `files` row → **skip the whole subtree.** The
  owner destroyed it.
  ⚠️ **The tombstone alone is NOT the gate.** `stage_version` re-creates a deleted `file_id`
  freely (`pg.rs:663,675` — `ON CONFLICT DO NOTHING`, no tombstone check) and `file_id`s are
  client-generated, so *"live has the file **and** a tombstone"* is a **reachable** state. The
  tombstone describes a **previous incarnation** of that id. A bare tombstone filter would refuse
  to merge a live, current file's lost subtree — permanently un-protecting it. So:
  `skip_subtree = tombstoned(file_id) && !live_files.contains(file_id)`.
- Live has the file → let `cur = live files.current_version`, then:
  - `file_versions` → **merge all, `WHERE finalized = true`.** Prior finalized rows are retained
    by design and carry the prior manifest; they are supposed to be there. Staged
    (`finalized = false`) rows are excluded: a backup taken mid-rotation contains one for `cur+1`
    (`discard_unfinalized` refuses to GC it once any version is finalized, `pg.rs:1300-1303`), and
    re-inserting it is harmless (`stage_version:698` deletes unfinalized rows before re-staging)
    but valueless — it re-creates state the client is expected to re-stage anyway.
  - `file_streams` → merge only `WHERE version = cur`. A superseded version's streams were
    pruned at finalize and their blobs are gone; re-inserting them creates zombie rows that
    404 on download.
  - `file_key_wraps` → merge only `WHERE file_version = cur` **and** no `wrap_revocations`
    row exists for `(file_id, file_version, recipient_id)`.
- Live lacks the file and there is no tombstone → **it was lost. Restore the whole subtree**
  (at the backup's own `cur`, since live has no `current_version` to gate on).

> ⚠️ **Correction to a correction.** The draft justified this branch with *"its blobs are still in
> the cold tier — **a cold copy is only removed on user delete**, and there was none."* **The
> premise is false.** `finalize_version` purges the cold copy on **every rotation**:
> `http.rs:1450-1457` — `for r in &prior_refs { st.blobs.delete_stream(r) }` — and
> `WriteBackTier::delete_stream` (`writeback_tier.rs:454-460`) drops **both** tiers.
>
> The first round of corrections caught `delete_chunk` as "a second cold-removal site" but audited
> only the call sites *inside* `writeback_tier.rs` and **missed the caller in `http.rs`**. The
> module's own inline comment at :455 ("the only time the cold copy is removed") is stale and
> should be fixed while implementing.
>
> Consequence: a restored file whose backed-up version was later superseded may have **no
> ciphertext anywhere**. That is not a new failure — the `= cur` gate already skips superseded
> streams — but the *justification* was wrong, and it makes the dead-box warning's wording wrong
> too (below).

Note a staged-but-unfinalized version `cur+1` may also appear in a backup: `discard_unfinalized`
refuses to GC staged rows once the file has any finalized version (`pg.rs:1300-1303`), so they
persist. Gating on `= cur` skips them, which is correct — a staged rotation is not user-visible
state, and the client re-stages on retry.

### Dead-box `--replace`

> ✅ **IMPLEMENTED** (round 6) as its own post-`pg_restore` subcommand, exactly as the round-5
> correction predicted it would have to be. The probe cannot live inside `restore()`: that call
> unseals the bundle to `<staging>/db.dump` and stops, and at that instant the restored
> `file_streams` rows do not exist yet, because `pg_restore` is the *driver's* next step. So it
> ships as `maxsecu-portable-server verify-restored-blobs` (the fifth subcommand, the shape R4-1
> already had to invent for the merge), engine-side as
> `backup::verify_stream_blobs(cold, refs) -> BlobResolution`, invoked by `restore-server.sh`
> after the `pg_restore` on **both** replace paths (live-with-`--force` and dead-box).
> It is **advisory**: it exits 0 even when it finds missing ciphertext and never drops a row.

With no live DB there are no tombstones, so a full replace resurrects files deleted between
the last backup and the crash. That knowledge genuinely died with the DB. Their blobs were
already purged, so restore should **verify every restored file's blobs resolve** and print the
ones that do not:

Probe `has_chunk(blob_ref, 0)` — **one HEAD per stream, not per chunk.** A removal purges the
whole stream (`delete_stream` → `self.cold.delete_stream`), so index 0 absent ⟺ the stream is
gone. Probing every chunk would multiply Dropbox calls by `chunk_count` for no extra signal.

⚠️ **The wording must name BOTH causes.** The draft said "likely post-backup deletions… their
owners can re-delete them", which mis-attributes: a post-backup **rotation** purges the prior
version's cold copy too (`http.rs:1450-1457` — see the correction above) and produces identical
symptoms, for which that advice is wrong.

```
warning: 3 restored files have missing ciphertext:
  a1b2…  b3c4…  d5e6…
these are post-backup deletions (their owners can re-delete them) or post-backup
rotations (the backed-up version's chunks were purged at finalize).
no rows were dropped — a cold-tier fault looks identical from here.
```

Do **not** auto-drop rows whose blobs are unreachable — that conflates "deleted" with
"Dropbox hiccuped during restore" and would permanently drop live files.

A `has_chunk` **error** (as opposed to `Ok(false)`) is a tier fault, **not** a missing file.
Collect those separately and print `warning: N streams could not be verified (cold tier fault)`.

## CLI

```
maxsecu-portable-server backup           [--keep N]
maxsecu-portable-server restore          --from latest|<stamp>
                                         [--only db,state,code,blobs]
                                         [--db-mode merge|replace]
                                         [--dry-run] [--force]
maxsecu-portable-server list-backups
maxsecu-portable-server restore-db-merge [--apply]   # driver-internal (phase 3)
```

**`restore-db-merge` is a fourth, driver-internal subcommand** the two-invocation flow requires:
`restore` unseals the dump to `<staging>/db.dump` and stops there; the driver `createdb` + `pg_restore`s
the scratch DB, then calls `restore-db-merge` to run the one cross-database step
(`restore_db_merge(live, staged, apply)`; `--apply` commits, bare is the rolled-back preview). The
scratch-DB URL carries the DB password, so — like the passphrase — **it arrives on stdin, never argv**
(argv is world-readable via `/proc`). The live pool it opens is `max_connections(1)` per the phase-2
driver contract.

> ⚠️ **FATAL GAP in the draft: restore had no way to FIND the bundle on a dead box.**
>
> The cold-tier location reaches the binary through `LauncherConfig`, which reads
> `MAXSECU_COLD_TIER` from `/etc/maxsecu/dropbox.env` and `MAXSECU_COLD_FS_DIR` from the unit.
> **A dead-box rebuild has neither** — and `/etc/maxsecu/dropbox.env` is *itself inside the state
> bundle*, i.e. it is state to be **restored**, not state restore can read. `config.rs:155` then
> resolves `cold_tier` to `Off` (its default, `config.rs:190`), `run.rs:36` returns the bare local
> `FsBlobStore`, no `ColdTier` is constructed at all, and this design's own fail-closed rule
> aborts. **Half the stated restore scope — the dead-box rebuild — was unimplementable.**
>
> The fix belongs in the **shell driver**, not the binary (`crates/server/src/backup/` may not
> read env at all; `LauncherConfig` reading env *is* its job):
>
> ```
> restore-server.sh --from latest [--cold-tier-fs <dir> | --dropbox-env <path>] [--force]
> list-backups                    [--cold-tier-fs <dir> | --dropbox-env <path>]
> ```
>
> The driver scrapes `MAXSECU_COLD_FS_DIR` / `EnvironmentFile=` out of the **live unit** when one
> exists (same-box rollback — the default and common case), and **requires** the flag when the
> unit is gone (dead box), exporting it before exec'ing the binary.

Passphrase arrives **on stdin, never argv** — argv is world-readable via `/proc`. This imposes a
contract on the drivers, and violating any part of it silently eats the passphrase while the
failure *looks* like "wrong passphrase":

- The scripts must **not consume stdin themselves** — let it flow to the binary.
- **Every** sub-command that is not the binary must be `</dev/null`-redirected: `su - postgres -c
  psql`, `git`, `cargo`, `systemctl`. Any one of them inheriting stdin drinks the passphrase.
- Any confirmation prompt must be `[ -t 0 ]`-gated (the pattern already at
  `install-server.sh:668`). A bare `read -r reply` would consume the passphrase line and then
  block forever.

`--db-mode` defaults to `merge` when a live DB exists and `replace` when it does not.
`--dry-run` unseals, verifies, prints the plan, and changes nothing.

**`--force`** (the draft gave it no meaning): it authorizes **`--db-mode replace` while a live DB
is reachable**. That combination is the `2a626d6` failure mode by construction — a wholesale
`pg_restore --clean` over live state — so it must never happen by accident. Nothing else in the
grammar consumes it.

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
| `crates/server/src/backup/format.rs` | MXBU seal/unseal **only** (the canonical container struct lives in `crates/encoding/src/structs.rs` — `Field` is `pub(crate)`) |
| `crates/encoding/src/structs.rs` | the MXBU container struct, `type_id` **`0x000F`** (`0x000E` is taken — see below) |
| `crates/server/src/backup/mod.rs` | backup/restore plan + execution over `ColdTier`. Unit-tested against `MemoryColdTier`, no network |
| `crates/server/src/writeback_tier.rs` | new `backup_copy_refs(&[(blob_ref, chunk_count)])` — driven by the DB's `file_streams`, **not** by `LocalIndex`. No eviction, no pin filter. Idempotent via `has_chunk` |
| `crates/server/src/tier.rs` | `ColdTier::list_prefix(&self, prefix) -> Result<Option<Vec<String>>, BlobError>` — new; **default `Ok(None)` = "this tier cannot list"**, following `broker_direct_link` (`tier.rs:195-202`), the repo's established capability pattern. There is no `Unsupported` variant to return: `BlobError` is a *struct*, not an enum. `Ok(Some(vec![]))` = "can list, no bundles". **`list-backups` must never collapse those two** — an empty list shown to an operator about to roll back is a trap; fail closed on `None`. Additive, internal Rust, not a frozen surface |
| `crates/portable-server/src/run.rs` | keep the concrete `Arc<WriteBackTier>` alongside the type-erased `Arc<dyn BlobStore>` (the `run.rs:64` sweeper pattern) so backup can reach it |
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

Two constraints this design must respect, neither of which is optional:

1. **The backup code may not read the environment at all.**
   `compat_server_reads_env_only_through_launcher_config` (`env_surface.rs:437`) walks **both**
   `crates/portable-server/src` *and* `crates/server/src` and fails on any
   `env::var("MAXSECU_*")` or `env::var("DATABASE_URL")` outside `LauncherConfig`. So
   `crates/server/src/backup/` takes every knob as a **function argument**. This turns the
   "prefer CLI flags" preference into a build-enforced rule.

2. **`--cold-tier-fs` reclassifies `MAXSECU_COLD_FS_DIR`.** It is currently
   `MAXSECU_COLD_FS_DIR|default` in `SERVER_ENV_SURFACE`, and the comment beneath the table
   (`install-server.sh:219-223`) explicitly justifies that with *"Neither script ever
   configures `fs`: a real deployment is either `off` or `dropbox`."* Adding the flag makes
   that statement **false**. The row moves to `|unit` and the justifying comment must be
   rewritten — otherwise the table documents a decision the script no longer makes.

   > ⚠️ **CORRECTION (an error in the first amendment).** That amendment claimed
   > `compat_both_deployment_paths_declare_the_same_env_surface` forces `SERVER_ENV_RECONCILE` to
   > move in lockstep. **It does not.** The test compares **name sets only**
   > (`env_surface.rs:342-343`, via `names_of`), and its own failure message says the tables must
   > *"[differ] only in what each one DOES with it."* Both names are **already** in
   > `SERVER_ENV_RECONCILE` as `|-` (`upgrade-server.sh:216-217`). Changing the *kind* on the
   > install side requires **no** upgrade-side change.

3. **⚠️ FATAL: `--cold-tier-fs` does not actually turn the fs tier on.** Setting
   `MAXSECU_COLD_FS_DIR` is **not sufficient** — `config.rs:155` gates the entire fs branch on
   `MAXSECU_COLD_TIER`:

   ```rust
   let cold_tier = match env("MAXSECU_COLD_TIER").as_deref() {
       Some("fs") => { let dir = env("MAXSECU_COLD_FS_DIR") … ColdTierCfg::Fs(dir) }
   ```

   `MAXSECU_COLD_TIER` is classified `envfile`, and its **only writer is the Dropbox branch**
   (`install-server.sh:635`), which `--no-dropbox` skips entirely. So
   `install-server.sh --cold-tier-fs <dir> --no-dropbox` yields `cold_tier = Off`, **no
   `WriteBackTier`**, and `backup-server.sh` fails closed. The E2E could not reach step 2.
   `MAXSECU_COLD_TIER` must also be unit-written when `--cold-tier-fs` is given. Two sharp edges:

   - **`EnvironmentFile=` is emitted AFTER every `Environment=` line** (`install-server.sh:721-738`),
     so systemd lets the envfile win: a leftover `/etc/maxsecu/dropbox.env` would silently
     override `MAXSECU_COLD_TIER=fs` in the unit. `--cold-tier-fs` and `--dropbox` must be
     **mutually exclusive**, and `--cold-tier-fs` must refuse to proceed if `dropbox.env` exists.
   - **`assert_env_surface_written` hardcodes `unit-opt` to mean "required iff `PUBLIC=1`"**
     (`install-server.sh:757`: `unit-opt) [ "$PUBLIC" -eq 1 ] || continue`). A `--cold-tier-fs`-gated
     row needs a new kind (e.g. `unit-fs`) or a per-name condition.

## Compat obligations

A bundle written today must be readable by **every future version, forever** — otherwise the
rollback fails exactly when you need it. This is **new frozen surface #12**.

- `docs/compat/CHECKLIST.md` — add surface #12. Also update surface #5's `type_id` count
  **13 → 14**.
  > ⚠️ **CORRECTION (an error in the first amendment).** That amendment said to bump *both* halves
  > of "13 `type_id`s + 13 `labels::*`". **Only the `type_id` count moves.** `0x000F` adds a
  > `type_id` and **no `labels::*` constant** — the MXBU container is never signed, so it needs no
  > domain-separation label. `labels` has exactly 13 today (`DIRBINDING` … `DIRECTORY_DELEGATION`,
  > `encoding/src/lib.rs:182-218`) and stays 13. Bumping both would make the surface wrong in the
  > other direction. The line becomes: **14 `type_id`s + 13 `labels::*`**.
- `compat/fixtures/backup/` — `backup_v1.bin` + `.passphrase.txt` + `.expect.json` + `corpus.lock`.
  **The area must be FLAT**: the shared `verify_corpus_lock` (`compat/src/lib.rs:134-152`) reads
  only an area's top level and asserts every file present is locked, so a `parts/` sub-dir would
  fail it (that is exactly why `client-state` needed a bespoke recursive checker).
- `crates/compat/tests/golden_open.rs` — add `backup` to `AREAS` (**note it is length-annotated
  `[&str; 6]` → must become `[&str; 7]`, and its doc comment says "six"**) + a
  `compat_frozen_backup_still_unseals` test.
- `crates/compat/tests/value_locks.rs` — MXBU/MXD5/MXKB mutual-unopenability (**see the
  half-vacuous-test warning above — a variable-length MXBU bundle fails `unseal_seed` on the
  length gate, proving nothing; use a 93-byte `MXBU`-prefixed buffer**); `_backup` vs blob_ref
  non-collision. **Pin the builder, not a guard**: `files.rs:414` is the sole production
  `blob_ref` builder and `[u8;16] → 32 hex` is what makes the invariant true. Nothing
  re-validates the prefix on read (`stream_dir` / `guard_blob_ref` only reject non-`Normal`
  path components), so asserting on a guard would pin the wrong thing.
- `docs/compat/LEDGER.md` — one entry covering the new format, the new `encoding` type_id
  (additive to surface #5), and migration 0002 (additive to surface #9)
- `crates/compat/tests/schema_equivalence.rs` — **needs no code change.** The test is generic over
  `migrations()` + `include_str!(docs/schema.sql)`, so it picked 0002 up with zero edits and
  `compat_fresh_install_equals_upgraded_install` passed unmodified *(verified against live PG,
  2026-07-16)*. The invariant is **not** `schema.sql == 0001_baseline.sql`; it is
  `schema.sql ≡ 0001 + 0002 + …` (catalog-equal). **0001 is frozen** — edit `docs/schema.sql`,
  add `migrations/0002_*.sql`, re-pin `compat/schema.lock`. Never touch 0001.
  One stale **comment** to refresh (it asserts nothing, so it cannot fail — but it lies):
  `schema_equivalence.rs:654` says "14 tables, 6 triggers, 5 trigger functions, 2 column
  comments"; post-0002 the true counts are **16 tables, 8 triggers**, 5 trigger functions
  (unchanged — 0002 reuses the shared guard rather than adding one), 2 column comments.

### The type_id is `0x000F`, not `0x000E`

⚠️ **`docs/encoding-spec.md` §5 — the registry an implementer would naturally consult — is
STALE.** Its table stops at `0x000D` and §9 still says "twelve structures". The code registers
**thirteen**, through `0x000E` = `BundleBody` (`encoding/src/lib.rs:62`, `structs.rs:489`),
added later without updating the doc. Allocating "the next free id" from the doc picks `0x000E`
and **collides with the body of every bundle post on the VPS right now** — and would fail
`value_locks.rs:78`'s `lock!(BundleBody, 0x000E, …)`.

Fix the doc as part of this work: add **both** the missing `0x000E` row and the new `0x000F`
row to §5, and correct §9's count. Also stale at 14: `encoding/src/lib.rs:48` ("the 13
structures of §4") and `CHECKLIST.md:21`. `is_registered()` is diagnostics-only — **not** an
exhaustive match — so the compiler will *not* catch a missed update.

### Minting the fixture

Build it **from the documented byte layout, not by calling `seal`** — copying the deliberate
`build_keyblob` pattern (`golden_open.rs:687`), so the gate proves we can open *foreign* bytes
rather than round-tripping ourselves. Use `ARGON2_FLOOR` in the fixture to keep the gate fast
(which is why `unseal` must not pin `ARGON2_DESKTOP_TARGET`).

⚠️ **Do not mint it with `compat_emit_fixtures`.** That generator (`golden_open.rs:829`) is
all-or-nothing and **non-deterministic**: it loops every area and regenerates every identity via
`generate_enc_keypair()` / `SigningKey::generate()` with fresh `random_array()` salt+nonce.
Running it to produce `backup_v1.bin` would rewrite **all six existing areas** with brand-new
key material → every sha256 in every `corpus.lock` moves → `compat_corpus_is_locked` fails
**and** the pre-push hook flags every fixture as tampered (`scripts/hooks/pre-push:170-174`).

Add a **separate `#[ignore]`d `compat_emit_backup_fixtures`** that writes only
`compat/fixtures/backup/*` and calls the existing `emit_corpus_lock("backup")`. Once `backup`
is in `AREAS`, a future `compat_emit_fixtures` run will `create_dir_all` + `emit_corpus_lock`
for it — harmless (it re-hashes what is on disk), but the two generators must never both
author the bytes.

The corpus is add-only. **Editing a fixture is never the fix.**

## The test — `scripts/test-backup-rollback.ps1`

`MAXSECU_COLD_FS_DIR` points **outside** the data dir, making `FsColdTier` a credential-free
Dropbox for both blobs and bundle parts. (The default `<data_dir>/cold/` would be destroyed
by step 3.)

1. Install server in WSL with cold-tier=fs → build the real client →
   `live-smoke --phase seed` enrolls, uploads, records the `file_id` + **the sealed app-dir path**
   to a state file
2. `backup-server.sh`
3. **Destroy:** `rm -rf ~/maxsecu-server-data` + `DROP DATABASE maxsecu` + **`DROP ROLE maxsecu`**
   + `rm -rf /etc/maxsecu` + delete the unit
4. `restore-server.sh --from latest --cold-tier-fs <dir>`
5. `live-smoke --phase verify` — **same** `dist\MaxSecuClient`, no re-enroll, no re-pin,
   byte-compares the file back

Step 5 is the point: it is a direct executable assertion of the CLAUDE.md rule.

**Five corrections to the draft's test design:**

- ⚠️ **"records the owner seeds" is not implementable.** `Identity::secret_bytes()` is
  `pub(crate)` (`identity.rs:153`), and the only reassembler is `from_test_seeds`, gated behind
  `#[cfg(feature = "test-support")]` — which `client-core/Cargo.toml:32-36` states is *"enabled
  only by the client↔server e2e suite … **MUST NEVER SHIP**"*. Enabling it for live-smoke would
  violate that and give live-smoke a second reason to diverge from the shipped client — the exact
  thing the `-p maxsecu-live-smoke` rule exists to prevent.
  **Persist the sealed app-dir and record its path instead.** This is strictly better, not a
  workaround: verify then goes through `keystore::unlock` → `keyblob::unlock`, the real client's
  at-rest path, which is a *more* faithful reading of "no re-enroll" than reconstituting seeds by
  hand.
- ⚠️ **The cited reusable machinery is misattributed.** `view_own_blog` spans `steps.rs:114-155`
  (not 117-155) and contains **no byte-compare** — it returns the plaintext. The compare lives in
  the caller (`steps.rs:226-228`) and is against the **compile-time const `BLOG_BODY`**, which
  cannot serve verify. So: `view_own_blog` reuses **verbatim**; the compare is **rewritten** as a
  digest compare against the state file.
- ⚠️ **`DROP DATABASE` alone leaves the role — and with it, the dead-box path untested.** The
  `maxsecu` role's password is per-install random and exists **only** in
  the unit's `Environment=DATABASE_URL=`.

  > **AMENDED 2026-08-02 — still per-install random, but no longer minted on EVERY run.** The
  > citation above (`install-server.sh:421`) is stale, and so is the implicit assumption behind it.
  > `scripts/install-server.sh:854-961` now **reuses** the password recovered from the unit whenever
  > the `maxsecu` role exists **and** that credential is proven to connect; it mints and `ALTER
  > ROLE`s only on a genuine `CREATE ROLE` (`:935`) or when nothing usable could be recovered
  > (`:931`). Anyone re-deriving the restore role-reconciliation from this spec must read
  > `scripts/restore-server.sh:905-928`'s comment, **not** this paragraph — the reconcile is still
  > REQUIRED, but the three paths that can still produce `P_new != P_old` are named there, not here. If the role survives the destroy, the restored unit's
  `DATABASE_URL` still authenticates and restore never has to re-create it — so the real dead-box
  shape (parse the password out of the bundled unit, `CREATE ROLE` + `CREATE DATABASE`) **ships
  untested**. Drop the role too (order per `install-server.sh:302-304`: database, then role).
- ⚠️ **A blog-only E2E cannot cover the pinned-stream path at all.** `prepare_blog_streams` sets
  `thumbnail: None, preview: None` (`upload.rs:425-432`) and live-smoke only uploads
  `FileType::Blog` (`steps.rs:85`). But **pinned Thumbnail/Preview streams are correction #1's
  headline failure** — a green E2E would prove nothing about the bug we corrected. **Seed must
  also upload an image** via the already-`pub` `prepare_image_streams` (`upload.rs:437`) — pure
  Rust via `RustImageCodec`, so it works under `default-features = false`. ~10 lines; it is the
  only way anything proves a pinned blob round-trips through a real cold tier.
- ⚠️ **`.git` is excluded from the source copy** (`test-full-install.ps1:116`), so `~/maxsecu` in
  the distro is not a git checkout. `backup-server.sh` must therefore **tolerate "not a git
  checkout"** (precedent: `upgrade-server.sh:343`) and record `git_sha: null`, with restore
  treating `null ≡ null` as agreement rather than a mismatch — otherwise **backup itself fails**.
  Testing `--only code` for real needs an opt-in `-IncludeGit` switch.

**Two safety rails the E2E needs, because its blast radius is the operator's real machine:**
`wsl.exe -d '' ` targets the **default distro**, so a `$null`/typo'd distro name would run
`rm -rf /root/…` against it. Guard on `$Distro -notlike 'maxsecu-bkup-*'` before any destructive
command, and assert the cold dir resolves **outside** the data dir before backing up — the default
is `<data_dir>/cold` (`config.rs:158`), i.e. *inside*, so a regression in the `--cold-tier-fs`
wiring would make the E2E destroy its own backup and report a restore bug that isn't there.
Positively assert the destruction happened, too — otherwise a "passing" restore may just be a
destroy that didn't, which is how this class of test rots into a tautology.

### Where each case is tested

The E2E costs tens of minutes; `crates/server/tests/pg_store.rs` (a live-PG harness that already
loads the real `schema.sql` into a fresh schema) costs milliseconds. **`MemoryColdTier` is the
wrong tool for the merge cases** — the merge is SQL and the memory tier has no DB at all.

| Case | Home | Why |
|---|---|---|
| merge-with-live-ahead | **Both** — `backup_merge.rs` for row-level truth + one ~2-min E2E scenario (no destroy needed) | "Cannot strand a user" is the rule this feature exists for; the Rust test cannot prove the dump→scratch→merge plumbing |
| delete-then-restore (tombstone honored) | **Rust only** — `backup_merge.rs` | Pure DB semantics. Also the home for the `ON CONFLICT (file_id) DO NOTHING` regression |
| revoke-then-restore (wrap not resurrected) | **Rust only** — `backup_merge.rs` | Also pins the `= cur` gate: rotate to N+1, restore a backup at N, assert version-N wraps are **not** re-inserted |
| `--only code` | **E2E only** | It is `git checkout` + `cargo build` + `systemctl restart` — there is no Rust to test. Default run asserts the fail-closed no-`.git` path; `-IncludeGit` exercises it for real |
| `--dry-run` changes nothing | **Rust primary** + 3 E2E lines | Rust proves the engine; the E2E is the only place that proves the *driver* doesn't `systemctl stop` before honoring the flag |
| wrong passphrase fails cleanly | **Rust primary** + 3 E2E lines | The E2E catches a driver that half-applies (stops the unit, then fails to unseal, leaving the box down) |

## Known limitations

- **Rollback loses what happened in between.** Inherent. `--db-mode merge` is the mitigation:
  it adds back what is missing and never removes what is new, so it cannot strand a user.
- **Dead-box replace can resurrect post-backup deletions.** Reported, not silently swallowed.
- **⚠️ `--db-mode replace` silently resurrects revoked wraps, and this is UNDETECTABLE.** The
  tombstone / `wrap_revocations` gate is **merge-only**; `replace` is a wholesale `pg_restore` of
  the backup's `file_key_wraps` as of backup time. A post-backup `delete_wrap` is **worse than a
  post-backup delete**: the file was never deleted, so its ciphertext still exists and resolves —
  meaning the blob-resolution warning above **cannot see it**. The de-authorized recipient
  silently regains a working DEK and *nothing prints*. This is why `replace` over a live DB
  requires `--force`, and why `merge` is the default wherever a live DB exists.
- **⚠️ A wrap that was revoked and later RE-SHARED at the same version is never restored
  by a merge.** `delete_wrap` writes a permanent `wrap_revocations` row and `gate::wrap_verdict`
  returns `SkipRevoked` for any wrap matching one — with no notion of the grant being
  re-issued afterwards. `add_wrap` re-grants at `files.current_version`, i.e. the SAME
  `(file_id, file_version, recipient_id)` key, and the revocation row is immutable, so the two
  coexist forever. If live then loses that wrap, the merge will not put it back.
  **Deliberately not fixed in code.** The only discriminator available is `created_at` vs
  `revoked_at`, and both are advisory (§7.5); ranking them would hinge the one gate that stops
  a de-authorized recipient recovering their DEK on a timestamp an operator can move. It
  **fails closed** (a user loses access rather than an unauthorized party gaining it) and it is
  **repairable without loss**: the owner re-shares. No re-enroll, no re-key, no re-upload — so
  it is not a CLAUDE.md-class break.
- **Manifest-less orphan bundle directories are never reaped.** A run that dies between its
  first sealed part and `commit_bundle` leaves a stamp dir with no `manifest/0`. `prune` filters
  to manifest-bearing stamps, so an orphan can never displace a good bundle — but nothing
  deletes it either. **Deliberate.** An orphan costs only storage; an age-bounded reaper could
  delete parts out from under a still-running backup, which would then write its manifest over
  an incomplete part set and produce a *listed bundle that cannot restore*. No age bound
  separates the two reliably (a slow first upload can outlast any threshold). The runbook tells
  the operator to remove them by hand.
- **No Dropbox `429` / `Retry-After` back-off**, and `backup_copy_refs` issues one
  un-throttled `get_metadata` per chunk — the workload most likely to trip a rate limit.
  Pre-existing (this change only adds `list_prefix` to that adapter) and it **fails closed**:
  `is_path_not_found` matches only a `409` carrying `path/not_found`, so a `429` becomes a hard
  error, never a phantom "chunk absent". It therefore cannot produce an under-copied bundle the
  operator believes is complete. Backup is idempotent and resumes, so the cost is a re-run.
- **A merge can never repair a partially-lost `control_log`.** It is skipped (the append-guard
  makes merging it impossible), so the anchored chain is recoverable only via `replace`.
- **Tombstones only exist going forward.** A file deleted by pre-0002 code left no record, so
  a merge from a bundle predating this feature could resurrect it. Bundles are short-lived
  (retention 10); the window closes on its own.
- **One-shot Argon2id per bundle.** A weak passphrase is the whole security of a bundle sitting
  in Dropbox. 12-char minimum is a floor, not a guarantee.

---

## Corrections (2026-07-16)

Every claim in the approved draft was re-verified against source before implementation began.
The architecture survived; **ten** load-bearing details did not. Recorded here because the
draft was confidently wrong in ways that read as plausible — the same failure mode that
produced the false "rollback re-opens `first_admin_claim`" claim caught during design.

| # | The draft said | Reality | Where |
|---|---|---|---|
| 1 | `backup_copy_all()` — mirror the idle-offload path, minus the eviction | **Would back up ZERO chunks after a restart.** `LocalIndex` is in-memory and lazily populated; the pin filter excludes all thumbnails/previews; `BlobStore` has no enumeration method at all. Now DB-driven off `file_streams` | `writeback_tier.rs:118,237,384`; `blob.rs:84-135` |
| 2 | "The backup only ever contains current-version rows (supersession already pruned the rest)" | **False.** `finalize_version` prunes only `file_streams`+`file_key_wraps`; the prior `file_versions` row is retained forever. The merge gate keyed on this and was unsound — it would resurrect wraps revoked by rotation | `pg.rs:828-843`; `0001_baseline.sql:200-218` |
| 3 | Write site `pg.rs revoke_share` (~1208), "inside the existing transaction" | **No such function.** It is `delete_wrap` (`pg.rs:1170`) — the only `revoke_share` in the repo was the spec line itself. And it has **no transaction**: three statements on `&self.pool`. One must be introduced, or a crash loses the revocation and restore hands back a de-authorized recipient's DEK | `pg.rs:1170-1219` |
| 4 | New `encoding` type_id (implicitly `0x000E`, per `encoding-spec.md` §5) | **`0x000E` is taken** by `BundleBody`. The doc is one release stale. Next free is **`0x000F`**; `0x000E` would collide with every bundle post on the VPS | `encoding/src/lib.rs:62`; `structs.rs:489`; `value_locks.rs:78` |
| 5 | Canonical container lives in `crates/server/src/backup/format.rs` | Contradicts the spec's own line 108, and is impractical: `Field` is `pub(crate)`, so a `Canonical` impl outside `maxsecu-encoding` cannot use it. Container → `encoding/src/structs.rs` | `encoding/src/types.rs:14` |
| 6 | `ColdTier::list_prefix` "defaulted to **Unsupported**" | No such variant exists — `BlobError` is a **struct**, not an enum; zero hits for `Unsupported` in `crates/server/src/`. Repo pattern is `Ok(None)` (`broker_direct_link`) | `blob.rs:22-35`; `tier.rs:195-202` |
| 7 | Reuse `nonce_for(nonce_base, part_index)` | No such helper. The only `nonce_for` is **private**, **single-arg**, and there is no `nonce_base` concept anywhere. Must be written locally | `crypto/src/aead.rs:26-31`; `lib.rs:26-29` |
| 8 | `file_tombstones` — `file_id BYTEA PRIMARY KEY`, plain INSERT | A deleted `file_id` **can be re-created** by `stage_version`, so the second delete hits the PK → 500 → **the owner can never delete that file again.** Needs `ON CONFLICT DO NOTHING` | `pg.rs:663,675,1412,1417`; `http.rs:1934` |
| 9 | Add `backup` to `AREAS` + mint the fixture | `compat_emit_fixtures` is all-or-nothing and **non-deterministic** — running it rewrites all six existing areas with fresh key material and trips the corpus lock + pre-push hook. Needs a separate `#[ignore]`d emitter. (`AREAS` is also `[&str; 6]` — a compile error, not a silent one) | `golden_open.rs:49-58,829-841` |
| 10 | MXBU/MXD5/MXKB mutual-unopenability, "only the magic keeps them apart" | **Half-vacuous.** `unseal_seed` checks length *before* magic, so a variable-length MXBU bundle fails on length having never read the magic. The model test at `value_locks.rs:417` already has this hole | `seedblob.rs:74-80` vs `keyblob.rs:106-111` |

Two **latent tightening traps** were also identified and headed off, both of which the
CHECKLIST forbids ("a stricter check that rejects data the previous version wrote is a break
even when it is more secure"):

- `unseal` must not require `params == ARGON2_DESKTOP_TARGET` — it would reject the
  `ARGON2_FLOOR` fixture *and* brick every bundle the day the target is retuned.
- The 12-char passphrase minimum must gate **seal only**. On unseal, any future raise of the
  minimum retroactively bricks every bundle already written under a shorter passphrase.

Smaller precision fixes folded into the body: the `allow_owner_delete` GUC punches through two
*dedicated* guards, not the shared `maxsecu_forbid_update_delete` (which is why tombstones stay
immutable even inside `delete_file`'s own txn — good news, now stated); the CASCADE hangs off
`file_versions`, not `files`; `user_id` is server-assigned, not client-generated; `delete_chunk`
is a *second* cold-removal site alongside `delete_stream`; the container body must hold
metadata only (`decode()`'s re-encode guard costs ~3N); `compat/fixtures/backup/` must be flat;
and `crates/server/src/backup/` may not read env at all (`env_surface.rs:437` walks it).

## Corrections, round 2 (2026-07-16)

A second verification pass — one agent designing the engine, one designing the E2E, both reading
source — found **twenty** more defects, including two that made the feature **unimplementable as
written** and one latent **nonce-reuse** hazard.

**Three of round 1's own corrections were wrong.** Recording that explicitly: a single verification
pass over a spec of this surface area is demonstrably not enough, and the corrections table is not
self-certifying.

### Severe

| # | Draft said | Reality | Where |
|---|---|---|---|
| **R2-1** | `restore --from latest\|<stamp>` — no source-locator | ⚠️ **FATAL.** A dead box has no unit and no `/etc/maxsecu` (the latter is *inside the bundle*), so `LauncherConfig` → `cold_tier: Off` → no `ColdTier` → fail-closed abort. **The dead-box rebuild — half the stated restore scope — could not run.** Needs `restore-server.sh --cold-tier-fs <dir> \| --dropbox-env <path>` | `config.rs:155,190`; `run.rs:36` |
| **R2-2** | `--cold-tier-fs` reclassifies `MAXSECU_COLD_FS_DIR` (round 1's own text) | ⚠️ **FATAL.** Necessary but **not sufficient** — `config.rs:155` gates the fs branch on `MAXSECU_COLD_TIER`, whose only writer is the Dropbox branch, which `--no-dropbox` skips. Result: `cold_tier = Off`, no `WriteBackTier`, backup fails closed. **The E2E could not reach step 2** | `install-server.sh:211,635`; `config.rs:155` |
| **R2-3** | "45-byte header" + "DB and state are independently sealed" | ⚠️ **Latent two-time pad.** `nonce_for` takes no component input. One header per *backup* ⇒ `db/0003` and `state/0003` seal different plaintexts under the same `(key, nonce)` ⇒ GCM plaintext-XOR **and** auth-key recovery ⇒ forgery. Now mandates one sealer (fresh salt + nonce_base) **per component**. *(Implementation note: this round-2 text also called for a container `component` tag; the implementation correctly reasoned it redundant — different salts already give different keys — and the spec now matches the code. Its trailing "header in part 0 only" is likewise superseded: every part repeats the header and `open_part` byte-compares it — see R5-1)* | — |
| **R2-4** | Merge = `INSERT … ON CONFLICT DO NOTHING` from the backup | **Nowhere to read the rows from.** `pg_dump -Fc` is opaque; cross-DB `INSERT..SELECT` needs `dblink`/`postgres_fdw` (absent; a bad dep for the dead-box path). **Merge requires a scratch database** — never mentioned | — |
| **R2-5** | *(round 1's correction #4)* `delete_chunk` is a second cold-removal site | **Incomplete — and it makes the merge rule's justification false.** `finalize_version` purges cold on **every rotation** (`http.rs:1450-1457` → `delete_stream` → both tiers). Round 1 audited only call sites *inside* `writeback_tier.rs` and missed the caller. So "a cold copy is only removed on user delete" is **false** | `http.rs:1450-1457` |
| **R2-6** | Known limitations cover "post-backup deletions" | **`--db-mode replace` silently resurrects revoked wraps, undetectably.** The gate is merge-only; the file still exists so its ciphertext resolves and the blob warning **cannot see it**. Worse than the deletion case, and unlisted | — |

### The rest

| # | Draft said | Reality |
|---|---|---|
| R2-7 | *(round 1)* `SERVER_ENV_RECONCILE` must move in lockstep | **Wrong — my error.** The test compares **name sets only**; both names are already present as `\|-`. No upgrade-side change needed |
| R2-8 | *(round 1)* CHECKLIST #5: "13 `type_id`s + 13 `labels::*`" → 14 | **Wrong — my error.** Only `type_id`s → 14. `0x000F` adds **no label** (the container is never signed); `labels` stays 13 |
| R2-9 | Skip `control_log`: "no `DELETE FROM` anywhere, so live is always a superset" | **Proves too much** — the same argument holds for `sessions`/`users`/`directory_bindings`/… and would skip every table, deleting the feature. Real reason: the `BEFORE INSERT` append-guard + the IDENTITY `setval`s |
| R2-10 | `{root}/_backup/<stamp>/manifest.json` | **Unreachable.** `put_chunk` realizes `{root}/{blob_ref}/{index}`, so that path yields a *directory* named `manifest.json` holding a file `0`. It is `manifest/0` |
| R2-11 | manifest carries "per-part digests" | **Must be over the CIPHERTEXT.** Plaintext digests in a world-readable file beside the bundle are a confirmation oracle over the dump — near-direct for the small, guessable state bundle |
| R2-12 | `--dry-run` … `--force` | **`--force` had no defined meaning.** It authorizes `replace` over a **live** DB — the `2a626d6` shape by construction |
| R2-13 | *(unstated)* | **Nothing said the server must be STOPPED.** The gate reads live, then inserts; a concurrent `delete_file`/`delete_wrap` resurrects exactly what it blocks, and **no isolation level fixes it** |
| R2-14 | `file_versions` → "merge all" | **Ambiguous.** A mid-rotation backup carries a `finalized = false` row for `cur+1`. Now `WHERE finalized = true` |
| R2-15 | "Live has a `file_tombstones` row → skip the whole subtree" | **Undefined precedence.** `stage_version` re-creates a deleted `file_id` freely, so "live has the file **and** a tombstone" is reachable. A bare filter would refuse to merge a live, current file's lost subtree. Gate is now `tombstoned && !live_files.contains(fid)` — **the live row wins** (operator decision, 2026-07-16) |
| R2-16 | seed "records the `file_id` + **owner seeds**" | **Not implementable.** `secret_bytes()` is `pub(crate)`; the only reassembler is behind `test-support`, which "**MUST NEVER SHIP**". Persist the sealed **app-dir** instead — strictly better (verify goes through the real `keystore::unlock`) |
| R2-17 | "`view_own_blog` + byte-compare … `steps.rs:117-155` is reusable" | **Misattributed.** It is 114-155 and has **no** byte-compare; the compare is at :226-228 against a compile-time const, useless to verify |
| R2-18 | Step 3 destroy = `rm -rf` + `DROP DATABASE` + delete the unit | **Leaves the role**, whose per-install random password lives only in the unit — so the restored `DATABASE_URL` still authenticates and **the dead-box role-recreation path ships untested**. `DROP ROLE` too |
| R2-19 | *(unstated)* | **The E2E structurally cannot cover pinned streams** — `prepare_blog_streams` sets `thumbnail/preview: None` and live-smoke only uploads blogs. That is correction #1's *headline* failure, so a green E2E would prove nothing about it. Seed must also upload an image |
| R2-20 | manifest carries the git SHA; `--only code` = `git checkout` | **`.git` is excluded from the source copy**, so the distro tree is not a checkout. `backup-server.sh` must tolerate that (precedent: `upgrade-server.sh:343`) and restore must treat `null ≡ null` as agreement — else **backup itself fails** |

## Corrections, round 3 (2026-07-16) — found by implementing phase 1

Phase 1's three tracks each found further defects while building against the twice-amended spec.
**Four more of my own corrections were wrong.** The pattern is now unambiguous and worth stating
for whoever reads this next: *on a surface this size, a correction is a hypothesis until code
executes it.*

| # | Said | Reality |
|---|---|---|
| **R3-1** | *(task brief + round-1 text)* "the local gate CANNOT run `pg_store` — no live PG on this machine" | **FALSE, and it mattered.** WSL `Ubuntu-22.04` has PG14 with role/db `maxsecu` provisioned; the old blocker was **IPv6** (`localhost`→`::1` is dead into WSL under mirrored networking) and `127.0.0.1` fixes it — already recorded in project memory. Phase 1b ran the **full** `pg_store` suite *and* the pg-backed `compat_fresh_install_equals_upgraded_install` for real. **Phase 2's merge rule — the riskiest part of this feature, and the part already got wrong once — must be tested against live Postgres, not reasoned about** |
| **R3-2** | `SELECT blob_ref, chunk_count FROM file_streams` | **Unfiltered — a phase-2 blocker.** Returns **staged, not-yet-finalized** streams, whose `chunk_count` is the *intended* count, not what is on disk. It would turn a user's ordinary in-flight upload into `missing_local` noise, or a failed backup. Must join `files.current_version` |
| **R3-3** | *(round-2 Components table)* `list_prefix` default "returns `Ok(vec![])` + a capability flag" | **Self-contradictory — my error.** The same cell then demanded "no bundles" be distinguishable from "cannot list", and correction #6 said `Ok(None)`. `Ok(vec![])` collapses exactly the distinction it asks for. Built as `Result<Option<Vec<String>>, BlobError>`, `Ok(None)` = cannot list |
| **R3-4** | *(round-1 Compat obligations)* `schema_equivalence.rs` — "the two new tables" | **No code change needed — my error.** The test is generic over `migrations()` + `include_str!(schema.sql)` and picked 0002 up unmodified. Only a stale comment (14/6 → 16/8) wants refreshing |
| **R3-5** | *(round-2)* make the magic test non-vacuous by "asserting the specific error variant" | **That remedy is itself vacuous — my error.** In the MXBU direction the length gate and the magic gate **both** return `CorruptPart`. Needs a *differential probe*: swap only the magic and assert the error **moves off** `CorruptPart` |
| **R3-6** | `part_ct = AES-256-GCM(key, nonce_for(nonce_base, part_index), …)` | **The nonce construction was never defined** — on a surface that must stay readable forever, and whose fixture is minted independently from the documented layout. Now normative: XOR the BE `part_index` into `base[8..12]` (TLS 1.3 record-nonce shape) |
| **R3-7** | *(round-1)* `encoding-spec.md` §5 is stale | **The drift was two sections wide.** §4 also never got a `bundle_body` entry when `0x000E` landed, so fixing §9's count to "fourteen" while §4 defined twelve would have introduced a *new* inconsistency while fixing the old one |
| **R3-8** | `backup_copy_refs` sketch: `missing_local` on a cold-only chunk — "already cold-only: fine" | **Unreachable** — `has_chunk` already caught and `continue`d every cold-only chunk two lines above. `missing_local` means missing from **both** tiers, which is a real fault worth reporting, not a benign case |

## Corrections, round 4 (2026-07-16) — found building phase 3

| # | Reality |
|---|---|
| **R4-1** | The two-invocation restore **needs a fourth subcommand**, `restore-db-merge`, the spec's three-command CLI did not list. `restore` cannot both unseal AND run the merge (the merge happens *after* the driver's `createdb`+`pg_restore`), so the binary is re-invoked. Now in the CLI grammar |
| **R4-2** | The scratch-DB URL **carries the DB password**, so passing it as `--staged-url <url>` on argv leaked it via `/proc` — violating the spec's own "never argv" discipline. Fixed: `restore-db-merge` reads the URL from **stdin**, like the passphrase |
| **R4-3** | `MAXSECU_COLD_FS_DIR` moved `\|default` → **`\|unit-fs`** (a new kind in `assert_env_surface_written`), not plain `\|unit` — it is written to the unit *only on the fs path*. `MAXSECU_COLD_TIER` stays `\|envfile` (its Dropbox-path home); the fs path is the one exception that also unit-writes it. env-surface gate stays green |
| **R4-4** | `backup-server.sh` must run the binary **as root** to read the root-0600 unit + `dropbox.env` — which trips git's dubious-ownership guard (git ≥2.35.2 refuses to run as root on a run-user-owned repo), silently recording `git_sha` null and disabling `--only code`. Worked around with a one-shot `safe.directory=*` in the binary's env; phase-4 `-IncludeGit` confirms it |
| **R4-5** | `--dry-run` row-level preview **requires a stopped server** (the merge's `ServerStillConnected` guard fires even at `apply=false`), conflicting with "dry-run must not stop the server". Resolved: on a running server `--dry-run` is plan-only (no stop); exact per-table counts only when the server is *already* stopped |

## Corrections, round 5 (2026-07-31) — found reviewing the completed implementation

Two places where this document described something other than what shipped. Both are documentation
defects with no runtime symptom, and both matter for the same reason: this spec is what a future
re-implementer — of a format that must open forever, or of an operator procedure taken on trust —
would build from.

| # | Said | Reality |
|---|---|---|
| **R5-1** | "**The header lives ONLY in part 0**" (MXBU v1), restated in R2-3's "header in part 0 only" | **The opposite ships, deliberately.** `MxbuSealer::seal_part` prefixes the 45-byte header to **every** stored part (`backup/format.rs`), so a part is self-describing off an untrusted tier — and the anti-splice property the draft wanted comes from a **per-part header compare**: the opener is derived from part 0 (`read_index`, `backup/mod.rs`) and `open_part` rejects any part whose 45-byte prefix differs from it, before the AEAD. This is a **frozen surface**, so the code is the authority and the prose was corrected to match it, never the reverse. Left as-is, the next independently-minted fixture or second writer would follow the spec, disagree with the reader, and the gate would be testing nothing — the exact failure the "the construction is normative" note above exists to prevent. Pinned by `compat/fixtures/backup/backup_v1.bin` (every part carries the header) |
| **R5-2** | Dead-box `--replace` "restore **verifies every restored file's blobs resolve** and prints the ones that do not", with two exact warning strings | **Now implemented (round 6)** — as the correction predicted, it could not live inside `restore()`: that call unseals to `<staging>/db.dump` and stops, and at that instant there is no restored `file_streams` to walk, because `pg_restore` is the driver's next step. It ships as its own post-`pg_restore` subcommand `verify-restored-blobs` (the fifth subcommand, the shape R4-1 already had to invent for the merge) over `backup::verify_stream_blobs`, called by `restore-server.sh` on both replace paths. Both warning strings are emitted verbatim. **Advisory by construction**: it exits 0 and never drops a row — from there a cold-tier fault is indistinguishable from a real absence, and dropping rows on that basis would destroy live files |

---

## Corrections, round 6 (2026-07-31) — found running the E2E to completion for the first time

`scripts/test-backup-rollback.ps1` had never completed a single run. Getting it to the end
surfaced three defects, none of them in the backup engine — two in the shared WSL harness and one
gap this round closed.

| # | What was believed | What is true |
|---|---|---|
| **R6-1** | `Confirm-EnrollmentOpen` proves the ceremony installed the delegation, by reading `print-fingerprint` | **It was a FALSE NEGATIVE and had never once passed.** `print-fingerprint` reads `<data_dir>/client-pins/directory_pub.der`, an operator-convenience export written **only by the server's startup path** (`run.rs` `prepare()`/`run()`, both behind `if directory_pub.is_some()` — in run.rs's own words, a delegation "loaded across a restart"). The ceremony installs the delegation at RUNTIME into `config/`, and nothing re-exports it until the next restart. Proven on a live distro: after a *successful* ceremony the file is absent; one `systemctl restart` makes it appear, with no other change. The oracle is now `GET /v1/bootstrap/delegation`, served straight off the live `st.auth.delegation()` context that also gates enrollment — 404 while awaiting, 200 + the cert once installed (both directions verified against a real distro), plus an assertion that `config/d5_delegation.bin` persisted. This is what blocked every prior run of **both** WSL E2Es |
| **R6-2** | The harness can embed double quotes in a `bash -lc` command string | **PowerShell 5.1 mangles them.** It wraps a native argument containing spaces in `"` without escaping the quotes already inside it, so an inner `"..."` whose content has spaces gets its quoting redistributed; bash then saw `encode(file_id,'hex')` unquoted and died with ``syntax error near unexpected token `('``. Three call sites were affected (`Get-LiveFileIds` and both destruction assertions); they survived elsewhere in the harness only because what those quote — `$HOME/...` — has no spaces. Rule now documented in place: **single quotes only** in a command string handed to `wsl.exe -- bash -lc`. `encode(file_id,'hex')` is gone too — psql already renders BYTEA as `\x<hex>` |
| **R6-3** | The dead-box `--replace` blob-resolution probe is deferred (R5-2) | **Implemented** — see R5-2, now updated. Ships as `verify-restored-blobs` over `backup::verify_stream_blobs`, called by `restore-server.sh` after `pg_restore` on both replace paths |

**A note on what R6-1 means for the feature.** Both harness defects sat *outside* the backup
engine — the delegation oracle is shared with `test-full-install.ps1` and is byte-identical at
`HEAD` — so the E2E's long-standing failure was never evidence against the backup implementation.
It was, however, exactly as costly: a test that cannot pass is a test that proves nothing, and
this one guarded the single most important claim in the project (an existing user keeps account,
keys and uploads across a destroy/restore).
