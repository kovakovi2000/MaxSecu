# Runbook — Server backup & rollback

**Status:** ops. Implements `docs/superpowers/specs/2026-07-16-server-backup-rollback-design.md`.
**Owner:** the VPS operator (root on the box the server runs on).
**Scripts:** `scripts/backup-server.sh`, `scripts/restore-server.sh` (thin root drivers around the `maxsecu-portable-server backup` / `restore` / `list-backups` / `restore-db-merge` subcommands).

> **The rule this exists to protect.** A rollback or a dead-box rebuild must **never** cost an existing user their account, keys, or uploaded data. `--db-mode merge` (the default whenever a live DB exists) adds back only what is missing and never removes a live row, so it cannot strand a user. Read [Known limitations](#known-limitations) before you ever reach for `--db-mode replace`.

---

## What a bundle is, and what it holds

A backup is one **passphrase-sealed** (`MXBU`: Argon2id + AES-256-GCM) bundle that rides the **same cold tier** (Dropbox or an `fs` directory) as the blobs — so, unlike the blobs, it must be encrypted **before** it egresses. It carries the run-state a box needs to come back:

| In the bundle | Why |
|---|---|
| `pg_dump -Fc` of the metadata DB | every user's directory binding + DEK key-wraps |
| `/etc/systemd/system/maxsecu-server.service` (+ drop-ins) | the **only copy of the DB password** on the box |
| `/etc/maxsecu/dropbox.env` | the Dropbox refresh token |
| `<data_dir>/tls/{cert,key}.der` | lose these → new cert → **every pinned client locked out** |
| `<data_dir>/config/*` | the delegation triple (`operational_secret.bin` + `d5_delegation.bin` + `directory_pub.der`) — only coherent as a set |

**Blobs are NOT in the bundle.** They stay on the cold tier, and `WriteBackTier` rehydrates a local copy on read-miss. So a dead-box rebuild needs only the few-KB bundle — the media comes back lazily, per file, on first read.

The bundle lives at `{cold_root}/_backup/<stamp>/…`. A plaintext `manifest/0` (stamp, git SHA, counts, per-part **ciphertext** digests) sits beside it so `--list` and a dead box can read the SHA without a binary that can unseal; it is an untrusted hint (the authenticated copy is inside the sealed `BackupIndex`, and restore aborts if they disagree).

---

## Prerequisites

- A **cold tier must be configured**, or backup **fails closed** (a backup you wrongly believe is complete is worse than none).
  - **On a FRESH install** (and only then), pass it to the installer: `scripts/install-server.sh … --dropbox` (token in `/etc/maxsecu/dropbox.env`), or `scripts/install-server.sh … --cold-tier-fs <dir>` (mutually exclusive with `--dropbox`).
  - **On a LIVE box, do NOT re-run the installer to add one.** Since 2026-08-02 it **refuses** an existing install outright (`scripts/install-server.sh:703-939`), and forcing it past that refusal rewrites the systemd unit from that run's flags. Add the tier **in place** with a drop-in — no data is touched and no client re-pins:
    ```bash
    sudo install -d /etc/systemd/system/maxsecu-server.service.d
    sudo tee /etc/systemd/system/maxsecu-server.service.d/20-cold-tier.conf >/dev/null <<'EOF'
    [Service]
    Environment=MAXSECU_COLD_TIER=fs
    Environment=MAXSECU_COLD_FS_DIR=/srv/maxsecu-cold
    EOF
    sudo install -d -o "$(sudo sed -n 's/^User=//p' /etc/systemd/system/maxsecu-server.service | tail -n1)" \
                 -m 0700 /srv/maxsecu-cold
    sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server
    ```
    This is the same recipe `scripts/backup-server.sh:418-432` and `scripts/upgrade-server.sh:492-503` print, and the one in `docs/runbooks/prod-upgrade.md` §4.3 — keep all four in step.
  - **`<dir>` must be OUTSIDE the data dir.** An `fs` cold tier aliasing the blob directory **destroys ciphertext**. It must also be owned by the unit's `User=`, which is why the recipe reads that out of the unit rather than assuming it. A drop-in holding a **secret** (a Dropbox token, a `DATABASE_URL`) must be **0600**; this one holds neither, so 0644 is correct.
- Run every command from the **same clone** the service was installed from (backup refuses if the unit's `ExecStart` binary differs from this tree's `target/release/maxsecu-portable-server`).
- **The passphrase is the entire security of a bundle sitting in Dropbox.** Choose ≥12 chars, store it somewhere durable and separate from the Dropbox account. There is no recovery if you lose it.

---

## Back up

The passphrase is read from **stdin** (never argv — `/proc` is world-readable). Pipe it in:

```bash
printf '%s' 'my bundle passphrase' | sudo bash scripts/backup-server.sh
printf '%s' 'my bundle passphrase' | sudo bash scripts/backup-server.sh --keep 20
```

- Backup is a **pure read**: it never stops the service or mutates the DB. It runs `pg_dump` itself, seals `db` + `state` as two independently-keyed bundles onto the cold tier, and copies every committed, current-version blob chunk onto the cold tier **keeping the local copy** (idempotent — a re-run resumes).
- `--keep N` prunes to the newest **N** state bundles (default **10**). **N must be at least 1** — pruning keeps the newest N stamps, so `--keep 0` would delete the bundle the run just sealed and leave you with no rollback point at all; both the driver and the binary refuse it. **Blobs are never pruned** — they are the live cold tier; pruning them would destroy user data.
- Retention only ever touches bundles that have a manifest, i.e. ones that reached their commit point. A run that dies mid-upload leaves a **manifest-less `_backup/<stamp>/` directory** behind: `--list` never shows it, `--from latest` never selects it, and pruning ignores it (it must not be able to displace a good bundle). Nothing reaps it automatically, **on purpose**: an orphan costs only cold-tier storage, whereas a reaper that deleted parts out from under a still-running backup would let that run go on to write its manifest over an incomplete part set — turning a harmless orphan into a *listed bundle that cannot restore*, which is far worse. No age bound distinguishes the two reliably (a slow first upload of a multi-hundred-MB dump over a poor link can outlast any threshold). So if a cold tier accumulates them after repeated failures, delete those stamp directories by hand — a directory under `_backup/` with no `manifest/0` in it is never restorable.
- `scripts/upgrade-server.sh` runs a backup automatically and aborts the upgrade on failure, so a rollback is true by default.

---

## List

No passphrase (reads only the plaintext manifests):

```bash
sudo bash scripts/restore-server.sh --list
# dead box (no unit to scrape the location from):
sudo bash scripts/restore-server.sh --list --cold-tier-fs /srv/maxsecu-cold
```

`--list` fails closed if the tier genuinely cannot enumerate (never shows an empty list as if there were no bundles — that would be a trap for an operator about to roll back).

---

## Restore — same-box rollback (the common case)

Undo a bad change on a box that is still alive. The driver unseals **first** (a wrong passphrase or missing bundle fails here, with the server still up and nothing half-applied), then stops the service, restores run-state, merges the DB, checks out the code, and restarts.

```bash
printf '%s' 'my bundle passphrase' | sudo bash scripts/restore-server.sh --from latest
# or a specific bundle:
printf '%s' 'my bundle passphrase' | sudo bash scripts/restore-server.sh --from 20260716-…
```

- Default scope is `--only db,state,code`. Default DB strategy is **merge** (a live DB exists).
- The TLS cert is restored **unchanged**, so the fingerprint clients pinned is the same — the run prints it at the end so you can confirm **no client needs to re-pin**.

### Just roll the code back (a failed upgrade where nothing was deleted)

The most common case. The live DB is a strict superset of the backup, so the merge is a no-op — you only want the old binary. Don't download a multi-hundred-MB dump for that:

```bash
printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest --only code
```

`--only code` = `git checkout <recorded sha>` + `cargo build --release` + restart, while the old server keeps serving until the rebuild finishes. (Requires a real git checkout; a hand-copied tree with no `.git` records/uses `git_sha: null`, and a recorded sha with no `.git` is a hard error naming the fix.)

---

## Restore — dead-box rebuild

Rebuilding a fresh VPS from scratch. There is **no unit and no `/etc/maxsecu`** to discover the cold tier from (`dropbox.env` is itself *inside* the bundle), so you **must** tell the driver where the bundle lives:

```bash
# filesystem cold tier:
printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest \
    --cold-tier-fs /srv/maxsecu-cold
# Dropbox cold tier:
printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest \
    --dropbox-env /path/to/dropbox.env
```

`--cold-tier-fs` and `--dropbox-env` are mutually exclusive (a box has one cold tier). With no live DB the default DB strategy is **replace**: the driver re-creates the `maxsecu` role (its per-install random password lives only in the just-restored unit) and the database, then `pg_restore`s into it. Blobs rehydrate from the cold tier on first read.

After the `pg_restore` the driver runs the **blob-resolution audit** and prints one of:

```
blob resolution: 42 of 42 stream(s) resolved on the cold tier
  every restored file's ciphertext resolves — nothing to audit
```

```
warning: 3 restored files have missing ciphertext:
  a1b2…  b3c4…  d5e6…
these are post-backup deletions (their owners can re-delete them) or post-backup
rotations (the backed-up version's chunks were purged at finalize).
no rows were dropped — a cold-tier fault looks identical from here.
```

A `warning: N streams could not be verified (cold tier fault)` line means the audit could not reach the tier for those streams — that is **not** a claim the files are gone. The audit never changes the database and never fails the restore; re-run it any time with `maxsecu-portable-server verify-restored-blobs`.

---

## `--dry-run`

Unseal, verify, print the plan, change **nothing**, never stop the server:

```bash
printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest --dry-run
```

On a **running** server a dry run is plan-only (the exact per-table merge counts need a quiescent DB — the merge refuses to run while the server is connected). To see the real per-table numbers **without applying**, `systemctl stop maxsecu-server` first and re-run the same `--dry-run` (it runs the identical insert pass inside a `SERIALIZABLE` txn and rolls it back, so the preview numbers are exactly the apply numbers).

---

## `--db-mode` and `--force`

| | |
|---|---|
| `--db-mode merge` (default with a live DB) | `INSERT … ON CONFLICT DO NOTHING` in FK order: add back what is missing, never touch a live row. Honors the `file_tombstones` / `wrap_revocations` tables so it does **not** resurrect a deleted file or a revoked wrap. Requires the server to be **stopped** (the driver does this). |
| `--db-mode replace` (default only on a dead box) | wholesale `pg_restore --clean` of the backup as of backup time. **Over a live DB this is the `2a626d6` failure mode by construction**, so it demands `--force`. |
| `--force` | authorizes **`--db-mode replace` while a live DB is reachable**, and nothing else. Do not use it to "fix" a merge — reach for it only when you deliberately want the backup's exact DB state to overwrite live. |

Component selection: `--only db,state,code,blobs` (comma list). **`blobs` performs no work** — it is accepted for compatibility only, and the plan says so (`blobs:   no pre-pull — cold blobs rehydrate lazily on read-miss`). Blobs are never bundled: they ride the cold tier and `WriteBackTier` fetches a copy on the first read-miss, so a restore needs no blob step. An earlier draft described it as a pre-pull that warms local disk up front; nothing implements that.

---

## Known limitations

- **`--db-mode replace` silently resurrects revoked wraps, undetectably.** The tombstone / revocation gate is **merge-only**. A `replace` puts back every `file_key_wraps` row as of backup time, including a share a user revoked afterward — and because that file was never deleted, its ciphertext still resolves, so even a blob-level check would see nothing wrong. The de-authorized recipient silently regains a working DEK and nothing prints. This is why `merge` is the default wherever a live DB exists and `replace` over live needs `--force`. Prefer `merge`.
  - **The recovery wrap is exempt from this hazard in both directions (2026-08-02).** It can no longer be revoked at all — `DELETE /v1/files/{id}/wraps/{recovery_id}` is `403 recovery_protected` for every caller including the owner (`docs/api.md` §10.2) — so there is no recovery `wrap_revocations` row for a merge to honour and none for a replace to override. Before that guard, a single owner-issued soft-revoke wrote a permanent tombstone that a **merge would faithfully preserve**, leaving a file the escrow key can never open with the restore reporting success.
- **Replace can resurrect post-backup deletions — but they are now listed for you.** With no live DB there are no tombstones, so a replace puts back every file that existed at backup time, including ones deleted since and ones whose backed-up version was superseded by a post-backup **rotation** (that version's chunks were purged at finalize). Either way the row comes back as a feed entry whose ciphertext is gone from both tiers, and it 404s on download. After any `replace`, `restore-server.sh` now runs a **blob-resolution audit** (`maxsecu-portable-server verify-restored-blobs`) that probes one chunk per restored stream and prints the files whose ciphertext does not resolve. It is **advisory**: it never drops a row and never fails the restore, because from there a cold-tier fault is indistinguishable from a real absence — dropping rows on that basis would destroy live files. Audit the listed files; a clean report means every restored file's bytes really are there.
- **A revoked-then-re-shared wrap is not restored by a merge.** `delete_wrap` records a permanent `wrap_revocations` row, and the merge skips any wrap matching one. If the owner later **re-shares the same file version to that same recipient**, `add_wrap` re-creates the wrap but the revocation record — immutable by design — stays. So if the live DB later loses that wrap, a merge will not put it back. This is deliberate and **fails closed**: the alternative is to rank `created_at` against `revoked_at`, which would hinge the one gate that stops a de-authorized recipient recovering their DEK on an advisory timestamp (§7.5). Nothing is destroyed — the owner simply re-shares the file again, which costs no re-enroll, no re-key and no re-upload.
- **Rollback loses what happened in between.** Inherent — `merge` is the mitigation (it never removes new state), but a rollback is still a step back in time for anything not yet in the bundle.
- **A merge cannot repair a partially-lost `control_log`.** That table is skipped by the merge (its append-guard makes merging impossible); its anchored chain is recoverable only via `replace`.
- **Tombstones only exist going forward.** A file deleted by pre-`0002` code left no record, so a merge from a bundle predating this feature could resurrect it. Bundle retention (default 10) closes that window on its own.
- **A Dropbox rate limit aborts a backup rather than corrupting one.** The adapter has no `429` / `Retry-After` back-off, and a backup walks every chunk of every file — the workload most likely to trip one. It **fails closed**: `has_chunk` treats only a `409` carrying `path/not_found` as absence, so a `429` surfaces as a hard error and the run stops with a non-zero exit. It can never be mistaken for "that chunk isn't there", so it cannot silently produce an under-copied bundle you believe is complete. Backup is idempotent and resumes, so the cost is a re-run, not data. On a large Dropbox library, run backups off-peak and re-run if one aborts.
- **Keep the passphrase safe.** One Argon2id derivation is all that stands between a bundle in Dropbox and an offline attacker who has your Dropbox account. The 12-char minimum is a floor, not a guarantee. If you lose the passphrase, the bundle is unrecoverable — there is no admin escape hatch.

---

## Cross-references

Design: `docs/superpowers/specs/2026-07-16-server-backup-rollback-design.md`. Compat: surface #12 in `docs/compat/CHECKLIST.md`, ledger entry 2026-07-16 in `docs/compat/LEDGER.md`, fixtures under `compat/fixtures/backup/`. Related ops: `docs/runbooks/tombstone-issuance.md`, `docs/runbooks/recovery-key-rotation.md`.

**Client side of a dead-box rebuild.** Nothing here restores the *operator's* client. A bundle carries the server's run-state only; the cold `recovery_key.blob` is yours and lives offline. If you need to sign in with it on the rebuilt box's fresh admin PC, the client will not find it where the ceremony wrote it — put it in place with `scripts/install-client.ps1 -StageRecoveryKey`, per [Starting an online recovery session](recovery-session.md#starting-an-online-recovery-session-the-file-placement).
