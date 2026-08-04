# Runbook — upgrading a live MaxSecu server (and the clients behind it)

**Audience:** the operator of a real VPS with real, non-technical users on it.
**Hard rule this runbook exists to protect:** an upgrade must never cost an existing user
access to their account, their keys, or anything they already uploaded. There is no admin
escape hatch — a change that makes a keyblob, a DEK wrap or a directory binding unreadable
destroys that data permanently.

**Status:** executed end to end on **2026-08-01** against a prod-shaped box carrying real
uploaded content (§6). Before that date `scripts/upgrade-server.sh` had **never been run**.
It has still **never run against the real VPS**.

---

## 0. SHOULD / SHOULD NOT — read this before you touch the VPS

Ordered by how badly the mistake hurts. The first three are unrecoverable: there is no admin
escape hatch, so nobody — not you, not a support ticket — can undo them.

### SHOULD NOT

1. **NEVER re-run `install-server.sh` on a live box.** It is a *fresh-install* tool. Since
   2026-08-02 it refuses an existing install by default, but do not rely on the guard — the
   guard is the seatbelt, not the plan. To change a setting, use a **systemd drop-in** (§4.3);
   to update code, use `upgrade-server.sh`; to change data, use `backup-`/`restore-server.sh`.
2. **NEVER pass `--rotate-tls-identity`** unless you have accepted that **every existing client
   is permanently locked out** and every user must be re-installed by hand. It mints a new
   server identity. There is no re-pin path for a non-technical user.
3. **NEVER use `install-client.ps1 -Reset` to update a client.** It deletes `dist\`. It now
   rescues the keystore first, but it is not an upgrade tool — update the exe and `ui/` in
   place, preserving `keystore/`, `config/` and `index/`.
4. **NEVER let the data directory be guessed.** If you are unsure the box's data dir matches
   the invoking user's home, state it: `sudo env MAXSECU_DATA_DIR=/actual/path bash …`. A
   wrong data dir orphans every uploaded blob and mints a new TLS identity.
5. **NEVER declare success on "the service is running."** `systemctl is-active` is a
   false-green on `Type=simple` + `Restart=always`. Use §5.
6. **NEVER skip the fingerprint diff** because the upgrade printed no errors. The diff is the
   only thing that proves nobody lost access.
7. **NEVER edit a golden fixture** to make the compat gate pass. The corpus is add-only, and
   the gate failing means an existing user's bytes stopped opening.

### SHOULD

1. **Take a manual `pg_dump` + a copy of the systemd unit before the FIRST upgrade**, and copy
   both off the box. The unit is the **only** copy of the database password. Do this even
   though the first upgrade runs `--no-backup`.
2. **Pass `--no-backup` on the FIRST upgrade only.** The installed binary predates the backup
   feature, so it cannot seal one; the script refuses rather than let the old binary boot a
   second root server. Every later upgrade should take a real backup.
3. **Expect minutes of downtime, not a blip.** The upgrade rebuilds the release binary on the
   VPS. Tell your users beforehand.
4. **Run the fingerprint before and after, and diff them** (`scripts/fingerprint.sh`). The
   upgrade is a success only if the diff is **additions only** — see §5 for the exact list of
   what may never change.
5. **Verify with a real client that was NOT upgraded**, before you touch any client. If the
   old client still logs in with no re-enroll and no re-pin, the server upgrade is sound.
6. **Upgrade the client only after the server is verified**, exe + `ui/` only, and keep the old
   exe for rollback.
7. **Check the client you ship is built from the tree whose `recovery_pin.bin` matches this
   box's ceremony.** Building from the wrong tree ships a client pinned to a *different*
   recovery account. This has happened.
8. **Run `powershell -File scripts/compat-gate.ps1` before every push**, and let the pre-push
   hook and CI run it too.

---

## 1. What an upgrade actually is here

Production is deployed by **dragging the tree over** — there is no `git` on the box. So an
upgrade is:

1. copy the new source over the old, leaving `target/` in place;
2. rebuild the release binary;
3. apply any pending SQL migrations;
4. reconcile the systemd unit's environment with what the new build expects;
5. restart, and prove it is genuinely healthy.

`scripts/upgrade-server.sh` does all five. It never modifies database contents, the blob
store, the TLS certificate or the Dropbox credentials.

**The TLS cert is the single most dangerous thing on the box.** Every client pins it. If it
changes, every user is locked out and cannot self-repair. Nothing here touches it, and §5
checks that explicitly.

> One nuance, because §6 records it: the *script* does not touch `client-pins/`, but the
> server **rewrites `client-pins/*.der` on every start**. The contents are a byte-copy of the
> untouched `tls/cert.der` and `config/directory_pub.der`, so the pin value cannot drift — but
> the files' timestamps change, and one may *appear* that was not there before.

---

## 2. Before you start

- [ ] SSH access and `sudo`.
- [ ] **A terminal.** The default path prompts for a backup passphrase (twice, minimum 12
      characters) and aborts if stdin is not a TTY. `sudo bash … < /dev/null` will not work.
- [ ] **Downtime budget.** The service is DOWN for the whole rebuild — minutes on a small VPS,
      not a blip.
- [ ] **Toolchain and disk on the box:** the cargo toolchain at `$HOME/.cargo/env`, `psql`,
      `sha256sum`, and enough free disk for a full release rebuild. All four are required
      *after* the service is stopped; a missing one triggers the rollback, but you still eat
      the downtime.
- [ ] **A manual restore point, if this is the first upgrade.** The first upgrade runs with
      `--no-backup` (§4.2), so there is no sealed bundle to roll back to. Take one yourself:
      ```bash
      sudo -u postgres pg_dump maxsecu > ~/pre-upgrade.sql
      sudo tar czf ~/pre-upgrade-datadir.tgz -C / root/maxsecu-server-data
      ```
      Copy both off the box.
- [ ] Somewhere off the box to keep the fingerprint files.

---

## 3. The procedure

### 3.1 Fingerprint the box FIRST

```bash
cd ~/maxsecu
sudo bash scripts/fingerprint.sh before /root/fp-before.txt
```

It records: row counts for every access-bearing table; the `users` row (login); the signed
`directory_bindings` row; every file, version, stream and key wrap; the TLS cert fingerprint;
raw digests of `tls/cert.der` and the delegation config; a digest of every blob; the cold
tier's contents; and the unit plus its drop-ins (with the database password redacted, so the
file is safe to copy off the box).

Copy it off the box. Without it you cannot prove afterwards that nothing was lost — and "the
server started" is not that proof.

### 3.2 Copy the new tree over

Copy the source over `~/maxsecu`, **overwriting files and leaving `target/` alone**. Do not
delete the tree first: `target/` holds the binary that is currently serving, and it is your
rollback. Do not copy `target/`, `.git/`, `node_modules/` or `dist/`.

### 3.3 Run the upgrade

```bash
cd ~/maxsecu
sudo bash scripts/upgrade-server.sh
```

On the **first** upgrade into the backup feature the script stops and tells you to re-run with
`--no-backup`. That is expected and correct — see §4.2.

> **Later upgrades only back up automatically if a cold tier is configured.** The sealed
> bundle is written to the cold tier; with none configured the backup fails closed and the
> upgrade aborts. If your box has no cold tier you will pass `--no-backup` every time, and
> §2's manual dump is your only restore point. Configure a cold tier (§4.3) or accept that.

It ends with `UPGRADE COMPLETE` **only** after the service has been up and stable for 20
seconds.

### 3.4 Fingerprint again and diff

```bash
sudo bash scripts/fingerprint.sh after /root/fp-after.txt
diff -u /root/fp-before.txt /root/fp-after.txt
```

**Read the diff.** §5 says which differences are acceptable.

### 3.5 Verify with a real client — before you touch any client

Open a client that has **not** been updated. Confirm it signs in with no re-enroll and no
re-pin, and that existing files still open. This is the actual acceptance test; the row counts
are corroborating evidence.

### 3.6 Only then, upgrade clients

Replace the executable and the `ui/` folder. **Never** re-run the installer with `-Reset`, and
never delete the app folder — see §4.8 and §4.9.

---

## 4. What can go wrong

### 4.1 A silently stale build — the worst kind, because it looks like success

**Symptom (loud):** the build dies with `unresolved import maxsecu_server::backup`.
**Symptom (quiet, the dangerous one):** the build succeeds, `UPGRADE COMPLETE` prints, and the
running binary mixes new and old code.

**Cause:** cargo decides what to rebuild from **modification times**. SFTP clients (WinSCP,
FileZilla) preserve timestamps by default, so copied sources can land *older* than the
artifacts already in `target/`. Cargo then judges the changed crates "fresh" and reuses the
old rlib. Reproduced for real: sources dated 07-17 against an rlib built 08-01.

**Guard:** the script refreshes the mtime of **every `.rs` under `crates/` and `tools/`, plus
the root `Cargo.toml` and `Cargo.lock`**, before it builds. Verified: with the hazard
deliberately reproduced, the binary hash still changed and the new feature was present.

**Residual:** per-crate `Cargo.toml` files and non-`.rs` build inputs keep their copied
mtimes. A change confined to one of those could still be missed. If you change a per-crate
manifest, `rm -rf target/release/.fingerprint` before upgrading.

**Cost:** every upgrade is a full rebuild of the local crates. That is why the downtime is
minutes.

### 4.2 The first upgrade can start a SECOND server as root

**Symptom:** the upgrade hangs forever with no output, or aborts saying the port is in use. On
a box installed with a non-default `--port`, it hangs while a second server quietly serves.

**Cause:** the default path takes a sealed backup by running `<installed binary> backup`. A
binary predating that feature ends its argument dispatch in a catch-all that **falls through
and boots a server** — as root, on the compiled-in default port, against the same database and
data dir, with the backup passphrase on its stdin and no timeout.

**Guard:** two layers.
- The new binary rejects an unknown argument with exit 2 instead of starting a server. That
  fixes every *future* upgrade.
- It cannot fix the *first* one, because the OLD binary runs during that step. So the script
  **probes the installed binary statically** — grepping for `MXBU`, the sealed bundle's magic,
  which only a backup-capable binary contains — and refuses with the exact command to run. It
  never executes the binary to find out, because executing it *is* the hazard.

**Fails closed:** it refuses rather than silently skipping the backup, because skipping would
remove your rollback point without telling you.

### 4.3 Re-running the installer used to destroy every client's trust — now guarded

**Symptom (historical):** after "repairing" something with `install-server.sh`, every user is locked
out and cannot fix it themselves.

**Cause:** `install-server.sh --public` **unconditionally deleted `tls/cert.der`, `key.der`
and the whole `client-pins/` directory**, and the server then mints a brand-new self-signed
certificate. Every pinned client fails closed. It also rotated the Postgres role password on
**every** run and wrote the matching unit hundreds of lines later — so an abort in between left the
live database password changed with the working one existing nowhere.

**Guard (2026-08-02 — this IS now fixed; five parts).**

1. **An EXISTING-INSTALL PREFLIGHT** at `scripts/install-server.sh:703-939`. Detection
   (`:737-762`) is the **OR** of three independent signals, because a partially-damaged box can be
   missing any one of them:
   - the systemd unit exists;
   - `<data_dir>/tls/cert.der` exists (the identity every installed client has pinned);
   - the `maxsecu` database has a non-empty `users` table.

   The database probe goes through `psql_maxsecu_query` (`scripts/install-server.sh:428`), which
   `cd`s to `/tmp` first — the idiom from `scripts/fingerprint.sh:131`, adopted after a
   `sudo -u postgres` chdir failure silently voided *every* query in that script. It runs
   **before** apt, before the multi-minute build, and before anything touches Postgres, so a
   refusal costs you nothing but the time to read it.
2. **The refusal message** (`:764-839`) names the tool for each intent: `upgrade-server.sh` for a
   code update, the drop-in recipe below for a config change, `backup-server.sh` /
   `restore-server.sh` for state, and `--reset` for a genuine wipe.
3. **`--force-overwrite-existing-install`** (parsed at `scripts/install-server.sh:229`) is the only
   way past the preflight. It **does NOT delete the TLS identity** — an operator adding Dropbox to a
   live box must never get a new certificate. What it *does* destroy: the systemd unit is rewritten
   from **this** run's flags, so any flag you omit silently reverts to its default (port, bind,
   capacity, cold tier).
4. **`--rotate-tls-identity`** (parsed at `:233`) is now the **only** thing that deletes an existing
   `tls/{cert,key}.der` + `client-pins/` (`:1246-1277`). What it destroys is absolute: **every client
   that pinned the old certificate is locked out permanently** and must be handed a freshly built app
   ZIP — there is no self-repair. The unconditional `--public` deletion is **gone**; with a cert
   already present and no `--rotate-tls-identity`, the script prints *"Keeping the existing TLS
   certificate"* and moves on.

   **Both flags are required together** to rotate on a live box. The refusal message prints the exact
   two-flag command line for the IP-changed case, so you are never stuck.
5. **THE IDENTITY RECONCILIATION + REFUSAL** (`scripts/install-server.sh:575-686`, refusal at
   `:841-914`). `DATA_DIR` and `RUN_USER` used to be pure guesses — `${SUDO_USER:-$USER}` and
   `$RUN_HOME/maxsecu-server-data` — assigned once and never checked against the installed unit,
   even though this is the only one of the five scripts that **writes them back into the unit**
   (`User=` at `:1495`, `Environment=MAXSECU_DATA_DIR=` at `:1506`). Install a box with
   `sudo bash …` as `ubuntu`, come back later in a root shell entered with `su -` (no `SUDO_USER`),
   and the script guessed `/root/maxsecu-server-data`: the preflight's cert probe and the step-9
   TLS gate both looked in the wrong place, both concluded "no certificate", and
   `--force-overwrite-existing-install` printed *"the TLS cert + client pins are KEPT"* while
   pointing the unit at an empty directory — where the server **mints a new TLS identity**. Every
   pinned client locked out, every blob orphaned, through the very flag point 3 recommends.
   Now the unit is the truth: its `User=` and its `MAXSECU_DATA_DIR` (falling back to
   `<WorkingDirectory>/maxsecu-server-data`, the binary's own default) are read and adopted
   **before** the preflight, and any disagreement **refuses outright, naming both values**.
   There is **no override**: neither `--force-overwrite-existing-install` nor
   `--rotate-tls-identity` unlocks it, because an installer must never relocate a live server's
   data. The refusal prints the two ways forward — re-run stating the box's own identity
   (`sudo env SUDO_USER=… MAXSECU_DATA_DIR=… bash …`), or genuinely move the directory with
   `stop` + `mv` + a drop-in, which carries the TLS identity and the blobs with it. A dead box
   has no unit, so `restore-server.sh`'s rebuild path is unaffected.
6. **THE UNIT-LESS VARIANT OF THE SAME CATASTROPHE** (probe at `scripts/install-server.sh:773`,
   refusal at `:964-1075`, conditional reassurance at `:1077-1114`).
   Point 5 can only reconcile against a **unit**. On a box where the **unit is gone but the data
   dir and the database survived** — which `scripts/backup-server.sh` explicitly routes operators
   into when it finds no unit — every guard above went quiet: nothing to disagree with, so no
   mismatch; the data dir was still the guess, so the cert probe missed; the `users` signal alone
   still let `--force-overwrite-existing-install` through; and the reassurance *"the TLS cert +
   client pins … are NOT deleted … this run locks out no client"* printed **while step 9 was about
   to mint a new identity**. Two fixes: the reassurance is now printed **only** when a certificate
   was **positively confirmed** at the resolved data dir (otherwise it says plainly that a new
   identity will be minted and every pinned client is locked out), and a **non-empty `users` table
   with no certificate at the resolved data dir is refused outright**. That combination is a
   contradiction — a live server always has a certificate, so accounts existing means a data
   directory exists and this run is not looking at it. **No override flag**, deliberately: the two
   genuine states behind it both have a correct tool. If the directory merely was not located,
   state it — `sudo env MAXSECU_DATA_DIR=/actual/path bash …` — which can only ever *agree* with
   the box and never relocate anything. If the directory is genuinely destroyed while the database
   survived, that is a **restore**, not an install: only a sealed bundle can put the original TLS
   key back. A flag would be indistinguishable at the command line from the first case, which is
   the one that destroys a working deployment. **A truly dead box is unaffected** — no database, no
   `maxsecu` database and an empty `users` table all read as zero accounts, so `restore-server.sh`'s
   rebuild path still passes straight through.

**The password half is fixed too.** `scripts/install-server.sh:1060-1167` no longer rotates: when the
`maxsecu` role exists **and** a `DATABASE_URL` recovered from the unit is **proven** to connect, it
is reused verbatim and **no `ALTER ROLE` is issued at all**. The `ALTER ROLE` at `:1137` fires only
when nothing usable could be recovered (a unit with no `DATABASE_URL` is already broken; re-minting
is the repair, not the damage), and the run says so out loud. A final connectivity assertion at
`:1158` fails loudly **before** the unit is written at `:1477`. The old hazard was the 340-line gap
between those two points, spanning the build and two blocking interactive prompts with no
`INT`/`TERM` trap; the fix removes the window on the reuse path rather than papering over it.

**Still treat `install-server.sh` as a *fresh install only* tool.** To change configuration on a live
box, use a drop-in:

```bash
sudo mkdir -p /etc/systemd/system/maxsecu-server.service.d
sudo tee /etc/systemd/system/maxsecu-server.service.d/20-cold-tier.conf >/dev/null <<'EOF'
[Service]
Environment=MAXSECU_COLD_TIER=fs
Environment=MAXSECU_COLD_FS_DIR=/srv/maxsecu-cold
EOF
sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server
```

The upgrade's environment reconcile provably cannot fight this: both cold-tier variables are
marked never-synthesize, and any variable set in a drop-in the script did not generate counts
as already-set.

> **Do not move this recipe or change its shape.** Four places now point an operator at it and must
> stay consistent: the installer's own refusal message (`scripts/install-server.sh:764-839`),
> `README.md` ("Change a setting on a running server"), `scripts/upgrade-server.sh:492-503` and
> `scripts/backup-server.sh:418-432`.
>
> **Two caveats the script-side copies carry, and this one must too.** (1) `MAXSECU_COLD_FS_DIR` must
> be **outside the data dir** — an `fs` cold tier aliasing the blob directory **destroys ciphertext**.
> (2) The directory must be owned by the unit's `User=`; the scripts derive that with
> `sed -n 's/^User=//p'` on the unit rather than assuming it. (3) A drop-in holding a **secret**
> (`DATABASE_URL`, a Dropbox token) must be **0600** — the generated reconcile drop-in is 0644 and
> must never hold one.

### 4.3a Recovering a unit that lost its `DATABASE_URL`

**Two** scripts print this recipe — `scripts/upgrade-server.sh:621-644` (its no-`DATABASE_URL`
refusal) and `scripts/backup-server.sh:282-302` (the same refusal on the backup path) — so keep it
identical here. `scripts/restore-server.sh` does **not** print it: it is the tool the recipe's
first route sends you to. **Never synthesize a
`DATABASE_URL`** — a guessed one either fails to connect or, worse, points at the wrong database.

Two routes, in order of preference:

1. **Recover the original from a sealed bundle.** The unit is inside it, and it is the **only** copy
   of the password:
   ```bash
   sudo bash scripts/restore-server.sh --list
   sudo bash scripts/restore-server.sh --from latest --only state
   ```
2. **If the password is genuinely lost**, mint a new one and hand it to the unit yourself:
   ```bash
   sudo -u postgres psql -c "ALTER ROLE maxsecu PASSWORD 'NEWPASS'"
   sudo mkdir -p /etc/systemd/system/maxsecu-server.service.d
   sudo tee /etc/systemd/system/maxsecu-server.service.d/20-database-url.conf >/dev/null <<'EOF'
   [Service]
   Environment=DATABASE_URL=postgres://maxsecu:NEWPASS@localhost/maxsecu
   EOF
   sudo chmod 0600 /etc/systemd/system/maxsecu-server.service.d/20-database-url.conf
   sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server
   ```
   **The `chmod 0600` is not optional** — that file holds the database password, and the generated
   reconcile drop-in next to it is 0644.

Do **not** re-run `install-server.sh` to repair this. On a box that still has a unit, a cert or any
users it now refuses (§4.3); with `--force-overwrite-existing-install` it would rewrite the whole
unit from that run's flags.

### 4.4 "The service is active" is a lie

**Symptom:** `UPGRADE COMPLETE` prints over a crash-looping server.

**Cause:** the unit is `Type=simple` with `Restart=always`, so systemd reports it active the
instant the fork succeeds. A binary that panics 200 ms into startup still reads as active.

**Guard:** start, wait, then require that it is **still** active **and** that `NRestarts` has
not moved. The wait is 20 seconds — the slowest way to die on startup is a Postgres connect,
whose timeout alone is 10 seconds, so a 5-second window called that healthy.

### 4.5 An aborted upgrade used to leave the box down

**Symptom:** the script dies mid-run — failed command, dropped SSH session, Ctrl-C — and
production stays stopped.

**Cause:** the service is stopped for the whole update, and the rollback was wired to a handful
of individual failure branches. Anything else bypassed it: a `set -e` abort on any of ~14
privileged commands, a signal, or two bare `exit 1`s.

**Guard:** the rollback now hangs off a single `EXIT` trap plus `INT`/`TERM` handlers. A flag
is raised when the unit goes down and cleared only when a start is *confirmed healthy*, so any
exit path restores the old binary and restarts. The environment-reconcile step used to install
its own `EXIT` trap, which silently **replaced** the rollback trap for the rest of the run;
that is gone.

### 4.6 Aborting *after* the stop over config it could have read first

**Symptom:** "no DATABASE_URL in the unit" — with production already stopped.

**Cause:** the database URL was read 140 lines *after* the stop, by a parser stricter than
systemd: it required `Environment=` at column zero and ignored `EnvironmentFile=`, so a valid
indented unit read as "unset".

**Guard:** everything read out of the unit is resolved **before anything is stopped**, and the
parser accepts leading whitespace, single or double quotes, and values from an
`EnvironmentFile`.

**Residual — CLOSED 2026-08-02.** `backup-server.sh` used to have the whitespace and quote tolerance
but **not** the `EnvironmentFile` fallback, so a unit carrying `DATABASE_URL` only in an
`EnvironmentFile` aborted the backup — and a failed backup aborts the upgrade. That gap is gone, and
it was closed in **two more scripts the old text did not mention**, both of which failed *silently*
rather than loudly:

- **`scripts/backup-server.sh:243`** — now the canonical parser. Beyond `DATABASE_URL` (the loud
  abort at `:282`), it also feeds `MAXSECU_DATA_DIR` (`:306`, previously a **silent wrong-data-dir
  seal**) and the two cold-tier variables (`:319-320`, previously a silent "the tier is off" with a
  misleading downstream failure).
- **`scripts/restore-server.sh:375`** — this held the **strictest** variant in the repo (no indent
  tolerance, no single quotes, no `EnvironmentFile` fallback) and it sits on the **dead-box**
  `DATABASE_URL` path (`:445`, `:891`) — i.e. the one you reach when the box is already gone.
- **`scripts/fingerprint.sh:79`** — read `MAXSECU_DATA_DIR` from a 0600 unit with a bare `cat`, so a
  non-root caller silently got a **default** data dir and a fingerprint that **proved nothing**. It
  now reads through `run_root`, as does the `ExecStart` lookup at `:127`.

All five copies (those three plus `scripts/install-server.sh:467` and `scripts/upgrade-server.sh:582`)
are byte-identical by design. See the deployment-surface section of `docs/compat/CHECKLIST.md` for
the duplication contract, why it is not in `scripts/lib/`, and the one **deliberate deviation from
systemd** they all carry (`EnvironmentFile=` is consulted as a *fallback*, whereas real systemd lets
it *override* `Environment=`).

Keeping `DATABASE_URL` as an `Environment=` line — what the installer writes — is still the shape
these scripts are tuned for, and it is the shape the precedence deviation cannot affect.

### 4.7 The rollback itself could fail

**Cause:** it copied the binary without stopping the unit, so on the crash-loop path it raced
the auto-restarting process for the file. It reported success from a bare "is-active". And a
unit that burned through systemd's default start rate limit (5 starts in 10 s, which a 200 ms
death plus `RestartSec=2` reaches) sits in `failed` and will not start until reset.

**Guard:** the rollback stops the unit, resets the failed state, **unlinks the target**,
restores the binary, starts it, and judges the result with the same settle check as the
upgrade.

> The unlink matters. Cargo **hardlinks** `target/release/<bin>` to
> `target/release/deps/<bin>-<hash>` (verified on the box: same inode, link count 2). A plain
> `cp` writes *through* that link, overwriting cargo's cached artifact with the old bytes while
> its fingerprint still says "fresh" — so a later bare `cargo build --release` would re-link
> the stale binary and report success.

### 4.8 A client rebuilt from the wrong tree is pinned to the wrong recovery key

**Symptom:** the rebuilt client refuses to start, or fails the recovery-pin check.

**Cause:** `crates/client-app/recovery_pin.bin` is embedded **at build time** and is produced
by the ceremony for *one specific server*. Build from a tree carrying a different copy and you
ship a client pinned to a different recovery account.

**Guard:** none automatic — **check it by hand**. Observed for real during the rehearsal: the
main tree and the ceremony worktree held different pins.

### 4.9 `install-client.ps1 -Reset` deletes the user's private key

**Symptom:** an account that can never sign in again. The server-side account and files still
exist; the client-side identity is gone.

**Cause:** `-Reset` deletes `dist\` wholesale, and `dist\<client>\keystore\` holds the
Argon2id-sealed **private key**. This has already cost one real account.

**Guard:** `-Reset` now rescues every non-empty keystore to a timestamped folder first and
tells you where. Even so: **do not use `-Reset` to upgrade a client.**

### 4.10 A fresh client cannot be told where the server is

**Symptom:** a new PC with a recovery key in hand is a dead end — "No server is configured."

**Cause:** the server address lives in `<app-dir>/config/connection.json`, and the only thing
that writes it is the in-app registration path. The installer ships no such file.

**Guard:** the recovery screen accepts a connection code and writes the file, authenticating it
against the pins already on disk — no network fetch, no trust-on-first-use. The **ordinary**
path still depends on registering in-app.

### 4.11 F3a — the index evidence for the paginated `GET /v1/files` (open item, measured 2026-08-02)

This is the section [`docs/compat/LEDGER.md`](../compat/LEDGER.md)'s F3 entry ("Performance note (no
migration added, on purpose)") points at. **No index was added and none is proposed here** — adding
one touches frozen surface #9 (the SQL schema) and needs its own decision and its own ledger entry.
What follows is the measurement, so that decision can be made from numbers instead of from
intuition.

**Finding: `files_listing_idx ON files(file_type, updated_at DESC)`
(`migrations/0001_baseline.sql:152`) CANNOT serve the new query — and could not serve the OLD one
either.**

Measured with `EXPLAIN (ANALYZE, BUFFERS)` against a real Postgres, **5000 files / 5000 wraps**,
with `docs/schema.sql` loaded verbatim. **All four query shapes** (feed / owner-filtered, `newest`
/ `oldest`) plan as **Seq Scan on `files` + Hash Join on `file_key_wraps` + Sort**. Four
independent reasons, none of which the change introduced:

1. the type predicate is written `($1::smallint IS NULL OR file_type = $1)` (`crates/server/src/pg.rs`
   — a **PRE-EXISTING** form), which is not sargable on the index's leading column under a generic
   plan;
2. with no type filter the leading column is unconstrained, so the index cannot supply the order
   at all;
3. the `file_id` tiebreak is not in the index, so even a matching prefix still needs a `Sort`;
4. the new `owner_id` predicate is served by a *separate* index (`files_owner_idx`) that cannot be
   combined with an ordered scan.

**New cost introduced by this change:** a second full scan of the filtered set per request, for
the `COUNT` that backs `total`.

**Absolute numbers: 1.0–2.1 ms per query at 5000 files.** So this is **not urgent** on a
personal-VPS-scale deployment.

**These numbers are from a SYNTHETIC 5000-file dataset, not from the real VPS.** Nobody has
measured prod. They are recorded unrounded because the point of the measurement is that it is
small enough to defer, and a rounded-up number would invite an unnecessary schema change.

**If it ever does matter**, the fix is a covering index like
`files(owner_id, updated_at DESC, file_id) WHERE listed AND current_version >= 1`, **plus**
splitting the `IS NULL OR` predicate into two prepared statements — and **both halves need a
frozen-surface-#9 decision** before anything is written.

---

## 5. Verifying the upgrade

**Acceptable** differences are additive only:

- new tables (`schema_migrations`, plus whatever the migrations add);
- new `schema_migrations` rows whose recorded hashes match the files on disk;
- a generated environment drop-in containing only variables that were previously **unset**,
  each at the value the server was already defaulting to — and possibly an
  `EnvironmentFile=-/etc/maxsecu/dropbox.env` line on an older unit;
- the binary's hash and mtime, `MainPID`, and the service start timestamp;
- `client-pins/*.der` timestamps (rewritten on every start from unchanged sources).

**Unacceptable — stop and roll back:**

- any row count going **down**;
- any change to the `users` row, especially `key_version`;
- any change to the `directory_bindings` bytes or signature;
- any change to the **TLS cert fingerprint** or the `tls/cert.der` digest;
- any change to the **blob TREE-DIGEST**;
- `NRestarts` above zero.

### Rolling back

```bash
sudo systemctl stop maxsecu-server
sudo systemctl reset-failed maxsecu-server
sudo rm -f  ~/maxsecu/target/release/maxsecu-portable-server        # break cargo's hardlink
sudo cp -p  ~/maxsecu/target/release/maxsecu-portable-server.pre-upgrade \
            ~/maxsecu/target/release/maxsecu-portable-server
sudo systemctl start maxsecu-server
sleep 20 && systemctl show maxsecu-server -p ActiveState -p NRestarts --value
```

The `rm -f` is required for the reason in §4.7. The final line is the health check the script
does automatically and this manual path does not.

**`.pre-upgrade` is a single slot, overwritten at the start of every run.** Upgrade twice and
it holds the *first upgrade's* binary, not the original. It is only a valid rollback for the
most recent run.

Migrations only ever **add**, so the pre-upgrade binary runs fine against the migrated schema.
For a deeper rollback including data, see [backup-restore.md](backup-restore.md) — but only if
you have a sealed bundle; the first upgrade has none (§2).

---

## 6. What happened when this was actually run (2026-08-01)

A prod-shaped box was built at the commit production runs, an account was enrolled, four files
were uploaded and viewed by hand, and the upgrade was run against it.

| step | result | evidence |
|---|---|---|
| Install at the prod commit | no `.git`, no `migrations/`, binary without the backup feature | `fp-before.txt`, box inspection |
| Stale-build hazard | deliberately reproduced (sources backdated to 07-17 vs an 08-01 artifact) | observed live; **not captured in the saved logs** |
| Upgrade without `--no-backup` | **refused before changing anything** | `upgrade-preflight-test.txt` shows the refusal message. The exit code in that log reads `EXIT=0` — a harness artifact; a separate run captured the real **exit 1** |
| Upgrade with `--no-backup` | **exit 0**; binary hash changed despite the reproduced hazard; new binary contains the backup feature | `upgrade-run.txt`, `fp-diff.txt` |
| Fingerprint diff | **additions only** — users, signed binding, all files, versions, streams and key wraps byte-identical | `fp-diff.txt` |
| TLS cert fingerprint | **unchanged** | `fp-diff.txt` (unchanged context line) |
| Blob tree | **unchanged** — absent from the diff entirely | `fp-before.txt` TREE-DIGEST vs `fp-after.txt` |
| Service health | active, `NRestarts=0` after the 20-second settle | `upgrade-run.txt` |
| The un-upgraded client | signed in with **no re-enroll and no re-pin**; files listed, opened and played | **hand-observed by the operator; not captured in a log** |
| The upgraded client | same account, same password, files still listed and played | **hand-observed by the operator** |

**Three** rows above are deliberately marked as hand-observed rather than log-evidenced — the
stale-build reproduction, and both client rows. The two client rows are the most important in the
table, and a runbook that dressed them up as machine-verified would be lying about the strength of
its own evidence. *(Corrected 2026-08-02: this sentence said "two" while three rows carried the
marker.)*

**Provenance of the 2026-08-01 lap, stated honestly.** It was `dry-lap.ps1 -Mode gate1` **plus
hand-driven steps inside the distro**, not one automated end-to-end run. The saved log directory is
missing files `dry-lap.ps1` always writes and contains files it never writes, and one of the logs it
does contain is truncated. The **conclusion** — the fingerprint diff is additions only — still holds;
it is the claim "this was produced by an automated lap" that does not — so read the three
hand-observed rows above as exactly that, and re-run the lap yourself before treating any of it as
machine-verified. *(This paragraph used to end with a pointer into a `docs/` scratch
session-handoff note. Those are gitignored — `.gitignore:63-69` — so the pointer would dangle on a
fresh clone and on the VPS; whatever is durable belongs here instead. `dry-lap.ps1` itself is not in
this tree.)*

`print-fingerprint` **failed** before the upgrade (the pin file did not exist) and **works**
after — the new binary writes `client-pins/directory_pub.der` on startup.

> ### RETRACTION (2026-08-02) — the two client rows above prove less than they say
>
> Both client rows rest on a client built from a git worktree that was **supposed** to be at the
> prod commit but was not. The worktree's `HEAD` was correct, and that is the only thing anything
> checked — but **85 tracked files in it had been overwritten with the current working tree's
> contents**, 60 of them under `crates/` or `tools/`, including `crates/encoding/src/lib.rs`,
> `crates/crypto/src/lib.rs`, `crates/client-core/src/download.rs` and most of `crates/client-app`.
> Verified by sha256: those files were byte-identical to the *current* tree and differed from the
> prod commit.
>
> So what was actually exercised was a **current-code client against a current-code server** —
> exactly the configuration in which a backward-compatibility break is invisible. The rows may
> still be true; the paths involved look behaviour-preserving. But they are **not evidence**, and
> the most important claim in this runbook must not rest on luck.
>
> Fixed: the lap harness now asserts the worktree is **pristine** (`git status --porcelain` empty)
> before building the client, re-asserts after the one deliberate deviation (the test oracle
> overlay), and runs from a freshly-created worktree. A `HEAD` check alone is not enough — that
> is the lesson worth carrying.
>
> **Until a lap with a genuinely prod-era client has been recorded here, treat "the un-upgraded
> client still works" as UNPROVEN.**

### 6a. 2026-08-02 — a fully automated lap, no hand steps

Every row below is **machine-verified**: asserted in code by `dry-lap.ps1`, which prints
`LAP VERDICT: CLEAN` only when all fifteen criteria read PASS and exits non-zero otherwise.
Nothing here was observed by eye. (Contrast §6, whose three marked rows were.)

| criterion | evidence |
|---|---|
| `upgrade-server.sh --no-backup` exits 0 | status read from `$LASTEXITCODE` on a solo invocation, never from a compound whose trailing command masks it |
| Un-flagged upgrade **refuses** | exit 1, names the pre-backup-feature binary and the `--no-backup` remedy, and is inert: unit not restarted, binary unchanged, no `.pre-upgrade`, one server process, nothing on 8443 |
| Stale-build hazard **reproduced** | every `crates/` + `tools/` source backdated 14 days behind every artifact, asserted, and the upgrade's source-mtime refresh defeated it — the binary sha changed |
| No access-bearing fingerprint section lost a line | per-section EXACT / SUPERSET / PAIRS-UP / DIGESTS with non-vacuity guards; `users` row + `key_version`, `directory_bindings` bytes + signature, files/versions/streams/wraps all byte-identical |
| TLS cert fingerprint unchanged | unchanged context line, plus the raw `tls/cert.der`, `config/directory_pub.der` and `operational_secret.bin` digests |
| Blob TREE-DIGEST unchanged | with an explicit guard that the digest line exists in both fingerprints |
| `NRestarts` 0 after the settle | 20-second settle, `active/running` |
| **Un-upgraded client still works** | a **genuinely prod-era** client — worktree asserted pristine at the prod commit before the build, and all five first-party crates asserted to have compiled from it in-lap — logs in with no re-enroll and no re-pin, and every seeded file decrypts to the same SHA-256 |
| Paginated feed OK new, unchanged old | against the **prod** server: no `total`, `offset` ignored, `next_cursor` null. Against the upgraded server: limit, disjoint offset, correct `total`, a full cursor walk, sort both ways, `owner=me`, `type` **excluding a proper subset**, and 400 on a cursor replayed under a changed filter |
| Latest installer **refuses** an existing install | exit 1, REFUSING banner, `cert.der` unchanged, unit still active — with no opt-out flag anywhere in the harness |
| Rollback surface intact **and functional** | seal / `--list` part counts agree across seal, list and the tier; wrong passphrase refused at the unseal with the unit untouched; `--dry-run` and `--only code` changed nothing; and a **hard-deleted file subtree was restored byte-identical**, which the prod-era client then re-downloaded and SHA-256-matched |

**What this lap still does not prove** — carried into §7 rather than glossed: VPS-scale rebuild
time and memory (the unit is stopped for the whole build), a real Dropbox cold tier and its
rehydration, an interrupted upgrade, multi-user / multi-recipient state, a bundle sealed *before*
a schema change, the new installer's fresh-install path, and `owner=me` excluding a file the
caller can see but does not own (only one account is enrolled, so it cannot be constructed here).
*(Two of those were closed the next day by the hand-driven lap in §6b: multi-user state, and
`owner=me` excluding a non-owned file. The rest still stand.)*

### 6b. 2026-08-03 — the hand-driven lap (operator at the keyboard)

**Every row in this table is hand-observed**, and that is a weaker class of evidence than §6a: it
rests on a human looking at a screen and saying so, with no assertion in code and nothing that
re-runs. It is recorded here because the thing it proves cannot be proved any other way — that a
real person can log in, see their files and play them, across a server upgrade. Rows that were
*machine*-verified during the same lap are marked as such inline; do not promote the rest.

Box: a fresh WSL distro built by `dry-lap.ps1 -Mode gate1` (prod `41912da`, prod-shaped, offline-D5
ceremony, prod-era client), then driven by hand. Unlike an automated lap this one carried **two
accounts, a cross-user share, 555 feed files and a 620-member bundle**.

| step | result | evidence |
|---|---|---|
| Operator logs in on the transplanted account | PASS — **hand-observed** | *"uploaded a video and image, tested playback, everything as expected"* |
| Second account + cross-user share, pre-upgrade | PASS — machine-verified server-side | `users=2`, `directory_bindings=2`, `wraps=9` (4 owner + 4 recovery + 1 share), `first_admin_claim` stayed 1 |
| BEFORE fingerprint is not a silent lie | PASS — machine-verified | 205 lines, `users=2` read live, `root=/root/maxsecu`, END trailer present, migrations section the prod-shape marker with zero shas |
| Un-flagged upgrade **refuses**, inertly | PASS — machine-verified | exit 1, MXBU probe (not a TTY refusal), `ActiveEnterTimestamp` identical, binary unchanged, no `.pre-upgrade`, one process, 8443 free |
| Stale-build hazard imposed and defeated | PASS — machine-verified | 222 sources backdated; binary sha `6564eec4…` → `3aaaccec…`, so cargo did **not** reuse the stale build |
| `--no-backup` upgrade | PASS — machine-verified | exit 0 read from a solo invocation; 2 migrations applied, 24 `already exists, skipping` notices |
| No access-bearing section changed | PASS — machine-verified | dry-lap's own comparator, AST-lifted and run by hand: **12 sections, 0 problems**; `users` and `directory_bindings` byte-identical, all 9 wraps intact |
| TLS cert fingerprint unchanged | PASS — machine-verified | `VIEAT7DWFXDDDRQTQTYSRNBN6I2EACW5`, new binary against the same cert; no client re-pins |
| Blob TREE-DIGEST unchanged | PASS — machine-verified | identical digest, `file count: 51`, `NRestarts` 0 after a 20 s settle |
| **Un-upgraded clients still work after the upgrade** | PASS — **hand-observed** | both accounts, prod-era `41912da` clients, untouched: *"signed into both user, everything plays and access as expected, no issue was found."* |
| Paging contract on the upgraded server | PASS — machine-verified | prod-era oracle: `total=5`, disjoint offset, 5-hop cursor walk, sort both ways, `owner=me`, `type` **excluding a proper subset**, 400 on a cursor replayed under a changed filter |
| Client upgraded in place | PASS — machine-verified | exe replaced, pin gate held (`378e8dd1…`, derived from the live `recovery_account` row, not from a file); `keystore/ config/ index/` byte-identical either side |
| **F3 numbered pager, by eye, all three skins** | PASS — **hand-observed** | 555 files = 12 pages, incl. the both-ellipsis window `1 … 4 5 6 7 8 … 12` on page 6 — the overflow branch, which is invisible below 8 pages |
| **`owner=me` EXCLUDES a non-owned file** | PASS — **hand-observed** | `bkupuser2`: Feed 1 item (the share), My Content 0. This is the §6a gap that one account could not construct |
| **Recovery session** | PASS — **hand-observed** | *"everything works as expected beside the code that was needed behind the IP"* — feed not frozen, all files incl. non-owned, banner + End recovery session, Post/My-files hidden, Admin available, Share hidden, files decrypt and play |

**Five rows are marked hand-observed**; the other ten in this table were machine-verified during the
same lap. Do not cite a hand-observed row as machine-verified.

**Why the recovery row matters most.** This box's recovery account has `mlkem_pub` set (1184 bytes)
and all 1176 files carried a recovery wrap, so the session exercised the **post-quantum** unwrap for
real. `build_verify_ctx` has zero test references and the wire-level e2e is CI-excluded — that path
had no gate proving it. It now has one hand observation, which is better than nothing and worse than
a test. **Write the test.**

**What the hand lap FOUND that no automated lap did** — six pre-existing defects, none an upgrade
regression (all verified byte-identical at `41912da`), recorded in §7:
every item open mints a full login and trips the server's 30-challenges-per-60 s cap; a 429 is
collapsed into the credential-failure shape; `Download all` silently reports partial success; the
recovery sign-in demands a connection code the documented cold-storage set does not include;
`sessions` grows without bound; and Stacked bundle mode was never styled, because every skin styles
`.bundle-stacked` while the component sets `.bundle-stack`.

**What this lap still does not prove:** everything in §6a's list except the two now closed, plus —
the pager was smoked at 12 pages, not at prod scale; the bundle was one 620-member bundle of generic
files; and no row here re-runs, so none of it defends against a future regression.

---

### 6c. 2026-08-03 — closing the installer holes, proven by EXECUTION (machine-verified)

Every row here is **machine-verified**: each was produced by running a script on a throwaway WSL box,
not by reading one. That is deliberate — all seven holes below were found by *driving*
`install-server.sh`, after two separate agents had *read* it and concluded it was safe.

**The method, because it is the point.** Each hole was driven twice, in the *identical* box state:
once with the **fixed** script and once with the **pre-fix** script (a byte copy of the 2004-line
version, kept alongside as `install-server-OLD.sh`). If the pre-fix run does not misbehave, the test
proves nothing — so the negative control is reported next to every result. The box was restored from
a pristine `wsl --export` snapshot before each scenario, so no scenario inherits another's damage.

| # | scenario | FIXED script | PRE-FIX script (negative control) |
|---|---|---|---|
| T-FRESH | brand-new box, `--public <IP> --port 18443`, **no other flags** | **exit 0** — unit written, `cert.der` + `key.der` present, service `active`, `NRestarts=0`, `schema_migrations=3`, `auth_nonces_open_idx` present | n/a (this is the no-regression check) |
| T-H1 | no unit + PostgreSQL stopped + real data dir NOT at the guessed path + **1 real account in the database** | **REFUSED, exit 1.** Minted nothing; the real identity survived byte-identical. The refusal names the signal it found: *"the 'maxsecu' database holds 1 user account(s)"* — i.e. it started PostgreSQL, asked, and got a real answer | **exit 0.** Printed `==> No TLS certificate yet — the server will mint one on first start` and minted a NEW identity over the real one. **Every pinned client locked out, no flag typed** |
| T-H7 | `cert.der` present, `key.der` deleted | **REFUSED, exit 1** — *"key.der is MISSING — a BROKEN identity, not a working one"*. Makes **no** continuity promise | **exit 1**, but printed *"are KEPT — no client is locked out"* and **never mentioned the key at all** — the false reassurance |
| T-H5 | role exists; the unit carries a password that does not work | **REFUSED, exit 1**, printing both repair recipes. The original password **still authenticates** — the live role was not touched | **exit 0.** The original password **no longer authenticates** — it rotated the live role, whose only copy was never written down |
| T-H2 | `--reset`, run **unattended** (stdin closed), with the unit pointing at `/srv/maxsecu-real-data` | **exit 0.** Destroyed the *unit-declared* directory, not the guessed one; removed the unit; dropped role + database; printed *"MaxSecu server state removed — but this machine is NOT back to zero"* with a full inventory of what was removed and what was deliberately kept | (established separately; the pre-fix path `rm -rf`s the guessed path and prints "back to zero" while the real identity survives) |
| T-H2b | `--reset` again, on the now-clean box | **exit 0** — a never-installed box must still reset cleanly (this is what `scripts/lib/wsl-harness.ps1` does unattended, and it must keep working with no new flag) | n/a |

**H6 (the portless `psql` calls) is a static result, not an execution one, and is reported as such:**
the pre-fix file contained the string `5432` **zero** times in 2004 lines; the fixed file derives
`DB_HOST`/`DB_PORT` from the installed unit's `DATABASE_URL` (defaulting to `127.0.0.1:5432`),
discovers a non-default cluster port when there is one, and threads `-h`/`-p` through every `psql`
call. No `-h localhost` remains.

**Identity values from the final run**, for anyone reproducing it: the box's real cert was
`a3782652…`; the pre-fix run replaced it with `285d8e97…`. In the earlier run of the same scenario
the pair was `61eb6028…` → `f5f54474…`. Two different boxes, same outcome.

**What §6c does NOT prove.** These are installer scenarios on a throwaway WSL box, not a full
upgrade lap: no client ever connected to these servers, no data was uploaded, and the `--force-`
`overwrite-existing-install` path was exercised only where a hole required it. The automated lap
(§6a) and the hand lap (§6b) remain the evidence for the upgrade path itself. In particular
**§6a/§6b blind spot 6 — "the new installer's fresh-install path" — is now CLOSED by T-FRESH**, which
is the first time the post-preflight installer has been run end to end on a genuinely fresh box.

**Three defects were introduced by the fixing process and caught before they shipped**, all by a
second agent that had not written the code. They are recorded because the *shape* matters more than
the instances: (1) the first version of the PostgreSQL readiness gate asked `systemctl is-active`,
which on Debian/Ubuntu is a `RemainAfterExit` wrapper that reports active the instant `start`
returns — so the "bounded wait" broke on iteration 0 and a healthy box whose cluster needed three
seconds got a **hard refusal on a fresh install**; (2) the IPv6 SAN fix introduced a **false
"covered"** verdict, because the `openssl x509` app prints `does match certificate` when
`X509_check_ip_asc` returns `-2` (parse failure) — it only tests `ok ? "" : " NOT"` — so `host:port`
strings and malformed literals all reported covered; (3) migration `0003` was first written as a
btree index, which **would have permanently blocked the upgrade** on any box holding an over-long
abandoned challenge (see `docs/compat/LEDGER.md`, 2026-08-03). All three passed a green gate before
they were caught. **A green gate is not a review.**


---

## 7. Still unguarded — know these before you upgrade prod

*(Items 1 and 5 are struck through: they were closed on 2026-08-02 and are kept, not deleted, so a
reader who remembers them can see what replaced them.)*

1. ~~**`install-server.sh --public` still deletes the TLS cert and `client-pins/`**~~ — **CLOSED
   2026-08-02.** The deletion now happens **only** with the explicit `--rotate-tls-identity`
   (`scripts/install-server.sh:1246-1277`), and on a box that already has an install the script
   **refuses outright** unless you also pass `--force-overwrite-existing-install`
   (`scripts/install-server.sh:703-939`). `--public` alone no longer touches the certificate. It is
   still a **fresh-install tool** — read §4.3 before you reach for either flag, because
   `--rotate-tls-identity` locks out every existing client permanently and
   `--force-overwrite-existing-install` rewrites the unit from that run's flags.
2. **The client's embedded recovery pin is not verified against the target server** (§4.8).
3. **No cold tier means no sealed backup, ever** (§3.3). Every upgrade needs `--no-backup`.
4. **The first upgrade has no restore point** unless you take the manual dump in §2.
5. ~~**`backup-server.sh` cannot read `DATABASE_URL` from an `EnvironmentFile`**~~ — **CLOSED
   2026-08-02** (§4.6), and closed in `restore-server.sh` and `fingerprint.sh` too, where the same
   gap failed *silently* instead of loudly. One **known deviation from systemd** remains and is
   deliberate: all five parser copies treat `EnvironmentFile=` as a *fallback*, whereas systemd lets
   it *override* `Environment=`. A box that sets `DATABASE_URL` in **both** places is therefore read
   differently by these scripts than by the service itself — i.e. an upgrade could migrate a
   different database than the server runs against. Do not set it in both places.
6. **`.pre-upgrade` is a single slot** (§5).
7. **`migrations_verify_history` aborts the upgrade** if a already-applied migration file's
   hash no longer matches what is recorded — i.e. if someone edited a shipped migration. The
   abort happens before the service is stopped, but it is confusing if you do not expect it.
8. **An `ExecStart` that does not match the expected binary path is a hard abort** — relevant
   if you run the upgrade from a second copy of the tree.
9. **A failed rollback runs twice.** The failure paths call the rollback then exit; if the
   rollback's own settle check fails, the trap runs the whole stop/reset/copy/start/20 s cycle
   again. Worst case is ~40 s and two extra restarts, not data loss.
10. **The closing fingerprint's data dir is a guess** when the unit does not set
    `MAXSECU_DATA_DIR`. Cosmetic: it prints a spurious error at the very end of a successful
    upgrade. (`scripts/fingerprint.sh` resolves it correctly; only the script's own closing
    line has this.)
11. **Downtime is the length of a full rebuild** (§4.1), not a blip.
12. **None of this has run against the real VPS.** It is proven on a prod-shaped replica with
    real content. That is much better than nothing, and much less than certainty.

### Found by the hand-driven lap, 2026-08-03 (§6b)

These are **client** defects, not upgrade defects. Every one was verified byte-identical at
`41912da`, so none is an upgrade regression — but they are what a real user meets, and an automated
lap structurally cannot find them, because no automated lap clicks.

13. **Every item open mints a full login, and the server caps challenges at 30/account/60 s.**
    `open_content` (`viewer.rs`) calls `reauth` → a fresh TLS dial + `/v1/session/challenge` +
    `/v1/session/proof` *per item*; at the lap `decrypt_card` was the only command that used the
    connection pool. Past 30 the server returns 429
    (`ratelimit.rs:40-41`). Live-proven: admitted challenges pinned at exactly 30 in a sliding
    60 s window seven times, never 31; 308 nonces, 308 used, **0 failed proofs ever**. A stacked
    620-member bundle drained the budget in one 718 ms burst of 27 serialized logins.
    **The working tree now routes every authed READ through the pool** — `commands/pool.rs`
    `get_on_pooled_channel`, called from `feed.rs` (`list_feed`, `decrypt_card`), `viewer.rs`
    (`open_content`), `bundle.rs` (`open_bundle_members_pooled`), `download_cmd.rs` and `video.rs`;
    the write and admin paths still mint their own login. Fixed in the tree, **not**
    operator-confirmed. (The pre-fix note this item used to cite in `ui/src/core/pool.ts` has been
    corrected in place — it described the one-command state and is no longer true.)
14. **A 429 is reported to the user as "Sign-in failed."** `session.rs:122-124` collapses any
    non-2xx into the non-oracle credential shape, and `Retry-After` is discarded — `post_json`
    throws away all headers. A throttled user is told their *credentials* failed, so the natural
    response is to re-enter a password, which cannot help. Raw transport failures take the same
    path, so a dead socket also reads as a sign-in problem instead of `offline`.
15. **`Download all` silently reports partial success.** `bundle-screen.ts` swallows each member
    failure in a bare `catch` and toasts the tally: a throttled run on a 620-member bundle says
    *"Downloaded 30 of 620"* with no error and no indication which 590 are missing or why.
16. **The recovery sign-in demands a connection code that the documented cold-storage set does not
    include.** `install-client.ps1:1057-1061` and `README.md:250-257` tell the operator to keep
    `recovery_key.blob` + `d5_recovery.blob` + the passphrase; the code is classified as a *handout*
    artifact. But the recovery screen accepts only `addr:port#FINGERPRINT`, and
    `request_recovery_challenge` reads the address from `connection.json`, which on a fresh folder
    only `set_server_from_code` writes. **An operator who followed the docs cannot complete the one
    flow that exists for disasters.** The `#FINGERPRINT` is a pure function of `server_cert.der` +
    `directory_pub.der` — both already in the folder — so it is a tautology, not a second factor,
    and the address is not in the hash preimage so it authenticates nothing; the pinned-cert TLS
    config is the real authenticator. The error shown is also wrong: a bare address fails at
    `split_once('#')` and never reaches a certificate comparison, yet reports a pin mismatch.
    *Both* the normal connect and register screens accept a bare `host:port` — only the break-glass
    path is stricter, which is exactly backwards.
17. **`sessions` grows without bound.** One row per authed *command* (334 rows, 76 already expired,
    after ~3 h of light use). The only non-INSERT is the logout `UPDATE`; there is no `DELETE` and
    no GC of expired rows.
18. **Stacked bundle mode was never styled: the component sets one class and every skin styles
    another.** `bundle-screen.ts` sets
    `container.className = this.mode === "gallery" ? "bundle-gallery" : "bundle-stack"`, but the
    only stacked rule any of the three sheets has ever carried is `.bundle-stacked` — a class
    **nothing in the app sets**. Byte-identical at `41912da`: the same assignment, the same
    `.bundle-stacked`-only rules, no `.bundle-stack` container rule in any skin. Stacked mode
    therefore fell back to raw block flow — no gap between members, and no `scroll-margin-top`, so
    walking to a member parked it *under* the sticky `.app-header` (`position: sticky; top: 0`).
    Only `styles.slot3.css` styled `.bundle-stack-item` at all, which is why members could look
    right individually while the container did not. Fixed **additively** in all three skins —
    `.bundle-stack { display: grid; gap: … }` plus
    `.bundle-stack > section { min-width: 0; scroll-margin-top: 7rem; }` — each at that skin's own
    gap (`styles.css` and `styles.slot3.css` `clamp(1rem, 2vw, 1.35rem)`; `styles.pizza.css` the
    tighter `clamp(0.65rem, 1.35vw, 1rem)` its density pass already gives `.bundle-stacked`).
    `.bundle-stacked` is left untouched in all three, so anything that ever adopts it is unaffected.
    **Nothing guards this.** `bundle-screen.test.ts` asserts `.bundle-gallery` is the feed's auto-fit
    tile grid but has no `.bundle-stack` counterpart — the Gallery half of this exact bug has a
    regression test and the Stacked half still does not. A class-name typo between a component and a
    stylesheet fails **silently**, in three files, and no automated lap can see it.

### Introduced and closed inside the 2026-08-03 fix rounds — the logout drain race

Recorded because a defect that is introduced and fixed in the same round leaves no trace anywhere
else, and this one was a **security** defect on the most privileged path in the product. It never
shipped: it did not exist at `41912da` and does not exist at `37283fd` (at both, `pool.rs` has no
generation counter at all and `logout` takes no pool handle). It existed only inside that day's fix
rounds and never left them — it was caught by a second agent that had not written it. It is written
down so that the *shape* of it is not re-introduced.

**The defect.** Closing item 13 routed every authed read through a backend connection pool, which
meant `logout` and `end_recovery_session` now had to destroy pooled channels. The first version
drained the pool BEFORE clearing the session, and `acquire` sampled the drain generation AFTER
`mint().await`. An `acquire` in flight across the drain therefore did all three wrong things at once:
it still saw a principal, so it minted a **live, channel-bound token for the user who was signing
out**; it was stamped with the POST-drain generation; and its `Drop` saw `born == current` and pushed
it into the idle set. On the recovery path that is a token that opens **every user's content**,
sitting in a pool the operator believes they just tore down.

**Closed on both sides, because either side alone is not enough.**
- *Command side* — the session is cleared FIRST and the pool drained SECOND, in
  `commands::auth::logout` and `commands::recovery_login::end_recovery_session` (both carry an
  `ORDER IS LOAD-BEARING` comment stating why). An acquire that entered before the clear is stamped
  with the OLD generation and is born stale; one that enters after finds no principal and no identity
  and cannot mint at all.
- *Pool side* — the birth generation for a channel that must be MINTED is sampled at `acquire`
  ENTRY (`born_if_minted`), before anything that could produce a channel, so a mint that straddles a
  drain is born stale and is discarded on return. A REUSED channel instead takes its generation at
  the pop. Every era test (`Drop`, `return_lent`, `take_fresh_idle`) is made while HOLDING the idle
  lock that `drain_idle` bumps under, so no check-then-push can straddle the drain.

**Regression tests** (`commands/pool.rs`): `a_channel_minted_across_a_drain_is_discarded_on_drop` and
`a_channel_minted_across_a_drain_is_not_re_pooled_when_lent`, both driven by the
`acquire_across_a_drain` helper, which gates a mint open, drains underneath it and then lets it
finish. The older `a_borrow_that_straddles_a_drain_is_discarded_on_drop` cannot catch this case —
it acquires BEFORE the drain, so its birth generation is pre-drain either way.

**What is still NOT tested, stated plainly:** the command-side ordering itself. Both tests exercise
the pool; nothing asserts that `logout` clears before it drains. Swap those two statements back and
the whole suite still passes. The ordering is held by a comment and by review, not by a gate.
(`acquire_across_a_drain`'s own doc comment still describes the OLD ordering as current fact — it is
stale, and the commands are what to believe.)

**The lesson worth carrying:** the fix for a rate-limit problem was to make authed connections
*reusable*, and reuse is exactly what makes a stale token dangerous. Any change that adds caching or
pooling to an authenticated path has to answer "what happens to a cached credential when the
principal changes underneath it" — and the answer has to hold for an operation already in flight,
not just for one that starts later.
