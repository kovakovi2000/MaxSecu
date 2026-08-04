#!/usr/bin/env bash
#
# backup-server.sh — seal a full recovery bundle of an ALREADY-INSTALLED MaxSecu
# server (DB + run-state) and copy every committed blob onto the cold tier, so a
# failed upgrade can be rolled back and a dead VPS rebuilt — WITHOUT ever costing
# an existing user their account, keys, or uploaded data.
# (design: docs/superpowers/specs/2026-07-16-server-backup-rollback-design.md)
#
# This is a THIN root driver around the `maxsecu-portable-server backup`
# subcommand. The binary does the real work — it holds DATABASE_URL through its
# LauncherConfig, so it runs `pg_dump -Fc` itself (into a 0700 work dir, sealed
# then unlinked — the plaintext dump never lingers), enumerates the committed,
# current-version file_streams, seals the `db` + `state` bundle onto the cold
# tier under a passphrase (Argon2id), and copies every committed blob chunk onto
# the cold tier while KEEPING the local copy. The driver's only jobs are:
#
#   1. hand the binary the SAME environment the running server uses (DATABASE_URL,
#      MAXSECU_DATA_DIR and the cold-tier location), scraped from the live unit;
#   2. run it as root so the root-only run-state (the systemd unit and the Dropbox
#      creds file) can be read into the bundle;
#   3. pipe the bundle passphrase straight through to the binary on stdin.
#
# What is in the bundle (see the design's "state bundle" table):
#   * the systemd unit (the ONLY copy of the DB password on the box),
#   * its drop-ins, /etc/maxsecu/dropbox.env (the refresh token),
#   * <data_dir>/tls/{cert,key}.der (lose these -> every pinned client locked out),
#   * <data_dir>/config/* (the delegation triple).
# Blobs are NOT in the bundle: they ride the cold tier and WriteBackTier rehydrates
# a copy on read-miss, so a rebuild needs only the few-KB bundle.
#
# THE PASSPHRASE. It arrives on THIS script's stdin and must reach ONLY the
# binary's stdin (argv is world-readable through /proc). So the script never reads
# its own stdin, and EVERY other sub-command it runs is `</dev/null`-redirected so
# none of them can drink the passphrase line. Nothing secret is ever put on a
# command line.
#
# Usage:
#   printf '%s' 'my bundle passphrase' | sudo bash scripts/backup-server.sh
#   printf '%s' 'my bundle passphrase' | sudo bash scripts/backup-server.sh --keep 20
#
# Flags:
#   --keep N   Keep the newest N state bundles, prune older ones (default 10).
#              Blobs are NEVER pruned — they are the live cold tier.
#   -h,--help  Show this help.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# 0. Resolve the repo root from this script's own location (scripts/ -> root).
#    The `backup` subcommand records the current git HEAD as the bundle's code
#    marker, so the binary is run with its CWD here (a git checkout, when there
#    is one — a hand-copied tree without .git is tolerated: git_sha is recorded
#    absent, exactly as upgrade-server.sh tolerates a non-checkout at ~343).
# --------------------------------------------------------------------------- #
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: backup-server.sh [--keep N]

Seal a full recovery bundle (database + run-state) of an already-installed MaxSecu
server onto its cold tier, and copy every committed blob onto the cold tier too
(keeping the local copy). Roll it back later with restore-server.sh.

The bundle passphrase is read from STDIN and must be piped in, e.g.:

    printf '%s' 'my bundle passphrase' | sudo bash scripts/backup-server.sh

  --keep N   Keep the newest N state bundles and prune older ones (default 10).
             Blobs are never pruned (they are the live cold tier).
  -h,--help  Show this help.
EOF
}

# --------------------------------------------------------------------------- #
# 1. Parse flags. Supports both `--flag value` and `--flag=value`.
# --------------------------------------------------------------------------- #
KEEP=""
while [ $# -gt 0 ]; do
	case "$1" in
	--keep=*)
		KEEP="${1#*=}"
		shift
		;;
	--keep)
		if [ $# -lt 2 ]; then
			echo "error: --keep needs a value" >&2
			exit 2
		fi
		KEEP="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

if [ -n "$KEEP" ]; then
	# Digits only, and short enough that the `-lt` below stays inside the shell's
	# integer range: `[ 99999999999999999999 -lt 1 ]` is not false, it is a
	# "integer expression expected" diagnostic that then falls THROUGH the guard.
	case "$KEEP" in
	'' | *[!0-9]*)
		echo "error: --keep must be a whole number (got '$KEEP')" >&2
		exit 2
		;;
	??????????*)
		echo "error: --keep is implausibly large (got '$KEEP')" >&2
		exit 2
		;;
	esac
	# Pruning runs AFTER the new bundle is sealed and its manifest written, and it
	# keeps the newest N stamps — so N=0 deletes EVERY stamp including the one this
	# run just made, and the driver would still print "BACKUP COMPLETE" over a cold
	# tier with no rollback point on it. Refuse the value rather than leave an
	# operator believing they have a backup.
	if [ "$KEEP" -lt 1 ]; then
		echo "error: --keep must be at least 1 — --keep 0 would prune the bundle this run" >&2
		echo "       just sealed, leaving no rollback point at all." >&2
		exit 2
	fi
fi

# --------------------------------------------------------------------------- #
# 2. Privilege + identity helpers (same model as install-/upgrade-server.sh).
#    Root is needed to read the root-only run-state (the unit + the Dropbox creds
#    file) into the bundle; the build tree + data dir belong to the invoking
#    (non-root) user.
# --------------------------------------------------------------------------- #
IS_ROOT=0
if [ "$(id -u)" -eq 0 ]; then
	IS_ROOT=1
fi

RUN_USER="${SUDO_USER:-$USER}"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
if [ -z "$RUN_HOME" ]; then
	RUN_HOME="$HOME"
fi

DATA_DIR="${MAXSECU_DATA_DIR:-$RUN_HOME/maxsecu-server-data}"
UNIT_PATH="/etc/systemd/system/maxsecu-server.service"
DROPIN_DIR="/etc/systemd/system/maxsecu-server.service.d"
DROPBOX_ENV_PATH="/etc/maxsecu/dropbox.env"
SERVER_BIN="$ROOT/target/release/maxsecu-portable-server"

# Run a command string as root (directly if already root, else via sudo).
run_root() {
	if [ "$IS_ROOT" -eq 1 ]; then
		bash -c "$1"
	else
		sudo bash -c "$1"
	fi
}

# --------------------------------------------------------------------------- #
# 3. Preconditions: the server must already be installed, and its service must
#    run THIS repo's binary (else we'd back up state that does not match the tree
#    a later restore would rebuild). Fail loudly rather than back up the wrong box.
# --------------------------------------------------------------------------- #
echo "==> Checking the existing install"
if ! run_root "test -f '$UNIT_PATH'" </dev/null; then
	echo "error: $UNIT_PATH not found — this server is not installed yet." >&2
	echo "       Run scripts/install-server.sh first (this script BACKS UP an install)." >&2
	echo "" >&2
	echo "       If this box DID have MaxSecu and only the unit is gone, do NOT treat" >&2
	echo "       it as a fresh install. Put the unit back from an EARLIER sealed bundle:" >&2
	echo "" >&2
	echo "           sudo bash scripts/restore-server.sh --list" >&2
	echo "           sudo bash scripts/restore-server.sh --from latest --only state" >&2
	echo "" >&2
	echo "       That unit is the ONLY copy of the database password, and restoring it" >&2
	echo "       also restores the TLS identity, so no client has to re-pin." >&2
	echo "" >&2
	echo "       Only if NO bundle exists is install-server.sh an option, and then only" >&2
	echo "       with the data directory STATED — without a unit it is guessed from" >&2
	echo "       whichever account you are logged in as, and a wrong guess makes the" >&2
	echo "       server mint a NEW identity that locks out every client permanently and" >&2
	echo "       orphans every blob:" >&2
	echo "" >&2
	echo "           sudo env MAXSECU_DATA_DIR='$DATA_DIR' bash scripts/install-server.sh \\" >&2
	echo "               <your flags> --force-overwrite-existing-install" >&2
	echo "" >&2
	echo "       (Check that path first — this script guessed it the same way.) The TLS" >&2
	echo "       certificate is kept, and no client re-pins, ONLY IF the certificate is" >&2
	echo "       actually found at <data dir>/tls/cert.der. install-server.sh refuses" >&2
	echo "       outright if it finds accounts in the database but no certificate there." >&2
	exit 1
fi

if ! run_root "test -x '$SERVER_BIN'" </dev/null; then
	echo "error: $SERVER_BIN is missing/not executable — build it first with" >&2
	echo "       'cargo build --release -p maxsecu-portable-server', or run" >&2
	echo "       scripts/install-server.sh / upgrade-server.sh." >&2
	exit 1
fi

# ExecStart is written as a bare binary path by install-server.sh (no args).
UNIT_BIN="$(run_root "sed -n 's/^ExecStart=//p' '$UNIT_PATH' | head -n1" </dev/null | tr -d '\r')"
if [ "$UNIT_BIN" != "$SERVER_BIN" ]; then
	echo "error: the service runs a different binary than this repo would build:" >&2
	echo "         service ExecStart : $UNIT_BIN" >&2
	echo "         this repo builds  : $SERVER_BIN" >&2
	echo "       Run this script from the SAME clone the service was installed from." >&2
	exit 1
fi
echo "    OK — service runs $SERVER_BIN"

# --------------------------------------------------------------------------- #
# 2c. REFUSE when the INSTALLED binary predates the backup feature.
#
# upgrade-server.sh runs this same probe (its step 3b) — duplicated here ON PURPOSE,
# because upgrade-server.sh is NOT the only way to reach this script. It is reached
# directly by an operator, by `install-server.sh`'s existing-install refusal (which
# offers `sudo bash scripts/backup-server.sh` as remedy 3), and by
# docs/runbooks/backup-restore.md. Every one of those bypasses the guard in
# upgrade-server.sh.
#
# Handing `backup` to a pre-feature binary does NOT fail. Its argument match ended in
# `_ => {}`, so it fell through and STARTED A SECOND SERVER, as root, against this
# same database and data dir, on the compiled-in default port, with the passphrase on
# its stdin and no timeout. Measured on a real 41912da box: it served for 705 seconds
# until it was killed by hand, and it wrote into <data_dir>/client-pins. Worse, a
# pre-feature binary that resolves a data dir with no cert MINTS A NEW TLS IDENTITY
# and a new directory trust root there — which locks out every pinned client
# permanently, with no admin escape hatch.
#
# The probe must not RUN the binary, because running it is the hazard. Look for a
# string only a backup-capable binary contains: `MXBU`, the sealed bundle's 4-byte
# magic (crates/server/src/backup/format.rs).
# --------------------------------------------------------------------------- #
if ! grep -aq 'MXBU' "$SERVER_BIN" 2>/dev/null; then
	echo "error: the INSTALLED server binary predates the backup feature, so it cannot" >&2
	echo "       take a backup. Nothing was changed and the server is still running." >&2
	echo "" >&2
	echo "       On this binary a backup is not possible AT ALL, so the one upgrade that" >&2
	echo "       installs backup support has to skip it:" >&2
	echo "" >&2
	echo "           sudo bash scripts/upgrade-server.sh --no-backup" >&2
	echo "" >&2
	echo "       After that upgrade this script works normally, and every later upgrade" >&2
	echo "       takes a sealed backup automatically." >&2
	echo "" >&2
	echo "       (Refusing rather than trying: asking a pre-feature binary to run a" >&2
	echo "       'backup' it does not know makes it start a SECOND server as root against" >&2
	echo "       this same database, and it never exits.)" >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 3a. Scrape the environment the running server uses out of its unit, so the
#     backup binary resolves EXACTLY the same database, data dir and cold tier
#     the server does (the binary reads these through its LauncherConfig — the
#     one sanctioned env reader; the backup engine itself never touches env).
#
#     Values are pulled from the base unit AND every drop-in, taking the LAST
#     assignment (which is what systemd itself would use), quotes stripped, and —
#     when nothing there supplies the name — from any `EnvironmentFile=` the unit
#     loads. Reading the root:root 0600 unit is why this whole step (and the
#     binary) run as root.
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# THE UNIT-ENV PARSER — FIVE IDENTICAL COPIES, ON PURPOSE. They live in:
#
#     scripts/install-server.sh   scripts/upgrade-server.sh
#     scripts/backup-server.sh    scripts/restore-server.sh
#     scripts/fingerprint.sh
#
# CHANGE ONE, CHANGE ALL FIVE. It is deliberately NOT extracted into
# scripts/lib/unit-env.sh: the server tree is delivered to the VPS by SFTP
# drag-and-drop with no git, so a partial copy that misses scripts/lib/ is a
# realistic failure mode — and `. missing-file` under `set -euo pipefail` would
# abort a DEAD-BOX RESTORE, the one path that must never fail for an avoidable
# reason. Self-contained beats DRY here.
#
# WHY NOT AN ANCHORED `^Environment=` SCRAPE: systemd accepts an INDENTED
# `Environment=` line and optional surrounding quotes, it merges the base unit with
# every drop-in (LAST assignment wins), and it takes the same variables from any
# `EnvironmentFile=` the unit loads (an optional leading `-` = "ignore if absent").
# A stricter scrape reports "unset" for a perfectly valid unit — which aborts a
# backup, and a failed backup aborts the upgrade that depends on it.
#
# KNOWN, DELIBERATE DEVIATION FROM SYSTEMD: real systemd applies `EnvironmentFile=`
# AFTER the `Environment=` lines, so the FILE overrides the unit line. These copies
# consult the file only as a FALLBACK, when no `Environment=` line supplies the
# name. That is the behaviour all of these scripts have always had, and DATABASE_URL
# is the variable at stake: flipping the precedence could change WHICH DATABASE an
# upgrade migrates on a box that sets it in both places. The deviation is recorded
# here rather than "fixed" blind.
# --------------------------------------------------------------------------- #
resolve_unit_env() { # $1 = variable name -> its effective value, or empty
	_name="$1"
	# The unit and every drop-in as ONE blob, read as root (they are 0600). Re-read
	# on EVERY call, never cached: restore-server.sh REPLACES the unit mid-run and
	# must then see the NEW one. `</dev/null` on every run_root so `sudo bash -c`
	# cannot swallow a caller's stdin — backup/restore carry the bundle passphrase
	# there. Tolerates a missing unit (fresh box / dead box): empty, never an abort.
	_all="$(run_root "cat '$UNIT_PATH' '$DROPIN_DIR'/*.conf 2>/dev/null || cat '$UNIT_PATH' 2>/dev/null || true" </dev/null | tr -d '\r')"
	_val="$(
		printf '%s\n' "$_all" |
			sed -n "s/^[[:space:]]*Environment=[\"']\\{0,1\\}${_name}=//p" |
			sed -e 's/^["'\'']//' -e 's/["'\'']$//' |
			tail -n1
	)"
	if [ -z "$_val" ]; then
		_files="$(
			printf '%s\n' "$_all" |
				sed -n 's/^[[:space:]]*EnvironmentFile=//p' |
				sed -e 's/^-//' -e 's/^["'\'']//' -e 's/["'\'']$//' |
				sed '/^$/d'
		)"
		while IFS= read -r _f; do
			[ -n "$_f" ] || continue
			run_root "test -f '$_f'" </dev/null || continue
			_v2="$(
				run_root "cat '$_f'" </dev/null | tr -d '\r' |
					sed -n "s/^[[:space:]]*${_name}=//p" |
					sed -e 's/^["'\'']//' -e 's/["'\'']$//' |
					tail -n1
			)"
			[ -n "$_v2" ] && _val="$_v2"
		done <<EOF
$_files
EOF
	fi
	printf '%s' "$_val"
}

DB_URL="$(resolve_unit_env DATABASE_URL)"
if [ -z "$DB_URL" ]; then
	echo "error: no DATABASE_URL in $UNIT_PATH (or in any EnvironmentFile it loads)" >&2
	echo "       — cannot reach the metadata database to dump it. Nothing was changed;" >&2
	echo "       a backup is a pure read." >&2
	echo "" >&2
	echo "       Do NOT re-run install-server.sh to repair the unit: it refuses to touch" >&2
	echo "       an existing install, and forcing it past that refusal re-mints the" >&2
	echo "       database password whenever the unit carries no working one — which is" >&2
	echo "       exactly the state you are in. Repair it one of these two ways:" >&2
	echo "         1. from an EARLIER sealed backup (it contains the original unit):" >&2
	echo "               sudo bash scripts/restore-server.sh --list" >&2
	echo "         2. or, if the password is genuinely lost, set a new one and put the" >&2
	echo "            matching URL in a ROOT-ONLY (0600 — it is a secret) drop-in:" >&2
	echo "               sudo -u postgres psql -c \"ALTER ROLE maxsecu PASSWORD 'NEWPASS'\"" >&2
	echo "               sudo install -d /etc/systemd/system/maxsecu-server.service.d" >&2
	echo "               printf '[Service]\\nEnvironment=DATABASE_URL=postgres://maxsecu:NEWPASS@localhost/maxsecu\\n' \\" >&2
	echo "                 | sudo install -m 0600 /dev/stdin \\" >&2
	echo "                   /etc/systemd/system/maxsecu-server.service.d/20-database-url.conf" >&2
	echo "               sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server" >&2
	echo "            (No account, key or upload is touched by either route — the rows" >&2
	echo "            live in the database, not in the unit.)" >&2
	exit 1
fi

UNIT_DATA_DIR="$(resolve_unit_env MAXSECU_DATA_DIR)"
if [ -z "$UNIT_DATA_DIR" ]; then
	# Absence means the server uses ./maxsecu-server-data relative to its
	# WorkingDirectory (= this repo root); mirror that so tls/ and config/ resolve.
	UNIT_DATA_DIR="$ROOT/maxsecu-server-data"
fi

# The cold tier the server offloads to — the same destination the bundle rides.
#   * an fs cold tier sets Environment=MAXSECU_COLD_TIER=fs in the unit
#     (install-server.sh --cold-tier-fs), with the directory in MAXSECU_COLD_FS_DIR;
#   * a Dropbox cold tier keeps MAXSECU_COLD_TIER=dropbox and the refresh token in
#     the root-only EnvironmentFile /etc/maxsecu/dropbox.env (never an Environment=
#     line), so it is detected by that file's presence, not by a unit scrape.
UNIT_COLD_TIER="$(resolve_unit_env MAXSECU_COLD_TIER)"
UNIT_COLD_FS_DIR="$(resolve_unit_env MAXSECU_COLD_FS_DIR)"

# --------------------------------------------------------------------------- #
# 3b. Assemble the binary's environment in a transient 0600 file (owned by the
#     run user) that the invocation SOURCES. Secrets (the DB password inside
#     DATABASE_URL, the Dropbox refresh token) travel this way rather than on a
#     command line, where /proc would expose them — the same discipline the
#     passphrase gets. `set -a` around the source exports every KEY=value.
# --------------------------------------------------------------------------- #
BIN_ENV="$(mktemp)"
trap 'rm -f "$BIN_ENV"' EXIT
chmod 0600 "$BIN_ENV"

# Append one `KEY='value'` assignment. This file is SOURCED by a shell, not read
# by systemd's EnvironmentFile parser, and the two disagree about an unquoted
# value that contains a space: systemd takes the whole rest of the line, while
# `.` sees an assignment PREFIX followed by a command and leaves the variable
# UNSET in the sourcing shell. A Dropbox root of `/My backups` (the installer
# takes that folder name from a free-text prompt) would therefore reach the
# backup binary as nothing at all, so it would seal the bundle and copy every
# blob under the default `/maxsecu` while the live server keeps offloading under
# `/My backups` — and a later dead-box rebuild, which reads the restored creds,
# would look in `/My backups` and never find the chunks this backup copied.
# Single quotes make the value literal; an embedded quote is closed, escaped and
# reopened.
emit_env() { # $1 = variable name, $2 = raw value
	printf "%s='%s'\n" "$1" "${2//\'/\'\\\'\'}"
}

# Fold a root-only creds file into that same quoted form, one assignment at a
# time. A single layer of surrounding quotes is stripped first, exactly as
# systemd's EnvironmentFile parser would, so a hand-quoted file keeps the meaning
# the running server gives it; comments and blank lines carry no assignment and
# are dropped rather than re-emitted (an apostrophe inside a comment would
# otherwise pair with one in a neighbouring value and swallow the lines between
# them). The `cat` is `</dev/null`-redirected in HERE rather than at the call
# site, so no future caller can accidentally let this function drink the
# passphrase off the script's stdin.
fold_creds_env() { # $1 = path to the creds file (read as root)
	local line k v
	run_root "cat '$1'" </dev/null | sed 's/^[[:space:]]*//' | while IFS= read -r line; do
		case "$line" in
		[A-Za-z_]*=*) : ;;
		*) continue ;;
		esac
		k="${line%%=*}"
		v="${line#*=}"
		case "$v" in
		\"*\")
			v="${v#\"}"
			v="${v%\"}"
			;;
		\'*\')
			v="${v#\'}"
			v="${v%\'}"
			;;
		esac
		emit_env "$k" "$v"
	done
}

{
	emit_env DATABASE_URL "$DB_URL"
	emit_env MAXSECU_DATA_DIR "$UNIT_DATA_DIR"
	# The `backup` subcommand records the current git HEAD by running `git` in the
	# CWD. This driver runs the binary as ROOT, but the checkout is owned by the
	# run user, so git's dubious-ownership guard would otherwise refuse it and the
	# code marker would be recorded absent even on a real git deploy (breaking
	# `restore --only code`). Marking the tree safe for this one root process keeps
	# a truthful sha without touching any persistent git config.
	printf 'GIT_CONFIG_COUNT=1\n'
	printf 'GIT_CONFIG_KEY_0=safe.directory\n'
	printf 'GIT_CONFIG_VALUE_0=*\n'
} >>"$BIN_ENV"

COLD_KIND="off"
if [ "$UNIT_COLD_TIER" = "fs" ]; then
	COLD_KIND="fs"
	{
		printf 'MAXSECU_COLD_TIER=fs\n'
		if [ -n "$UNIT_COLD_FS_DIR" ]; then
			emit_env MAXSECU_COLD_FS_DIR "$UNIT_COLD_FS_DIR"
		fi
	} >>"$BIN_ENV"
elif run_root "test -f '$DROPBOX_ENV_PATH'" </dev/null; then
	# Dropbox cold tier: fold in the whole root-only creds file
	# (MAXSECU_COLD_TIER=dropbox + MAXSECU_DROPBOX_*), re-quoted assignment by
	# assignment so the binary resolves the SAME root the running server does. Read
	# as root; the 0600 BIN_ENV protects it, and root (the identity the binary runs
	# as here) reads it either way.
	COLD_KIND="dropbox"
	fold_creds_env "$DROPBOX_ENV_PATH" >>"$BIN_ENV"
fi

# The binary runs as root but SOURCES this file; make sure root can read it (it
# always can) and keep it 0600. When we are root, mktemp made it root-owned, which
# is fine — the sourcing shell is root too.
if [ "$COLD_KIND" = "off" ]; then
	echo "warning: the live unit has no cold tier configured (MAXSECU_COLD_TIER is off" >&2
	echo "         and there is no $DROPBOX_ENV_PATH). The backup will fail closed:" >&2
	echo "         there is nowhere to seal the bundle." >&2
	echo "" >&2
	echo "         Do NOT re-run install-server.sh to add one — it refuses to touch an" >&2
	echo "         existing install. Add the tier IN PLACE with a systemd drop-in (no" >&2
	echo "         data is touched, no client re-pins):" >&2
	echo "             sudo install -d /etc/systemd/system/maxsecu-server.service.d" >&2
	echo "             printf '[Service]\\nEnvironment=MAXSECU_COLD_TIER=fs\\nEnvironment=MAXSECU_COLD_FS_DIR=/srv/maxsecu-cold\\n' \\" >&2
	echo "               | sudo install -m 0644 /dev/stdin \\" >&2
	echo "                 /etc/systemd/system/maxsecu-server.service.d/20-cold-tier.conf" >&2
	echo "             sudo install -d -o \"\$(sed -n 's/^User=//p' '$UNIT_PATH' | tail -n1)\" -m 0700 /srv/maxsecu-cold" >&2
	echo "             sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server" >&2
	echo "         The directory must be OUTSIDE the data dir and owned by the unit's" >&2
	echo "         User= — an fs tier aliasing the blob dir DESTROYS ciphertext." >&2
fi
echo "    database   : (scraped from the unit)"
echo "    data dir   : $UNIT_DATA_DIR"
echo "    cold tier  : $COLD_KIND"

# --------------------------------------------------------------------------- #
# 4. Run the backup. The passphrase on THIS script's stdin flows straight into
#    the binary (we do not read it here). The binary is run as root so it can
#    read the root-only unit + dropbox.env into the `state` bundle; its CWD is the
#    repo so the git HEAD is recorded. Every other sub-command above was
#    `</dev/null`-redirected so none of them could have consumed the passphrase.
# --------------------------------------------------------------------------- #
KEEP_ARG=""
if [ -n "$KEEP" ]; then
	KEEP_ARG="--keep $KEEP"
fi

echo "==> Sealing the backup bundle (this reads your passphrase from stdin)"
# NB: no `</dev/null` here — this is the ONE command that must inherit the
# operator's stdin. `run_root` uses `bash -c`/`sudo bash -c`, both of which pass
# stdin through to the sealed command.
if ! run_root "set -a; . '$BIN_ENV'; set +a; cd '$ROOT' && exec '$SERVER_BIN' backup $KEEP_ARG"; then
	echo "error: backup failed. Nothing on the server was changed (backup is a pure" >&2
	echo "       read — it never stops the service or mutates the database)." >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 4a. Hand the fs cold tier back to the SERVICE user. The binary just ran as ROOT
#     (it has to — the state bundle contains the root-0600 unit and dropbox.env),
#     and every directory it created under the cold root — the bundle's
#     `_backup/<stamp>/...` and one per blob_ref copied by backup_copy_refs — is
#     root:root 0755. The server runs as $RUN_USER, so without this its next
#     idle-offload (a `create_dir_all` + write under the cold root) gets EACCES,
#     and that failure is swallowed: WriteBackTier drops the victim and moves on,
#     while a hard-delete's cold-side teardown is logged, not surfaced. The
#     symptom would be a local store that silently stops evicting.
#     Dropbox needs none of this (no local tree). Non-fatal: the backup is already
#     sealed and complete, so a chown failure must not report the backup as failed.
# --------------------------------------------------------------------------- #
#     The owner to hand it BACK to is the unit's own `User=`, not $RUN_USER: on a
#     root shell (no SUDO_USER) $RUN_USER is `root`, which would skip the chown
#     entirely and leave exactly the root-owned tree this exists to prevent.
SVC_USER="$(run_root "sed -n 's/^User=//p' '$UNIT_PATH' | tail -n1" </dev/null | tr -d '\r')"
if [ -z "$SVC_USER" ]; then
	SVC_USER="$RUN_USER"
fi
if [ "$COLD_KIND" = "fs" ] && [ -n "$UNIT_COLD_FS_DIR" ] && [ "$SVC_USER" != "root" ]; then
	if ! run_root "chown -R '$SVC_USER' '$UNIT_COLD_FS_DIR'" </dev/null; then
		echo "warning: could not hand $UNIT_COLD_FS_DIR back to $SVC_USER. The backup is" >&2
		echo "         complete and valid, but the service may be unable to offload into" >&2
		echo "         the cold tier until you run:" >&2
		echo "             sudo chown -R $SVC_USER $UNIT_COLD_FS_DIR" >&2
	fi
fi

echo ""
echo "================ BACKUP COMPLETE ================"
echo "A sealed recovery bundle is on the cold tier and every committed blob has"
echo "been copied there (the local copies are untouched). List bundles with:"
echo "    sudo bash scripts/restore-server.sh --list"
echo "Roll back / rebuild with:"
echo "    printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest"
echo "================================================"
