#!/usr/bin/env bash
#
# upgrade-server.sh — safely rebuild + restart an ALREADY-INSTALLED MaxSecu server
# IN PLACE, with ZERO data loss and no client re-pin.
#
# Use this to apply a code update (e.g. after `git pull`) to a running production
# server. Unlike `install-server.sh --reset`, it NEVER touches your data: the
# Postgres database, the data dir (blobs), the TLS certificate, the client pins,
# and the saved Dropbox login are all left exactly in place. The server's
# fingerprint does not change, so clients keep working WITHOUT re-pinning.
#
# What it does:
#   1. Take a SEALED, rollback-able backup (scripts/backup-server.sh) so a failed
#      upgrade can actually be undone — and ABORT the upgrade if the backup fails.
#      This replaces the old bare pg_dump, which nothing ever read back. It runs
#      BEFORE the pull, using the currently-installed binary, so the bundle records
#      the PRE-upgrade commit (which `restore --only code` checks out to roll the code
#      BACK) and a still-un-migrated database. The bundle is encrypted with a
#      passphrase you are prompted for; skip it only with an explicit --no-backup.
#      (The one exception is the FIRST upgrade into this feature: the installed binary
#      predates the `backup` subcommand, so pass --no-backup for that upgrade alone.)
#   2. (optional) `git pull --ff-only` when this folder is a git checkout; if it
#      isn't (you copied the files in by hand), that step is skipped.
#   3. STOP the server, refresh source timestamps so cargo cannot reuse a stale
#      build, and rebuild the release binary. The service is down for the whole
#      update: that makes two live server processes impossible and lets the
#      migrations run against a quiescent database. A copy of the binary that was
#      running is kept first, and ANY failure from here on puts it back and starts
#      the server again — a failed upgrade never leaves the box down.
#   4. Apply any pending database migrations (migrations/NNNN_*.sql), each in one
#      transaction, BEFORE the new binary starts — so the new code never meets an
#      old schema. Migrations only ADD to the schema; your rows are never
#      rewritten or dropped, and the sealed backup in step 1 already captured a
#      restore point. Nothing at all happens here when the schema is already up to
#      date (the common case).
#   5. (optional) set the local cache capacity via a systemd drop-in.
#   6. RECONCILE the service's environment with what this build expects. The unit
#      was written once, by install-server.sh, and is never rewritten here — so a
#      new MAXSECU_* variable would otherwise reach FRESH INSTALLS ONLY and every
#      already-deployed server would silently run without it, forever. This step
#      adds any MISSING variable via a drop-in, at exactly the value the binary
#      already defaults to. It NEVER touches a variable you have set: your port,
#      your DATABASE_URL, your cache capacity and your Dropbox login are read, not
#      written. Running it twice changes nothing.
#   7. Start the service again and health-check it PROPERLY: `systemctl is-active`
#      is a false-green on a Type=simple + Restart=always unit, so this waits and
#      requires the unit to be active AND to not have restarted in between.
#
# Usage:
#   ./scripts/upgrade-server.sh                    # backup + pull + rebuild + restart
#   ./scripts/upgrade-server.sh --no-pull          # rebuild the current checkout as-is
#   ./scripts/upgrade-server.sh --no-backup        # skip the sealed pre-upgrade backup
#   ./scripts/upgrade-server.sh --capacity-gb 50   # also set the cache cap to 50 GB
#
# Flags:
#   --no-pull        Do NOT `git pull`; rebuild whatever is checked out now.
#   --no-backup      Do NOT take the sealed pre-upgrade backup. You then upgrade with
#                    NO rollback point — only pass this if you know why.
#   --capacity-gb N  Set MAXSECU_CACHE_CAPACITY_BYTES via a systemd drop-in (GB).
#   -h, --help       Show this help.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# 0. Resolve the repo root from this script's own location (scripts/ -> root).
#    NB: git updates tracked files by atomic rename (a new inode), and bash keeps
#    reading the original inode it opened, so a `git pull` below cannot rewrite
#    this running script underneath us.
# --------------------------------------------------------------------------- #
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: upgrade-server.sh [--no-pull] [--no-backup] [--capacity-gb N]

Rebuild + restart an already-installed MaxSecu server IN PLACE, with no data
loss and no client re-pin. Your rows, blobs, TLS cert, client pins, and Dropbox
login are all left untouched (only `install-server.sh --reset` deletes those).
The service is STOPPED for the whole update, so the downtime is the length of
the rebuild, not a blip. That is the trade for never having two live server
processes and for migrating a quiescent database. A copy of the running binary
is taken first and a trap puts it back on ANY failure — including Ctrl-C or a
dropped SSH session — so a failed upgrade never leaves the box down.

Pending database migrations (migrations/NNNN_*.sql) are applied before the
restart, each in a single transaction, so the new code never starts against an
old schema. Migrations only ADD to the schema — no account, key, or uploaded
file is ever touched — and a SEALED, rollback-able backup is taken first (via
scripts/backup-server.sh) unless you pass --no-backup. A failed backup ABORTS
the upgrade: an upgrade you cannot roll back is the failure this guards against.

The service's ENVIRONMENT is reconciled the same way: any variable this build
expects that your unit does not define anywhere is added via a systemd drop-in,
at exactly the value the server already defaults to. A variable you HAVE set —
your port, your DATABASE_URL, your cache capacity, your Dropbox login — is read
and left alone, never overwritten. Running the upgrade twice changes nothing.

  --no-pull        Do NOT `git pull`; rebuild whatever is checked out now.
  --no-backup      Do NOT take the sealed pre-upgrade backup. You then upgrade with
                   NO rollback point — only pass this if you know why.
  --capacity-gb N  Set the local cache capacity in GB (writes a systemd drop-in
                   for MAXSECU_CACHE_CAPACITY_BYTES). Omit to leave it unchanged.
  -h, --help       Show this help.
EOF
}

# --------------------------------------------------------------------------- #
# 1. Parse flags. Supports both `--flag value` and `--flag=value`.
# --------------------------------------------------------------------------- #
DO_PULL=1
DO_BACKUP=1
CAPACITY_GB=""
while [ $# -gt 0 ]; do
	case "$1" in
	--no-pull)
		DO_PULL=0
		shift
		;;
	--no-backup)
		DO_BACKUP=0
		shift
		;;
	--capacity-gb=*)
		CAPACITY_GB="${1#*=}"
		shift
		;;
	--capacity-gb)
		if [ $# -lt 2 ]; then
			echo "error: --capacity-gb needs a value" >&2
			exit 2
		fi
		CAPACITY_GB="$2"
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

if [ -n "$CAPACITY_GB" ]; then
	case "$CAPACITY_GB" in
	'' | *[!0-9]*)
		echo "error: --capacity-gb must be a positive whole number of GB (got '$CAPACITY_GB')" >&2
		exit 2
		;;
	esac
	if [ "$CAPACITY_GB" -lt 1 ]; then
		echo "error: --capacity-gb must be at least 1 GB (got '$CAPACITY_GB')" >&2
		exit 2
	fi
fi

# --------------------------------------------------------------------------- #
# 2. Privilege + identity helpers (same model as install-server.sh). Root is
#    needed for systemd/postgres; the build + data dir belong to the invoking
#    (non-root) user, never root.
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

CARGO_ENV="$RUN_HOME/.cargo/env"
DATA_DIR="${MAXSECU_DATA_DIR:-$RUN_HOME/maxsecu-server-data}"
UNIT_PATH="/etc/systemd/system/maxsecu-server.service"
DROPIN_DIR="/etc/systemd/system/maxsecu-server.service.d"
SERVER_BIN="$ROOT/target/release/maxsecu-portable-server"
# The sealed-backup driver (design 2026-07-16). It scrapes the unit's env, runs the
# freshly-built binary's `backup` subcommand under sudo, and reads the passphrase from
# stdin. We call it with the passphrase piped in (never on argv).
BACKUP_SCRIPT="$ROOT/scripts/backup-server.sh"
# Soft minimum for the backup passphrase, mirroring MIN_PASSPHRASE_CHARS in
# crates/server/src/backup/format.rs (the binary is the real authority — it refuses to
# seal a shorter one, which would abort the upgrade anyway). Kept equal, never higher,
# so this pre-check never rejects a passphrase the binary would accept.
MIN_BACKUP_PASSPHRASE_CHARS=12
# The drop-in this script generates to reconcile the unit's environment (step 7b).
# `10-` sorts before an operator's own drop-in and before `capacity.conf`, and
# drop-ins are applied in lexicographic order with the LAST assignment winning —
# so anything an operator writes still beats what we generate here.
ENV_DROPIN="$DROPIN_DIR/10-maxsecu-env.conf"
# Root-only 0600 creds file the unit loads via `EnvironmentFile=-`. Secrets live
# here and NEVER in an `Environment=` line.
DROPBOX_ENV_PATH="/etc/maxsecu/dropbox.env"

# --------------------------------------------------------------------------- #
# 2a. THE SERVER ENV RECONCILE TABLE — the upgrade half of the single source of
#     truth for every environment variable the server reads (`MAXSECU_ENV_VARS` in
#     crates/portable-server/src/config.rs).
#
#     THE HOLE THIS CLOSES. scripts/install-server.sh writes the systemd unit,
#     including its `Environment=` lines. This script has never rewritten that
#     unit — it only ever appended a capacity drop-in. So a new MAXSECU_* variable
#     added to the installer reached FRESH INSTALLS ONLY: every already-deployed
#     server kept the unit it was installed with, forever, and silently ran
#     without the variable. Exactly the shape of the schema hole (docs/schema.sql
#     applied on fresh install only) that migrations/ now closes.
#
#     THE CONSTRAINT. An upgrade that resets an operator's MAXSECU_PORT or their
#     DATABASE_URL is itself a break. So step 7b writes a drop-in containing ONLY
#     the variables that are MISSING EVERYWHERE — never one that is already set in
#     the unit, in another drop-in, or in an EnvironmentFile. A drop-in is applied
#     AFTER the base unit, so re-emitting a variable that is already set would
#     OVERRIDE the operator, which is the exact opposite of the goal.
#
#     `<NAME>|<default>`, where `-` means NEVER SYNTHESIZE: absence is either
#     meaningful or unrecoverable, and each such row carries its reason below.
#
#     Every non-`-` default is EXACTLY the value the binary already uses when the
#     variable is absent (crates/portable-server/src/config.rs). That is what makes
#     writing it provably behaviour-preserving on a live server: we only ever
#     materialise the value the server is *already running with*, so a reconcile
#     can never change how an existing deployment behaves. It only makes the unit
#     an explicit, complete statement of that configuration — which is what gives a
#     FUTURE variable (one whose default is not safe, or whose default changes) a
#     place to land on servers that already exist.
#
#     NEVER PUT A SECRET IN THIS TABLE: the generated drop-in is 0644. Secrets go
#     in the root-only 0600 EnvironmentFile (see MAXSECU_DROPBOX_* below).
#
#     scripts/install-server.sh carries the matching SERVER_ENV_SURFACE table, and
#     crates/compat/tests/env_surface.rs FAILS THE BUILD if the code and the two
#     tables ever drift apart.
# --------------------------------------------------------------------------- #
SERVER_ENV_RECONCILE='
DATABASE_URL|-
MAXSECU_DATA_DIR|-
MAXSECU_PUBLIC_ADDR|-
MAXSECU_BIND|127.0.0.1
MAXSECU_PORT|8443
MAXSECU_CACHE_CAPACITY_BYTES|200000000000
MAXSECU_OFFLOAD_IDLE_DAYS|30
MAXSECU_DIRECT_LINKS|0
MAXSECU_COLD_TIER|-
MAXSECU_COLD_FS_DIR|-
MAXSECU_DROPBOX_APP_KEY|-
MAXSECU_DROPBOX_APP_SECRET|-
MAXSECU_DROPBOX_REFRESH_TOKEN|-
MAXSECU_DROPBOX_ACCESS_TOKEN|-
MAXSECU_DROPBOX_ROOT|-
'
# Why each `-` (never synthesize):
#
#   DATABASE_URL          The most load-bearing variable of all, and the ONE we
#                         could never invent: it carries a per-install random
#                         password that exists nowhere but this unit. Guessing it
#                         would point the server at a database that does not exist
#                         — every account, key and upload gone from the users'
#                         point of view. Its absence is therefore a HARD ERROR, not
#                         something to paper over: step 5c aborts the upgrade when
#                         it is missing, BEFORE the server is stopped (which is why
#                         that lookup lives in 5c and not next to the migrations
#                         that use it), and names the two ways to repair the unit
#                         (a sealed backup, or a root-only drop-in). It does NOT
#                         send you back to install-server.sh: that script refuses to
#                         touch an existing install, and forcing it past the refusal
#                         re-mints the DB password when the unit carries no working
#                         one. There is no default and never must be.
#
#   MAXSECU_DATA_DIR      Absence means the server is using `./maxsecu-server-data`
#                         RELATIVE to WorkingDirectory. That directory holds the TLS
#                         cert, the client pins, the recovery state and every blob.
#                         Writing an absolute path here would MOVE the data dir out
#                         from under a running deployment: the server would come
#                         back with a brand-new cert (every pinned client locked
#                         out) and an empty blob store. Never.
#
#   MAXSECU_PUBLIC_ADDR   Absence is MEANINGFUL: this server was installed
#                         local-only, and its TLS cert has no public-IP SAN. There
#                         is nothing to default it to — we cannot invent the
#                         operator's IP — and setting one would not regenerate the
#                         cert anyway. `install-server.sh --public` is how a server
#                         becomes public; it rewrites the unit AND drops the stale
#                         cert.
#
#   MAXSECU_COLD_TIER     Absence == the compiled-in `Off` == no cold tier, which is
#   MAXSECU_COLD_FS_DIR   precisely what a server without a Dropbox creds file is
#   MAXSECU_DROPBOX_*     doing today. The cold-tier family is supplied as a group
#                         by the root-only 0600 EnvironmentFile (they are SECRETS —
#                         they must never appear in a 0644 drop-in), and the tier
#                         fails closed unless the whole credential set is present.
#                         Materialising `MAXSECU_COLD_TIER=off` here would add
#                         nothing and would put a second, contradictory assignment
#                         in play against that file. What this script MUST ensure is
#                         that the unit actually LOADS the file — step 7b adds the
#                         `EnvironmentFile=` line if an old unit predates it.

# Run a command string as root (directly if already root, else via sudo).
run_root() {
	if [ "$IS_ROOT" -eq 1 ]; then
		bash -c "$1"
	else
		sudo bash -c "$1"
	fi
}

# Run a command string as the invoking (non-root) user, with a proper HOME.
run_as_user() {
	if [ "$IS_ROOT" -eq 1 ]; then
		su - "$RUN_USER" -c "$1"
	else
		bash -c "$1"
	fi
}

# --------------------------------------------------------------------------- #
# 3. Preconditions: the server must already be installed, and its service must
#    run THIS repo's binary (else we'd rebuild the wrong clone and restart into
#    a stale one). Fail loudly rather than silently upgrading the wrong tree.
# --------------------------------------------------------------------------- #
echo "==> Checking the existing install"
if ! run_root "test -f '$UNIT_PATH'"; then
	echo "error: $UNIT_PATH not found — this server is not installed yet." >&2
	echo "       Run scripts/install-server.sh first (this script only UPGRADES)." >&2
	echo "" >&2
	echo "       If this box DID have MaxSecu and only the unit is gone, do not treat" >&2
	echo "       it as a fresh install: install-server.sh detects the surviving data" >&2
	echo "       dir / database and refuses. Put the unit back from a sealed bundle —" >&2
	echo "           sudo bash scripts/restore-server.sh --list" >&2
	echo "       — because that unit is the ONLY copy of the database password. Only" >&2
	echo "       if no bundle exists is 'install-server.sh <flags>" >&2
	echo "       --force-overwrite-existing-install' the right tool, and then ONLY with" >&2
	echo "       the real data directory stated explicitly:" >&2
	echo "           sudo env MAXSECU_DATA_DIR=/actual/path bash scripts/install-server.sh \\" >&2
	echo "                --force-overwrite-existing-install <flags>" >&2
	echo "       Without it the installer resolves the data dir from the INVOKING USER's" >&2
	echo "       home, and with the unit gone there is nothing to correct that guess." >&2
	echo "       It keeps the TLS certificate (no client re-pins) ONLY IF the cert is" >&2
	echo "       actually found at <data dir>/tls/cert.der; if it is not, the installer" >&2
	echo "       now REFUSES rather than mint a new server identity and lock every" >&2
	echo "       pinned client out permanently. The DB password is re-minted either way." >&2
	exit 1
fi

# ExecStart is written as a bare binary path by install-server.sh (no args).
UNIT_BIN="$(run_root "sed -n 's/^ExecStart=//p' '$UNIT_PATH' | head -n1" | tr -d '\r')"
if [ "$UNIT_BIN" != "$SERVER_BIN" ]; then
	echo "error: the service runs a different binary than this repo would build:" >&2
	echo "         service ExecStart : $UNIT_BIN" >&2
	echo "         this repo builds  : $SERVER_BIN" >&2
	echo "       Run this script from the SAME clone the service was installed from" >&2
	echo "       (the folder whose target/release/ holds the ExecStart path above)." >&2
	echo "       Do NOT re-run install-server.sh to repoint the unit: it now REFUSES to" >&2
	echo "       touch an existing install (it would rewrite the whole unit from this" >&2
	echo "       run's flags). If the original clone is genuinely gone, edit ExecStart" >&2
	echo "       in the unit itself — it is the ONE line this check reads — and restart:" >&2
	echo "           sudo sed -i 's|^ExecStart=.*|ExecStart=$SERVER_BIN|' '$UNIT_PATH'" >&2
	echo "           sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server" >&2
	exit 1
fi
echo "    OK — service runs $SERVER_BIN"
echo "    data dir (left untouched): $DATA_DIR"

# --------------------------------------------------------------------------- #
# 3b. Decide the pre-upgrade backup and collect its passphrase NOW, up front, so a box
#     that cannot be backed up fails FAST — before anything is pulled or built. The
#     SEALED backup itself runs next (step 4), BEFORE the pull, so it records the
#     pre-upgrade commit and an un-migrated DB (see step 4 for why). This replaces the
#     old bare pg_dump, which was DB-only, unencrypted, and which nothing ever read
#     back — it was not a real rollback path.
#
#     FAIL CLOSED: a silent no-backup upgrade is exactly the failure this feature
#     prevents, so a non-interactive run with no way to supply a passphrase ABORTS.
#     The ONLY way to upgrade without a rollback point is the explicit --no-backup.
#
#     The passphrase is read WITHOUT echo into a variable and later piped to
#     backup-server.sh on stdin — never on argv (/proc is world-readable). It lives in
#     this shell's memory only until step 4 consumes and unsets it.
# --------------------------------------------------------------------------- #
BACKUP_PASSPHRASE=""
if [ "$DO_BACKUP" -eq 1 ]; then
	if [ ! -f "$BACKUP_SCRIPT" ]; then
		echo "error: $BACKUP_SCRIPT not found — cannot take the sealed pre-upgrade backup." >&2
		echo "       Update this checkout (the backup driver ships alongside this script)," >&2
		echo "       or pass --no-backup to upgrade WITHOUT a rollback point." >&2
		exit 1
	fi
	# CAN THE INSTALLED BINARY EVEN TAKE A BACKUP? Probe it STATICALLY.
	#
	# Ordered BEFORE the TTY check on purpose: this is a hard property of the box, not
	# of how the script was invoked, and "your binary cannot do this, pass --no-backup"
	# is a far more useful thing to be told than "no terminal".
	#
	# backup-server.sh runs `<installed binary> backup`. A binary that predates the
	# backup feature ends its argument match in `_ => {}` — so that argument does not
	# error, it FALLS THROUGH AND STARTS A SERVER: a second maxsecu-server, as root,
	# on the compiled-in default port, against this same database and data dir, with
	# the backup passphrase sitting on its stdin and no timeout. On a box installed
	# with --port (so the default port is free) it BINDS SUCCESSFULLY and serves
	# forever while this script hangs. That is the single worst thing this script can
	# do, and it happens on the FIRST upgrade into the backup feature — i.e. on every
	# existing deployment, exactly once, which is the least-tested path there is.
	#
	# The probe must not RUN the binary, because running it is the hazard. So look for
	# a string only a backup-capable binary contains: `MXBU`, the sealed bundle's
	# 4-byte magic (crates/server/src/backup/format.rs). Verified present in a
	# backup-capable binary and absent from a pre-feature one.
	#
	# Fail CLOSED and make the operator choose: skipping the backup silently would
	# remove the rollback point without saying so.
	if ! grep -aq 'MXBU' "$SERVER_BIN" 2>/dev/null; then
		echo "error: the INSTALLED server binary predates the backup feature, so it cannot" >&2
		echo "       take the sealed pre-upgrade backup this script wants." >&2
		echo "" >&2
		echo "       Re-run this ONE upgrade with --no-backup:" >&2
		echo "           sudo bash scripts/upgrade-server.sh --no-backup" >&2
		echo "" >&2
		echo "       Every later upgrade can take a backup normally, because the binary this" >&2
		echo "       upgrade installs supports it. Nothing has been changed and the server is" >&2
		echo "       still running." >&2
		echo "" >&2
		echo "       (Refusing rather than skipping silently: asking the old binary to run a" >&2
		echo "       'backup' it does not know would make it start a SECOND server as root" >&2
		echo "       against this same database.)" >&2
		exit 1
	fi
	if [ ! -t 0 ]; then
		echo "error: no terminal to read a backup passphrase from, and --no-backup was not" >&2
		echo "       given. Refusing a silent no-rollback upgrade — that is the exact failure" >&2
		echo "       this backup guards against. Re-run in a terminal to be prompted, or pass" >&2
		echo "       --no-backup to upgrade WITHOUT a rollback point." >&2
		exit 1
	fi
	echo "==> A sealed, rollback-able backup will be taken before this upgrade changes"
	echo "    anything. Choose a passphrase to encrypt it (Argon2id). You will need this"
	echo "    EXACT passphrase to restore — it is stored NOWHERE, so keep it safe."
	while :; do
		printf 'Backup passphrase (min %s chars): ' "$MIN_BACKUP_PASSPHRASE_CHARS"
		read -rs BACKUP_PASSPHRASE || BACKUP_PASSPHRASE=""
		printf '\n'
		printf 'Confirm passphrase: '
		read -rs backup_pp_confirm || backup_pp_confirm=""
		printf '\n'
		if [ "$BACKUP_PASSPHRASE" != "$backup_pp_confirm" ]; then
			echo "    the two entries did not match — try again." >&2
			continue
		fi
		if [ "${#BACKUP_PASSPHRASE}" -lt "$MIN_BACKUP_PASSPHRASE_CHARS" ]; then
			echo "    too short (minimum $MIN_BACKUP_PASSPHRASE_CHARS characters) — try again." >&2
			continue
		fi
		break
	done
	unset backup_pp_confirm
else
	echo "==> Skipping the sealed pre-upgrade backup (--no-backup) — this upgrade will"
	echo "    have NO rollback point if it goes wrong."
fi

# --------------------------------------------------------------------------- #
# 4. SEALED, ROLLBACK-ABLE PRE-UPGRADE BACKUP (design 2026-07-16). This replaces the
#    old bare pg_dump, which was DB-only, unencrypted, and which nothing ever read
#    back — it was never a real rollback path. The sealed bundle carries the DB dump,
#    the unit + drop-ins + Dropbox creds, the TLS cert and the delegation config, and
#    it copies every committed blob onto the cold tier. Backup is a pure READ — it
#    does not stop the server.
#
#    IT RUNS BEFORE THE PULL, ON PURPOSE, using the CURRENTLY-INSTALLED binary
#    ($SERVER_BIN as it is right now — the running one). Two reasons:
#      * the backup manifest records `git rev-parse HEAD`, and `restore --only code`
#        checks that SHA out. To roll the code BACK after a bad upgrade it must be the
#        PRE-upgrade commit — so the backup has to run before `git pull` moves HEAD.
#      * the DB is still un-migrated here, so the bundle is a clean pre-upgrade state.
#    Consequence (documented): the FIRST upgrade INTO this feature is from a binary
#    that predates the `backup` subcommand, so its backup fails — pass --no-backup for
#    that one transitional upgrade; every subsequent upgrade backs up normally.
#
#    ABORT ON FAILURE ("Auto-backup, abort on failure"): a failed backup means the
#    upgrade would not be rollback-able. Nothing has been pulled, built, migrated or
#    restarted at this point, so aborting leaves the running server wholly untouched.
#
#    The passphrase (collected in step 3b) is piped to backup-server.sh on STDIN,
#    never on argv (/proc is world-readable). backup-server.sh owns the privilege +
#    env-scraping (it exports the unit's cold-tier env and runs the binary under
#    sudo); we stay agnostic to that and simply feed it the passphrase line.
# --------------------------------------------------------------------------- #
if [ "$DO_BACKUP" -eq 1 ]; then
	echo "==> Taking the sealed pre-upgrade backup (scripts/backup-server.sh)"
	if ! printf '%s\n' "$BACKUP_PASSPHRASE" | bash "$BACKUP_SCRIPT"; then
		unset BACKUP_PASSPHRASE
		echo "error: the sealed pre-upgrade backup FAILED — aborting the upgrade before any" >&2
		echo "       change. Nothing was pulled, built, migrated or restarted; the running" >&2
		echo "       server is untouched. Likely causes:" >&2
		echo "         * this is the FIRST upgrade into the backup feature — the installed" >&2
		echo "           binary predates the 'backup' subcommand. Pass --no-backup for this" >&2
		echo "           one upgrade; the next one backs up normally." >&2
		echo "         * NO cold tier is configured (the bundle has nowhere to live). Do NOT" >&2
		echo "           re-run install-server.sh to add one — it refuses to touch an existing" >&2
		echo "           install. Add it IN PLACE with a systemd drop-in (no data is touched," >&2
		echo "           no client re-pins):" >&2
		echo "               sudo install -d /etc/systemd/system/maxsecu-server.service.d" >&2
		echo "               printf '[Service]\\nEnvironment=MAXSECU_COLD_TIER=fs\\nEnvironment=MAXSECU_COLD_FS_DIR=/srv/maxsecu-cold\\n' \\" >&2
		echo "                 | sudo install -m 0644 /dev/stdin \\" >&2
		echo "                   /etc/systemd/system/maxsecu-server.service.d/20-cold-tier.conf" >&2
		echo "               sudo install -d -o \$(sed -n 's/^User=//p' '$UNIT_PATH' | tail -n1) -m 0700 /srv/maxsecu-cold" >&2
		echo "               sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server" >&2
		echo "           (the directory must be OUTSIDE the data dir, and owned by the unit's" >&2
		echo "           User= — an fs tier aliasing the blob dir destroys ciphertext.)" >&2
		echo "       Or pass --no-backup to upgrade WITHOUT a rollback point." >&2
		exit 1
	fi
	unset BACKUP_PASSPHRASE
	echo "    backup OK"
fi

# --------------------------------------------------------------------------- #
# 5. Optional git pull. Git is used only when this folder IS a git checkout and
#    git is installed; otherwise (e.g. you copied the files in by hand) we skip
#    the pull and just build what is already on disk. A fast-forward-only pull
#    means a diverged/dirty tree fails loudly instead of silently merging.
# --------------------------------------------------------------------------- #
if [ "$DO_PULL" -eq 0 ]; then
	echo "==> Skipping git pull (--no-pull); building the files already in place"
elif ! run_as_user "command -v git >/dev/null 2>&1 && git -C '$ROOT' rev-parse --is-inside-work-tree >/dev/null 2>&1"; then
	echo "==> Not a git checkout (or git not installed) — skipping pull, using the files already in place"
else
	echo "==> Updating the source (git pull --ff-only)"
	BEFORE="$(run_as_user "git -C '$ROOT' rev-parse --short HEAD" | tr -d '\r')"
	if ! run_as_user "git -C '$ROOT' pull --ff-only"; then
		echo "error: 'git pull --ff-only' failed. The running server was NOT touched." >&2
		echo "       Resolve the repo state (or re-run with --no-pull to build the" >&2
		echo "       files already in place), then run this script again." >&2
		exit 1
	fi
	AFTER="$(run_as_user "git -C '$ROOT' rev-parse --short HEAD" | tr -d '\r')"
	if [ "$BEFORE" = "$AFTER" ]; then
		echo "    already up to date at $AFTER"
	else
		echo "    updated $BEFORE -> $AFTER"
	fi
fi

# --------------------------------------------------------------------------- #
# 5a. SANITY-CHECK THE TREE ON DISK -- while the server is still serving.
#
# Production has no git. The new version is DRAGGED AND DROPPED on top of the old
# folder, so there is no commit to verify against and a copy can be partial: an
# interrupted SFTP transfer, a zip extracted without its subfolders, or simply the
# wrong directory. Every one of those used to be discovered AFTER the server was
# stopped -- migrations/apply.sh is sourced at step 6b, so a missing migrations/
# aborted the run under `set -e` with the service already down.
#
# Check it here, where a failure costs nothing, and PRINT what was found so the
# operator can see whether the folder they copied is the one they meant.
# --------------------------------------------------------------------------- #
echo "==> Checking the source tree on disk"
if [ ! -d "$ROOT/migrations" ]; then
	echo "error: $ROOT/migrations does not exist." >&2
	echo "       This tree cannot be the new version -- every release since the" >&2
	echo "       migration runner landed ships that directory." >&2
	echo "" >&2
	echo "       You are most likely upgrading the WRONG FOLDER, or the copy of the" >&2
	echo "       new tree onto this box is incomplete. Re-copy the whole tree over" >&2
	echo "       $ROOT and run this again." >&2
	echo "" >&2
	echo "       The server was NOT stopped and nothing was changed." >&2
	exit 1
fi
if [ ! -f "$ROOT/migrations/apply.sh" ]; then
	echo "error: $ROOT/migrations/apply.sh is missing (the migration runner)." >&2
	echo "       The copy of the new tree onto this box is incomplete. Re-copy it." >&2
	echo "       The server was NOT stopped and nothing was changed." >&2
	exit 1
fi
TREE_MIGRATIONS="$(find "$ROOT/migrations" -maxdepth 1 -type f -name '*.sql' | wc -l | tr -d ' ')"
if [ "$TREE_MIGRATIONS" -eq 0 ]; then
	echo "error: $ROOT/migrations holds no .sql files at all." >&2
	echo "       Expected at least 0001_baseline.sql. The copy is incomplete." >&2
	echo "       The server was NOT stopped and nothing was changed." >&2
	exit 1
fi
echo "    migrations in this tree: $TREE_MIGRATIONS"
find "$ROOT/migrations" -maxdepth 1 -type f -name '*.sql' -printf '      %f\n' 2>/dev/null | LC_ALL=C sort || true

# --------------------------------------------------------------------------- #
# 5b. PRE-FETCH the crates this build needs -- still before anything is stopped.
#
# The rebuild at step 6 runs with the service DOWN. cargo resolves and downloads
# dependencies at that moment, so on a box with no outbound HTTPS to crates.io (a
# firewalled VPS, an expired proxy, a DNS outage) the FIRST thing that fails is the
# build, and it fails mid-downtime. The EXIT trap does restore the previous binary,
# but the outage is real and the operator is left reading a cargo network error.
#
# Fetching here turns that into a clean pre-flight refusal with the server still
# serving. It is a no-op on a box whose registry cache is already warm.
# --------------------------------------------------------------------------- #
echo "==> Pre-fetching build dependencies (before anything is stopped)"
if ! run_as_user "cd '$ROOT' && . '$CARGO_ENV' && cargo fetch --locked"; then
	echo "error: could not fetch the crates this build needs." >&2
	echo "" >&2
	echo "       This runs BEFORE the server is stopped precisely so a network or" >&2
	echo "       registry problem cannot strand you mid-upgrade. The server is still" >&2
	echo "       running and nothing was changed." >&2
	echo "" >&2
	echo "       Usual causes: no outbound HTTPS to crates.io / static.crates.io," >&2
	echo "       a proxy that needs configuring, or a Cargo.lock that disagrees with" >&2
	echo "       Cargo.toml (--locked refuses to update it)." >&2
	echo "" >&2
	echo "       Fix connectivity and run this script again." >&2
	exit 1
fi
echo "    dependencies are available locally"

# --------------------------------------------------------------------------- #
# 5c. Resolve everything we read out of the unit BEFORE anything is stopped.
#
#     Every one of these lookups can fail, and a failure must abort while the
#     server is still SERVING. Resolving them after the stop is how you get an
#     upgrade that dies at "no DATABASE_URL" with production already down and no
#     rollback — the abort messages below even promise the opposite ("before
#     touching anything"), so the promise and the code have to be made to agree.
#
#     The parser matters. systemd accepts a leading indent on `Environment=` and
#     optional surrounding quotes, and it also takes the same variables from any
#     `EnvironmentFile=` the unit loads. An anchored `^Environment=` scrape sees
#     none of that and reports "unset" for a perfectly valid unit.
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

DATABASE_URL="$(resolve_unit_env DATABASE_URL)"
if [ -z "$DATABASE_URL" ]; then
	echo "error: no DATABASE_URL in $UNIT_PATH (or in any EnvironmentFile it loads)" >&2
	echo "       — cannot reach the database to check for pending schema migrations." >&2
	echo "       Refusing to restart into a possibly mismatched schema." >&2
	echo "       Nothing has been changed and the server is still running." >&2
	echo "" >&2
	echo "       Do NOT re-run install-server.sh to repair the unit: it refuses to touch" >&2
	echo "       an existing install, and forcing it past that refusal re-mints the" >&2
	echo "       database password whenever the unit carries no working one — which is" >&2
	echo "       exactly the state you are in. Repair it one of these two ways:" >&2
	echo "         1. from a sealed backup (it contains the original unit):" >&2
	echo "               sudo bash scripts/restore-server.sh --list" >&2
	echo "               printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh \\" >&2
	echo "                   --from latest --only state" >&2
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

# postgres://USER:PASS@HOST[:PORT]/DB[?params]  (install-server.sh writes exactly
# this shape; the password is `openssl rand -hex 24`, so it is never URL-encoded).
DB_REST="${DATABASE_URL#*://}"
DB_CREDS="${DB_REST%%@*}"
DB_HOSTPATH="${DB_REST#*@}"
DB_USER="${DB_CREDS%%:*}"
DB_PASS=""
if [ "$DB_CREDS" != "$DB_USER" ]; then
	DB_PASS="${DB_CREDS#*:}"
fi
DB_HOSTPORT="${DB_HOSTPATH%%/*}"
DB_NAME="${DB_HOSTPATH#*/}"
DB_NAME="${DB_NAME%%\?*}"
DB_HOST="${DB_HOSTPORT%%:*}"
DB_PORT="${DB_HOSTPORT#*:}"
if [ "$DB_PORT" = "$DB_HOSTPORT" ]; then
	DB_PORT=5432
fi
if [ -z "$DB_USER" ] || [ -z "$DB_HOST" ] || [ -z "$DB_NAME" ]; then
	echo "error: could not parse the DATABASE_URL from $UNIT_PATH." >&2
	echo "       Expected postgres://USER:PASS@HOST/DB. Refusing to continue." >&2
	echo "       Nothing has been changed and the server is still running." >&2
	exit 1
fi

# The data dir the unit actually uses — NOT a guess. Used only for the read-only
# fingerprint print at the end, but guessing it prints a spurious error on any box
# installed with a non-default data dir.
UNIT_DATA_DIR="$(resolve_unit_env MAXSECU_DATA_DIR)"
if [ -n "$UNIT_DATA_DIR" ]; then
	DATA_DIR="$UNIT_DATA_DIR"
fi

# --------------------------------------------------------------------------- #
# 6. STOP THE SERVER, then rebuild.
#
#    The service is down for the whole update. That is deliberate: it makes it
#    impossible for two server processes to be live at once, and it lets the
#    migrations below run against a quiescent database. The price is real downtime
#    for the length of the build, which makes the FAILURE path the important part
#    — so we keep a copy of the binary that is running right now and put it back if
#    anything goes wrong. A failed upgrade must never leave the box down.
#
#    "Anything goes wrong" has to mean ANYTHING, not just the failures we thought
#    to guard. Between the stop and the start there are dozens of privileged
#    commands, any of which `set -euo pipefail` will abort on, plus whatever a
#    Ctrl-C or a dropped SSH session does. So the rollback hangs off a TRAP rather
#    than off individual `if` blocks: SERVER_STOPPED is raised the moment the unit
#    goes down and cleared only when a start has been CONFIRMED healthy, and the
#    EXIT trap restores the old binary whenever it is still raised.
# --------------------------------------------------------------------------- #
PREV_BIN="$SERVER_BIN.pre-upgrade"
SERVER_STOPPED=0
ENV_TMP=""

# Is the unit genuinely healthy, or merely "active"?
#
# `systemctl is-active` ALONE IS A FALSE-GREEN. The unit is Type=simple with
# Restart=always, so systemd reports it active the instant the fork/exec succeeds
# — a binary that panics 200ms into startup still reads "active" while it
# crash-loops. So: sample NRestarts, wait, and require both that it is still
# active and that it has not restarted in between.
#
# The wait must outlast the SLOWEST way the server can die on startup, or the
# check is a false-green of its own. The serve path's Postgres acquire timeout is
# 10s (crates/portable-server/src/run.rs), so a binary that cannot reach the
# database is still on its FIRST process — active, NRestarts unchanged — for a
# full 10 seconds. A 5s window declared that healthy.
SETTLE_SECONDS=20
settle_check() {
	_before="$(run_root "systemctl show maxsecu-server -p NRestarts --value" </dev/null | tr -d '\r')"
	sleep "$SETTLE_SECONDS"
	_after="$(run_root "systemctl show maxsecu-server -p NRestarts --value" </dev/null | tr -d '\r')"
	SETTLE_RESTARTS_BEFORE="$_before"
	SETTLE_RESTARTS_AFTER="$_after"
	run_root "systemctl is-active --quiet maxsecu-server" </dev/null &&
		[ "$_before" = "$_after" ]
}

# Put the pre-upgrade binary back and bring the server up again. Reached from the
# EXIT trap, so it must be safe to call in any state and must never itself abort.
restore_previous_binary() {
	[ "$SERVER_STOPPED" = "1" ] || return 0
	echo "==> Restoring the pre-upgrade binary and starting the server again" >&2
	# STOP FIRST. On the crash-loop path the unit is auto-restarting, so the old
	# process may hold the image (`cp` -> ETXTBSY) and `systemctl start` would be a
	# no-op against a unit systemd already considers active. And a unit that burned
	# through the default start rate limit (5 starts / 10s, which a 200ms death plus
	# RestartSec=2 reaches) sits in `failed` and will not start at all until it is
	# reset — so reset it.
	run_root "systemctl stop maxsecu-server" </dev/null || true
	run_root "systemctl reset-failed maxsecu-server" </dev/null || true
	# UNLINK BEFORE COPYING — not cosmetic. Cargo HARDLINKS
	# target/release/<bin> to target/release/deps/<bin>-<hash> (verified: same inode,
	# link count 2). A plain `cp` opens the destination with O_TRUNC and writes THROUGH
	# that link, so it would rewrite cargo's cached artifact with the OLD bytes while
	# leaving cargo's fingerprint saying "fresh" — and a later bare
	# `cargo build --release` would then re-link the stale binary into place and report
	# success. Removing the path first breaks the link, so the copy lands on a new
	# inode and cargo's cache is left honest.
	run_root "rm -f '$SERVER_BIN'" || true
	run_root "cp -p '$PREV_BIN' '$SERVER_BIN'" || true
	run_root "systemctl start maxsecu-server" </dev/null || true
	# Judge the rollback by the SAME standard as the upgrade. Reporting success from
	# a bare `is-active` here would be the exact false-green this script exists to
	# eliminate, on the one path where being wrong is worst.
	if settle_check; then
		echo "    the server is back up on the pre-upgrade binary; your data is untouched." >&2
		SERVER_STOPPED=0
	else
		echo "    WARNING: the server did NOT come back up healthy." >&2
		echo "             (NRestarts $SETTLE_RESTARTS_BEFORE -> $SETTLE_RESTARTS_AFTER over ${SETTLE_SECONDS}s)" >&2
		echo "             The pre-upgrade binary is in place at $SERVER_BIN." >&2
		echo "             Investigate with: journalctl -u maxsecu-server -n 50 --no-pager" >&2
	fi
}

# One EXIT trap for the whole script. It owns BOTH the tempfile cleanup and the
# rollback, because a second `trap ... EXIT` anywhere would silently replace this
# one — which is how the env-reconcile step used to disarm the rollback.
on_exit() {
	_status=$?
	[ -n "$ENV_TMP" ] && rm -f "$ENV_TMP"
	if [ "$SERVER_STOPPED" = "1" ]; then
		echo "" >&2
		echo "error: the upgrade stopped early with the service still DOWN" >&2
		echo "       (exit status $_status). Rolling back so the box is serving again." >&2
		restore_previous_binary
	fi
	return $_status
}
trap on_exit EXIT
# Convert a Ctrl-C / SIGTERM into a normal exit so the EXIT trap above runs. The
# largest window for one is the multi-minute rebuild, with the service down.
trap 'exit 130' INT
trap 'exit 143' TERM

echo "==> Stopping maxsecu-server for the update"
run_root "cp -p '$SERVER_BIN' '$PREV_BIN'"
run_root "systemctl stop maxsecu-server"
# From here until a CONFIRMED healthy start, the EXIT trap owns the box.
SERVER_STOPPED=1

# DEFEAT CARGO'S mtime FRESHNESS CHECK.
#
# Production is deployed by DRAGGING THE TREE OVER, and SFTP clients commonly
# PRESERVE each file's modification time. If those times end up older than the
# artifacts already in target/ — which happens whenever the box was last built more
# recently than the sources were authored — cargo judges the changed crates "fresh"
# and does not rebuild them. Observed for real: crates/server sources dated 07-17
# against an rlib built 08-01 produced `unresolved import maxsecu_server::backup`.
# That failure was loud, but the same mechanism can just as easily yield a binary
# that silently mixes new and old code while this script prints UPGRADE COMPLETE.
# Touching the workspace sources makes them all newer than any surviving artifact,
# so cargo re-examines every one; unchanged crates still hit the cache, so this
# costs little. Registry dependencies are immutable and unaffected.
echo "==> Refreshing source timestamps so cargo cannot reuse a stale build"
run_as_user "find '$ROOT/crates' '$ROOT/tools' -name '*.rs' -type f -exec touch {} + 2>/dev/null || true; touch '$ROOT/Cargo.toml' '$ROOT/Cargo.lock' 2>/dev/null || true; true"

echo "==> Rebuilding maxsecu-portable-server (release) — this can take a while"
if ! run_as_user "cd '$ROOT' && . '$CARGO_ENV' && cargo build --release -p maxsecu-portable-server"; then
	echo "error: build failed. Nothing was migrated and no configuration changed." >&2
	restore_previous_binary
	exit 1
fi
if ! run_as_user "test -x '$SERVER_BIN'"; then
	echo "error: build reported success but $SERVER_BIN is missing/not executable." >&2
	restore_previous_binary
	exit 1
fi
echo "    build OK"

# Did this build actually produce different code? PREV_BIN is the byte copy taken
# before the stop. An IDENTICAL hash means the tree on disk builds exactly what was
# already installed -- which is correct and expected when re-running this script,
# but is ALSO the signature of the one mistake a no-git deployment makes easily:
# upgrading a folder the new files were never copied into. Say so rather than
# printing an unqualified success; the operator is the only one who can tell the
# two apart.
NEW_BIN_SHA="$(run_root "sha256sum '$SERVER_BIN' 2>/dev/null | cut -d' ' -f1" || true)"
OLD_BIN_SHA="$(run_root "sha256sum '$PREV_BIN' 2>/dev/null | cut -d' ' -f1" || true)"
if [ -n "$NEW_BIN_SHA" ] && [ "$NEW_BIN_SHA" = "$OLD_BIN_SHA" ]; then
	echo ""
	echo "    NOTE: the rebuilt binary is BYTE-IDENTICAL to the one already installed"
	echo "          ($NEW_BIN_SHA)."
	echo "          That is normal if you are re-running this script. If you expected"
	echo "          NEW code, the new files did not reach $ROOT -- check that you"
	echo "          copied the new tree over THIS folder, then run this again."
	echo ""
else
	echo "    binary changed: ${OLD_BIN_SHA:-(none)} -> ${NEW_BIN_SHA:-(unknown)}"
fi

# --------------------------------------------------------------------------- #
# 6b. Apply pending database migrations — BEFORE the restart, so the new binary
#     never starts against an old schema.
#
#     This is the hole this step closes: docs/schema.sql used to be applied ONLY
#     by install-server.sh on a FRESH install, and this script applied no schema
#     change at all. Any edit to the schema therefore stranded every existing
#     deployment — new code expecting a column the running database did not have.
#
#     migrations/apply.sh applies each pending migrations/NNNN_*.sql in ONE
#     transaction together with its schema_migrations row (all-or-nothing), in
#     numeric order, and REFUSES to run if an already-applied migration's
#     recorded sha256 no longer matches the file on disk (rewritten history would
#     make this server and a fresh install permanently different products).
#
#     Migrations must run as the `maxsecu` APP role, not the postgres superuser —
#     otherwise new objects would be owned by `postgres` and the server could not
#     use them. The role's password lives in the root-owned 0600 systemd unit, so
#     we read it from there and pass it via PGPASSWORD (never on argv, where `ps`
#     would show it). DATABASE_URL was resolved and parsed back in step 5c, while
#     the server was still up, precisely so that a bad unit cannot strand the box.
# --------------------------------------------------------------------------- #
echo "==> Applying database migrations"

MIGRATIONS_DIR="$ROOT/migrations"
db_psql() {
	PGPASSWORD="$DB_PASS" psql -v ON_ERROR_STOP=1 \
		-h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" "$@"
}
# shellcheck source=../migrations/apply.sh
. "$MIGRATIONS_DIR/apply.sh"

# Each of these returns non-zero (never exits) on failure, so guarding them in an
# `if` is enough — and it MUST be guarded now that the service is stopped: a bare
# `set -e` abort here would leave the box down. Every migration runs in its own
# transaction, so a failure leaves the schema at the last good state, which is
# exactly the schema the pre-upgrade binary expects.
if ! migrations_ensure_table ||
	# Refuse BEFORE applying anything: a rewritten history must never be half-run.
	! migrations_verify_history ||
	! migrations_apply_pending; then
	echo "error: database migrations failed. The schema is at its last good state." >&2
	restore_previous_binary
	exit 1
fi

# --------------------------------------------------------------------------- #
# 7. Optional: set the cache capacity via a systemd drop-in (clean + reversible;
#    does not edit the main unit). Only written when --capacity-gb was given.
# --------------------------------------------------------------------------- #
if [ -n "$CAPACITY_GB" ]; then
	CAP_BYTES=$((CAPACITY_GB * 1000000000))
	echo "==> Setting cache capacity to ${CAPACITY_GB} GB ($CAP_BYTES bytes) via drop-in"
	run_root "mkdir -p '$DROPIN_DIR'"
	run_root "printf '[Service]\nEnvironment=MAXSECU_CACHE_CAPACITY_BYTES=%s\n' '$CAP_BYTES' > '$DROPIN_DIR/capacity.conf'"
	run_root "chmod 0644 '$DROPIN_DIR/capacity.conf'"
	run_root "systemctl daemon-reload"
fi

# --------------------------------------------------------------------------- #
# 7b. RECONCILE THE UNIT'S ENVIRONMENT with the surface this build expects.
#     (Runs AFTER step 7 on purpose, so a --capacity-gb given on THIS run counts
#     as "already set" and is never second-guessed below.)
#
#     Algorithm — deliberately conservative, because getting this wrong resets a
#     live server's configuration:
#
#       ALREADY = every variable NAME defined by
#                   the base unit
#                 ∪ every drop-in EXCEPT the one we generate
#                 ∪ every EnvironmentFile the unit loads
#                 ∪ (systemd's own merged view MINUS the names in our drop-in)
#       WRITE   = { (name, default) ∈ SERVER_ENV_RECONCILE
#                 : default ≠ '-'  ∧  name ∉ ALREADY }
#
#     SYSTEMD PRECEDENCE, and why the shape above is the safe one:
#
#       * Drop-ins are applied AFTER the base unit (and among themselves in
#         lexicographic filename order), and for a variable set twice the LAST
#         assignment wins. So writing a variable into a drop-in OVERRIDES the base
#         unit. That is why we must never emit a name that is already set anywhere:
#         it would silently replace the operator's value with our default. "Only
#         what is missing everywhere" is the entire safety property.
#       * `EnvironmentFile=` is read at exec time and its settings OVERRIDE
#         `Environment=` (systemd.exec(5)). We still treat a name defined in one as
#         ALREADY-set and decline to emit it — relying on that precedence rule to
#         save us would be relying on the subtlest line in the manual.
#
#     We parse the FILES rather than trusting `systemctl show` alone, because the
#     merged view cannot tell our own drop-in apart from the operator's — and on
#     the second run ours is loaded, so "already set" computed from the merged view
#     would make us rewrite our own drop-in EMPTY (a flip-flop, not a no-op). We
#     still UNION IN `systemctl show` (minus the names in our own drop-in) as a
#     safety net for anything the file parser could miss (line continuations,
#     exotic quoting). Every discrepancy therefore lands on the safe side: an extra
#     name in ALREADY means we decline to write — never that we overwrite.
#
#     IDEMPOTENT: the drop-in's content is a pure function of the table and of
#     ALREADY, and it is rewritten only when it actually differs — so a second run
#     changes nothing and does not even daemon-reload.
# --------------------------------------------------------------------------- #
echo "==> Reconciling the service environment with this build"

# Extract variable NAMES from `Environment=` directives. Several assignments may
# share one line, and systemd permits surrounding quotes.
env_names_from_unit_text() {
	sed -n 's/^[[:space:]]*Environment=//p' |
		tr ' \t' '\n\n' |
		sed -n 's/^["'\'']\{0,1\}\([A-Za-z_][A-Za-z0-9_]*\)=.*$/\1/p'
}

# Extract variable NAMES from an EnvironmentFile's `KEY=value` lines (`#` comments
# and blanks simply do not match).
env_names_from_env_file() {
	sed -n 's/^[[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\)=.*$/\1/p'
}

# Extract the PATHS an `EnvironmentFile=` directive names, dropping the optional
# leading `-` (= "ignore if absent") and any surrounding quotes.
env_file_paths() {
	sed -n 's/^[[:space:]]*EnvironmentFile=//p' |
		sed -e 's/^-//' -e 's/^["'\'']//' -e 's/["'\'']$//' |
		sed '/^$/d'
}

# The unit is root:root 0600, and so are the creds files — read them as root.
# `</dev/null` on every run_root inside a read loop: `sudo bash -c` would otherwise
# inherit the loop's stdin and could swallow the lines still to be read.
UNIT_TEXT="$(run_root "cat '$UNIT_PATH'" </dev/null)"
DROPIN_LIST="$(run_root "ls -1 '$DROPIN_DIR'/*.conf 2>/dev/null || true" </dev/null | tr -d '\r')"

# Split every config file into OTHER (the base unit + every drop-in that is NOT
# ours — i.e. everything an operator or install-server.sh owns) and OURS (the
# drop-in this script generates). The split is the whole trick: OURS is ours to
# rewrite, so it must never count as "somebody already set this" — otherwise the
# second run would see its own output, conclude nothing is missing, and rewrite the
# drop-in EMPTY. That is a flip-flop, not an idempotent no-op.
OTHER_TEXT="$UNIT_TEXT"
OURS_TEXT=""
while IFS= read -r dconf; do
	[ -n "$dconf" ] || continue
	dtext="$(run_root "cat '$dconf'" </dev/null)"
	if [ "$dconf" = "$ENV_DROPIN" ]; then
		OURS_TEXT="$OURS_TEXT
$dtext"
	else
		OTHER_TEXT="$OTHER_TEXT
$dtext"
	fi
done <<EOF
$DROPIN_LIST
EOF

# (1) Names set by the base unit + every drop-in that is not ours.
ALREADY="$(printf '%s\n' "$OTHER_TEXT" | env_names_from_unit_text)"
OURS="$(printf '%s\n' "$OURS_TEXT" | env_names_from_unit_text)"

# (2) Names set by every EnvironmentFile the unit loads. The Dropbox creds arrive
#     this way; they are SECRETS and must never be re-emitted into a 0644 drop-in.
#     Names are harvested from every declared file (ours included — the file's
#     contents are the same whoever declared it), but whether the unit ALREADY
#     DECLARES the Dropbox file is judged from OTHER only, for the same reason as
#     above: if we added that declaration on a previous run we must add it again,
#     or it would vanish on this one.
ENV_FILE_LIST_OTHER="$(printf '%s\n' "$OTHER_TEXT" | env_file_paths)"
ENV_FILE_LIST_ALL="$(printf '%s\n%s\n' "$OTHER_TEXT" "$OURS_TEXT" | env_file_paths | sort -u)"

UNIT_LOADS_DROPBOX_ENV=0
if printf '%s\n' "$ENV_FILE_LIST_OTHER" | grep -qxF -- "$DROPBOX_ENV_PATH"; then
	UNIT_LOADS_DROPBOX_ENV=1
fi

while IFS= read -r efile; do
	[ -n "$efile" ] || continue
	if run_root "test -f '$efile'" </dev/null; then
		ALREADY="$ALREADY
$(run_root "cat '$efile'" </dev/null | env_names_from_env_file)"
	fi
done <<EOF
$ENV_FILE_LIST_ALL
EOF

# (3) Safety net: systemd's own merged view of `Environment=` — it, not us, is the
#     authority on drop-in ordering, quoting and line continuations — minus the
#     names in OUR drop-in (same reason as above). A name this adds can only make
#     us decline to write; it can never make us overwrite. Every discrepancy
#     between the two parsers therefore lands on the safe side.
SYSTEMD_ENV_NAMES="$(
	run_root "systemctl show maxsecu-server -p Environment --value 2>/dev/null || true" </dev/null |
		tr -d '\r' | tr ' \t' '\n\n' |
		sed -n 's/^["'\'']\{0,1\}\([A-Za-z_][A-Za-z0-9_]*\)=.*$/\1/p'
)"
while IFS= read -r sname; do
	[ -n "$sname" ] || continue
	if printf '%s\n' "$OURS" | grep -qxF -- "$sname"; then
		continue
	fi
	ALREADY="$ALREADY
$sname"
done <<EOF
$SYSTEMD_ENV_NAMES
EOF

ALREADY="$(printf '%s\n' "$ALREADY" | sed '/^$/d' | sort -u)"

# Build the drop-in body: the table's entries that have a default AND are missing
# everywhere. A default is never a secret and never contains whitespace (guarded),
# so no quoting is required.
DROPIN_BODY=""
ADDED=""
while IFS='|' read -r rname rdefault; do
	[ -n "$rname" ] || continue
	[ "$rdefault" != "-" ] || continue # never synthesize (see the table's notes)
	case "$rdefault" in
	*[[:space:]\"\']*)
		echo "error: SERVER_ENV_RECONCILE default for $rname contains whitespace or a quote." >&2
		echo "       The generated drop-in writes bare Environment=NAME=VALUE lines." >&2
		exit 1
		;;
	esac
	if printf '%s\n' "$ALREADY" | grep -qxF -- "$rname"; then
		continue # already set — the operator's / the unit's value stands untouched
	fi
	DROPIN_BODY="$DROPIN_BODY
Environment=$rname=$rdefault"
	ADDED="$ADDED $rname"
done <<EOF
$SERVER_ENV_RECONCILE
EOF

# An old unit may predate the `EnvironmentFile=` line entirely — in which case the
# operator could drop a perfectly good /etc/maxsecu/dropbox.env in place and the
# server would never load it. `EnvironmentFile=` entries APPEND across drop-ins,
# and the leading `-` makes an absent file a no-op, so adding it is safe either way.
if [ "$UNIT_LOADS_DROPBOX_ENV" -ne 1 ]; then
	DROPIN_BODY="$DROPIN_BODY
EnvironmentFile=-$DROPBOX_ENV_PATH"
	ADDED="$ADDED EnvironmentFile=$DROPBOX_ENV_PATH"
fi

if [ -z "$DROPIN_BODY" ]; then
	# Nothing is missing anywhere else — so our drop-in has nothing left to supply.
	# It must be REMOVED, not merely left alone: a drop-in is applied AFTER the base
	# unit, so a stale one full of our defaults would OVERRIDE the values the unit
	# now carries (this is exactly what happens after `install-server.sh` re-writes
	# the unit with the full surface). Every OTHER drop-in — the capacity one, an
	# operator's own — is left strictly alone.
	if run_root "test -f '$ENV_DROPIN'"; then
		echo "    the unit now defines every variable itself — removing the stale $ENV_DROPIN"
		run_root "rm -f '$ENV_DROPIN'"
		run_root "systemctl daemon-reload"
	else
		echo "    the unit already defines every variable this build expects — nothing to do"
	fi
else
	# NB: no `trap ... EXIT` here. ENV_TMP is a global that the single on_exit trap
	# already cleans up; installing a second EXIT trap would REPLACE that one and
	# silently disarm the rollback for the rest of the run — with the service down.
	ENV_TMP="$(mktemp)"
	{
		echo "# GENERATED by scripts/upgrade-server.sh — DO NOT EDIT."
		echo "#"
		echo "# Variables this build expects that the unit did not define anywhere. Each"
		echo "# value is exactly the server's compiled-in default, i.e. what this server was"
		echo "# ALREADY running with when the variable was absent — so this file changes no"
		echo "# behaviour; it makes the configuration explicit. A variable already set in the"
		echo "# unit, in another drop-in, or in an EnvironmentFile is NEVER written here."
		echo "#"
		echo "# To override any of these, set them in the unit or in a drop-in whose filename"
		echo "# sorts AFTER this one — later assignments win. Edits to THIS file are"
		echo "# regenerated away on the next upgrade."
		echo "[Service]"
		printf '%s\n' "$DROPIN_BODY" | sed '/^$/d'
	} >"$ENV_TMP"

	if run_root "test -f '$ENV_DROPIN'" && run_root "cmp -s '$ENV_TMP' '$ENV_DROPIN'"; then
		echo "    already reconciled — no change"
		rm -f "$ENV_TMP"
		ENV_TMP=""
	else
		echo "    adding to $ENV_DROPIN:$ADDED"
		run_root "mkdir -p '$DROPIN_DIR'"
		run_root "install -o root -g root -m 0644 '$ENV_TMP' '$ENV_DROPIN'"
		rm -f "$ENV_TMP"
		ENV_TMP=""
		run_root "systemctl daemon-reload"
	fi
fi

# --------------------------------------------------------------------------- #
# 8. Start the service again (it has been down since step 6) and confirm it is
#    genuinely healthy.
#
#    The health check is `settle_check` (defined in step 6), which exists because
#    `systemctl is-active` ALONE IS A FALSE-GREEN: the unit is Type=simple with
#    Restart=always, so systemd reports it active the instant the fork/exec
#    succeeds — a binary that panics 200ms into startup still reads "active" while
#    it crash-loops, and this script would happily print UPGRADE COMPLETE over it.
#    The wait is ${SETTLE_SECONDS}s rather than a couple, because the slowest way
#    to die on startup is a Postgres connect, whose acquire timeout alone is 10s.
# --------------------------------------------------------------------------- #
echo "==> Starting maxsecu-server"
run_root "systemctl reset-failed maxsecu-server" </dev/null || true
run_root "systemctl start maxsecu-server" </dev/null || true

echo "    waiting ${SETTLE_SECONDS}s to confirm it stays up"
if settle_check; then
	echo "    service is active (running)"
	# Confirmed healthy — the EXIT trap stands down.
	SERVER_STOPPED=0
else
	if [ "$SETTLE_RESTARTS_BEFORE" != "$SETTLE_RESTARTS_AFTER" ]; then
		echo "error: maxsecu-server is CRASH-LOOPING (NRestarts $SETTLE_RESTARTS_BEFORE -> $SETTLE_RESTARTS_AFTER)." >&2
		echo "       systemd reports it 'active' because the unit is Type=simple, but the" >&2
		echo "       new binary is dying on startup." >&2
	else
		echo "error: maxsecu-server did NOT come back active. Recent logs:" >&2
	fi
	run_root "journalctl -u maxsecu-server -n 40 --no-pager" >&2 || true
	echo "       Your data is intact. Rolling back to the binary that was running" >&2
	echo "       before this upgrade so the server is serving again:" >&2
	restore_previous_binary
	echo "       Note: the schema HAS been migrated. Migrations only ADD, so the" >&2
	echo "       pre-upgrade binary runs fine against it. Investigate the logs above," >&2
	echo "       then re-run this script once the cause is fixed." >&2
	exit 1
fi

# Keep the pre-upgrade binary as a zero-cost manual rollback point.
echo "    (previous binary kept at $PREV_BIN)"

# The TLS cert was not touched, so the fingerprint clients pinned is unchanged.
#
# PRINT THE CERT-ONLY FINGERPRINT. This used to print `print-fingerprint`, which is
# pin_fingerprint(cert, directory_pub) -- a DIFFERENT value from the one in the
# connection code an installed client actually holds, which install-server.sh builds
# from `print-cert-fingerprint` = pin_fingerprint(cert, &[]). The two can never
# match, so the old line invited a non-technical operator to compare a value against
# their users' connection code, see a mismatch under a banner promising it was
# unchanged, and conclude the server identity had rotated -- the one conclusion that
# leads to re-pinning every client for no reason.
echo "==> Server-cert fingerprint (unchanged — clients do NOT need to re-pin):"
echo "    This is the value in your users' connection code, after the '#'."
run_as_user "MAXSECU_DATA_DIR='$DATA_DIR' '$SERVER_BIN' print-cert-fingerprint" || true
# The directory pin is a separate value and is NOT what clients compare on connect.
# Shown labelled, so the two can never be confused again.
echo "    (directory pin, a different value — not the connection code:)"
run_as_user "MAXSECU_DATA_DIR='$DATA_DIR' '$SERVER_BIN' print-fingerprint 2>/dev/null | sed 's/^/      /'" || true

echo ""
echo "================ UPGRADE COMPLETE ================"
echo "The new server binary is live, on an up-to-date schema. Accounts, keys,"
echo "uploads, TLS cert and client pins were all left in place. Watch it handle"
echo "real traffic with:"
echo "    journalctl -u maxsecu-server -f"
echo "================================================="
