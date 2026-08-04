#!/usr/bin/env bash
#
# restore-server.sh — roll back a failed upgrade, or rebuild a dead VPS, from a
# bundle sealed by backup-server.sh — WITHOUT ever costing an existing user their
# account, keys, or uploaded data.
# (design: docs/superpowers/specs/2026-07-16-server-backup-rollback-design.md)
#
# This is the root driver around the `restore` / `restore-db-merge` subcommands.
# The binary reads the opaque `pg_dump -Fc` archive; only `pg_restore` can put its
# rows back and cross-database `INSERT..SELECT` is impossible without an extension
# this repo will not add to the dead-box path — so the DB restore is a THREE-part
# flow with driver work in the middle:
#
#   1. binary  `restore --from <stamp>` : unseal the run-state into <staging>/state
#              and the dump into <staging>/db.dump; print the plan + the machine
#              lines (staging=, db_dump=, state_dir=, plan_json=). Does NOT stop the
#              server and does NOT touch the database — so a WRONG PASSPHRASE fails
#              HERE, with the server still up and nothing half-applied.
#   2. driver  systemctl stop; copy <staging>/state/* back to /etc + <data_dir>;
#              for a MERGE: createdb maxsecu_restore_<stamp> + pg_restore into it.
#   3. binary  `restore-db-merge --apply` (scratch URL on stdin) : the one cross-DB
#              step. The live pool is max_connections(1) and the merge refuses to
#              run while any OTHER connection to the live DB is open — which is why
#              the server MUST be stopped first (no isolation level makes the gate
#              safe against a concurrent delete). Then driver: dropdb + start.
#
#   `--db-mode replace` skips step 3: it is a wholesale `pg_restore --clean` into
#   live (or, on a dead box with no live DB, CREATE ROLE + CREATE DATABASE from the
#   restored unit's password, then pg_restore into the fresh DB). Over a LIVE DB it
#   is the 2a626d6 failure mode by construction, so it demands --force.
#
# FINDING THE BUNDLE ON A DEAD BOX (design's FATAL GAP #1). The cold-tier location
# reaches the binary through its LauncherConfig, which reads MAXSECU_COLD_FS_DIR
# from the unit and MAXSECU_COLD_TIER from /etc/maxsecu/dropbox.env — and a dead
# box has NEITHER (dropbox.env is itself INSIDE the bundle). So this driver:
#   * scrapes the cold-tier location out of the LIVE unit for a same-box rollback
#     (the default, common case), and
#   * REQUIRES --cold-tier-fs <dir> | --dropbox-env <path> when the unit is gone,
#     exporting the matching MAXSECU_COLD_TIER / MAXSECU_COLD_FS_DIR (or the Dropbox
#     creds) before exec'ing the binary, so LauncherConfig resolves the tier.
# Without it on a dead box, restore fails closed naming the flag.
#
# THE PASSPHRASE. It arrives on THIS script's stdin and must reach ONLY the binary
# (argv is world-readable through /proc). The single unseal (step 1) inherits our
# stdin; EVERY other sub-command — su - postgres, psql, pg_restore, createdb,
# dropdb, git, cargo, systemctl — is `</dev/null`-redirected so none can drink the
# passphrase line, and no secret is ever put on a command line (the DB password and
# any Dropbox token travel through a transient 0600 env file the binary sources).
#
# Usage:
#   printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest
#   printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest \
#       --cold-tier-fs /srv/maxsecu-cold          # dead-box rebuild
#   sudo bash scripts/restore-server.sh --list    # list bundles (no passphrase)
#
# Flags:
#   --from latest|<stamp>          Which bundle to restore (REQUIRED unless --list).
#   --only db,state,code,blobs     Restrict to these components (default: db,state,code).
#   --db-mode merge|replace        DB strategy (default: merge if a live DB exists,
#                                  else replace). merge never removes a live row.
#   --dry-run                      Unseal + verify + print the plan; change nothing,
#                                  never stop the server.
#   --force                        Authorize `--db-mode replace` over a LIVE DB.
#   --cold-tier-fs <dir>           Cold tier is the local filesystem at <dir>
#                                  (dead-box rebuild). Mutually exclusive with
#                                  --dropbox-env.
#   --dropbox-env <path>           Cold tier is Dropbox; load its creds from <path>
#                                  (dead-box rebuild). Mutually exclusive with
#                                  --cold-tier-fs.
#   --list                         List available bundles and exit.
#   -h,--help                      Show this help.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# 0. Resolve the repo root from this script's own location (scripts/ -> root).
# --------------------------------------------------------------------------- #
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: restore-server.sh --from latest|<stamp> [--only ...] [--db-mode merge|replace]
                         [--dry-run] [--force] [--cold-tier-fs <dir> | --dropbox-env <path>]
       restore-server.sh --list [--cold-tier-fs <dir> | --dropbox-env <path>]

Roll back a failed upgrade or rebuild a dead VPS from a bundle sealed by
backup-server.sh, without stranding any existing user. The bundle passphrase is
read from STDIN (not for --list):

    printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh --from latest

  --from latest|<stamp>       Which bundle to restore (required unless --list).
  --only db,state,code,blobs  Restrict to these components (default db,state,code).
  --db-mode merge|replace     DB strategy (default merge with a live DB, else replace).
  --dry-run                   Unseal, verify, print the plan; change nothing.
  --force                     Authorize replace over a LIVE database.
  --cold-tier-fs <dir>        Dead-box rebuild: cold tier is the filesystem at <dir>.
  --dropbox-env <path>        Dead-box rebuild: cold tier is Dropbox, creds at <path>.
  --list                      List available bundles and exit.
  -h,--help                   Show this help.
EOF
}

# --------------------------------------------------------------------------- #
# 1. Parse flags. Supports both `--flag value` and `--flag=value`.
# --------------------------------------------------------------------------- #
FROM=""
ONLY=""
DB_MODE=""
DRY_RUN=0
FORCE=0
COLD_TIER_FS=""
DROPBOX_ENV=""
LIST=0
while [ $# -gt 0 ]; do
	case "$1" in
	--from=*)
		FROM="${1#*=}"
		shift
		;;
	--from)
		[ $# -ge 2 ] || { echo "error: --from needs a value" >&2; exit 2; }
		FROM="$2"
		shift 2
		;;
	--only=*)
		ONLY="${1#*=}"
		shift
		;;
	--only)
		[ $# -ge 2 ] || { echo "error: --only needs a value" >&2; exit 2; }
		ONLY="$2"
		shift 2
		;;
	--db-mode=*)
		DB_MODE="${1#*=}"
		shift
		;;
	--db-mode)
		[ $# -ge 2 ] || { echo "error: --db-mode needs a value" >&2; exit 2; }
		DB_MODE="$2"
		shift 2
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	--force)
		FORCE=1
		shift
		;;
	--cold-tier-fs=*)
		COLD_TIER_FS="${1#*=}"
		shift
		;;
	--cold-tier-fs)
		[ $# -ge 2 ] || { echo "error: --cold-tier-fs needs a directory" >&2; exit 2; }
		COLD_TIER_FS="$2"
		shift 2
		;;
	--dropbox-env=*)
		DROPBOX_ENV="${1#*=}"
		shift
		;;
	--dropbox-env)
		[ $# -ge 2 ] || { echo "error: --dropbox-env needs a path" >&2; exit 2; }
		DROPBOX_ENV="$2"
		shift 2
		;;
	--list)
		LIST=1
		shift
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

# The two cold-tier locators are mutually exclusive — a box has ONE cold tier, and
# a stale Dropbox creds file next to an fs directory would be ambiguous.
if [ -n "$COLD_TIER_FS" ] && [ -n "$DROPBOX_ENV" ]; then
	echo "error: --cold-tier-fs and --dropbox-env are mutually exclusive." >&2
	exit 2
fi
if [ -n "$DB_MODE" ] && [ "$DB_MODE" != "merge" ] && [ "$DB_MODE" != "replace" ]; then
	echo "error: --db-mode must be 'merge' or 'replace' (got '$DB_MODE')." >&2
	exit 2
fi
if [ "$LIST" -eq 0 ] && [ -z "$FROM" ]; then
	echo "error: --from is required (or pass --list to list bundles)." >&2
	usage >&2
	exit 2
fi
# --from and --only are the operator inputs that flow into a shell command string
# (and into a blob_ref, inside the binary). Validate them to the SAME shapes the
# binary accepts — a stamp is [0-9A-Za-z-], --only is a comma list of the four
# component names — so a typo fails cleanly rather than mangling the invocation.
if [ -n "$FROM" ] && [ "$FROM" != "latest" ]; then
	case "$FROM" in
	*[!0-9A-Za-z-]*)
		echo "error: --from must be 'latest' or a bundle stamp ([0-9A-Za-z-])." >&2
		exit 2
		;;
	esac
fi
if [ -n "$ONLY" ]; then
	case "$ONLY" in
	*[!a-z,]*)
		echo "error: --only must be a comma list of db,state,code,blobs." >&2
		exit 2
		;;
	esac
fi

# --------------------------------------------------------------------------- #
# 2. Privilege + identity helpers (same model as install-/upgrade-server.sh).
#    Root is needed for systemd, /etc writes and the postgres superuser; the
#    unsealed staging, the data dir and the build tree belong to the invoking
#    (non-root) user — the identity the server itself runs as.
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
DROPBOX_ENV_PATH="/etc/maxsecu/dropbox.env"
SERVER_BIN="$ROOT/target/release/maxsecu-portable-server"

# Fail EARLY and by name when the binary is not there. backup-server.sh has always
# checked this; restore did not, so a dead box that had not built the binary yet got
# `run_bin` exiting 127 — which the unseal step reports as "wrong passphrase, missing
# bundle, or a git-sha disagreement". That is the worst possible message to hand an
# operator mid-rebuild: it sends them hunting for a lost passphrase when the actual
# fix is `cargo build`.
if [ ! -x "$SERVER_BIN" ]; then
	echo "error: $SERVER_BIN is missing/not executable — build it first with" >&2
	echo "       'cargo build --release -p maxsecu-portable-server', or run" >&2
	echo "       scripts/install-server.sh (a dead-box rebuild needs the box" >&2
	echo "       bootstrapped with Postgres + Rust + this binary before a restore)." >&2
	echo "" >&2
	echo "       install-server.sh is safe HERE and only here: on a genuinely dead box" >&2
	echo "       — no systemd unit, no <data_dir>/tls/cert.der, no rows in the maxsecu" >&2
	echo "       database — it sees a fresh install and proceeds. If ANY of those three" >&2
	echo "       survived, it refuses by design (it would rewrite the unit from this" >&2
	echo "       run's flags); in that case just build the binary and come back here," >&2
	echo "       because this restore is what puts the surviving box back together." >&2
	exit 1
fi

# Run a command string as root (directly if already root, else via sudo).
run_root() {
	if [ "$IS_ROOT" -eq 1 ]; then
		bash -c "$1"
	else
		sudo bash -c "$1"
	fi
}

# Run a command string as the invoking (non-root) user — the identity the server
# runs as, so files it creates (staging, the restored data dir on a dead box) are
# owned correctly and git/cargo do not trip git's dubious-ownership guard.
run_as_user() {
	if [ "$IS_ROOT" -eq 1 ]; then
		su - "$RUN_USER" -c "$1"
	else
		bash -c "$1"
	fi
}

# Feed SQL on stdin to psql as the postgres superuser (keeps secrets off argv).
psql_super_stdin() {
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "psql -v ON_ERROR_STOP=1"
	else
		sudo -u postgres psql -v ON_ERROR_STOP=1
	fi
}

# Run a scalar psql query as the postgres superuser and print the result.
psql_super_query() {
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "psql -tAc \"$1\""
	else
		sudo -u postgres psql -tAc "$1"
	fi
}

# createdb / dropdb as the postgres superuser (db names are not secrets).
create_scratch_db() { # $1 = db name, $2 = owner role
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "createdb -O '$2' '$1'" </dev/null
	else
		sudo -u postgres createdb -O "$2" "$1" </dev/null
	fi
}
drop_db_if_exists() { # $1 = db name
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "dropdb --if-exists '$1'" </dev/null 2>/dev/null || true
	else
		sudo -u postgres dropdb --if-exists "$1" </dev/null 2>/dev/null || true
	fi
}

# Parse postgres://USER:PASS@HOST[:PORT]/DB[?params] into DB_USER/PASS/HOST/PORT/NAME.
# install-server.sh writes exactly this shape; the password is `openssl rand -hex 24`,
# so it is never URL-encoded (upgrade-server.sh:418-435).
parse_database_url() { # $1 = url
	local rest creds hostpath hostport
	rest="${1#*://}"
	creds="${rest%%@*}"
	hostpath="${rest#*@}"
	DB_USER="${creds%%:*}"
	DB_PASS=""
	if [ "$creds" != "$DB_USER" ]; then
		DB_PASS="${creds#*:}"
	fi
	hostport="${hostpath%%/*}"
	DB_NAME="${hostpath#*/}"
	DB_NAME="${DB_NAME%%\?*}"
	DB_HOST="${hostport%%:*}"
	DB_PORT="${hostport#*:}"
	if [ "$DB_PORT" = "$hostport" ]; then
		DB_PORT=5432
	fi
}

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
# backup, and a failed backup aborts the upgrade that depends on it. THIS script is
# the worst place of all to be strict: it reads DATABASE_URL on the DEAD-BOX REBUILD
# path, where a false "unset" strands the recovery itself.
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

# THE SAME parser, aimed at a unit FILE on disk instead of the live unit — used for
# the RESTORED unit sitting in staging, whose path differs from the live one. It
# re-points UNIT_PATH/DROPIN_DIR for the duration of the call rather than carrying a
# SECOND, weaker regex: this script used to hold the strictest copy in the repo
# (no indent tolerance, no single quotes, no EnvironmentFile fallback) and it read
# DATABASE_URL through it on the dead-box path. `$STATE_DIR/unit/drop-ins` is where
# collect_state_files seals the drop-ins, so systemd's last-wins merge is honoured
# for the staged unit too. Every call site is a `$( )` substitution (a subshell), so
# the re-point cannot leak; the explicit restore is belt-and-braces.
resolve_file_env() { # $1 = unit file path, $2 = variable name
	_saved_unit_path="$UNIT_PATH"
	_saved_dropin_dir="$DROPIN_DIR"
	UNIT_PATH="$1"
	DROPIN_DIR="$(dirname "$1")/drop-ins"
	_file_val="$(resolve_unit_env "$2")"
	UNIT_PATH="$_saved_unit_path"
	DROPIN_DIR="$_saved_dropin_dir"
	printf '%s' "$_file_val"
}

# --------------------------------------------------------------------------- #
# 3. Is there a live install (same-box rollback), or is this a dead box?
# --------------------------------------------------------------------------- #
LIVE_UNIT=0
if run_root "test -f '$UNIT_PATH'" </dev/null; then
	LIVE_UNIT=1
fi

# "A live DB is present" ~= "the live unit carries a DATABASE_URL". This drives the
# binary's default db-mode (merge vs replace) and the replace-over-live-DB guard.
LIVE_DB_URL=""
if [ "$LIVE_UNIT" -eq 1 ]; then
	LIVE_DB_URL="$(resolve_unit_env DATABASE_URL)"
fi
LIVE_DB_PRESENT=0
if [ -n "$LIVE_DB_URL" ]; then
	LIVE_DB_PRESENT=1
fi

# The data dir the binary should use: the live unit's on a same-box rollback, else
# the install default. On a dead box the restored unit's MAXSECU_DATA_DIR (read from
# staging after step 1) governs where tls/ + config/ actually land.
BIN_DATA_DIR="$DATA_DIR"
if [ "$LIVE_UNIT" -eq 1 ]; then
	scraped_dd="$(resolve_unit_env MAXSECU_DATA_DIR)"
	if [ -n "$scraped_dd" ]; then
		BIN_DATA_DIR="$scraped_dd"
	fi
fi

# --------------------------------------------------------------------------- #
# 3a. Resolve the COLD-TIER LOCATION (design FATAL GAP #1). Precedence: an explicit
#     flag wins (it is how a dead box is told where the bundle lives); otherwise
#     scrape the live unit; otherwise fail closed naming the flag.
# --------------------------------------------------------------------------- #
COLD_KIND="" # fs | dropbox
COLD_FS_DIR=""
COLD_DROPBOX_SRC="" # a creds FILE to fold into the binary env

if [ -n "$COLD_TIER_FS" ]; then
	case "$COLD_TIER_FS" in
	/*) : ;;
	*)
		echo "error: --cold-tier-fs must be an ABSOLUTE path (got '$COLD_TIER_FS')." >&2
		exit 2
		;;
	esac
	COLD_KIND="fs"
	COLD_FS_DIR="$COLD_TIER_FS"
elif [ -n "$DROPBOX_ENV" ]; then
	if ! run_root "test -f '$DROPBOX_ENV'" </dev/null; then
		echo "error: --dropbox-env path not found: $DROPBOX_ENV" >&2
		exit 2
	fi
	COLD_KIND="dropbox"
	COLD_DROPBOX_SRC="$DROPBOX_ENV"
elif [ "$LIVE_UNIT" -eq 1 ]; then
	# Same-box rollback: use whatever cold tier the running server uses.
	unit_cold="$(resolve_unit_env MAXSECU_COLD_TIER)"
	if [ "$unit_cold" = "fs" ]; then
		COLD_KIND="fs"
		COLD_FS_DIR="$(resolve_unit_env MAXSECU_COLD_FS_DIR)"
	elif run_root "test -f '$DROPBOX_ENV_PATH'" </dev/null; then
		COLD_KIND="dropbox"
		COLD_DROPBOX_SRC="$DROPBOX_ENV_PATH"
	fi
fi

if [ -z "$COLD_KIND" ]; then
	if [ "$LIVE_UNIT" -eq 1 ]; then
		echo "error: the live server has no cold tier configured (MAXSECU_COLD_TIER is off" >&2
		echo "       and there is no $DROPBOX_ENV_PATH) — there is no backup destination to" >&2
		echo "       restore FROM. If you know where the bundle lives, pass --cold-tier-fs" >&2
		echo "       <dir> or --dropbox-env <path>." >&2
	else
		echo "error: no live server unit found (dead-box rebuild), so the bundle location" >&2
		echo "       cannot be discovered. Pass --cold-tier-fs <dir> (the filesystem cold" >&2
		echo "       tier's directory) or --dropbox-env <path> (a Dropbox creds file) so the" >&2
		echo "       binary can find and unseal the bundle." >&2
	fi
	exit 1
fi

# --------------------------------------------------------------------------- #
# 3b. Assemble the binary's environment in a transient 0600 file the invocation
#     SOURCES (`set -a` around the source exports every KEY=value). Secrets — the
#     DB password inside DATABASE_URL, any Dropbox refresh token, PGPASSWORD later —
#     travel this way rather than on a command line where /proc would expose them.
# --------------------------------------------------------------------------- #
BIN_ENV="$(mktemp)"
OUT="$(mktemp)"
chmod 0600 "$BIN_ENV" "$OUT"

# Append one `KEY='value'` assignment. This file is SOURCED by a shell, not read
# by systemd's EnvironmentFile parser, and the two disagree about an unquoted
# value that contains a space: systemd takes the whole rest of the line, while
# `.` sees an assignment PREFIX followed by a command and leaves the variable
# UNSET in the sourcing shell. A Dropbox root of `/My backups` (the installer
# takes that folder name from a free-text prompt) would therefore reach the
# binary as nothing at all, and the restore would hunt for the bundle — and for
# the blob copies a dead-box rebuild depends on — under the default `/maxsecu`
# instead of where backup-server.sh, which quotes the same way, put them. Single
# quotes make the value literal; an embedded quote is closed, escaped and
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

# Cleanup on ANY exit: drop the scratch DB if we created one (never leave it
# behind), bring the server back if WE stopped it (a mid-restore failure must never
# leave the box down), and remove the transient files + staging.
SCRATCH_DB=""
SERVER_STOPPED=0
STAGING=""
cleanup() {
	if [ -n "$SCRATCH_DB" ]; then
		drop_db_if_exists "$SCRATCH_DB"
		# drop_db_if_exists forces its own status to 0 (a dropdb failure must not
		# abort the rest of the cleanup), so nothing else in this script can tell
		# whether the copy actually went away. Ask postgres directly: a survivor is a
		# second, unwatched copy of every keyblob and DEK wrap sitting on the box,
		# and the operator is the only one who can remove it. An unreachable postgres
		# answers nothing, which is not a survivor — stay quiet then.
		if [ "$(psql_super_query "SELECT 1 FROM pg_database WHERE datname='$SCRATCH_DB'" </dev/null 2>/dev/null | tr -d '\r' || true)" = "1" ]; then
			echo "warning: the scratch database $SCRATCH_DB could NOT be dropped. It holds a" >&2
			echo "         full copy of the metadata database (every keyblob and DEK wrap)." >&2
			echo "         Remove it by hand:  sudo -u postgres dropdb $SCRATCH_DB" >&2
		fi
	fi
	if [ "$SERVER_STOPPED" -eq 1 ]; then
		run_root "systemctl start maxsecu-server 2>/dev/null || true" </dev/null || true
	fi
	if [ -n "$STAGING" ]; then
		run_root "rm -rf '$STAGING'" </dev/null 2>/dev/null || true
	fi
	rm -f "$BIN_ENV" "$OUT" 2>/dev/null || true
}
trap cleanup EXIT

{
	emit_env MAXSECU_DATA_DIR "$BIN_DATA_DIR"
	# DATABASE_URL is present iff a live DB exists — the binary reads only its
	# PRESENCE for step 1 (to default merge vs replace) and its VALUE for the merge
	# (step 3) live pool. Absent => the binary sees a dead box and defaults replace.
	if [ "$LIVE_DB_PRESENT" -eq 1 ]; then
		emit_env DATABASE_URL "$LIVE_DB_URL"
	fi
} >>"$BIN_ENV"

if [ "$COLD_KIND" = "fs" ]; then
	if [ -z "$COLD_FS_DIR" ]; then
		echo "error: the fs cold tier has no directory (MAXSECU_COLD_FS_DIR is unset in the" >&2
		echo "       unit); pass --cold-tier-fs <dir> explicitly." >&2
		exit 1
	fi
	{
		printf 'MAXSECU_COLD_TIER=fs\n'
		emit_env MAXSECU_COLD_FS_DIR "$COLD_FS_DIR"
	} >>"$BIN_ENV"
else
	# Dropbox: fold the whole creds file in (MAXSECU_COLD_TIER=dropbox +
	# MAXSECU_DROPBOX_*), re-quoted assignment by assignment so the binary resolves
	# the SAME root backup-server.sh sealed into. Read as root; the 0600 BIN_ENV
	# protects it.
	fold_creds_env "$COLD_DROPBOX_SRC" >>"$BIN_ENV"
fi

# The binary runs as the RUN_USER (its own identity), so it must be able to read
# BIN_ENV. When we are root, mktemp made it root-owned — hand it to the run user.
if [ "$IS_ROOT" -eq 1 ]; then
	chown "$RUN_USER" "$BIN_ENV" "$OUT"
fi

# Run the backup binary as the RUN_USER with BIN_ENV sourced (exported). stdin and
# stdout are the CALLER's unless redirected — the single unseal must inherit our
# stdin for the passphrase; everything else is `</dev/null`.
run_bin() { # $1 = command line
	run_as_user "set -a; . '$BIN_ENV'; set +a; $1"
}

echo "    cold tier : $COLD_KIND"
if [ "$LIVE_UNIT" -eq 1 ]; then
	echo "    box       : same-box rollback (live unit present)"
else
	echo "    box       : dead-box rebuild (no live unit)"
fi

# --------------------------------------------------------------------------- #
# 4. --list convenience (no passphrase — reads only the plaintext manifests).
# --------------------------------------------------------------------------- #
if [ "$LIST" -eq 1 ]; then
	echo "==> Listing backup bundles"
	run_bin "'$SERVER_BIN' list-backups" </dev/null
	exit 0
fi

# --------------------------------------------------------------------------- #
# 5. STEP 1 — unseal the bundle into staging + print the plan. Run FIRST, BEFORE
#    the server is ever stopped: a wrong passphrase or a missing bundle fails here
#    with the box still up and nothing half-applied (the failure mode the E2E's
#    wrong-passphrase case guards). For a dry run on a RUNNING server we pass the
#    binary's own --dry-run (plan-only, no download, no staging); otherwise we
#    materialize the dump + state so the driver can act on them.
# --------------------------------------------------------------------------- #
INV1_ARGS="--from '$FROM'"
[ -n "$ONLY" ] && INV1_ARGS="$INV1_ARGS --only '$ONLY'"
[ -n "$DB_MODE" ] && INV1_ARGS="$INV1_ARGS --db-mode '$DB_MODE'"
[ "$FORCE" -eq 1 ] && INV1_ARGS="$INV1_ARGS --force"

# Is the server currently running? (false / non-zero on a dead box with no unit.)
SERVER_RUNNING=0
if run_root "systemctl is-active --quiet maxsecu-server" </dev/null 2>/dev/null; then
	SERVER_RUNNING=1
fi

# A dry run against a RUNNING server stays plan-only (row-level counts need a
# quiescent DB — the merge gate refuses to run while the server is connected, and
# we must NOT stop the server for a dry run). A dry run against an already-stopped
# server, and every real apply, materializes the bundle so the driver can proceed.
MATERIALIZE=1
if [ "$DRY_RUN" -eq 1 ] && [ "$SERVER_RUNNING" -eq 1 ]; then
	MATERIALIZE=0
	INV1_ARGS="$INV1_ARGS --dry-run"
fi

echo "==> Unsealing the bundle (this reads your passphrase from stdin)"
# NB: no `</dev/null` — the ONE command that must inherit the operator's stdin.
if ! run_bin "cd '$ROOT' && exec '$SERVER_BIN' restore $INV1_ARGS" >"$OUT"; then
	echo "" >&2
	echo "error: could not unseal the bundle (wrong passphrase, missing bundle, or a" >&2
	echo "       git-sha disagreement). The server was NOT stopped and the database was" >&2
	echo "       NOT touched — nothing was half-applied." >&2
	exit 1
fi

# Show the human plan (everything but the machine key=value lines).
grep -vE '^(staging|db_dump|state_dir|plan_json)=' "$OUT" || true

# Component scope + db strategy come from the binary's own resolved plan — the
# single source of truth (works for both the dry-run and apply outputs).
HAS_DB=0
PLAN_DB_MODE=""
if grep -qE '^  db: +merge' "$OUT"; then
	HAS_DB=1
	PLAN_DB_MODE="merge"
elif grep -qE '^  db: +replace' "$OUT"; then
	HAS_DB=1
	PLAN_DB_MODE="replace"
fi
HAS_STATE=0
grep -qE '^  state: +[0-9]' "$OUT" && HAS_STATE=1
HAS_CODE=0
CODE_SHA=""
if grep -qE '^  code: +checkout ' "$OUT"; then
	HAS_CODE=1
	CODE_SHA="$(sed -n 's/^  code: *checkout //p' "$OUT" | head -n1 | tr -d '\r')"
	[ "$CODE_SHA" = "<none>" ] && CODE_SHA=""
fi

# Machine lines (present only when the bundle was materialized, i.e. not the
# plan-only running-server dry run).
STAGING="$(sed -n 's/^staging=//p' "$OUT" | head -n1 | tr -d '\r')"
DB_DUMP="$(sed -n 's/^db_dump=//p' "$OUT" | head -n1 | tr -d '\r')"
STATE_DIR="$(sed -n 's/^state_dir=//p' "$OUT" | head -n1 | tr -d '\r')"
STAMP=""
[ -n "$STAGING" ] && STAMP="$(basename "$STAGING")"

# --------------------------------------------------------------------------- #
# 5a. DRY RUN — change nothing, never stop the server. If a merge is in scope AND
#     the operator has ALREADY stopped the server, we can safely produce the real
#     per-table numbers via a throwaway scratch DB (createdb + pg_restore +
#     restore-db-merge WITHOUT --apply, which runs the identical insert pass inside
#     a SERIALIZABLE txn and rolls it back). Otherwise the component plan above is
#     the preview and we say why the row-level counts are withheld.
# --------------------------------------------------------------------------- #
if [ "$DRY_RUN" -eq 1 ]; then
	if [ "$MATERIALIZE" -eq 1 ] && [ "$HAS_DB" -eq 1 ] && [ "$PLAN_DB_MODE" = "merge" ] && [ "$LIVE_DB_PRESENT" -eq 1 ]; then
		echo "==> Dry-run merge preview (server is stopped — computing exact per-table counts)"
		parse_database_url "$LIVE_DB_URL"
		emit_env PGPASSWORD "$DB_PASS" >>"$BIN_ENV"
		SCRATCH_DB="maxsecu_restore_$(printf '%s' "$STAMP" | tr 'A-Z' 'a-z')"
		drop_db_if_exists "$SCRATCH_DB"
		create_scratch_db "$SCRATCH_DB" "$DB_USER"
		run_bin "pg_restore --no-owner --exit-on-error -h '$DB_HOST' -p '$DB_PORT' -U '$DB_USER' -d '$SCRATCH_DB' '$DB_DUMP'" </dev/null
		# The scratch URL carries the DB password, so it goes to the binary on
		# stdin, never argv (which /proc exposes) — the same rule as the passphrase.
		STAGED_URL="postgres://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$SCRATCH_DB"
		printf '%s\n' "$STAGED_URL" | run_bin "'$SERVER_BIN' restore-db-merge"
		# The scratch DB is a pg_restore of the WHOLE metadata dump — every keyblob
		# and every DEK wrap — so it must never outlive this run. Leave SCRATCH_DB
		# set: drop_db_if_exists swallows its own failure, and the EXIT trap is the
		# only thing that would notice and say so.
		drop_db_if_exists "$SCRATCH_DB"
	elif [ "$HAS_DB" -eq 1 ] && [ "$PLAN_DB_MODE" = "merge" ] && [ "$LIVE_DB_PRESENT" -eq 1 ]; then
		echo "==> Dry run: the plan above is the component-level preview."
		echo "    Exact per-table merge counts need a quiescent database (the merge refuses"
		echo "    to run while the server is connected). To see them WITHOUT applying, stop"
		echo "    the server (systemctl stop maxsecu-server) and re-run this same --dry-run;"
		echo "    or run without --dry-run to apply (the counts print as it commits)."
	fi
	echo ""
	# "the server was not stopped" is true of THIS run either way, but printing it
	# unconditionally is misleading in the exact sequence the runbook prescribes: to
	# see real per-table counts the operator stops the unit first and re-runs the same
	# --dry-run. They would then read "the server was not stopped" as "the service is
	# up", walk away, and leave the box down — a silent outage caused by following the
	# documentation. Say what is actually true of the service right now.
	if [ "$LIVE_UNIT" -eq 1 ] && [ "$SERVER_RUNNING" -eq 0 ]; then
		echo "==> Dry run complete — nothing was changed."
		echo "    NOTE: maxsecu-server is currently STOPPED (it already was before this run;"
		echo "          this dry run neither stopped nor started it). Start it again with:"
		echo "              systemctl start maxsecu-server"
	else
		echo "==> Dry run complete — nothing was changed and the server was not stopped."
	fi
	exit 0
fi

# --------------------------------------------------------------------------- #
# 6. APPLY. Stop the server BEFORE any state/DB mutation (only when the DB or the
#    run-state is in scope — a code-only rollback builds while the old server keeps
#    serving, exactly like upgrade-server.sh, and only restarts at the end). On a
#    dead box there is nothing to stop yet.
# --------------------------------------------------------------------------- #
if [ "$LIVE_UNIT" -eq 1 ] && { [ "$HAS_DB" -eq 1 ] || [ "$HAS_STATE" -eq 1 ]; }; then
	echo "==> Stopping maxsecu-server for the restore (brief downtime)"
	run_root "systemctl stop maxsecu-server" </dev/null
	SERVER_STOPPED=1
fi

# --------------------------------------------------------------------------- #
# 6a. RUN-STATE: copy <staging>/state/* back to the system paths the binary sealed
#     them from (reverse of collect_state_files). Root-only creds get root:root
#     modes; the data-dir material is chowned to the identity systemd will actually
#     run the restored unit as. This is what re-materializes the unit, the Dropbox
#     creds, the TLS cert/key (so no pinned client is locked out) and the
#     delegation triple.
# --------------------------------------------------------------------------- #
RESTORE_DATA_DIR="$BIN_DATA_DIR"
DATA_OWNER="$RUN_USER"
DATA_GROUP="$RUN_USER"
if [ "$HAS_STATE" -eq 1 ] && [ -n "$STATE_DIR" ]; then
	echo "==> Restoring run-state (unit, creds, TLS cert/key, delegation)"

	if [ -f "$STATE_DIR/unit/maxsecu-server.service" ]; then
		# The identity that has to be able to READ the TLS key and the delegation
		# triple is the restored unit's own User= (install-server.sh writes it), which
		# is not necessarily whoever is invoking this script: a rollback run straight
		# from a root shell has no SUDO_USER, so RUN_USER is `root` and the 0600/0700
		# installs below would take the key away from the service — it would come back
		# up unable to read its own TLS key and the run would end at "did NOT come back
		# active" with the box down. Resolve the owner from the unit BEFORE anything is
		# written, and take the primary group from passwd rather than assuming a
		# user-private group of the same name (falling back to that name only when
		# passwd has no gid to give — `install -g ''` would abort the restore here,
		# with the unit already replaced).
		svc_user="$(sed -n 's/^User=//p' "$STATE_DIR/unit/maxsecu-server.service" | tail -n1 | tr -d '\r')"
		if [ -n "$svc_user" ]; then
			if ! getent passwd "$svc_user" >/dev/null </dev/null; then
				echo "error: the restored unit runs as user '$svc_user', which does not exist on" >&2
				echo "       this box — systemd could not start the service as that identity, and" >&2
				echo "       handing its TLS key to anyone else would lock the service out of it." >&2
				echo "       Create the account and re-run — nothing has been restored yet." >&2
				exit 1
			fi
			DATA_OWNER="$svc_user"
			DATA_GROUP="$(getent passwd "$svc_user" </dev/null | cut -d: -f4)"
			[ -n "$DATA_GROUP" ] || DATA_GROUP="$svc_user"
		fi

		run_root "install -o root -g root -m 0600 '$STATE_DIR/unit/maxsecu-server.service' '$UNIT_PATH'" </dev/null
		# The restored unit is the source of truth for where the data dir lives.
		dd_from_unit="$(resolve_file_env "$STATE_DIR/unit/maxsecu-server.service" MAXSECU_DATA_DIR)"
		[ -n "$dd_from_unit" ] && RESTORE_DATA_DIR="$dd_from_unit"
		# The binary's env still names the data dir we resolved BEFORE the restore (the
		# live unit's, or the install default). Everything below writes tls/ and
		# config/ under the RESTORED unit's dir instead, and the closing
		# print-fingerprint reads its client-pins/ — which are regenerated from exactly
		# that material when the service starts. Re-emitting the variable makes the
		# `set -a; . BIN_ENV` in run_bin last-wins on the dir the server will really
		# use, so the "no client needs to re-pin" line cannot come from a stale pin
		# directory belonging to some earlier install.
		emit_env MAXSECU_DATA_DIR "$RESTORE_DATA_DIR" >>"$BIN_ENV"
	fi

	if [ -d "$STATE_DIR/unit/drop-ins" ]; then
		run_root "mkdir -p '$DROPIN_DIR'" </dev/null
		for f in "$STATE_DIR"/unit/drop-ins/*; do
			[ -f "$f" ] || continue
			run_root "install -o root -g root -m 0644 '$f' '$DROPIN_DIR/$(basename "$f")'" </dev/null
		done
	fi

	if [ -f "$STATE_DIR/dropbox.env" ]; then
		run_root "install -d -o root -g root -m 0700 /etc/maxsecu" </dev/null
		run_root "install -o root -g root -m 0600 '$STATE_DIR/dropbox.env' '$DROPBOX_ENV_PATH'" </dev/null
	fi

	if [ -d "$STATE_DIR/tls" ]; then
		run_root "install -d -o '$DATA_OWNER' -g '$DATA_GROUP' -m 0700 '$RESTORE_DATA_DIR/tls'" </dev/null
		[ -f "$STATE_DIR/tls/cert.der" ] &&
			run_root "install -o '$DATA_OWNER' -g '$DATA_GROUP' -m 0644 '$STATE_DIR/tls/cert.der' '$RESTORE_DATA_DIR/tls/cert.der'" </dev/null
		[ -f "$STATE_DIR/tls/key.der" ] &&
			run_root "install -o '$DATA_OWNER' -g '$DATA_GROUP' -m 0600 '$STATE_DIR/tls/key.der' '$RESTORE_DATA_DIR/tls/key.der'" </dev/null
	fi

	if [ -d "$STATE_DIR/config" ]; then
		run_root "install -d -o '$DATA_OWNER' -g '$DATA_GROUP' -m 0700 '$RESTORE_DATA_DIR/config'" </dev/null
		for f in "$STATE_DIR"/config/*; do
			[ -f "$f" ] || continue
			run_root "install -o '$DATA_OWNER' -g '$DATA_GROUP' -m 0600 '$f' '$RESTORE_DATA_DIR/config/$(basename "$f")'" </dev/null
		done
	fi

	run_root "systemctl daemon-reload" </dev/null
fi

# --------------------------------------------------------------------------- #
# 6b. DATABASE. Resolve the DATABASE_URL to operate against: the in-place unit
#     (same-box, or dead-box AFTER the unit was just restored above). It carries
#     the per-install random password — the ONLY copy — which the dead-box path
#     needs to re-create the role.
# --------------------------------------------------------------------------- #
if [ "$HAS_DB" -eq 1 ]; then
	RESTORE_DB_URL=""
	if run_root "test -f '$UNIT_PATH'" </dev/null; then
		RESTORE_DB_URL="$(resolve_unit_env DATABASE_URL)"
	elif [ -n "$STATE_DIR" ] && [ -f "$STATE_DIR/unit/maxsecu-server.service" ]; then
		RESTORE_DB_URL="$(resolve_file_env "$STATE_DIR/unit/maxsecu-server.service" DATABASE_URL)"
	fi
	if [ -z "$RESTORE_DB_URL" ]; then
		echo "error: could not determine the DATABASE_URL to restore into. On a dead box" >&2
		echo "       the DB password lives ONLY in the sealed unit, so the state component" >&2
		echo "       must be restored too — re-run without '--only db' (use the default, or" >&2
		echo "       include 'state')." >&2
		exit 1
	fi
	parse_database_url "$RESTORE_DB_URL"
	emit_env PGPASSWORD "$DB_PASS" >>"$BIN_ENV"

	# RECONCILE THE ROLE WITH THE UNIT WE JUST INSTALLED. This must happen on EVERY
	# path, not only the dead-box one.
	#
	# The unit file is the ONLY place the `maxsecu` role's password is ever written,
	# and step 6a above overwrites the live unit with the BUNDLE's copy. So whenever
	# ANYTHING has re-set that password since the backup, the box now has role
	# password P_new while the unit (and the `$RESTORE_DB_URL` we just scraped out of
	# it) says P_old.
	#
	# RE-CHECKED against install-server.sh's now-CONDITIONAL rotation (F1): that
	# script no longer mints a fresh password on every run — when the `maxsecu` role
	# already exists AND a working DATABASE_URL can be recovered from the installed
	# unit, it REUSES that password and issues no ALTER ROLE at all. The reconcile
	# below is still required, because three live paths still produce P_new ≠ P_old:
	#   * install-server.sh --force-overwrite-existing-install on a box whose unit
	#     carried no working DATABASE_URL — it mints and ALTER ROLEs, by design;
	#   * a genuine fresh install (CREATE ROLE) done after the bundle was sealed;
	#   * an operator repairing a lost password by hand (`ALTER ROLE … PASSWORD` plus
	#     a drop-in), which is the recipe upgrade-/backup-server.sh now print.
	# On the common path — nothing rotated since the backup — the statement below
	# sets the role to the password it already has, i.e. a no-op.
	#
	# Previously only the dead-box branch re-synced the role, so the merge and
	# replace-over-live branches went straight to `pg_restore` with P_old and died on
	# `FATAL: password authentication failed` — with the server already stopped and the
	# P_old unit already installed. The EXIT trap then restarted a server that could no
	# longer authenticate either, and a retry re-scraped P_old from the restored unit
	# and failed identically: an outage with the working password gone from the only
	# place it lived, on a box whose operator has no escape hatch.
	#
	# The superuser can always set it, and the unit we just installed is by definition
	# the password the restored server will use, so make the role agree with it. On the
	# paths where no unit was restored this scrapes the LIVE unit and the statement is a
	# no-op. Single quotes in the literal are doubled (SQL escaping) so a password
	# containing one cannot break — or inject into — the statement.
	DB_PASS_SQL="${DB_PASS//\'/\'\'}"
	role_exists="$(psql_super_query "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" </dev/null | tr -d '\r' || true)"
	if [ "$role_exists" = "1" ]; then
		printf "ALTER ROLE %s WITH LOGIN PASSWORD '%s';\n" "$DB_USER" "$DB_PASS_SQL" | psql_super_stdin >/dev/null
	else
		printf "CREATE ROLE %s WITH LOGIN PASSWORD '%s';\n" "$DB_USER" "$DB_PASS_SQL" | psql_super_stdin >/dev/null
	fi

	if [ "$PLAN_DB_MODE" = "merge" ]; then
		# MERGE — dump -> scratch DB -> the one cross-DB gated insert pass -> drop.
		echo "==> Merging the backup into the live database (adds back what is missing,"
		echo "    never removes a live row)"
		SCRATCH_DB="maxsecu_restore_$(printf '%s' "$STAMP" | tr 'A-Z' 'a-z')"
		drop_db_if_exists "$SCRATCH_DB"
		create_scratch_db "$SCRATCH_DB" "$DB_USER"
		run_bin "pg_restore --no-owner --exit-on-error -h '$DB_HOST' -p '$DB_PORT' -U '$DB_USER' -d '$SCRATCH_DB' '$DB_DUMP'" </dev/null
		STAGED_URL="postgres://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$SCRATCH_DB"
		# The live pool is DATABASE_URL (in BIN_ENV) at max_connections(1); the merge
		# refuses to run if any OTHER connection to the live DB is open, which is why
		# the server was stopped above. The scratch URL carries the DB password, so it
		# reaches the binary on stdin, never argv (which /proc exposes).
		printf '%s\n' "$STAGED_URL" | run_bin "'$SERVER_BIN' restore-db-merge --apply"
		# The scratch DB is a pg_restore of the WHOLE metadata dump — every keyblob
		# and every DEK wrap — so it must never outlive this run. Leave SCRATCH_DB
		# set: drop_db_if_exists swallows its own failure, and the EXIT trap is the
		# only thing that would notice and say so.
		drop_db_if_exists "$SCRATCH_DB"
	elif [ "$LIVE_DB_PRESENT" -eq 1 ]; then
		# REPLACE over a LIVE DB — the 2a626d6 shape; the binary already refused this
		# without --force at step 1, so reaching here means --force was given.
		echo "==> REPLACING the live database wholesale (--db-mode replace --force)"
		run_bin "pg_restore --clean --if-exists --no-owner --exit-on-error -h '$DB_HOST' -p '$DB_PORT' -U '$DB_USER' -d '$DB_NAME' '$DB_DUMP'" </dev/null
	else
		# DEAD-BOX REPLACE — no live DB. The role was already created/re-synced from the
		# just-restored unit above (that reconciliation used to live here, and only
		# here); all that is left is the database itself.
		echo "==> Rebuilding the database from scratch (dead-box replace)"
		db_exists="$(psql_super_query "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" </dev/null | tr -d '\r' || true)"
		if [ "$db_exists" != "1" ]; then
			printf "CREATE DATABASE %s OWNER %s;\n" "$DB_NAME" "$DB_USER" | psql_super_stdin >/dev/null
		fi
		run_bin "pg_restore --no-owner --exit-on-error -h '$DB_HOST' -p '$DB_PORT' -U '$DB_USER' -d '$DB_NAME' '$DB_DUMP'" </dev/null
	fi

	# ------------------------------------------------------------------------- #
	# BLOB-RESOLUTION AUDIT — replace paths only (design "Dead-box `--replace`").
	#
	# A replace consults no tombstones, so it puts back every file that existed at
	# backup time: including ones deleted since, and ones whose backed-up version
	# was superseded by a post-backup ROTATION (that version's chunks were purged
	# at finalize). Either way the row returns as a feed entry whose ciphertext is
	# gone from both tiers, and it 404s on download. Name them.
	#
	# It runs HERE, and not inside the `restore` subcommand, for a structural
	# reason: while `restore` was unsealing, `pg_restore` had not run yet, so there
	# was no `file_streams` table to walk. Hence its own subcommand.
	#
	# The MERGE path does not need it — the tombstone/revocation gate already stops
	# a deleted file coming back, and it never removes a live row.
	#
	# ADVISORY, and deliberately non-fatal: the restore already happened and is the
	# right outcome, and from here a cold-tier fault is indistinguishable from a
	# real absence. It prints; the operator audits. It never drops a row — doing so
	# would conflate "the owner deleted this" with "Dropbox hiccuped during the
	# restore" and would permanently destroy live files.
	# ------------------------------------------------------------------------- #
	if [ "$PLAN_DB_MODE" = "replace" ]; then
		echo "==> Auditing that every restored file's ciphertext still resolves"
		# The dead-box path has no DATABASE_URL in BIN_ENV (there was no live DB when
		# it was built); on the live-replace path this is the same value again. Emitted
		# through emit_env so a password containing a quote cannot break the sourcing.
		emit_env DATABASE_URL "$RESTORE_DB_URL" >>"$BIN_ENV"
		if ! run_bin "'$SERVER_BIN' verify-restored-blobs" </dev/null; then
			echo "warning: the blob-resolution audit did not complete; the restore itself is" >&2
			echo "         unaffected. Re-run it later with: $SERVER_BIN verify-restored-blobs" >&2
		fi
	fi
fi

# --------------------------------------------------------------------------- #
# 6c. CODE — check out the recorded commit and rebuild. Tolerates a tree with no
#     .git (the E2E source copy excludes it): a recorded sha with no checkout is a
#     hard error (we cannot honor it); a NULL sha (`<none>`) means the bundle
#     recorded no code marker, so there is nothing to check out — leave the current
#     tree/binary in place rather than fail the whole restore.
# --------------------------------------------------------------------------- #
if [ "$HAS_CODE" -eq 1 ]; then
	if run_as_user "git -C '$ROOT' rev-parse --is-inside-work-tree >/dev/null 2>&1" </dev/null; then
		if [ -n "$CODE_SHA" ]; then
			echo "==> Checking out $CODE_SHA and rebuilding the server binary"
			# Remember where HEAD was, so the note below can name the branch to go back
			# to. `--symbolic-full-name` gives an empty string if HEAD is ALREADY
			# detached, which is exactly when there is no branch to name.
			PREV_BRANCH="$(run_as_user "git -C '$ROOT' symbolic-ref --quiet --short HEAD 2>/dev/null || true" </dev/null | tr -d '\r' | head -1)"
			run_as_user "cd '$ROOT' && git checkout '$CODE_SHA'" </dev/null
			# `git checkout <sha>` DETACHES HEAD, and upgrade-server.sh's `git pull
			# --ff-only` then fails on every subsequent upgrade with an error that names
			# neither the cause nor the fix. Rolling back is not supposed to cost the
			# operator their upgrade path, so say so here, where the cause is legible.
			echo "    NOTE: the checkout above left $ROOT on a DETACHED HEAD at $CODE_SHA."
			if [ -n "$PREV_BRANCH" ]; then
				echo "          Once you are done rolling back, return to the branch before the"
				echo "          next upgrade (upgrade-server.sh runs 'git pull --ff-only', which"
				echo "          fails on a detached HEAD):"
				echo "              git -C '$ROOT' checkout $PREV_BRANCH"
			else
				echo "          Return to your branch before the next upgrade — upgrade-server.sh"
				echo "          runs 'git pull --ff-only', which fails on a detached HEAD."
			fi
		else
			echo "==> Code: the bundle recorded no git sha; rebuilding the current tree"
		fi
		if ! run_as_user "cd '$ROOT' && . '$CARGO_ENV' && cargo build --release -p maxsecu-portable-server" </dev/null; then
			echo "error: the code rebuild failed. Fix the build and re-run; the DB/run-state" >&2
			echo "       restore above already completed." >&2
			exit 1
		fi
	elif [ -n "$CODE_SHA" ]; then
		echo "error: --only code / the default restore recorded git sha $CODE_SHA, but this" >&2
		echo "       tree is not a git checkout (.git is excluded from the E2E source copy)." >&2
		echo "       Restore code by hand (git checkout $CODE_SHA in a real clone) or drop" >&2
		echo "       'code' from --only." >&2
		exit 1
	else
		echo "==> Code: no git sha recorded and no .git here — leaving the current binary."
	fi
fi

# --------------------------------------------------------------------------- #
# 7. Bring the service back (restart picks up the restored binary + TLS cert). On a
#    dead box this is the first start; enable it so it survives a reboot.
# --------------------------------------------------------------------------- #
echo "==> Restarting maxsecu-server"
run_root "systemctl daemon-reload" </dev/null
run_root "systemctl enable maxsecu-server >/dev/null 2>&1 || true" </dev/null
run_root "systemctl restart maxsecu-server" </dev/null
# We handed the service back ourselves — the cleanup trap must not second-guess it.
SERVER_STOPPED=0

if run_root "systemctl is-active --quiet maxsecu-server" </dev/null; then
	echo "    service is active (running)"
else
	echo "error: maxsecu-server did NOT come back active. Recent logs:" >&2
	run_root "journalctl -u maxsecu-server -n 40 --no-pager" </dev/null >&2 || true
	exit 1
fi

# The TLS cert was RESTORED unchanged, so the fingerprint clients pinned is the
# same — print it so you can confirm no client needs to re-pin. This line is the
# operator's ONLY confirmation of that, so a failure has to be said out loud: a
# banner followed by nothing reads exactly like a banner followed by a matching
# fingerprint, and the whole point of the restore is that nobody is locked out.
echo "==> Server fingerprint (restored unchanged — clients do NOT need to re-pin):"
run_bin "'$SERVER_BIN' print-fingerprint" </dev/null || {
	echo "warning: the fingerprint could not be printed — the pin files under" >&2
	echo "         $RESTORE_DATA_DIR/client-pins were unreadable. The TLS cert itself was" >&2
	echo "         restored unchanged, so pinned clients still connect; confirm with" >&2
	echo "         'sudo -u <service user> $SERVER_BIN print-fingerprint'." >&2
}

echo ""
echo "================ RESTORE COMPLETE ================"
echo "The server is live again on the restored state. Accounts, keys and uploads"
echo "were preserved (merge adds back what was missing and never removes a live"
echo "row); blobs rehydrate from the cold tier on first read. Watch it with:"
echo "    journalctl -u maxsecu-server -f"
echo "================================================="
