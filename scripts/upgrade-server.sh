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
#   1. (optional) pg_dump the metadata database as a quick safety backup.
#   2. (optional) `git pull --ff-only` when this folder is a git checkout; if it
#      isn't (you copied the files in by hand), that step is skipped.
#   3. Rebuild the release server binary WHILE the old one keeps serving, so a
#      build failure leaves the running server completely untouched.
#   4. Apply any pending database migrations (migrations/NNNN_*.sql), each in one
#      transaction, BEFORE the new binary starts — so the new code never meets an
#      old schema. Migrations only ADD to the schema; your rows are never
#      rewritten or dropped, and step 1 took a dump first anyway. Nothing at all
#      happens here when the schema is already up to date (the common case).
#   5. (optional) set the local cache capacity via a systemd drop-in.
#   6. Restart the service (a ~1s blip) and health-check it.
#
# Usage:
#   ./scripts/upgrade-server.sh                    # pull + backup + rebuild + restart
#   ./scripts/upgrade-server.sh --no-pull          # rebuild the current checkout as-is
#   ./scripts/upgrade-server.sh --no-backup        # skip the pg_dump
#   ./scripts/upgrade-server.sh --capacity-gb 50   # also set the cache cap to 50 GB
#
# Flags:
#   --no-pull        Do NOT `git pull`; rebuild whatever is checked out now.
#   --no-backup      Do NOT pg_dump the database first.
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
The build runs while the old server keeps serving, so a build failure leaves
production running the old binary.

Pending database migrations (migrations/NNNN_*.sql) are applied before the
restart, each in a single transaction, so the new code never starts against an
old schema. Migrations only ADD to the schema — no account, key, or uploaded
file is ever touched — and a pg_dump is taken first unless you pass --no-backup.

  --no-pull        Do NOT `git pull`; rebuild whatever is checked out now.
  --no-backup      Do NOT pg_dump the database first.
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
	exit 1
fi

# ExecStart is written as a bare binary path by install-server.sh (no args).
UNIT_BIN="$(run_root "sed -n 's/^ExecStart=//p' '$UNIT_PATH' | head -n1" | tr -d '\r')"
if [ "$UNIT_BIN" != "$SERVER_BIN" ]; then
	echo "error: the service runs a different binary than this repo would build:" >&2
	echo "         service ExecStart : $UNIT_BIN" >&2
	echo "         this repo builds  : $SERVER_BIN" >&2
	echo "       Run this script from the SAME clone the service was installed from," >&2
	echo "       or re-run install-server.sh to repoint the unit." >&2
	exit 1
fi
echo "    OK — service runs $SERVER_BIN"
echo "    data dir (left untouched): $DATA_DIR"

# --------------------------------------------------------------------------- #
# 4. Optional quick DB backup. The metadata DB is small (blobs live in the data
#    dir, not Postgres), so a pg_dump is fast and cheap insurance. We never
#    modify the DB, but this lets you roll back the whole box if you want to.
#    The data dir is NOT tarred here — it can be huge and is never touched.
# --------------------------------------------------------------------------- #
if [ "$DO_BACKUP" -eq 1 ]; then
	BACKUP_DIR="$RUN_HOME/maxsecu-upgrade-backups"
	STAMP="$(date +%Y%m%d%H%M%S)"
	BACKUP_FILE="$BACKUP_DIR/db-$STAMP.sql"
	echo "==> Backing up the metadata database to $BACKUP_FILE"
	run_as_user "mkdir -p '$BACKUP_DIR'"
	# Dump as the postgres superuser (role/db are named 'maxsecu'); write to a
	# path the run user owns. Fail the upgrade if the backup can't be written.
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "pg_dump maxsecu" >"$BACKUP_FILE"
	else
		sudo -u postgres pg_dump maxsecu >"$BACKUP_FILE"
	fi
	run_as_user "test -s '$BACKUP_FILE'" ||
		{ echo "error: database backup is empty — aborting before any change." >&2; exit 1; }
	echo "    backup OK ($(wc -c <"$BACKUP_FILE") bytes)"
else
	echo "==> Skipping database backup (--no-backup)"
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
# 6. Rebuild the release binary WHILE the old server keeps serving. cargo links
#    the new binary via an atomic rename, so overwriting the in-use file is safe;
#    and if the build fails we `exit` here, leaving production on the old binary.
# --------------------------------------------------------------------------- #
echo "==> Rebuilding maxsecu-portable-server (release) — this can take a while"
if ! run_as_user "cd '$ROOT' && . '$CARGO_ENV' && cargo build --release -p maxsecu-portable-server"; then
	echo "error: build failed. The running server was NOT touched (still on the old" >&2
	echo "       binary). Fix the build and re-run; nothing was restarted." >&2
	exit 1
fi
if ! run_as_user "test -x '$SERVER_BIN'"; then
	echo "error: build reported success but $SERVER_BIN is missing/not executable." >&2
	exit 1
fi
echo "    build OK"

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
#     would show it).
# --------------------------------------------------------------------------- #
echo "==> Applying database migrations"

# Take the LAST Environment=DATABASE_URL= across the unit and any drop-in, which
# is what systemd itself would use. The optional surrounding quotes systemd
# permits are stripped.
DATABASE_URL="$(
	run_root "cat '$UNIT_PATH' '$DROPIN_DIR'/*.conf 2>/dev/null |
		sed -n 's/^Environment=\"\\?DATABASE_URL=//p' |
		sed 's/\"\$//' |
		tail -n1"
)"
DATABASE_URL="$(printf '%s' "$DATABASE_URL" | tr -d '\r')"
if [ -z "$DATABASE_URL" ]; then
	echo "error: no DATABASE_URL in $UNIT_PATH — cannot reach the database to check" >&2
	echo "       for pending schema migrations. Refusing to restart into a possibly" >&2
	echo "       mismatched schema. Re-run scripts/install-server.sh to repair the unit." >&2
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
	exit 1
fi

MIGRATIONS_DIR="$ROOT/migrations"
db_psql() {
	PGPASSWORD="$DB_PASS" psql -v ON_ERROR_STOP=1 \
		-h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" "$@"
}
# shellcheck source=../migrations/apply.sh
. "$MIGRATIONS_DIR/apply.sh"

migrations_ensure_table
# Refuse BEFORE applying anything: a rewritten history must never be half-run.
migrations_verify_history
migrations_apply_pending

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
# 8. Restart the service (a brief blip) and confirm it came back healthy.
# --------------------------------------------------------------------------- #
echo "==> Restarting maxsecu-server"
run_root "systemctl restart maxsecu-server"

if run_root "systemctl is-active --quiet maxsecu-server"; then
	echo "    service is active (running)"
else
	echo "error: maxsecu-server did NOT come back active. Recent logs:" >&2
	run_root "journalctl -u maxsecu-server -n 40 --no-pager" >&2 || true
	echo "       Investigate above. Your data is intact; you can roll back the binary" >&2
	echo "       with 'git checkout <old-commit> && cargo build --release -p maxsecu-portable-server'." >&2
	exit 1
fi

# The TLS cert was not touched, so the fingerprint clients pinned is unchanged.
# Print it so you can confirm it matches what your users already have.
echo "==> Server fingerprint (unchanged — clients do NOT need to re-pin):"
run_as_user "MAXSECU_DATA_DIR='$DATA_DIR' '$SERVER_BIN' print-fingerprint" || true

echo ""
echo "================ UPGRADE COMPLETE ================"
echo "The new server binary is live, on an up-to-date schema. Accounts, keys,"
echo "uploads, TLS cert and client pins were all left in place. Watch it handle"
echo "real traffic with:"
echo "    journalctl -u maxsecu-server -f"
echo "================================================="
