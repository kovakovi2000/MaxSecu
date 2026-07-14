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
#   6. RECONCILE the service's environment with what this build expects. The unit
#      was written once, by install-server.sh, and is never rewritten here — so a
#      new MAXSECU_* variable would otherwise reach FRESH INSTALLS ONLY and every
#      already-deployed server would silently run without it, forever. This step
#      adds any MISSING variable via a drop-in, at exactly the value the binary
#      already defaults to. It NEVER touches a variable you have set: your port,
#      your DATABASE_URL, your cache capacity and your Dropbox login are read, not
#      written. Running it twice changes nothing.
#   7. Restart the service (a ~1s blip) and health-check it.
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

The service's ENVIRONMENT is reconciled the same way: any variable this build
expects that your unit does not define anywhere is added via a systemd drop-in,
at exactly the value the server already defaults to. A variable you HAVE set —
your port, your DATABASE_URL, your cache capacity, your Dropbox login — is read
and left alone, never overwritten. Running the upgrade twice changes nothing.

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
#                         something to paper over: step 6b already aborts the
#                         upgrade (before touching anything) when it is missing,
#                         and tells you to re-run install-server.sh to repair the
#                         unit. There is no default and there must never be one.
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
	ENV_TMP="$(mktemp)"
	trap 'rm -f "$ENV_TMP"' EXIT
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
		trap - EXIT
	else
		echo "    adding to $ENV_DROPIN:$ADDED"
		run_root "mkdir -p '$DROPIN_DIR'"
		run_root "install -o root -g root -m 0644 '$ENV_TMP' '$ENV_DROPIN'"
		rm -f "$ENV_TMP"
		trap - EXIT
		run_root "systemctl daemon-reload"
	fi
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
