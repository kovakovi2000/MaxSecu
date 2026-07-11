#!/usr/bin/env bash
#
# install-server.sh — one-command MaxSecu server install for a fresh Ubuntu 22.04 VPS.
#
# Written for someone with near-zero technical knowledge: SSH into the box once,
# `git clone` the repo, then run this. It is idempotent — safe to run again if
# something was interrupted or you want to switch to `--public`.
#
# Usage:
#   ./scripts/install-server.sh                 # local-only (127.0.0.1), for testing
#   ./scripts/install-server.sh --public        # reachable on the internet; auto-detect IP
#   ./scripts/install-server.sh --public 1.2.3.4   # reachable on the internet; explicit IP
#   ./scripts/install-server.sh --public --port 9443
#
# Flags:
#   --public [IP]   Bind 0.0.0.0 and bake the public IP into the TLS cert SAN so
#                   users can type it on the login/register screen. If IP is
#                   omitted it is auto-detected (https://api.ipify.org) and echoed
#                   for you to confirm.
#   --port N        Listen port (default 8443).
#   --capacity-gb N Local hot-store cache capacity in GB before the cold tier
#                   offloads (default 200). Prompted interactively; a
#                   non-interactive run defaults to 200 without asking.
#   --dropbox       Force the Dropbox cold-tier setup prompt ON (needs a TTY: you
#                   paste the App key/secret + a browser authorization code, which
#                   the installer exchanges for a refresh token). --no-dropbox
#                   forces it OFF (no prompt).
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# 0. Resolve the repo root from this script's own location (scripts/ -> root).
# --------------------------------------------------------------------------- #
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: install-server.sh [--public [IP]] [--port N] [--capacity-gb N]

  --public [IP]   Make the server reachable from the internet. Binds 0.0.0.0 and
                  puts the public IP in the TLS certificate. If you omit IP it is
                  auto-detected and shown for you to confirm.
  --port N        Listen port (default 8443).
  --capacity-gb N Local hot-store cache capacity in GB before the cold tier
                  offloads (default 200). Interactively you are prompted; in a
                  non-interactive run it defaults to 200 without asking.
  --dropbox       Force the Dropbox cold-tier setup prompt ON. You must run in a
                  terminal (TTY): you paste the App key + secret and a one-time
                  browser authorization code, and the installer exchanges it for a
                  long-lived refresh token itself.
  --no-dropbox    Skip the Dropbox cold-tier prompt entirely.
  --reset         Tear the server down to ZERO and exit (do NOT reinstall): stop +
                  remove the service, DROP the database + role (all accounts incl.
                  the recovery account), delete the data dir + TLS cert, remove the
                  saved Dropbox login, and close the firewall port. Idempotent and
                  safe on a never-installed box. The source folder is left in place.
  -h, --help      Show this help.
EOF
}

# --------------------------------------------------------------------------- #
# 1. Parse flags. Supports both `--flag value` and `--flag=value`.
# --------------------------------------------------------------------------- #
PUBLIC=0
PUBLIC_IP=""
PORT=8443
# Local hot-store cache capacity in GB. Empty = "not set on the command line":
# resolved later to an interactive prompt (default 200) or a silent 200 in a
# non-interactive run.
CAPACITY_GB=""
# Dropbox cold-tier: -1 = decide interactively (default), 1 = forced on, 0 = forced off.
DROPBOX_FORCE=-1
# --reset / --uninstall: tear everything down and exit instead of installing.
RESET=0

while [ $# -gt 0 ]; do
	case "$1" in
	--public=*)
		PUBLIC=1
		PUBLIC_IP="${1#*=}"
		shift
		;;
	--public)
		PUBLIC=1
		# An optional IP may follow. Consume it only if the next token is not
		# another flag (does not start with '-').
		if [ $# -ge 2 ] && [ -n "${2:-}" ] && [ "${2#-}" = "$2" ]; then
			PUBLIC_IP="$2"
			shift 2
		else
			shift
		fi
		;;
	--port=*)
		PORT="${1#*=}"
		shift
		;;
	--port)
		if [ $# -lt 2 ]; then
			echo "error: --port needs a value" >&2
			exit 2
		fi
		PORT="$2"
		shift 2
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
	--dropbox)
		DROPBOX_FORCE=1
		shift
		;;
	--no-dropbox)
		DROPBOX_FORCE=0
		shift
		;;
	--reset | --uninstall)
		RESET=1
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

if ! [ "$PORT" -gt 0 ] 2>/dev/null || [ "$PORT" -gt 65535 ]; then
	echo "error: --port must be a number between 1 and 65535 (got '$PORT')" >&2
	exit 2
fi

# --------------------------------------------------------------------------- #
# 2. Privilege + identity helpers.
#    Root is needed for apt / systemd / postgres. The build and the runtime data
#    dir belong to the *invoking* user, never root.
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

# Run a psql query as the postgres superuser and print the result (for guards).
psql_super_query() {
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "psql -tAc \"$1\""
	else
		sudo -u postgres psql -tAc "$1"
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

# --------------------------------------------------------------------------- #
# 2b. Full teardown (--reset). Removes ALL server state so the next install is
#     truly from zero, then EXITS. Every step is guarded / idempotent, so this is
#     safe to run twice, or on a box where MaxSecu was never installed (it just
#     reports "nothing to do" for each already-absent piece). The one thing it
#     never touches is the source checkout it is running from.
# --------------------------------------------------------------------------- #
if [ "$RESET" -eq 1 ]; then
	DROPBOX_ENV_DIR="/etc/maxsecu"
	echo "==> MaxSecu server RESET — removing ALL server state (no reinstall)"
	echo "    run as   : $RUN_USER"
	echo "    data dir : $DATA_DIR"
	echo "    db       : maxsecu (role + database)"
	echo ""

	# 1. Stop + disable + remove the systemd service so nothing restarts mid-wipe.
	echo "==> Stopping and removing the systemd service"
	run_root "systemctl disable --now maxsecu-server 2>/dev/null || true"
	run_root "rm -f '$UNIT_PATH'"
	run_root "systemctl daemon-reload 2>/dev/null || true"

	# 2. Drop the database (all accounts incl. the singleton recovery account) and
	#    the login role. WITH (FORCE) evicts any lingering connections (PG13+); if
	#    the local Postgres is older it falls back to a plain DROP DATABASE. Guarded
	#    so a missing/stopped Postgres does not abort the rest of the teardown.
	if run_root "systemctl is-active --quiet postgresql"; then
		echo "==> Dropping the 'maxsecu' database and role"
		printf 'DROP DATABASE IF EXISTS maxsecu WITH (FORCE);\n' | psql_super_stdin >/dev/null 2>&1 ||
			printf 'DROP DATABASE IF EXISTS maxsecu;\n' | psql_super_stdin >/dev/null 2>&1 || true
		printf 'DROP ROLE IF EXISTS maxsecu;\n' | psql_super_stdin >/dev/null 2>&1 || true
	else
		echo "==> PostgreSQL is not running — skipping the database drop"
	fi

	# 3. Remove the data dir (TLS cert, client pins, blob store, recovery state).
	echo "==> Removing the data directory $DATA_DIR"
	run_as_user "rm -rf '$DATA_DIR'" 2>/dev/null || run_root "rm -rf '$DATA_DIR'"

	# 4. Remove the Dropbox cold-tier credentials (root-only 0600 env file + dir).
	echo "==> Removing Dropbox cold-tier credentials ($DROPBOX_ENV_DIR)"
	run_root "rm -rf '$DROPBOX_ENV_DIR'"

	# 5. Close the firewall port if ufw manages it. Uses $PORT, so pass the same
	#    --port you installed with if it was not the 8443 default.
	if command -v ufw >/dev/null 2>&1; then
		echo "==> Removing the ufw allow rule for ${PORT}/tcp"
		run_root "ufw delete allow ${PORT}/tcp 2>/dev/null || true"
	fi

	echo ""
	echo "============================================================"
	echo " MaxSecu server state removed. This machine is back to zero."
	echo "============================================================"
	echo ""
	echo " The source folder was left in place:"
	echo "     $ROOT"
	echo " To also discard any local code edits there, run:"
	echo "     git -C '$ROOT' reset --hard && git -C '$ROOT' clean -xffd"
	echo ""
	echo " To install again from scratch:"
	echo "     $0 --public"
	echo "============================================================"
	exit 0
fi

echo "==> MaxSecu server install"
echo "    repo root : $ROOT"
echo "    run as    : $RUN_USER (home $RUN_HOME)"
echo "    data dir  : $DATA_DIR"
echo "    port      : $PORT"
if [ "$PUBLIC" -eq 1 ]; then
	echo "    mode      : PUBLIC (reachable from the internet)"
else
	echo "    mode      : local-only (127.0.0.1)"
fi

# --------------------------------------------------------------------------- #
# 3. Install prerequisites via apt (idempotent — dpkg skips what's present).
# --------------------------------------------------------------------------- #
echo "==> Installing system packages (apt)"
APT_PKGS="build-essential pkg-config libssl-dev clang curl git postgresql"
missing=""
for pkg in $APT_PKGS; do
	if ! dpkg -s "$pkg" >/dev/null 2>&1; then
		missing="$missing $pkg"
	fi
done
if [ -n "$missing" ]; then
	echo "    installing:$missing"
	# --allow-releaseinfo-change: on a non-fresh VPS a pre-existing third-party
	# repo (e.g. an ondrej/php PPA) may have changed its Label/Suite metadata,
	# which makes a plain `apt-get update` exit non-zero and — under `set -e` —
	# abort the whole install for a reason unrelated to MaxSecu. Accepting the
	# (metadata-only) change lets the update proceed. It does NOT bypass GPG
	# signature verification: unsigned/badly-signed repos still fail.
	run_root "DEBIAN_FRONTEND=noninteractive apt-get update --allow-releaseinfo-change"
	run_root "DEBIAN_FRONTEND=noninteractive apt-get install -y$missing"
else
	echo "    all packages already present — nothing to do"
fi

# Make sure PostgreSQL is running and set to start on boot.
run_root "systemctl enable --now postgresql" || true

# --------------------------------------------------------------------------- #
# 4. Resolve the public IP now that curl is guaranteed to be installed.
# --------------------------------------------------------------------------- #
if [ "$PUBLIC" -eq 1 ] && [ -z "$PUBLIC_IP" ]; then
	echo "==> Auto-detecting this server's public IP"
	PUBLIC_IP="$(curl -s --max-time 15 https://api.ipify.org || true)"
	if [ -z "$PUBLIC_IP" ]; then
		echo "error: could not auto-detect a public IP." >&2
		echo "       Re-run with it explicit, e.g.:  $0 --public YOUR.IP.HERE" >&2
		exit 1
	fi
	echo "    Detected public IP: $PUBLIC_IP"
	echo "    Users will connect to  $PUBLIC_IP:$PORT  — make sure this is correct."
fi

# --------------------------------------------------------------------------- #
# 5. Install the Rust toolchain (rustup, non-interactive). Guarded.
# --------------------------------------------------------------------------- #
echo "==> Ensuring the Rust toolchain (rustup)"
if [ -x "$RUN_HOME/.cargo/bin/rustup" ]; then
	echo "    rustup already installed"
else
	echo "    installing rustup for $RUN_USER"
	run_as_user "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
fi

# --------------------------------------------------------------------------- #
# 6. Build the server (release). Toolchain version comes from rust-toolchain.toml.
# --------------------------------------------------------------------------- #
echo "==> Building maxsecu-portable-server (release) — this can take a while"
run_as_user "cd '$ROOT' && . '$CARGO_ENV' && cargo build --release -p maxsecu-portable-server"
SERVER_BIN="$ROOT/target/release/maxsecu-portable-server"
if [ ! -x "$SERVER_BIN" ]; then
	echo "error: build finished but $SERVER_BIN is missing" >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 7. PostgreSQL role + database (idempotent). A fresh random password is set on
#    every run and only ever written into the root-owned service file below.
# --------------------------------------------------------------------------- #
echo "==> Configuring PostgreSQL role + database 'maxsecu'"
DB_PASS="$(openssl rand -hex 24)"

role_exists="$(psql_super_query "SELECT 1 FROM pg_roles WHERE rolname='maxsecu'" || true)"
if [ "$role_exists" = "1" ]; then
	echo "    role 'maxsecu' exists — updating its password"
	printf "ALTER ROLE maxsecu WITH LOGIN PASSWORD '%s';\n" "$DB_PASS" | psql_super_stdin >/dev/null
else
	echo "    creating role 'maxsecu'"
	printf "CREATE ROLE maxsecu WITH LOGIN PASSWORD '%s';\n" "$DB_PASS" | psql_super_stdin >/dev/null
fi

db_exists="$(psql_super_query "SELECT 1 FROM pg_database WHERE datname='maxsecu'" || true)"
if [ "$db_exists" = "1" ]; then
	echo "    database 'maxsecu' exists — leaving it in place"
else
	echo "    creating database 'maxsecu' owned by 'maxsecu'"
	printf 'CREATE DATABASE maxsecu OWNER maxsecu;\n' | psql_super_stdin >/dev/null
fi

DATABASE_URL="postgres://maxsecu:${DB_PASS}@localhost/maxsecu"

# --------------------------------------------------------------------------- #
# 8. Apply the schema (PgStore does NOT auto-create). Guarded: skip if the core
#    'users' table already exists. Password travels via PGPASSWORD, not argv.
# --------------------------------------------------------------------------- #
echo "==> Applying database schema"
have_users="$(
	PGPASSWORD="$DB_PASS" psql -h localhost -U maxsecu -d maxsecu -tAc \
		"SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='users' LIMIT 1" || true
)"
if [ -n "$have_users" ]; then
	echo "    schema already applied (table 'users' present) — skipping"
else
	echo "    loading $ROOT/docs/schema.sql"
	PGPASSWORD="$DB_PASS" psql -v ON_ERROR_STOP=1 -h localhost -U maxsecu -d maxsecu -f "$ROOT/docs/schema.sql" >/dev/null
fi

# --------------------------------------------------------------------------- #
# 9. For --public, drop any stale cert/pins so the cert regenerates WITH the
#    public-IP SAN on next server start. (Cert files: tls/cert.der, tls/key.der.)
# --------------------------------------------------------------------------- #
run_as_user "mkdir -p '$DATA_DIR'"
if [ "$PUBLIC" -eq 1 ]; then
	echo "==> Removing stale TLS cert + client pins so the cert regenerates for $PUBLIC_IP"
	run_as_user "rm -rf '$DATA_DIR/client-pins' '$DATA_DIR/tls/cert.der' '$DATA_DIR/tls/key.der'"
fi

# --------------------------------------------------------------------------- #
# 9b. Optional Dropbox cold-tier offload. Interactive; the credentials are read
#     WITHOUT echo and written only to a root:root 0600 EnvironmentFile that the
#     systemd unit loads. Answering No (or a non-TTY run) never touches an
#     existing creds file, so re-runs preserve prior Dropbox setup.
# --------------------------------------------------------------------------- #
DROPBOX_ENV_PATH="/etc/maxsecu/dropbox.env"
DROPBOX_ENABLED_THIS_RUN=0

# Decide whether to run the Dropbox setup prompt.
want_dropbox=0
if [ "$DROPBOX_FORCE" -eq 0 ]; then
	: # explicitly disabled with --no-dropbox
elif [ "$DROPBOX_FORCE" -eq 1 ]; then
	# --dropbox forces yes, but secrets can only be read from a real terminal.
	if [ -t 0 ]; then
		want_dropbox=1
	else
		echo "error: --dropbox needs an interactive terminal to read the secrets," >&2
		echo "       but stdin is not a TTY. Re-run in a terminal, or set the" >&2
		echo "       MAXSECU_DROPBOX_* credentials in $DROPBOX_ENV_PATH by hand." >&2
		exit 2
	fi
elif [ -t 0 ]; then
	# Default: interactive prompt, default No.
	printf 'Enable Dropbox cold-tier offload? [y/N] '
	read -r reply || reply=""
	case "$reply" in
	y | Y | yes | YES | Yes)
		want_dropbox=1
		;;
	*) ;;
	esac
else
	# No TTY and no forcing flag → auto-No so non-interactive --public never hangs.
	echo "==> Non-interactive run (no TTY): skipping the Dropbox cold-tier prompt"
	echo "    (re-run in a terminal, or pass --dropbox, to enable it)"
fi

if [ "$want_dropbox" -eq 1 ]; then
	echo "==> Dropbox cold-tier setup"
	echo "    Paste your App key + App secret (Dropbox App Console), then authorize"
	echo "    the app ONCE in your browser and paste the code back — this installer"
	echo "    exchanges it for a long-lived refresh token for you (no manual curl)."
	echo "    Secrets are NOT echoed; they are written only to $DROPBOX_ENV_PATH (root 0600)."
	echo ""

	printf 'Dropbox App key: '
	read -r DBX_APP_KEY || DBX_APP_KEY=""

	printf 'Dropbox App secret: '
	read -rs DBX_APP_SECRET || DBX_APP_SECRET=""
	printf '\n'

	# Populated by the code→token exchange below; empty means "leave the tier off".
	DBX_REFRESH_TOKEN=""
	DBX_ACCESS_TOKEN=""

	if [ -z "$DBX_APP_KEY" ] || [ -z "$DBX_APP_SECRET" ]; then
		echo "warning: App key and App secret are both required." >&2
		echo "         One was blank — leaving the Dropbox cold tier OFF (nothing written)." >&2
	else
		# One-time offline authorization: the operator opens this URL in THEIR own
		# browser (this box is headless), clicks Allow, and Dropbox shows a short
		# single-use authorization code. `token_access_type=offline` is what makes
		# Dropbox issue a long-lived refresh token at the exchange below.
		echo ""
		echo "    1. Open this URL in a browser and click \"Allow\":"
		echo ""
		echo "       https://www.dropbox.com/oauth2/authorize?client_id=${DBX_APP_KEY}&response_type=code&token_access_type=offline"
		echo ""
		echo "    2. Copy the authorization code Dropbox shows you and paste it here."
		echo ""
		printf 'Authorization code: '
		read -r DBX_CODE || DBX_CODE=""

		if [ -z "$DBX_CODE" ]; then
			echo "warning: no authorization code entered — leaving the Dropbox cold tier OFF." >&2
		else
			echo "    Exchanging the code for a refresh token…"
			# The App secret and code go through a private curl config file
			# (umask 077) so neither ever appears in the process arg list (`ps`).
			OLD_UMASK="$(umask)"
			umask 077
			DBX_CURL_CFG="$(mktemp)"
			umask "$OLD_UMASK"
			trap 'rm -f "$DBX_CURL_CFG"' EXIT
			printf 'user = "%s:%s"\ndata = "grant_type=authorization_code"\ndata-urlencode = "code=%s"\n' \
				"$DBX_APP_KEY" "$DBX_APP_SECRET" "$DBX_CODE" >"$DBX_CURL_CFG"
			DBX_RESP="$(curl -sS -K "$DBX_CURL_CFG" https://api.dropboxapi.com/oauth2/token || true)"
			rm -f "$DBX_CURL_CFG"
			trap - EXIT
			unset DBX_CODE

			# Extract the tokens from Dropbox's compact single-line JSON (no jq
			# dependency). A missing refresh_token means the exchange failed.
			DBX_REFRESH_TOKEN="$(printf '%s' "$DBX_RESP" | sed -n 's/.*"refresh_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
			DBX_ACCESS_TOKEN="$(printf '%s' "$DBX_RESP" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
			if [ -z "$DBX_REFRESH_TOKEN" ]; then
				DBX_ERR="$(printf '%s' "$DBX_RESP" | sed -n 's/.*"error_description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
				if [ -z "$DBX_ERR" ]; then
					DBX_ERR="$(printf '%s' "$DBX_RESP" | sed -n 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
				fi
				echo "warning: Dropbox did not return a refresh token — leaving the cold tier OFF." >&2
				if [ -n "$DBX_ERR" ]; then
					echo "         Dropbox said: $DBX_ERR" >&2
				fi
				echo "         (The code is single-use and expires fast — re-run to try again.)" >&2
			fi
			unset DBX_RESP
		fi
	fi

	if [ -n "$DBX_REFRESH_TOKEN" ]; then
		printf 'Dropbox root folder [/maxsecu]: '
		read -r DBX_ROOT || DBX_ROOT=""
		if [ -z "$DBX_ROOT" ]; then
			DBX_ROOT="/maxsecu"
		fi

		# Build the creds file in a private temp file (umask 077 so it is never
		# world/group-readable, even briefly), then install it root:root 0600.
		# The access token from the exchange warm-starts the server's token cache.
		run_root "install -d -o root -g root -m 0700 /etc/maxsecu"
		OLD_UMASK="$(umask)"
		umask 077
		DBX_TMP="$(mktemp)"
		umask "$OLD_UMASK"
		trap 'rm -f "$DBX_TMP"' EXIT
		{
			printf '%s\n' "MAXSECU_COLD_TIER=dropbox"
			printf 'MAXSECU_DROPBOX_APP_KEY=%s\n' "$DBX_APP_KEY"
			printf 'MAXSECU_DROPBOX_APP_SECRET=%s\n' "$DBX_APP_SECRET"
			printf 'MAXSECU_DROPBOX_REFRESH_TOKEN=%s\n' "$DBX_REFRESH_TOKEN"
			if [ -n "$DBX_ACCESS_TOKEN" ]; then
				printf 'MAXSECU_DROPBOX_ACCESS_TOKEN=%s\n' "$DBX_ACCESS_TOKEN"
			fi
			printf 'MAXSECU_DROPBOX_ROOT=%s\n' "$DBX_ROOT"
		} >"$DBX_TMP"

		run_root "install -o root -g root -m 0600 '$DBX_TMP' '$DROPBOX_ENV_PATH'"
		rm -f "$DBX_TMP"
		trap - EXIT

		# Drop the plaintext secrets from this shell's memory now that they are
		# safely on disk (0600). Nothing was ever echoed to the terminal.
		unset DBX_APP_SECRET DBX_REFRESH_TOKEN DBX_ACCESS_TOKEN
		DROPBOX_ENABLED_THIS_RUN=1
		echo "    Wrote $DROPBOX_ENV_PATH (root:root 0600)."
	fi
fi

# --------------------------------------------------------------------------- #
# 9d. Resolve the local hot-store cache capacity (GB). A --capacity-gb value is
#     honoured as given; otherwise an interactive run prompts (default 200) and a
#     non-interactive run silently defaults to 200 so it never hangs. The value
#     is validated as a positive whole number and converted to the byte count the
#     server reads from MAXSECU_CACHE_CAPACITY_BYTES (decimal GB, matching the
#     server's 200_000_000_000 default).
# --------------------------------------------------------------------------- #
if [ -z "$CAPACITY_GB" ]; then
	if [ -t 0 ]; then
		printf 'Local cache capacity in GB before cold-tier offload [200]: '
		read -r reply || reply=""
		if [ -z "$reply" ]; then
			CAPACITY_GB=200
		else
			CAPACITY_GB="$reply"
		fi
	else
		CAPACITY_GB=200
	fi
fi

# Must be a positive whole number of GB. 200 -> 200000000000 fits comfortably in
# 64-bit shell arithmetic; a pathologically huge N could overflow, but that is far
# beyond any real disk so it is not guarded here.
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
CAP_BYTES=$((CAPACITY_GB * 1000000000))

# --------------------------------------------------------------------------- #
# 10. Write the systemd unit. It holds the DB password, so it is root:root 0600
#     and the password is never printed to the terminal.
# --------------------------------------------------------------------------- #
echo "==> Writing systemd unit $UNIT_PATH"
if [ "$PUBLIC" -eq 1 ]; then
	BIND_ADDR="0.0.0.0"
else
	BIND_ADDR="127.0.0.1"
fi

UNIT_TMP="$(mktemp)"
trap 'rm -f "$UNIT_TMP"' EXIT
{
	echo "[Unit]"
	echo "Description=MaxSecu portable server"
	echo "After=network-online.target postgresql.service"
	echo "Wants=network-online.target"
	echo "Requires=postgresql.service"
	echo ""
	echo "[Service]"
	echo "Type=simple"
	echo "User=$RUN_USER"
	echo "WorkingDirectory=$ROOT"
	echo "ExecStart=$SERVER_BIN"
	echo "Restart=always"
	echo "RestartSec=2"
	echo "Environment=DATABASE_URL=$DATABASE_URL"
	echo "Environment=MAXSECU_BIND=$BIND_ADDR"
	if [ "$PUBLIC" -eq 1 ]; then
		echo "Environment=MAXSECU_PUBLIC_ADDR=$PUBLIC_IP"
	fi
	echo "Environment=MAXSECU_PORT=$PORT"
	echo "Environment=MAXSECU_DATA_DIR=$DATA_DIR"
	echo "Environment=MAXSECU_CACHE_CAPACITY_BYTES=$CAP_BYTES"
	# Optional Dropbox cold-tier creds. Leading '-' => an absent file is ignored,
	# so no-Dropbox installs and re-runs are unaffected and never clobbered.
	echo "EnvironmentFile=-$DROPBOX_ENV_PATH"
	echo ""
	echo "[Install]"
	echo "WantedBy=multi-user.target"
} >"$UNIT_TMP"

run_root "install -o root -g root -m 0600 '$UNIT_TMP' '$UNIT_PATH'"
rm -f "$UNIT_TMP"
trap - EXIT

# --------------------------------------------------------------------------- #
# 11. Enable + (re)start the service.
# --------------------------------------------------------------------------- #
echo "==> Enabling + starting maxsecu-server"
run_root "systemctl daemon-reload"
run_root "systemctl enable --now maxsecu-server"
# If it was already running, pick up the new unit/cert.
run_root "systemctl restart maxsecu-server"

# --------------------------------------------------------------------------- #
# 12. Open the firewall for the port when public and ufw is present.
# --------------------------------------------------------------------------- #
if [ "$PUBLIC" -eq 1 ] && command -v ufw >/dev/null 2>&1; then
	echo "==> Allowing ${PORT}/tcp through ufw"
	run_root "ufw allow ${PORT}/tcp" || true
fi

# --------------------------------------------------------------------------- #
# 13. Wait for the client pins to appear (proves the server started + generated
#     its cert). Bounded so a broken start does not hang forever.
# --------------------------------------------------------------------------- #
echo "==> Waiting for the server to generate its client pins"
PIN_CERT="$DATA_DIR/client-pins/server_cert.der"
pins_ready=0
for _ in $(seq 1 60); do
	if [ -f "$PIN_CERT" ]; then
		pins_ready=1
		break
	fi
	sleep 1
done

if [ "$pins_ready" -ne 1 ]; then
	echo "" >&2
	echo "warning: the server did not produce $PIN_CERT within 60s." >&2
	echo "         Check its logs with:  journalctl -u maxsecu-server -e" >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 13b. Offline-D5 inversion (design 2026-07-10 §§6,8): the final connection code
#      is minted on the ADMIN PC (the directory root D5 originates there), NOT
#      here. A Prod install starts AWAITING DELEGATION with enrollment CLOSED, so
#      this script prints only what install-client needs to run the ceremony:
#        * the CERT-ONLY fingerprint  (print-cert-fingerprint) — pins TLS while
#          the server still has no directory_pub;
#        * the one-time delegation token (print-token) — burned by the ceremony.
#      Both read <data_dir>, so MAXSECU_DATA_DIR must point at the right dir.
# --------------------------------------------------------------------------- #
if [ "$PUBLIC" -eq 1 ]; then
	PUBLIC_ADDRESS="$PUBLIC_IP:$PORT"
	# Clean dial target for the connection code: bare IP:PORT, no annotation.
	CONN_ADDR="$PUBLIC_IP:$PORT"
else
	PUBLIC_ADDRESS="127.0.0.1:$PORT (local-only — re-run with --public to expose it)"
	CONN_ADDR="127.0.0.1:$PORT"
fi

echo "==> Reading the server-cert fingerprint (for the client to pin over TLS)"
CERT_FP="$(MAXSECU_DATA_DIR="$DATA_DIR" "$SERVER_BIN" print-cert-fingerprint || true)"
if [ -z "$CERT_FP" ]; then
	echo "error: could not read the server-cert fingerprint (print-cert-fingerprint" >&2
	echo "       returned nothing). Check the server binary and $DATA_DIR/client-pins." >&2
	exit 1
fi

# The one-time delegation token is written during the Prod (awaiting-delegation)
# startup. It may land a beat after server_cert.der, so retry briefly. An empty
# result after the retries means the server is ALREADY delegated (token burned)
# or this is a non-Prod (Dev/MemoryStore) run with no ceremony.
echo "==> Reading the one-time delegation token"
TOKEN=""
for _ in $(seq 1 15); do
	TOKEN="$(MAXSECU_DATA_DIR="$DATA_DIR" "$SERVER_BIN" print-token 2>/dev/null || true)"
	if [ -n "$TOKEN" ]; then
		break
	fi
	sleep 1
done

# --------------------------------------------------------------------------- #
# 14. Friendly summary. Never prints the DB password.
# --------------------------------------------------------------------------- #
# Prod-readiness checklist values, shared by both final banners below.
if [ "$PUBLIC" -eq 1 ]; then
	CERT_SAN_ADDR="$PUBLIC_IP"
else
	CERT_SAN_ADDR="127.0.0.1"
fi
if [ "$DROPBOX_ENABLED_THIS_RUN" -eq 1 ]; then
	DROPBOX_STATUS="ENABLED"
else
	DROPBOX_STATUS="off"
fi

if [ -z "$TOKEN" ]; then
	# No token → already delegated (or a non-Prod run). Enrollment is already
	# open; the final connection code was minted on the admin PC during the
	# ceremony. As a convenience, re-derive it here (print-fingerprint is valid
	# once directory_pub.der has been pinned by the delegation).
	FULL_FP="$(MAXSECU_DATA_DIR="$DATA_DIR" "$SERVER_BIN" print-fingerprint 2>/dev/null || true)"
	echo ""
	echo "============================================================"
	echo " MaxSecu server is installed and running — ALREADY DELEGATED."
	echo "============================================================"
	echo ""
	echo " A directory delegation is already installed and enrollment is OPEN."
	echo " The one-time delegation token has been consumed (single use), so there"
	echo " is nothing new to hand to install-client."
	echo ""
	echo " PUBLIC ADDRESS to give your users:"
	echo ""
	echo "        $PUBLIC_ADDRESS"
	echo ""
	if [ -n "$FULL_FP" ]; then
		echo " Connection code (the one the admin PC minted, re-derived for reference):"
		echo ""
		echo "        $CONN_ADDR#$FULL_FP"
		echo ""
	fi
	echo " To start over from a fresh awaiting-delegation state, run:  $0 --reset"
	echo " then re-install; that regenerates a new one-time token."
	echo ""
	echo " To watch the server's live logs at any time:"
	echo ""
	echo "        journalctl -u maxsecu-server -f"
	echo ""
	echo " PROD-READINESS:"
	echo ""
	echo "        ✓ release build"
	echo "        ✓ TLS cert for $CERT_SAN_ADDR"
	if [ "$PUBLIC" -eq 1 ] && command -v ufw >/dev/null 2>&1; then
		echo "        ✓ firewall ${PORT}/tcp open"
	fi
	echo "        ✓ systemd service enabled"
	echo "        Dropbox cold-tier: $DROPBOX_STATUS"
	echo ""
	echo "============================================================"
else
	echo ""
	echo "============================================================"
	echo " MaxSecu server is installed and running — AWAITING DELEGATION."
	echo "============================================================"
	echo ""
	echo " Enrollment is CLOSED until you complete the one-time delegation"
	echo " ceremony from your Windows admin PC. This server holds ONLY a"
	echo " short-lived operational key — the directory root (D5) is generated"
	echo " on your PC by install-client, never here. That is what makes the"
	echo " admin PC (not this internet-facing server) the directory authority."
	echo ""
	echo " 1. PUBLIC ADDRESS to give your users (type this on the app's"
	echo "    login / register screen):"
	echo ""
	echo "        $PUBLIC_ADDRESS"
	echo ""
	echo " 2. SERVER-CERT FINGERPRINT (lets install-client pin this server over TLS):"
	echo ""
	echo "        $CERT_FP"
	echo ""
	echo " 3. ONE-TIME DELEGATION TOKEN (single use — keep it secret until used):"
	echo ""
	echo "        $TOKEN"
	echo ""
	echo " 4. NEXT STEP — on your Windows admin PC, in the repo folder, run:"
	echo ""
	echo "        powershell -ExecutionPolicy Bypass -File scripts\\install-client.ps1 -ConnectionCode $CONN_ADDR#$CERT_FP -Token $TOKEN"
	echo ""
	echo "    install-client fetches + pins this server's cert, generates the"
	echo "    directory root, uploads the delegation (which OPENS enrollment),"
	echo "    and then prints the FINAL connection code to hand to your users."
	echo "    No SSH to this server is required."
	echo ""
	echo " 5. To watch the server's live logs at any time:"
	echo ""
	echo "        journalctl -u maxsecu-server -f"
	echo ""
	echo " PROD-READINESS:"
	echo ""
	echo "        ✓ release build"
	echo "        ✓ TLS cert for $CERT_SAN_ADDR"
	if [ "$PUBLIC" -eq 1 ] && command -v ufw >/dev/null 2>&1; then
		echo "        ✓ firewall ${PORT}/tcp open"
	fi
	echo "        ✓ systemd service enabled"
	echo "        Dropbox cold-tier: $DROPBOX_STATUS"
	echo ""
	echo " AWAITING DELEGATION (enrollment CLOSED) is the EXPECTED state right"
	echo " after a fresh prod install — this is NOT an error. Enrollment opens"
	echo " automatically once the admin PC uploads the delegation via install-client"
	echo " (step 4 above)."
	echo ""
	echo "============================================================"
fi

if [ "$DROPBOX_ENABLED_THIS_RUN" -eq 1 ]; then
	echo ""
	echo " Dropbox cold-tier offload: ENABLED (creds in $DROPBOX_ENV_PATH, root-only)."
elif [ ! -e "$DROPBOX_ENV_PATH" ]; then
	echo ""
	echo " Dropbox cold-tier offload is OFF. Re-run this script (or pass --dropbox)"
	echo " to enable it."
fi
