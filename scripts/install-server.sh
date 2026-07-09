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
#   --dropbox       Force the Dropbox cold-tier prompt ON (needs a TTY to paste
#                   the secrets). --no-dropbox forces it OFF (no prompt).
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# 0. Resolve the repo root from this script's own location (scripts/ -> root).
# --------------------------------------------------------------------------- #
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: install-server.sh [--public [IP]] [--port N]

  --public [IP]   Make the server reachable from the internet. Binds 0.0.0.0 and
                  puts the public IP in the TLS certificate. If you omit IP it is
                  auto-detected and shown for you to confirm.
  --port N        Listen port (default 8443).
  --dropbox       Force the Dropbox cold-tier setup prompt ON. You must run in a
                  terminal (TTY) so the App key/secret/refresh token can be typed.
  --no-dropbox    Skip the Dropbox cold-tier prompt entirely.
  -h, --help      Show this help.
EOF
}

# --------------------------------------------------------------------------- #
# 1. Parse flags. Supports both `--flag value` and `--flag=value`.
# --------------------------------------------------------------------------- #
PUBLIC=0
PUBLIC_IP=""
PORT=8443
# Dropbox cold-tier: -1 = decide interactively (default), 1 = forced on, 0 = forced off.
DROPBOX_FORCE=-1

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
	--dropbox)
		DROPBOX_FORCE=1
		shift
		;;
	--no-dropbox)
		DROPBOX_FORCE=0
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
	echo "==> Dropbox cold-tier setup — paste the values from your Dropbox App Console."
	echo "    Secrets are NOT echoed; they are written only to $DROPBOX_ENV_PATH (root 0600)."

	printf 'Dropbox App key: '
	read -r DBX_APP_KEY || DBX_APP_KEY=""

	printf 'Dropbox App secret: '
	read -rs DBX_APP_SECRET || DBX_APP_SECRET=""
	printf '\n'

	printf 'Dropbox Refresh token: '
	read -rs DBX_REFRESH_TOKEN || DBX_REFRESH_TOKEN=""
	printf '\n'

	printf 'Dropbox Access token (optional, press Enter to skip): '
	read -rs DBX_ACCESS_TOKEN || DBX_ACCESS_TOKEN=""
	printf '\n'

	printf 'Dropbox root folder [/maxsecu]: '
	read -r DBX_ROOT || DBX_ROOT=""
	if [ -z "$DBX_ROOT" ]; then
		DBX_ROOT="/maxsecu"
	fi

	if [ -z "$DBX_APP_KEY" ] || [ -z "$DBX_APP_SECRET" ] || [ -z "$DBX_REFRESH_TOKEN" ]; then
		echo "warning: App key, App secret and Refresh token are all required." >&2
		echo "         One or more was blank — leaving the Dropbox cold tier OFF." >&2
		echo "         Nothing was written; re-run to try again." >&2
	else
		# Build the creds file in a private temp file (umask 077 so it is never
		# world/group-readable, even briefly), then install it root:root 0600.
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
# 14. Friendly summary. Never prints the DB password.
# --------------------------------------------------------------------------- #
if [ "$PUBLIC" -eq 1 ]; then
	PUBLIC_ADDRESS="$PUBLIC_IP:$PORT"
else
	PUBLIC_ADDRESS="127.0.0.1:$PORT (local-only — re-run with --public to expose it)"
fi

echo ""
echo "============================================================"
echo " MaxSecu server is installed and running."
echo "============================================================"
echo ""
echo " 1. PUBLIC ADDRESS to give your users (type this on the app's"
echo "    login / register screen):"
echo ""
echo "        $PUBLIC_ADDRESS"
echo ""
echo " 2. The client pins the app needs are here on this server:"
echo ""
echo "        $DATA_DIR/client-pins/server_cert.der"
echo "        $DATA_DIR/client-pins/directory_pub.der"
echo ""
echo " 3. NEXT STEP — on your Windows PC, in the repo folder, run:"
echo ""
echo "        powershell -ExecutionPolicy Bypass -File scripts\\install-client.ps1 -Vps $RUN_USER@${PUBLIC_IP:-<server-ip>}"
echo ""
echo "    That builds your app + the shareable ZIP and fetches the"
echo "    pins above for you automatically."
echo ""
echo " 4. To watch the server's live logs at any time:"
echo ""
echo "        journalctl -u maxsecu-server -f"
echo ""
echo "============================================================"

if [ "$DROPBOX_ENABLED_THIS_RUN" -eq 1 ]; then
	echo ""
	echo " Dropbox cold-tier offload: ENABLED (creds in $DROPBOX_ENV_PATH, root-only)."
elif [ ! -e "$DROPBOX_ENV_PATH" ]; then
	echo ""
	echo " Dropbox cold-tier offload is OFF. Re-run this script (or pass --dropbox)"
	echo " to enable it."
fi
