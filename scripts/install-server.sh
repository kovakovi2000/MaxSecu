#!/usr/bin/env bash
#
# install-server.sh — one-command MaxSecu server install for a FRESH Ubuntu 22.04 VPS.
#
# Written for someone with near-zero technical knowledge: SSH into the box once,
# `git clone` the repo, then run this.
#
# ***  THIS IS A FRESH-INSTALL TOOL. IT IS NOT RE-RUNNABLE ON A LIVE SERVER.  ***
#
# It used to advertise itself as idempotent. It is not, and the difference costs
# users their data: it REWRITES the systemd unit from this run's flags, and with
# --rotate-tls-identity it deletes the TLS cert — after which the server mints a
# BRAND-NEW identity and every already-installed client fails closed permanently,
# with no re-pin path and no admin escape hatch. So it now DETECTS an existing
# install (systemd unit, or <data_dir>/tls/cert.der, or a non-empty `users` table)
# and REFUSES, naming what to use instead:
#
#   * code update .................. sudo bash scripts/upgrade-server.sh
#   * configuration change ......... a systemd drop-in (the refusal prints the recipe)
#   * data backup / rollback ....... scripts/backup-server.sh, scripts/restore-server.sh
#   * start over from zero ......... this script's own --reset, then install again
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
#   --cold-tier-fs DIR
#                   Use the LOCAL filesystem as the cold tier (a credential-free
#                   model of Dropbox — it is what makes the sealed backup bundle
#                   have somewhere to live without a Dropbox account). Writes BOTH
#                   MAXSECU_COLD_TIER=fs and MAXSECU_COLD_FS_DIR=DIR into the unit.
#                   Mutually exclusive with --dropbox, and refused if a Dropbox
#                   creds file already exists (a box has exactly one cold tier).
#   --reset         Tear the server down to ZERO and exit (do NOT reinstall). See
#                   usage() below for exactly what it destroys.
#   --force-overwrite-existing-install
#                   Proceed even though an existing install was detected. Rewrites
#                   the systemd unit from THIS run's flags (port, bind, capacity,
#                   cold tier) — anything you set by hand or via a drop-in that this
#                   run does not re-specify is lost. It does NOT delete the TLS
#                   identity (see --rotate-tls-identity) and does NOT drop the
#                   database. The `maxsecu` role password is REUSED from the
#                   existing unit when one can be recovered and proven to work.
#                   It also does NOT relocate the data dir: if this run's data dir
#                   or run user disagrees with the installed unit, the run is
#                   REFUSED and this flag does not override that.
#                   WHAT IT CANNOT PROMISE IS THAT CLIENT TRUST SURVIVES. "Keeps
#                   the certificate" only means anything when a certificate is
#                   actually FOUND at the resolved data dir — if none is, the
#                   server mints a NEW identity and every pinned client is locked
#                   out. So a run that finds accounts in the database but NO
#                   certificate there is REFUSED outright too (no override): that
#                   combination means the data dir was not located. Without a
#                   systemd unit the data dir is a GUESS off $SUDO_USER/$HOME, so
#                   state MAXSECU_DATA_DIR explicitly on a unit-less box.
#   --rotate-tls-identity
#                   Delete <data_dir>/tls/{cert,key}.der + client-pins/ so the
#                   server mints a NEW self-signed certificate on next start. ONLY
#                   for a box whose public IP genuinely changed. EVERY existing
#                   client is locked out permanently and must be handed a rebuilt
#                   ZIP; there is no self-repair for a non-technical user.
#   --assume-no-database
#                   Carry on when the installer CANNOT READ the account database at
#                   all (PostgreSQL will not start / will not answer). It does not
#                   overwrite anything and it is not --force-overwrite-existing-
#                   install; it only says "I have checked, this machine holds no
#                   MaxSecu accounts". FORFEITS the check that refuses to mint a new
#                   server identity over a live deployment — if accounts do exist
#                   here, every client is locked out permanently. Meant for a
#                   dead-box rebuild where the cluster itself is gone.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# 0. Resolve the repo root from this script's own location (scripts/ -> root).
# --------------------------------------------------------------------------- #
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
	cat <<'EOF'
Usage: install-server.sh [--public [IP]] [--port N] [--capacity-gb N]
                         [--dropbox | --no-dropbox | --cold-tier-fs DIR]
                         [--force-overwrite-existing-install] [--rotate-tls-identity]
                         [--assume-no-database]
       install-server.sh --reset [--port N]

FRESH-INSTALL TOOL. On a box that already has a MaxSecu install (a systemd unit,
a TLS cert in the data dir, or a non-empty `users` table) this REFUSES and tells
you what to use instead — upgrade-server.sh for code, a systemd drop-in for
configuration, backup-/restore-server.sh for data.

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
  --cold-tier-fs DIR
                  Use the local filesystem at DIR as the cold tier (no Dropbox
                  account needed). Writes MAXSECU_COLD_TIER=fs + MAXSECU_COLD_FS_DIR
                  into the unit. Mutually exclusive with --dropbox; refused if a
                  Dropbox creds file already exists.
  --reset         Tear the server down to ZERO and exit (do NOT reinstall): stop +
                  remove the service, DROP the database + role (all accounts incl.
                  the recovery account), delete the data dir + TLS cert, remove the
                  saved Dropbox login, and close the firewall port. Idempotent and
                  safe on a never-installed box. The source folder is left in place.
                  It targets the data dir the INSTALLED UNIT declares, not a guess.
                  In a terminal it shows what is at stake and asks you to type
                  DESTROY; run from a script (no TTY) it proceeds as before, with no
                  extra flag. It refuses without destroying anything if PostgreSQL
                  cannot be reached on a box that has a cluster, and it reports what
                  actually survived instead of always claiming "back to zero".
  --force-overwrite-existing-install
                  Proceed even though an existing install was detected. The unit is
                  rewritten from THIS run's flags, so pass every flag the box was
                  installed with or you will silently change its configuration. It
                  does NOT delete the TLS identity, does NOT drop the database, and
                  REUSES the `maxsecu` role password recovered from the existing
                  unit whenever that password is proven to still work. It never
                  RELOCATES the data dir either: a data dir or run user that
                  disagrees with the installed unit is refused outright, and this
                  flag does not override that refusal.
                  It does NOT promise your clients keep working: the certificate is
                  only "kept" if one is FOUND at the resolved data dir, and if none
                  is the server mints a NEW identity that locks every pinned client
                  out permanently. Accounts in the database + no certificate there
                  is therefore ALSO refused outright (no override) — it means the
                  data dir was not located. With no systemd unit the data dir is
                  guessed from the account you are logged in as, so on a unit-less
                  box pass it: `sudo env MAXSECU_DATA_DIR=/actual/path bash ...`.
  --rotate-tls-identity
                  Delete the TLS cert + client pins so a NEW server identity is
                  minted on next start. ONLY for a box whose public IP genuinely
                  changed: it locks out EVERY existing client permanently — each
                  one needs a freshly built ZIP. Never needed to add Dropbox, a
                  cold tier, or to change the port.
  --assume-no-database
                  Only for a box whose PostgreSQL cannot be read at all. Before
                  installing, this script counts the accounts in the `maxsecu`
                  database so it can refuse to mint a new server identity over a
                  live deployment; if it cannot get an answer it stops. This flag
                  says "I have checked, this machine holds no MaxSecu accounts —
                  carry on anyway". IT FORFEITS THAT PROTECTION: if accounts really
                  are there, every installed client is locked out permanently and
                  needs a rebuilt ZIP. It is NOT a synonym for
                  --force-overwrite-existing-install and overwrites nothing by
                  itself. Use it on a dead-box rebuild where the database cluster
                  itself is gone; otherwise repair PostgreSQL first.
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
# --cold-tier-fs: 1 = use the local filesystem as the cold tier, with the directory
# in COLD_FS_DIR. Mutually exclusive with Dropbox (see the validation below step 1).
COLD_FS=0
COLD_FS_DIR=""
# --reset / --uninstall: tear everything down and exit instead of installing.
RESET=0
# --force-overwrite-existing-install: proceed past the EXISTING-INSTALL PREFLIGHT.
# Long and unambiguous on purpose — nobody types it by accident, and it reads like
# what it does in a shell-history or a runbook. It must start with '-' so the
# `--public` case below (which consumes ONE following non-flag token as the IP)
# cannot swallow it.
FORCE_OVERWRITE=0
# --rotate-tls-identity: the NARROW opt-in for deleting the TLS cert + client pins.
# Deliberately separate from --force-overwrite-existing-install: an operator adding
# Dropbox to a live box must NEVER get a new cert, while an operator whose VPS
# genuinely changed public IP DOES need one and accepts the re-pin. One flag cannot
# express both intents, so there are two.
ROTATE_TLS=0
# --assume-no-database: the NARROW opt-out for the account check in step 2b-pre,
# and nothing else. It is needed because that check now REFUSES when it cannot read
# the database at all, and a genuine dead-box rebuild (scripts/restore-server.sh
# routes operators into this script) can legitimately be "PostgreSQL package
# present, cluster destroyed" — which would otherwise be an unrecoverable exit with
# no way past it. Deliberately NOT a synonym for
# --force-overwrite-existing-install: that one says "overwrite what is here", this
# one says "I have checked, there are no MaxSecu accounts on this machine".
ASSUME_NO_DATABASE=0

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
	--cold-tier-fs=*)
		COLD_FS=1
		COLD_FS_DIR="${1#*=}"
		shift
		;;
	--cold-tier-fs)
		if [ $# -lt 2 ]; then
			echo "error: --cold-tier-fs needs a directory value" >&2
			exit 2
		fi
		COLD_FS=1
		COLD_FS_DIR="$2"
		shift 2
		;;
	--reset | --uninstall)
		RESET=1
		shift
		;;
	--force-overwrite-existing-install)
		FORCE_OVERWRITE=1
		shift
		;;
	--rotate-tls-identity)
		ROTATE_TLS=1
		shift
		;;
	--assume-no-database)
		ASSUME_NO_DATABASE=1
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

# The --public address ends up in TWO places that are hard to undo: verbatim in the
# unit as `Environment=MAXSECU_PUBLIC_ADDR=<value>`, and baked into the TLS
# certificate's SAN list on a fresh mint. This script validates --port, --capacity-gb
# and --cold-tier-fs; this value was the only one that reached both of those with no
# check at all, and the auto-detect below feeds it a raw HTTP body.
#
# DELIBERATELY PERMISSIVE — it rejects only what could never have produced a working
# deployment. crates/portable-server/src/pki.rs `san_for` puts an IP literal in an IP
# SAN and ANYTHING ELSE in a DNS SAN, so `--public my.host.name` is a supported,
# working shape and must keep working; so must a trailing dot, an uppercase name and
# an IPv6 literal. What is refused is an empty value, a leading '-' (that is a
# mistyped flag, not an address), and any character outside the IPv4/IPv6/DNS host
# charset — which is what stops a whitespace- or newline-carrying value from
# injecting extra lines into the [Service] section of the unit.
validate_public_addr() { # $1 = the address; prints why and returns 1 if unusable
	case "$1" in
	'')
		echo "error: --public was given an empty address." >&2
		return 1
		;;
	-*)
		echo "error: --public address must not start with '-' (got '$1'). That looks" >&2
		echo "       like a mistyped flag rather than an address." >&2
		return 1
		;;
	*[!A-Za-z0-9.:_-]*)
		echo "error: --public address contains a character that cannot appear in an" >&2
		echo "       IPv4/IPv6 literal or a DNS host name (got '$1')." >&2
		echo "       Allowed: letters, digits, '.', ':', '-' and '_'." >&2
		echo "       A value carrying a space or a newline would be written straight" >&2
		echo "       into the systemd unit and baked into the TLS certificate." >&2
		return 1
		;;
	esac
	return 0
}

# --------------------------------------------------------------------------- #
# IS THIS STRING A WELL-FORMED IPv6 LITERAL? Consumed by step 14a and nothing else.
#
#   WHY IT HAS TO EXIST. Step 14a asks `openssl x509 -checkip` whether the
#   certificate on disk covers the address this box will be reached on, because
#   that runs X509_check_ip_asc — the same byte comparison the TLS stack does, so
#   every textual form of one IPv6 address answers alike. But THE openssl x509 APP
#   PRINTS "does match certificate" FOR AN ADDRESS IT COULD NOT PARSE:
#   X509_check_ip_asc returns -2 on a parse failure and the app only tests
#   `ok ? "" : " NOT"`, so -2 reads as a match. Measured on openssl 3.2.4 against a
#   certificate carrying none of them, all five of
#       203.0.113.9:8443   vps.example.com:8443   2001:db8:::1
#       2001:db8::1:       2001:0db8::g1
#   printed "does match certificate". And validate_public_addr above deliberately
#   permits ':' anywhere (it must: a bare IPv6 literal is a supported --public
#   value), so a `host:port` typo reaches that call.
#
#   A FALSE "covered" IS WORSE THAN THE FALSE ALARM IT REPLACED. The false alarm
#   pointed a healthy install at a destructive README section; a false "covered"
#   prints "✓ TLS cert for <addr>" on the one run where the certificate really does
#   NOT cover the address, and every client then fails the pinned handshake with no
#   hint as to why. So a verdict of "covered" now needs BOTH halves: the address is
#   a well-formed IP literal AND openssl said it matched.
#
#   NO MORE PERMISSIVE THAN openssl's OWN PARSER — that direction is the dangerous
#   one, since anything accepted here and then rejected by a2i_IPADDRESS is exactly
#   the false "does match" again. Every form below was checked against a control
#   certificate that cannot contain it (a printed "does NOT match" proves openssl
#   parsed it): compressed / expanded / uppercase, '::', a trailing '::', and an
#   embedded IPv4 quad all parse and are accepted; 5-digit groups, ':::', a
#   trailing ':', a 9th group, a zone id and an octet > 255 all fail to parse and
#   are rejected. Being STRICTER only ever costs a "not-covered", never a wrong
#   "covered".
# --------------------------------------------------------------------------- #
_is_ipv4_octet() { # $1 -> 0 for 1..3 digits with a value <= 255
	case "$1" in
	'' | *[!0-9]* | ????*) return 1 ;;
	esac
	# bash's `test` parses base 10, so a leading zero is not read as octal.
	[ "$1" -le 255 ]
}

_is_ipv4_dotted_quad() { # $1 -> 0 for exactly A.B.C.D with every octet 0..255
	# The leading/trailing/doubled '.' cases are rejected HERE rather than left to
	# the octet walk below: `1.2.3.4.` walks as four good octets and an empty tail
	# the loop then breaks out of, so it used to be accepted — and openssl cannot
	# parse `1::1.2.3.4.`, which is precisely the false "does match" this whole
	# family of checks exists to stop.
	case "$1" in
	*[!0-9.]* | .* | *. | *..*) return 1 ;;
	esac
	_q_rest="$1"
	_q_n=0
	while :; do
		case "$_q_rest" in
		*.*)
			_q_oct="${_q_rest%%.*}"
			_q_rest="${_q_rest#*.}"
			;;
		*)
			_q_oct="$_q_rest"
			_q_rest=""
			;;
		esac
		_is_ipv4_octet "$_q_oct" || return 1
		_q_n=$((_q_n + 1))
		[ -n "$_q_rest" ] || break
	done
	[ "$_q_n" -eq 4 ]
}

# Counts the ':'-separated hex groups of $1 into $_v6_n; non-zero if any group is
# empty, over four digits, or not hex. An EMPTY argument is zero groups (that is
# the legal side of a leading or trailing '::').
_v6_count_groups() { # $1 = ':'-separated hex groups -> sets _v6_n
	_v6_n=0
	_v6_s="$1"
	[ -n "$_v6_s" ] || return 0
	case "$_v6_s" in
	:* | *:) return 1 ;; # an empty leading/trailing group
	esac
	while [ -n "$_v6_s" ]; do
		case "$_v6_s" in
		*:*)
			_v6_g="${_v6_s%%:*}"
			_v6_s="${_v6_s#*:}"
			;;
		*)
			_v6_g="$_v6_s"
			_v6_s=""
			;;
		esac
		case "$_v6_g" in
		'' | *[!0-9A-Fa-f]* | ?????*) return 1 ;;
		esac
		_v6_n=$((_v6_n + 1))
	done
	return 0
}

is_ipv6_literal() { # $1 -> 0 only for a well-formed IPv6 literal
	_v6="$1"
	case "$_v6" in
	*[!0-9A-Fa-f:.]*) return 1 ;; # hex digits, ':' and '.' only
	*:*) ;;                       # and it must actually carry a ':'
	*) return 1 ;;
	esac
	# A '.' may appear ONLY in a trailing embedded IPv4 quad (`::ffff:192.0.2.1`,
	# `0:0:0:0:0:ffff:192.0.2.1`). Swap that quad for the two hex groups it stands
	# for, so everything below is uniform.
	case "$_v6" in
	*.*)
		_v6_tailtext="${_v6##*:}"
		_v6_uptolast="${_v6%:*}"
		_is_ipv4_dotted_quad "$_v6_tailtext" || return 1
		case "$_v6_uptolast" in
		*.*) return 1 ;; # a dot anywhere but the final group
		esac
		_v6="$_v6_uptolast:0:0"
		;;
	esac
	case "$_v6" in
	*:::*) return 1 ;;
	esac
	case "$_v6" in
	*::*)
		_v6_a="${_v6%%::*}"
		_v6_b="${_v6#*::}"
		case "$_v6_b" in
		*::*) return 1 ;; # at most ONE '::'
		esac
		_v6_count_groups "$_v6_a" || return 1
		_v6_na="$_v6_n"
		_v6_count_groups "$_v6_b" || return 1
		# '::' stands for AT LEAST one all-zero group, so the written groups
		# can be at most seven.
		[ "$((_v6_na + _v6_n))" -le 7 ]
		;;
	*)
		_v6_count_groups "$_v6" || return 1
		[ "$_v6_n" -eq 8 ]
		;;
	esac
}

# Both --public flag forms land here. The auto-detect path (step 4) skips this — it
# has nothing to check yet — and validates its own result there.
if [ -n "$PUBLIC_IP" ]; then
	validate_public_addr "$PUBLIC_IP" || exit 2
fi

# --cold-tier-fs turns the LOCAL filesystem cold tier ON: it writes BOTH
# MAXSECU_COLD_TIER=fs and MAXSECU_COLD_FS_DIR=DIR into the unit (config.rs gates the
# whole fs branch on MAXSECU_COLD_TIER=fs, so the directory alone would leave the tier
# Off). It is MUTUALLY EXCLUSIVE with --dropbox: the unit loads the Dropbox creds file
# via `EnvironmentFile=` AFTER its `Environment=` lines, so a Dropbox
# MAXSECU_COLD_TIER=dropbox would silently override MAXSECU_COLD_TIER=fs — a box has
# exactly one cold tier. (The refusal on an EXISTING dropbox.env is done further down,
# once the root-capable run_root helper exists.)
if [ "$COLD_FS" -eq 1 ]; then
	if [ "$DROPBOX_FORCE" -eq 1 ]; then
		echo "error: --cold-tier-fs and --dropbox are mutually exclusive — a box has one" >&2
		echo "       cold tier. The Dropbox creds file is loaded AFTER the unit's" >&2
		echo "       Environment= lines and would override MAXSECU_COLD_TIER=fs." >&2
		exit 2
	fi
	if [ -z "$COLD_FS_DIR" ]; then
		echo "error: --cold-tier-fs needs a directory (got an empty value)." >&2
		exit 2
	fi
	case "$COLD_FS_DIR" in
	/*) ;;
	*)
		echo "error: --cold-tier-fs directory must be an ABSOLUTE path (got '$COLD_FS_DIR')." >&2
		exit 2
		;;
	esac
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
DROPIN_DIR="/etc/systemd/system/maxsecu-server.service.d"
# The drop-in scripts/upgrade-server.sh generates to reconcile an already-deployed
# unit's environment with the surface the build expects. This script writes a unit
# that carries the WHOLE surface explicitly, so that drop-in is redundant the
# moment we (re-)write the unit — and it must be REMOVED, not left behind: a
# drop-in is applied AFTER the base unit, so a stale one would override the
# freshly-chosen --port / --bind / --capacity-gb values.
ENV_DROPIN="$DROPIN_DIR/10-maxsecu-env.conf"

# --------------------------------------------------------------------------- #
# 2a. THE SERVER ENV SURFACE — the fresh-install half of the single source of
#     truth for every environment variable the server reads
#     (`MAXSECU_ENV_VARS` in crates/portable-server/src/config.rs).
#
#     Why this table exists: THIS script writes the systemd unit, including its
#     `Environment=` lines. scripts/upgrade-server.sh never rewrites that unit —
#     so a variable wired only here would reach FRESH INSTALLS ONLY, and every
#     already-deployed server would silently run without it, forever. The two
#     scripts must therefore always agree on the surface; upgrade-server.sh
#     carries the matching SERVER_ENV_RECONCILE table, and
#     crates/compat/tests/env_surface.rs FAILS THE BUILD if the code and the two
#     tables ever drift apart.
#
#     `<NAME>|<how it reaches the server>`:
#       unit      an `Environment=` line in the unit written in step 10 below.
#       unit-opt  an `Environment=` line written only when it applies (--public).
#       unit-fs   an `Environment=` line written only on a --cold-tier-fs install
#                 (the local, credential-free cold tier). Off / Dropbox installs
#                 never set it in the unit. See MAXSECU_COLD_FS_DIR below.
#       envfile   supplied by `EnvironmentFile=-/etc/maxsecu/dropbox.env`, the
#                 root-only 0600 creds file written in step 9b. NEVER an
#                 `Environment=` line: the unit is readable by anyone who can read
#                 /etc/systemd/system, and these are secrets.
#       default   deliberately NOT written; the compiled-in default is correct and
#                 self-consistent. Each one carries its reason below.
#
#     The `unit` / `unit-opt` rows are ENFORCED against the generated unit in step
#     10 (`assert_env_surface_written`), so this table cannot rot into a comment.
# --------------------------------------------------------------------------- #
SERVER_ENV_SURFACE='
DATABASE_URL|unit
MAXSECU_DATA_DIR|unit
MAXSECU_BIND|unit
MAXSECU_PORT|unit
MAXSECU_CACHE_CAPACITY_BYTES|unit
MAXSECU_OFFLOAD_IDLE_DAYS|unit
MAXSECU_DIRECT_LINKS|unit
MAXSECU_PUBLIC_ADDR|unit-opt
MAXSECU_COLD_TIER|envfile
MAXSECU_DROPBOX_APP_KEY|envfile
MAXSECU_DROPBOX_APP_SECRET|envfile
MAXSECU_DROPBOX_REFRESH_TOKEN|envfile
MAXSECU_DROPBOX_ACCESS_TOKEN|envfile
MAXSECU_DROPBOX_ROOT|envfile
MAXSECU_COLD_FS_DIR|unit-fs
'
# MAXSECU_COLD_FS_DIR|unit-fs — the directory for the LOCAL, credential-free `fs`
# cold tier. Written into the unit, together with `Environment=MAXSECU_COLD_TIER=fs`,
# ONLY when the operator passes --cold-tier-fs (which the server-backup design added
# so the sealed backup bundle has somewhere to live without a Dropbox account). On an
# `off` or `dropbox` install it is NOT written, and the binary derives it from
# MAXSECU_DATA_DIR (`<data_dir>/cold`). --cold-tier-fs is mutually exclusive with
# --dropbox and refuses to run if /etc/maxsecu/dropbox.env exists, because the unit
# loads that file AFTER its Environment= lines and it would override
# MAXSECU_COLD_TIER=fs.
#
# MAXSECU_COLD_TIER|envfile — its row STAYS `envfile` because on the Dropbox path it
# is supplied by the root-only 0600 EnvironmentFile (step 9b). The --cold-tier-fs path
# is the one exception that also writes it into the unit (`MAXSECU_COLD_TIER=fs`); that
# fs-path unit line is enforced by a dedicated check in step 10b rather than by the
# `envfile` row, so the row correctly documents its Dropbox-path home.

# The compiled-in defaults for the two knobs with no install flag. Written
# EXPLICITLY into the unit (rather than left to the binary) so that the unit is a
# complete, auditable statement of how this server is configured — and so that
# upgrade-server.sh has something to compare an existing unit against. Both values
# must stay IDENTICAL to crates/portable-server/src/config.rs, or a fresh install
# and an upgraded one stop being the same product.
OFFLOAD_IDLE_DAYS=30 # DEFAULT_OFFLOAD_IDLE_DAYS
DIRECT_LINKS=0       # direct_links_enabled: only "1"/"true" enable it — fail-closed

# Run a command string as root (directly if already root, else via sudo).
run_root() {
	if [ "$IS_ROOT" -eq 1 ]; then
		bash -c "$1"
	else
		sudo bash -c "$1"
	fi
}

# Is $1 the same directory as $2, or somewhere inside it?
#
#   A REAL BOUNDARY TEST, not a string prefix. `${cand#"$dir"}` says
#   /srv/maxsecu-data-cold is inside /srv/maxsecu-data — it is not, it is a SIBLING
#   whose name happens to start with the same characters. The one caller is the
#   --reset banner, where getting it wrong means the operator is NEVER TOLD that a
#   cold tier full of offloaded ciphertext (and any sealed backup bundle written
#   there) survived the wipe, because the banner only names a tier it believes is
#   outside the data directory.
path_is_within() { # $1 = candidate, $2 = directory -> 0 when $1 is $2 or under it
	_pw_c="${1%/}"
	_pw_d="${2%/}"
	if [ -z "$_pw_d" ]; then
		# "$2" was "/" — root contains everything — or empty, which contains
		# nothing.
		case "$2" in
		/*) return 0 ;;
		*) return 1 ;;
		esac
	fi
	# The quoted expansions are LITERAL inside a case pattern, so a data dir
	# carrying a glob character cannot widen the match; only the trailing /* is a
	# wildcard.
	case "$_pw_c" in
	"$_pw_d" | "$_pw_d"/*) return 0 ;;
	esac
	return 1
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
# THE THREE KNOBS EVERY SUPERUSER psql CALL BELOW SHARES.
#
#   PG_PORT_OPT — WHICH CLUSTER. Every one of these helpers talks to the postgres
#   superuser over the LOCAL UNIX SOCKET (that is what makes peer auth work, and
#   why none of them ever carried a `-h`), but the socket is named after the PORT:
#   /var/run/postgresql/.s.PGSQL.<port>. With no `-p` libpq looks for 5432 — so on
#   a box whose cluster listens ANYWHERE ELSE the probe finds nothing and the
#   install refuses on a perfectly healthy machine. That is not exotic: it is what
#   `apt-get install postgresql-NN` does whenever a cluster already occupies 5432
#   (the new one lands on 5433). Step 2b-0c below fills this in from the installed
#   unit's DATABASE_URL, else from pg_lsclusters, and leaves it EMPTY on a
#   brand-new box — where empty means byte-for-byte today's behaviour.
#
#   PG_PROBE_TIMEOUT / PG_TIMEOUT_CMD — HOW LONG ONE PROBE MAY BLOCK. A readiness
#   loop that counts iterations is not bounded at all if one iteration can hang
#   forever, and these probes run on the FRESH-INSTALL path. Both belts are worn:
#   PGCONNECT_TIMEOUT caps libpq's connect, and `timeout` caps the whole command
#   (including a `su - postgres` that never returns). `timeout` is coreutils and is
#   present on every supported box, but its absence must not be fatal — hence the
#   `command -v` guard rather than a hard dependency.
#
#   PG_WAIT_SECS — the wall-clock budget the two readiness loops spend waiting.
# --------------------------------------------------------------------------- #
PG_PORT_OPT=""
PG_PROBE_TIMEOUT=10
PG_WAIT_SECS=30
PG_TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
	PG_TIMEOUT_CMD="timeout $PG_PROBE_TIMEOUT"
fi

# Run a psql query as the postgres superuser and print the result (for guards).
psql_super_query() {
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "psql $PG_PORT_OPT -tAc \"$1\""
	else
		sudo -u postgres psql $PG_PORT_OPT -tAc "$1"
	fi
}

# Feed SQL on stdin to psql as the postgres superuser (keeps secrets off argv).
psql_super_stdin() {
	if [ "$IS_ROOT" -eq 1 ]; then
		su - postgres -c "psql $PG_PORT_OPT -v ON_ERROR_STOP=1"
	else
		sudo -u postgres psql $PG_PORT_OPT -v ON_ERROR_STOP=1
	fi
}

# Run a scalar query against the `maxsecu` DATABASE as the postgres superuser,
# swallowing every failure (no Postgres yet, no such database, no such table) —
# callers treat "no answer" as "not an existing install".
#
# `cd /tmp` IS NOT COSMETIC. `sudo -u postgres` cannot enter a directory the
# postgres account has no access to, and the repo root is 0700 root:root on a
# standard install. Without the cd, EVERY query fails with "could not change
# directory to ..." while still returning a plausible-looking empty string — a
# detector that always answers "fresh box". That exact bug already cost this
# project a full lap; the idiom is copied verbatim from scripts/fingerprint.sh.
psql_maxsecu_query() {
	if [ "$IS_ROOT" -eq 1 ]; then
		(cd /tmp && su - postgres -c "psql $PG_PORT_OPT -d maxsecu -tAc \"$1\"" 2>/dev/null) || true
	else
		(cd /tmp && sudo -u postgres psql $PG_PORT_OPT -d maxsecu -tAc "$1" 2>/dev/null) || true
	fi
}

# THE SIBLINGS THAT DO NOT SWALLOW. psql_maxsecu_query above answers "" for BOTH
# "the table is empty" and "Postgres would not talk to me", and every caller then
# reads that as "not an existing install" — a detector that fails OPEN on exactly
# the box it exists to protect. These two carry the identical `cd /tmp` guard (read
# its paragraph above; without it EVERY query fails on the `su - postgres` path,
# which already cost this project a full lap) but RETURN psql's exit status, so the
# preflight can tell "zero accounts" apart from "could not ask".
#
# `set -o pipefail` (top of file) is what lets a caller write
# `if v="$(pg_probe db sql | tr -d '[:space:]')"` and still see psql's failure.
#
# BOUNDED IN WALL-CLOCK TIME, like pg_connect_diag below: these are read-only
# preflight probes on the fresh-install path, and a probe that blocks forever is a
# fresh install that hangs forever with no output.
pg_probe() { # $1 = database, $2 = SQL -> scalar on stdout, psql's exit status
	if [ "$IS_ROOT" -eq 1 ]; then
		(cd /tmp && $PG_TIMEOUT_CMD su - postgres -c "PGCONNECT_TIMEOUT=$PG_PROBE_TIMEOUT psql $PG_PORT_OPT -d '$1' -tAc \"$2\"" 2>/dev/null)
	else
		(cd /tmp && $PG_TIMEOUT_CMD sudo -u postgres env PGCONNECT_TIMEOUT="$PG_PROBE_TIMEOUT" psql $PG_PORT_OPT -d "$1" -tAc "$2" 2>/dev/null)
	fi
}

# The first rung of the ladder: can we talk to this cluster AT ALL? Keeps psql's
# DIAGNOSTIC on stdout instead of discarding it, because "could not connect" and
# "authentication failed" have completely different remedies and the refusal
# promises to name which one happened. The value is never used, only the status.
#
# THIS IS THE CALL THE TWO READINESS LOOPS SPIN ON, so it carries its own
# wall-clock cap. Without one, "30 iterations" bounds nothing: a single blocked
# connect (a half-open socket, a stalled /var/run/postgresql, a `su` that hangs)
# wedges a fresh install for as long as the kernel is willing to wait. See the
# PG_PROBE_TIMEOUT paragraph above.
pg_connect_diag() { # -> psql's stderr text on stdout, psql's exit status
	if [ "$IS_ROOT" -eq 1 ]; then
		(cd /tmp && $PG_TIMEOUT_CMD su - postgres -c "PGCONNECT_TIMEOUT=$PG_PROBE_TIMEOUT psql $PG_PORT_OPT -d postgres -tAc 'SELECT 1'" 2>&1 >/dev/null)
	else
		(cd /tmp && $PG_TIMEOUT_CMD sudo -u postgres env PGCONNECT_TIMEOUT="$PG_PROBE_TIMEOUT" psql $PG_PORT_OPT -d postgres -tAc 'SELECT 1' 2>&1 >/dev/null)
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
# backup, and a failed backup aborts the upgrade that depends on it. HERE it decides
# whether step 7 can REUSE the existing database password or must rotate it, so a
# false "unset" rotates the credential of a live database for no reason.
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

# --------------------------------------------------------------------------- #
# 2b-0. RECONCILE THIS RUN'S IDENTITY WITH THE INSTALLED UNIT — before anything
#        reads $DATA_DIR.
#
#   UNTIL HERE, RUN_USER AND DATA_DIR ARE GUESSES. RUN_USER is
#   `${SUDO_USER:-$USER}` and DATA_DIR is `$RUN_HOME/maxsecu-server-data` (step 2
#   above). Both are wrong the moment the same box is touched from a different
#   account: `sudo bash scripts/install-server.sh` run by `ubuntu` guesses
#   /home/ubuntu/maxsecu-server-data, while a later run from a root shell reached
#   by `su -` has NO SUDO_USER and guesses /root/maxsecu-server-data.
#
#   WHY THAT IS A CATASTROPHE, NOT A COSMETIC BUG. Every probe below reads
#   $DATA_DIR — the preflight's TLS-cert signal, and the TLS gate in step 9. A
#   wrong guess makes both report "no certificate here", so a
#   --force-overwrite-existing-install run prints "the TLS cert + client pins are
#   KEPT", then computes HAVE_TLS_CERT=0 from the same wrong path, writes a unit
#   whose MAXSECU_DATA_DIR points at the NEW, EMPTY directory — and the server
#   MINTS A NEW TLS IDENTITY there on first start. Every pinned client is locked
#   out permanently and every uploaded blob is orphaned in the old directory.
#   That is precisely the outcome the preflight exists to prevent, reached through
#   the very flag the preflight recommends.
#
#   THE INSTALLED UNIT IS THE TRUTH — it is what systemd actually starts the
#   server with. So it is read and ADOPTED here, exactly as the four sibling
#   scripts do (scripts/upgrade-server.sh, scripts/backup-server.sh,
#   scripts/restore-server.sh, scripts/fingerprint.sh all reconcile their data dir
#   against `resolve_unit_env MAXSECU_DATA_DIR`). This script was the only one
#   that still guessed, and the only one that WRITES the value back into the unit.
#
#   AND THEN IT REFUSES ON DISAGREEMENT (step 2b-post, below the preflight). An
#   install that silently RELOCATES a live server's data dir must not be reachable
#   from a flag whose own message promises the certificate is kept — so a
#   disagreement is fatal even with --force-overwrite-existing-install, and there
#   is deliberately NO override (see that block for why --rotate-tls-identity is
#   not one either).
#
#   PLACEMENT. Before the banner, the preflight AND the `--reset` early exit (step
#   2b-1, immediately below), so all three see the corrected values. `--reset` used
#   to run ABOVE this block and tore down whatever the step-2 GUESS happened to
#   name; it is now the first consumer of the adoption. A DEAD BOX (no unit) has
#   nothing to adopt and nothing to disagree with, so a rebuild driven by
#   scripts/restore-server.sh passes straight through — that path really is a
#   fresh install.
# --------------------------------------------------------------------------- #

# A plain systemd DIRECTIVE (`User=`, `WorkingDirectory=`) from the unit + its
# drop-ins, read as root (the unit is 0600), last assignment winning — the same
# merge rule resolve_unit_env applies to `Environment=` lines. Deliberately NOT
# folded into resolve_unit_env: that function is one of FIVE byte-identical copies
# (see its header), and this script must not be the one that makes them diverge.
resolve_unit_directive() { # $1 = directive name -> its effective value, or empty
	run_root "cat '$UNIT_PATH' '$DROPIN_DIR'/*.conf 2>/dev/null || cat '$UNIT_PATH' 2>/dev/null || true" </dev/null |
		tr -d '\r' |
		sed -n "s/^[[:space:]]*$1=[\"']\\{0,1\\}//p" |
		sed -e "s/[\"']\$//" -e '/^$/d' |
		tail -n1
}

# What this run computed on its own, kept verbatim so the refusal can name BOTH
# values rather than just the one it ended up with.
COMPUTED_RUN_USER="$RUN_USER"
COMPUTED_DATA_DIR="$DATA_DIR"
UNIT_RUN_USER=""
UNIT_DATA_DIR=""
IDENTITY_MISMATCH=""

if run_root "test -f '$UNIT_PATH'"; then
	UNIT_RUN_USER="$(resolve_unit_directive User)"
	UNIT_DATA_DIR="$(resolve_unit_env MAXSECU_DATA_DIR)"
	if [ -z "$UNIT_DATA_DIR" ]; then
		# A unit with no MAXSECU_DATA_DIR line: the binary resolves the data dir
		# RELATIVE TO ITS WorkingDirectory (`./maxsecu-server-data` —
		# crates/portable-server/src/config.rs), so read that rather than guess a
		# home directory. Same fallback the sibling scripts use.
		_unit_wd="$(resolve_unit_directive WorkingDirectory)"
		if [ -n "$_unit_wd" ]; then
			UNIT_DATA_DIR="${_unit_wd%/}/maxsecu-server-data"
		fi
	fi

	# The run user first: RUN_HOME (and therefore the guessed DATA_DIR and the
	# cargo env path) hangs off it.
	if [ -n "$UNIT_RUN_USER" ] && [ "$UNIT_RUN_USER" != "$RUN_USER" ]; then
		IDENTITY_MISMATCH="$IDENTITY_MISMATCH
    * run user : this run computed  $COMPUTED_RUN_USER
                 the installed unit says  $UNIT_RUN_USER   <- what the server runs as"
		RUN_USER="$UNIT_RUN_USER"
		# `|| true` is load-bearing: this name comes from the UNIT, so it can be an
		# account that no longer exists, and `getent` then exits 2 — which under the
		# script's `set -o pipefail` + `set -e` would abort the whole run with no
		# message at all. An empty answer simply leaves RUN_HOME as computed.
		_unit_home="$(getent passwd "$RUN_USER" 2>/dev/null | cut -d: -f6 || true)"
		if [ -n "$_unit_home" ]; then
			RUN_HOME="$_unit_home"
			CARGO_ENV="$RUN_HOME/.cargo/env"
		fi
	fi

	if [ -n "$UNIT_DATA_DIR" ]; then
		if [ "$UNIT_DATA_DIR" != "$DATA_DIR" ]; then
			IDENTITY_MISMATCH="$IDENTITY_MISMATCH
    * data dir : this run computed  $COMPUTED_DATA_DIR
                 the installed unit says  $UNIT_DATA_DIR   <- where the cert and blobs are"
		fi
		# Adopt regardless: every probe below must look where the server actually
		# looks, even on the paths that go on to refuse.
		DATA_DIR="$UNIT_DATA_DIR"
	fi

	if [ -n "$IDENTITY_MISMATCH" ]; then
		echo "==> Reconciled with the installed unit $UNIT_PATH:$IDENTITY_MISMATCH"
	fi
fi

# --------------------------------------------------------------------------- #
# 2b-0c. WHICH POSTGRES CLUSTER DO THE SUPERUSER PROBES TALK TO?
#
#   THE FIELD FAILURE THIS CLOSES. Every superuser probe in this file goes over the
#   local unix socket, and that socket is named after the PORT
#   (/var/run/postgresql/.s.PGSQL.5432). With no `-p`, a box whose cluster listens
#   anywhere else answers NOTHING — and the preflight then either refuses an
#   entirely healthy machine ("the account database could not be read") or, worse,
#   asks a DIFFERENT cluster than the one the server will use. A non-default port
#   is not an exotic configuration: `apt-get install postgresql-NN` puts the new
#   cluster on 5433 whenever 5432 is already taken by an existing one, which is the
#   ordinary shape of a shared VPS.
#
#   IN PRIORITY ORDER, AND NEVER A GUESS:
#     1. the INSTALLED UNIT's DATABASE_URL — that is what systemd actually starts
#        the server with, so it cannot disagree with reality. Only honoured when
#        its host is local: a unit pointing at a remote database says nothing about
#        which LOCAL socket the superuser probes should use.
#     2. pg_lsclusters, and only when it lists EXACTLY ONE port. Two clusters and
#        no unit is genuinely ambiguous — guessing there is how you create the role
#        on one cluster and load the schema into the other — so it falls through.
#     3. nothing. PG_PORT_OPT stays empty and every helper behaves byte-for-byte as
#        it did before this block existed. THIS IS THE BRAND-NEW BOX: no unit, no
#        pg_lsclusters (it ships in postgresql-common, which is not installed yet),
#        so a genuine fresh install is untouched by all of the above.
#   Step 7a re-runs this once PostgreSQL is actually installed, and derives the
#   TCP host/port it hands the server from the same answer, so both halves of the
#   install always land on the same cluster.
# --------------------------------------------------------------------------- #
PG_SUPER_PORT=""

pg_discover_super_port() { # sets PG_SUPER_PORT + PG_PORT_OPT; no-op once found
	if [ -n "$PG_SUPER_PORT" ]; then
		return 0
	fi
	_pgd_url="$(resolve_unit_env DATABASE_URL)"
	if [ -n "$_pgd_url" ]; then
		_pgd_hp="${_pgd_url#*://}"
		_pgd_hp="${_pgd_hp#*@}"
		_pgd_hp="${_pgd_hp%%/*}"
		_pgd_h="${_pgd_hp%%:*}"
		_pgd_p="${_pgd_hp#*:}"
		if [ "$_pgd_p" = "$_pgd_hp" ]; then
			_pgd_p=""
		fi
		case "$_pgd_h" in
		127.0.0.1 | localhost | ::1 | '[::1]' | '')
			# A local host with NO explicit port means 5432 — that is what the
			# server's own client does with such a URL, and step 7a parses it the
			# same way. Taking it here rather than falling through to
			# pg_lsclusters is what stops the socket probes and the TCP URL from
			# disagreeing on a box that has a second cluster.
			case "$_pgd_p" in
			'') PG_SUPER_PORT=5432 ;;
			*[!0-9]*) ;;
			*) PG_SUPER_PORT="$_pgd_p" ;;
			esac
			;;
		esac
		unset _pgd_hp _pgd_h _pgd_p
	fi
	unset _pgd_url
	if [ -z "$PG_SUPER_PORT" ]; then
		_pgd_ports="$(run_root "command -v pg_lsclusters >/dev/null 2>&1 && pg_lsclusters -h 2>/dev/null | awk '{print \$3}' | grep -E '^[0-9]+\$' | sort -u" </dev/null 2>/dev/null || true)"
		if [ -n "$_pgd_ports" ] && [ "$(printf '%s\n' "$_pgd_ports" | wc -l)" -eq 1 ]; then
			PG_SUPER_PORT="$_pgd_ports"
		fi
		unset _pgd_ports
	fi
	if [ -n "$PG_SUPER_PORT" ]; then
		PG_PORT_OPT="-p $PG_SUPER_PORT"
	fi
	return 0
}

pg_discover_super_port

# --------------------------------------------------------------------------- #
# 2b-1. FULL TEARDOWN (--reset). Removes ALL server state so the next install is
#       truly from zero, then EXITS. Every step is guarded / idempotent, so this
#       is safe to run twice, or on a box where MaxSecu was never installed (it
#       just reports "nothing to do" for each already-absent piece). The one
#       thing it never touches is the source checkout it is running from.
#
#   WHY IT NO LONGER RUNS ABOVE 2b-0. It used to be the very first block after
#   flag parsing, so $DATA_DIR was still the step-2 GUESS
#   (`${MAXSECU_DATA_DIR:-$RUN_HOME/maxsecu-server-data}`). A reset run from a root
#   shell entered with `su -` (no SUDO_USER) on a box installed as `ubuntu`
#   therefore DROPped the database, deleted the unit — and left the REAL data
#   directory, with tls/cert.der, tls/key.der and every uploaded blob, completely
#   untouched, under a banner that said "This machine is back to zero". The next
#   install then saw none of the three existing-install signals, minted a SECOND
#   identity beside the orphaned one, and every pinned client was locked out. Below
#   2b-0, $DATA_DIR is what the UNIT declares — what systemd actually starts the
#   server with — so the teardown aims at the real box.
#
#   THE UNIT DIES LAST, NOT FIRST — AND ONLY IF THE DROP IS PROVEN. It is the only
#   durable copy of the database password (step 10 writes
#   `Environment=DATABASE_URL=...` and nothing else stores it). Deleting it before
#   the DROP is what turned a half-failed teardown into a live database holding
#   real accounts that nobody could log into. So: DROP first; then RE-PROBE for the
#   database and the role, and remove the unit only when both are provably gone.
#   Once the database really is gone the unit's credential is worthless and
#   removing it costs nothing. Every DROP statement here is error-swallowed — it
#   has to be, since "already gone" and "cannot drop" both come back non-zero — so
#   an exit status proves nothing; the RE-PROBE is what makes "if the DROP fails
#   the unit is still there and the box is repairable" an enforced guarantee
#   instead of a hope.
#
#   IT REFUSES RATHER THAN HALF-DESTROY. If PostgreSQL cannot be reached AND this
#   box has a cluster, nothing is destroyed at all — that combination (database
#   alive, data dir and unit gone) is exactly what makes the NEXT install refuse
#   with no override. On a box with no cluster there is nothing to drop, so it
#   passes straight through and still exits 0: `--reset` on a never-installed box
#   must keep working, unattended, with no new flag (scripts/lib/wsl-harness.ps1
#   runs it and dies on any non-zero exit).
#
#   AND IT REPORTS WHAT IT ACTUALLY DID. The closing banner is computed from
#   post-hoc probes; "back to zero" is printed only when it is true.
# --------------------------------------------------------------------------- #
if [ "$RESET" -eq 1 ]; then
	DROPBOX_ENV_DIR="/etc/maxsecu"

	# Everything the teardown needs to know, read from the unit BEFORE anything is
	# removed — the unit is about to be deleted, and it is the only place these
	# values exist. `resolve_unit_env` is the shared five-copy parser (it merges the
	# drop-ins); this run's own --port stays the fallback for a unit-less box.
	RESET_PORT="$(resolve_unit_env MAXSECU_PORT)"
	case "$RESET_PORT" in
	'' | *[!0-9]*) RESET_PORT="$PORT" ;;
	esac
	RESET_COLD_TIER="$(resolve_unit_env MAXSECU_COLD_TIER)"
	RESET_COLD_DIR="$(resolve_unit_env MAXSECU_COLD_FS_DIR)"
	if [ -z "$RESET_COLD_DIR" ]; then
		# crates/portable-server/src/config.rs defaults the fs tier to
		# <data_dir>/cold, which the data-dir removal below already covers.
		RESET_COLD_DIR="$DATA_DIR/cold"
	fi

	# CAN WE ACTUALLY TALK TO POSTGRESQL? `systemctl is-active postgresql` — what
	# this block used to ask — answers a different question: the unit can be active
	# while the cluster refuses connections, and a cluster can be reachable on a box
	# where that unit name does not exist.
	RESET_PG_OK=0
	RESET_PG_CLUSTER=0
	PG_STARTED_BY_RESET=0
	RESET_PG_DIAG=""
	if RESET_PG_DIAG="$(pg_connect_diag)"; then
		RESET_PG_OK=1
	fi
	if [ "$RESET_PG_OK" -eq 0 ]; then
		# Is there anything to drop at all? The same NARROW cluster evidence step
		# 2b-pre0 uses — deliberately not `command -v psql` (the postgresql-client
		# package alone satisfies it), not `getent passwd postgres` (that account
		# survives an apt-get purge), and not a bare `systemctl cat
		# postgresql.service` (that unit ships in postgresql-common, so it is there
		# on a box with the cluster TOOLING and no cluster) — any of those would turn
		# "nothing to reset" into a hard failure. Repeated here rather than shared
		# because 2b-pre0 runs below this early exit; the three arms must stay
		# IDENTICAL to it.
		if run_root "systemctl cat postgresql.service >/dev/null 2>&1 && { ls -d /etc/postgresql/*/*/postgresql.conf >/dev/null 2>&1 || [ -n \"\$(systemctl list-units --all --no-legend 'postgresql@*.service' 2>/dev/null)\" ]; }"; then
			RESET_PG_CLUSTER=1
		elif run_root "ls -d /var/lib/postgresql/*/main >/dev/null 2>&1"; then
			RESET_PG_CLUSTER=1
		elif run_root "command -v pg_lsclusters >/dev/null 2>&1 && [ -n \"\$(pg_lsclusters -h 2>/dev/null)\" ]"; then
			RESET_PG_CLUSTER=1
		fi
		if [ "$RESET_PG_CLUSTER" -eq 1 ]; then
			echo "==> PostgreSQL is installed but not answering — starting it so the"
			echo "    'maxsecu' database and role can actually be dropped."
			echo "    (systemctl start, NOT enable: what starts at boot is left as it is.)"
			# Same rule as 2b-pre0: only record a start that actually succeeded, so
			# the refusal below cannot claim this run started a service it did not.
			if run_root "systemctl start postgresql >/dev/null 2>&1"; then
				PG_STARTED_BY_RESET=1
			else
				echo "    (the start command itself FAILED — probing anyway)"
			fi
			# Wall-clock bound, not an iteration count — see 2b-pre0's copy of this
			# loop for why a count is not a timeout.
			_reset_deadline="$(($(date +%s) + PG_WAIT_SECS))"
			while [ "$(date +%s)" -lt "$_reset_deadline" ]; do
				if RESET_PG_DIAG="$(pg_connect_diag)"; then
					RESET_PG_OK=1
					break
				fi
				sleep 1
			done
			unset _reset_deadline
		fi
	fi

	if [ "$RESET_PG_OK" -eq 0 ] && [ "$RESET_PG_CLUSTER" -eq 1 ]; then
		echo "" >&2
		echo "============================================================" >&2
		echo " REFUSING: --reset cannot reach PostgreSQL, and this box HAS a cluster." >&2
		echo "============================================================" >&2
		echo "" >&2
		# Same rule as the four refusals further down: claim the start only when it
		# actually happened. `systemctl start` can fail outright (masked unit, no
		# cluster behind the wrapper), and this line then described an action that
		# never took place.
		if [ "$PG_STARTED_BY_RESET" -eq 1 ]; then
			echo " PostgreSQL was started by this check and left running, but it still does" >&2
			echo " not answer. What it said:" >&2
		else
			echo " PostgreSQL could not be started by this check either. What it said:" >&2
		fi
		echo "" >&2
		echo "     ${RESET_PG_DIAG:-(no diagnostic)}" >&2
		echo "" >&2
		echo " NOTHING HAS BEEN DESTROYED. Carrying on would delete the data directory" >&2
		echo " and the systemd unit while the 'maxsecu' database and role — and every" >&2
		echo " account in them — survived. The unit is the ONLY durable copy of that" >&2
		echo " database's password, so that combination leaves a live database nobody" >&2
		echo " can log into, and the NEXT install-server.sh refuses outright (accounts" >&2
		echo " present, no TLS certificate) with no override flag." >&2
		echo "" >&2
		echo " FIX POSTGRESQL FIRST, then re-run this exact command:" >&2
		echo "" >&2
		echo "        sudo systemctl status postgresql" >&2
		echo "        sudo journalctl -u postgresql -e" >&2
		echo "" >&2
		echo " If the cluster is genuinely gone for good and you accept losing every" >&2
		echo " account it held, remove it and re-run --reset:" >&2
		echo "" >&2
		echo "        sudo apt-get purge -y postgresql postgresql-*" >&2
		echo "        sudo bash $0 --reset --port $RESET_PORT" >&2
		echo "============================================================" >&2
		exit 1
	fi

	# How much is at stake, in plain numbers, BEFORE the confirmation.
	if [ "$RESET_PG_OK" -eq 1 ]; then
		RESET_USERS="none — there is no 'maxsecu' database on this box"
		if _reset_db="$(pg_probe postgres "SELECT 1 FROM pg_database WHERE datname='maxsecu'" | tr -d '[:space:]')" &&
			[ "$_reset_db" = "1" ]; then
			RESET_USERS="UNKNOWN — the 'maxsecu' database is there but would not answer"
			if _reset_n="$(pg_probe maxsecu "SELECT count(*) FROM users" | tr -d '[:space:]')"; then
				case "$_reset_n" in
				'' | *[!0-9]*) ;;
				*) RESET_USERS="$_reset_n user account(s), including the recovery account" ;;
				esac
			fi
		fi
	else
		RESET_USERS="none — this box has no PostgreSQL cluster"
	fi

	echo "==> MaxSecu server RESET — removing ALL server state (no reinstall)"
	echo "    run as    : $RUN_USER"
	echo "    data dir  : $DATA_DIR"
	if [ "$DATA_DIR" != "$COMPUTED_DATA_DIR" ]; then
		echo "                (read from $UNIT_PATH — NOT this run's guess,"
		echo "                 which was $COMPUTED_DATA_DIR)"
	fi
	echo "    db        : maxsecu (role + database)"
	echo "    accounts  : $RESET_USERS"
	echo "    firewall  : ${RESET_PORT}/tcp"
	echo ""

	# THE CONFIRMATION IS TTY-GATED, and there is deliberately NO new flag for the
	# unattended path: scripts/lib/wsl-harness.ps1, the README and
	# docs/runbooks/prod-upgrade.md all invoke `--reset` with no keyboard attached
	# and must keep working exactly as before. `DESTROY` rather than `y` on purpose —
	# a reflex `y` is what this class of button gets.
	if [ -t 0 ]; then
		echo "    THIS DESTROYS EVERY ACCOUNT, EVERY KEY AND EVERY UPLOAD ON THIS BOX,"
		echo "    including the server's TLS identity. There is no admin escape hatch:"
		echo "    every client that pinned this server is locked out for good, and none"
		echo "    of it comes back without a sealed backup bundle."
		echo ""
		printf '    Type DESTROY (capitals) to go ahead, anything else to abort: '
		read -r reply || reply=""
		if [ "$reply" != "DESTROY" ]; then
			echo ""
			echo "==> Aborted. NOTHING was destroyed."
			if [ "$PG_STARTED_BY_RESET" -eq 1 ]; then
				echo "    (PostgreSQL was started by this check and has been left running;"
				echo "     what starts at boot was not changed.)"
			fi
			exit 1
		fi
		echo ""
	else
		echo "==> Non-interactive run (no TTY): proceeding without the DESTROY prompt."
	fi

	# 1. Stop + disable the service so nothing restarts mid-wipe. The UNIT FILE
	#    itself survives until step 4 — see the header.
	echo "==> Stopping and disabling the systemd service"
	run_root "systemctl disable --now maxsecu-server 2>/dev/null || true"

	# 2. Drop the database (all accounts incl. the singleton recovery account) and
	#    the login role. WITH (FORCE) evicts any lingering connections (PG13+); if
	#    the local Postgres is older it falls back to a plain DROP DATABASE.
	#
	#    AND THEN PROVE IT — see the header. A DROP can fail with the cluster
	#    perfectly reachable (lingering connections after a failed WITH (FORCE) on
	#    PG<13, the role still owning objects in another database, a permission
	#    error), and every statement below swallows its status, so nothing here
	#    would have noticed. RESET_DROP_OK is PROBED afterwards, never inferred: it
	#    is what decides whether the unit — the only durable copy of this database's
	#    password — may be deleted. "Could not ask" counts as NOT proven; a guess is
	#    not worth the one artefact that makes the box repairable.
	RESET_DROP_OK=1
	if [ "$RESET_PG_OK" -eq 1 ]; then
		echo "==> Dropping the 'maxsecu' database and role"
		printf 'DROP DATABASE IF EXISTS maxsecu WITH (FORCE);\n' | psql_super_stdin >/dev/null 2>&1 ||
			printf 'DROP DATABASE IF EXISTS maxsecu;\n' | psql_super_stdin >/dev/null 2>&1 || true
		printf 'DROP ROLE IF EXISTS maxsecu;\n' | psql_super_stdin >/dev/null 2>&1 || true

		if _drop_db="$(pg_probe postgres "SELECT 1 FROM pg_database WHERE datname='maxsecu'" | tr -d '[:space:]')"; then
			if [ "$_drop_db" = "1" ]; then
				RESET_DROP_OK=0
				echo "    the 'maxsecu' DATABASE is STILL THERE after the DROP" >&2
			fi
		else
			RESET_DROP_OK=0
			echo "    could not confirm the 'maxsecu' database was dropped" >&2
		fi
		if _drop_role="$(pg_probe postgres "SELECT 1 FROM pg_roles WHERE rolname='maxsecu'" | tr -d '[:space:]')"; then
			if [ "$_drop_role" = "1" ]; then
				RESET_DROP_OK=0
				echo "    the 'maxsecu' ROLE is STILL THERE after the DROP" >&2
			fi
		else
			RESET_DROP_OK=0
			echo "    could not confirm the 'maxsecu' role was dropped" >&2
		fi
		unset _drop_db _drop_role
	else
		echo "==> No PostgreSQL cluster on this box — there is no MaxSecu database to drop"
	fi

	# 3. Remove the data dir (TLS cert, client pins, blob store, recovery state).
	echo "==> Removing the data directory $DATA_DIR"
	run_as_user "rm -rf '$DATA_DIR'" 2>/dev/null || run_root "rm -rf '$DATA_DIR'"

	# 4. NOW the systemd unit and its drop-ins — AND ONLY IF STEP 2 IS PROVEN. A
	#    drop-in is applied AFTER the base unit, so anything left behind here (the
	#    capacity drop-in, the env-reconcile drop-in) would silently override the
	#    next install's freshly-chosen values — a "reset" that quietly kept the old
	#    configuration is not a reset.
	#
	#    While a 'maxsecu' database or role is still standing, though, deleting the
	#    unit is the single worst thing this script can do: it is the ONLY durable
	#    copy of that database's password, so the box would be left holding a live
	#    database, with every account still in it, that nobody can ever log into.
	#    Keeping it costs nothing — the next install-server.sh sees the unit,
	#    refuses, and points at upgrade-server.sh — and the operator can re-run the
	#    same --reset once the cause is cleared. The drop-in directory goes with it:
	#    an operator-written 20-database-url.conf lives there and can be the only
	#    copy of the working credential.
	if [ "$RESET_DROP_OK" -eq 1 ]; then
		echo "==> Removing the systemd unit and its drop-ins"
		run_root "rm -f '$UNIT_PATH'"
		run_root "rm -rf '$DROPIN_DIR'"
		run_root "systemctl daemon-reload 2>/dev/null || true"
	else
		echo "==> KEEPING the systemd unit and its drop-ins ON PURPOSE — the 'maxsecu'" >&2
		echo "    database and/or role survived step 2, and $UNIT_PATH is the only" >&2
		echo "    durable copy of that database's password." >&2
	fi

	# 5. Remove the Dropbox cold-tier credentials (root-only 0600 env file + dir).
	echo "==> Removing Dropbox cold-tier credentials ($DROPBOX_ENV_DIR)"
	run_root "rm -rf '$DROPBOX_ENV_DIR'"

	# 6. Close the firewall port if ufw manages it. The port comes from the UNIT;
	#    this run's --port is closed too when the two disagree, so a mistyped
	#    --port cannot leave the real one open.
	if command -v ufw >/dev/null 2>&1; then
		echo "==> Removing the ufw allow rule for ${RESET_PORT}/tcp"
		run_root "ufw delete allow ${RESET_PORT}/tcp 2>/dev/null || true"
		if [ "$RESET_PORT" != "$PORT" ]; then
			echo "==> Removing the ufw allow rule for ${PORT}/tcp (this run's --port)"
			run_root "ufw delete allow ${PORT}/tcp 2>/dev/null || true"
		fi
	fi

	# 7. WHAT IS ACTUALLY LEFT — probed, not assumed. RESET_LEFT holds things this
	#    run was supposed to remove and did not (a real failure); RESET_RESIDUAL
	#    holds a server identity found SOMEWHERE ELSE, which is not this run's
	#    fault but is exactly the state the next install would mis-read as a fresh
	#    box, so it must be named.
	RESET_LEFT=""
	RESET_RESIDUAL=""
	# The unit and its drop-ins are the one pair that can be left behind ON PURPOSE
	# (step 4), so they are labelled as such rather than reported as a failure.
	RESET_KEPT_NOTE=""
	if [ "$RESET_DROP_OK" -eq 0 ]; then
		RESET_KEPT_NOTE=" — KEPT ON PURPOSE (see below)"
	fi
	if run_root "test -e '$UNIT_PATH'"; then
		RESET_LEFT="$RESET_LEFT
     * the systemd unit $UNIT_PATH$RESET_KEPT_NOTE"
	fi
	if run_root "test -e '$DROPIN_DIR'"; then
		RESET_LEFT="$RESET_LEFT
     * the drop-in directory $DROPIN_DIR$RESET_KEPT_NOTE"
	fi
	if run_root "test -e '$DATA_DIR'"; then
		RESET_LEFT="$RESET_LEFT
     * the data directory $DATA_DIR"
	fi
	if [ "$RESET_PG_OK" -eq 1 ]; then
		if _left_db="$(pg_probe postgres "SELECT 1 FROM pg_database WHERE datname='maxsecu'" | tr -d '[:space:]')" &&
			[ "$_left_db" = "1" ]; then
			RESET_LEFT="$RESET_LEFT
     * the 'maxsecu' DATABASE"
		fi
		if _left_role="$(pg_probe postgres "SELECT 1 FROM pg_roles WHERE rolname='maxsecu'" | tr -d '[:space:]')" &&
			[ "$_left_role" = "1" ]; then
			RESET_LEFT="$RESET_LEFT
     * the 'maxsecu' ROLE"
		fi
	fi
	# An UNPROVEN drop must never reach the "back to zero" banner. The two probes
	# just above are the ones that name a survivor, but they can themselves fail to
	# answer — the very case RESET_DROP_OK already caught — and an empty RESET_LEFT
	# would then report a clean teardown this run cannot vouch for.
	if [ "$RESET_DROP_OK" -eq 0 ] && [ -z "$RESET_LEFT" ]; then
		RESET_LEFT="$RESET_LEFT
     * the 'maxsecu' database and/or role — this run could NOT confirm they were
       dropped, so it kept the unit that holds their password"
	fi

	# The residual sweep. NAMING a survivor is safe; guessing what to delete is how
	# this whole family of bugs started, so nothing here removes anything.
	if [ "$COMPUTED_DATA_DIR" != "$DATA_DIR" ] && run_root "test -f '$COMPUTED_DATA_DIR/tls/cert.der'"; then
		RESET_RESIDUAL="$RESET_RESIDUAL
     * $COMPUTED_DATA_DIR/tls/cert.der"
	fi
	_sweep="$(run_root "find /home /root /srv /opt -maxdepth 6 -type f -path '*/tls/cert.der' 2>/dev/null || true" </dev/null || true)"
	while IFS= read -r _hit; do
		[ -n "$_hit" ] || continue
		case "$RESET_RESIDUAL" in
		*"$_hit"*) continue ;;
		esac
		RESET_RESIDUAL="$RESET_RESIDUAL
     * $_hit"
	done <<EOF
$_sweep
EOF

	echo ""
	if [ -n "$RESET_LEFT" ]; then
		echo "============================================================" >&2
		echo " PARTIAL RESET — this machine is NOT back to zero." >&2
		echo "============================================================" >&2
		echo "" >&2
		echo " Still present after the teardown:$RESET_LEFT" >&2
		echo "" >&2
		if [ "$RESET_DROP_OK" -eq 0 ]; then
			echo " THE UNIT WAS KEPT DELIBERATELY. The 'maxsecu' database and/or role did" >&2
			echo " not go away, and $UNIT_PATH is the only durable copy of that database's" >&2
			echo " password. Deleting it would have left a live database — every account" >&2
			echo " still in it, including recovery — that nobody, including you, could ever" >&2
			echo " log into again. Leaving it costs nothing: the next install-server.sh" >&2
			echo " sees it and refuses." >&2
			echo "" >&2
			echo " The usual causes are a client still connected to the 'maxsecu' database" >&2
			echo " (a running maxsecu-server, an open psql), or the role still owning" >&2
			echo " objects in another database:" >&2
			echo "" >&2
			echo "        sudo systemctl stop maxsecu-server" >&2
			echo "        sudo -u postgres psql -c \"SELECT pid, usename, datname FROM pg_stat_activity WHERE datname='maxsecu'\"" >&2
			echo "" >&2
		fi
		echo " Do NOT install over this. Re-run the same --reset once the cause is" >&2
		echo " cleared (a stopped PostgreSQL, a busy mount, a read-only filesystem)," >&2
		echo " or remove the item above by hand." >&2
		echo "============================================================" >&2
		exit 1
	fi
	echo "============================================================"
	if [ -n "$RESET_RESIDUAL" ]; then
		echo " MaxSecu server state removed — but this machine is NOT back to zero."
	else
		echo " MaxSecu server state removed. This machine is back to zero."
	fi
	echo "============================================================"
	echo ""
	echo " REMOVED:"
	echo "     * the systemd unit $UNIT_PATH and $DROPIN_DIR"
	echo "     * the data directory $DATA_DIR (TLS identity, client pins, blobs)"
	if [ "$RESET_PG_OK" -eq 1 ]; then
		echo "     * the 'maxsecu' database and role — every account, incl. recovery"
	else
		echo "     * no database (this box has no PostgreSQL cluster)"
	fi
	echo "     * the Dropbox cold-tier credentials in $DROPBOX_ENV_DIR"
	echo "     * the ufw allow rule for ${RESET_PORT}/tcp, where ufw manages it"
	echo ""
	echo " LEFT IN PLACE, ON PURPOSE:"
	echo "     * the source folder $ROOT"
	echo "       (to discard local code edits too:"
	echo "        git -C '$ROOT' reset --hard && git -C '$ROOT' clean -xffd)"
	if [ "$RESET_COLD_TIER" = "fs" ] && ! path_is_within "$RESET_COLD_DIR" "$DATA_DIR"; then
		echo "     * the local-filesystem COLD TIER at"
		echo "       $RESET_COLD_DIR"
		echo "       It is OUTSIDE the data directory, so it still holds offloaded"
		echo "       ciphertext and any sealed backup bundle written there. Delete it"
		echo "       yourself if you meant to erase those too."
	fi
	echo ""
	echo " NOTE: removing $DROPBOX_ENV_DIR also removed the Dropbox refresh token."
	echo " Sealed backup bundles held on that Dropbox account are no longer reachable"
	echo " from this box until those credentials are set up again."
	if [ -n "$RESET_RESIDUAL" ]; then
		echo ""
		echo " STILL ON THIS MACHINE — a TLS server identity was found at:$RESET_RESIDUAL"
		echo ""
		echo " A later install-server.sh looks only at its OWN data directory, so it will"
		echo " NOT see that one: it would mint a SECOND identity beside it. Either delete"
		echo " it, or point the reset at it and run it again:"
		echo ""
		echo "     sudo env MAXSECU_DATA_DIR=<that path, without /tls/cert.der> \\"
		echo "         bash $0 --reset --port $RESET_PORT"
	fi
	echo ""
	echo " To install again from scratch:"
	echo "     $0 --public"
	echo "============================================================"
	exit 0
fi

# --------------------------------------------------------------------------- #
# 2b-2. PURE-ARGUMENT PRECONDITIONS — checked HERE, before apt, before the
#       multi-minute build, before anything touches the database or the TLS
#       directory. They depend on nothing but the command line and the presence
#       of a terminal, and they used to be evaluated ~1300 lines further down: a
#       scripted `install-server.sh --public --dropbox </dev/null` ran the whole
#       apt step, the whole release build, created the database role and migrated
#       the schema, and THEN exited 2 saying --dropbox needs a TTY. The refusal
#       has to cost the operator nothing but the time to read it, which is the
#       property the preflight above already claims for the whole script.
#
#       DELIBERATELY NOT IN THE FLAG-PARSE LOOP, and deliberately BELOW the
#       --reset early exit: `--reset --dropbox </dev/null` and
#       `--reset --capacity-gb 0` must still tear the box down and exit 0, which
#       is what scripts/lib/wsl-harness.ps1 and the runbooks rely on. Validating
#       at parse time would turn both into exit 2.
#
#       The LATE checks stay where they are. Step 9d prompts for the capacity
#       interactively when no flag was given, and that typed answer needs the same
#       validation; this block only covers a value that came off the command line.
# --------------------------------------------------------------------------- #
if [ "$DROPBOX_FORCE" -eq 1 ] && [ ! -t 0 ]; then
	echo "error: --dropbox needs an interactive terminal to read the secrets," >&2
	echo "       but stdin is not a TTY. Re-run in a terminal, or set the" >&2
	echo "       MAXSECU_DROPBOX_* credentials in /etc/maxsecu/dropbox.env by hand." >&2
	exit 2
fi
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
if [ "$COLD_FS" -eq 1 ]; then
	echo "    cold tier : local filesystem at $COLD_FS_DIR"
fi

# --------------------------------------------------------------------------- #
# 2b-pre0. IS THERE A POSTGRES CLUSTER ON THIS BOX AT ALL — and if there is one
#          that is not ANSWERING, start it so the preflight below can ask it how
#          many accounts exist.
#
#   WHY. The account count is one of the three existing-install signals, and a
#   stopped PostgreSQL used to make it answer "0 accounts" — indistinguishable from
#   a genuinely empty box, on the exact machine where being wrong locks every user
#   out forever. So: look first, and only then decide.
#
#   THE QUESTION IS "DOES IT ANSWER", NOT "IS THE UNIT ACTIVE". Both the gate and
#   the wait below used to ask `systemctl is-active postgresql`, which is the wrong
#   question in BOTH directions — the same mistake the --reset block ~350 lines
#   above already spells out and already fixed. On Debian/Ubuntu
#   `postgresql.service` is a RemainAfterExit wrapper (`ExecStart=/bin/true`) that
#   merely pulls in `postgresql@NN-main.service`: it reports ACTIVE the instant
#   `systemctl start` returns, and it STAYS active while the real cluster
#   underneath it is down. So the old form
#     (a) broke its own bounded wait on iteration 0 — `pg_isready && ... ||
#         is-active` groups as `(pg_isready) || (is-active)`, and the wrapper is
#         active immediately, so a cluster that needs a few seconds to accept
#         connections was asked too early and 2b-pre1 refused a HEALTHY FRESH
#         INSTALL outright; and
#     (b) skipped the start ENTIRELY whenever the wrapper was active over a dead
#         cluster — the exact state this block exists for.
#   Both now use `pg_connect_diag`: the same connection probe --reset uses, and the
#   same question the account probe below actually needs answered.
#
#   `systemctl start`, NEVER `enable --now`. A run that ends in a refusal must not
#   quietly change what this machine starts at boot. Step 3 further down does the
#   `enable --now` on the paths that really are installing. If the service was
#   started here it is LEFT RUNNING (stopping it again could just as easily be the
#   wrong answer on a box that was mid-repair), and every refusal below says so.
#
#   THE DETECTION IS DELIBERATELY NARROW — evidence of an actual CLUSTER, not of
#   the tooling. `command -v psql` is satisfied by the postgresql-client package
#   alone, and `getent passwd postgres` survives an `apt-get purge`; either would
#   make a legitimately fresh box try to start a service that does not exist, and a
#   brand-new VPS must still install with no flags at all. `systemctl cat
#   postgresql.service` ALONE is not narrow enough either, and used to be arm 1 on
#   its own: that unit file ships in the postgresql-common PACKAGE, so it is present
#   on a box that has the Debian cluster TOOLING and no cluster — after
#   `apt-get remove` (as opposed to purge), or where postgresql-common came in as a
#   dependency. It is now ANDed with real cluster evidence, the way arms 2 and 3
#   already carry their own: a cluster CONFIG under /etc/postgresql (pg_createcluster
#   writes it, and it is what survives when the data dir lives somewhere
#   non-standard), or a loaded postgresql@NN-main instance unit. A box with neither
#   has no cluster to start.
# --------------------------------------------------------------------------- #
PG_CLUSTER_PRESENT=0
PG_STARTED_BY_THIS_RUN=0
if run_root "systemctl cat postgresql.service >/dev/null 2>&1 && { ls -d /etc/postgresql/*/*/postgresql.conf >/dev/null 2>&1 || [ -n \"\$(systemctl list-units --all --no-legend 'postgresql@*.service' 2>/dev/null)\" ]; }"; then
	PG_CLUSTER_PRESENT=1
elif run_root "ls -d /var/lib/postgresql/*/main >/dev/null 2>&1"; then
	PG_CLUSTER_PRESENT=1
elif run_root "command -v pg_lsclusters >/dev/null 2>&1 && [ -n \"\$(pg_lsclusters -h 2>/dev/null)\" ]"; then
	PG_CLUSTER_PRESENT=1
fi

if [ "$PG_CLUSTER_PRESENT" -eq 1 ] && ! pg_connect_diag >/dev/null 2>&1; then
	echo "==> PostgreSQL is installed but not answering — starting it to look for"
	echo "    existing accounts before this install touches anything."
	echo "    (systemctl start, NOT enable: what starts at boot is left as it is.)"
	# ONLY RECORD A START THAT ACTUALLY HAPPENED. This flag is what makes four
	# refusals below say "PostgreSQL was STARTED by this run and LEFT RUNNING", and
	# it used to be set unconditionally after a `|| true` — so a start that FAILED
	# (masked unit, missing cluster, systemd not running) still produced that claim,
	# sending the operator to stop a service this run never started.
	if run_root "systemctl start postgresql >/dev/null 2>&1"; then
		PG_STARTED_BY_THIS_RUN=1
	else
		echo "    (the start command itself FAILED — probing anyway)"
	fi
	# Bounded wait: a cold cluster needs a moment before it accepts connections,
	# and answering "0 accounts" because we asked too early is the whole bug. ONE
	# condition, no `||` fallback — the fallback is what made this break out on
	# iteration 0 (see the header). Same bound, same probe, as --reset.
	#
	# BOUNDED BY THE CLOCK, NOT BY A COUNT OF ITERATIONS. "30 iterations" is not a
	# timeout when a single iteration can block forever: a cluster stuck in
	# connect(), an NFS-stalled socket directory or a `su - postgres` that hangs
	# would wedge a FRESH INSTALL indefinitely with no output. Two independent
	# bounds now: each probe is capped by pg_connect_diag itself
	# (PGCONNECT_TIMEOUT + `timeout $PG_PROBE_TIMEOUT`, see its definition), and the
	# loop stops at a wall-clock deadline. Worst case is PG_WAIT_SECS plus one
	# probe's cap, whatever any single call does.
	_pg_deadline="$(($(date +%s) + PG_WAIT_SECS))"
	while [ "$(date +%s)" -lt "$_pg_deadline" ]; do
		if pg_connect_diag >/dev/null 2>&1; then
			break
		fi
		sleep 1
	done
	unset _pg_deadline
fi

# --------------------------------------------------------------------------- #
# 2b-pre. THE EXISTING-INSTALL PREFLIGHT — fail closed on a box that already runs
#         MaxSecu.
#
#   WHY. This script is a FRESH-INSTALL tool that used to advertise itself as
#   idempotent, and the obvious operator action — "re-run the installer to change a
#   setting" — was the one that destroyed the deployment:
#     * with --public it deleted <data_dir>/tls/{cert,key}.der, after which the
#       server MINTS A NEW SERVER IDENTITY (crates/portable-server/src/pki.rs) and
#       every client that pinned the old cert fails closed FOREVER. There is no
#       admin escape hatch by design and no self-repair for a non-technical user;
#     * it rotated the `maxsecu` role password on EVERY run and only wrote the
#       matching unit hundreds of lines later, with two interactive prompts in
#       between — so a Ctrl-C left a live database whose working password existed
#       NOWHERE. (Step 7 below no longer rotates when it can recover and prove the
#       existing one, which removes that window rather than papering over it.)
#     * it rewrites the whole unit from THIS run's flags, so a re-run that omits a
#       flag silently changes the port / bind / capacity / cold tier.
#
#   WHERE. Deliberately EARLY — before apt (step 3), before the multi-minute build
#   (step 6), and before anything WRITES to Postgres (step 7). A refusal must cost
#   the operator nothing but the time to read it.
#
#   ONE THING IT MAY CHANGE, STATED PLAINLY: step 2b-pre0 above STARTS an
#   already-installed-but-stopped PostgreSQL, purely so the account signal below can
#   be read instead of guessed, and leaves it running. It uses `systemctl start`,
#   never `enable`, so what this machine starts at boot is untouched — and every
#   refusal that follows a start says so rather than claiming nothing happened.
#
#   DETECTION is the OR of three independent signals, because any one of them can be
#   missing on a partially-damaged box:
#     1. the systemd unit exists;
#     2. <data_dir>/tls/cert.der OR tls/key.der exists — either half of the server
#        identity clients pinned (the OR is deliberate: half a pair is still
#        evidence of a previous install, and it is refused further down rather than
#        mistaken for a fresh box);
#     3. the `maxsecu` database has a non-empty `users` table.
#   `--reset` clears all three (it removes the unit + drop-ins, DROPs the database
#   and role, and deletes the data dir), which is what keeps the automated harnesses
#   green without the opt-out flag: both of them --reset or provision a fresh distro
#   first (scripts/lib/wsl-harness.ps1, scripts/test-full-install.ps1). A genuine
#   DEAD-BOX REBUILD (scripts/restore-server.sh) also has none of the three, so it
#   passes too — that path really is a fresh install.
# --------------------------------------------------------------------------- #
EXISTING_SIGNALS=""

if run_root "test -f '$UNIT_PATH'"; then
	EXISTING_SIGNALS="$EXISTING_SIGNALS
    * the systemd unit $UNIT_PATH exists"
fi

# Read as root: the data dir belongs to $RUN_USER and may sit under a home
# directory this invocation cannot traverse otherwise.
#
# BOTH HALVES ARE PROBED, AND THE ANSWER THAT MATTERS IS THE **AND**. A
# certificate whose private key is gone is a BROKEN identity, not a kept one:
# crates/portable-server/src/pki.rs regenerates BOTH files when EITHER is missing,
# so the next start mints a NEW server identity and every pinned client is locked
# out — which is exactly the outcome an orphaned cert.der makes look safe.
#
# KEPT AS ITS OWN VARIABLE, not just folded into $EXISTING_SIGNALS. It is the
# POSITIVE CONFIRMATION that a WORKING identity is at the RESOLVED data dir, and
# two things below are only allowed to speak because of it:
#   * the --force-overwrite-existing-install reassurance ("the TLS cert + client
#     pins are KEPT ... this run locks out no client") may be printed ONLY when
#     this is 1. With no cert at all, OR with a cert whose key is gone, that
#     sentence is FALSE — step 9 computes HAVE_TLS_CERT=0 from this same pair of
#     probes and the server mints a NEW identity;
#   * step 2b-post2 refuses outright when this is 0 while the database holds real
#     accounts.
#
# DETECTION, THOUGH, STAYS AN **OR**: either half on its own is evidence that this
# box was installed before, so either half on its own must keep producing a
# signal. Folding the signal append under the AND would make a cert-only box look
# BRAND NEW — the preflight would then not even ask for
# --force-overwrite-existing-install, which is strictly worse than today.
HAVE_CERT_AT_DATA_DIR=0
if run_root "test -f '$DATA_DIR/tls/cert.der'"; then
	HAVE_CERT_AT_DATA_DIR=1
fi
HAVE_KEY_AT_DATA_DIR=0
if run_root "test -f '$DATA_DIR/tls/key.der'"; then
	HAVE_KEY_AT_DATA_DIR=1
fi
HAVE_IDENTITY_AT_DATA_DIR=0
# The half that IS there and the half that is MISSING, set only when exactly one
# of the two exists. Both stay empty on a healthy box and on an empty one, so
# `[ -n "$TLS_ORPHAN_FILE" ]` is the half-identity test everywhere below.
TLS_ORPHAN_FILE=""
TLS_MISSING_FILE=""
if [ "$HAVE_CERT_AT_DATA_DIR" -eq 1 ] && [ "$HAVE_KEY_AT_DATA_DIR" -eq 1 ]; then
	HAVE_IDENTITY_AT_DATA_DIR=1
	EXISTING_SIGNALS="$EXISTING_SIGNALS
    * a TLS certificate exists at $DATA_DIR/tls/cert.der
      (this is the identity every installed client has pinned)"
elif [ "$HAVE_CERT_AT_DATA_DIR" -eq 1 ]; then
	TLS_ORPHAN_FILE="cert.der"
	TLS_MISSING_FILE="key.der"
elif [ "$HAVE_KEY_AT_DATA_DIR" -eq 1 ]; then
	TLS_ORPHAN_FILE="key.der"
	TLS_MISSING_FILE="cert.der"
fi
if [ -n "$TLS_ORPHAN_FILE" ]; then
	EXISTING_SIGNALS="$EXISTING_SIGNALS
    * a TLS identity file exists at $DATA_DIR/tls/$TLS_ORPHAN_FILE, but its other
      half $TLS_MISSING_FILE is MISSING — a BROKEN identity, not a working one"
fi

# HOW MANY ACCOUNTS ARE ON THIS BOX — AND, JUST AS IMPORTANTLY, WHETHER WE KNOW.
#
# This used to be one line that read "" for BOTH "the table is empty" and "Postgres
# would not answer", and then turned "" into 0. A stopped cluster therefore made a
# LIVE deployment look like a brand-new box — the one state in which continuing
# mints a new server identity and locks every user out forever. "Could not find
# out" and "there is nothing there" are not the same fact and must not share a
# value.
#
# So the answer is TRI-STATE, in USERS_PROBE_STATE:
#   absent        — asked, and there are provably no MaxSecu accounts here (no
#                   cluster and nothing answering, or no `maxsecu` database, or no
#                   `users` table). EXISTING_USERS=0 and that zero is TRUSTED.
#   known         — asked, got a number. EXISTING_USERS is that number.
#   indeterminate — could NOT ask. EXISTING_USERS stays 0 but that zero means
#                   nothing, and the refusal below fires rather than acting on it.
#
# `count(*)` rather than `SELECT 1 ... LIMIT 1` on the last rung, so the message can
# still say how many accounts are at stake. Each rung records WHICH question failed
# (USERS_PROBE_RUNG) so the refusal can name it, and rung 1 keeps psql's own
# diagnostic: "could not connect" (start or repair the service) and "authentication
# failed" (fix pg_hba.conf / the postgres account) are different jobs.
EXISTING_USERS=0
USERS_PROBE_STATE="indeterminate"
USERS_PROBE_RUNG="connecting to PostgreSQL"
USERS_PROBE_DETAIL=""
if _pg_diag="$(pg_connect_diag)"; then
	USERS_PROBE_RUNG="listing the databases on this cluster"
	if _pg_answer="$(pg_probe postgres "SELECT 1 FROM pg_database WHERE datname='maxsecu'" | tr -d '[:space:]')"; then
		if [ -z "$_pg_answer" ]; then
			# The cluster answered and carries no `maxsecu` database at all.
			USERS_PROBE_STATE="absent"
		else
			USERS_PROBE_RUNG="looking for the 'users' table in the 'maxsecu' database"
			# `IS NOT NULL` is never itself NULL, so psql prints exactly `t` or `f`
			# here — an EMPTY answer therefore already means the query errored, and
			# must NOT be read as "no table".
			if _pg_answer="$(pg_probe maxsecu "SELECT to_regclass('public.users') IS NOT NULL" | tr -d '[:space:]')"; then
				case "$_pg_answer" in
				f)
					# The database is there but the schema was never loaded.
					USERS_PROBE_STATE="absent"
					;;
				t)
					USERS_PROBE_RUNG="counting the rows of the 'users' table"
					if _pg_answer="$(pg_probe maxsecu "SELECT count(*) FROM users" | tr -d '[:space:]')"; then
						case "$_pg_answer" in
						'' | *[!0-9]*)
							: # not a number -> we did not get an answer
							;;
						*)
							USERS_PROBE_STATE="known"
							EXISTING_USERS="$_pg_answer"
							;;
						esac
					fi
					;;
				esac
			fi
		fi
	fi
elif [ "$PG_CLUSTER_PRESENT" -eq 0 ]; then
	# Nothing answered AND there is no cluster on this machine that could have
	# answered. This is the ordinary brand-new VPS, and it is why
	# `install-server.sh --public <IP>` still installs there with no flags at all:
	# PostgreSQL is installed further down, by step 3.
	USERS_PROBE_STATE="absent"
else
	# A cluster IS here and it would not talk to us — the state that used to read as
	# "brand-new box" and proceed.
	USERS_PROBE_DETAIL="$_pg_diag"
	case "$_pg_diag" in
	*authentication*failed* | *pg_hba.conf* | *"does not exist"*)
		USERS_PROBE_RUNG="authenticating to PostgreSQL as the 'postgres' superuser"
		;;
	esac
fi

if [ "$EXISTING_USERS" -gt 0 ]; then
	EXISTING_SIGNALS="$EXISTING_SIGNALS
    * the 'maxsecu' database holds $EXISTING_USERS user account(s)"
fi

# --------------------------------------------------------------------------- #
# 2b-pre1. THE ACCOUNT COUNT COULD NOT BE READ — refuse rather than guess zero.
#
#   WHERE IT FIRES, AND WHY NOT EVERYWHERE. Only in the two states where a
#   phantom zero is what does the damage:
#     * $EXISTING_SIGNALS is EMPTY — nothing else says "installed", so the
#       unreadable database is the ONLY thing standing between this run and a
#       full fresh install over a live box;
#     * --force-overwrite-existing-install was passed AND no working TLS identity
#       was found at the resolved data dir — that is the exact combination step
#       2b-post2 refuses on, and it can only make that call with a trustworthy
#       count.
#   Otherwise it FALLS THROUGH on purpose: with signals present and no force flag,
#   the existing-install refusal below already fails closed and points at
#   upgrade-server.sh, which is the message that operator actually needs.
#
#   IT IS NOT SILENT ABOUT WHAT IT CHANGED. Step 2b-pre0 may have STARTED
#   PostgreSQL to get an answer and leaves it running, so this refusal says so
#   rather than claiming nothing happened.
# --------------------------------------------------------------------------- #
if [ "$USERS_PROBE_STATE" = "indeterminate" ] && [ "$ASSUME_NO_DATABASE" -ne 1 ] &&
	{ [ -z "$EXISTING_SIGNALS" ] ||
		{ [ "$FORCE_OVERWRITE" -eq 1 ] && [ "$HAVE_IDENTITY_AT_DATA_DIR" -eq 0 ]; }; }; then
	echo "" >&2
	echo "============================================================" >&2
	echo " REFUSING: this box's account database could not be read." >&2
	echo "============================================================" >&2
	echo "" >&2
	echo " What failed: $USERS_PROBE_RUNG" >&2
	if [ -n "$USERS_PROBE_DETAIL" ]; then
		echo "" >&2
		echo " PostgreSQL said:" >&2
		printf '%s\n' "$USERS_PROBE_DETAIL" | sed 's/^/     /' >&2
	fi
	echo "" >&2
	echo " Before installing, this script counts the accounts in the 'maxsecu'" >&2
	echo " database. That count is what stops it from installing straight over a" >&2
	echo " LIVE server: a box with accounts but no TLS identity at the data dir it" >&2
	echo " found is refused, because continuing would MINT A NEW SERVER IDENTITY and" >&2
	echo " lock every installed client out PERMANENTLY (there is no re-pin path and" >&2
	echo " no admin escape hatch)." >&2
	echo "" >&2
	echo " It did not get an answer. It will NOT read that as 'this machine is" >&2
	echo " empty' — that guess is the one that destroys a deployment." >&2
	echo "" >&2
	if [ "$PG_STARTED_BY_THIS_RUN" -eq 1 ]; then
		echo " NOTE: PostgreSQL was STARTED by this check and has been LEFT RUNNING." >&2
		echo " Nothing else on this box was changed, and what starts at boot was not" >&2
		echo " touched (this used 'systemctl start', not 'systemctl enable')." >&2
	else
		echo " Nothing on this box was changed." >&2
	fi
	echo "" >&2
	echo " WHAT TO DO:" >&2
	echo "" >&2
	echo " 1. GET POSTGRESQL ANSWERING, then re-run this command unchanged. The" >&2
	echo "    three usual causes, in the order they actually happen:" >&2
	echo "" >&2
	echo "    (a) THE CLUSTER IS ON A NON-DEFAULT PORT. This is the common one on a" >&2
	echo "        shared VPS: 'apt-get install postgresql' puts a SECOND cluster on" >&2
	echo "        5433 when 5432 is taken, and the superuser socket is named after" >&2
	echo "        the port. List them and ask the right one:" >&2
	echo "" >&2
	echo "            pg_lsclusters" >&2
	echo "            sudo -u postgres psql -p <that port> -c 'SELECT 1'" >&2
	echo "" >&2
	echo "        This run probed ${PG_SUPER_PORT:-the default port 5432 (no cluster port could be discovered)}." >&2
	echo "        If the answer is a different port, put it in the unit's" >&2
	echo "        DATABASE_URL (a 0600 drop-in — it holds the password) and re-run;" >&2
	echo "        that is where this script takes the port from." >&2
	echo "" >&2
	echo "    (b) pg_hba.conf NO LONGER GRANTS peer TO 'postgres'. The probe runs as" >&2
	echo "        the postgres OS account over the local socket, so a pg_hba.conf" >&2
	echo "        whose 'local all postgres' line was changed to md5/scram (or" >&2
	echo "        removed) fails with an authentication error, not a connection one:" >&2
	echo "" >&2
	echo "            sudo -u postgres psql -c 'SHOW hba_file'   # if it answers" >&2
	echo "            sudo grep -vE '^\\s*(#|\$)' /etc/postgresql/*/*/pg_hba.conf" >&2
	echo "" >&2
	echo "        The first uncommented line should be:  local all postgres peer" >&2
	echo "" >&2
	echo "    (c) THE SERVICE IS DOWN:" >&2
	echo "" >&2
	echo "            sudo systemctl start postgresql" >&2
	echo "            sudo systemctl status postgresql" >&2
	echo "            sudo journalctl -u postgresql -n 50 --no-pager" >&2
	echo "" >&2
	echo "    This is the exact command this check runs:" >&2
	echo "" >&2
	echo "        sudo -u postgres psql ${PG_PORT_OPT:+$PG_PORT_OPT }-c 'SELECT 1'" >&2
	echo "" >&2
	echo "    When it prints a 1, re-run the installer." >&2
	echo "" >&2
	echo " 2. IF THIS MACHINE GENUINELY HAS NO MAXSECU DATABASE — a rebuild of a box" >&2
	echo "    whose PostgreSQL cluster itself is gone — say so explicitly:" >&2
	echo "" >&2
	echo "        $0 <your flags> --assume-no-database" >&2
	echo "" >&2
	echo "    That flag ONLY skips this account check. It overwrites nothing by" >&2
	echo "    itself. But if accounts really are on this machine, it forfeits the" >&2
	echo "    protection above and every client is locked out permanently — so use" >&2
	echo "    it only when you know the database is gone." >&2
	echo "" >&2
	echo " 3. IF THIS BOX IS BEING REBUILT FROM A BACKUP, the sealed bundle is the" >&2
	echo "    path that keeps every client connected — it carries the ORIGINAL TLS" >&2
	echo "    identity, which no install can recreate:" >&2
	echo "" >&2
	echo "        sudo bash scripts/restore-server.sh --list" >&2
	echo "" >&2
	echo " DO NOT REACH FOR --reset. It DROPs the database and deletes the data" >&2
	echo " directory. If this machine does hold accounts, that is precisely the" >&2
	echo " damage this refusal is here to prevent." >&2
	echo "============================================================" >&2
	exit 1
fi

if [ "$USERS_PROBE_STATE" = "indeterminate" ] && [ "$ASSUME_NO_DATABASE" -eq 1 ]; then
	echo "" >&2
	echo "WARNING: --assume-no-database: the account database could not be read" >&2
	echo "         ($USERS_PROBE_RUNG failed) and you told this run to carry on as" >&2
	echo "         if this machine holds no MaxSecu accounts. The check that refuses" >&2
	echo "         to mint a new server identity over a live deployment is FORFEITED" >&2
	echo "         for this run. If accounts do exist here, every installed client is" >&2
	echo "         locked out permanently and needs a freshly built ZIP." >&2
	echo "" >&2
fi

if [ -n "$EXISTING_SIGNALS" ] && [ "$FORCE_OVERWRITE" -ne 1 ]; then
	echo "" >&2
	echo "============================================================" >&2
	echo " REFUSING: this box already has a MaxSecu server installed." >&2
	echo "============================================================" >&2
	echo "" >&2
	echo " What was found:$EXISTING_SIGNALS" >&2
	echo "" >&2
	# THE HALF-INSTALL SHAPE — the unit and NOTHING else. It is the most likely way
	# to arrive at this refusal on a box that never actually served anyone: a FIRST
	# install that got as far as writing the unit and then failed late (the port was
	# already taken, the build ran out of memory, the server would not start), so
	# the retry meets a refusal written for a LIVE deployment. Naming it here, and
	# giving it remedy 5 below, is what stops the operator reaching for --reset.
	if [ "$HAVE_IDENTITY_AT_DATA_DIR" -eq 0 ] && [ -z "$TLS_ORPHAN_FILE" ] &&
		[ "$EXISTING_USERS" -eq 0 ] && [ "$USERS_PROBE_STATE" != "indeterminate" ]; then
		echo " READ THIS FIRST — that is the ONLY thing found: a unit, with no TLS" >&2
		echo " identity at $DATA_DIR" >&2
		echo " and no accounts in the 'maxsecu' database. That is what a FIRST INSTALL" >&2
		echo " THAT FAILED LATE leaves behind (the port was taken, the build died, the" >&2
		echo " server would not start) — not a live server. Nobody has pinned anything" >&2
		echo " and there is nothing to lose here, so the answer is almost certainly" >&2
		echo " number 5 below: fix the original failure and re-run. Do NOT reach for" >&2
		echo " --reset for this; you do not need it." >&2
		echo "" >&2
	fi
	echo " install-server.sh is a FRESH-INSTALL tool. Running it here would rewrite" >&2
	echo " the systemd unit from this run's flags, and it has not been touched." >&2
	echo " Use the tool that matches what you actually want:" >&2
	echo "" >&2
	echo " 1. APPLY A CODE UPDATE (git pull + rebuild + migrate + restart), with no" >&2
	echo "    data loss and no client re-pin:" >&2
	echo "" >&2
	echo "        sudo bash scripts/upgrade-server.sh" >&2
	echo "" >&2
	echo " 2. CHANGE A SETTING on the running server — use a systemd drop-in. It is" >&2
	echo "    applied AFTER the unit, so it overrides one value and touches nothing" >&2
	echo "    else (example: turn on the local-filesystem cold tier):" >&2
	echo "" >&2
	echo "        sudo mkdir -p $DROPIN_DIR" >&2
	echo "        sudo tee $DROPIN_DIR/20-cold-tier.conf >/dev/null <<'EOF'" >&2
	echo "        [Service]" >&2
	echo "        Environment=MAXSECU_COLD_TIER=fs" >&2
	echo "        Environment=MAXSECU_COLD_FS_DIR=/srv/maxsecu-cold" >&2
	echo "        EOF" >&2
	echo "        sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server" >&2
	echo "" >&2
	echo "    Same shape for MAXSECU_PORT, MAXSECU_BIND, MAXSECU_CACHE_CAPACITY_BYTES." >&2
	echo "    A drop-in holding a SECRET (DATABASE_URL, a Dropbox token) must be 0600." >&2
	echo "    See docs/runbooks/prod-upgrade.md." >&2
	echo "" >&2
	echo " 3. BACK UP or ROLL BACK the data:" >&2
	echo "" >&2
	echo "        printf '%s' 'passphrase' | sudo bash scripts/backup-server.sh" >&2
	echo "        sudo bash scripts/restore-server.sh --list" >&2
	echo "" >&2
	echo "    TWO PRECONDITIONS, or both of those refuse (harmlessly) instead:" >&2
	echo "      a) A BACKUP NEEDS A COLD TIER. It is where the sealed bundle is" >&2
	echo "         written, so with MAXSECU_COLD_TIER off there is nowhere to put" >&2
	echo "         one and a backup is not possible at all. Add a tier in place with" >&2
	echo "         the drop-in in remedy 2 above — do NOT re-run this installer for" >&2
	echo "         it, which is what you are reading this message for." >&2
	echo "      b) THE INSTALLED BINARY MUST ALREADY SUPPORT BACKUPS. On a server" >&2
	echo "         installed before that feature, neither command can work; upgrade" >&2
	echo "         first, and that one upgrade has to skip its own backup:" >&2
	echo "             sudo bash scripts/upgrade-server.sh --no-backup" >&2
	echo "" >&2
	echo " 4. START OVER FROM ZERO (destroys EVERYTHING on this box — every account," >&2
	echo "    every key, every upload, the TLS identity and the database):" >&2
	echo "" >&2
	echo "        sudo bash $0 --reset --port $PORT" >&2
	echo "        sudo bash $0 --public --port $PORT" >&2
	echo "" >&2
	echo " 5. THE FIRST INSTALL FAILED PART-WAY and you are retrying. A run that dies" >&2
	echo "    after the unit is written (port already in use, out of memory during the" >&2
	echo "    build, the server never came up) leaves that unit behind, and it is one" >&2
	echo "    of the signals above — so this refusal fires on the RETRY. FIX THE" >&2
	echo "    ORIGINAL FAILURE FIRST, then re-run the same command with the flag at" >&2
	echo "    the bottom of this message:" >&2
	echo "" >&2
	echo "        sudo journalctl -u maxsecu-server -n 80 --no-pager   # why it failed" >&2
	echo "        sudo ss -lntp | grep -w $PORT                        # port taken?" >&2
	echo "        $0 <your flags> --force-overwrite-existing-install" >&2
	echo "" >&2
	echo "    On this shape of box that re-run is SAFE and is NOT the destructive" >&2
	echo "    path: it reuses the database password out of the unit it finds, keeps" >&2
	echo "    whatever is in the data directory, and only rewrites the unit — which" >&2
	echo "    is exactly what you want, since the flags you are passing are the ones" >&2
	echo "    that should be in it. --reset is NOT the tool for this and would throw" >&2
	echo "    away anything that did survive." >&2
	echo "" >&2
	echo " If you have read all of that and still mean to re-run the installer over" >&2
	echo " this install, say so explicitly:" >&2
	echo "" >&2
	echo "        $0 <your flags> --force-overwrite-existing-install" >&2
	echo "" >&2
	echo " WHAT THAT FLAG WILL DESTROY:" >&2
	echo "   * the systemd unit is REWRITTEN from this run's flags. Anything you set" >&2
	echo "     by hand in the unit, and every --port / --capacity-gb / --cold-tier-fs" >&2
	echo "     you do NOT repeat on this command line, is replaced by this run's" >&2
	echo "     values or by the compiled-in default." >&2
	echo "   * the env-reconcile drop-in $ENV_DROPIN is deleted (it is regenerated by" >&2
	echo "     the next upgrade)." >&2
	echo "   * the 'maxsecu' role password is re-minted IF this unit carries no" >&2
	echo "     working DATABASE_URL to reuse." >&2
	echo "" >&2
	echo " WHAT IT WILL *NOT* DESTROY:" >&2
	if [ "$HAVE_IDENTITY_AT_DATA_DIR" -eq 1 ]; then
		echo "   * the TLS certificate and client pins under" >&2
		echo "     $DATA_DIR" >&2
		echo "     are KEPT — no client is locked out." >&2
	elif [ -n "$TLS_ORPHAN_FILE" ]; then
		# HALF an identity. "Kept" would be a lie in the most damaging direction:
		# the server regenerates BOTH tls/ files when either is missing, so this
		# box mints a NEW identity on its next start no matter what this run does.
		echo "   * NOT client trust: $DATA_DIR/tls/$TLS_ORPHAN_FILE is there but" >&2
		echo "     $TLS_MISSING_FILE is MISSING, so what is on this box is a BROKEN" >&2
		echo "     identity, not a working one. The server regenerates BOTH files when" >&2
		echo "     either one is gone, so it would MINT A NEW SERVER IDENTITY and every" >&2
		echo "     client that pinned the old certificate would be locked out" >&2
		echo "     PERMANENTLY. Put the ORIGINAL key back from a sealed bundle first:" >&2
		echo "         sudo bash scripts/restore-server.sh --list" >&2
		echo "         sudo bash scripts/restore-server.sh --from latest --only state" >&2
	else
		# NOT a reassurance: no certificate was CONFIRMED at the resolved data dir,
		# so step 9 would compute HAVE_TLS_CERT=0 and the server would mint a NEW
		# identity. Saying "the cert is kept" here is the exact lie that cost this
		# project a lap (see step 2b-post2 below).
		echo "   * NOT the TLS certificate: none was found at" >&2
		echo "     $DATA_DIR/tls/cert.der" >&2
		echo "     so this run would MINT A NEW SERVER IDENTITY there, and every client" >&2
		echo "     that pinned an earlier certificate of this box would be locked out" >&2
		echo "     PERMANENTLY. If the 'maxsecu' database still holds accounts, the run" >&2
		echo "     is REFUSED outright rather than doing that — the data dir was almost" >&2
		echo "     certainly not located. Re-run stating it, e.g." >&2
		echo "         sudo env MAXSECU_DATA_DIR=/actual/path bash $0 <your flags> \\" >&2
		echo "             --force-overwrite-existing-install" >&2
	fi
	echo "   * the database, the blobs and the Dropbox credentials are left in place." >&2
	echo "   * the data directory is never RELOCATED. If this run's idea of the data" >&2
	echo "     dir or the run user disagrees with the installed unit, the run is" >&2
	echo "     REFUSED outright and that flag does NOT override the refusal." >&2
	echo "" >&2
	echo " THE ONE CASE THAT NEEDS A NEW CERTIFICATE: this server's PUBLIC IP CHANGED," >&2
	echo " so the address baked into the certificate no longer matches. That repair" >&2
	echo " LOCKS OUT EVERY EXISTING CLIENT PERMANENTLY — each one has to be handed a" >&2
	echo " freshly built app ZIP before it can connect again, and there is no" >&2
	echo " self-repair for a non-technical user. The command is deliberately NOT pasted" >&2
	echo " here: read \"If your VPS's public IP changed\" in README.md first, and only" >&2
	echo " then type it out yourself." >&2
	echo "" >&2
	echo " NOT SURE WHICH OF THESE YOU WANT? Then it is this one. It updates the code," >&2
	echo " keeps every account, every key and every client pin, and changes no" >&2
	echo " configuration:" >&2
	echo "" >&2
	echo "        sudo bash scripts/upgrade-server.sh" >&2
	echo "" >&2
	# ONLY TRUE WHEN IT IS TRUE. Step 2b-pre0 may have STARTED PostgreSQL to read
	# the account signal that produced this very refusal, and leaves it running —
	# an unconditional "NOTHING WAS CHANGED" is then a lie about the one thing this
	# run did do. Same treatment as the step-7 refusal ~700 lines below.
	if [ "$PG_STARTED_BY_THIS_RUN" -eq 1 ]; then
		echo " NOTHING THAT HOLDS YOUR DATA WAS CHANGED BY THIS RUN. The ONE thing it" >&2
		echo " did do is START PostgreSQL — an earlier check found it installed but not" >&2
		echo " answering, and started it to read the account count above. It has been" >&2
		echo " LEFT RUNNING, and what starts at boot was not touched (that used" >&2
		echo " 'systemctl start', not 'systemctl enable')." >&2
	else
		echo " NOTHING ON THIS SERVER WAS CHANGED BY THIS RUN." >&2
	fi
	echo "============================================================" >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 2b-post. THE IDENTITY REFUSAL — --force-overwrite-existing-install does NOT buy
#          a relocation.
#
#   Only reachable with --force-overwrite-existing-install: a mismatch requires an
#   installed unit, an installed unit is one of the three preflight signals, and
#   the preflight above already exited without the flag.
#
#   Step 2b-0 adopted the unit's values, so from here on every probe reads the
#   right place. What it CANNOT do is decide which of the two the operator meant —
#   and getting that wrong writes a unit pointing at a different directory than
#   the one holding the TLS identity and every uploaded blob. So: refuse, name
#   both values, and let a human resolve it.
#
#   NO OVERRIDE, ON PURPOSE — not even --rotate-tls-identity. That flag means "the
#   public IP changed, mint a new certificate"; it says nothing about moving data,
#   and combining the two would orphan every blob while ALSO locking out every
#   client, in one command, silently. Relocating a data dir is a `systemctl stop` +
#   `mv` + drop-in operation (or --reset for a genuine from-zero rebuild), not a
#   side effect of re-running the installer.
# --------------------------------------------------------------------------- #
if [ -n "$IDENTITY_MISMATCH" ]; then
	echo "" >&2
	echo "============================================================" >&2
	echo " REFUSING: this run's identity disagrees with the installed unit." >&2
	echo "============================================================" >&2
	echo "" >&2
	echo " $UNIT_PATH is what systemd actually starts the server with:$IDENTITY_MISMATCH" >&2
	echo "" >&2
	echo " This happens when the installer is re-run from a DIFFERENT account than" >&2
	echo " the one that installed the box — e.g. installed with 'sudo bash ...' as" >&2
	echo " 'ubuntu', re-run from a root shell entered with 'su -' (where SUDO_USER is" >&2
	echo " unset, so this script would guess /root)." >&2
	echo "" >&2
	echo " WHY THIS IS FATAL AND --force-overwrite-existing-install DOES NOT OVERRIDE IT:" >&2
	echo " the unit written at the end of this run carries MAXSECU_DATA_DIR and User=." >&2
	echo " Writing this run's values would point the server at a DIFFERENT directory:" >&2
	echo " it would find no TLS certificate there and MINT A NEW SERVER IDENTITY, which" >&2
	echo " locks out every installed client permanently, and every already-uploaded" >&2
	echo " blob would be orphaned in the old directory. There is no override flag for" >&2
	echo " that — --rotate-tls-identity does not unlock it either. The unit, the data" >&2
	echo " directory and the database are untouched and the server is still running." >&2
	if [ "$PG_STARTED_BY_THIS_RUN" -eq 1 ]; then
		echo " (The one thing this run did do: an earlier check found PostgreSQL" >&2
		echo " installed but not answering and STARTED it, leaving it running. What" >&2
		echo " starts at boot was not touched.)" >&2
	fi
	echo "" >&2
	echo " WHAT TO DO:" >&2
	echo "" >&2
	echo " 1. If you only meant to update the code — this is not the tool anyway:" >&2
	echo "" >&2
	echo "        sudo bash scripts/upgrade-server.sh" >&2
	echo "" >&2
	echo " 2. If you really meant to re-run the installer over this install, state the" >&2
	echo "    box's own identity explicitly so nothing is guessed:" >&2
	echo "" >&2
	echo "        sudo env SUDO_USER='${UNIT_RUN_USER:-$COMPUTED_RUN_USER}' \\" >&2
	echo "            MAXSECU_DATA_DIR='${UNIT_DATA_DIR:-$COMPUTED_DATA_DIR}' \\" >&2
	echo "            bash $0 <your flags> --force-overwrite-existing-install" >&2
	echo "" >&2
	echo " 3. If you genuinely want the data somewhere else, MOVE it — do not let an" >&2
	echo "    installer re-point the unit and leave the old directory behind:" >&2
	echo "" >&2
	echo "        sudo systemctl stop maxsecu-server" >&2
	echo "        sudo mv '${UNIT_DATA_DIR:-<old dir>}' '<new dir>'" >&2
	echo "        sudo chown -R '${UNIT_RUN_USER:-<unit user>}' '<new dir>'" >&2
	echo "        sudo mkdir -p $DROPIN_DIR" >&2
	echo "        sudo tee $DROPIN_DIR/20-data-dir.conf >/dev/null <<'EOF'" >&2
	echo "        [Service]" >&2
	echo "        Environment=MAXSECU_DATA_DIR=<new dir>" >&2
	echo "        EOF" >&2
	echo "        sudo systemctl daemon-reload && sudo systemctl start maxsecu-server" >&2
	echo "" >&2
	echo "    The TLS identity and the blobs travel WITH the directory, so nothing is" >&2
	echo "    re-minted and no client is locked out." >&2
	echo "============================================================" >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 2b-post2. A LIVE DEPLOYMENT WITH NO CERTIFICATE AT THE RESOLVED DATA DIR — refuse.
#
#   THE HOLE THIS CLOSES. Step 2b-0 can only reconcile against a UNIT. On a box
#   where the UNIT IS GONE but the data dir and the database SURVIVED —
#   scripts/backup-server.sh routes operators into exactly this state when it finds
#   no unit — every guard above goes quiet:
#     * IDENTITY_MISMATCH stays empty (nothing to disagree with), so 2b-post never
#       fires;
#     * DATA_DIR is still the step-2 GUESS, so from a root shell entered with
#       `su -` it is /root/maxsecu-server-data and the cert probe MISSES;
#     * the users signal alone still trips the preflight, so
#       --force-overwrite-existing-install PROCEEDS;
#     * step 9 then computes HAVE_TLS_CERT=0 from that same wrong path and MINTS A
#       NEW TLS IDENTITY: every pinned client locked out permanently, every
#       uploaded blob orphaned in the directory nobody looked in.
#   Byte-for-byte the 2b-post catastrophe, reached without a unit.
#
#   THE SIGNAL, AND WHY IT IS UNAMBIGUOUS. A live deployment ALWAYS has a
#   COMPLETE identity — cert.der AND key.der: the server mints the pair on its
#   first start (crates/portable-server/src/pki.rs) and only --rotate-tls-identity
#   or --reset ever removes it. So "the `users` table is NON-EMPTY while no
#   WORKING identity is at the resolved data dir" is a CONTRADICTION — real
#   accounts exist, therefore a real data dir exists, therefore either this run is
#   not looking at it or the identity there has been broken. There is no reading
#   of that state under which minting a new identity here is the right move.
#
#   TWO SHAPES, TWO MESSAGES. Nothing at all in tls/ means the data dir was almost
#   certainly not located -> state MAXSECU_DATA_DIR. HALF a pair means the box IS
#   the right one and its identity is damaged -> restore the sealed bundle, or
#   rename the orphan aside. Routing the half state into the "find the real data
#   directory" body would send the operator to a `find` that returns the directory
#   already in use. See the branch at the top of the block.
#
#   NO OVERRIDE FLAG, ON PURPOSE — and specifically NOT --rotate-tls-identity.
#   That flag means "the public IP changed, mint a new certificate"; it is an
#   acceptance of a client re-pin, NOT of writing a unit that points at the wrong
#   directory and orphans every blob. The two genuine states behind this signal
#   both have a correct tool already, and neither is an installer flag:
#     (1) the data dir simply was not located -> re-run stating it
#         (MAXSECU_DATA_DIR=...). That can only ever AGREE with reality: if the
#         cert is there the run proceeds normally, and if it is not there this
#         refusal repeats. It can never RELOCATE anything, which is exactly why it
#         is offered instead of a --force-anyway flag;
#     (2) the data dir is genuinely destroyed while the database survived -> that
#         is a RESTORE, not an install (scripts/restore-server.sh), because the
#         sealed bundle is the only thing that can put the ORIGINAL TLS key back
#         and keep every client connected.
#   A flag that covered (2) would be indistinguishable, at the command line, from
#   an operator in state (1) who guessed wrong — and state (1) is the one that
#   destroys a working deployment. So the escape hatch is a stated path, not a
#   flag.
#
#   A DEAD BOX IS UNAFFECTED, which is required: scripts/restore-server.sh sends
#   the operator here. No cluster / no `maxsecu` database / no `users` table all
#   yield USERS_PROBE_STATE=absent with EXISTING_USERS=0, so this never fires on a
#   rebuild. `--reset` exits long before this point.
#
#   AND IT ONLY FIRES ON A COUNT THAT WAS ACTUALLY READ. The `known` conjunct is
#   not decoration: this refusal used to rest on a zero that the old swallowing
#   probe also produced for "Postgres would not answer", which meant the guard was
#   silently disarmed on exactly the damaged box it was written for. A count that
#   could not be taken is now stopped earlier, in 2b-pre1 — it never arrives here
#   dressed up as a zero.
# --------------------------------------------------------------------------- #
if [ "$USERS_PROBE_STATE" = "known" ] && [ "$EXISTING_USERS" -gt 0 ] && [ "$HAVE_IDENTITY_AT_DATA_DIR" -eq 0 ]; then
	if [ -n "$TLS_ORPHAN_FILE" ]; then
		# HALF AN IDENTITY, ITS OWN MESSAGE. The body below must NOT be reused here:
		# "NO certificate at $DATA_DIR/tls/cert.der" is simply false when cert.der is
		# the half that survived, and "FIND THE REAL DATA DIRECTORY" would send the
		# operator to a `find` that lands on the directory already in use — an
		# unsatisfiable refusal. The real exits are the sealed bundle, or renaming
		# the orphan aside to return the box to the dead-identity state the installer
		# already handles.
		echo "" >&2
		echo "============================================================" >&2
		echo " REFUSING: this box has real accounts and a BROKEN TLS identity." >&2
		echo "============================================================" >&2
		echo "" >&2
		echo " Found:" >&2
		echo "   * the 'maxsecu' database holds $EXISTING_USERS user account(s)" >&2
		echo "   * $DATA_DIR/tls/$TLS_ORPHAN_FILE exists" >&2
		echo "   * but its other half $DATA_DIR/tls/$TLS_MISSING_FILE is MISSING" >&2
		echo "" >&2
		echo " Half a TLS identity is not an identity. The server regenerates BOTH" >&2
		echo " files when either one is missing (crates/portable-server/src/pki.rs), so" >&2
		echo " its next start MINTS A NEW SERVER IDENTITY and every client that pinned" >&2
		echo " the old certificate is locked out PERMANENTLY — there is no re-pin path" >&2
		echo " and no admin escape hatch. This is the last moment the ORIGINAL key can" >&2
		echo " still be put back. The unit, the data directory and the database are" >&2
		echo " untouched." >&2
		if [ "$PG_STARTED_BY_THIS_RUN" -eq 1 ]; then
			echo " (The one thing this run did do: an earlier check found PostgreSQL" >&2
			echo " installed but not answering and STARTED it, leaving it running. What" >&2
			echo " starts at boot was not touched.)" >&2
		fi
		echo "" >&2
		echo " WHAT TO DO:" >&2
		echo "" >&2
		echo " 1. PUT THE ORIGINAL IDENTITY BACK from a sealed backup bundle. This is" >&2
		echo "    the ONLY path that keeps every installed client connected — a sealed" >&2
		echo "    bundle always carries both tls/cert.der and tls/key.der:" >&2
		echo "" >&2
		echo "        sudo bash scripts/restore-server.sh --list" >&2
		echo "        sudo bash scripts/restore-server.sh --from latest --only state" >&2
		echo "" >&2
		echo " 2. IF THE DATA DIRECTORY ABOVE IS THE WRONG ONE, state the real one —" >&2
		echo "    without a systemd unit it is guessed from the account you are logged" >&2
		echo "    in as:" >&2
		echo "" >&2
		echo "        sudo find /home /root /srv /var -maxdepth 4 -type f \\" >&2
		echo "            -path '*maxsecu*/tls/cert.der' 2>/dev/null" >&2
		echo "        sudo env MAXSECU_DATA_DIR=/actual/path bash $0 <your flags>" >&2
		echo "" >&2
		echo " 3. NO BACKUP BUNDLE? Then the original server identity is unrecoverable" >&2
		echo "    and every user needs a freshly built app ZIP no matter what you do" >&2
		echo "    next. Make that call deliberately. Move the orphaned half ASIDE —" >&2
		echo "    RENAME it, never delete it, so its fingerprint stays readable if you" >&2
		echo "    ever need to prove what this box used to be — and then re-run:" >&2
		echo "" >&2
		echo "        sudo mv '$DATA_DIR/tls/$TLS_ORPHAN_FILE' \\" >&2
		echo "            '$DATA_DIR/tls/$TLS_ORPHAN_FILE.orphan'" >&2
		echo "" >&2
		echo " DO NOT REACH FOR --reset. It DROPs the database and deletes the data" >&2
		echo " directory, destroying the $EXISTING_USERS account(s) this refusal exists" >&2
		echo " to protect — and it would not bring the lost key back. There is no" >&2
		echo " override flag here either: neither --rotate-tls-identity nor" >&2
		echo " --force-overwrite-existing-install unlocks it." >&2
		echo "============================================================" >&2
		exit 1
	fi
	echo "" >&2
	echo "============================================================" >&2
	echo " REFUSING: this box has real accounts but no TLS certificate here." >&2
	echo "============================================================" >&2
	echo "" >&2
	echo " Found:" >&2
	echo "   * the 'maxsecu' database holds $EXISTING_USERS user account(s)" >&2
	echo "   * NO certificate at $DATA_DIR/tls/cert.der" >&2
	if run_root "test -f '$UNIT_PATH'"; then
		echo "   * the systemd unit $UNIT_PATH exists and was used to resolve the" >&2
		echo "     data dir above" >&2
	else
		echo "   * NO systemd unit at $UNIT_PATH — so the data dir above is this" >&2
		echo "     run's GUESS (from \$MAXSECU_DATA_DIR, or \$HOME of '$RUN_USER')," >&2
		echo "     not something read off the installed server" >&2
	fi
	echo "" >&2
	echo " Those two cannot both be true of a working server. A live MaxSecu server" >&2
	echo " mints its certificate on first start and nothing removes it, so accounts" >&2
	echo " existing means a data directory exists — and this run is not looking at" >&2
	echo " it. Continuing would write a unit pointing HERE, the server would MINT A" >&2
	echo " NEW SERVER IDENTITY, and:" >&2
	echo "   * every client that pinned the real certificate would be locked out" >&2
	echo "     PERMANENTLY (there is no re-pin path and no admin escape hatch), and" >&2
	echo "   * every already-uploaded blob would be ORPHANED in the real directory." >&2
	echo " The unit, the data directory and the database are untouched." >&2
	if [ "$PG_STARTED_BY_THIS_RUN" -eq 1 ]; then
		echo " (The one thing this run did do: an earlier check found PostgreSQL" >&2
		echo " installed but not answering and STARTED it, leaving it running. What" >&2
		echo " starts at boot was not touched.)" >&2
	fi
	echo "" >&2
	echo " WHAT TO DO:" >&2
	echo "" >&2
	echo " 1. FIND THE REAL DATA DIRECTORY and state it. This is the usual answer" >&2
	echo "    when the unit is gone, because without a unit the directory is guessed" >&2
	echo "    from whichever account you are logged in as:" >&2
	echo "" >&2
	echo "        sudo find /home /root /srv /var -maxdepth 4 -type f \\" >&2
	echo "            -path '*maxsecu*/tls/cert.der' 2>/dev/null" >&2
	echo "        sudo env MAXSECU_DATA_DIR=/actual/path bash $0 <your flags> \\" >&2
	echo "            --force-overwrite-existing-install" >&2
	echo "" >&2
	echo "    Stating it can only ever AGREE with the box: if the certificate is" >&2
	echo "    there the install proceeds and keeps it; if it is not, you get this" >&2
	echo "    same refusal again. It can never relocate your data." >&2
	echo "" >&2
	echo " 2. IF THE UNIT IS GONE BUT THE DATA IS FINE, put the unit back instead —" >&2
	echo "    it is the ONLY copy of the database password:" >&2
	echo "" >&2
	echo "        sudo bash scripts/restore-server.sh --list" >&2
	echo "        sudo bash scripts/restore-server.sh --from latest --only state" >&2
	echo "" >&2
	echo " 3. IF THE DATA DIRECTORY IS GENUINELY GONE while the database survived," >&2
	echo "    this is a RESTORE, not an install. Only a sealed bundle can put the" >&2
	echo "    ORIGINAL TLS identity back and keep your users connected:" >&2
	echo "" >&2
	echo "        sudo bash scripts/restore-server.sh --list" >&2
	echo "" >&2
	echo "    With no bundle, the server identity is unrecoverable: every user needs" >&2
	echo "    a freshly built app ZIP no matter what you do next. Make that call" >&2
	echo "    deliberately — this installer will not make it for you as a side" >&2
	echo "    effect. There is NO override flag here: --rotate-tls-identity does not" >&2
	echo "    unlock it and neither does --force-overwrite-existing-install." >&2
	echo "============================================================" >&2
	exit 1
fi

if [ -n "$EXISTING_SIGNALS" ]; then
	echo ""
	echo "WARNING: an existing install was detected and you passed" >&2
	echo "         --force-overwrite-existing-install:$EXISTING_SIGNALS" >&2
	echo "         The systemd unit will be REWRITTEN from this run's flags." >&2
	if [ "$ROTATE_TLS" -eq 1 ]; then
		echo "         --rotate-tls-identity is ALSO set: the TLS cert + client pins" >&2
		echo "         WILL be deleted and a NEW server identity minted. Every client" >&2
		echo "         that pinned the old certificate is locked out permanently and" >&2
		echo "         needs a rebuilt ZIP." >&2
	elif [ "$HAVE_IDENTITY_AT_DATA_DIR" -eq 1 ]; then
		# Only reachable with a COMPLETE identity — cert.der AND key.der — POSITIVELY
		# CONFIRMED at $DATA_DIR by the two probes in 2b-pre; this branch may not be
		# entered on a guess, nor on half a pair. Two guards make the sentence true
		# rather than hopeful: 2b-post refuses when this run disagrees with the unit
		# about the data dir, and 2b-post2 refuses when there are accounts but no
		# working identity here. So $DATA_DIR IS the directory the server uses, the
		# unit will keep pointing at it, and nothing this run does deletes or
		# relocates what is in there.
		echo "         The TLS cert + client pins under" >&2
		echo "         $DATA_DIR" >&2
		echo "         are NOT deleted and the unit keeps pointing at that same" >&2
		echo "         directory, so this run locks out no client that can reach this" >&2
		echo "         server today." >&2
	elif [ -n "$TLS_ORPHAN_FILE" ]; then
		# HALF an identity, and no accounts to lose (2b-post2 refuses a non-empty
		# `users` table in this state). The run may proceed, but it must NOT borrow
		# the reassurance above: the server regenerates BOTH tls/ files when either
		# is missing, so a new identity really is minted.
		echo "         The TLS identity under" >&2
		echo "         $DATA_DIR" >&2
		echo "         is BROKEN: tls/$TLS_ORPHAN_FILE is there but tls/$TLS_MISSING_FILE" >&2
		echo "         is MISSING. The server regenerates BOTH when either one is gone," >&2
		echo "         so it will MINT A NEW SERVER IDENTITY on its first start and any" >&2
		echo "         client that pinned an earlier certificate of this box is locked" >&2
		echo "         out PERMANENTLY and needs a freshly built ZIP. This is allowed" >&2
		echo "         only because no accounts were found in the 'maxsecu' database (a" >&2
		echo "         non-empty one is refused above); if you expected accounts here," >&2
		echo "         STOP and restore the sealed bundle instead." >&2
	else
		# NO certificate here, and (2b-post2) no accounts either — the dead-box /
		# rebuild path that scripts/restore-server.sh drives. Allowed, but it must
		# NOT borrow the reassurance above: a new identity really is minted, and if
		# this box ever handed out a client, that client is gone.
		echo "         NO TLS certificate was found at" >&2
		echo "         $DATA_DIR/tls/cert.der" >&2
		echo "         so NO client trust is preserved by this run: the server will" >&2
		echo "         MINT A NEW SERVER IDENTITY there on its first start, and any" >&2
		echo "         client that pinned an earlier certificate of this box is locked" >&2
		echo "         out PERMANENTLY and needs a freshly built ZIP. This is allowed" >&2
		echo "         only because the 'maxsecu' database holds no accounts (a" >&2
		echo "         non-empty one is refused above); if you expected accounts here," >&2
		echo "         STOP and re-run stating MAXSECU_DATA_DIR." >&2
	fi
	echo ""
fi

# --------------------------------------------------------------------------- #
# 2c. --cold-tier-fs must not sit on top of a Dropbox creds file. The unit loads
#     /etc/maxsecu/dropbox.env via `EnvironmentFile=-` AFTER its `Environment=` lines,
#     so a leftover MAXSECU_COLD_TIER=dropbox there would silently OVERRIDE the
#     MAXSECU_COLD_TIER=fs we are about to write — the box would come back on the wrong
#     cold tier. Refuse EARLY (before the long apt/build steps) rather than ship an
#     ambiguous unit. Checked here because run_root exists now and the creds file is
#     root:root 0600 in a 0700 dir (unreadable to a non-root `test -e`).
# --------------------------------------------------------------------------- #
if [ "$COLD_FS" -eq 1 ] && run_root "test -e '/etc/maxsecu/dropbox.env'"; then
	echo "error: --cold-tier-fs was given, but /etc/maxsecu/dropbox.env already exists" >&2
	echo "       (this box was set up for the Dropbox cold tier). The two cold tiers are" >&2
	echo "       mutually exclusive. Remove just the stale Dropbox credentials:" >&2
	echo "" >&2
	echo "           sudo rm -f /etc/maxsecu/dropbox.env" >&2
	echo "" >&2
	echo "       (that file holds ONLY the Dropbox token — no account, key or upload" >&2
	echo "       is touched), then re-run with --cold-tier-fs. Or omit --cold-tier-fs" >&2
	echo "       to keep Dropbox." >&2
	echo "       Do NOT use '$0 --reset' for this: --reset DROPS the database and role" >&2
	echo "       (every account, including the recovery account) and deletes the data" >&2
	echo "       dir and TLS cert. It is not a way to change cold tier." >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 2d. Provision the fs cold-tier directory, OWNED BY THE SERVICE USER.
#     Nothing else creates it: the binary makes it lazily inside put_chunk
#     (blob.rs `create_dir_all`), so whichever identity writes FIRST owns the
#     tree. backup-server.sh runs the binary as ROOT (it must, to read the
#     root-0600 unit + dropbox.env into the state bundle), so on a box where the
#     first write is a backup, root would create `<dir>` 0755 root:root and the
#     service — which runs as `User=$RUN_USER` — could never offload into it
#     again. Creating it up front with the right owner removes that race.
#     (backup-server.sh also hands ownership back after a root run, for the
#     per-blob_ref sub-directories root creates on every backup.)
# --------------------------------------------------------------------------- #
if [ "$COLD_FS" -eq 1 ]; then
	echo "==> Preparing the fs cold-tier directory $COLD_FS_DIR"
	run_root "install -d -o '$RUN_USER' -g '$RUN_USER' -m 0700 '$COLD_FS_DIR'"
	# Positively prove the SERVICE identity can write there. Offload failures are
	# swallowed by design (WriteBackTier drops the victim and moves on), so an
	# unwritable cold tier is silent: the local store simply stops evicting and the
	# disk fills. Fail the install instead, while the operator is still watching.
	if ! run_as_user "test -w '$COLD_FS_DIR'"; then
		echo "error: $COLD_FS_DIR is not writable by '$RUN_USER' — the account the" >&2
		echo "       server runs as. The cold tier would silently never receive an" >&2
		echo "       offload and no backup bundle could be sealed there. Fix the" >&2
		echo "       ownership, or pick a different --cold-tier-fs directory." >&2
		exit 1
	fi
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
	# `--fail`: without it curl happily hands back an HTTP error page or a captive
	# portal's HTML as the "IP", and only an EMPTY answer was rejected below — after
	# which that body goes verbatim into the unit and the certificate. `-S` keeps
	# curl's own reason visible now that errors are no longer silent.
	PUBLIC_IP="$(curl -fsS --max-time 15 https://api.ipify.org || true)"
	if [ -z "$PUBLIC_IP" ]; then
		echo "error: could not auto-detect a public IP." >&2
		echo "       Re-run with it explicit, e.g.:  $0 --public YOUR.IP.HERE" >&2
		exit 1
	fi
	# Same check the flag forms got at parse time — the auto-detected value has to
	# clear the same bar, because it reaches exactly the same two places.
	if ! validate_public_addr "$PUBLIC_IP"; then
		echo "       (that is what https://api.ipify.org returned, so the detection is" >&2
		echo "       what is broken here — not your command line.)" >&2
		echo "       Re-run with the address explicit:  $0 --public YOUR.IP.HERE" >&2
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
# 7. PostgreSQL role + database. IDEMPOTENT, and deliberately NOT a rotation.
#
#    THE BUG THIS REPLACES. This step used to mint `openssl rand -hex 24` and
#    ALTER ROLE it onto the LIVE role on EVERY run, gated on nothing. The only
#    durable copy of that password is the systemd unit, written ~390 lines later —
#    and between the two sit the whole build, two blocking interactive prompts (the
#    Dropbox y/N and the capacity question) and a late flag validation, with no
#    INT/TERM trap anywhere. A Ctrl-C or a typo'd flag therefore left a live
#    database whose working password existed NOWHERE, on a box whose operator has
#    no escape hatch.
#
#    THE FIX IS NOT A TRAP, IT IS NEVER ROTATING. If the role already exists AND a
#    DATABASE_URL can be recovered from the installed unit AND that credential is
#    PROVEN to still work, we reuse it verbatim and issue no ALTER ROLE at all — so
#    there is no window to protect. A password is minted ONLY on the genuine
#    CREATE ROLE path, where there is no live credential to destroy. There is no
#    `ALTER ROLE` in this script any more: an existing role this installer cannot
#    authenticate against is a REFUSAL that prints the two repairs, which is what
#    scripts/upgrade-server.sh already tells operators to do in that same state.
#
#    NB scripts/restore-server.sh's role reconciliation is written against this
#    behaviour and was re-checked when it changed — see its "RECONCILE THE ROLE
#    WITH THE UNIT WE JUST INSTALLED" comment.
# --------------------------------------------------------------------------- #
echo "==> Configuring PostgreSQL role + database 'maxsecu'"

# --------------------------------------------------------------------------- #
# 7a. WHERE THE DATABASE IS. Read off the INSTALLED UNIT's DATABASE_URL, never
#     guessed and deliberately NOT a flag — the unit is what systemd starts the
#     server with, so it is the only answer that cannot disagree with reality.
#     A box with no unit (fresh install, dead-box rebuild) gets 127.0.0.1:5432.
#
#     WHY THIS EXISTS. Every psql call below used to be `-h localhost` with NO
#     PORT, and the string 5432 appeared nowhere in this file. On a box whose
#     PostgreSQL was relocated (a non-default port, or a second cluster) the
#     recovery probe below therefore asked the WRONG server, concluded the stored
#     password was dead, and — before this change — re-minted the credential of a
#     live database. The parse is the same one upgrade-server.sh and
#     restore-server.sh already use, defaulting a missing port to 5432.
#
#     THREADED THROUGH EVERY portless call, not some of them: a partial threading
#     would create the role on one cluster and load docs/schema.sql into another.
#     (`psql_super_query` / `psql_super_stdin` / `psql_maxsecu_query` keep NO -h —
#     they go over the local unix socket as the postgres superuser, which is what
#     makes peer auth work — but they DO carry the port, via PG_PORT_OPT: the
#     socket is named after it, so portless meant "cluster on 5432 only".)
#
#     THE DISCOVERY RUNS AGAIN HERE. 2b-0c ran before step 3, so on a brand-new box
#     it had no PostgreSQL to look at; by this line apt has installed one and
#     pg_lsclusters exists. Re-running it is what keeps the socket probes and the
#     TCP URL below on the SAME cluster on a box whose cluster is not on 5432.
# --------------------------------------------------------------------------- #
pg_discover_super_port
UNIT_DB_URL="$(resolve_unit_env DATABASE_URL)"
DB_HOST="127.0.0.1"
# The default port is the cluster this box actually has, not a hard-coded 5432 —
# the unit below still overrides it when there is one.
DB_PORT="${PG_SUPER_PORT:-5432}"
if [ -n "$UNIT_DB_URL" ]; then
	_u_rest="${UNIT_DB_URL#*://}"
	_u_hostpath="${_u_rest#*@}"
	_u_hostport="${_u_hostpath%%/*}"
	_u_host="${_u_hostport%%:*}"
	_u_port="${_u_hostport#*:}"
	if [ "$_u_port" = "$_u_hostport" ]; then
		_u_port=5432
	fi
	case "$_u_port" in
	'' | *[!0-9]*) _u_port=5432 ;;
	esac
	if [ -n "$_u_host" ]; then
		DB_HOST="$_u_host"
		DB_PORT="$_u_port"
		echo "    database address from $UNIT_PATH: $DB_HOST:$DB_PORT"
	fi
	unset _u_rest _u_hostpath _u_hostport _u_host _u_port
fi

role_exists="$(psql_super_query "SELECT 1 FROM pg_roles WHERE rolname='maxsecu'" || true)"
db_exists="$(psql_super_query "SELECT 1 FROM pg_database WHERE datname='maxsecu'" || true)"

# Set on the branches that actually CHANGE the database server, so the abort
# message below can only claim "nothing was touched" when that is true.
ROLE_CREATED=0
DB_CREATED=0

# Try to RECOVER the password already in use, rather than replacing it.
DB_PASS=""
if [ "$role_exists" = "1" ]; then
	EXISTING_DB_URL="$UNIT_DB_URL"
	if [ -n "$EXISTING_DB_URL" ]; then
		# postgres://USER:PASS@HOST[:PORT]/DB[?params] — the same parse
		# upgrade-server.sh and restore-server.sh use.
		_dburl_rest="${EXISTING_DB_URL#*://}"
		_dburl_creds="${_dburl_rest%%@*}"
		_dburl_user="${_dburl_creds%%:*}"
		_dburl_pass=""
		if [ "$_dburl_creds" != "$_dburl_user" ]; then
			_dburl_pass="${_dburl_creds#*:}"
		fi
		if [ "$_dburl_user" != "maxsecu" ]; then
			# The unit points at some other role. Reusing its password for the
			# `maxsecu` role would be a guess; do not.
			_dburl_pass=""
		fi
		if [ -n "$_dburl_pass" ]; then
			# PROVE it still works before trusting it. Against the real database when
			# there is one, else against `postgres` (any login role may connect there
			# by default) so the credential is still positively verified.
			_probe_db="postgres"
			if [ "$db_exists" = "1" ]; then
				_probe_db="maxsecu"
			fi
			if PGPASSWORD="$_dburl_pass" psql -h "$DB_HOST" -p "$DB_PORT" -U maxsecu -d "$_probe_db" -tAc 'SELECT 1' >/dev/null 2>&1; then
				DB_PASS="$_dburl_pass"
				echo "    role 'maxsecu' exists — REUSING the password from $UNIT_PATH"
				echo "    (verified by connecting as 'maxsecu'; no ALTER ROLE is issued, so"
				echo "     an interrupted run cannot strand this database)"
			else
				echo "    role 'maxsecu' exists, but the password in $UNIT_PATH does not" >&2
				echo "    work against $DB_HOST:$DB_PORT — see the refusal below." >&2
			fi
		fi
		unset _dburl_rest _dburl_creds _dburl_user _dburl_pass
	fi
fi

if [ -n "$DB_PASS" ]; then
	: # reused — nothing to write to the role
elif [ "$role_exists" = "1" ]; then
	# THE ROLE IS LIVE AND THIS INSTALLER CANNOT AUTHENTICATE AGAINST IT. It used to
	# mint a new password here and ALTER ROLE it onto that live role — which is the
	# single most dangerous statement in this script:
	#   * the only durable copy of the new password is the systemd unit, written
	#     ~450 lines later, with the whole build and the capacity prompt in between
	#     and no INT/TERM trap. A Ctrl-C in that window leaves a live database whose
	#     working password exists NOWHERE, on a box with no admin escape hatch;
	#   * the role's real password is not lost by accident — the usual cause is a
	#     unit that was replaced or hand-edited, and the sealed backup bundle still
	#     holds the original. Overwriting the role destroys that repair.
	# scripts/upgrade-server.sh already tells operators, in this exact state, NOT to
	# re-run install-server.sh. The two scripts now agree: refuse, and print the
	# same two repairs it prints.
	echo "" >&2
	echo "============================================================" >&2
	echo " REFUSING: the 'maxsecu' role exists, but no working password for it" >&2
	echo " could be recovered." >&2
	echo "============================================================" >&2
	echo "" >&2
	if [ -n "$UNIT_DB_URL" ]; then
		echo " $UNIT_PATH carries a DATABASE_URL, but connecting as 'maxsecu' with it" >&2
		echo " to $DB_HOST:$DB_PORT was rejected." >&2
	else
		echo " There is no DATABASE_URL in $UNIT_PATH (or in any EnvironmentFile it" >&2
		echo " loads), so there is nothing to recover a password from." >&2
	fi
	echo "" >&2
	echo " This installer will NOT invent a new one and ALTER ROLE it onto a live" >&2
	echo " database. The password would then exist only in this shell until the unit" >&2
	echo " is written hundreds of lines later — one Ctrl-C and nobody, including you," >&2
	echo " could ever log into that database again." >&2
	echo "" >&2
	# THIS USED TO SAY "Nothing has been changed.", WHICH IS FALSE HERE. This
	# refusal lives in step 7, so step 3 (apt), step 5 (rustup) and step 6 (the
	# whole release build) have already run, and step 2b-pre0 may have started
	# PostgreSQL. Say what is actually true instead — and it is the part the
	# operator needs, because none of what did run can cost anyone access. Same
	# standard as the 2b-pre1 refusal ~800 lines above, which distinguishes its own
	# two cases rather than printing one convenient sentence.
	echo " NOTHING THAT HOLDS YOUR DATA WAS TOUCHED. The role's password was NOT" >&2
	echo " changed, no database, account, key or upload was created or written, and" >&2
	echo " $UNIT_PATH is exactly as it was." >&2
	echo "" >&2
	echo " What this run DID do before stopping here is everything up to step 7:" >&2
	echo " system packages, the Rust toolchain and the release build. None of that" >&2
	echo " touches your data, and a re-run reuses all of it." >&2
	if [ "$PG_STARTED_BY_THIS_RUN" -eq 1 ]; then
		echo " PostgreSQL was also STARTED by an earlier check in this run and has been" >&2
		echo " LEFT RUNNING; what starts at boot was not touched (that used 'systemctl" >&2
		echo " start', not 'systemctl enable')." >&2
	fi
	echo "" >&2
	echo " FIX IT ONE OF THESE TWO WAYS, then re-run this installer:" >&2
	echo "" >&2
	echo " 1. FROM A SEALED BACKUP — it contains the ORIGINAL unit, so the password" >&2
	echo "    that is already on the role comes back and nothing is rotated:" >&2
	echo "" >&2
	echo "        sudo bash scripts/restore-server.sh --list" >&2
	echo "        printf '%s' 'passphrase' | sudo bash scripts/restore-server.sh \\" >&2
	echo "            --from latest --only state" >&2
	echo "" >&2
	echo " 2. OR, if the password is genuinely lost, set a new one YOURSELF and put" >&2
	echo "    the matching URL in a ROOT-ONLY (0600 — it is a secret) drop-in:" >&2
	echo "" >&2
	echo "        sudo -u postgres psql -c \"ALTER ROLE maxsecu PASSWORD 'NEWPASS'\"" >&2
	echo "        sudo install -d $DROPIN_DIR" >&2
	echo "        printf '[Service]\\nEnvironment=DATABASE_URL=postgres://maxsecu:NEWPASS@$DB_HOST:$DB_PORT/maxsecu\\n' \\" >&2
	echo "          | sudo install -m 0600 /dev/stdin \\" >&2
	echo "            $DROPIN_DIR/20-database-url.conf" >&2
	echo "        sudo systemctl daemon-reload" >&2
	echo "" >&2
	echo "    No account, key or upload is touched by either route — those rows live" >&2
	echo "    in the database, not in the unit." >&2
	echo "" >&2
	echo " DO NOT REACH FOR --reset. It DROPs the database and role, which deletes" >&2
	echo " every account on this box, including the recovery account." >&2
	echo "============================================================" >&2
	exit 1
else
	DB_PASS="$(openssl rand -hex 24)"
	echo "    creating role 'maxsecu'"
	printf "CREATE ROLE maxsecu WITH LOGIN PASSWORD '%s';\n" "$DB_PASS" | psql_super_stdin >/dev/null
	ROLE_CREATED=1
fi

if [ "$db_exists" = "1" ]; then
	echo "    database 'maxsecu' exists — leaving it in place"
else
	echo "    creating database 'maxsecu' owned by 'maxsecu'"
	printf 'CREATE DATABASE maxsecu OWNER maxsecu;\n' | psql_super_stdin >/dev/null
	DB_CREATED=1
fi

# The host/port are written EXPLICITLY (they used to be `@localhost/maxsecu` with
# no port). Both are what this run just proved it can reach, so the server is
# pointed at the same cluster the schema was loaded into. Widening only:
# upgrade-server.sh, backup-server.sh and restore-server.sh all parse HOST[:PORT]
# and already default a missing port to 5432.
DATABASE_URL="postgres://maxsecu:${DB_PASS}@${DB_HOST}:${DB_PORT}/maxsecu"

# POSITIVELY PROVE the credential we are about to bake into the unit actually
# reaches the database. Every path above ends here, so this covers the reused one as
# well as both minted ones. Without it the first symptom of a bad credential is the
# schema step below trying to LOAD docs/schema.sql into a database it cannot open —
# a loud failure, but one that names neither the cause nor the fix.
if ! PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U maxsecu -d maxsecu -tAc 'SELECT 1' >/dev/null 2>&1; then
	echo "error: cannot connect to the 'maxsecu' database as role 'maxsecu' with the" >&2
	echo "       password this install is about to write into $UNIT_PATH." >&2
	echo "       Tried $DB_HOST:$DB_PORT." >&2
	# "no data was touched" is only TRUE when neither of the two mutating branches
	# above ran. Printing it unconditionally told an operator to walk away from a
	# database this run had just created a role in — with a password that exists
	# nowhere, because the unit is never written on this path.
	if [ "$ROLE_CREATED" -eq 0 ] && [ "$DB_CREATED" -eq 0 ]; then
		echo "       Nothing has been written to the unit and no data was touched." >&2
	else
		echo "       Nothing has been written to the unit, but this run DID change the" >&2
		echo "       database server before failing:" >&2
		if [ "$ROLE_CREATED" -eq 1 ]; then
			echo "         * the login role 'maxsecu' was CREATED. Its password exists ONLY" >&2
			echo "           in this aborted run and was never written anywhere." >&2
		fi
		if [ "$DB_CREATED" -eq 1 ]; then
			echo "         * the database 'maxsecu' was CREATED (empty — no schema loaded)." >&2
		fi
		echo "       Both were made by THIS run and hold no accounts, so undoing them is" >&2
		echo "       safe. Fix the connection problem, then either re-run this installer" >&2
		echo "       or clear them first:" >&2
		if [ "$DB_CREATED" -eq 1 ]; then
			echo "           sudo -u postgres psql -c 'DROP DATABASE IF EXISTS maxsecu'" >&2
		fi
		if [ "$ROLE_CREATED" -eq 1 ]; then
			echo "           sudo -u postgres psql -c 'DROP ROLE IF EXISTS maxsecu'" >&2
		fi
	fi
	echo "       Check that PostgreSQL is running and that pg_hba.conf allows a" >&2
	echo "       password login from $DB_HOST:" >&2
	echo "           sudo systemctl status postgresql" >&2
	echo "           sudo -u postgres psql -c \"\\du maxsecu\"" >&2
	exit 1
fi

# --------------------------------------------------------------------------- #
# 8. Apply the schema (PgStore does NOT auto-create). Guarded: skip if the core
#    'users' table already exists. Password travels via PGPASSWORD, not argv.
# --------------------------------------------------------------------------- #
echo "==> Applying database schema"
have_users="$(
	PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U maxsecu -d maxsecu -tAc \
		"SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='users' LIMIT 1" || true
)"
FRESH_SCHEMA=0
if [ -n "$have_users" ]; then
	echo "    schema already applied (table 'users' present) — skipping"
else
	echo "    loading $ROOT/docs/schema.sql"
	PGPASSWORD="$DB_PASS" psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -p "$DB_PORT" -U maxsecu -d maxsecu -f "$ROOT/docs/schema.sql" >/dev/null
	FRESH_SCHEMA=1
fi

# --------------------------------------------------------------------------- #
# 8b. Migration bookkeeping (migrations/apply.sh). A fresh install gets its whole
#     schema from docs/schema.sql above, which — proven by the compat gate's
#     schema-equivalence test — is exactly `0001_baseline.sql` + every later
#     migration. So we RECORD every migration as already-applied rather than
#     re-running it. That is what makes a fresh box and an upgraded box the same
#     product.
#
#     The `else` branch is NOT dead code, even though this script now refuses an
#     existing install by default. It is reached whenever a database survives
#     without the other two signals — a --force-overwrite-existing-install re-run,
#     and a partially-destroyed box whose `users` table is empty but whose schema
#     is older than this checkout. There we must NOT blanket-mark migrations as
#     applied: that would silently strand it. Instead we run the very same
#     pending-migration path upgrade-server.sh uses. Migrations run as the
#     `maxsecu` app role (not the postgres superuser), so every object they create
#     is owned by the role the server connects as.
# --------------------------------------------------------------------------- #
echo "==> Recording database migrations"
MIGRATIONS_DIR="$ROOT/migrations"
db_psql() {
	PGPASSWORD="$DB_PASS" psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -p "$DB_PORT" -U maxsecu -d maxsecu "$@"
}
# shellcheck source=../migrations/apply.sh
. "$MIGRATIONS_DIR/apply.sh"

migrations_ensure_table
if [ "$FRESH_SCHEMA" -eq 1 ]; then
	migrations_mark_all_applied
else
	# Pre-existing database: it may predate migrations entirely (empty
	# schema_migrations → 0001_baseline is "pending", and it is idempotent, so
	# applying it to the already-present schema is a no-op).
	migrations_verify_history
	migrations_apply_pending
fi

# --------------------------------------------------------------------------- #
# 9. THE SERVER'S TLS IDENTITY. On a genuine first install there is nothing here
#    and the server mints its cert on first start, with the public-IP SAN.
#
#    THIS BLOCK USED TO BE UNCONDITIONAL UNDER --public, and it was the single
#    largest footgun in the product. Deleting tls/{cert,key}.der makes
#    `ensure_dev_cert` fall through and generate a BRAND-NEW key pair
#    (crates/portable-server/src/pki.rs) — a new server identity. Every client that
#    pinned the old certificate then fails the TLS handshake permanently: there is
#    no re-pin path, no admin escape hatch, and the users are non-technical. (The
#    `client-pins/` directory alone is recoverable — run.rs re-exports it from the
#    cert on every start — so the PERMANENT damage is specifically the two tls/
#    files, which is why the guard is on the cert and not on the pins.)
#
#    So: delete ONLY when there is nothing to lose (no cert yet), or when the
#    operator explicitly asked for a new identity with --rotate-tls-identity.
#    --force-overwrite-existing-install alone must NOT destroy client trust: an
#    operator adding Dropbox to a live box must never get a new cert, while an
#    operator whose VPS genuinely changed public IP does need one and accepts the
#    re-pin. Two intents, two flags.
# --------------------------------------------------------------------------- #
run_as_user "mkdir -p '$DATA_DIR'"
# THE **AND**, not the certificate alone. A cert.der whose key.der is gone cannot
# serve TLS, and `ensure_dev_cert` regenerates BOTH files when either is missing —
# so treating an orphaned cert as "an identity to keep" printed a reassurance
# ("every installed client stays connected") on the one path where the server was
# about to mint a new identity anyway. The same pair of probes runs in 2b-pre; it
# is repeated here rather than carried in a variable so this block stays readable
# on its own.
HAVE_TLS_CERT=0
if run_root "test -f '$DATA_DIR/tls/cert.der'" && run_root "test -f '$DATA_DIR/tls/key.der'"; then
	HAVE_TLS_CERT=1
fi

if [ "$HAVE_TLS_CERT" -eq 0 ]; then
	# Nothing usable to lose: there is no working cert+key pair, so the server mints
	# a fresh identity on start. The `rm -rf` still runs so a HALF-WRITTEN tls/
	# cannot survive into the new identity. Note which direction is actually
	# reachable: pki.rs writes cert.der BEFORE key.der, so an interrupted mint can
	# only ever leave a CERT WITH NO KEY — the "key with no cert" this comment used
	# to name is the one shape that cannot be manufactured that way.
	if [ "$PUBLIC" -eq 1 ] || [ "$ROTATE_TLS" -eq 1 ]; then
		if [ -n "$TLS_ORPHAN_FILE" ]; then
			echo "==> BROKEN TLS identity at $DATA_DIR/tls: $TLS_ORPHAN_FILE is there but"
			echo "    $TLS_MISSING_FILE is MISSING, so it cannot be kept — a NEW identity"
			echo "    will be minted on the next start and every client that pinned the old"
			echo "    certificate is locked out PERMANENTLY. (A box with accounts in the"
			echo "    database is REFUSED long before this point; if you did not mean this,"
			echo "    press Ctrl-C and restore the sealed bundle instead.)"
		else
			echo "==> No TLS certificate yet — the server will mint one on first start"
		fi
		run_as_user "rm -rf '$DATA_DIR/client-pins' '$DATA_DIR/tls/cert.der' '$DATA_DIR/tls/key.der'"
	fi
elif [ "$ROTATE_TLS" -eq 1 ]; then
	echo ""
	echo "==> --rotate-tls-identity: DELETING the existing TLS cert + client pins."
	echo "    The server will mint a NEW identity on the next start. EVERY client that"
	echo "    pinned the old certificate is now locked out PERMANENTLY and must be"
	echo "    given a freshly built app ZIP — there is no self-repair for them."
	echo ""
	run_as_user "rm -rf '$DATA_DIR/client-pins' '$DATA_DIR/tls/cert.der' '$DATA_DIR/tls/key.der'"
else
	echo "==> Keeping the existing TLS certificate at $DATA_DIR/tls/cert.der"
	echo "    (every installed client stays connected — no re-pin, no new ZIP)."
	if [ "$PUBLIC" -eq 1 ]; then
		echo "    NOTE: the certificate is NOT regenerated, so its address list is"
		echo "    whatever it was minted with. If this box's public address really did"
		echo "    change to $PUBLIC_IP, clients will fail the TLS handshake until you"
		echo "    re-run with --rotate-tls-identity — which locks out every existing"
		echo "    client and forces a rebuilt ZIP for all of them."
	fi
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
if [ "$COLD_FS" -eq 1 ]; then
	# The cold tier is the local filesystem (--cold-tier-fs) — never Dropbox. The two
	# are mutually exclusive (validated after flag parsing), so the prompt is skipped
	# unconditionally here.
	echo "==> Cold tier: local filesystem ($COLD_FS_DIR) — skipping the Dropbox prompt"
elif [ "$DROPBOX_FORCE" -eq 0 ]; then
	: # explicitly disabled with --no-dropbox
elif [ "$DROPBOX_FORCE" -eq 1 ]; then
	# --dropbox forces yes, but secrets can only be read from a real terminal. Step
	# 2b-2 now refuses this combination up front, before apt and the build, so the
	# else arm below is a BACKSTOP rather than the primary check — kept because it
	# is the arm that would actually try to read the secrets.
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
	# The two knobs with no install flag, written explicitly at their compiled-in
	# defaults (see SERVER_ENV_SURFACE in step 2a). Both are exactly what the binary
	# would have used had they been absent, so this changes nothing about how the
	# server behaves — it makes the unit a COMPLETE statement of its configuration,
	# which is what lets upgrade-server.sh tell "missing" apart from "set to the
	# default on purpose" on an already-deployed box.
	echo "Environment=MAXSECU_OFFLOAD_IDLE_DAYS=$OFFLOAD_IDLE_DAYS"
	echo "Environment=MAXSECU_DIRECT_LINKS=$DIRECT_LINKS"
	# --cold-tier-fs: turn the LOCAL, credential-free fs cold tier ON. BOTH lines are
	# required — config.rs gates the whole fs branch on MAXSECU_COLD_TIER=fs and reads
	# the directory from MAXSECU_COLD_FS_DIR; writing only the directory would leave
	# the tier Off (cold_tier defaults to Off unless MAXSECU_COLD_TIER selects it).
	# These `Environment=` lines are emitted BEFORE the EnvironmentFile= line below;
	# --cold-tier-fs refuses to run when a dropbox.env exists (step 2c), so nothing in
	# that (absent) file can override MAXSECU_COLD_TIER=fs here.
	if [ "$COLD_FS" -eq 1 ]; then
		echo "Environment=MAXSECU_COLD_TIER=fs"
		echo "Environment=MAXSECU_COLD_FS_DIR=$COLD_FS_DIR"
	fi
	# Optional Dropbox cold-tier creds. Leading '-' => an absent file is ignored,
	# so no-Dropbox installs and re-runs are unaffected and never clobbered.
	echo "EnvironmentFile=-$DROPBOX_ENV_PATH"
	echo ""
	echo "[Install]"
	echo "WantedBy=multi-user.target"
} >"$UNIT_TMP"

# --------------------------------------------------------------------------- #
# 10b. Enforce SERVER_ENV_SURFACE against the unit we just generated, BEFORE it is
#      installed. Without this the table in step 2a is a comment that can silently
#      rot; with it, a variable declared `unit` but never emitted aborts the
#      install rather than shipping a server missing part of its configuration.
#      (`envfile` rows are covered by the EnvironmentFile line; `default` rows are
#      deliberately absent; `unit-fs` rows are required only on a --cold-tier-fs run.)
# --------------------------------------------------------------------------- #
surface_missing=""
while IFS='|' read -r sname skind; do
	[ -n "$sname" ] || continue
	case "$skind" in
	unit) ;;
	unit-opt)
		# Only required on the deployment shape it applies to.
		[ "$PUBLIC" -eq 1 ] || continue
		;;
	unit-fs)
		# Only written on a --cold-tier-fs install (the local, credential-free tier).
		[ "$COLD_FS" -eq 1 ] || continue
		;;
	*) continue ;;
	esac
	if ! grep -q "^Environment=${sname}=" "$UNIT_TMP"; then
		surface_missing="$surface_missing $sname"
	fi
done <<EOF
$SERVER_ENV_SURFACE
EOF

# --cold-tier-fs must actually TURN THE FS TIER ON. config.rs gates the whole fs
# branch on MAXSECU_COLD_TIER=fs, so a unit that set MAXSECU_COLD_FS_DIR but not
# MAXSECU_COLD_TIER=fs would resolve to cold_tier=Off — the sealed backup would then
# fail closed with "no cold tier configured". MAXSECU_COLD_TIER's surface row stays
# `envfile` (its Dropbox-path home), so the loop above does not enforce this fs-path
# line; enforce it explicitly here (the exact value, not just the name).
if [ "$COLD_FS" -eq 1 ] && ! grep -q "^Environment=MAXSECU_COLD_TIER=fs\$" "$UNIT_TMP"; then
	surface_missing="$surface_missing MAXSECU_COLD_TIER=fs"
fi

if ! grep -q "^EnvironmentFile=-\{0,1\}${DROPBOX_ENV_PATH}\$" "$UNIT_TMP"; then
	surface_missing="$surface_missing EnvironmentFile=$DROPBOX_ENV_PATH"
fi

if [ -n "$surface_missing" ]; then
	echo "error: the generated unit is missing part of the declared server env surface:" >&2
	echo "        $surface_missing" >&2
	echo "       SERVER_ENV_SURFACE (step 2a) and the unit writer (step 10) have drifted." >&2
	echo "       Refusing to install a server whose configuration is incomplete." >&2
	rm -f "$UNIT_TMP"
	exit 1
fi

run_root "install -o root -g root -m 0600 '$UNIT_TMP' '$UNIT_PATH'"
rm -f "$UNIT_TMP"
trap - EXIT

# The unit we just wrote carries the WHOLE env surface explicitly, so
# upgrade-server.sh's env-reconcile drop-in is redundant by construction. Drop it:
# a drop-in is applied AFTER the base unit, so a stale one from an earlier upgrade
# would OVERRIDE the values just chosen here (a re-run with a new --port would
# silently keep the old one). upgrade-server.sh regenerates it on the next upgrade
# if it is ever needed again. Any OTHER drop-in (an operator's own, the capacity
# drop-in) is left strictly alone — those are deliberate overrides, not ours.
run_root "rm -f '$ENV_DROPIN'"

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
#
#     THE OUTCOME IS RECORDED, NOT ASSUMED. The prod-readiness checklist at the end
#     used to print "✓ firewall <port>/tcp open" whenever the ufw BINARY existed —
#     so an inactive ufw, or an `ufw allow` that failed under its `|| true`, still
#     got a tick. On a public box that tick is the difference between "your users
#     can reach this" and a silent connection timeout nobody can explain. Three
#     states, from what actually happened: opened / not-opened / inactive.
# --------------------------------------------------------------------------- #
FIREWALL_STATE="n/a"
if [ "$PUBLIC" -eq 1 ] && command -v ufw >/dev/null 2>&1; then
	# `ufw status` prints "Status: inactive" on a box where the rule is stored but
	# nothing is enforced — that is NOT an open port, and it is not a failure
	# either: the box simply has no firewall in the way.
	if run_root "ufw status 2>/dev/null | head -n1 | grep -qi 'Status: active'"; then
		echo "==> Allowing ${PORT}/tcp through ufw"
		if run_root "ufw allow ${PORT}/tcp"; then
			FIREWALL_STATE="opened"
		else
			FIREWALL_STATE="failed"
		fi
	else
		echo "==> ufw is installed but INACTIVE — no rule needed for ${PORT}/tcp"
		FIREWALL_STATE="inactive"
	fi
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
	# NOT "re-run with --public": on a box that has already served a single user this
	# script now refuses, and forcing it past that refusal rewrites the unit without
	# regenerating the certificate — so the address in the cert would still be
	# 127.0.0.1 and every public dial would fail the handshake. Going public after
	# the fact is a --reset + reinstall, or a drop-in for MAXSECU_BIND /
	# MAXSECU_PUBLIC_ADDR plus --rotate-tls-identity to re-mint the SANs (which
	# locks out every already-installed client). Say the honest thing here.
	PUBLIC_ADDRESS="127.0.0.1:$PORT (local-only — re-run with --public to expose it; see 'Part 1 — Set up the server' in the README)"
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

# --------------------------------------------------------------------------- #
# 14a. DOES THE CERTIFICATE ON DISK ACTUALLY COVER $CERT_SAN_ADDR? READ IT.
#
#   This checklist used to print "✓ TLS cert for $CERT_SAN_ADDR" straight off the
#   --public FLAG, having never opened the certificate. On the one run where that
#   matters — a --force-overwrite-existing-install with a CHANGED --public and no
#   --rotate-tls-identity — step 9 KEEPS a certificate minted for the OLD address
#   and says so honestly ~500 lines above, and then this banner contradicted it,
#   handed out a "PUBLIC ADDRESS to give your users" and a connection code that
#   every client fails the pinned TLS handshake on (the client builds a
#   RootCertStore from the pinned cert, so webpki checks the SAN against the host
#   that was dialled).
#
#   READING IT, rather than inferring from HAVE_TLS_CERT / ROTATE_TLS, is what
#   makes this correct in every state including the broken ones: by this point the
#   server has started and generated its pins, so tls/cert.der IS the certificate
#   it is serving — whether this run kept it, or the server minted a fresh one
#   because half the identity was missing. openssl is guaranteed present (step 7
#   uses `openssl rand`), but a failure to parse must report UNKNOWN and assert
#   NOTHING. Three states: covered / not-covered / unknown.
# --------------------------------------------------------------------------- #
CERT_SAN_STATE="unknown"
CERT_SAN_LIST=""
CERT_SAN_LIST="$(run_root "{ openssl x509 -inform DER -in '$DATA_DIR/tls/cert.der' -noout -ext subjectAltName 2>/dev/null || openssl x509 -inform DER -in '$DATA_DIR/tls/cert.der' -noout -text 2>/dev/null; } | grep -E 'DNS:|IP Address:' || true" </dev/null 2>/dev/null || true)"
CERT_SAN_LIST="$(printf '%s' "$CERT_SAN_LIST" | tr -s '[:space:]' ' ' | sed -e 's/^ //' -e 's/ $//')"
if [ -n "$CERT_SAN_LIST" ]; then
	# Match a whole SAN entry, never a substring: "IP Address:10.0.0.1" must not
	# satisfy a check for "10.0.0.10".
	case " ${CERT_SAN_LIST}," in
	*" DNS:$CERT_SAN_ADDR,"* | *" IP Address:$CERT_SAN_ADDR,"*)
		CERT_SAN_STATE="covered"
		;;
	*)
		CERT_SAN_STATE="not-covered"
		;;
	esac
	# AN IPv6 ADDRESS IS NOT A STRING. The compare above is textual, and openssl
	# renders an IPv6 SAN UPPERCASE AND FULLY EXPANDED: `--public 2001:db8::1`
	# mints a certificate that really does carry that address (rcgen writes the 16
	# raw bytes, and the client's pinned verifier matches BYTES, not text — see
	# pki.rs::ip_san_validates_through_pinned_client_handshake), but the cert
	# prints `IP Address:2001:DB8:0:0:0:0:0:1` and the string compare therefore
	# answered NOT-COVERED. On a perfectly healthy fresh install that printed a
	# false alarm and pointed the operator at the README section whose only command
	# is --force-overwrite-existing-install --rotate-tls-identity — the one
	# irreversible action, which locks out every installed client permanently. A
	# FALSE not-covered here is worse than no check at all.
	#
	# `openssl x509 -checkip` runs X509_check_ip_asc — the same byte comparison the
	# TLS stack does — so every textual form of one address (compressed, expanded,
	# upper, lower) answers alike.
	#
	# NARROW IN FOUR WAYS, so IPv4 and DNS stay byte-for-byte as they were:
	#   * it runs only when the textual pass already said not-covered;
	#   * it runs only when the address carries a ':', i.e. looks like an IPv6
	#     literal. Dotted-quad IPv4 and DNS names are printed verbatim by openssl
	#     and already compare correctly, so they never reach this;
	#   * it runs only when the address IS ONE — is_ipv6_literal above. THE openssl
	#     x509 APP PRINTS "does match certificate" FOR AN ADDRESS IT CANNOT PARSE
	#     (X509_check_ip_asc returns -2 and the app tests only `ok ? "" : " NOT"`),
	#     and validate_public_addr permits ':' anywhere, so without this gate
	#     `203.0.113.9:8443`, `vps.example.com:8443`, `2001:db8:::1`,
	#     `2001:db8::1:` and `2001:0db8::g1` ALL reported covered against a
	#     certificate carrying none of them — a false ✓ on the one run where the
	#     certificate really is wrong, which is worse than the false alarm this
	#     whole paragraph exists to remove;
	#   * it is POSITIVE-ONLY: nothing but openssl's exact "does match certificate"
	#     flips the verdict, so an openssl too old for -checkip, or one that cannot
	#     read the file, leaves the answer exactly as it is today.
	# The address is safe to single-quote: validate_public_addr already refused
	# every character outside [A-Za-z0-9.:_-], so it can carry no quote or space.
	if [ "$CERT_SAN_STATE" = "not-covered" ]; then
		case "$CERT_SAN_ADDR" in
		*:*)
			if is_ipv6_literal "$CERT_SAN_ADDR"; then
				_san_checkip="$(run_root "openssl x509 -inform DER -in '$DATA_DIR/tls/cert.der' -noout -checkip '$CERT_SAN_ADDR' 2>/dev/null || true" </dev/null 2>/dev/null || true)"
				case "$_san_checkip" in
				*" does match certificate"*) CERT_SAN_STATE="covered" ;;
				esac
				unset _san_checkip
			fi
			;;
		esac
	fi
fi
# THE COLD TIER THIS BOX WILL ACTUALLY RUN WITH — derived from STATE, once, and
# consumed by both the PROD-READINESS line and the closing advice. It used to be
# read off `DROPBOX_ENABLED_THIS_RUN` alone, which is false in three of the four
# real cases: a --cold-tier-fs install (the unit carries MAXSECU_COLD_TIER=fs, and
# step 10b hard-enforces it) reported "off", and so did any run over a box that
# already had Dropbox credentials. The banner then told the operator to RE-RUN THIS
# INSTALLER to fix a tier that was already on — routing them straight back into the
# destructive path the whole preflight exists to prevent.
#
# `run_root`, not a bare `test -e`: the creds file is root:root 0600 inside a 0700
# directory, so a non-root `test -e` reports "absent" even when Dropbox IS set up —
# step 2c says exactly this and already probes it correctly. A probe that FAILS
# (expired sudo timestamp, no TTY) must report UNKNOWN, not "absent": falling
# through to the off arm reproduces the very bug this replaces, so the probe prints
# a token and anything else is UNKNOWN.
COLD_TIER_STATE="off"
if [ "$DROPBOX_ENABLED_THIS_RUN" -eq 1 ]; then
	COLD_TIER_STATE="dropbox-new"
elif [ "$COLD_FS" -eq 1 ]; then
	COLD_TIER_STATE="fs"
else
	_cold_probe="$(run_root "test -e '$DROPBOX_ENV_PATH' && echo present || echo absent" </dev/null 2>/dev/null || true)"
	case "$_cold_probe" in
	present) COLD_TIER_STATE="dropbox-existing" ;;
	absent) COLD_TIER_STATE="off" ;;
	*) COLD_TIER_STATE="unknown" ;;
	esac
	unset _cold_probe
fi
case "$COLD_TIER_STATE" in
dropbox-new) DROPBOX_STATUS="ENABLED (credentials written by this run)" ;;
dropbox-existing) DROPBOX_STATUS="ENABLED (credentials already present at $DROPBOX_ENV_PATH)" ;;
fs) DROPBOX_STATUS="off — the cold tier is the local filesystem at $COLD_FS_DIR" ;;
unknown) DROPBOX_STATUS="UNKNOWN ($DROPBOX_ENV_PATH could not be read as root)" ;;
*) DROPBOX_STATUS="off" ;;
esac

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
	case "$CERT_SAN_STATE" in
	covered) echo "        ✓ TLS cert for $CERT_SAN_ADDR" ;;
	not-covered)
		echo "        ! TLS cert does NOT cover $CERT_SAN_ADDR"
		echo "          it actually carries: $CERT_SAN_LIST"
		;;
	*) echo "        ? TLS cert: its address list could not be read" ;;
	esac
	case "$FIREWALL_STATE" in
	opened) echo "        ✓ firewall ${PORT}/tcp open (ufw allow succeeded)" ;;
	failed)
		echo "        ! firewall ${PORT}/tcp NOT opened - 'ufw allow ${PORT}/tcp'"
		echo "          failed. Run it by hand or your users cannot reach this box."
		;;
	inactive) echo "        - firewall: ufw is installed but INACTIVE (nothing blocks ${PORT}/tcp)" ;;
	esac
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
	case "$CERT_SAN_STATE" in
	covered) echo "        ✓ TLS cert for $CERT_SAN_ADDR" ;;
	not-covered)
		echo "        ! TLS cert does NOT cover $CERT_SAN_ADDR"
		echo "          it actually carries: $CERT_SAN_LIST"
		;;
	*) echo "        ? TLS cert: its address list could not be read" ;;
	esac
	case "$FIREWALL_STATE" in
	opened) echo "        ✓ firewall ${PORT}/tcp open (ufw allow succeeded)" ;;
	failed)
		echo "        ! firewall ${PORT}/tcp NOT opened - 'ufw allow ${PORT}/tcp'"
		echo "          failed. Run it by hand or your users cannot reach this box."
		;;
	inactive) echo "        - firewall: ufw is installed but INACTIVE (nothing blocks ${PORT}/tcp)" ;;
	esac
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

# THE ADDRESS AND THE CONNECTION CODE ABOVE ARE ONLY USABLE IF THE PINNED
# CERTIFICATE COVERS THE ADDRESS THE CLIENT DIALS. Said once, out loud, instead of
# leaving it to a tick in the checklist. Reachable when this run KEPT a certificate
# minted for a different address — a force-overwrite with a changed --public, or a
# box first installed local-only.
if [ "$CERT_SAN_STATE" = "not-covered" ]; then
	echo ""
	echo " !! THE ADDRESS ABOVE WILL NOT WORK AS IT STANDS."
	echo "    This server is serving a certificate that does NOT carry"
	echo "    $CERT_SAN_ADDR. It carries: $CERT_SAN_LIST"
	echo "    A client dialling $CERT_SAN_ADDR fails the pinned TLS handshake, so do"
	echo "    not hand out the address or the connection code above yet."
	echo ""
	echo "    The certificate was NOT regenerated by this run — deliberately: minting"
	echo "    a new one locks out every client that pinned the old one, permanently,"
	echo "    and each of them then needs a freshly built app ZIP. Give your users an"
	echo "    address the certificate already covers if you can. If the box's public"
	echo "    address genuinely changed and there is no way back, read"
	echo "    \"If your VPS's public IP changed\" in README.md before doing anything."
fi
if [ "$CERT_SAN_STATE" = "unknown" ]; then
	echo ""
	echo " NOTE: this script could not read the address list out of"
	echo " $DATA_DIR/tls/cert.der, so it cannot confirm that the address above is one"
	echo " the certificate covers. Check it before handing the code to users:"
	echo ""
	echo "     sudo openssl x509 -inform DER -in $DATA_DIR/tls/cert.der \\"
	echo "         -noout -ext subjectAltName"
fi

case "$COLD_TIER_STATE" in
dropbox-new)
	echo ""
	echo " Dropbox cold-tier offload: ENABLED (creds in $DROPBOX_ENV_PATH, root-only)."
	;;
dropbox-existing)
	echo ""
	echo " Cold-tier offload: Dropbox — credentials were ALREADY present at"
	echo " $DROPBOX_ENV_PATH (root-only) and the unit loads them. This run did not"
	echo " change them, and nothing needs turning on."
	;;
fs)
	echo ""
	echo " Cold-tier offload: the LOCAL FILESYSTEM at"
	echo "     $COLD_FS_DIR"
	echo " The unit carries Environment=MAXSECU_COLD_TIER=fs and"
	echo " Environment=MAXSECU_COLD_FS_DIR, so offload and the sealed backup bundle"
	echo " from scripts/backup-server.sh both land there. Nothing needs turning on."
	;;
unknown)
	echo ""
	echo " Cold-tier offload: UNKNOWN. $DROPBOX_ENV_PATH could not be read as root"
	echo " from this run, so this script cannot tell whether Dropbox credentials are"
	echo " already there. Do NOT assume the tier is off — check it yourself:"
	echo ""
	echo "     sudo test -e $DROPBOX_ENV_PATH && echo present || echo absent"
	echo ""
	echo " If it is absent, add a tier with a drop-in (see below) rather than by"
	echo " re-running this installer, which refuses to touch an existing install."
	;;
*)
	echo ""
	echo " Cold-tier offload is OFF (no Dropbox credentials, no --cold-tier-fs)."
	echo " Turn it on NOW by re-running this install with --dropbox or"
	echo " --cold-tier-fs <dir>, while the box is still empty."
	echo ""
	echo " Once this server has real users, do NOT re-run this script to add it — it"
	echo " refuses to touch an existing install. Add the tier in place with a drop-in:"
	echo ""
	echo "     sudo mkdir -p $DROPIN_DIR"
	echo "     sudo tee $DROPIN_DIR/20-cold-tier.conf >/dev/null <<'EOF'"
	echo "     [Service]"
	echo "     Environment=MAXSECU_COLD_TIER=fs"
	echo "     Environment=MAXSECU_COLD_FS_DIR=/srv/maxsecu-cold"
	echo "     EOF"
	echo "     sudo install -d -o $RUN_USER -g $RUN_USER -m 0700 /srv/maxsecu-cold"
	echo "     sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server"
	echo ""
	echo " The directory must be OUTSIDE $DATA_DIR — an fs cold tier that aliases the"
	echo " blob directory destroys ciphertext. For Dropbox instead, write the"
	echo " MAXSECU_DROPBOX_* credentials into $DROPBOX_ENV_PATH (root:root 0600); the"
	echo " unit already loads that file."
	;;
esac
