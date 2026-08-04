#!/bin/bash
# fingerprint.sh — capture EVERYTHING an existing user's access depends on, read
# from the DATABASE and the SERVER (never from a client). Run it BEFORE and AFTER
# an upgrade and diff the two files. See docs/runbooks/prod-upgrade.md.
#
#   sudo bash scripts/fingerprint.sh before /root/fp-before.txt
#   ... upgrade ...
#   sudo bash scripts/fingerprint.sh after  /root/fp-after.txt
#   diff -u /root/fp-before.txt /root/fp-after.txt
#
# STRICTLY READ-ONLY. It runs SELECTs, hashes files, and reads systemd state. It
# never writes to the database, the data dir or the unit.
#
# WHY THIS EXISTS. "The service came back up" is not evidence that an upgrade was
# safe. The failure this guards against is silent: a lost `file_key_wraps` row, a
# bumped `key_version`, a regenerated TLS certificate. Every one of those leaves a
# healthy-looking server and a user who can never get their data back. Diffing this
# file is the only cheap way to prove none of it happened.
#
# The DATABASE_URL password is redacted from the unit dump, so the output is safe
# to copy off the box.
set -u

LABEL="${1:?usage: fingerprint.sh <label> <outfile>}"
OUT="${2:?usage: fingerprint.sh <label> <outfile>}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_PATH=/etc/systemd/system/maxsecu-server.service
DROPIN_DIR=/etc/systemd/system/maxsecu-server.service.d

# Run a command string as root (directly if already root, else via sudo). This
# script is documented as `sudo bash scripts/fingerprint.sh`, but the unit and the
# Dropbox creds file are root:root 0600, so the reads below go through here rather
# than assuming the caller's identity.
IS_ROOT=0
if [ "$(id -u)" -eq 0 ]; then
	IS_ROOT=1
fi
run_root() {
	if [ "$IS_ROOT" -eq 1 ]; then
		bash -c "$1"
	else
		sudo bash -c "$1"
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
# backup, and a failed backup aborts the upgrade that depends on it. HERE the
# failure is quieter and worse: a wrong MAXSECU_DATA_DIR makes this fingerprint hash
# the wrong tree, so it PROVES NOTHING while still looking plausible — exactly the
# class of silent failure this file exists to catch.
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

# Resolve what the server ACTUALLY runs with, rather than guessing. Both fall back
# to the documented defaults when the unit does not set them: absence of
# MAXSECU_DATA_DIR means `./maxsecu-server-data` relative to WorkingDirectory,
# which for a standard install is the repo root.
DATA_DIR="${MAXSECU_DATA_DIR:-$(resolve_unit_env MAXSECU_DATA_DIR)}"
[ -n "$DATA_DIR" ] || DATA_DIR="$ROOT/maxsecu-server-data"
# ExecStart, likewise read as ROOT: the unit is 0600, so a plain `sed` silently
# yields nothing for a non-root caller and this falls back to the default path —
# which on a box installed from another clone points at a binary that is not the one
# serving, and the two cert/directory fingerprints below then prove nothing.
SERVER_BIN="${SERVER_BIN:-$(run_root "sed -n 's/^ExecStart=//p' '$UNIT_PATH' 2>/dev/null | head -n1" </dev/null | tr -d '\r')}"
[ -n "$SERVER_BIN" ] || SERVER_BIN="$ROOT/target/release/maxsecu-portable-server"

# Run every query from a directory the `postgres` user can actually enter. Without
# the `cd`, running this script from the repo root (which is 0700 root:root on a
# standard install) makes `sudo -u postgres` fail with "could not change directory"
# on EVERY query — and because each failure is captured as the cell value, the
# fingerprint still gets written, still looks plausible, and proves nothing.
q() { (cd /tmp && sudo -u postgres psql -d maxsecu -tAc "$1" 2>&1); }

{
	echo "################ FINGERPRINT: $LABEL ################"
	echo "root=$ROOT  data_dir=$DATA_DIR"
	echo "server_bin=$SERVER_BIN"
	echo

	echo "=== row counts (the tables a user's access lives in) ==="
	for t in users directory_bindings files file_versions file_streams file_key_wraps \
		registration_keys first_admin_claim recovery_account file_genesis control_log auth_events; do
		printf '%-22s %s\n' "$t" "$(q "SELECT count(*) FROM $t")"
	done
	echo

	echo "=== all tables present ==="
	q "SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY 1"
	echo

	echo "=== users (user_id | username | key_version | roles | status | signed?) ==="
	echo "--- an existing user's LOGIN lives here; a lost row or a bumped key_version = locked out."
	q "SELECT encode(user_id,'hex'), username, key_version, array_to_string(roles,','), status, (signed_at IS NOT NULL), encode(enc_pub,'hex'), encode(sig_pub,'hex') FROM users ORDER BY 2"
	echo

	echo "=== directory_bindings (user_id | key_version | roles | sha256(binding_bytes) | sha256(sig)) ==="
	echo "--- THE SIGNED BINDING. If these bytes change, every client that verifies it fails closed."
	q "SELECT encode(user_id,'hex'), key_version, array_to_string(roles,','), encode(sha256(binding_bytes),'hex'), encode(sha256(directory_signature),'hex'), not_before, not_after FROM directory_bindings ORDER BY 1,2"
	echo

	echo "=== files (file_id hex | owner hex | type | current_version | listed | bundle_id) ==="
	q "SELECT encode(file_id,'hex'), encode(owner_id,'hex'), file_type, current_version, listed, coalesce(encode(bundle_id,'hex'),'-') FROM files ORDER BY 1"
	echo

	echo "=== file_versions (file_id | version | finalized | sha256(manifest_bytes)) ==="
	q "SELECT encode(file_id,'hex'), version, finalized, encode(sha256(manifest_bytes),'hex') FROM file_versions ORDER BY 1,2"
	echo

	echo "=== file_streams (file_id | version | stream_type | chunk_count | total_bytes | digest | blob_ref) ==="
	q "SELECT encode(file_id,'hex'), version, stream_type, chunk_count, total_bytes, encode(digest,'hex'), blob_ref FROM file_streams ORDER BY 1,2,3"
	echo

	echo "=== file_key_wraps (file_id | ver | recipient | type | sha256(wrapped_dek)) ==="
	echo "--- THE DEK WRAPS. Losing one of these = that user can never open that file again."
	q "SELECT encode(file_id,'hex'), file_version, encode(recipient_id,'hex'), recipient_type, encode(sha256(wrapped_dek),'hex') FROM file_key_wraps ORDER BY 1,2,3"
	echo

	echo "=== schema_migrations (ABSENT on a box that has never been upgraded) ==="
	q "SELECT id, sha256, applied_at FROM schema_migrations ORDER BY id"
	echo

	echo "=== TLS cert fingerprint (MUST NOT CHANGE - a change locks out every pinned client) ==="
	MAXSECU_DATA_DIR="$DATA_DIR" "$SERVER_BIN" print-cert-fingerprint 2>&1 || echo "(print-cert-fingerprint failed)"
	echo

	echo "=== directory pin / server fingerprint (MUST NOT CHANGE) ==="
	MAXSECU_DATA_DIR="$DATA_DIR" "$SERVER_BIN" print-fingerprint 2>&1 || echo "(print-fingerprint failed)"
	echo

	echo "=== raw TLS cert + delegation config digests (independent of the binary) ==="
	for f in tls/cert.der tls/key.der config/d5_delegation.bin config/directory_pub.der config/operational_secret.bin; do
		if [ -f "$DATA_DIR/$f" ]; then
			printf '%-34s %s\n' "$f" "$(sha256sum "$DATA_DIR/$f" | cut -d' ' -f1)"
		else
			printf '%-34s %s\n' "$f" "(absent)"
		fi
	done
	echo

	echo "=== blob tree (every ciphertext chunk on local disk) ==="
	if [ -d "$DATA_DIR/blobs" ]; then
		echo "file count: $(find "$DATA_DIR/blobs" -type f | wc -l)"
		echo "total bytes: $(find "$DATA_DIR/blobs" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')"
		echo "per-file digests:"
		(cd "$DATA_DIR/blobs" && find . -type f | sort | xargs -r sha256sum)
		echo "TREE-DIGEST: $( (cd "$DATA_DIR/blobs" && find . -type f | sort | xargs -r sha256sum) | sha256sum | cut -d' ' -f1)"
	else
		echo "(no blobs dir)"
	fi
	echo

	echo "=== cold tier contents (if configured) ==="
	COLD="$(resolve_unit_env MAXSECU_COLD_FS_DIR)"
	if [ -n "$COLD" ] && [ -d "$COLD" ]; then
		echo "cold dir: $COLD"
		find "$COLD" -type f | sort | sed "s|^$COLD/||"
	else
		echo "(no fs cold tier configured)"
	fi
	echo

	echo "=== unit + drop-ins (config the server actually runs with) ==="
	echo "--- $(readlink -f "$UNIT_PATH") ---"
	sed 's/\(DATABASE_URL=postgres:\/\/[^:]*:\)[^@]*/\1<REDACTED>/' "$UNIT_PATH" 2>/dev/null
	for d in "$DROPIN_DIR"/*.conf; do
		[ -f "$d" ] || continue
		echo "--- $d ---"
		sed 's/\(DATABASE_URL=postgres:\/\/[^:]*:\)[^@]*/\1<REDACTED>/' "$d"
	done
	echo

	echo "=== service health (is-active is a FALSE-GREEN on Type=simple + Restart=always) ==="
	echo "ActiveState : $(systemctl show maxsecu-server -p ActiveState --value)"
	echo "SubState    : $(systemctl show maxsecu-server -p SubState --value)"
	echo "NRestarts   : $(systemctl show maxsecu-server -p NRestarts --value)"
	echo "MainPID     : $(systemctl show maxsecu-server -p MainPID --value)"
	echo "ExecMainStartTimestamp: $(systemctl show maxsecu-server -p ExecMainStartTimestamp --value)"
	echo

	echo "=== server binary identity ==="
	if [ -f "$SERVER_BIN" ]; then
		echo "sha256: $(sha256sum "$SERVER_BIN" | cut -d' ' -f1)"
		echo "mtime : $(date -r "$SERVER_BIN" -Is)"
	else
		echo "(server binary absent)"
	fi
	echo

	echo "=== migrations present in the tree on this box ==="
	sha256sum "$ROOT"/migrations/*.sql 2>&1 || echo "(no migrations dir)"
	echo

	echo "################ END FINGERPRINT: $LABEL ################"
} >"$OUT" 2>&1

echo "fingerprint written: $OUT ($(wc -l <"$OUT") lines)"
