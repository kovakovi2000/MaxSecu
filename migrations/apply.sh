# shellcheck shell=bash
#
# migrations/apply.sh — the MaxSecu schema-migration runner.
#
# SOURCED (never executed) by scripts/install-server.sh and scripts/upgrade-server.sh
# so both agree, byte for byte, on what "the schema" is.
#
# WHY THIS EXISTS
#   `docs/schema.sql` is loaded only on a FRESH install. Before this runner,
#   `upgrade-server.sh` applied no schema change at all — so any edit to
#   schema.sql silently stranded every existing deployment: the new server code
#   expected a column the running database did not have. That breaks the hard
#   rule (docs/compat/CHECKLIST.md): *every upgrade must keep existing users'
#   access intact.*
#
# THE MODEL
#   * `migrations/NNNN_<slug>.sql`, applied in numeric order, each inside ONE
#     transaction together with its `schema_migrations` row — so a migration is
#     either fully applied AND recorded, or not applied at all.
#   * `migrations/0001_baseline.sql` IS today's `docs/schema.sql`. That is what
#     every already-deployed server is running, which is why it is the baseline.
#     It is idempotent, so applying it to a database that already has the schema
#     is a no-op (that is exactly what the first upgrade of an existing server
#     does).
#   * A fresh install keeps loading `docs/schema.sql` and then RECORDS every
#     migration as already-applied, so a fresh box and an upgraded box converge
#     on the same state. `crates/compat/tests/schema_equivalence.rs` proves that
#     against a live Postgres.
#   * An already-applied migration may NEVER be edited: its sha256 is recorded in
#     the database, and `migrations_verify_history` REFUSES to run when a
#     recorded digest no longer matches the file on disk. Editing history would
#     leave fresh installs and existing installs permanently divergent.
#
# CONTRACT FOR THE SOURCING SCRIPT
#   MIGRATIONS_DIR   absolute path of this directory.
#   db_psql()        runs `psql` against the MaxSecu database AS THE APP ROLE
#                    (`maxsecu`), with `-v ON_ERROR_STOP=1` already set, passing
#                    through its arguments and stdin. Ownership matters: objects
#                    created by another role would be unreadable/unwritable by
#                    the server, so migrations must NOT be applied as the
#                    `postgres` superuser.

# The migration bookkeeping table. Created by the runner, never by a migration —
# it is runner metadata, not part of the product schema, and a migration that
# created it would make an upgraded database differ from a fresh one.
migrations_ensure_table() {
	printf '%s\n' \
		'CREATE TABLE IF NOT EXISTS schema_migrations (' \
		'  id         INT PRIMARY KEY,' \
		'  applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),' \
		'  sha256     TEXT NOT NULL' \
		');' | db_psql -q
}

# sha256 of one migration file (lowercase hex, no filename).
migrations_sha() {
	sha256sum "$1" | cut -d' ' -f1
}

# Print every migration's FILENAME, one per line, in numeric (= lexicographic,
# because the ids are zero-padded) order. Fails loudly on a stray .sql that is
# not numbered — such a file would silently never be applied.
migrations_names() {
	local dir all matched
	dir="${MIGRATIONS_DIR:?MIGRATIONS_DIR must be set before sourcing migrations/apply.sh}"
	if [ ! -d "$dir" ]; then
		echo "error: migrations directory not found: $dir" >&2
		return 1
	fi
	all="$(find "$dir" -maxdepth 1 -type f -name '*.sql' | wc -l)"
	matched="$(find "$dir" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' | wc -l)"
	if [ "$all" -ne "$matched" ]; then
		echo "error: $dir holds a .sql file that is not named NNNN_<slug>.sql." >&2
		echo "       It would never be applied — an existing server would be stranded." >&2
		echo "       Rename it (e.g. 0002_add_thing.sql) and try again." >&2
		return 1
	fi
	if [ "$matched" -eq 0 ]; then
		echo "error: $dir holds no migrations at all (expected at least 0001_baseline.sql)." >&2
		return 1
	fi
	find "$dir" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' -printf '%f\n' | LC_ALL=C sort
}

# Print "<zero-padded id> <sha256>" for every migration the DATABASE says it has
# already applied, in id order.
migrations_applied() {
	db_psql -tAc \
		"SELECT lpad(id::text, 4, '0') || ' ' || sha256 FROM schema_migrations ORDER BY id"
}

# REFUSE TO RUN if history was rewritten: an already-applied migration whose file
# is gone, or whose bytes no longer hash to what this database recorded when it
# applied it. Either means fresh installs and existing installs would silently
# diverge forever — the exact failure this whole mechanism exists to prevent.
migrations_verify_history() {
	local dir applied id recorded path disk candidate
	dir="$MIGRATIONS_DIR"
	applied="$(migrations_applied)"
	while read -r id recorded; do
		[ -n "$id" ] || continue
		# The file for this id, whatever its slug.
		path=""
		for candidate in "$dir/${id}_"*.sql; do
			if [ -f "$candidate" ]; then
				path="$candidate"
				break
			fi
		done
		if [ -z "$path" ]; then
			echo "" >&2
			echo "error: REFUSING TO UPGRADE — migration history was rewritten." >&2
			echo "       This database applied migration $id, but no migrations/${id}_*.sql" >&2
			echo "       exists in this checkout. A migration may be ADDED, never removed:" >&2
			echo "       deleting one makes this server and a freshly-installed server" >&2
			echo "       permanently different products." >&2
			echo "       Restore the file (git) and re-run. Nothing was changed." >&2
			return 1
		fi
		disk="$(migrations_sha "$path")"
		if [ "$disk" != "$recorded" ]; then
			echo "" >&2
			echo "error: REFUSING TO UPGRADE — migration history was rewritten." >&2
			echo "       $(basename "$path") no longer matches what this database applied:" >&2
			echo "         recorded when applied : $recorded" >&2
			echo "         on disk now           : $disk" >&2
			echo "       An APPLIED migration is frozen: its effect is already baked into" >&2
			echo "       this database and cannot be un-run. Editing it means a fresh" >&2
			echo "       install and this server would end up with DIFFERENT schemas." >&2
			echo "       Revert the edit and put the change in a NEW migrations/NNNN_*.sql" >&2
			echo "       instead. Nothing was changed." >&2
			return 1
		fi
	done <<EOF
$applied
EOF
}

# Apply every migration this database has not applied yet, in numeric order, each
# in ONE transaction with its schema_migrations row. Idempotent: re-running it
# applies nothing. Call migrations_verify_history FIRST.
migrations_apply_pending() {
	local dir applied name id sha pending=0

	dir="$MIGRATIONS_DIR"
	applied="$(migrations_applied)"

	# Pre-pass: vet EVERY pending migration before applying ANY of them, so a bad
	# one at the end cannot leave the earlier ones half-shipped.
	#
	# A migration must NOT open/close its own transaction: the runner wraps it
	# together with the schema_migrations INSERT so the two commit as one. A stray
	# COMMIT inside the file would end that transaction early and could leave a
	# migration applied but unrecorded — it would then be re-applied on every
	# future upgrade. The pattern matches only a statement-level BEGIN;/COMMIT;;
	# plpgsql's bare `BEGIN` (no semicolon) is untouched.
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		id="${name%%_*}"
		if printf '%s\n' "$applied" | grep -q "^${id} "; then
			continue # already applied — its bytes are frozen, verify_history owns it
		fi
		if grep -qiE '^[[:space:]]*(BEGIN|COMMIT|ROLLBACK)[[:space:]]*;' "$dir/$name"; then
			echo "error: $name contains a top-level BEGIN;/COMMIT;/ROLLBACK;." >&2
			echo "       Migrations must not manage their own transaction — the runner" >&2
			echo "       wraps each one in a single transaction together with its" >&2
			echo "       schema_migrations row, so the two commit as one. Remove those" >&2
			echo "       statements. Nothing was changed." >&2
			return 1
		fi
	done < <(migrations_names)

	while IFS= read -r name; do
		[ -n "$name" ] || continue
		id="${name%%_*}"
		if printf '%s\n' "$applied" | grep -q "^${id} "; then
			continue
		fi

		sha="$(migrations_sha "$dir/$name")"
		echo "    applying $name"
		if ! {
			printf 'BEGIN;\n'
			cat "$dir/$name"
			printf "\nINSERT INTO schema_migrations (id, sha256) VALUES (%s, '%s');\n" \
				"$((10#$id))" "$sha"
			printf 'COMMIT;\n'
		} | db_psql -q; then
			echo "" >&2
			echo "error: migration $name FAILED. It ran inside a transaction, so the" >&2
			echo "       database was rolled back and is EXACTLY as it was — nothing was" >&2
			echo "       half-applied. The server has not been restarted." >&2
			return 1
		fi
		pending=$((pending + 1))
	done < <(migrations_names)

	if [ "$pending" -eq 0 ]; then
		echo "    database schema is already up to date"
	else
		echo "    applied $pending migration(s)"
	fi
}

# Record EVERY migration as already-applied WITHOUT running it. For a FRESH
# install only, where `docs/schema.sql` has just created the whole schema (which
# schema_equivalence.rs proves equals baseline + every migration). Never call
# this on a database that was not just created from docs/schema.sql — it would
# mark migrations as applied that this database has never seen.
migrations_mark_all_applied() {
	local name id sha
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		id="${name%%_*}"
		sha="$(migrations_sha "$MIGRATIONS_DIR/$name")"
		printf "INSERT INTO schema_migrations (id, sha256) VALUES (%s, '%s') ON CONFLICT (id) DO NOTHING;\n" \
			"$((10#$id))" "$sha"
	done < <(migrations_names) | db_psql -q
	echo "    recorded $(migrations_names | wc -l) migration(s) as applied (fresh install)"
}
