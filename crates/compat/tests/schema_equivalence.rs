//! The DB half of the backward-compatibility gate.
//!
//! > **A fresh install and an upgraded install must be the same product.**
//!
//! `docs/schema.sql` is loaded ONLY by `scripts/install-server.sh`, on a FRESH
//! install. An already-deployed server never sees it again — it only ever gets
//! `migrations/NNNN_*.sql` from `scripts/upgrade-server.sh`. So the two paths can
//! silently diverge, and when they do, the *same* server binary meets two
//! *different* databases: new code, old schema, every existing user stranded.
//! (Before this gate there were no migrations at all, so ANY edit to schema.sql
//! stranded every existing deployment.)
//!
//! This file closes that with three layers:
//!
//! 1. **`compat/schema.lock`** pins the sha256 of `docs/schema.sql` and of every
//!    migration. A bare schema edit fails offline, immediately, with a message
//!    saying why. An *applied* migration can never be edited (the server records
//!    its digest in `schema_migrations` and refuses to upgrade if it changes).
//! 2. **Structural checks** on the migration set (numbering, no self-managed
//!    transactions) that mirror what the shell runner enforces on the VPS.
//! 3. **The load-bearing test** — build schema A from `docs/schema.sql` and
//!    schema B from `0001_baseline.sql` + every later migration in one live
//!    Postgres, then compare their catalogs: tables, columns, constraints,
//!    indexes, TRIGGERS, trigger functions and comments. Any divergence fails.
//!
//! Triggers are compared deliberately: the append-only enforcement
//! (`maxsecu_forbid_update_delete`, `maxsecu_forbid_delete`, the control-log
//! hash-chain guard) lives in triggers and their plpgsql bodies. Omitting them
//! would let this gate go green while append-only silently vanished from every
//! upgraded server — a security regression, not merely a compat one.
//!
//! The Postgres test SKIPS when no database is reachable (this dev box has none)
//! and runs for real in the CI `pg-gate` job.

use std::path::{Path, PathBuf};
use std::time::Duration;

use maxsecu_compat::{sha256_hex, CHECKLIST};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::Row;

/// The fresh-install schema. Read-only, and the baseline is defined to equal it.
const SCHEMA_SQL: &str = include_str!("../../../docs/schema.sql");

/// Same default as `crates/server/tests/pg_store.rs`, so the CI `pg-gate` job's
/// Postgres service container is found with no extra configuration.
const DEFAULT_PG: &str = "postgres://maxsecu:maxsecu@localhost/maxsecu?sslmode=disable";

// --------------------------------------------------------------------------- //
// Repo paths + digests
// --------------------------------------------------------------------------- //

/// `<repo>` — `maxsecu_compat::fixtures_root()` is `<repo>/compat/fixtures`.
/// (A local helper on purpose: `compat/schema.lock` is not a fixture, and the
/// library's corpus helpers are owned by another part of the gate.)
fn repo_root() -> PathBuf {
    maxsecu_compat::fixtures_root()
        .parent()
        .and_then(Path::parent)
        .expect("compat/fixtures is two levels below the repo root")
        .to_path_buf()
}

fn migrations_dir() -> PathBuf {
    repo_root().join("migrations")
}

/// SHA-256 of a file with CRLF normalized to LF, so the lock is identical on a
/// Windows checkout and on Linux CI. (`.gitattributes` already forces LF, so
/// this is the plain file digest in practice — it just cannot become a
/// line-ending trap later.)
fn digest_of(path: &Path) -> String {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}. {CHECKLIST}", path.display()));
    let lf: Vec<u8> = String::from_utf8(bytes)
        .unwrap_or_else(|_| panic!("{} is not UTF-8", path.display()))
        .replace("\r\n", "\n")
        .into_bytes();
    sha256_hex(&lf)
}

/// One migration on disk.
struct Migration {
    id: u32,
    /// Zero-padded, as it appears in the filename and in `schema_migrations`.
    id_str: String,
    name: String,
    path: PathBuf,
}

/// Every `migrations/NNNN_<slug>.sql`, in numeric order.
///
/// Also enforces the runner's rule that EVERY `.sql` in the directory is
/// numbered: an unnumbered one would never be applied to an existing server,
/// while a fresh install (which loads `docs/schema.sql` wholesale) would have it.
fn migrations() -> Vec<Migration> {
    let dir = migrations_dir();
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}. {CHECKLIST}", dir.display()));

    for entry in entries {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".sql") {
            continue; // apply.sh (the runner) also lives here
        }

        let (id_str, rest) = name.split_once('_').unwrap_or_else(|| {
            panic!(
                "migrations/{name} is not named NNNN_<slug>.sql. An unnumbered .sql is \
                 never applied by scripts/upgrade-server.sh, so every EXISTING server \
                 would silently miss it while fresh installs got it. {CHECKLIST}"
            )
        });
        assert!(
            id_str.len() == 4 && id_str.bytes().all(|b| b.is_ascii_digit()) && !rest.is_empty(),
            "migrations/{name} is not named NNNN_<slug>.sql (4-digit zero-padded id). \
             The runner applies migrations in numeric order and matches them by that \
             prefix. {CHECKLIST}"
        );

        out.push(Migration {
            id: id_str.parse().expect("4 ascii digits"),
            id_str: id_str.to_string(),
            name,
            path: entry.path(),
        });
    }

    out.sort_by_key(|m| m.id);
    assert!(
        !out.is_empty(),
        "migrations/ holds no NNNN_*.sql at all — expected at least 0001_baseline.sql. {CHECKLIST}"
    );
    out
}

/// `compat/schema.lock` as `(key, value)` pairs in file order.
fn schema_lock() -> Vec<(String, String)> {
    let path = repo_root().join("compat").join("schema.lock");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing {}: {e}. {CHECKLIST}", path.display()));

    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some(k), Some(v)) => out.push((k.to_string(), v.to_string())),
            _ => panic!(
                "malformed line in {}: {line:?} (want `<key>  <value>`)",
                path.display()
            ),
        }
    }
    out
}

fn lock_get(lock: &[(String, String)], key: &str) -> String {
    lock.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| {
            panic!("compat/schema.lock has no `{key}` entry. {CHECKLIST}");
        })
}

// --------------------------------------------------------------------------- //
// Offline gate — runs everywhere, no Postgres needed
// --------------------------------------------------------------------------- //

/// `docs/schema.sql` may not change without a migration carrying the same change
/// to every already-deployed server.
#[test]
fn compat_schema_lock_pins_docs_schema_sql() {
    let lock = schema_lock();
    let want = lock_get(&lock, "schema");
    let got = digest_of(&repo_root().join("docs").join("schema.sql"));

    assert_eq!(
        got,
        want,
        "\n\nDB SCHEMA CHANGED: docs/schema.sql no longer matches compat/schema.lock.\n\
         \n\
         docs/schema.sql is applied ONLY on a FRESH install. Existing deployments — real\n\
         users, real data, no admin escape hatch — only ever receive migrations/NNNN_*.sql\n\
         via scripts/upgrade-server.sh. A bare schema edit therefore gives new installs a\n\
         schema that NO existing server will ever have, and the one server binary you ship\n\
         then breaks on every old database.\n\
         \n\
         To change the schema:\n\
           1. ADD migrations/NNNN_<slug>.sql with the change (never edit an applied one:\n\
              the server records each migration's sha256 and refuses to upgrade if it moves).\n\
           2. Mirror the SAME change into docs/schema.sql.\n\
           3. Re-pin compat/schema.lock: new `schema` digest, new `NNNN` line, bump `schema_head`.\n\
           4. compat_fresh_install_equals_upgraded_install (CI pg-gate) then proves the two\n\
              paths produce an identical database.\n\
         {CHECKLIST}\n"
    );
}

/// Every migration is pinned, and pinned to what is on disk. Editing an applied
/// migration is the one thing the upgrade path can never recover from.
#[test]
fn compat_schema_lock_pins_every_migration() {
    let lock = schema_lock();
    let migs = migrations();

    for m in &migs {
        let want = lock_get(&lock, &m.id_str);
        let got = digest_of(&m.path);
        assert_eq!(
            got, want,
            "\n\nMIGRATION CHANGED: migrations/{} no longer matches compat/schema.lock.\n\
             \n\
             A migration is FROZEN once it can have been applied. Every server that ran it\n\
             recorded its sha256 in `schema_migrations`, and scripts/upgrade-server.sh\n\
             REFUSES to upgrade when a recorded digest no longer matches disk — because the\n\
             edit can no longer be delivered to that server, so it and a fresh install would\n\
             be different products forever.\n\
             \n\
             Put the change in a NEW migrations/NNNN_<slug>.sql instead.\n\
             {CHECKLIST}\n",
            m.name
        );
    }

    // Every locked migration must still exist (deletion is the same break).
    for (key, _) in &lock {
        if key == "schema" || key == "schema_head" {
            continue;
        }
        assert!(
            migs.iter().any(|m| &m.id_str == key),
            "compat/schema.lock pins migration {key}, but migrations/{key}_*.sql is gone. \
             A migration may be ADDED, never removed — servers that already applied it can \
             never un-apply it. Restore the file. {CHECKLIST}"
        );
    }

    // Contiguous, from 1, no duplicates: the runner applies strictly in numeric
    // order, so a gap or a reused id makes "which migrations has this server
    // seen?" unanswerable.
    for (i, m) in migs.iter().enumerate() {
        let want = i as u32 + 1;
        assert_eq!(
            m.id, want,
            "migration ids must be contiguous from 0001 (found {} where {want:04} was \
             expected). Gaps and duplicates make the applied-set ambiguous. {CHECKLIST}",
            m.name
        );
    }

    // `schema_head` = the migration that brings a database up to the pinned
    // docs/schema.sql. Bumping it is the explicit, reviewable act of saying "I
    // shipped this schema change to existing servers too".
    let head: u32 = lock_get(&lock, "schema_head")
        .parse()
        .expect("schema_head must be an integer");
    let max = migs.last().expect("at least one migration").id;
    assert_eq!(
        head, max,
        "compat/schema.lock `schema_head` is {head} but the newest migration is {max:04}. \
         schema_head must name the migration that brings an existing database up to the \
         pinned docs/schema.sql — otherwise nobody can tell whether the last schema edit \
         was ever delivered to existing servers. {CHECKLIST}"
    );
}

/// A migration must not open or close its own transaction: `migrations/apply.sh`
/// wraps each one in ONE transaction together with its `schema_migrations` row,
/// so applying and recording commit together. A stray `COMMIT;` would break that
/// atomicity and could leave a migration applied but unrecorded — re-applied on
/// every future upgrade.
#[test]
fn compat_migrations_do_not_manage_their_own_transaction() {
    for m in migrations() {
        let sql = std::fs::read_to_string(&m.path).expect("read migration");
        for (n, line) in sql.lines().enumerate() {
            let t = line.trim().to_ascii_uppercase();
            // Statement-level only. plpgsql's bare `BEGIN` (no semicolon) is fine.
            let bad = t.starts_with("BEGIN;")
                || t.starts_with("COMMIT;")
                || t.starts_with("ROLLBACK;")
                || t == "BEGIN ;"
                || t == "COMMIT ;";
            assert!(
                !bad,
                "migrations/{}:{}: `{}` — a migration must not manage its own transaction. \
                 The runner (migrations/apply.sh) wraps it in one transaction with its \
                 schema_migrations INSERT so the two are atomic. {CHECKLIST}",
                m.name,
                n + 1,
                line.trim()
            );
        }
    }
}

/// The baseline is, by definition, what every existing server already runs — so
/// re-running it on such a server (which is exactly what the first upgrade does,
/// with an empty `schema_migrations`) must be a no-op, not an error.
#[test]
fn compat_baseline_is_idempotent_by_construction() {
    let baseline = migrations_dir().join("0001_baseline.sql");
    let sql = std::fs::read_to_string(&baseline).expect("read 0001_baseline.sql");

    let bare_table = sql
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("CREATE TABLE ") && !t.contains("IF NOT EXISTS")
        })
        .count();
    assert_eq!(
        bare_table, 0,
        "0001_baseline.sql has a bare `CREATE TABLE` — it must be `CREATE TABLE IF NOT \
         EXISTS`. The first upgrade of an EXISTING server applies this baseline to a \
         database that already has every table; a bare CREATE would abort the upgrade. \
         {CHECKLIST}"
    );

    // Same for indexes.
    let bare_index = sql
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            (t.starts_with("CREATE INDEX ") || t.starts_with("CREATE UNIQUE INDEX "))
                && !t.contains("IF NOT EXISTS")
        })
        .count();
    assert_eq!(
        bare_index, 0,
        "0001_baseline.sql has a bare `CREATE INDEX` — it must be `IF NOT EXISTS`. {CHECKLIST}"
    );

    // Every CREATE TRIGGER must be preceded by a DROP TRIGGER IF EXISTS (Postgres
    // has no `CREATE TRIGGER IF NOT EXISTS`).
    let creates = sql
        .lines()
        .filter(|l| l.trim_start().starts_with("CREATE TRIGGER "))
        .count();
    let drops = sql
        .lines()
        .filter(|l| l.trim_start().starts_with("DROP TRIGGER IF EXISTS "))
        .count();
    assert!(
        creates > 0 && drops == creates,
        "0001_baseline.sql has {creates} CREATE TRIGGER but {drops} DROP TRIGGER IF EXISTS. \
         Postgres has no CREATE TRIGGER IF NOT EXISTS, so each one needs a preceding drop \
         or the baseline is not re-runnable on an existing server. Triggers are where \
         append-only lives — they must survive every upgrade. {CHECKLIST}"
    );
}

// --------------------------------------------------------------------------- //
// The load-bearing test — needs a live Postgres
// --------------------------------------------------------------------------- //

/// Where to find Postgres, and whether the operator named it explicitly.
///
/// * `DATABASE_URL` / `MAXSECU_TEST_PG` set → explicit: an unreachable server is
///   a hard FAILURE (a gate that skips itself in CI is no gate).
/// * neither set → try the same default the `pg-gate` service container uses; if
///   nothing is there (this dev box), SKIP loudly.
fn pg_url() -> (String, bool) {
    if let Ok(u) = std::env::var("DATABASE_URL") {
        if !u.is_empty() {
            return (u, true);
        }
    }
    if let Ok(u) = std::env::var("MAXSECU_TEST_PG") {
        if !u.is_empty() {
            return (u, true);
        }
    }
    (DEFAULT_PG.to_string(), false)
}

fn rand_suffix() -> String {
    let b = maxsecu_crypto::random_array::<6>();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A pool whose `search_path` is one throwaway schema, so unqualified DDL lands
/// there (the same trick `crates/server/tests/pg_store.rs` uses).
async fn pool_on(url: &str, schema: &str) -> PgPool {
    let opts: PgConnectOptions = url.parse().expect("DATABASE_URL is not a valid PG url");
    let opts = opts.options([("search_path", schema)]);
    PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .expect("connect with search_path")
}

/// Introspect one schema and return the aspect's rows, schema-name-normalized and
/// sorted, so two schemas are directly comparable.
async fn probe(admin: &PgPool, sql: &str, schema: &str) -> Vec<String> {
    let rows = sqlx::query(sql)
        .bind(schema)
        .fetch_all(admin)
        .await
        .unwrap_or_else(|e| panic!("introspection query failed: {e}\n{sql}"));

    let mut out: Vec<String> = rows
        .iter()
        .map(|r| {
            let s: String = r.get(0);
            // pg_get_*def() qualifies with the (throwaway, random) schema name.
            s.replace(schema, "<schema>")
        })
        .collect();
    out.sort();
    out
}

/// Tables (a table with zero columns would otherwise be invisible).
const Q_TABLES: &str = "
    SELECT concat_ws(' | ', table_name::text, table_type::text)
    FROM information_schema.tables
    WHERE table_schema = $1";

/// Columns: name, position, type, nullability, default, identity.
const Q_COLUMNS: &str = "
    SELECT concat_ws(' | ',
        table_name::text,
        ordinal_position::text,
        column_name::text,
        data_type::text,
        udt_name::text,
        is_nullable::text,
        coalesce(column_default::text, '~none~'),
        coalesce(character_maximum_length::text, '~none~'),
        coalesce(numeric_precision::text, '~none~'),
        coalesce(numeric_scale::text, '~none~'),
        coalesce(datetime_precision::text, '~none~'),
        is_identity::text,
        coalesce(identity_generation::text, '~none~'))
    FROM information_schema.columns
    WHERE table_schema = $1";

/// PRIMARY KEY / UNIQUE / FOREIGN KEY / CHECK, by their full definitions.
const Q_CONSTRAINTS: &str = "
    SELECT concat_ws(' | ',
        rel.relname::text,
        con.conname::text,
        con.contype::text,
        pg_get_constraintdef(con.oid))
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
    WHERE ns.nspname = $1";

/// Indexes, including partial/predicate indexes (the control-log epoch uniques).
const Q_INDEXES: &str = "
    SELECT concat_ws(' | ',
        tab.relname::text,
        idx.relname::text,
        pg_get_indexdef(i.indexrelid))
    FROM pg_index i
    JOIN pg_class idx ON idx.oid = i.indexrelid
    JOIN pg_class tab ON tab.oid = i.indrelid
    JOIN pg_namespace ns ON ns.oid = idx.relnamespace
    WHERE ns.nspname = $1";

/// TRIGGERS. Append-only lives here — never drop this from the comparison.
/// `tgisinternal` excludes the hidden triggers Postgres creates for FKs.
const Q_TRIGGERS: &str = "
    SELECT concat_ws(' | ',
        tab.relname::text,
        t.tgname::text,
        pg_get_triggerdef(t.oid))
    FROM pg_trigger t
    JOIN pg_class tab ON tab.oid = t.tgrelid
    JOIN pg_namespace ns ON ns.oid = tab.relnamespace
    WHERE ns.nspname = $1 AND NOT t.tgisinternal";

/// The trigger FUNCTIONS' full source. A trigger can be present and identical
/// while the plpgsql body that actually enforces append-only was gutted.
const Q_FUNCTIONS: &str = "
    SELECT concat_ws(' | ',
        p.proname::text,
        pg_get_function_identity_arguments(p.oid),
        pg_get_functiondef(p.oid))
    FROM pg_proc p
    JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = $1";

/// COMMENT ON COLUMN — the "advisory only, do not trust" notes. Not access-
/// critical, but if the two paths disagree here they are not the same product.
const Q_COMMENTS: &str = "
    SELECT concat_ws(' | ',
        tab.relname::text,
        att.attname::text,
        col_description(tab.oid, att.attnum))
    FROM pg_attribute att
    JOIN pg_class tab ON tab.oid = att.attrelid
    JOIN pg_namespace ns ON ns.oid = tab.relnamespace
    WHERE ns.nspname = $1
      AND att.attnum > 0
      AND NOT att.attisdropped
      AND col_description(tab.oid, att.attnum) IS NOT NULL";

/// Compare one aspect and append a human diff to `report` on divergence.
fn compare(aspect: &str, blast: &str, fresh: &[String], upgraded: &[String], report: &mut String) {
    if fresh == upgraded {
        return;
    }
    report.push_str(&format!("\n--- {aspect} DIVERGED ---\n{blast}\n"));
    for row in fresh {
        if !upgraded.contains(row) {
            report.push_str(&format!("  only in FRESH (docs/schema.sql)      : {row}\n"));
        }
    }
    for row in upgraded {
        if !fresh.contains(row) {
            report.push_str(&format!("  only in UPGRADED (migrations/*.sql)  : {row}\n"));
        }
    }
}

/// **The load-bearing test.** A fresh install and an upgraded install must be the
/// same product.
#[tokio::test]
async fn compat_fresh_install_equals_upgraded_install() {
    let (url, explicit) = pg_url();

    // Fail fast when nothing is listening: sqlx's 30s default acquire timeout
    // would otherwise stall every dev run by half a minute just to skip.
    let admin = match PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            assert!(
                !explicit,
                "compat schema-equivalence: cannot reach Postgres at {url}: {e}\n\
                 DATABASE_URL / MAXSECU_TEST_PG is set, so this gate must actually RUN — it \
                 is what proves an upgraded server ends up with the same schema as a fresh \
                 one. Start Postgres or unset the variable."
            );
            eprintln!(
                "SKIP compat_fresh_install_equals_upgraded_install: no Postgres at {url} ({e}).\n\
                 Set DATABASE_URL to run it. It runs for real in the CI `pg-gate` job."
            );
            return;
        }
    };

    let suffix = rand_suffix();
    let fresh_schema = format!("mxcompat_fresh_{suffix}");
    let upgraded_schema = format!("mxcompat_upgraded_{suffix}");

    for s in [&fresh_schema, &upgraded_schema] {
        sqlx::query(&format!("CREATE SCHEMA \"{s}\""))
            .execute(&admin)
            .await
            .expect("create throwaway schema");
    }

    // A: a FRESH install — exactly what scripts/install-server.sh loads.
    let fresh_pool = pool_on(&url, &fresh_schema).await;
    sqlx::raw_sql(SCHEMA_SQL)
        .execute(&fresh_pool)
        .await
        .expect("load docs/schema.sql");

    // B: an UPGRADED install — the baseline plus every migration, in numeric
    // order, exactly as scripts/upgrade-server.sh applies them. NB: the runner
    // creates `schema_migrations` itself (it is bookkeeping, not product schema),
    // so no migration may create it — and this comparison would catch it if one did.
    let upgraded_pool = pool_on(&url, &upgraded_schema).await;
    for m in migrations() {
        let sql = std::fs::read_to_string(&m.path).expect("read migration");
        sqlx::raw_sql(&sql)
            .execute(&upgraded_pool)
            .await
            .unwrap_or_else(|e| panic!("migrations/{} failed to apply: {e}", m.name));
    }

    let mut report = String::new();
    let aspects: [(&str, &str, &str); 7] = [
        (
            "TABLES",
            Q_TABLES,
            "A table exists on one path and not the other. One of fresh installs or \
             existing servers has no place to put its rows.",
        ),
        (
            "COLUMNS",
            Q_COLUMNS,
            "A column, its type, its nullability or its default differs. The one server \
             binary you ship would run against BOTH of these databases — on one of them it \
             breaks, and there is no admin escape hatch for the users on it.",
        ),
        (
            "CONSTRAINTS",
            Q_CONSTRAINTS,
            "A PRIMARY KEY / UNIQUE / FOREIGN KEY / CHECK differs. These are integrity \
             invariants the server relies on (e.g. the recovery <=> RECOVERY_ID check, the \
             single-use registration key PK). If the only difference is an auto-generated \
             constraint NAME, give the constraint an explicit name in both files.",
        ),
        (
            "INDEXES",
            Q_INDEXES,
            "An index differs. The control-log per-scope epoch uniques are correctness, not \
             performance: without them a revocation epoch can be reused.",
        ),
        (
            "TRIGGERS",
            Q_TRIGGERS,
            "A TRIGGER differs. APPEND-ONLY LIVES IN TRIGGERS: directory_bindings and \
             control_log immutability, the file_genesis / file_versions guards, and the \
             control-log hash-chain linkage. A missing trigger on the upgraded path means \
             every upgraded server silently loses append-only enforcement — a SECURITY \
             regression, not just a compat one.",
        ),
        (
            "TRIGGER FUNCTIONS",
            Q_FUNCTIONS,
            "A plpgsql function body differs. The trigger can look identical while the code \
             that actually refuses the UPDATE/DELETE is gone.",
        ),
        (
            "COLUMN COMMENTS",
            Q_COMMENTS,
            "A COMMENT ON COLUMN differs. Not access-critical, but the two install paths are \
             then demonstrably not producing the same database — fix the drift.",
        ),
    ];

    for (aspect, sql, blast) in aspects {
        let a = probe(&admin, sql, &fresh_schema).await;
        let b = probe(&admin, sql, &upgraded_schema).await;
        compare(aspect, blast, &a, &b, &mut report);
    }

    // Drop the throwaway schemas BEFORE asserting, so a failure does not litter
    // the database (and CI can re-run cleanly).
    fresh_pool.close().await;
    upgraded_pool.close().await;
    for s in [&fresh_schema, &upgraded_schema] {
        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{s}\" CASCADE"))
            .execute(&admin)
            .await;
    }

    assert!(
        report.is_empty(),
        "\n\nA FRESH INSTALL AND AN UPGRADED INSTALL ARE NOT THE SAME PRODUCT.\n\
         \n\
         docs/schema.sql (what scripts/install-server.sh gives a NEW server) and\n\
         migrations/0001_baseline.sql + migrations/* (all an EXISTING server ever gets from\n\
         scripts/upgrade-server.sh) built DIFFERENT databases:\n\
         {report}\n\
         Every schema change must be made in BOTH: add migrations/NNNN_<slug>.sql for the\n\
         servers that already exist, mirror it into docs/schema.sql for the ones that don't\n\
         yet, and re-pin compat/schema.lock.\n\
         {CHECKLIST}\n"
    );
}
