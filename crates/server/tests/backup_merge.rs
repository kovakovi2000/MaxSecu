//! The DB-restore **merge** against a live Postgres (WSL `Ubuntu-22.04`, role/db
//! `maxsecu`). Each test stands up **two throwaway databases** — a `live` and a
//! `staged` (scratch) — both loaded from the real `docs/schema.sql`, seeds them
//! through the real `PgStore` write paths, then runs
//! [`restore_db_merge`](maxsecu_server::backup::restore_db_merge) across them.
//!
//! Two databases, not two schemas: [`merge::run`](maxsecu_server::backup) refuses
//! when any *other* connection to the live database is open (the server must be
//! stopped), and that guard is scoped `datname = current_database()` precisely so
//! the staged scratch database's connections do not count — which only holds when
//! staged is a genuinely separate database, exactly as production's
//! `createdb maxsecu_restore_<stamp>` makes it. The live pool is capped at ONE
//! connection so the guard sees only the merge's own transaction.
//!
//! Set `MAXSECU_TEST_PG` to override the connection string. An unreachable
//! Postgres **fails** the suite (the gate must run, never pass vacuously) unless
//! `MAXSECU_PG_OPTIONAL=1` downgrades it to a loud skip.

use std::sync::OnceLock;

use maxsecu_crypto::random_array;
use maxsecu_encoding::structs::{Genesis, Manifest, Stream};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileScope, FileType, Id, StreamType, Suite, Timestamp,
};
use maxsecu_encoding::{encode, RECOVERY_ID};
use maxsecu_server::backup::restore_db_merge;
use maxsecu_server::{parse_stage, GenesisInput, PgStore, StageInput, Store, WrapInput};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use tokio::sync::Mutex;

const SCHEMA_SQL: &str = include_str!("../../../docs/schema.sql");
const TS: u64 = 1_719_500_000_000;

fn base_url() -> String {
    std::env::var("MAXSECU_TEST_PG").unwrap_or_else(|_| {
        "postgres://maxsecu:maxsecu@localhost/maxsecu?sslmode=disable".to_owned()
    })
}

fn pg_unreachable_is_fatal(pg_optional: bool) -> bool {
    !pg_optional
}
fn pg_optional_env() -> bool {
    std::env::var("MAXSECU_PG_OPTIONAL").as_deref() == Ok("1")
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// `CREATE DATABASE` briefly accesses the template database; two running
/// concurrently can trip "source database is being accessed by other users", so
/// serialize just the creation (schema load afterwards touches no template).
fn create_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// A live database + a staged (scratch) database, each with its own pool, plus a
/// maintenance pool (to the base DB) used only to create/drop them.
struct MergeDb {
    admin: PgPool,
    live_pool: PgPool,
    staged_pool: PgPool,
    live: PgStore,
    staged: PgStore,
    live_db: String,
    staged_db: String,
}

async fn connect_db(url: &str, db: &str, max: u32) -> PgPool {
    let opts: PgConnectOptions = url.parse().unwrap();
    let opts = opts.database(db);
    PgPoolOptions::new()
        .max_connections(max)
        .connect_with(opts)
        .await
        .unwrap()
}

impl MergeDb {
    /// **Fails the suite** if Postgres is unreachable (the gate must run), unless
    /// `MAXSECU_PG_OPTIONAL=1`, in which case it returns `None` (loud skip).
    async fn setup() -> Option<MergeDb> {
        let url = base_url();
        let admin = match PgPoolOptions::new().max_connections(1).connect(&url).await {
            Ok(p) => p,
            Err(e) => {
                if pg_unreachable_is_fatal(pg_optional_env()) {
                    panic!(
                        "backup_merge: cannot reach Postgres at {url}: {e}\n\
                         Start Postgres (WSL Ubuntu-22.04, role/db `maxsecu`) or set \
                         MAXSECU_PG_OPTIONAL=1 to skip the PG suite."
                    );
                }
                eprintln!("SKIP backup_merge (MAXSECU_PG_OPTIONAL=1): {url}: {e}");
                return None;
            }
        };
        let suffix = hex(&random_array::<8>());
        let live_db = format!("mxmerge_l_{suffix}");
        let staged_db = format!("mxmerge_s_{suffix}");
        {
            let _g = create_lock().lock().await;
            for db in [&live_db, &staged_db] {
                sqlx::query(&format!("CREATE DATABASE \"{db}\""))
                    .execute(&admin)
                    .await
                    .expect("create throwaway database");
            }
        }
        // Live is capped at ONE connection: the pg_stat_activity guard counts
        // every OTHER connection to the live database, so a second idle pooled
        // connection would make the merge (correctly) refuse.
        let live_pool = connect_db(&url, &live_db, 1).await;
        let staged_pool = connect_db(&url, &staged_db, 4).await;
        for p in [&live_pool, &staged_pool] {
            sqlx::raw_sql(SCHEMA_SQL)
                .execute(p)
                .await
                .expect("load docs/schema.sql");
        }
        let live = PgStore::new(live_pool.clone());
        let staged = PgStore::new(staged_pool.clone());
        Some(MergeDb {
            admin,
            live_pool,
            staged_pool,
            live,
            staged,
            live_db,
            staged_db,
        })
    }

    async fn merge(&self, apply: bool) -> maxsecu_server::backup::MergePreview {
        restore_db_merge(&self.live_pool, &self.staged_pool, apply)
            .await
            .expect("merge runs")
    }

    async fn teardown(self) {
        self.live_pool.close().await;
        self.staged_pool.close().await;
        for db in [&self.live_db, &self.staged_db] {
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db}\" WITH (FORCE)"))
                .execute(&self.admin)
                .await;
        }
        self.admin.close().await;
    }
}

macro_rules! db_or_skip {
    () => {
        match MergeDb::setup().await {
            Some(db) => db,
            None => return,
        }
    };
}

// ---- seed helpers (mirror pg_store.rs; the real write paths) ----

async fn seed_user_on(pool: &PgPool, id: [u8; 16], name: &str) {
    sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1,$2,$3,$4)")
        .bind(&id[..])
        .bind(name)
        .bind(&[0xAAu8; 32][..])
        .bind(&[0xBBu8; 32][..])
        .execute(pool)
        .await
        .unwrap();
}

fn pg_manifest(file: [u8; 16], version: u64, author: [u8; 16]) -> Vec<u8> {
    encode(&Manifest {
        file_id: Id(file),
        version,
        file_type: FileType::Blog,
        alg: Suite::V1,
        chunk_size: 1 << 20,
        dek_commit: Bytes32([0xDC; 32]),
        streams: vec![
            Stream {
                stream_type: StreamType::Content,
                compression: Compression::None,
                chunk_count: 2,
                digest: Bytes32([0xC0; 32]),
            },
            Stream {
                stream_type: StreamType::Metadata,
                compression: Compression::None,
                chunk_count: 1,
                digest: Bytes32([0x2E; 32]),
            },
        ],
        recovery_present: true,
        author_id: Id(author),
        created_at: Timestamp(TS + version),
    })
}

fn pg_genesis(file: [u8; 16], owner: [u8; 16]) -> GenesisInput {
    GenesisInput {
        genesis_bytes: encode(&Genesis {
            file_id: Id(file),
            owner_id: Id(owner),
            owner_key_version: 1,
            created_at: Timestamp(TS),
        }),
        genesis_sig: [0x9A; 64],
    }
}

fn pg_stage(
    file: [u8; 16],
    version: u64,
    owner: [u8; 16],
    genesis: Option<GenesisInput>,
) -> StageInput {
    StageInput {
        file_id: file,
        caller_id: owner,
        file_type_advisory: FileType::Blog as u8 as i16,
        genesis,
        manifest_bytes: pg_manifest(file, version, owner),
        manifest_sig: [0x9B; 64],
        wraps: vec![
            WrapInput {
                recipient_id: owner,
                recipient_type: 1,
                wrapped_dek: vec![0xA1; 48],
                wrap_alg: 1,
                granted_by: owner,
                grant_bytes: vec![0xB1; 8],
                grant_sig: [0xC1; 64],
            },
            WrapInput {
                recipient_id: RECOVERY_ID.0,
                recipient_type: 2,
                wrapped_dek: vec![0xA2; 48],
                wrap_alg: 1,
                granted_by: owner,
                grant_bytes: vec![0xB2; 8],
                grant_sig: [0xC2; 64],
            },
        ],
        stream_totals: vec![(1, 2_000_000), (2, 256)],
        proposed_version: version,
        listed: true,
        bundle_id: None,
    }
}

fn wrap_row(recipient: [u8; 16], granted_by: [u8; 16], tag: u8) -> WrapInput {
    WrapInput {
        recipient_id: recipient,
        recipient_type: 1,
        wrapped_dek: vec![tag; 48],
        wrap_alg: 1,
        granted_by,
        grant_bytes: vec![tag; 8],
        grant_sig: [tag; 64],
    }
}

/// Stage + finalize one version through the real write path.
async fn stage_finalize(store: &PgStore, file: [u8; 16], owner: [u8; 16], version: u64) {
    let genesis = (version == 1).then(|| pg_genesis(file, owner));
    let inp = parse_stage(pg_stage(file, version, owner, genesis)).unwrap();
    store.stage_version(inp, TS + version).await.unwrap();
    store
        .finalize_version(file, version, owner, TS + version)
        .await
        .unwrap();
}

/// Build a file up to `up_to` finalized versions (1..=up_to).
async fn build_versions(store: &PgStore, file: [u8; 16], owner: [u8; 16], up_to: u64) {
    for v in 1..=up_to {
        stage_finalize(store, file, owner, v).await;
    }
}

async fn count(pool: &PgPool, sql: &str, file: &[u8; 16]) -> i64 {
    sqlx::query_scalar(sql)
        .bind(&file[..])
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn wrap_at(pool: &PgPool, file: [u8; 16], version: i64, recipient: [u8; 16]) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM file_key_wraps \
         WHERE file_id = $1 AND file_version = $2 AND recipient_id = $3",
    )
    .bind(&file[..])
    .bind(version)
    .bind(&recipient[..])
    .fetch_one(pool)
    .await
    .unwrap();
    n == 1
}

async fn current_version(pool: &PgPool, file: [u8; 16]) -> Option<i64> {
    sqlx::query_scalar("SELECT current_version FROM files WHERE file_id = $1")
        .bind(&file[..])
        .fetch_optional(pool)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------

/// **DISASTER RECOVERY MUST NOT BE ABLE TO FAIL ON AN INDEX.**
///
/// `merge_auth_nonces` inserts the bundle's `username` values verbatim, inside
/// the one transaction the whole restore runs in — so a single un-indexable row
/// anywhere in the bundle aborts the ENTIRE restore, not just that row.
///
/// `auth_nonces.username` is unbounded `TEXT` and `pg::nonce_key_col` hex-encodes
/// it (2×), so bundles taken before `http::MAX_SESSION_USERNAME_BYTES` existed can
/// carry a multi-megabyte claimed name. An abandoned challenge keeps `used_at`
/// NULL forever, which puts it INSIDE `auth_nonces_open_idx`. Had that index been
/// the obvious btree, this insert would die on "index row requires N bytes,
/// maximum size is 8191" and take the restore with it. It is a **hash** index
/// (migration 0003), which stores a 32-bit hash and has no entry-size ceiling —
/// this test is what holds that decision in place.
///
/// Note the live database here is loaded from `docs/schema.sql`, i.e. it already
/// HAS the index: this is the post-upgrade box the operator is restoring onto.
#[tokio::test]
async fn merge_restores_a_bundle_carrying_an_unindexable_nonce_username() {
    let db = db_or_skip!();

    // FIXTURE FIDELITY: the staged database models the RESTORED BUNDLE, and in
    // production it is `pg_restore`d from a dump of the box the backup was taken
    // on — a PRE-0003 server, which had no index on `auth_nonces` at all. Drop it
    // here so the staged side can hold the row a real old box could hold. The
    // LIVE side keeps the index (it is loaded from docs/schema.sql): that is the
    // upgraded box the operator is restoring onto, and it is the side under test.
    sqlx::query("DROP INDEX auth_nonces_open_idx")
        .execute(&db.staged_pool)
        .await
        .expect("staged models a pre-0003 bundle");

    // 128 000 hex chars = a 64 000-byte claimed name — 47× the 2704-byte btree
    // entry cap. Random, so pglz cannot compress it under the cap either (that
    // is why highly repetitive junk is NOT a valid fixture here).
    let long: String = sqlx::query_scalar(
        "SELECT string_agg(md5(random()::text), '') FROM generate_series(1, 4000)",
    )
    .fetch_one(&db.staged_pool)
    .await
    .unwrap();
    assert_eq!(
        long.len(),
        128_000,
        "fixture: the name must be way over 2704"
    );

    // The bundle's row: UNCONSUMED (used_at NULL ⇒ inside the partial index) and
    // long expired, exactly the residue a real pre-0003 box accumulates.
    sqlx::query(
        "INSERT INTO auth_nonces (nonce, username, expires_at) \
         VALUES ($1, $2, now() - interval '400 days')",
    )
    .bind(&[0x77u8; 32][..])
    .bind(&long)
    .execute(&db.staged_pool)
    .await
    .unwrap();
    // A second, ordinary row so "the merge inserted something" is not carried by
    // the abusive row alone.
    sqlx::query(
        "INSERT INTO auth_nonces (nonce, username, expires_at) \
         VALUES ($1, $2, now() + interval '60 seconds')",
    )
    .bind(&[0x78u8; 32][..])
    .bind(hex(b"alice"))
    .execute(&db.staged_pool)
    .await
    .unwrap();

    // THE ASSERTION: the restore completes. `merge` unwraps, so a failure here
    // is the "merge runs" expect — which is precisely the abort being caught.
    let preview = db.merge(true).await;
    assert_eq!(
        preview.per_table_inserts.get("auth_nonces"),
        Some(&2),
        "both bundle nonce rows must land, got {:?}",
        preview.per_table_inserts
    );

    // And the row is really there, indexed, and readable by the login lookup.
    let restored: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_nonces WHERE username = $1")
        .bind(&long)
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    assert_eq!(restored, 1, "the over-long row survived the restore");

    db.teardown().await;
}

/// Live rotated past the backup: the `= cur` gate drops every backed-up stream
/// and wrap, so a merge inserts nothing into the file family and strands nothing.
#[tokio::test]
async fn merge_with_live_ahead_strands_nothing() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xF1u8; 16];
    seed_user_on(&db.live_pool, owner, "owner").await;
    seed_user_on(&db.staged_pool, owner, "owner").await;

    build_versions(&db.staged, file, owner, 3).await; // backup knew 1..3
    build_versions(&db.live, file, owner, 5).await; // live is at 5

    let before_wraps_v5 = count(
        &db.live_pool,
        "SELECT count(*) FROM file_key_wraps WHERE file_id = $1 AND file_version = 5",
        &file,
    )
    .await;

    let preview = db.merge(true).await;

    assert!(
        preview.per_table_inserts.is_empty(),
        "a live-ahead merge inserts nothing, got {:?}",
        preview.per_table_inserts
    );
    // The two backed-up v3 wraps (owner + recovery) were considered and dropped
    // as superseded — the `= cur` gate, not luck.
    assert_eq!(preview.wraps_skipped_superseded, 2);
    assert_eq!(preview.subtrees_skipped_tombstoned, 0);
    assert_eq!(preview.files_restored_whole, 0);

    // No live row was touched.
    assert_eq!(current_version(&db.live_pool, file).await, Some(5));
    assert_eq!(
        count(
            &db.live_pool,
            "SELECT count(*) FROM file_key_wraps WHERE file_id = $1 AND file_version = 5",
            &file,
        )
        .await,
        before_wraps_v5
    );
    // Nothing sprayed into the superseded versions.
    assert_eq!(
        count(
            &db.live_pool,
            "SELECT count(*) FROM file_streams WHERE file_id = $1 AND version < 5",
            &file,
        )
        .await,
        0
    );
    db.teardown().await;
}

/// Live hard-deleted the file (tombstone, no live row): the whole subtree is
/// skipped — no zombie feed entry over ciphertext that no longer exists.
#[tokio::test]
async fn delete_then_restore_skips_the_subtree() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xF2u8; 16];
    seed_user_on(&db.live_pool, owner, "owner").await;
    seed_user_on(&db.staged_pool, owner, "owner").await;

    build_versions(&db.staged, file, owner, 1).await; // backup holds the file
    build_versions(&db.live, file, owner, 1).await;
    db.live.delete_file(file, owner).await.unwrap(); // …then live destroyed it

    let preview = db.merge(true).await;

    assert_eq!(preview.subtrees_skipped_tombstoned, 1);
    assert_eq!(preview.files_restored_whole, 0);
    // Not one file-family row came back.
    for (table, sql) in [
        ("files", "SELECT count(*) FROM files WHERE file_id = $1"),
        (
            "file_genesis",
            "SELECT count(*) FROM file_genesis WHERE file_id = $1",
        ),
        (
            "file_versions",
            "SELECT count(*) FROM file_versions WHERE file_id = $1",
        ),
        (
            "file_streams",
            "SELECT count(*) FROM file_streams WHERE file_id = $1",
        ),
        (
            "file_key_wraps",
            "SELECT count(*) FROM file_key_wraps WHERE file_id = $1",
        ),
    ] {
        assert_eq!(
            count(&db.live_pool, sql, &file).await,
            0,
            "{table} resurrected"
        );
        assert!(!preview.per_table_inserts.contains_key(table));
    }
    // The live tombstone count is unchanged -- not because the merge never writes
    // that table (the absence-record pass does), but because in THIS fixture the
    // staged database never deleted the file, so the bundle carries no tombstone
    // for it and the pass has nothing to insert.
    assert_eq!(
        count(
            &db.live_pool,
            "SELECT count(*) FROM file_tombstones WHERE file_id = $1",
            &file
        )
        .await,
        1
    );
    db.teardown().await;
}

/// A deleted `file_id` re-created in live carries an old tombstone AND a live
/// row. The live row WINS (operator decision): the subtree merges, and a
/// recipient present only in the backup is added back.
#[tokio::test]
async fn recreated_file_id_with_a_tombstone_still_merges() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let extra = [0x22u8; 16];
    let file = [0xF3u8; 16];
    seed_user_on(&db.live_pool, owner, "owner").await;
    seed_user_on(&db.live_pool, extra, "extra").await;
    seed_user_on(&db.staged_pool, owner, "owner").await;
    seed_user_on(&db.staged_pool, extra, "extra").await;

    // Live: create, delete (tombstone), then RE-create the same id.
    build_versions(&db.live, file, owner, 1).await;
    db.live.delete_file(file, owner).await.unwrap();
    build_versions(&db.live, file, owner, 1).await;

    // Staged (the backup) holds the same file plus a share to `extra` at v1.
    build_versions(&db.staged, file, owner, 1).await;
    db.staged
        .add_wrap(file, wrap_row(extra, owner, 0xB0), owner, TS + 9)
        .await
        .unwrap();

    assert!(
        !wrap_at(&db.live_pool, file, 1, extra).await,
        "precondition"
    );
    let preview = db.merge(true).await;

    assert_eq!(
        preview.subtrees_skipped_tombstoned, 0,
        "the live row must win"
    );
    assert_eq!(preview.files_restored_whole, 0);
    // The backed-up recipient came back on the live, current file.
    assert_eq!(preview.per_table_inserts.get("file_key_wraps"), Some(&1));
    assert!(wrap_at(&db.live_pool, file, 1, extra).await);
    assert_eq!(current_version(&db.live_pool, file).await, Some(1));
    db.teardown().await;
}

/// Live revoked a recipient (soft-revoke → `wrap_revocations` row). A merge must
/// NOT hand that de-authorized recipient their wrapped DEK back.
#[tokio::test]
async fn revoke_then_restore_does_not_resurrect_the_wrap() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r = [0x22u8; 16];
    let file = [0xF4u8; 16];
    seed_user_on(&db.live_pool, owner, "owner").await;
    seed_user_on(&db.live_pool, r, "recip").await;
    seed_user_on(&db.staged_pool, owner, "owner").await;
    seed_user_on(&db.staged_pool, r, "recip").await;

    // Staged (backup) still holds R's wrap.
    build_versions(&db.staged, file, owner, 1).await;
    db.staged
        .add_wrap(file, wrap_row(r, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();

    // Live shared to R, then revoked — the wrap is gone, a revocation recorded.
    build_versions(&db.live, file, owner, 1).await;
    db.live
        .add_wrap(file, wrap_row(r, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();
    db.live.delete_wrap(file, r, owner).await.unwrap();
    assert!(
        !wrap_at(&db.live_pool, file, 1, r).await,
        "precondition: R revoked"
    );

    let preview = db.merge(true).await;

    assert_eq!(preview.wraps_skipped_revoked, 1);
    assert_eq!(preview.wraps_skipped_superseded, 0);
    assert!(
        !wrap_at(&db.live_pool, file, 1, r).await,
        "a revoked recipient must not get their wrap back"
    );
    // owner + recovery conflicted; R was skipped → nothing inserted.
    assert!(!preview.per_table_inserts.contains_key("file_key_wraps"));
    db.teardown().await;
}

/// The correction #2 regression: a backup's wraps live at v3; live rotated to v4.
/// The `= cur` gate (NOT version existence) drops the v3 wraps wholesale, so a
/// recipient revoked *by rotation* is not resurrected.
#[tokio::test]
async fn rotation_revoked_wrap_is_not_resurrected() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let a = [0x22u8; 16];
    let b = [0x33u8; 16];
    let file = [0xF6u8; 16];
    for p in [&db.live_pool, &db.staged_pool] {
        seed_user_on(p, owner, "owner").await;
        seed_user_on(p, a, "aaa").await;
        seed_user_on(p, b, "bbb").await;
    }

    // Staged: file at v3, shared to A and B at v3.
    build_versions(&db.staged, file, owner, 3).await;
    db.staged
        .add_wrap(file, wrap_row(a, owner, 0xA0), owner, TS + 30)
        .await
        .unwrap();
    db.staged
        .add_wrap(file, wrap_row(b, owner, 0xB0), owner, TS + 31)
        .await
        .unwrap();

    // Live: rotated on to v4 (A and B not re-shared there).
    build_versions(&db.live, file, owner, 4).await;

    let preview = db.merge(true).await;

    // A + B (+ owner + recovery) at v3 are all superseded relative to cur = 4.
    assert_eq!(preview.wraps_skipped_superseded, 4);
    assert!(!preview.per_table_inserts.contains_key("file_key_wraps"));
    assert!(!wrap_at(&db.live_pool, file, 3, a).await);
    assert!(!wrap_at(&db.live_pool, file, 3, b).await);
    assert!(!wrap_at(&db.live_pool, file, 4, a).await);
    assert!(!wrap_at(&db.live_pool, file, 4, b).await);
    assert_eq!(current_version(&db.live_pool, file).await, Some(4));
    db.teardown().await;
}

/// The `= cur` gate is NOT enough on its own: an ABANDONED STAGING in the backup
/// can wear live's current version number.
///
/// `discard_unfinalized` refuses to GC a staged `cur+1` once the file has any
/// finalized version, so a backup taken mid-rotation carries that unfinalized
/// subtree. If live then finalizes `cur+1` with a DIFFERENT recipient set, the
/// abandoned staging's `file_version` now EQUALS live's `cur` and clears the gate.
/// No `wrap_revocations` row can stop it — that recipient was never granted in
/// live, so there is nothing to revoke.
///
/// Here: staged has v1 finalized plus an abandoned v2 staging that wraps to `a`;
/// live finalized a real v2 that does NOT include `a`. `a` must not come back.
#[tokio::test]
async fn an_abandoned_staging_at_lives_current_version_is_not_merged() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let a = [0x22u8; 16];
    let file = [0xF9u8; 16];
    for p in [&db.live_pool, &db.staged_pool] {
        seed_user_on(p, owner, "owner").await;
        seed_user_on(p, a, "aaa").await;
    }

    // Staged: v1 finalized, then v2 STAGED AND LEFT UNFINALIZED, carrying an extra
    // recipient `a` and an extra (Thumbnail) stream the real v2 will not have.
    build_versions(&db.staged, file, owner, 1).await;
    let mut abandoned = pg_stage(file, 2, owner, None);
    abandoned.wraps.push(wrap_row(a, owner, 0xA5));
    abandoned.stream_totals.push((3, 4_096)); // Thumbnail — absent from live's v2
    db.staged
        .stage_version(parse_stage(abandoned).unwrap(), TS + 2)
        .await
        .unwrap();

    // Prove the FIXTURE is what this test claims before asserting on the merge —
    // a staged v2 that never landed would make every assertion below vacuous.
    assert!(
        wrap_at(&db.staged_pool, file, 2, a).await,
        "fixture: staged v2 has no wrap for `a`"
    );
    let staged_unfinalized: i64 = count(
        &db.staged_pool,
        "SELECT count(*) FROM file_versions WHERE file_id = $1 AND version = 2 AND finalized = false",
        &file,
    )
    .await;
    assert_eq!(
        staged_unfinalized, 1,
        "fixture: staged v2 is not unfinalized"
    );

    // Live: v2 really was finalized — owner + recovery only, no `a`, no thumbnail.
    build_versions(&db.live, file, owner, 2).await;
    assert_eq!(current_version(&db.live_pool, file).await, Some(2));

    let preview = db.merge(true).await;

    // Nothing from the abandoned staging may land, even though its version == cur.
    assert!(
        !wrap_at(&db.live_pool, file, 2, a).await,
        "an abandoned staging's wrap resurrected a recipient live never granted"
    );
    assert!(!preview.per_table_inserts.contains_key("file_key_wraps"));
    assert!(!preview.per_table_inserts.contains_key("file_streams"));
    let thumb: i64 = count(
        &db.live_pool,
        "SELECT count(*) FROM file_streams WHERE file_id = $1 AND stream_type = 3",
        &file,
    )
    .await;
    assert_eq!(
        thumb, 0,
        "a zombie stream from the abandoned staging was merged; its blob_ref was never uploaded"
    );
    // The unfinalized version row itself was already excluded by merge_file_versions.
    let vers: i64 = count(
        &db.live_pool,
        "SELECT count(*) FROM file_versions WHERE file_id = $1",
        &file,
    )
    .await;
    assert_eq!(vers, 2);
    db.teardown().await;
}

/// Merge is add-only: it never UPDATEs or DELETEs a live row. A staged row that
/// collides with a live one (same PK, different content) leaves the live row
/// exactly as it was, and live counts only ever grow.
#[tokio::test]
async fn merge_only_ever_inserts() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xF7u8; 16]; // shared file
    let lost = [0xF8u8; 16]; // only in the backup → restored whole

    // Same user_id in both, but a DIFFERENT status/roles in staged — a merge that
    // updated on conflict would overwrite live's row.
    sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub, status) VALUES ($1,$2,$3,$4,'active')")
        .bind(&owner[..]).bind("owner").bind(&[0xAAu8;32][..]).bind(&[0xBBu8;32][..])
        .execute(&db.live_pool).await.unwrap();
    sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub, status) VALUES ($1,$2,$3,$4,'suspended')")
        .bind(&owner[..]).bind("owner").bind(&[0x01u8;32][..]).bind(&[0x02u8;32][..])
        .execute(&db.staged_pool).await.unwrap();

    build_versions(&db.live, file, owner, 1).await;
    build_versions(&db.staged, file, owner, 1).await;
    build_versions(&db.staged, lost, owner, 1).await; // live never had it

    let users_before: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    let files_before: i64 = sqlx::query_scalar("SELECT count(*) FROM files")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();

    let preview = db.merge(true).await;

    // The live user is byte-for-byte what it was — NOT overwritten by staged.
    let (status, enc): (String, Vec<u8>) =
        sqlx::query_as("SELECT status, enc_pub FROM users WHERE user_id = $1")
            .bind(&owner[..])
            .fetch_one(&db.live_pool)
            .await
            .unwrap();
    assert_eq!(status, "active", "merge must not update a live row");
    assert_eq!(enc, vec![0xAAu8; 32]);

    // Counts only grew: the lost file was restored, nothing was removed.
    let users_after: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    let files_after: i64 = sqlx::query_scalar("SELECT count(*) FROM files")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    assert_eq!(
        users_after, users_before,
        "no new user (same id conflicted)"
    );
    assert_eq!(files_after, files_before + 1, "the lost file was restored");
    assert_eq!(preview.files_restored_whole, 1);
    assert_eq!(current_version(&db.live_pool, lost).await, Some(1));
    db.teardown().await;
}

/// `control_log` and `auth_events` are skipped entirely — the append-guard fires
/// before conflict arbitration and both carry an IDENTITY sequence.
#[tokio::test]
async fn merge_leaves_control_log_and_auth_events_untouched() {
    let db = db_or_skip!();
    let issuer = [0x11u8; 16];
    seed_user_on(&db.staged_pool, issuer, "issuer").await;

    // Staged has one of each; live has none.
    let rec = encode(&maxsecu_encoding::structs::Revocation {
        scope: FileScope::Specific(Id([0x0A; 16])),
        revoked_user_id: Id([0x99; 16]),
        revoked_capability: None,
        from_version: 1,
        revocation_epoch: 1,
        prev_head: Bytes32([0u8; 32]),
        issued_by: Id(issuer),
        co_signed_by: None,
        created_at: Timestamp(TS),
    });
    db.staged
        .append_control(rec, [0xCC; 64], None)
        .await
        .unwrap();
    sqlx::query("INSERT INTO auth_events (action, result) VALUES ('login','ok')")
        .execute(&db.staged_pool)
        .await
        .unwrap();

    let preview = db.merge(true).await;

    let cl: i64 = sqlx::query_scalar("SELECT count(*) FROM control_log")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    let ae: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_events")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    assert_eq!(cl, 0, "control_log must be skipped");
    assert_eq!(ae, 0, "auth_events must be skipped");
    assert!(!preview.per_table_inserts.contains_key("control_log"));
    assert!(!preview.per_table_inserts.contains_key("auth_events"));
    // The issuer user still merged (proves the run succeeded, not aborted).
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
    db.teardown().await;
}

/// Bare `ON CONFLICT DO NOTHING` (no target): a staged user whose username
/// collides with a *different* live user_id is silently skipped — not an abort.
/// An explicit `ON CONFLICT (user_id)` target would let the username unique
/// violation escape and kill the whole restore.
#[tokio::test]
async fn merge_survives_a_username_collision() {
    let db = db_or_skip!();
    let live_alice = [0x11u8; 16];
    let staged_alice = [0x22u8; 16]; // different id, SAME username
    let zoe = [0x33u8; 16]; // unique — proves the run continued

    seed_user_on(&db.live_pool, live_alice, "alice").await;
    seed_user_on(&db.staged_pool, staged_alice, "alice").await;
    seed_user_on(&db.staged_pool, zoe, "zoe").await;

    let preview = db.merge(true).await;

    // "alice" still resolves to the LIVE user; the colliding staged row was
    // suppressed, not merged, and did not abort the transaction.
    let alice_id: Vec<u8> =
        sqlx::query_scalar("SELECT user_id FROM users WHERE username = 'alice'")
            .fetch_one(&db.live_pool)
            .await
            .unwrap();
    assert_eq!(alice_id, live_alice.to_vec());
    let staged_alice_present: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE user_id = $1")
            .bind(&staged_alice[..])
            .fetch_one(&db.live_pool)
            .await
            .unwrap();
    assert_eq!(
        staged_alice_present, 0,
        "the colliding row must NOT be inserted"
    );
    let zoe_present: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE user_id = $1")
        .bind(&zoe[..])
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    assert_eq!(zoe_present, 1, "the run continued past the collision");
    assert_eq!(preview.per_table_inserts.get("users"), Some(&1)); // only zoe
    db.teardown().await;
}

/// The server must be STOPPED: any other connection to the live database makes
/// the merge refuse (proves the `pg_stat_activity` guard is not vacuous — every
/// happy-path test above would pass even if the guard never fired).
#[tokio::test]
async fn merge_refuses_when_another_connection_is_open() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    seed_user_on(&db.staged_pool, owner, "owner").await;

    // A second, independent connection to the LIVE database — a stand-in for a
    // still-running server.
    let intruder = connect_db(&base_url(), &db.live_db, 1).await;
    let held = intruder.acquire().await.unwrap();

    let err = restore_db_merge(&db.live_pool, &db.staged_pool, true)
        .await
        .expect_err("merge must refuse while another connection is live");
    let msg = err.to_string();
    assert!(
        msg.contains("stop the server"),
        "expected a server-still-up refusal, got: {msg}"
    );
    // Nothing was merged.
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    assert_eq!(users, 0);

    drop(held);
    intruder.close().await;
    db.teardown().await;
}

/// `--dry-run` (`apply = false`) previews the exact same numbers but writes
/// nothing: the identical insert pass runs inside the transaction and is rolled
/// back.
#[tokio::test]
async fn dry_run_previews_but_changes_nothing() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let lost = [0xF9u8; 16];
    seed_user_on(&db.live_pool, owner, "owner").await;
    seed_user_on(&db.staged_pool, owner, "owner").await;
    build_versions(&db.staged, lost, owner, 1).await; // live lacks it entirely

    let dry = db.merge(false).await;
    assert_eq!(dry.files_restored_whole, 1);
    assert_eq!(dry.per_table_inserts.get("files"), Some(&1));
    // Nothing was actually written.
    assert_eq!(current_version(&db.live_pool, lost).await, None);

    // The apply run reports the identical numbers and DOES write.
    let wet = db.merge(true).await;
    assert_eq!(wet.per_table_inserts, dry.per_table_inserts);
    assert_eq!(wet.files_restored_whole, dry.files_restored_whole);
    assert_eq!(current_version(&db.live_pool, lost).await, Some(1));
    db.teardown().await;
}

/// ADVERSARIAL (phase-2 stage-3 verification, added by the skeptic pass): the
/// revocation gate must be PRECISE per-recipient inside ONE batch at the SAME
/// (file, current version) — skip the recipient live revoked while still
/// restoring a co-recipient live legitimately lost. An over-broad skip would
/// strand R2 (a backward-compat access break); an under-broad one would resurrect
/// R1's revoked DEK. No existing test mixes both directions in a single wrap
/// batch, so this is the tight spot between the two failure modes.
#[tokio::test]
async fn revocation_gate_is_per_recipient_in_a_mixed_batch() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r1 = [0x22u8; 16]; // revoked in live → must NOT come back
    let r2 = [0x33u8; 16]; // never in live → legitimately lost, MUST be restored
    let file = [0xFAu8; 16];
    for p in [&db.live_pool, &db.staged_pool] {
        seed_user_on(p, owner, "owner").await;
        seed_user_on(p, r1, "r1").await;
        seed_user_on(p, r2, "r2").await;
    }

    // Live: file at v1, shared to R1, then R1 revoked. R2 never present.
    build_versions(&db.live, file, owner, 1).await;
    db.live
        .add_wrap(file, wrap_row(r1, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();
    db.live.delete_wrap(file, r1, owner).await.unwrap();

    // Staged (backup): file at v1, shared to BOTH R1 and R2.
    build_versions(&db.staged, file, owner, 1).await;
    db.staged
        .add_wrap(file, wrap_row(r1, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();
    db.staged
        .add_wrap(file, wrap_row(r2, owner, 0xB0), owner, TS + 3)
        .await
        .unwrap();

    assert!(
        !wrap_at(&db.live_pool, file, 1, r1).await,
        "precondition: R1 revoked in live"
    );
    assert!(
        !wrap_at(&db.live_pool, file, 1, r2).await,
        "precondition: R2 absent in live"
    );

    let preview = db.merge(true).await;

    assert_eq!(preview.wraps_skipped_revoked, 1, "exactly R1 skipped");
    assert_eq!(preview.wraps_skipped_superseded, 0);
    assert_eq!(
        preview.per_table_inserts.get("file_key_wraps"),
        Some(&1),
        "exactly R2 restored (owner + recovery conflicted, R1 skipped)"
    );
    assert!(
        !wrap_at(&db.live_pool, file, 1, r1).await,
        "a revoked recipient must NOT get their wrap back"
    );
    assert!(
        wrap_at(&db.live_pool, file, 1, r2).await,
        "a legitimately-lost recipient MUST be restored"
    );
    db.teardown().await;
}

/// The username-collision case that has FILES attached. `merge_users` suppresses
/// the staged row (the live username wins), so nothing in live carries the
/// backup's `user_id` — and `files.owner_id REFERENCES users(user_id)` is a
/// non-deferrable FK that `ON CONFLICT DO NOTHING` cannot absorb. Left to
/// Postgres the whole restore dies on `files_owner_id_fkey` at the exact moment
/// the operator is recovering from a disaster; the merge must name the account
/// instead so they know what to do.
#[tokio::test]
async fn username_collision_with_owned_files_names_the_user() {
    let db = db_or_skip!();
    let live_alice = [0x11u8; 16];
    let staged_alice = [0x22u8; 16]; // different id, SAME username
    let file = [0xF0u8; 16];

    seed_user_on(&db.live_pool, live_alice, "alice").await;
    seed_user_on(&db.staged_pool, staged_alice, "alice").await;
    build_versions(&db.staged, file, staged_alice, 1).await;

    let err = restore_db_merge(&db.live_pool, &db.staged_pool, true)
        .await
        .expect_err("a staged owner that cannot be merged must not reach the FK");
    let msg = err.to_string();
    assert!(
        msg.contains("alice"),
        "expected the colliding account to be named, got: {msg}"
    );
    assert!(
        !msg.contains("files_owner_id_fkey"),
        "expected an actionable error, got a raw FK abort: {msg}"
    );
    db.teardown().await;
}

/// The bundle's OWN absence records must ride across. `file_tombstones` and
/// `wrap_revocations` are the two tables a merge is gated on; a merge into a
/// rebuilt database that dropped them on the floor would leave live believing
/// nothing was ever deleted or revoked — and the NEXT merge, from an older bundle
/// that still holds the rows, would resurrect exactly what migration 0002 exists
/// to block. The second merge here is that next merge.
#[tokio::test]
async fn merge_carries_the_bundles_own_absence_records() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r = [0x22u8; 16];
    let destroyed = [0xE1u8; 16];
    let shared = [0xE2u8; 16];
    for p in [&db.live_pool, &db.staged_pool] {
        seed_user_on(p, owner, "owner").await;
        seed_user_on(p, r, "recip").await;
    }

    // The bundle records both absences: a file its owner destroyed, and a
    // recipient whose read access the owner took away.
    build_versions(&db.staged, destroyed, owner, 1).await;
    db.staged.delete_file(destroyed, owner).await.unwrap();
    build_versions(&db.staged, shared, owner, 1).await;
    db.staged
        .add_wrap(shared, wrap_row(r, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();
    db.staged.delete_wrap(shared, r, owner).await.unwrap();

    // Live is a rebuilt database: it holds neither absence.
    let live_tombs: i64 = sqlx::query_scalar("SELECT count(*) FROM file_tombstones")
        .fetch_one(&db.live_pool)
        .await
        .unwrap();
    assert_eq!(live_tombs, 0, "precondition: live is rebuilt");

    let preview = db.merge(true).await;

    assert_eq!(preview.per_table_inserts.get("file_tombstones"), Some(&1));
    assert_eq!(preview.per_table_inserts.get("wrap_revocations"), Some(&1));
    assert_eq!(
        count(
            &db.live_pool,
            "SELECT count(*) FROM file_tombstones WHERE file_id = $1",
            &destroyed
        )
        .await,
        1,
        "the owner's delete was forgotten"
    );
    assert_eq!(
        count(
            &db.live_pool,
            "SELECT count(*) FROM wrap_revocations WHERE file_id = $1",
            &shared
        )
        .await,
        1,
        "the owner's revocation was forgotten"
    );

    // Now the merge those rows exist to gate: an older bundle that still holds
    // R's wrap. Live's freshly-carried revocation must block it.
    db.staged
        .add_wrap(shared, wrap_row(r, owner, 0xB0), owner, TS + 5)
        .await
        .unwrap();
    let second = db.merge(true).await;
    assert_eq!(second.wraps_skipped_revoked, 1);
    assert!(
        !wrap_at(&db.live_pool, shared, 1, r).await,
        "a revocation the bundle recorded did not survive the first merge"
    );
    db.teardown().await;
}

/// …but the bundle's own tombstone must NOT gate the merge carrying it. The
/// absence records are read from LIVE only, so they are merged last, after
/// `read_live_facts`. `stage_version` re-creates a deleted `file_id` freely, so a
/// bundle can hold a tombstone AND the file that id was re-used for; gating on
/// the bundle's own tombstone would skip that live subtree and lose, on a rebuilt
/// box, a file the backup is holding.
#[tokio::test]
async fn a_bundles_own_tombstone_does_not_gate_its_own_merge() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xE3u8; 16];
    seed_user_on(&db.live_pool, owner, "owner").await;
    seed_user_on(&db.staged_pool, owner, "owner").await;

    // The bundle: create, delete (tombstone), then RE-create the same id.
    build_versions(&db.staged, file, owner, 1).await;
    db.staged.delete_file(file, owner).await.unwrap();
    build_versions(&db.staged, file, owner, 1).await;
    assert_eq!(
        count(
            &db.staged_pool,
            "SELECT count(*) FROM file_tombstones WHERE file_id = $1",
            &file
        )
        .await,
        1,
        "fixture: the bundle must hold both the tombstone and the re-created file"
    );
    assert_eq!(current_version(&db.staged_pool, file).await, Some(1));

    // Live lost everything.
    let preview = db.merge(true).await;

    assert_eq!(
        preview.subtrees_skipped_tombstoned, 0,
        "the bundle's own tombstone gated the merge carrying it"
    );
    assert_eq!(preview.files_restored_whole, 1);
    assert_eq!(current_version(&db.live_pool, file).await, Some(1));
    assert_eq!(
        count(
            &db.live_pool,
            "SELECT count(*) FROM file_key_wraps WHERE file_id = $1",
            &file
        )
        .await,
        2,
        "the re-created file's wraps must be restored with it"
    );
    // …and the tombstone still came across for the next merge to be gated on.
    assert_eq!(
        count(
            &db.live_pool,
            "SELECT count(*) FROM file_tombstones WHERE file_id = $1",
            &file
        )
        .await,
        1
    );
    db.teardown().await;
}

/// A bundle whose `pg_dump` predates migration 0002 materializes a scratch
/// database with no `file_tombstones` / `wrap_revocations` at all. Reading a
/// missing relation raises, so without the `to_regclass` check "this bundle is
/// old" would become "this bundle cannot be restored" — a rollback to a
/// pre-0002 backup is exactly when an operator needs one to work.
#[tokio::test]
async fn a_bundle_predating_the_absence_tables_still_merges() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let lost = [0xE4u8; 16];
    seed_user_on(&db.staged_pool, owner, "owner").await;
    build_versions(&db.staged, lost, owner, 1).await;
    for t in ["file_tombstones", "wrap_revocations"] {
        sqlx::query(&format!("DROP TABLE {t}"))
            .execute(&db.staged_pool)
            .await
            .unwrap();
    }

    let preview = db.merge(true).await;

    assert_eq!(preview.files_restored_whole, 1);
    assert_eq!(current_version(&db.live_pool, lost).await, Some(1));
    assert!(!preview.per_table_inserts.contains_key("file_tombstones"));
    assert!(!preview.per_table_inserts.contains_key("wrap_revocations"));
    db.teardown().await;
}

/// …and it must count only the backends that could actually race it. Since PG 10
/// `pg_stat_activity` lists the server's own background processes too, and while
/// most report a NULL `datname`, an autovacuum worker reports the database it is
/// vacuuming — so an unfiltered count refuses the restore with "stop the server"
/// at the exact moment the operator has already stopped it.
///
/// Autovacuum cannot be summoned on demand (`autovacuum_naptime` is a minute), so
/// this uses the other non-client backend that attaches to a database: a parallel
/// worker. One client connection runs a deliberately parallel, deliberately slow
/// query; the merge must report **one** other connection — the client backend —
/// not the worker(s) underneath it.
#[tokio::test]
async fn the_stopped_server_guard_counts_only_client_backends() {
    let db = db_or_skip!();

    let intruder = connect_db(&base_url(), &db.live_db, 1).await;
    sqlx::raw_sql(
        "CREATE TABLE parallel_bait AS SELECT g FROM generate_series(1,16) g; \
         CREATE FUNCTION slow(x int) RETURNS int LANGUAGE plpgsql PARALLEL SAFE \
         AS $$ BEGIN PERFORM pg_sleep(1); RETURN x; END $$;",
    )
    .execute(&intruder)
    .await
    .unwrap();
    let bait = intruder.clone();
    let query = tokio::spawn(async move {
        // ~16s of work handed to the workers, so they are still alive when the
        // merge below reads pg_stat_activity. The result is never collected.
        let _ = sqlx::raw_sql(
            "SET max_parallel_workers_per_gather = 2; SET parallel_setup_cost = 0; \
             SET parallel_tuple_cost = 0; SET min_parallel_table_scan_size = 0; \
             SET parallel_leader_participation = off; \
             SELECT sum(slow(g)) FROM parallel_bait;",
        )
        .execute(&bait)
        .await;
    });

    // Prove the FIXTURE before asserting on the guard: with no worker attached to
    // the live database this test would pass either way.
    let mut workers = 0i64;
    for _ in 0..200 {
        workers = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = $1 AND backend_type = 'parallel worker'",
        )
        .bind(&db.live_db)
        .fetch_one(&db.admin)
        .await
        .unwrap();
        if workers > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        workers > 0,
        "fixture: no parallel worker attached to the live database"
    );

    let err = restore_db_merge(&db.live_pool, &db.staged_pool, true)
        .await
        .expect_err("merge must still refuse — a client backend IS open");
    let msg = err.to_string();
    assert!(
        msg.contains("has 1 other connection(s)"),
        "the guard counted {workers} non-client backend(s): {msg}"
    );

    query.abort();
    db.teardown().await;
}
