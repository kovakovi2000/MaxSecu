//! The DB-merge step — the one cross-database operation, in Rust.
//!
//! `pg_dump -Fc` is an opaque archive only `pg_restore` reads, and no single SQL
//! statement can join a live database to a scratch one, so the merge cannot be a
//! `dblink`/`postgres_fdw` `INSERT..SELECT`. The driver `pg_restore`s the sealed
//! dump into a throwaway `maxsecu_restore_<stamp>` database; this function reads
//! the source rows from that scratch DB and the tombstones + `current_version`
//! from **live**, applies [`gate`](super::gate), and `INSERT … ON CONFLICT DO
//! NOTHING`s the survivors back into live in FK order. The server must be STOPPED
//! first — the gate reads live then inserts, and a concurrent `delete_file` /
//! `delete_wrap` would resurrect exactly what the gate exists to block, which no
//! isolation level can fix.
//!
//! # Never-gated, gated, skipped
//!
//! * **Never gated** (`users`, `directory_bindings`, `registration_keys`,
//!   `first_admin_claim`, `recovery_account`, `sessions`, `auth_nonces`): merged
//!   whole. A live row always wins on conflict, so a consumed registration key
//!   (marked, not deleted) or a renamed user cannot be clobbered.
//! * **Tombstone/revocation gated** (`files`, `file_genesis`, `file_versions`,
//!   `file_streams`, `file_key_wraps`): see [`gate`](super::gate).
//! * **Skipped entirely** (`control_log`, `auth_events`): `control_log`'s
//!   `BEFORE INSERT` append-guard fires *before* conflict arbitration, so
//!   `DO NOTHING` cannot save the transaction, and both carry an `IDENTITY`
//!   sequence a bulk insert would desync. The reason is the guard, not "there is
//!   no `DELETE FROM`" — that argument proves too much (it would skip every table).
//! * **The absence records** (`file_tombstones`, `wrap_revocations`): merged
//!   whole, add-only, and **last**. They are the two tables migration 0002 added
//!   to write down a deliberate absence, and they are what gates a merge — so a
//!   bundle restored into a rebuilt database must carry its own delete/revoke
//!   history across, or the next merge from an older bundle resurrects exactly
//!   what 0002 exists to block. Their `BEFORE UPDATE OR DELETE` guard never fires
//!   on `INSERT`, so unlike `control_log` they are safe to bulk-insert.
//!
//! # Conflict target and unnest
//!
//! Every insert uses **bare** `ON CONFLICT DO NOTHING` (no target). An explicit
//! target arbitrates only that one index, so a `users.username` unique violation
//! would abort the whole restore instead of yielding to the live row. `users` and
//! `directory_bindings` are inserted **row by row** because their `roles TEXT[]`
//! column cannot ride a parallel-array `unnest`; every other table bulk-inserts
//! through `unnest`.
//!
//! # `apply` vs dry-run
//!
//! `apply == false` is the `--dry-run` / plan path. It runs the **identical**
//! insert pass inside the same `SERIALIZABLE` transaction and then **rolls it
//! back**, so the returned [`MergePreview`] counts are the real
//! `ON CONFLICT DO NOTHING` `rows_affected` — a dry run and an apply cannot
//! diverge, because they are the same code differing only in commit vs rollback.
//! Merge never updates or deletes a live row: it is add-only.

use std::collections::{BTreeSet, HashMap};
use std::io;

use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;

use super::gate::{self, FileGate, WrapVerdict};
use super::{BackupError, LiveFacts, MergePreview};

/// Merge the `staged` scratch database into `live`, gated on live's tombstones
/// and `current_version`. Returns what it did (or, when `apply` is false, what it
/// *would* do). This is the exact signature the
/// [`restore_db_merge`](super::restore_db_merge) call site drives.
pub async fn run(live: &PgPool, staged: &PgPool, apply: bool) -> Result<MergePreview, BackupError> {
    let mut tx = live.begin().await?;
    // Must be the first statement in the transaction.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;

    // The server must be stopped. Any other connection to the live database can
    // commit a delete_file / delete_wrap between our read of the live facts and
    // our inserts, resurrecting precisely what the gate exists to block — and no
    // isolation level fixes it (a snapshot re-inserts the deleted rows;
    // SERIALIZABLE turns the race into a retry, not a correct merge). This is
    // scoped to `current_database()` on purpose: the staged scratch DB is a
    // *different* database, so its connections must not count.
    //
    // Only *client* backends can run a `delete_file`/`delete_wrap`, and since PG
    // 10 `pg_stat_activity` also lists the server's own background processes. Most
    // report a NULL `datname`, but an autovacuum worker reports the database it is
    // vacuuming — so without this filter a restore can be refused with "stop the
    // server" at the exact moment the operator has already stopped it, purely
    // because autovacuum happened to wake up on the live database.
    let others: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity \
         WHERE datname = current_database() AND pid <> pg_backend_pid() \
           AND backend_type = 'client backend'",
    )
    .fetch_one(&mut *tx)
    .await?;
    if others > 0 {
        return Err(BackupError::ServerStillConnected { others });
    }

    let live_facts = read_live_facts(&mut tx).await?;
    let mut preview = MergePreview::default();

    // Never-gated tables, FK order: users precedes files.
    let suppressed = merge_users(&mut tx, staged, &mut preview).await?;
    let unmerged_owners = unmerged_users(&mut tx, suppressed).await?;
    merge_directory_bindings(&mut tx, staged, &mut preview).await?;
    merge_registration_keys(&mut tx, staged, &mut preview).await?;
    merge_first_admin_claim(&mut tx, staged, &mut preview).await?;
    merge_recovery_account(&mut tx, staged, &mut preview).await?;
    merge_sessions(&mut tx, staged, &mut preview).await?;
    merge_auth_nonces(&mut tx, staged, &mut preview).await?;

    // The tombstone/revocation-gated file family. merge_files reads the staged
    // `files` once, builds the gate, and inserts the survivors; the rest gate
    // their rows against it.
    let gate = merge_files(&mut tx, staged, &live_facts, &unmerged_owners, &mut preview).await?;
    preview.subtrees_skipped_tombstoned = gate.skipped_tombstoned();
    preview.files_restored_whole = gate.restored_whole();
    merge_file_genesis(&mut tx, staged, &gate, &mut preview).await?;
    merge_file_versions(&mut tx, staged, &gate, &mut preview).await?;
    merge_file_streams(&mut tx, staged, &gate, &mut preview).await?;
    merge_file_key_wraps(&mut tx, staged, &gate, &live_facts, &mut preview).await?;

    // The bundle's own absence records, carried across LAST and deliberately so.
    // `read_live_facts` has already run, so these rows cannot gate the merge that
    // is carrying them — which is the point. `stage_version` re-creates a deleted
    // `file_id` freely, so a bundle can hold a tombstone AND the live subtree of
    // the file that id was re-used for; gating on the bundle's own tombstone would
    // then skip that subtree and destroy, on a rebuilt box, data the backup is
    // holding. Only LIVE's absences decide what this merge may re-insert.
    merge_file_tombstones(&mut tx, staged, &mut preview).await?;
    merge_wrap_revocations(&mut tx, staged, &mut preview).await?;

    if apply {
        tx.commit().await?;
    } else {
        // The dry run performed the identical inserts; discard them. The counts in
        // `preview` are already the real rows_affected.
        tx.rollback().await?;
    }
    Ok(preview)
}

type Tx<'a> = Transaction<'a, Postgres>;

/// Read a 16-byte id column, defending against a non-16-byte `BYTEA` the schema's
/// `octet_length` CHECK should already prevent.
fn get16(row: &PgRow, col: &str) -> Result<[u8; 16], BackupError> {
    let v: Vec<u8> = row.try_get(col)?;
    v.try_into().map_err(|v: Vec<u8>| {
        BackupError::Io(io::Error::other(format!(
            "column {col}: expected 16 bytes, got {}",
            v.len()
        )))
    })
}

/// Record the `ON CONFLICT DO NOTHING` `rows_affected` for a table — only when it
/// added something, so the preview and its `Display` stay to the point.
fn record_inserts(preview: &mut MergePreview, table: &str, n: u64) {
    if n > 0 {
        *preview
            .per_table_inserts
            .entry(table.to_owned())
            .or_insert(0) += n;
    }
}

/// The append-only truth a merge is gated on, read from the **live** database
/// inside the merge transaction (a consistent snapshot on the inserting
/// connection).
async fn read_live_facts(tx: &mut Tx<'_>) -> Result<LiveFacts, BackupError> {
    let mut facts = LiveFacts::default();

    for r in sqlx::query("SELECT file_id FROM file_tombstones")
        .fetch_all(&mut **tx)
        .await?
        .iter()
    {
        facts.tombstoned.insert(get16(r, "file_id")?);
    }
    for r in sqlx::query("SELECT file_id, current_version FROM files")
        .fetch_all(&mut **tx)
        .await?
        .iter()
    {
        let fid = get16(r, "file_id")?;
        facts.live_files.insert(fid);
        facts
            .current_version
            .insert(fid, r.try_get::<i64, _>("current_version")?);
    }
    for r in sqlx::query("SELECT file_id, file_version, recipient_id FROM wrap_revocations")
        .fetch_all(&mut **tx)
        .await?
        .iter()
    {
        facts.revoked.insert((
            get16(r, "file_id")?,
            r.try_get::<i64, _>("file_version")?,
            get16(r, "recipient_id")?,
        ));
    }
    Ok(facts)
}

// ---- never-gated tables ----

/// `users` — row by row (the `roles TEXT[]` column blocks `unnest`).
///
/// Returns the `(user_id, username)` of every staged row the insert did **not**
/// add, which is not the same thing as "already in live": a bare
/// `ON CONFLICT DO NOTHING` also swallows a `username` unique violation raised by
/// a live account carrying a *different* `user_id`. Those ids never appear in
/// live, and `files.owner_id` is an FK to them — see [`unmerged_users`].
async fn merge_users(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<Vec<(Vec<u8>, String)>, BackupError> {
    let rows = sqlx::query(
        "SELECT user_id, username, enc_pub, sig_pub, key_version, roles, status, \
         enrolled_at, signed_at FROM users",
    )
    .fetch_all(staged)
    .await?;
    let mut inserted = 0u64;
    let mut suppressed = Vec::new();
    for r in &rows {
        let res = sqlx::query(
            "INSERT INTO users \
             (user_id, username, enc_pub, sig_pub, key_version, roles, status, \
              enrolled_at, signed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
        )
        .bind(r.try_get::<Vec<u8>, _>("user_id")?)
        .bind(r.try_get::<String, _>("username")?)
        .bind(r.try_get::<Vec<u8>, _>("enc_pub")?)
        .bind(r.try_get::<Vec<u8>, _>("sig_pub")?)
        .bind(r.try_get::<i64, _>("key_version")?)
        .bind(r.try_get::<Vec<String>, _>("roles")?)
        .bind(r.try_get::<String, _>("status")?)
        .bind(r.try_get::<OffsetDateTime, _>("enrolled_at")?)
        .bind(r.try_get::<Option<OffsetDateTime>, _>("signed_at")?)
        .execute(&mut **tx)
        .await?;
        if res.rows_affected() == 0 {
            suppressed.push((
                r.try_get::<Vec<u8>, _>("user_id")?,
                r.try_get::<String, _>("username")?,
            ));
        }
        inserted += res.rows_affected();
    }
    record_inserts(preview, "users", inserted);
    Ok(suppressed)
}

/// Narrow the staged users the insert did not add down to those live genuinely
/// does **not** have, keyed by `user_id` and carrying the username for the error
/// message.
///
/// Almost every suppressed row is the ordinary case — live already holds the same
/// `user_id`, so nothing is missing — and `rows_affected` alone cannot tell that
/// apart from a `username` collision under a different id. Ask live directly.
async fn unmerged_users(
    tx: &mut Tx<'_>,
    suppressed: Vec<(Vec<u8>, String)>,
) -> Result<HashMap<Vec<u8>, String>, BackupError> {
    let mut absent: HashMap<Vec<u8>, String> = suppressed.into_iter().collect();
    if absent.is_empty() {
        return Ok(absent);
    }
    let ids: Vec<Vec<u8>> = absent.keys().cloned().collect();
    for r in sqlx::query("SELECT user_id FROM users WHERE user_id = ANY($1::bytea[])")
        .bind(&ids)
        .fetch_all(&mut **tx)
        .await?
        .iter()
    {
        absent.remove(&r.try_get::<Vec<u8>, _>("user_id")?);
    }
    Ok(absent)
}

/// `directory_bindings` — row by row (the `roles TEXT[]` column blocks `unnest`).
async fn merge_directory_bindings(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows = sqlx::query(
        "SELECT user_id, key_version, enc_pub, sig_pub, roles, not_before, not_after, \
         binding_bytes, directory_signature, created_at FROM directory_bindings",
    )
    .fetch_all(staged)
    .await?;
    let mut inserted = 0u64;
    for r in &rows {
        let res = sqlx::query(
            "INSERT INTO directory_bindings \
             (user_id, key_version, enc_pub, sig_pub, roles, not_before, not_after, \
              binding_bytes, directory_signature, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
        )
        .bind(r.try_get::<Vec<u8>, _>("user_id")?)
        .bind(r.try_get::<i64, _>("key_version")?)
        .bind(r.try_get::<Vec<u8>, _>("enc_pub")?)
        .bind(r.try_get::<Vec<u8>, _>("sig_pub")?)
        .bind(r.try_get::<Vec<String>, _>("roles")?)
        .bind(r.try_get::<OffsetDateTime, _>("not_before")?)
        .bind(r.try_get::<OffsetDateTime, _>("not_after")?)
        .bind(r.try_get::<Vec<u8>, _>("binding_bytes")?)
        .bind(r.try_get::<Vec<u8>, _>("directory_signature")?)
        .bind(r.try_get::<OffsetDateTime, _>("created_at")?)
        .execute(&mut **tx)
        .await?;
        inserted += res.rows_affected();
    }
    record_inserts(preview, "directory_bindings", inserted);
    Ok(())
}

async fn merge_registration_keys(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows =
        sqlx::query("SELECT key_hash, issued_at, expires_at, used_at FROM registration_keys")
            .fetch_all(staged)
            .await?;
    let mut key_hash = Vec::new();
    let mut issued_at = Vec::new();
    let mut expires_at = Vec::new();
    let mut used_at: Vec<Option<OffsetDateTime>> = Vec::new();
    for r in &rows {
        key_hash.push(r.try_get::<Vec<u8>, _>("key_hash")?);
        issued_at.push(r.try_get::<OffsetDateTime, _>("issued_at")?);
        expires_at.push(r.try_get::<OffsetDateTime, _>("expires_at")?);
        used_at.push(r.try_get::<Option<OffsetDateTime>, _>("used_at")?);
    }
    if key_hash.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO registration_keys (key_hash, issued_at, expires_at, used_at) \
         SELECT * FROM unnest($1::bytea[], $2::timestamptz[], $3::timestamptz[], $4::timestamptz[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&key_hash)
    .bind(&issued_at)
    .bind(&expires_at)
    .bind(&used_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "registration_keys", res.rows_affected());
    Ok(())
}

async fn merge_first_admin_claim(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows = sqlx::query("SELECT id, claimed_at FROM first_admin_claim")
        .fetch_all(staged)
        .await?;
    let mut id = Vec::new();
    let mut claimed_at = Vec::new();
    for r in &rows {
        id.push(r.try_get::<bool, _>("id")?);
        claimed_at.push(r.try_get::<OffsetDateTime, _>("claimed_at")?);
    }
    if id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO first_admin_claim (id, claimed_at) \
         SELECT * FROM unnest($1::boolean[], $2::timestamptz[]) ON CONFLICT DO NOTHING",
    )
    .bind(&id)
    .bind(&claimed_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "first_admin_claim", res.rows_affected());
    Ok(())
}

async fn merge_recovery_account(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows =
        sqlx::query("SELECT id, enc_pub, sig_pub, mlkem_pub, registered_at FROM recovery_account")
            .fetch_all(staged)
            .await?;
    let mut id = Vec::new();
    let mut enc_pub = Vec::new();
    let mut sig_pub = Vec::new();
    let mut mlkem_pub: Vec<Option<Vec<u8>>> = Vec::new();
    let mut registered_at = Vec::new();
    for r in &rows {
        id.push(r.try_get::<bool, _>("id")?);
        enc_pub.push(r.try_get::<Vec<u8>, _>("enc_pub")?);
        sig_pub.push(r.try_get::<Vec<u8>, _>("sig_pub")?);
        mlkem_pub.push(r.try_get::<Option<Vec<u8>>, _>("mlkem_pub")?);
        registered_at.push(r.try_get::<OffsetDateTime, _>("registered_at")?);
    }
    if id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO recovery_account (id, enc_pub, sig_pub, mlkem_pub, registered_at) \
         SELECT * FROM unnest($1::boolean[], $2::bytea[], $3::bytea[], $4::bytea[], $5::timestamptz[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&id)
    .bind(&enc_pub)
    .bind(&sig_pub)
    .bind(&mlkem_pub)
    .bind(&registered_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "recovery_account", res.rows_affected());
    Ok(())
}

async fn merge_sessions(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows = sqlx::query(
        "SELECT token_hash, user_id, tls_exporter, issued_at, expires_at, revoked_at FROM sessions",
    )
    .fetch_all(staged)
    .await?;
    let mut token_hash = Vec::new();
    let mut user_id = Vec::new();
    let mut tls_exporter = Vec::new();
    let mut issued_at = Vec::new();
    let mut expires_at = Vec::new();
    let mut revoked_at: Vec<Option<OffsetDateTime>> = Vec::new();
    for r in &rows {
        token_hash.push(r.try_get::<Vec<u8>, _>("token_hash")?);
        user_id.push(r.try_get::<Vec<u8>, _>("user_id")?);
        tls_exporter.push(r.try_get::<Vec<u8>, _>("tls_exporter")?);
        issued_at.push(r.try_get::<OffsetDateTime, _>("issued_at")?);
        expires_at.push(r.try_get::<OffsetDateTime, _>("expires_at")?);
        revoked_at.push(r.try_get::<Option<OffsetDateTime>, _>("revoked_at")?);
    }
    if token_hash.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO sessions \
         (token_hash, user_id, tls_exporter, issued_at, expires_at, revoked_at) \
         SELECT * FROM unnest($1::bytea[], $2::bytea[], $3::bytea[], $4::timestamptz[], \
         $5::timestamptz[], $6::timestamptz[]) ON CONFLICT DO NOTHING",
    )
    .bind(&token_hash)
    .bind(&user_id)
    .bind(&tls_exporter)
    .bind(&issued_at)
    .bind(&expires_at)
    .bind(&revoked_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "sessions", res.rows_affected());
    Ok(())
}

async fn merge_auth_nonces(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows =
        sqlx::query("SELECT nonce, username, issued_at, expires_at, used_at FROM auth_nonces")
            .fetch_all(staged)
            .await?;
    let mut nonce = Vec::new();
    let mut username = Vec::new();
    let mut issued_at = Vec::new();
    let mut expires_at = Vec::new();
    let mut used_at: Vec<Option<OffsetDateTime>> = Vec::new();
    for r in &rows {
        nonce.push(r.try_get::<Vec<u8>, _>("nonce")?);
        username.push(r.try_get::<String, _>("username")?);
        issued_at.push(r.try_get::<OffsetDateTime, _>("issued_at")?);
        expires_at.push(r.try_get::<OffsetDateTime, _>("expires_at")?);
        used_at.push(r.try_get::<Option<OffsetDateTime>, _>("used_at")?);
    }
    if nonce.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO auth_nonces (nonce, username, issued_at, expires_at, used_at) \
         SELECT * FROM unnest($1::bytea[], $2::text[], $3::timestamptz[], $4::timestamptz[], \
         $5::timestamptz[]) ON CONFLICT DO NOTHING",
    )
    .bind(&nonce)
    .bind(&username)
    .bind(&issued_at)
    .bind(&expires_at)
    .bind(&used_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "auth_nonces", res.rows_affected());
    Ok(())
}

// ---- the tombstone/revocation-gated file family ----

/// Read the staged `files` once, build the [`FileGate`], and insert the survivor
/// file rows. A live row wins on conflict, so a file live already has keeps its
/// (newer) `current_version`; a file live lost is restored whole with the
/// backup's own row.
///
/// `unmerged_owners` is the fail-closed half of the username-collision handling.
/// `files.owner_id` is a **non-deferrable** FK to `users`, and `ON CONFLICT`
/// arbitrates unique/exclusion conflicts only — the referential-integrity trigger
/// raises independently and takes the whole merge transaction with it. A staged
/// account live has re-registered under a different `user_id` therefore turns
/// every file that account owns into an abort, surfaced as a raw
/// `files_owner_id_fkey` at the exact moment the operator is recovering from a
/// disaster. Catching it here names the account instead. Refusing rather than
/// dropping those files is deliberate: silently discarding a user's entire
/// backed-up history is the one outcome this project never accepts.
async fn merge_files(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    live: &LiveFacts,
    unmerged_owners: &HashMap<Vec<u8>, String>,
    preview: &mut MergePreview,
) -> Result<FileGate, BackupError> {
    let rows = sqlx::query(
        "SELECT file_id, owner_id, file_type, current_version, listed, bundle_id, \
         created_at, updated_at FROM files",
    )
    .fetch_all(staged)
    .await?;

    let mut staged_files = Vec::with_capacity(rows.len());
    for r in &rows {
        staged_files.push((
            get16(r, "file_id")?,
            r.try_get::<i64, _>("current_version")?,
        ));
    }
    let gate = gate::plan_file_gate(&staged_files, live);

    let mut file_id = Vec::new();
    let mut owner_id = Vec::new();
    let mut file_type = Vec::new();
    let mut current_version = Vec::new();
    let mut listed = Vec::new();
    let mut bundle_id: Vec<Option<Vec<u8>>> = Vec::new();
    let mut created_at = Vec::new();
    let mut updated_at = Vec::new();
    let mut orphaned: BTreeSet<&str> = BTreeSet::new();
    for r in &rows {
        let fid = get16(r, "file_id")?;
        if gate.survivor_cur(&fid).is_none() {
            continue; // subtree skipped — the owner destroyed it
        }
        let owner = r.try_get::<Vec<u8>, _>("owner_id")?;
        if let Some(name) = unmerged_owners.get(&owner) {
            orphaned.insert(name.as_str());
        }
        file_id.push(fid.to_vec());
        owner_id.push(owner);
        file_type.push(r.try_get::<i16, _>("file_type")?);
        current_version.push(r.try_get::<i64, _>("current_version")?);
        listed.push(r.try_get::<bool, _>("listed")?);
        bundle_id.push(r.try_get::<Option<Vec<u8>>, _>("bundle_id")?);
        created_at.push(r.try_get::<OffsetDateTime, _>("created_at")?);
        updated_at.push(r.try_get::<OffsetDateTime, _>("updated_at")?);
    }
    if !orphaned.is_empty() {
        let mut usernames: Vec<String> = orphaned.into_iter().map(str::to_owned).collect();
        usernames.sort();
        return Err(BackupError::OwnerUsernameCollision { usernames });
    }
    if !file_id.is_empty() {
        let res = sqlx::query(
            "INSERT INTO files \
             (file_id, owner_id, file_type, current_version, listed, bundle_id, \
              created_at, updated_at) \
             SELECT * FROM unnest($1::bytea[], $2::bytea[], $3::smallint[], $4::bigint[], \
             $5::boolean[], $6::bytea[], $7::timestamptz[], $8::timestamptz[]) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&file_id)
        .bind(&owner_id)
        .bind(&file_type)
        .bind(&current_version)
        .bind(&listed)
        .bind(&bundle_id)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&mut **tx)
        .await?;
        record_inserts(preview, "files", res.rows_affected());
    }
    Ok(gate)
}

async fn merge_file_genesis(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    gate: &FileGate,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows = sqlx::query(
        "SELECT file_id, owner_id, owner_key_version, genesis_bytes, genesis_sig, created_at \
         FROM file_genesis",
    )
    .fetch_all(staged)
    .await?;
    let mut file_id = Vec::new();
    let mut owner_id = Vec::new();
    let mut owner_key_version = Vec::new();
    let mut genesis_bytes = Vec::new();
    let mut genesis_sig = Vec::new();
    let mut created_at = Vec::new();
    for r in &rows {
        let fid = get16(r, "file_id")?;
        if gate.survivor_cur(&fid).is_none() {
            continue;
        }
        file_id.push(fid.to_vec());
        owner_id.push(r.try_get::<Vec<u8>, _>("owner_id")?);
        owner_key_version.push(r.try_get::<i64, _>("owner_key_version")?);
        genesis_bytes.push(r.try_get::<Vec<u8>, _>("genesis_bytes")?);
        genesis_sig.push(r.try_get::<Vec<u8>, _>("genesis_sig")?);
        created_at.push(r.try_get::<OffsetDateTime, _>("created_at")?);
    }
    if file_id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO file_genesis \
         (file_id, owner_id, owner_key_version, genesis_bytes, genesis_sig, created_at) \
         SELECT * FROM unnest($1::bytea[], $2::bytea[], $3::bigint[], $4::bytea[], $5::bytea[], \
         $6::timestamptz[]) ON CONFLICT DO NOTHING",
    )
    .bind(&file_id)
    .bind(&owner_id)
    .bind(&owner_key_version)
    .bind(&genesis_bytes)
    .bind(&genesis_sig)
    .bind(&created_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "file_genesis", res.rows_affected());
    Ok(())
}

/// `file_versions` → all **finalized** rows for surviving files. Prior finalized
/// rows are retained by design (they carry the prior manifest); staged
/// `finalized = false` rows are a mid-rotation artifact the client re-stages, so
/// they are excluded at the source.
async fn merge_file_versions(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    gate: &FileGate,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows = sqlx::query(
        "SELECT file_id, version, manifest_bytes, manifest_sig, author_id, alg, finalized, \
         created_at FROM file_versions WHERE finalized = true",
    )
    .fetch_all(staged)
    .await?;
    let mut file_id = Vec::new();
    let mut version = Vec::new();
    let mut manifest_bytes = Vec::new();
    let mut manifest_sig = Vec::new();
    let mut author_id = Vec::new();
    let mut alg = Vec::new();
    let mut finalized = Vec::new();
    let mut created_at = Vec::new();
    for r in &rows {
        let fid = get16(r, "file_id")?;
        if gate.survivor_cur(&fid).is_none() {
            continue;
        }
        file_id.push(fid.to_vec());
        version.push(r.try_get::<i64, _>("version")?);
        manifest_bytes.push(r.try_get::<Vec<u8>, _>("manifest_bytes")?);
        manifest_sig.push(r.try_get::<Vec<u8>, _>("manifest_sig")?);
        author_id.push(r.try_get::<Vec<u8>, _>("author_id")?);
        alg.push(r.try_get::<i32, _>("alg")?);
        finalized.push(r.try_get::<bool, _>("finalized")?);
        created_at.push(r.try_get::<OffsetDateTime, _>("created_at")?);
    }
    if file_id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO file_versions \
         (file_id, version, manifest_bytes, manifest_sig, author_id, alg, finalized, created_at) \
         SELECT * FROM unnest($1::bytea[], $2::bigint[], $3::bytea[], $4::bytea[], $5::bytea[], \
         $6::int[], $7::boolean[], $8::timestamptz[]) ON CONFLICT DO NOTHING",
    )
    .bind(&file_id)
    .bind(&version)
    .bind(&manifest_bytes)
    .bind(&manifest_sig)
    .bind(&author_id)
    .bind(&alg)
    .bind(&finalized)
    .bind(&created_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "file_versions", res.rows_affected());
    Ok(())
}

/// `file_streams` → only the survivor's current version. A superseded version's
/// streams were pruned at finalize and their blobs are gone; re-inserting them
/// would 404 on download.
///
/// Staged (`finalized = false`) rows are excluded **at the source**, exactly as
/// [`merge_file_versions`] does. The `= cur` gate alone does not cover them: a
/// backup taken mid-rotation carries the unfinalized `cur+1` subtree
/// (`discard_unfinalized` refuses to GC it once any version is finalized), and if
/// live has *since* finalized `cur+1`, that abandoned staging's version number now
/// EQUALS live's `cur` and sails through the gate. Its rows describe a rotation
/// that never happened, so any stream the real `cur+1` does not also have inserts
/// as a zombie pointing at a `blob_ref` nothing ever uploaded.
async fn merge_file_streams(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    gate: &FileGate,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows = sqlx::query(
        "SELECT s.file_id, s.version, s.stream_type, s.compression, s.chunk_size, \
         s.chunk_count, s.total_bytes, s.digest, s.blob_ref FROM file_streams s \
         JOIN file_versions v ON v.file_id = s.file_id AND v.version = s.version \
         WHERE v.finalized = true",
    )
    .fetch_all(staged)
    .await?;
    let mut file_id = Vec::new();
    let mut version = Vec::new();
    let mut stream_type = Vec::new();
    let mut compression = Vec::new();
    let mut chunk_size = Vec::new();
    let mut chunk_count = Vec::new();
    let mut total_bytes = Vec::new();
    let mut digest = Vec::new();
    let mut blob_ref = Vec::new();
    for r in &rows {
        let fid = get16(r, "file_id")?;
        let Some(cur) = gate.survivor_cur(&fid) else {
            continue;
        };
        let v = r.try_get::<i64, _>("version")?;
        if !gate::keep_stream(cur, v) {
            continue;
        }
        file_id.push(fid.to_vec());
        version.push(v);
        stream_type.push(r.try_get::<i16, _>("stream_type")?);
        compression.push(r.try_get::<i16, _>("compression")?);
        chunk_size.push(r.try_get::<i32, _>("chunk_size")?);
        chunk_count.push(r.try_get::<i64, _>("chunk_count")?);
        total_bytes.push(r.try_get::<i64, _>("total_bytes")?);
        digest.push(r.try_get::<Vec<u8>, _>("digest")?);
        blob_ref.push(r.try_get::<String, _>("blob_ref")?);
    }
    if file_id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO file_streams \
         (file_id, version, stream_type, compression, chunk_size, chunk_count, \
          total_bytes, digest, blob_ref) \
         SELECT * FROM unnest($1::bytea[], $2::bigint[], $3::smallint[], $4::smallint[], \
         $5::int[], $6::bigint[], $7::bigint[], $8::bytea[], $9::text[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&file_id)
    .bind(&version)
    .bind(&stream_type)
    .bind(&compression)
    .bind(&chunk_size)
    .bind(&chunk_count)
    .bind(&total_bytes)
    .bind(&digest)
    .bind(&blob_ref)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "file_streams", res.rows_affected());
    Ok(())
}

/// `file_key_wraps` → only the survivor's current version, and only recipients
/// with no `wrap_revocations` row. The `= cur` gate drops wraps a rotation
/// superseded (whose ciphertext is gone); the revocation gate is what keeps a
/// de-authorized recipient from getting their wrapped DEK back.
///
/// Staged (`finalized = false`) rows are excluded **at the source** for the reason
/// spelled out on [`merge_file_streams`] — and here the consequence is sharper. If
/// the backup carries an abandoned staging for `cur+1` and live has since finalized
/// `cur+1` with a DIFFERENT recipient set, the abandoned staging's wraps match
/// `= cur` and insert. No `wrap_revocations` row exists to stop them (that recipient
/// was never granted in live), so a recipient the owner dropped before finalizing
/// would silently receive a working DEK — the exact failure the revocation gate
/// exists to prevent, arriving through the one door it does not watch.
async fn merge_file_key_wraps(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    gate: &FileGate,
    live: &LiveFacts,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    let rows = sqlx::query(
        "SELECT w.file_id, w.file_version, w.recipient_id, w.recipient_type, w.wrapped_dek, \
         w.wrap_alg, w.granted_by, w.grant_bytes, w.grant_sig, w.created_at FROM file_key_wraps w \
         JOIN file_versions v ON v.file_id = w.file_id AND v.version = w.file_version \
         WHERE v.finalized = true",
    )
    .fetch_all(staged)
    .await?;
    let mut file_id = Vec::new();
    let mut file_version = Vec::new();
    let mut recipient_id = Vec::new();
    let mut recipient_type = Vec::new();
    let mut wrapped_dek = Vec::new();
    let mut wrap_alg = Vec::new();
    let mut granted_by = Vec::new();
    let mut grant_bytes = Vec::new();
    let mut grant_sig = Vec::new();
    let mut created_at = Vec::new();
    for r in &rows {
        let fid = get16(r, "file_id")?;
        let Some(cur) = gate.survivor_cur(&fid) else {
            continue;
        };
        let fv = r.try_get::<i64, _>("file_version")?;
        let rid = get16(r, "recipient_id")?;
        match gate::wrap_verdict(live, fid, cur, fv, rid) {
            WrapVerdict::Keep => {}
            WrapVerdict::SkipSuperseded => {
                preview.wraps_skipped_superseded += 1;
                continue;
            }
            WrapVerdict::SkipRevoked => {
                preview.wraps_skipped_revoked += 1;
                continue;
            }
        }
        file_id.push(fid.to_vec());
        file_version.push(fv);
        recipient_id.push(rid.to_vec());
        recipient_type.push(r.try_get::<i16, _>("recipient_type")?);
        wrapped_dek.push(r.try_get::<Vec<u8>, _>("wrapped_dek")?);
        wrap_alg.push(r.try_get::<i32, _>("wrap_alg")?);
        granted_by.push(r.try_get::<Vec<u8>, _>("granted_by")?);
        grant_bytes.push(r.try_get::<Vec<u8>, _>("grant_bytes")?);
        grant_sig.push(r.try_get::<Vec<u8>, _>("grant_sig")?);
        created_at.push(r.try_get::<OffsetDateTime, _>("created_at")?);
    }
    if file_id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO file_key_wraps \
         (file_id, file_version, recipient_id, recipient_type, wrapped_dek, wrap_alg, \
          granted_by, grant_bytes, grant_sig, created_at) \
         SELECT * FROM unnest($1::bytea[], $2::bigint[], $3::bytea[], $4::smallint[], $5::bytea[], \
         $6::int[], $7::bytea[], $8::bytea[], $9::bytea[], $10::timestamptz[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&file_id)
    .bind(&file_version)
    .bind(&recipient_id)
    .bind(&recipient_type)
    .bind(&wrapped_dek)
    .bind(&wrap_alg)
    .bind(&granted_by)
    .bind(&grant_bytes)
    .bind(&grant_sig)
    .bind(&created_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "file_key_wraps", res.rows_affected());
    Ok(())
}

// ---- the append-only absence records (migration 0002) ----

/// Does the *staged* scratch database have this relation?
///
/// The scratch DB is whatever `pg_restore` materialized from the bundle's own
/// `pg_dump`, so its schema is the schema of the day the backup was taken. A
/// bundle older than migration 0002 has no `file_tombstones` / `wrap_revocations`
/// at all, and selecting from a missing relation raises — which would turn "this
/// bundle predates the tombstone tables" into "this bundle cannot be restored".
/// `to_regclass` answers with NULL instead of raising, so the two passes below
/// simply do nothing for such a bundle.
async fn staged_has_table(staged: &PgPool, table: &str) -> Result<bool, BackupError> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(staged)
            .await?,
    )
}

/// `file_tombstones` — "the owner destroyed this file, forever".
///
/// Never gated and never filtered: a tombstone is an append-only fact, and the
/// live row it describes is gone by design (there is no FK to violate). Carrying
/// it across is what keeps a *later* merge — from an older bundle that still
/// holds the file — from resurrecting it.
async fn merge_file_tombstones(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    if !staged_has_table(staged, "public.file_tombstones").await? {
        return Ok(());
    }
    let rows = sqlx::query("SELECT file_id, deleted_at FROM file_tombstones")
        .fetch_all(staged)
        .await?;
    let mut file_id = Vec::new();
    let mut deleted_at = Vec::new();
    for r in &rows {
        file_id.push(r.try_get::<Vec<u8>, _>("file_id")?);
        deleted_at.push(r.try_get::<OffsetDateTime, _>("deleted_at")?);
    }
    if file_id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO file_tombstones (file_id, deleted_at) \
         SELECT * FROM unnest($1::bytea[], $2::timestamptz[]) ON CONFLICT DO NOTHING",
    )
    .bind(&file_id)
    .bind(&deleted_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "file_tombstones", res.rows_affected());
    Ok(())
}

/// `wrap_revocations` — "this recipient's read access was taken away".
///
/// The counterpart of [`merge_file_tombstones`], and for the same reason: without
/// it a rebuilt database forgets every revocation the bundle recorded, and the
/// next merge hands those de-authorized recipients their wrapped DEK back.
async fn merge_wrap_revocations(
    tx: &mut Tx<'_>,
    staged: &PgPool,
    preview: &mut MergePreview,
) -> Result<(), BackupError> {
    if !staged_has_table(staged, "public.wrap_revocations").await? {
        return Ok(());
    }
    let rows =
        sqlx::query("SELECT file_id, file_version, recipient_id, revoked_at FROM wrap_revocations")
            .fetch_all(staged)
            .await?;
    let mut file_id = Vec::new();
    let mut file_version = Vec::new();
    let mut recipient_id = Vec::new();
    let mut revoked_at = Vec::new();
    for r in &rows {
        file_id.push(r.try_get::<Vec<u8>, _>("file_id")?);
        file_version.push(r.try_get::<i64, _>("file_version")?);
        recipient_id.push(r.try_get::<Vec<u8>, _>("recipient_id")?);
        revoked_at.push(r.try_get::<OffsetDateTime, _>("revoked_at")?);
    }
    if file_id.is_empty() {
        return Ok(());
    }
    let res = sqlx::query(
        "INSERT INTO wrap_revocations (file_id, file_version, recipient_id, revoked_at) \
         SELECT * FROM unnest($1::bytea[], $2::bigint[], $3::bytea[], $4::timestamptz[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&file_id)
    .bind(&file_version)
    .bind(&recipient_id)
    .bind(&revoked_at)
    .execute(&mut **tx)
    .await?;
    record_inserts(preview, "wrap_revocations", res.rows_affected());
    Ok(())
}
