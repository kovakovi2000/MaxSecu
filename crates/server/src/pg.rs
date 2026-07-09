//! Postgres-backed [`Store`] — the production persistence adapter over the
//! Phase-1 tables in `docs/schema.sql` (`users`, `auth_nonces`, `sessions`,
//! `registration_keys`). Every row is inert/ephemeral auth state; no secret,
//! salt, KDF param, or private key ever lands here (DESIGN §4.3 / D4).
//!
//! **Clock model.** The auth state machine reasons in `u64` epoch-milliseconds
//! (the app clock); the schema stores `TIMESTAMPTZ`. Freshness (nonce/session
//! TTLs) is driven by the *app-provided* `now_ms`/expiry, never the DB clock —
//! `expires_at` is stored as the converted app value and compared against the
//! converted app `now`, so the freshness decision is identical to `MemoryStore`
//! (TIMESTAMPTZ is "advisory, never a freshness basis", schema.sql / §7.5). The
//! advisory audit columns (`issued_at`/`used_at`/`revoked_at`) use the DB clock.
//!
//! **Fail-closed, but observable.** The [`Store`] contract is *fallible*
//! (`Result<_, StoreError>`): a backend fault propagates as `Err` so the service
//! and HTTP layers can log it and answer `500`, rather than the old infallible
//! contract that forced this adapter to swallow every DB error into a
//! fail-closed `None`/`false` — which silently denied and was indistinguishable
//! from a legitimate "not found". Callers still fail *closed* (they map `Err` to
//! denial); the difference is the fault is no longer invisible (see [`StoreError`]).

use async_trait::async_trait;
use maxsecu_crypto::random_array;
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::{DirBinding, MLKEM768_PUB_LEN};
use maxsecu_encoding::GENESIS_HEAD;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;

use crate::control::{decode_control, role_text};
use crate::error::{ControlAppendError, StoreError};
use crate::files::{
    AddWrapError, DeleteError, DeleteWrapError, DiscardError, FinalizeError, ListFilter,
    ParsedStage, StageError, VersionSelector, WrapInput,
};
use crate::store::{
    ancestor_chain, ChunkSlot, EnrollOutcome, FileListEntry, FileMeta, FileView, RecipientView,
    RecoveryAccount, SessionRecord, Store, StoredBinding, StoredControlRecord, StreamView,
    UserRecord, VersionMeta, WrapView, BUNDLE_FILE_TYPE,
};

/// Postgres [`Store`]. Cheap to clone (the pool is an `Arc` internally).
#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub fn new(pool: PgPool) -> Self {
        PgStore { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// App epoch-ms → `TIMESTAMPTZ`. Total over the representable range we use
/// (app-clock values: `now + ttl`, always well within range).
fn ms_to_ts(ms: u64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .expect("epoch-ms within OffsetDateTime range")
}

/// Checked epoch-ms → `TIMESTAMPTZ` for values decoded from a record (e.g. a
/// binding's `not_after`): an out-of-range timestamp is a `StoreError`, never a
/// handler panic.
fn try_ms_to_ts(ms: u64, op: &'static str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .map_err(|_| StoreError::new(op, "timestamp out of representable range"))
}

/// `TIMESTAMPTZ` → app epoch-ms (truncating sub-ms, which we never store).
fn ts_to_ms(ts: OffsetDateTime) -> u64 {
    (ts.unix_timestamp_nanos() / 1_000_000) as u64
}

/// Encode an opaque nonce-association key for the `auth_nonces.username` column.
///
/// That column is `TEXT`, but a nonce key is not always a printable username: the
/// recovery challenge key deliberately embeds NUL (`0x00`) so it can never collide
/// with a real username (see `recovery::recovery_nonce_key`). Postgres `TEXT`
/// cannot store `0x00` ("invalid byte sequence for encoding UTF8"), which made
/// `insert_nonce` 500 on every recovery challenge. Hex-encoding the key sidesteps
/// that: the encoding is injective and applied identically on insert AND lookup,
/// so it preserves both exact matching and the NUL-based disjointness from
/// usernames (a username's raw bytes can never contain NUL, so its hex can never
/// equal a recovery key's hex). MemoryStore keeps the raw key — only PG needs this.
fn nonce_key_col(key: &str) -> String {
    key.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Map any sqlx failure to a `StoreError` tagged with the operation name. The
/// message stays server-side (logged at the HTTP boundary), never sent to a client.
fn store_err(op: &'static str) -> impl Fn(sqlx::Error) -> StoreError {
    move |e| StoreError::new(op, e.to_string())
}

/// Read a fixed-width `bytea` column. A present-but-wrong-width value is a
/// data-integrity fault (`Err`), not a "not found" — the server's own rows are
/// CHECK-constrained to the right width, so this can only mean corruption.
fn col_fixed<const N: usize>(
    row: &PgRow,
    op: &'static str,
    col: &'static str,
) -> Result<[u8; N], StoreError> {
    let v: Vec<u8> = row.try_get(col).map_err(store_err(op))?;
    v.try_into()
        .map_err(|_| StoreError::new(op, format!("column `{col}` has unexpected width")))
}

#[async_trait]
impl Store for PgStore {
    async fn create_user(
        &self,
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        // Server-assigned id (api.md §1.4). The PK + UNIQUE(username) make this
        // race-safe: a concurrent duplicate username loses with a unique violation.
        let user_id: [u8; 16] = random_array();
        let res = sqlx::query(
            "INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1, $2, $3, $4)",
        )
        .bind(&user_id[..])
        .bind(username)
        .bind(&enc_pub[..])
        .bind(&sig_pub[..])
        .execute(&self.pool)
        .await;
        match res {
            Ok(_) => Ok(Some(user_id)),
            // Username taken is a *business* outcome (→ 409), not a fault.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(None),
            Err(e) => Err(store_err("create_user")(e)),
        }
    }

    async fn user_by_name(&self, username: &str) -> Result<Option<UserRecord>, StoreError> {
        let row = sqlx::query("SELECT user_id, enc_pub, sig_pub FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err("user_by_name"))?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(UserRecord {
            user_id: col_fixed(&row, "user_by_name", "user_id")?,
            enc_pub: col_fixed(&row, "user_by_name", "enc_pub")?,
            sig_pub: col_fixed(&row, "user_by_name", "sig_pub")?,
        }))
    }

    async fn insert_nonce(
        &self,
        nonce: [u8; 32],
        username: &str,
        expires_at_ms: u64,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO auth_nonces (nonce, username, expires_at) VALUES ($1, $2, $3)")
            .bind(&nonce[..])
            .bind(nonce_key_col(username))
            .bind(ms_to_ts(expires_at_ms))
            .execute(&self.pool)
            .await
            .map_err(store_err("insert_nonce"))?;
        Ok(())
    }

    async fn outstanding_nonces(
        &self,
        username: &str,
        now_ms: u64,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        let rows = sqlx::query(
            "SELECT nonce FROM auth_nonces \
             WHERE username = $1 AND used_at IS NULL AND expires_at > $2",
        )
        .bind(nonce_key_col(username))
        .bind(ms_to_ts(now_ms))
        .fetch_all(&self.pool)
        .await
        .map_err(store_err("outstanding_nonces"))?;
        rows.iter()
            .map(|r| col_fixed(r, "outstanding_nonces", "nonce"))
            .collect()
    }

    async fn consume_nonce(&self, nonce: &[u8; 32]) -> Result<(), StoreError> {
        sqlx::query("UPDATE auth_nonces SET used_at = now() WHERE nonce = $1 AND used_at IS NULL")
            .bind(&nonce[..])
            .execute(&self.pool)
            .await
            .map_err(store_err("consume_nonce"))?;
        Ok(())
    }

    async fn insert_session(
        &self,
        token_hash: [u8; 32],
        rec: SessionRecord,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, tls_exporter, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&token_hash[..])
        .bind(&rec.user_id[..])
        .bind(&rec.tls_exporter[..])
        .bind(ms_to_ts(rec.expires_at_ms))
        .execute(&self.pool)
        .await
        .map_err(store_err("insert_session"))?;
        Ok(())
    }

    async fn get_session(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<SessionRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT user_id, tls_exporter, expires_at, revoked_at FROM sessions \
             WHERE token_hash = $1",
        )
        .bind(&token_hash[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err("get_session"))?;
        let Some(row) = row else { return Ok(None) };
        let expires_at: OffsetDateTime = row
            .try_get("expires_at")
            .map_err(store_err("get_session"))?;
        let revoked_at: Option<OffsetDateTime> = row
            .try_get("revoked_at")
            .map_err(store_err("get_session"))?;
        Ok(Some(SessionRecord {
            user_id: col_fixed(&row, "get_session", "user_id")?,
            tls_exporter: col_fixed(&row, "get_session", "tls_exporter")?,
            expires_at_ms: ts_to_ms(expires_at),
            revoked: revoked_at.is_some(),
        }))
    }

    async fn revoke_session(&self, token_hash: &[u8; 32]) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() \
             WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(&token_hash[..])
        .execute(&self.pool)
        .await
        .map_err(store_err("revoke_session"))?;
        Ok(())
    }

    async fn put_binding(
        &self,
        user_id: [u8; 16],
        key_version: u64,
        binding_bytes: Vec<u8>,
        signature: [u8; 64],
    ) -> Result<(), StoreError> {
        // Decode the signed bytes once to populate the advisory projection columns
        // (directory_bindings is NOT NULL on them). The stored authority is the
        // exact `binding_bytes`; clients verify those, never these projections.
        let b: DirBinding = decode(&binding_bytes)
            .map_err(|_| StoreError::new("put_binding", "binding bytes are not canonical"))?;
        let roles: Vec<String> = b.roles.roles().iter().map(role_text).collect();

        // Insert into the immutable history; re-publishing the same
        // (user_id, key_version) is a no-op (the row is trigger-immutable).
        sqlx::query(
            "INSERT INTO directory_bindings \
             (user_id, key_version, enc_pub, sig_pub, roles, not_before, not_after, \
              binding_bytes, directory_signature) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT (user_id, key_version) DO NOTHING",
        )
        .bind(&user_id[..])
        .bind(key_version as i64)
        .bind(&b.enc_pub.0[..])
        .bind(&b.sig_pub.0[..])
        .bind(&roles)
        .bind(try_ms_to_ts(b.not_before.0, "put_binding")?)
        .bind(try_ms_to_ts(b.not_after.0, "put_binding")?)
        .bind(&binding_bytes)
        .bind(&signature[..])
        .execute(&self.pool)
        .await
        .map_err(store_err("put_binding"))?;

        // Mark the account signed and sync the advisory current-material mirror.
        sqlx::query(
            "UPDATE users SET signed_at = now(), enc_pub = $2, sig_pub = $3, \
             key_version = $4, roles = $5 WHERE user_id = $1",
        )
        .bind(&user_id[..])
        .bind(&b.enc_pub.0[..])
        .bind(&b.sig_pub.0[..])
        .bind(key_version as i64)
        .bind(&roles)
        .execute(&self.pool)
        .await
        .map_err(store_err("put_binding"))?;
        Ok(())
    }

    async fn binding_by_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredBinding>, StoreError> {
        let row = sqlx::query(
            "SELECT db.binding_bytes, db.directory_signature \
             FROM directory_bindings db JOIN users u ON u.user_id = db.user_id \
             WHERE u.username = $1 ORDER BY db.key_version DESC LIMIT 1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err("binding_by_username"))?;
        binding_from_row(row, "binding_by_username")
    }

    async fn binding_by_user_id(
        &self,
        user_id: &[u8; 16],
    ) -> Result<Option<StoredBinding>, StoreError> {
        let row = sqlx::query(
            "SELECT binding_bytes, directory_signature FROM directory_bindings \
             WHERE user_id = $1 ORDER BY key_version DESC LIMIT 1",
        )
        .bind(&user_id[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err("binding_by_user_id"))?;
        binding_from_row(row, "binding_by_user_id")
    }

    async fn issue_registration_key(
        &self,
        key_hash: [u8; 32],
        expires_at_ms: u64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO registration_keys (key_hash, expires_at) VALUES ($1, $2) \
             ON CONFLICT (key_hash) DO NOTHING",
        )
        .bind(&key_hash[..])
        .bind(try_ms_to_ts(expires_at_ms, "issue_registration_key")?)
        .execute(&self.pool)
        .await
        .map_err(store_err("issue_registration_key"))?;
        Ok(())
    }

    async fn consume_registration_key(&self, key_hash: &[u8; 32]) -> Result<bool, StoreError> {
        // Atomic single-use: the `used_at IS NULL` predicate means exactly one of
        // any racing consumers updates the row. `expires_at` is the operational
        // TTL (DB clock — no app `now` passed).
        let res = sqlx::query(
            "UPDATE registration_keys SET used_at = now() \
             WHERE key_hash = $1 AND used_at IS NULL AND expires_at > now()",
        )
        .bind(&key_hash[..])
        .execute(&self.pool)
        .await
        .map_err(store_err("consume_registration_key"))?;
        Ok(res.rows_affected() == 1)
    }

    async fn claim_first_admin(&self) -> Result<bool, StoreError> {
        // Atomic once-only claim, mirroring `set_recovery_account`: the singleton
        // PK + `ON CONFLICT DO NOTHING` serializes concurrent claimers so exactly
        // one INSERT affects a row (→ admin) — the first-admin decision cannot be
        // split across a racing read + create.
        let res = sqlx::query(
            "INSERT INTO first_admin_claim (id) VALUES (true) ON CONFLICT (id) DO NOTHING",
        )
        .execute(&self.pool)
        .await
        .map_err(store_err("claim_first_admin"))?;
        Ok(res.rows_affected() == 1)
    }

    async fn enroll(
        &self,
        reg_key_hash: [u8; 32],
        user_id: [u8; 16],
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
        user_binding: &StoredBinding,
        admin_binding: &StoredBinding,
    ) -> Result<EnrollOutcome, StoreError> {
        // ONE transaction: every step runs on `&mut *tx`, so a fault (or an early
        // KeyInvalid/UsernameTaken) rolls the whole unit back — no burned key, no
        // orphan user, no dangling admin claim.
        let mut tx = self.pool.begin().await.map_err(store_err("enroll"))?;

        // 1. Consume the single-use key atomically (same predicate as
        // `consume_registration_key`). Not consumed ⇒ nothing was written ⇒ roll
        // back and report KeyInvalid.
        let consumed = sqlx::query(
            "UPDATE registration_keys SET used_at = now() \
             WHERE key_hash = $1 AND used_at IS NULL AND expires_at > now()",
        )
        .bind(&reg_key_hash[..])
        .execute(&mut *tx)
        .await
        .map_err(store_err("enroll"))?;
        if consumed.rows_affected() != 1 {
            tx.rollback().await.map_err(store_err("enroll"))?;
            return Ok(EnrollOutcome::KeyInvalid);
        }

        // 2. Create the user with the caller-provided (already-bound) user_id. A
        // unique violation (username OR id taken) rolls back — the key is unspent.
        let ins = sqlx::query(
            "INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1, $2, $3, $4)",
        )
        .bind(&user_id[..])
        .bind(username)
        .bind(&enc_pub[..])
        .bind(&sig_pub[..])
        .execute(&mut *tx)
        .await;
        match ins {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                tx.rollback().await.map_err(store_err("enroll"))?;
                return Ok(EnrollOutcome::UsernameTaken);
            }
            Err(e) => return Err(store_err("enroll")(e)),
        }

        // 3. Resolve the one-time first-admin slot inside the txn.
        let claim = sqlx::query(
            "INSERT INTO first_admin_claim (id) VALUES (true) ON CONFLICT (id) DO NOTHING",
        )
        .execute(&mut *tx)
        .await
        .map_err(store_err("enroll"))?;
        let is_admin = claim.rows_affected() == 1;

        // 4. Store the matching already-signed binding (+ the advisory projection
        // columns / users mirror, exactly as `put_binding` does), all on the txn.
        let binding = if is_admin {
            admin_binding
        } else {
            user_binding
        };
        let b: DirBinding = decode(&binding.binding_bytes)
            .map_err(|_| StoreError::new("enroll", "binding bytes are not canonical"))?;
        let roles: Vec<String> = b.roles.roles().iter().map(role_text).collect();
        sqlx::query(
            "INSERT INTO directory_bindings \
             (user_id, key_version, enc_pub, sig_pub, roles, not_before, not_after, \
              binding_bytes, directory_signature) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(&user_id[..])
        .bind(1i64)
        .bind(&b.enc_pub.0[..])
        .bind(&b.sig_pub.0[..])
        .bind(&roles)
        .bind(try_ms_to_ts(b.not_before.0, "enroll")?)
        .bind(try_ms_to_ts(b.not_after.0, "enroll")?)
        .bind(&binding.binding_bytes)
        .bind(&binding.signature[..])
        .execute(&mut *tx)
        .await
        .map_err(store_err("enroll"))?;
        sqlx::query(
            "UPDATE users SET signed_at = now(), enc_pub = $2, sig_pub = $3, \
             key_version = $4, roles = $5 WHERE user_id = $1",
        )
        .bind(&user_id[..])
        .bind(&b.enc_pub.0[..])
        .bind(&b.sig_pub.0[..])
        .bind(1i64)
        .bind(&roles)
        .execute(&mut *tx)
        .await
        .map_err(store_err("enroll"))?;

        // 5. Commit — the enrollment becomes visible all at once.
        tx.commit().await.map_err(store_err("enroll"))?;
        Ok(EnrollOutcome::Enrolled { is_admin })
    }

    async fn set_recovery_account(
        &self,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
        mlkem_pub: Option<[u8; MLKEM768_PUB_LEN]>,
    ) -> Result<bool, StoreError> {
        // Once-only via the singleton PK (`id = true`): a second INSERT hits
        // `ON CONFLICT DO NOTHING`, so exactly one of any racing setters lands a
        // row and the stored keys are never overwritten. Public keys only (D4);
        // `mlkem_pub` NULL = classical-only recovery.
        let res = sqlx::query(
            "INSERT INTO recovery_account (id, enc_pub, sig_pub, mlkem_pub) VALUES (true, $1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&enc_pub[..])
        .bind(&sig_pub[..])
        .bind(mlkem_pub.as_ref().map(|k| &k[..]))
        .execute(&self.pool)
        .await
        .map_err(store_err("set_recovery_account"))?;
        Ok(res.rows_affected() == 1)
    }

    async fn recovery_account(&self) -> Result<Option<RecoveryAccount>, StoreError> {
        let Some(row) =
            sqlx::query("SELECT enc_pub, sig_pub, mlkem_pub FROM recovery_account WHERE id = true")
                .fetch_optional(&self.pool)
                .await
                .map_err(store_err("recovery_account"))?
        else {
            return Ok(None);
        };
        let enc_pub = col_fixed::<32>(&row, "recovery_account", "enc_pub")?;
        let sig_pub = col_fixed::<32>(&row, "recovery_account", "sig_pub")?;
        // `mlkem_pub` is nullable (classical-only recovery); when present the DB
        // CHECK guarantees the width, but we re-validate on read-back (D4).
        let mlkem_raw: Option<Vec<u8>> = row
            .try_get("mlkem_pub")
            .map_err(store_err("recovery_account"))?;
        let mlkem_pub = match mlkem_raw {
            None => None,
            Some(v) => Some(v.try_into().map_err(|_| {
                StoreError::new("recovery_account", "mlkem_pub has unexpected width")
            })?),
        };
        Ok(Some(RecoveryAccount {
            enc_pub,
            sig_pub,
            mlkem_pub,
        }))
    }

    async fn append_control(
        &self,
        record_bytes: Vec<u8>,
        sig: [u8; 64],
        co_sig: Option<[u8; 64]>,
    ) -> Result<[u8; 32], ControlAppendError> {
        let d = decode_control(&record_bytes).ok_or(ControlAppendError::Malformed)?;
        // Pre-check the head for a clean Conflict; the append-guard trigger is the
        // authoritative defense-in-depth (and the race winner under concurrency).
        let current = self
            .control_head()
            .await
            .map_err(ControlAppendError::Store)?;
        if d.prev_head != current {
            return Err(ControlAppendError::Conflict);
        }
        let effective_from = match d.effective_from_ms {
            Some(ms) => {
                Some(try_ms_to_ts(ms, "append_control").map_err(ControlAppendError::Store)?)
            }
            None => None,
        };
        let res = sqlx::query(
            "INSERT INTO control_log \
             (kind, prev_head, head, record_bytes, sig, co_sig, issued_by, co_signed_by, \
              is_account_wide, scope_file_id, subject_user_id, revoked_capability, from_version, \
              scope_epoch, supersedes_epoch, compromised_key_version, effective_from) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
        )
        .bind(d.kind)
        .bind(&d.prev_head[..])
        .bind(&d.head[..])
        .bind(&record_bytes)
        .bind(&sig[..])
        .bind(co_sig.as_ref().map(|s| &s[..]))
        .bind(&d.issued_by[..])
        .bind(d.co_signed_by.as_ref().map(|i| &i[..]))
        .bind(d.is_account_wide)
        .bind(d.scope_file_id.as_ref().map(|i| &i[..]))
        .bind(&d.subject_user_id[..])
        .bind(d.revoked_capability)
        .bind(d.from_version)
        .bind(d.scope_epoch)
        .bind(d.supersedes_epoch)
        .bind(d.compromised_key_version)
        .bind(effective_from)
        .execute(&self.pool)
        .await;
        match res {
            Ok(_) => Ok(d.head),
            // The append-guard trigger raises P0001 on a prev_head mismatch (a
            // concurrent append won the race) → Conflict, not a server fault.
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("P0001") => {
                Err(ControlAppendError::Conflict)
            }
            Err(e) => Err(ControlAppendError::Store(store_err("append_control")(e))),
        }
    }

    async fn control_records(&self) -> Result<Vec<StoredControlRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT kind, record_bytes, sig, co_sig, head FROM control_log ORDER BY chain_seq",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err("control_records"))?;
        rows.iter().map(control_record_from_row).collect()
    }

    async fn control_head(&self) -> Result<[u8; 32], StoreError> {
        let row = sqlx::query("SELECT head FROM control_log ORDER BY chain_seq DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err("control_head"))?;
        match row {
            Some(row) => col_fixed(&row, "control_head", "head"),
            None => Ok(GENESIS_HEAD.0),
        }
    }

    async fn stage_version(&self, parsed: ParsedStage, _now_ms: u64) -> Result<u64, StageError> {
        let op = "stage_version";
        let serr = |e: sqlx::Error| StageError::Store(store_err(op)(e));
        let version = parsed.version as i64;
        let mut tx = self.pool.begin().await.map_err(serr)?;

        // Existing owner, if any (for the coarse owner check on both paths).
        let owner_row = sqlx::query("SELECT owner_id FROM files WHERE file_id = $1")
            .bind(&parsed.file_id[..])
            .fetch_optional(&mut *tx)
            .await
            .map_err(serr)?;
        let existing_owner: Option<[u8; 16]> = match owner_row {
            Some(r) => Some(col_fixed(&r, op, "owner_id").map_err(StageError::Store)?),
            None => None,
        };

        // A finalized target version is immutable — cannot re-stage (api.md §12).
        let finalized: Option<bool> =
            sqlx::query("SELECT finalized FROM file_versions WHERE file_id = $1 AND version = $2")
                .bind(&parsed.file_id[..])
                .bind(version)
                .fetch_optional(&mut *tx)
                .await
                .map_err(serr)?
                .map(|r| r.get::<bool, _>("finalized"));
        if finalized == Some(true) {
            return Err(StageError::AlreadyFinalized);
        }

        match &parsed.genesis {
            // Version 1 / create.
            Some(g) => {
                if let Some(owner) = existing_owner {
                    if owner != g.owner_id {
                        return Err(StageError::NotOwner); // someone else owns this file_id
                    }
                }
                sqlx::query(
                    "INSERT INTO files (file_id, owner_id, file_type, current_version, listed, bundle_id) \
                     VALUES ($1,$2,$3,0,$4,$5) ON CONFLICT (file_id) DO NOTHING",
                )
                .bind(&parsed.file_id[..])
                .bind(&g.owner_id[..])
                .bind(parsed.file_type)
                .bind(parsed.listed)
                .bind(parsed.bundle_id.as_ref().map(|b| &b[..]))
                .execute(&mut *tx)
                .await
                .map_err(serr)?;
                sqlx::query(
                    "INSERT INTO file_genesis \
                     (file_id, owner_id, owner_key_version, genesis_bytes, genesis_sig) \
                     VALUES ($1,$2,$3,$4,$5) ON CONFLICT (file_id) DO NOTHING",
                )
                .bind(&parsed.file_id[..])
                .bind(&g.owner_id[..])
                .bind(g.owner_key_version as i64)
                .bind(&g.genesis_bytes)
                .bind(&g.genesis_sig[..])
                .execute(&mut *tx)
                .await
                .map_err(serr)?;
            }
            // Rotation (vN): the file must exist and the caller own it (D29).
            None => match existing_owner {
                None => return Err(StageError::NoSuchFile),
                Some(owner) if owner != parsed.author_id => return Err(StageError::NotOwner),
                Some(_) => {}
            },
        }

        // Idempotent overwrite of a still-staged version (cascades streams + wraps).
        sqlx::query(
            "DELETE FROM file_versions WHERE file_id = $1 AND version = $2 AND finalized = false",
        )
        .bind(&parsed.file_id[..])
        .bind(version)
        .execute(&mut *tx)
        .await
        .map_err(serr)?;
        sqlx::query(
            "INSERT INTO file_versions \
             (file_id, version, manifest_bytes, manifest_sig, author_id, alg, finalized) \
             VALUES ($1,$2,$3,$4,$5,$6,false)",
        )
        .bind(&parsed.file_id[..])
        .bind(version)
        .bind(&parsed.manifest_bytes)
        .bind(&parsed.manifest_sig[..])
        .bind(&parsed.author_id[..])
        .bind(parsed.alg)
        .execute(&mut *tx)
        .await
        .map_err(serr)?;

        for s in &parsed.streams {
            sqlx::query(
                "INSERT INTO file_streams \
                 (file_id, version, stream_type, compression, chunk_size, chunk_count, \
                  total_bytes, digest, blob_ref) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(&parsed.file_id[..])
            .bind(version)
            .bind(s.stream_type)
            .bind(s.compression)
            .bind(s.chunk_size as i32)
            .bind(s.chunk_count as i64)
            .bind(s.total_bytes as i64)
            .bind(&s.digest[..])
            .bind(&s.blob_ref)
            .execute(&mut *tx)
            .await
            .map_err(serr)?;
        }
        for w in &parsed.wraps {
            sqlx::query(
                "INSERT INTO file_key_wraps \
                 (file_id, file_version, recipient_id, recipient_type, wrapped_dek, wrap_alg, \
                  granted_by, grant_bytes, grant_sig) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(&parsed.file_id[..])
            .bind(version)
            .bind(&w.recipient_id[..])
            .bind(w.recipient_type)
            .bind(&w.wrapped_dek)
            .bind(w.wrap_alg)
            .bind(&w.granted_by[..])
            .bind(&w.grant_bytes)
            .bind(&w.grant_sig[..])
            .execute(&mut *tx)
            .await
            .map_err(serr)?;
        }
        tx.commit().await.map_err(serr)?;
        Ok(parsed.version)
    }

    async fn finalize_version(
        &self,
        file_id: [u8; 16],
        version: u64,
        caller_id: [u8; 16],
        _now_ms: u64,
    ) -> Result<(), FinalizeError> {
        let op = "finalize_version";
        let serr = |e: sqlx::Error| FinalizeError::Store(store_err(op)(e));
        let v = version as i64;
        let mut tx = self.pool.begin().await.map_err(serr)?;

        // Lock the file row to serialize concurrent finalizes (the strict +1 race).
        let frow = sqlx::query(
            "SELECT owner_id, current_version FROM files WHERE file_id = $1 FOR UPDATE",
        )
        .bind(&file_id[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(serr)?;
        let Some(frow) = frow else {
            return Err(FinalizeError::NoSuchVersion);
        };
        let owner: [u8; 16] = col_fixed(&frow, op, "owner_id").map_err(FinalizeError::Store)?;
        if owner != caller_id {
            return Err(FinalizeError::NotOwner);
        }
        let current: i64 = frow.get("current_version");

        let finalized: Option<bool> =
            sqlx::query("SELECT finalized FROM file_versions WHERE file_id = $1 AND version = $2")
                .bind(&file_id[..])
                .bind(v)
                .fetch_optional(&mut *tx)
                .await
                .map_err(serr)?
                .map(|r| r.get::<bool, _>("finalized"));
        match finalized {
            None => return Err(FinalizeError::NoSuchVersion),
            Some(true) => return Err(FinalizeError::AlreadyFinalized),
            Some(false) => {}
        }
        let expected = (current as u64) + 1;
        if version != expected {
            return Err(FinalizeError::VersionConflict {
                expected,
                got: version,
            });
        }

        sqlx::query(
            "UPDATE file_versions SET finalized = true WHERE file_id = $1 AND version = $2",
        )
        .bind(&file_id[..])
        .bind(v)
        .execute(&mut *tx)
        .await
        .map_err(serr)?;
        sqlx::query("UPDATE files SET current_version = $2, updated_at = now() WHERE file_id = $1")
            .bind(&file_id[..])
            .bind(v)
            .execute(&mut *tx)
            .await
            .map_err(serr)?;
        // Drop the prior version's chunks (streams) + wraps; genesis + the prior
        // manifest are retained (api.md §8.4 / §12.9).
        if current >= 1 {
            sqlx::query("DELETE FROM file_streams WHERE file_id = $1 AND version = $2")
                .bind(&file_id[..])
                .bind(current)
                .execute(&mut *tx)
                .await
                .map_err(serr)?;
            sqlx::query("DELETE FROM file_key_wraps WHERE file_id = $1 AND file_version = $2")
                .bind(&file_id[..])
                .bind(current)
                .execute(&mut *tx)
                .await
                .map_err(serr)?;
        }
        tx.commit().await.map_err(serr)?;
        Ok(())
    }

    async fn get_file(
        &self,
        file_id: [u8; 16],
        selector: VersionSelector,
        caller_id: [u8; 16],
    ) -> Result<Option<FileView>, StoreError> {
        let op = "get_file";
        let version: i64 = match selector {
            VersionSelector::Specific(v) => v as i64,
            VersionSelector::Latest => {
                let row = sqlx::query("SELECT current_version FROM files WHERE file_id = $1")
                    .bind(&file_id[..])
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(store_err(op))?;
                match row {
                    Some(r) => r.get::<i64, _>("current_version"),
                    None => return Ok(None),
                }
            }
        };
        if version == 0 {
            return Ok(None); // nothing finalized yet
        }
        // The version row, only if finalized (visible).
        let vrow = sqlx::query(
            "SELECT manifest_bytes, manifest_sig FROM file_versions \
             WHERE file_id = $1 AND version = $2 AND finalized = true",
        )
        .bind(&file_id[..])
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err(op))?;
        let Some(vrow) = vrow else { return Ok(None) };

        // All wraps for this version — for the caller's wrap, the recovery grant
        // (presence check), and the re-share ancestor chain. Their absence (no
        // caller wrap) is a 404 (no access oracle, api.md §8.5).
        let wrows = sqlx::query(
            "SELECT recipient_id, recipient_type, wrapped_dek, granted_by, grant_bytes, grant_sig \
             FROM file_key_wraps WHERE file_id = $1 AND file_version = $2",
        )
        .bind(&file_id[..])
        .bind(version)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err(op))?;
        let mut wraps: Vec<WrapInput> = Vec::with_capacity(wrows.len());
        for r in &wrows {
            wraps.push(WrapInput {
                recipient_id: col_fixed(r, op, "recipient_id")?,
                recipient_type: r.get("recipient_type"),
                wrapped_dek: r.try_get("wrapped_dek").map_err(store_err(op))?,
                wrap_alg: 1,
                granted_by: col_fixed(r, op, "granted_by")?,
                grant_bytes: r.try_get("grant_bytes").map_err(store_err(op))?,
                grant_sig: col_fixed(r, op, "grant_sig")?,
            });
        }
        let Some(my) = wraps.iter().find(|w| w.recipient_id == caller_id) else {
            return Ok(None);
        };
        let recovery_grant = wraps
            .iter()
            .find(|w| w.recipient_type == 2)
            .map(|w| (w.grant_bytes.clone(), w.grant_sig));

        // The author (owner-only write, §11.7) roots the ancestor chain.
        let orow = sqlx::query("SELECT owner_id FROM files WHERE file_id = $1")
            .bind(&file_id[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err(op))?;
        let Some(orow) = orow else { return Ok(None) };
        let owner_id: [u8; 16] = col_fixed(&orow, op, "owner_id")?;
        let ancestor_grants = ancestor_chain(&wraps, my, owner_id);

        let grow =
            sqlx::query("SELECT genesis_bytes, genesis_sig FROM file_genesis WHERE file_id = $1")
                .bind(&file_id[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(store_err(op))?;
        let Some(grow) = grow else { return Ok(None) };

        let srows = sqlx::query(
            "SELECT stream_type, chunk_count, chunk_size, blob_ref FROM file_streams \
             WHERE file_id = $1 AND version = $2 ORDER BY stream_type",
        )
        .bind(&file_id[..])
        .bind(version)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err(op))?;
        let streams = srows
            .iter()
            .map(|r| StreamView {
                stream_type: r.get("stream_type"),
                chunk_count: r.get::<i64, _>("chunk_count") as u64,
                chunk_size: r.get::<i32, _>("chunk_size") as u32,
                blob_ref: r.get("blob_ref"),
            })
            .collect();

        Ok(Some(FileView {
            version: version as u64,
            manifest_bytes: vrow.try_get("manifest_bytes").map_err(store_err(op))?,
            manifest_sig: col_fixed(&vrow, op, "manifest_sig")?,
            genesis_bytes: grow.try_get("genesis_bytes").map_err(store_err(op))?,
            genesis_sig: col_fixed(&grow, op, "genesis_sig")?,
            my_wrap: WrapView {
                wrapped_dek: my.wrapped_dek.clone(),
                grant_bytes: my.grant_bytes.clone(),
                grant_sig: my.grant_sig,
                ancestor_grants,
            },
            recovery_grant,
            streams,
        }))
    }

    async fn list_files(&self, filter: ListFilter) -> Result<Vec<FileListEntry>, StoreError> {
        let op = "list_files";
        let rows = sqlx::query(
            "SELECT file_id, file_type, current_version, updated_at FROM files \
             WHERE current_version >= 1 AND listed = true \
             AND ($1::smallint IS NULL OR file_type = $1) \
             ORDER BY updated_at DESC, file_id LIMIT $2",
        )
        .bind(filter.file_type)
        .bind(filter.limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err(op))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let file_id: [u8; 16] = col_fixed(r, op, "file_id")?;
            let version: i64 = r.get("current_version");
            let updated_at: OffsetDateTime = r.try_get("updated_at").map_err(store_err(op))?;
            let srows = sqlx::query(
                "SELECT stream_type, total_bytes FROM file_streams \
                 WHERE file_id = $1 AND version = $2 AND stream_type <> 1 ORDER BY stream_type",
            )
            .bind(&file_id[..])
            .bind(version)
            .fetch_all(&self.pool)
            .await
            .map_err(store_err(op))?;
            let small_streams = srows
                .iter()
                .map(|s| {
                    (
                        s.get::<i16, _>("stream_type"),
                        s.get::<i64, _>("total_bytes") as u64,
                    )
                })
                .collect();
            out.push(FileListEntry {
                file_id,
                file_type: r.get("file_type"),
                version: version as u64,
                updated_at_ms: ts_to_ms(updated_at),
                small_streams,
            });
        }
        Ok(out)
    }

    async fn version_meta(
        &self,
        file_id: [u8; 16],
        version: u64,
    ) -> Result<Option<VersionMeta>, StoreError> {
        let op = "version_meta";
        let v = version as i64;
        let frow = sqlx::query(
            "SELECT f.owner_id, fv.finalized FROM file_versions fv \
             JOIN files f ON f.file_id = fv.file_id \
             WHERE fv.file_id = $1 AND fv.version = $2",
        )
        .bind(&file_id[..])
        .bind(v)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err(op))?;
        let Some(frow) = frow else { return Ok(None) };

        let srows = sqlx::query(
            "SELECT stream_type, blob_ref, chunk_count, chunk_size FROM file_streams \
             WHERE file_id = $1 AND version = $2 ORDER BY stream_type",
        )
        .bind(&file_id[..])
        .bind(v)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err(op))?;
        let streams = srows
            .iter()
            .map(|s| ChunkSlot {
                stream_type: s.get("stream_type"),
                blob_ref: s.get("blob_ref"),
                chunk_count: s.get::<i64, _>("chunk_count") as u64,
                chunk_size: s.get::<i32, _>("chunk_size") as u32,
            })
            .collect();
        Ok(Some(VersionMeta {
            owner_id: col_fixed(&frow, op, "owner_id")?,
            finalized: frow.get("finalized"),
            streams,
        }))
    }

    async fn get_file_meta(&self, file_id: [u8; 16]) -> Result<Option<FileMeta>, StoreError> {
        let op = "get_file_meta";
        let row = sqlx::query(
            "SELECT owner_id, file_type, listed, bundle_id FROM files WHERE file_id = $1",
        )
        .bind(&file_id[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err(op))?;
        let Some(row) = row else { return Ok(None) };
        // `bundle_id` is a nullable 16-byte BYTEA; widen-check like `col_fixed`.
        let raw: Option<Vec<u8>> = row.try_get("bundle_id").map_err(store_err(op))?;
        let bundle_id = match raw {
            Some(v) => Some(v.try_into().map_err(|_| {
                StoreError::new(op, "column `bundle_id` has unexpected width".to_string())
            })?),
            None => None,
        };
        Ok(Some(FileMeta {
            owner_id: col_fixed(&row, op, "owner_id")?,
            file_type: row.get("file_type"),
            listed: row.get("listed"),
            bundle_id,
        }))
    }

    async fn add_wrap(
        &self,
        file_id: [u8; 16],
        wrap: WrapInput,
        caller_id: [u8; 16],
        now_ms: u64,
    ) -> Result<(), AddWrapError> {
        let op = "add_wrap";
        // Body consistency (re-sharer signs as themselves; user recipient only).
        if wrap.granted_by != caller_id
            || wrap.recipient_type != 1
            || wrap.recipient_id == maxsecu_encoding::RECOVERY_ID.0
        {
            return Err(AddWrapError::BadRequest);
        }
        // Current finalized version (files.current_version is 0 until first
        // finalize); absent file or none-finalized ⇒ no access (no oracle).
        let frow = sqlx::query("SELECT current_version FROM files WHERE file_id = $1")
            .bind(&file_id[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err(op))?;
        let version = match frow {
            Some(r) => r.get::<i64, _>("current_version"),
            None => return Err(AddWrapError::NoAccess),
        };
        if version == 0 {
            return Err(AddWrapError::NoAccess);
        }
        // Coarse §10.1: the caller must already hold a wrap for this version.
        let holds = sqlx::query(
            "SELECT 1 FROM file_key_wraps \
             WHERE file_id = $1 AND file_version = $2 AND recipient_id = $3",
        )
        .bind(&file_id[..])
        .bind(version)
        .bind(&caller_id[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err(op))?;
        if holds.is_none() {
            return Err(AddWrapError::NoAccess);
        }
        // Idempotent by recipient — a re-share replaces an existing row.
        sqlx::query(
            "INSERT INTO file_key_wraps \
               (file_id, file_version, recipient_id, recipient_type, wrapped_dek, wrap_alg, \
                granted_by, grant_bytes, grant_sig) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (file_id, file_version, recipient_id) DO UPDATE SET \
               recipient_type = EXCLUDED.recipient_type, wrapped_dek = EXCLUDED.wrapped_dek, \
               wrap_alg = EXCLUDED.wrap_alg, granted_by = EXCLUDED.granted_by, \
               grant_bytes = EXCLUDED.grant_bytes, grant_sig = EXCLUDED.grant_sig",
        )
        .bind(&file_id[..])
        .bind(version)
        .bind(&wrap.recipient_id[..])
        .bind(wrap.recipient_type)
        .bind(&wrap.wrapped_dek[..])
        .bind(wrap.wrap_alg)
        .bind(&wrap.granted_by[..])
        .bind(&wrap.grant_bytes[..])
        .bind(&wrap.grant_sig[..])
        .execute(&self.pool)
        .await
        .map_err(store_err(op))?;
        sqlx::query("UPDATE files SET updated_at = $2 WHERE file_id = $1")
            .bind(&file_id[..])
            .bind(ms_to_ts(now_ms))
            .execute(&self.pool)
            .await
            .map_err(store_err(op))?;
        Ok(())
    }

    async fn delete_wrap(
        &self,
        file_id: [u8; 16],
        recipient_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<(), DeleteWrapError> {
        let op = "delete_wrap";
        let frow = sqlx::query("SELECT owner_id, current_version FROM files WHERE file_id = $1")
            .bind(&file_id[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err(op))?;
        let Some(frow) = frow else {
            return Err(DeleteWrapError::NotFound);
        };
        let owner_id: [u8; 16] = col_fixed(&frow, op, "owner_id")?;
        let version: i64 = frow.get("current_version");
        if version == 0 {
            return Err(DeleteWrapError::NotFound);
        }
        let wrow = sqlx::query(
            "SELECT granted_by FROM file_key_wraps \
             WHERE file_id = $1 AND file_version = $2 AND recipient_id = $3",
        )
        .bind(&file_id[..])
        .bind(version)
        .bind(&recipient_id[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err(op))?;
        let Some(wrow) = wrow else {
            return Err(DeleteWrapError::NotFound);
        };
        let granted_by: [u8; 16] = col_fixed(&wrow, op, "granted_by")?;
        // Coarse owner-or-granter gate (§14.5).
        if caller_id != owner_id && caller_id != granted_by {
            return Err(DeleteWrapError::NotAuthorized);
        }
        sqlx::query(
            "DELETE FROM file_key_wraps \
             WHERE file_id = $1 AND file_version = $2 AND recipient_id = $3",
        )
        .bind(&file_id[..])
        .bind(version)
        .bind(&recipient_id[..])
        .execute(&self.pool)
        .await
        .map_err(store_err(op))?;
        Ok(())
    }

    async fn list_recipients(
        &self,
        file_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<Option<Vec<RecipientView>>, StoreError> {
        let op = "list_recipients";
        // Owner-only; absent file or non-owner caller ⇒ None (no oracle).
        let frow = sqlx::query("SELECT owner_id, current_version FROM files WHERE file_id = $1")
            .bind(&file_id[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err(op))?;
        let Some(frow) = frow else { return Ok(None) };
        let owner_id: [u8; 16] = col_fixed(&frow, op, "owner_id")?;
        if owner_id != caller_id {
            return Ok(None);
        }
        let version: i64 = frow.get("current_version");
        if version == 0 {
            return Ok(None);
        }
        // All wraps for the current version — to assemble each recipient's chain.
        let wrows = sqlx::query(
            "SELECT recipient_id, recipient_type, wrapped_dek, granted_by, grant_bytes, grant_sig \
             FROM file_key_wraps WHERE file_id = $1 AND file_version = $2",
        )
        .bind(&file_id[..])
        .bind(version)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err(op))?;
        let mut wraps: Vec<WrapInput> = Vec::with_capacity(wrows.len());
        for r in &wrows {
            wraps.push(WrapInput {
                recipient_id: col_fixed(r, op, "recipient_id")?,
                recipient_type: r.get("recipient_type"),
                wrapped_dek: r.try_get("wrapped_dek").map_err(store_err(op))?,
                wrap_alg: 1,
                granted_by: col_fixed(r, op, "granted_by")?,
                grant_bytes: r.try_get("grant_bytes").map_err(store_err(op))?,
                grant_sig: col_fixed(r, op, "grant_sig")?,
            });
        }
        let out = wraps
            .iter()
            .filter(|w| w.recipient_type == 1)
            .map(|w| RecipientView {
                recipient_id: w.recipient_id,
                granted_by: w.granted_by,
                grant_bytes: w.grant_bytes.clone(),
                grant_sig: w.grant_sig,
                ancestor_grants: ancestor_chain(&wraps, w, owner_id),
            })
            .collect();
        Ok(Some(out))
    }

    async fn discard_unfinalized(
        &self,
        file_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<Vec<String>, DiscardError> {
        let op = "discard_unfinalized";
        let serr = |e: sqlx::Error| DiscardError::Store(store_err(op)(e));

        // Check the file exists, verify caller is the owner, and confirm there is no
        // finalized version (the append-only model forbids removing finalized content).
        let frow = sqlx::query("SELECT owner_id, current_version FROM files WHERE file_id = $1")
            .bind(&file_id[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(serr)?;
        let Some(frow) = frow else {
            return Ok(vec![]); // idempotent: absent file has no staged version
        };
        let owner_id: [u8; 16] = col_fixed(&frow, op, "owner_id").map_err(DiscardError::Store)?;
        if owner_id != caller_id {
            return Err(DiscardError::NotFound); // no oracle
        }
        let current_version: i64 = frow.get("current_version");
        if current_version >= 1 {
            return Err(DiscardError::HasFinalizedVersion);
        }

        // Collect blob_refs of the unfinalized version's streams before deleting rows.
        let srows = sqlx::query(
            "SELECT fs.blob_ref FROM file_streams fs \
             JOIN file_versions fv ON fv.file_id = fs.file_id AND fv.version = fs.version \
             WHERE fs.file_id = $1 AND fv.finalized = false",
        )
        .bind(&file_id[..])
        .fetch_all(&self.pool)
        .await
        .map_err(serr)?;
        let blob_refs: Vec<String> = srows.iter().map(|r| r.get("blob_ref")).collect();

        // Delete the unfinalized file_versions row; CASCADE removes file_streams and
        // file_key_wraps rows (same path as the idempotent re-stage overwrite, §12).
        // The append-only trigger only blocks finalized=true rows; WHERE finalized=false
        // is the exact same predicate used by the re-stage DELETE in stage_version.
        sqlx::query("DELETE FROM file_versions WHERE file_id = $1 AND finalized = false")
            .bind(&file_id[..])
            .execute(&self.pool)
            .await
            .map_err(serr)?;

        // Leave file_genesis (immutable, §11.7) and files (inert, current_version = 0).
        Ok(blob_refs)
    }

    async fn delete_file(
        &self,
        file_id: [u8; 16],
        owner_id: [u8; 16],
    ) -> Result<Vec<String>, DeleteError> {
        let op = "delete_file";
        let serr = |e: sqlx::Error| DeleteError::Store(store_err(op)(e));
        let mut tx = self.pool.begin().await.map_err(serr)?;

        // Transaction-local carve-out over the append-only triggers (schema.sql):
        // ONLY inside this `SET LOCAL` scope may `file_genesis` / a *finalized*
        // `file_versions` row be deleted (the guards allow it iff this GUC is
        // 'on'). `SET LOCAL` auto-resets at COMMIT/ROLLBACK, so no other
        // statement or connection is ever affected, and every other code path
        // leaves the GUC unset → immutability holds. `directory_bindings` and
        // `control_log` keep their own shared guard and stay fully immutable.
        sqlx::query("SET LOCAL maxsecu.allow_owner_delete = 'on'")
            .execute(&mut *tx)
            .await
            .map_err(serr)?;

        // Owner-check the target under a row lock. No oracle: an absent file and
        // a non-owner both collapse to NotFound (early return → ROLLBACK, so the
        // GUC never persists and nothing is deleted).
        let frow =
            sqlx::query("SELECT owner_id, file_type FROM files WHERE file_id = $1 FOR UPDATE")
                .bind(&file_id[..])
                .fetch_optional(&mut *tx)
                .await
                .map_err(serr)?;
        let Some(frow) = frow else {
            return Err(DeleteError::NotFound);
        };
        let target_owner: [u8; 16] =
            col_fixed(&frow, op, "owner_id").map_err(DeleteError::Store)?;
        if target_owner != owner_id {
            return Err(DeleteError::NotFound); // non-owner is indistinguishable from missing
        }
        let file_type: i16 = frow.get("file_type");

        // The delete set: the target plus — only for a bundle — every member it
        // OWNS. The `owner_id = $2` predicate makes the cascade owner-scoped: a
        // member another user pointed at this bundle (a member declares its own
        // `bundle_id`) is NEVER removed by this owner's delete. NB: this SELECT is
        // not `FOR UPDATE`, so a concurrent member-insert could race — benign here,
        // since a bundle + its members are created atomically by the single owner
        // and the enclosing txn already prevents a partial cascade (no locking /
        // recursion needed).
        let mut targets: Vec<[u8; 16]> = vec![file_id];
        if file_type == BUNDLE_FILE_TYPE {
            let mrows =
                sqlx::query("SELECT file_id FROM files WHERE bundle_id = $1 AND owner_id = $2")
                    .bind(&file_id[..])
                    .bind(&owner_id[..])
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(serr)?;
            for r in &mrows {
                targets.push(col_fixed(r, op, "file_id").map_err(DeleteError::Store)?);
            }
        }
        let target_slices: Vec<Vec<u8>> = targets.iter().map(|t| t[..].to_vec()).collect();

        // Every stream's blob_ref across all versions of all targets, collected
        // before the rows go away so the handler can purge the blob tier.
        let srows =
            sqlx::query("SELECT blob_ref FROM file_streams WHERE file_id = ANY($1::bytea[])")
                .bind(&target_slices)
                .fetch_all(&mut *tx)
                .await
                .map_err(serr)?;
        let blob_refs: Vec<String> = srows.iter().map(|r| r.get("blob_ref")).collect();

        // Delete respecting FKs: file_versions first (ON DELETE CASCADE tears down
        // file_streams + file_key_wraps), then the immutable file_genesis, then
        // the files row — all under the GUC carve-out.
        sqlx::query("DELETE FROM file_versions WHERE file_id = ANY($1::bytea[])")
            .bind(&target_slices)
            .execute(&mut *tx)
            .await
            .map_err(serr)?;
        sqlx::query("DELETE FROM file_genesis WHERE file_id = ANY($1::bytea[])")
            .bind(&target_slices)
            .execute(&mut *tx)
            .await
            .map_err(serr)?;
        sqlx::query("DELETE FROM files WHERE file_id = ANY($1::bytea[])")
            .bind(&target_slices)
            .execute(&mut *tx)
            .await
            .map_err(serr)?;

        tx.commit().await.map_err(serr)?;
        Ok(blob_refs)
    }
}

/// Map an optional `(binding_bytes, directory_signature)` row to a [`StoredBinding`].
fn binding_from_row(
    row: Option<PgRow>,
    op: &'static str,
) -> Result<Option<StoredBinding>, StoreError> {
    let Some(row) = row else { return Ok(None) };
    let binding_bytes: Vec<u8> = row.try_get("binding_bytes").map_err(store_err(op))?;
    Ok(Some(StoredBinding {
        binding_bytes,
        signature: col_fixed(&row, op, "directory_signature")?,
    }))
}

/// Map a `control_log` row to a [`StoredControlRecord`] (a present-but-wrong-width
/// `co_sig` is a data-integrity fault, not a missing co-signature).
fn control_record_from_row(row: &PgRow) -> Result<StoredControlRecord, StoreError> {
    let op = "control_records";
    let kind: i16 = row.try_get("kind").map_err(store_err(op))?;
    let record_bytes: Vec<u8> = row.try_get("record_bytes").map_err(store_err(op))?;
    let co_sig: Option<Vec<u8>> = row.try_get("co_sig").map_err(store_err(op))?;
    let co_sig = match co_sig {
        Some(v) => Some(
            v.try_into()
                .map_err(|_| StoreError::new(op, "co_sig has unexpected width"))?,
        ),
        None => None,
    };
    Ok(StoredControlRecord {
        kind,
        record_bytes,
        sig: col_fixed(row, op, "sig")?,
        co_sig,
        head: col_fixed(row, op, "head")?,
    })
}
