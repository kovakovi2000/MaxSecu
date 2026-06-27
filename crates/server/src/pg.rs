//! Postgres-backed [`Store`] — the production persistence adapter over the
//! Phase-1 tables in `docs/schema.sql` (`users`, `auth_nonces`, `sessions`,
//! `enrollment_vouchers`). Every row is inert/ephemeral auth state; no secret,
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
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::Role;
use maxsecu_encoding::GENESIS_HEAD;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;

use crate::control::{decode_control, role_from_text, role_text};
use crate::error::{ControlAppendError, StoreError};
use crate::store::{SessionRecord, StoredBinding, StoredControlRecord, Store, UserRecord};

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

    async fn consume_voucher(&self, voucher_hash: &[u8; 32]) -> Result<bool, StoreError> {
        // Atomic single-use: the `used_at IS NULL` predicate means exactly one of
        // any racing consumers updates the row. `expires_at` is the operational
        // voucher TTL (DB clock — no app `now` is passed here).
        let res = sqlx::query(
            "UPDATE enrollment_vouchers SET used_at = now() \
             WHERE voucher_hash = $1 AND used_at IS NULL AND expires_at > now()",
        )
        .bind(&voucher_hash[..])
        .execute(&self.pool)
        .await
        .map_err(store_err("consume_voucher"))?;
        Ok(res.rows_affected() == 1)
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
            .bind(username)
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
        .bind(username)
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
        let expires_at: OffsetDateTime =
            row.try_get("expires_at").map_err(store_err("get_session"))?;
        let revoked_at: Option<OffsetDateTime> =
            row.try_get("revoked_at").map_err(store_err("get_session"))?;
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
            Some(ms) => Some(try_ms_to_ts(ms, "append_control").map_err(ControlAppendError::Store)?),
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

    async fn user_roles(&self, user_id: &[u8; 16]) -> Result<Vec<Role>, StoreError> {
        let row = sqlx::query("SELECT roles FROM users WHERE user_id = $1")
            .bind(&user_id[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err("user_roles"))?;
        let Some(row) = row else { return Ok(Vec::new()) };
        let roles: Vec<String> = row.try_get("roles").map_err(store_err("user_roles"))?;
        Ok(roles.iter().filter_map(|s| role_from_text(s)).collect())
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
