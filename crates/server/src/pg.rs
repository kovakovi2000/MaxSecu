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
//! **Fail-closed.** The [`Store`] contract is infallible (it was shaped for the
//! in-memory backing). A real DB call can fail; an unexpected error here maps to
//! the *safe* fallback (`None`/empty/`false`) so a transient fault denies rather
//! than grants. (Follow-up: make `Store` return `Result` for observability.)

use async_trait::async_trait;
use maxsecu_crypto::random_array;
use sqlx::postgres::PgPool;
use sqlx::Row;
use time::OffsetDateTime;

use crate::store::{SessionRecord, Store, UserRecord};

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

/// App epoch-ms → `TIMESTAMPTZ`. Total over the representable range we use.
fn ms_to_ts(ms: u64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .expect("epoch-ms within OffsetDateTime range")
}

/// `TIMESTAMPTZ` → app epoch-ms (truncating sub-ms, which we never store).
fn ts_to_ms(ts: OffsetDateTime) -> u64 {
    (ts.unix_timestamp_nanos() / 1_000_000) as u64
}

/// A `bytea` column → fixed-width array, or `None` on the wrong width.
fn fixed<const N: usize>(v: Vec<u8>) -> Option<[u8; N]> {
    v.try_into().ok()
}

#[async_trait]
impl Store for PgStore {
    async fn create_user(
        &self,
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
    ) -> Option<[u8; 16]> {
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
            Ok(_) => Some(user_id),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => None, // username taken → 409
            Err(_) => None,                                                   // fail-closed
        }
    }

    async fn consume_voucher(&self, voucher_hash: &[u8; 32]) -> bool {
        // Atomic single-use: the `used_at IS NULL` predicate means exactly one of
        // any racing consumers updates the row. `expires_at` is the operational
        // voucher TTL (DB clock — no app `now` is passed here).
        let res = sqlx::query(
            "UPDATE enrollment_vouchers SET used_at = now() \
             WHERE voucher_hash = $1 AND used_at IS NULL AND expires_at > now()",
        )
        .bind(&voucher_hash[..])
        .execute(&self.pool)
        .await;
        matches!(res, Ok(r) if r.rows_affected() == 1)
    }

    async fn user_by_name(&self, username: &str) -> Option<UserRecord> {
        let row = sqlx::query("SELECT user_id, enc_pub, sig_pub FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()?;
        Some(UserRecord {
            user_id: fixed(row.try_get("user_id").ok()?)?,
            enc_pub: fixed(row.try_get("enc_pub").ok()?)?,
            sig_pub: fixed(row.try_get("sig_pub").ok()?)?,
        })
    }

    async fn insert_nonce(&self, nonce: [u8; 32], username: &str, expires_at_ms: u64) {
        let _ = sqlx::query(
            "INSERT INTO auth_nonces (nonce, username, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&nonce[..])
        .bind(username)
        .bind(ms_to_ts(expires_at_ms))
        .execute(&self.pool)
        .await; // fail-closed: a missing nonce simply can't be proven against
    }

    async fn outstanding_nonces(&self, username: &str, now_ms: u64) -> Vec<[u8; 32]> {
        let rows = sqlx::query(
            "SELECT nonce FROM auth_nonces \
             WHERE username = $1 AND used_at IS NULL AND expires_at > $2",
        )
        .bind(username)
        .bind(ms_to_ts(now_ms))
        .fetch_all(&self.pool)
        .await;
        match rows {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|r| fixed(r.try_get("nonce").ok()?))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn consume_nonce(&self, nonce: &[u8; 32]) {
        let _ = sqlx::query("UPDATE auth_nonces SET used_at = now() WHERE nonce = $1 AND used_at IS NULL")
            .bind(&nonce[..])
            .execute(&self.pool)
            .await;
    }

    async fn insert_session(&self, token_hash: [u8; 32], rec: SessionRecord) {
        let _ = sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, tls_exporter, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&token_hash[..])
        .bind(&rec.user_id[..])
        .bind(&rec.tls_exporter[..])
        .bind(ms_to_ts(rec.expires_at_ms))
        .execute(&self.pool)
        .await;
    }

    async fn get_session(&self, token_hash: &[u8; 32]) -> Option<SessionRecord> {
        let row = sqlx::query(
            "SELECT user_id, tls_exporter, expires_at, revoked_at FROM sessions \
             WHERE token_hash = $1",
        )
        .bind(&token_hash[..])
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;
        let expires_at: OffsetDateTime = row.try_get("expires_at").ok()?;
        let revoked_at: Option<OffsetDateTime> = row.try_get("revoked_at").ok()?;
        Some(SessionRecord {
            user_id: fixed(row.try_get("user_id").ok()?)?,
            tls_exporter: fixed(row.try_get("tls_exporter").ok()?)?,
            expires_at_ms: ts_to_ms(expires_at),
            revoked: revoked_at.is_some(),
        })
    }

    async fn revoke_session(&self, token_hash: &[u8; 32]) {
        let _ = sqlx::query("UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL")
            .bind(&token_hash[..])
            .execute(&self.pool)
            .await;
    }
}
