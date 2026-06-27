//! `PgStore` integration tests against a live Postgres (WSL `Ubuntu-22.04`,
//! role/db `maxsecu`). Each test loads the **real** `docs/schema.sql` into a
//! fresh, uniquely-named schema (drift-free, parallel-safe) and drops it after.
//!
//! Set `MAXSECU_TEST_PG` to override the connection string; if Postgres is
//! unreachable (e.g. on the Windows client box) the tests **skip** loudly rather
//! than fail — they are meant to run in the WSL server environment.

use maxsecu_crypto::{random_array, sha256, SigningKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::AuthProofContext;
use maxsecu_encoding::types::{Bytes32, Text, Timestamp};
use maxsecu_server::{AuthConfig, AuthService, PgStore, SessionRecord, Store};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};

const SCHEMA_SQL: &str = include_str!("../../../docs/schema.sql");
const EXPORTER: [u8; 32] = [0xE7; 32];
const TS: u64 = 1_719_500_000_000;

fn base_url() -> String {
    std::env::var("MAXSECU_TEST_PG")
        .unwrap_or_else(|_| "postgres://maxsecu:maxsecu@localhost/maxsecu?sslmode=disable".to_owned())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// A throwaway schema holding the Phase-1 tables, plus the pool under test.
struct TestDb {
    store: PgStore,
    admin: PgPool, // no search_path — used only to create/drop the schema
    schema: String,
    url: String,
}

impl TestDb {
    /// Returns `None` (skip) if Postgres is unreachable.
    async fn setup() -> Option<TestDb> {
        let url = base_url();
        let admin = match PgPoolOptions::new().max_connections(1).connect(&url).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIP pg_store: cannot reach Postgres at {url}: {e}");
                return None;
            }
        };
        let schema = format!("mxtest_{}", hex(&random_array::<6>()));
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&admin)
            .await
            .unwrap();

        let opts: PgConnectOptions = url.parse().unwrap();
        let opts = opts.options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::raw_sql(SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("load docs/schema.sql into the test schema");

        Some(TestDb {
            store: PgStore::new(pool),
            admin,
            schema,
            url,
        })
    }

    /// A second `PgStore` over the same schema but a *fresh* pool — proving a
    /// fact survives in the DB, not in one process's memory.
    async fn reopen(&self) -> PgStore {
        let opts: PgConnectOptions = self.url.parse().unwrap();
        let opts = opts.options([("search_path", self.schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(opts)
            .await
            .unwrap();
        PgStore::new(pool)
    }

    /// Seed an admin user (the in-person voucher issuer; satisfies the
    /// `enrollment_vouchers.issued_by` FK). Returns its `user_id`.
    async fn seed_admin(&self) -> [u8; 16] {
        let id: [u8; 16] = random_array();
        sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1,$2,$3,$4)")
            .bind(&id[..])
            .bind("admin")
            .bind(&[0xAAu8; 32][..])
            .bind(&[0xBBu8; 32][..])
            .execute(self.store.pool())
            .await
            .unwrap();
        id
    }

    /// Seed a usable, unexpired enrollment voucher by its plaintext code.
    async fn seed_voucher(&self, issued_by: &[u8; 16], code: &str) {
        let h = sha256(code.as_bytes());
        sqlx::query(
            "INSERT INTO enrollment_vouchers (voucher_hash, issued_by, expires_at) \
             VALUES ($1, $2, now() + interval '1 day')",
        )
        .bind(&h[..])
        .bind(&issued_by[..])
        .execute(self.store.pool())
        .await
        .unwrap();
    }

    async fn teardown(self) {
        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{}\" CASCADE", self.schema))
            .execute(&self.admin)
            .await;
    }
}

/// Skip-or-run helper: returns the `TestDb` or prints a skip and bails the test.
macro_rules! db_or_skip {
    () => {
        match TestDb::setup().await {
            Some(db) => db,
            None => return,
        }
    };
}

fn make_proof(sk: &SigningKey, server_id: &str, nonce: &[u8; 32], ts: u64) -> [u8; 64] {
    let ctx = AuthProofContext {
        server_id: Text::new(server_id).unwrap(),
        tls_exporter: Bytes32(EXPORTER),
        nonce: Bytes32(*nonce),
        timestamp: Timestamp(ts),
    };
    sk.sign_canonical(labels::AUTH, &ctx)
}

#[tokio::test]
async fn register_then_full_login_persists_in_postgres() {
    let db = db_or_skip!();

    // In-person enrollment: admin issues a voucher; the new user consumes it.
    let admin = db.seed_admin().await;
    db.seed_voucher(&admin, "voucher-1").await;
    assert!(
        db.store.consume_voucher(&sha256(b"voucher-1")).await,
        "valid unused voucher consumes"
    );

    let sk = SigningKey::generate();
    let user_id = db
        .store
        .create_user("bob", [0xE1; 32], sk.verifying_key().to_bytes())
        .await
        .expect("create_user returns a fresh id");
    assert_eq!(user_id.len(), 16);

    // Full channel-bound login over the PgStore.
    let svc = AuthService::new(db.store.clone(), AuthConfig::default());
    let ch = svc.challenge("bob", TS).await.unwrap();
    let proof = make_proof(&sk, svc.server_id(), &ch.nonce, TS);
    let token = svc
        .prove("bob", TS, &proof, &EXPORTER, TS)
        .await
        .expect("login succeeds");

    // The session resolves to the user — read back through a FRESH pool, so the
    // session truly lives in Postgres.
    let svc2 = AuthService::new(db.reopen().await, AuthConfig::default());
    assert_eq!(
        svc2.validate_session(token.as_bytes(), &EXPORTER, TS + 1)
            .await
            .unwrap(),
        user_id
    );

    db.teardown().await;
}

#[tokio::test]
async fn duplicate_username_returns_none() {
    let db = db_or_skip!();
    assert!(db
        .store
        .create_user("carol", [0x01; 32], [0x02; 32])
        .await
        .is_some());
    assert!(
        db.store
            .create_user("carol", [0x03; 32], [0x04; 32])
            .await
            .is_none(),
        "second create with the same username is a 409 (None)"
    );
    db.teardown().await;
}

#[tokio::test]
async fn voucher_is_single_use_and_unknown_is_false() {
    let db = db_or_skip!();
    let admin = db.seed_admin().await;
    db.seed_voucher(&admin, "one-shot").await;
    assert!(db.store.consume_voucher(&sha256(b"one-shot")).await);
    assert!(
        !db.store.consume_voucher(&sha256(b"one-shot")).await,
        "second consume of the same voucher fails"
    );
    assert!(
        !db.store.consume_voucher(&sha256(b"never-issued")).await,
        "unknown voucher fails"
    );
    db.teardown().await;
}

#[tokio::test]
async fn nonce_outstanding_respects_ttl_and_single_use() {
    let db = db_or_skip!();
    let nonce: [u8; 32] = random_array();
    // Expires at TS+1000 (the u64-ms ↔ TIMESTAMPTZ mapping under test).
    db.store.insert_nonce(nonce, "dave", TS + 1000).await;

    assert_eq!(
        db.store.outstanding_nonces("dave", TS).await,
        vec![nonce],
        "fresh nonce is outstanding before expiry"
    );
    assert!(
        db.store
            .outstanding_nonces("dave", TS + 2000)
            .await
            .is_empty(),
        "nonce past its expiry is not outstanding"
    );

    // Single-use: consuming removes it from the outstanding set.
    db.store.consume_nonce(&nonce).await;
    assert!(
        db.store.outstanding_nonces("dave", TS).await.is_empty(),
        "consumed nonce is not outstanding"
    );
    db.teardown().await;
}

#[tokio::test]
async fn session_channel_bind_expiry_and_revoke() {
    let db = db_or_skip!();
    let user_id: [u8; 16] = random_array();
    sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1,$2,$3,$4)")
        .bind(&user_id[..])
        .bind("erin")
        .bind(&[0xE1u8; 32][..])
        .bind(&[0xE2u8; 32][..])
        .execute(db.store.pool())
        .await
        .unwrap();

    let token: [u8; 32] = random_array();
    let token_hash = sha256(&token);
    db.store
        .insert_session(
            token_hash,
            SessionRecord {
                user_id,
                tls_exporter: EXPORTER,
                expires_at_ms: TS + 3_600_000,
                revoked: false,
            },
        )
        .await;

    let svc = AuthService::new(db.store.clone(), AuthConfig::default());
    // Right channel, not expired → ok.
    assert_eq!(
        svc.validate_session(&token, &EXPORTER, TS + 1).await.unwrap(),
        user_id
    );
    // Wrong channel → 401.
    assert!(svc.validate_session(&token, &[0x00; 32], TS + 1).await.is_err());
    // Expired → 401.
    assert!(svc
        .validate_session(&token, &EXPORTER, TS + 3_600_001)
        .await
        .is_err());
    // Revoked (persisted) → 401, even on the right channel.
    db.store.revoke_session(&token_hash).await;
    assert!(svc.validate_session(&token, &EXPORTER, TS + 1).await.is_err());

    db.teardown().await;
}

/// Unknown user → `user_by_name` is `None`; a seeded user round-trips exactly.
#[tokio::test]
async fn user_by_name_round_trips() {
    let db = db_or_skip!();
    assert!(db.store.user_by_name("ghost").await.is_none());

    let enc = [0x11; 32];
    let sig = [0x22; 32];
    let id = db.store.create_user("frank", enc, sig).await.unwrap();
    let rec = db.store.user_by_name("frank").await.expect("frank exists");
    assert_eq!(rec.user_id, id);
    assert_eq!(rec.enc_pub, enc);
    assert_eq!(rec.sig_pub, sig);
    db.teardown().await;
}
