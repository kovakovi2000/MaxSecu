//! `PgStore` integration tests against a live Postgres (WSL `Ubuntu-22.04`,
//! role/db `maxsecu`). Each test loads the **real** `docs/schema.sql` into a
//! fresh, uniquely-named schema (drift-free, parallel-safe) and drops it after.
//!
//! Set `MAXSECU_TEST_PG` to override the connection string. An unreachable
//! Postgres **fails** the suite (the gate must run, never pass vacuously) unless
//! `MAXSECU_PG_OPTIONAL=1` is set, which downgrades it to a loud skip (P5.0b).

use maxsecu_crypto::{random_array, sha256, SigningKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{
    AuthProofContext, DirBinding, Genesis, Manifest, Stream, MLKEM768_PUB_LEN,
};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileType, Id, Role, RoleSet, StreamType, Suite, Text, Timestamp,
};
use maxsecu_encoding::{encode, RECOVERY_ID};
use maxsecu_server::{
    parse_stage, router, AddWrapError, AppState, AuthConfig, AuthService, DeleteError,
    DeleteWrapError, EnrollOutcome, FinalizeError, GenesisInput, ListFilter, ListSort,
    MemoryBlobStore, NullAuditSink, PgStore, RecoveryAccount, SessionRecord, StageError,
    StageInput, Store, StoredBinding, TlsExporter, VersionSelector, WrapInput, AUTH_PRUNE_BATCH,
    AUTH_PRUNE_GRACE_MS,
};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::sync::Arc;

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use tower::ServiceExt; // oneshot

const SCHEMA_SQL: &str = include_str!("../../../docs/schema.sql");
const EXPORTER: [u8; 32] = [0xE7; 32];
const TS: u64 = 1_719_500_000_000;

fn base_url() -> String {
    std::env::var("MAXSECU_TEST_PG").unwrap_or_else(|_| {
        "postgres://maxsecu:maxsecu@localhost/maxsecu?sslmode=disable".to_owned()
    })
}

/// Policy (P5.0b): an unreachable Postgres is a **hard failure** — the PG gate
/// must actually run, never pass vacuously — unless the operator explicitly opts
/// out (a dev box with no Postgres). Pure so it is unit-tested without env races.
fn pg_unreachable_is_fatal(pg_optional: bool) -> bool {
    !pg_optional
}

/// The opt-out switch: `MAXSECU_PG_OPTIONAL=1` downgrades an unreachable PG from
/// a suite failure to a loud skip.
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

/// A throwaway schema holding the Phase-1 tables, plus the pool under test.
struct TestDb {
    store: PgStore,
    admin: PgPool, // no search_path — used only to create/drop the schema
    schema: String,
    url: String,
}

impl TestDb {
    /// Connects to Postgres. **Fails the suite** if unreachable (the PG gate must
    /// run), unless `MAXSECU_PG_OPTIONAL=1`, in which case it returns `None`
    /// (loud skip). It never silently passes when PG is down (P5.0b).
    async fn setup() -> Option<TestDb> {
        let url = base_url();
        let admin = match PgPoolOptions::new().max_connections(1).connect(&url).await {
            Ok(p) => p,
            Err(e) => {
                if pg_unreachable_is_fatal(pg_optional_env()) {
                    panic!(
                        "pg_store: cannot reach Postgres at {url}: {e}\n\
                         The PG integration gate must run on both targets. Start Postgres \
                         (WSL Ubuntu-22.04, role/db `maxsecu`) or set MAXSECU_PG_OPTIONAL=1 \
                         to skip the PG suite on a box without Postgres."
                    );
                }
                eprintln!(
                    "SKIP pg_store (MAXSECU_PG_OPTIONAL=1): cannot reach Postgres at {url}: {e}"
                );
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

    /// Seed a user with a chosen `user_id` (for `files.owner_id` FK).
    async fn seed_user(&self, id: [u8; 16], name: &str) {
        sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1,$2,$3,$4)")
            .bind(&id[..])
            .bind(name)
            .bind(&[0xAAu8; 32][..])
            .bind(&[0xBBu8; 32][..])
            .execute(self.store.pool())
            .await
            .unwrap();
    }

    async fn teardown(self) {
        let _ = sqlx::query(&format!(
            "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
            self.schema
        ))
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

#[test]
fn unreachable_pg_is_fatal_unless_opted_out() {
    // Default posture: an unreachable Postgres must FAIL the suite (the PG gate
    // is not allowed to pass vacuously). Only the explicit opt-out downgrades it
    // to a skip.
    assert!(
        pg_unreachable_is_fatal(false),
        "default: unreachable Postgres fails the suite"
    );
    assert!(
        !pg_unreachable_is_fatal(true),
        "MAXSECU_PG_OPTIONAL=1: unreachable Postgres skips instead"
    );
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

/// Build a canonical, D5-signed binding for `user_id` with the given roles — the
/// exact wire form `enroll` decodes to populate the projection columns.
fn signed_binding(
    d5: &SigningKey,
    user_id: [u8; 16],
    username: &str,
    enc_pub: [u8; 32],
    sig_pub: [u8; 32],
    admin: bool,
) -> StoredBinding {
    let roles = if admin {
        RoleSet::new([Role::User, Role::Admin])
    } else {
        RoleSet::new([Role::User])
    };
    let b = DirBinding {
        username: Text::new(username).unwrap(),
        user_id: Id(user_id),
        enc_pub: Bytes32(enc_pub),
        sig_pub: Bytes32(sig_pub),
        key_version: 1,
        roles,
        not_before: Timestamp(0),
        not_after: Timestamp(4_102_444_800_000),
        mlkem_pub: None,
    };
    StoredBinding {
        signature: d5.sign_canonical(labels::DIRBINDING, &b),
        binding_bytes: encode(&b),
    }
}

/// `enroll` over REAL Postgres is a single all-or-nothing transaction: an invalid
/// key writes nothing; the first enrollee is `{User, Admin}` and later ones
/// `{User}`; and a username collision rolls the whole unit back (key unspent).
#[tokio::test]
async fn enroll_is_atomic_and_first_is_admin_over_pg() {
    let db = db_or_skip!();
    let store = &db.store;
    let d5 = SigningKey::generate();
    const NEVER: u64 = 4_102_444_800_000;

    // (a) An UNSEEDED key: KeyInvalid, and nothing is written (transaction rolls back).
    let kh = sha256(b"rk-1");
    let uid1: [u8; 16] = random_array();
    let ub = signed_binding(&d5, uid1, "alice", [0x11; 32], [0x22; 32], false);
    let ab = signed_binding(&d5, uid1, "alice", [0x11; 32], [0x22; 32], true);
    assert_eq!(
        store
            .enroll(kh, uid1, "alice", [0x11; 32], [0x22; 32], &ub, &ab)
            .await
            .unwrap(),
        EnrollOutcome::KeyInvalid
    );
    assert!(
        store.user_by_name("alice").await.unwrap().is_none(),
        "KeyInvalid created no user"
    );
    assert!(store.binding_by_username("alice").await.unwrap().is_none());

    // (b) Seed the key; the FIRST enrollment claims admin + stores the admin
    // binding, atomically consuming the key. Verify over a FRESH pool (it's in the
    // DB, not one process's memory).
    store.issue_registration_key(kh, NEVER).await.unwrap();
    assert_eq!(
        store
            .enroll(kh, uid1, "alice", [0x11; 32], [0x22; 32], &ub, &ab)
            .await
            .unwrap(),
        EnrollOutcome::Enrolled { is_admin: true }
    );
    assert!(
        !store.consume_registration_key(&kh).await.unwrap(),
        "the key was consumed inside enroll"
    );
    let fresh = db.reopen().await;
    let stored = fresh.binding_by_username("alice").await.unwrap().unwrap();
    let decoded: DirBinding = maxsecu_encoding::decode(&stored.binding_bytes).unwrap();
    assert!(
        decoded.roles.roles().contains(&Role::Admin),
        "first registrant persisted as admin"
    );

    // (c) A SECOND enrollment is User-only.
    let kh2 = sha256(b"rk-2");
    let uid2: [u8; 16] = random_array();
    let ub2 = signed_binding(&d5, uid2, "bob", [0x33; 32], [0x44; 32], false);
    let ab2 = signed_binding(&d5, uid2, "bob", [0x33; 32], [0x44; 32], true);
    store.issue_registration_key(kh2, NEVER).await.unwrap();
    assert_eq!(
        store
            .enroll(kh2, uid2, "bob", [0x33; 32], [0x44; 32], &ub2, &ab2)
            .await
            .unwrap(),
        EnrollOutcome::Enrolled { is_admin: false }
    );
    let stored = store.binding_by_username("bob").await.unwrap().unwrap();
    let decoded: DirBinding = maxsecu_encoding::decode(&stored.binding_bytes).unwrap();
    assert!(
        !decoded.roles.roles().contains(&Role::Admin),
        "second registrant is user-only"
    );

    // (d) A username collision rolls the whole unit back — the key is NOT burned.
    let kh3 = sha256(b"rk-3");
    let uid3: [u8; 16] = random_array();
    let ub3 = signed_binding(&d5, uid3, "alice", [0x55; 32], [0x66; 32], false);
    let ab3 = signed_binding(&d5, uid3, "alice", [0x55; 32], [0x66; 32], true);
    store.issue_registration_key(kh3, NEVER).await.unwrap();
    assert_eq!(
        store
            .enroll(kh3, uid3, "alice", [0x55; 32], [0x66; 32], &ub3, &ab3)
            .await
            .unwrap(),
        EnrollOutcome::UsernameTaken
    );
    assert!(
        store.consume_registration_key(&kh3).await.unwrap(),
        "the key survived the rolled-back enrollment (still consumable)"
    );

    db.teardown().await;
}

#[tokio::test]
async fn register_then_full_login_persists_in_postgres() {
    let db = db_or_skip!();

    let sk = SigningKey::generate();
    let user_id = db
        .store
        .create_user("bob", [0xE1; 32], sk.verifying_key().to_bytes())
        .await
        .unwrap()
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
        .unwrap()
        .is_some());
    assert!(
        db.store
            .create_user("carol", [0x03; 32], [0x04; 32])
            .await
            .unwrap()
            .is_none(),
        "second create with the same username is a 409 (None)"
    );
    db.teardown().await;
}

#[tokio::test]
async fn recovery_account_registers_once_with_mlkem_over_postgres() {
    let db = db_or_skip!();
    assert!(
        db.store.recovery_account().await.unwrap().is_none(),
        "no recovery account before any set"
    );
    let enc = [0x11u8; 32];
    let sig = [0x22u8; 32];
    let mlkem = [0x33u8; MLKEM768_PUB_LEN];
    assert!(
        db.store
            .set_recovery_account(enc, sig, Some(mlkem))
            .await
            .unwrap(),
        "first registration lands the singleton row"
    );
    assert_eq!(
        db.store.recovery_account().await.unwrap(),
        Some(RecoveryAccount {
            enc_pub: enc,
            sig_pub: sig,
            mlkem_pub: Some(mlkem),
        }),
        "the PQ-hybrid pubkeys (incl. the 1184-byte ML-KEM key) round-trip verbatim"
    );
    // A second attempt with DIFFERENT keys loses (ON CONFLICT DO NOTHING) and
    // does NOT overwrite — the singleton PK enforces once-only.
    assert!(
        !db.store
            .set_recovery_account([0xAAu8; 32], [0xBBu8; 32], None)
            .await
            .unwrap(),
        "second registration is rejected (once-only)"
    );
    assert_eq!(
        db.store.recovery_account().await.unwrap(),
        Some(RecoveryAccount {
            enc_pub: enc,
            sig_pub: sig,
            mlkem_pub: Some(mlkem),
        }),
        "the ORIGINAL keys (incl. ML-KEM) are preserved after a losing second set"
    );
    db.teardown().await;
}

#[tokio::test]
async fn recovery_account_classical_only_persists_null_mlkem_over_postgres() {
    let db = db_or_skip!();
    let enc = [0x44u8; 32];
    let sig = [0x55u8; 32];
    // No ML-KEM key: the nullable `mlkem_pub` column stays NULL and reads back None.
    assert!(db.store.set_recovery_account(enc, sig, None).await.unwrap());
    assert_eq!(
        db.store.recovery_account().await.unwrap(),
        Some(RecoveryAccount {
            enc_pub: enc,
            sig_pub: sig,
            mlkem_pub: None,
        }),
        "classical-only recovery persists with a NULL mlkem_pub"
    );
    db.teardown().await;
}

#[tokio::test]
async fn nonce_outstanding_respects_ttl_and_single_use() {
    let db = db_or_skip!();
    let nonce: [u8; 32] = random_array();
    // Expires at TS+1000 (the u64-ms ↔ TIMESTAMPTZ mapping under test).
    db.store
        .insert_nonce(nonce, "dave", TS + 1000)
        .await
        .unwrap();

    assert_eq!(
        db.store.outstanding_nonces("dave", TS).await.unwrap(),
        vec![nonce],
        "fresh nonce is outstanding before expiry"
    );
    assert!(
        db.store
            .outstanding_nonces("dave", TS + 2000)
            .await
            .unwrap()
            .is_empty(),
        "nonce past its expiry is not outstanding"
    );

    // Single-use: consuming removes it from the outstanding set.
    db.store.consume_nonce(&nonce).await.unwrap();
    assert!(
        db.store
            .outstanding_nonces("dave", TS)
            .await
            .unwrap()
            .is_empty(),
        "consumed nonce is not outstanding"
    );
    db.teardown().await;
}

#[tokio::test]
async fn recovery_style_nonce_key_with_nul_round_trips_in_postgres() {
    // Regression: the recovery-challenge nonce key embeds NUL (0x00) so it can
    // never collide with a real username. Postgres TEXT cannot store 0x00, so
    // `insert_nonce` used to 500 ("invalid byte sequence for encoding UTF8: 0x00")
    // on EVERY recovery challenge (invisible to the MemoryStore e2e). The key must
    // now insert, match itself, and stay disjoint from a plain username.
    let db = db_or_skip!();
    let nonce: [u8; 32] = random_array();
    let key = "\u{0}recovery\u{0}deadbeefdeadbeefdeadbeefdeadbeef";

    db.store.insert_nonce(nonce, key, TS + 1000).await.unwrap();

    assert_eq!(
        db.store.outstanding_nonces(key, TS).await.unwrap(),
        vec![nonce],
        "a NUL-containing recovery key must insert and match itself"
    );
    assert!(
        db.store
            .outstanding_nonces("recovery", TS)
            .await
            .unwrap()
            .is_empty(),
        "a plain username must not collide with the recovery key"
    );
    db.teardown().await;
}

#[tokio::test]
async fn recovery_principal_session_persists_without_a_users_row() {
    // Regression: recovery/verify mints an admin session for the reserved
    // RECOVERY_ID principal, which by design has NO users-table row (spec §6/§9).
    // A `sessions.user_id REFERENCES users(user_id)` FK made insert_session 500 on
    // recovery/verify over Postgres (invisible to the MemoryStore e2e). Without
    // inserting any users row, the all-zero-principal session must persist and
    // validate back as that principal.
    let db = db_or_skip!();
    let token: [u8; 32] = random_array();

    db.store
        .insert_session(
            sha256(&token),
            SessionRecord {
                user_id: RECOVERY_ID.0,
                tls_exporter: EXPORTER,
                expires_at_ms: TS + 3_600_000,
                revoked: false,
            },
        )
        .await
        .expect("recovery-principal session must persist with no users row");

    let svc = AuthService::new(db.store.clone(), AuthConfig::default());
    assert_eq!(
        svc.validate_session(&token, &EXPORTER, TS + 1)
            .await
            .unwrap(),
        RECOVERY_ID.0,
        "the persisted session resolves to the recovery principal"
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
        .await
        .unwrap();

    let svc = AuthService::new(db.store.clone(), AuthConfig::default());
    // Right channel, not expired → ok.
    assert_eq!(
        svc.validate_session(&token, &EXPORTER, TS + 1)
            .await
            .unwrap(),
        user_id
    );
    // Wrong channel → 401.
    assert!(svc
        .validate_session(&token, &[0x00; 32], TS + 1)
        .await
        .is_err());
    // Expired → 401.
    assert!(svc
        .validate_session(&token, &EXPORTER, TS + 3_600_001)
        .await
        .is_err());
    // Revoked (persisted) → 401, even on the right channel.
    db.store.revoke_session(&token_hash).await.unwrap();
    assert!(svc
        .validate_session(&token, &EXPORTER, TS + 1)
        .await
        .is_err());

    db.teardown().await;
}

fn dir_binding(
    user_id: [u8; 16],
    username: &str,
    enc: u8,
    sig: u8,
    key_version: u64,
) -> DirBinding {
    DirBinding {
        username: Text::new(username).unwrap(),
        user_id: Id(user_id),
        enc_pub: Bytes32([enc; 32]),
        sig_pub: Bytes32([sig; 32]),
        key_version,
        roles: RoleSet::new([Role::User]),
        not_before: Timestamp(0),
        not_after: Timestamp(4_102_444_800_000), // 2100-01-01, a valid TIMESTAMPTZ
        mlkem_pub: None,
    }
}

/// A signed binding persists, serves by name and id, and the latest key_version
/// wins; re-publishing the same version is a no-op against the immutable history.
#[tokio::test]
async fn directory_binding_persists_and_latest_version_serves() {
    let db = db_or_skip!();
    let d5 = SigningKey::generate();
    let user_id: [u8; 16] = random_array();
    // A users row so by-username resolves (the binding is signed post-registration).
    sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1,$2,$3,$4)")
        .bind(&user_id[..])
        .bind("grace")
        .bind(&[0xE1u8; 32][..])
        .bind(&[0x51u8; 32][..])
        .execute(db.store.pool())
        .await
        .unwrap();

    let b1 = dir_binding(user_id, "grace", 0xE1, 0x51, 1);
    let bytes1 = encode(&b1);
    let sig1 = d5.sign_canonical(labels::DIRBINDING, &b1);
    db.store
        .put_binding(user_id, 1, bytes1.clone(), sig1)
        .await
        .unwrap();

    // Round-trips through a fresh pool (truly persisted), byte-exact.
    let store2 = db.reopen().await;
    let got = store2
        .binding_by_user_id(&user_id)
        .await
        .unwrap()
        .expect("binding");
    assert_eq!(got.binding_bytes, bytes1);
    assert_eq!(got.signature, sig1);
    let by_name = store2
        .binding_by_username("grace")
        .await
        .unwrap()
        .expect("by name");
    assert_eq!(by_name.binding_bytes, bytes1);

    // An account with no signed binding → None.
    assert!(store2.binding_by_username("ghost").await.unwrap().is_none());

    // Re-publishing v1 is a no-op (immutable history); a rotation to v2 becomes latest.
    db.store
        .put_binding(user_id, 1, bytes1.clone(), sig1)
        .await
        .unwrap();
    let b2 = dir_binding(user_id, "grace", 0xE2, 0x52, 2);
    let bytes2 = encode(&b2);
    let sig2 = d5.sign_canonical(labels::DIRBINDING, &b2);
    db.store
        .put_binding(user_id, 2, bytes2.clone(), sig2)
        .await
        .unwrap();
    let latest = db
        .reopen()
        .await
        .binding_by_user_id(&user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.binding_bytes, bytes2, "latest key_version serves");

    db.teardown().await;
}

fn revocation_bytes(prev_head: [u8; 32], epoch: u64, victim: u8, issuer: [u8; 16]) -> Vec<u8> {
    use maxsecu_encoding::structs::Revocation;
    use maxsecu_encoding::types::FileScope;
    encode(&Revocation {
        scope: FileScope::Specific(Id([0x0A; 16])),
        revoked_user_id: Id([victim; 16]),
        revoked_capability: None,
        from_version: 1,
        revocation_epoch: epoch,
        prev_head: Bytes32(prev_head),
        issued_by: Id(issuer),
        co_signed_by: None,
        created_at: Timestamp(1_719_500_000_000),
    })
}

/// The control-log chain appends, serves in order, persists, and the append-guard
/// trigger rejects a fork (a stale `prev_head`) as a Conflict.
#[tokio::test]
async fn control_log_chain_appends_serves_and_rejects_forks() {
    use maxsecu_server::ControlAppendError;
    let db = db_or_skip!();
    let genesis = [0u8; 32];
    // issued_by has a FK to users — seed the admin issuer.
    let issuer: [u8; 16] = random_array();
    sqlx::query("INSERT INTO users (user_id, username, enc_pub, sig_pub) VALUES ($1,$2,$3,$4)")
        .bind(&issuer[..])
        .bind("ctl-admin")
        .bind(&[0xAAu8; 32][..])
        .bind(&[0xBBu8; 32][..])
        .execute(db.store.pool())
        .await
        .unwrap();

    assert_eq!(
        db.store.control_head().await.unwrap(),
        genesis,
        "empty chain head is GENESIS_HEAD"
    );

    let r1 = revocation_bytes(genesis, 1, 0x99, issuer);
    let head1 = db
        .store
        .append_control(r1.clone(), [0xCC; 64], None)
        .await
        .unwrap();
    assert_eq!(db.store.control_head().await.unwrap(), head1);

    let r2 = revocation_bytes(head1, 2, 0x98, issuer);
    let head2 = db
        .store
        .append_control(r2.clone(), [0xDD; 64], None)
        .await
        .unwrap();

    // Serve in append order through a fresh pool (truly persisted).
    let store2 = db.reopen().await;
    let recs = store2.control_records().await.unwrap();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].record_bytes, r1);
    assert_eq!(recs[1].record_bytes, r2);
    assert_eq!(recs[1].head, head2);
    assert_eq!(recs[0].kind, 6);

    // A fork (prev_head = GENESIS again) is rejected by the append guard.
    let fork = revocation_bytes(genesis, 3, 0x97, issuer);
    assert!(matches!(
        db.store.append_control(fork, [0xEE; 64], None).await,
        Err(ControlAppendError::Conflict)
    ));

    db.teardown().await;
}

/// Unknown user → `user_by_name` is `None`; a seeded user round-trips exactly.
#[tokio::test]
async fn user_by_name_round_trips() {
    let db = db_or_skip!();
    assert!(db.store.user_by_name("ghost").await.unwrap().is_none());

    let enc = [0x11; 32];
    let sig = [0x22; 32];
    let id = db
        .store
        .create_user("frank", enc, sig)
        .await
        .unwrap()
        .expect("frank created");
    let rec = db
        .store
        .user_by_name("frank")
        .await
        .unwrap()
        .expect("frank exists");
    assert_eq!(rec.user_id, id);
    assert_eq!(rec.enc_pub, enc);
    assert_eq!(rec.sig_pub, sig);
    db.teardown().await;
}

// ---- Phase 3 P3.6: file records over Postgres ----

fn pg_manifest(file: [u8; 16], version: u64, author: [u8; 16], ftype: FileType) -> Vec<u8> {
    encode(&Manifest {
        file_id: Id(file),
        version,
        file_type: ftype,
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
    ftype: FileType,
) -> StageInput {
    StageInput {
        file_id: file,
        caller_id: owner,
        file_type_advisory: ftype as u8 as i16,
        genesis,
        manifest_bytes: pg_manifest(file, version, owner, ftype),
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

#[tokio::test]
async fn file_lifecycle_persists_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xF1u8; 16];
    db.seed_user(owner, "owner").await;

    // Stage v1 — not visible until finalize, even via a fresh pool.
    let p1 = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    assert_eq!(db.store.stage_version(p1, TS).await.unwrap(), 1);
    let fresh = db.reopen().await;
    assert!(fresh
        .get_file(file, VersionSelector::Latest, owner)
        .await
        .unwrap()
        .is_none());

    // version_meta projects the staged slots (owner, not-yet-finalized, streams).
    let meta = db
        .store
        .version_meta(file, 1)
        .await
        .unwrap()
        .expect("staged meta");
    assert_eq!(meta.owner_id, owner);
    assert!(!meta.finalized);
    assert_eq!(meta.streams.len(), 2);
    assert!(meta
        .streams
        .iter()
        .any(|s| s.stream_type == 1 && s.chunk_count == 2));

    // Finalize v1 → durably visible to the owner with its exact records.
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();
    let fresh = db.reopen().await;
    let view = fresh
        .get_file(file, VersionSelector::Latest, owner)
        .await
        .unwrap()
        .expect("finalized v1 visible after reopen");
    assert_eq!(view.version, 1);
    assert_eq!(
        view.manifest_bytes,
        pg_manifest(file, 1, owner, FileType::Blog)
    );
    assert_eq!(view.my_wrap.wrapped_dek, vec![0xA1; 48]);
    assert!(view.recovery_grant.is_some());
    assert_eq!(view.streams.len(), 2);

    // A non-recipient gets None — same as missing (no oracle).
    assert!(db
        .store
        .get_file(file, VersionSelector::Latest, [0x77; 16])
        .await
        .unwrap()
        .is_none());

    // Rotate to v2 (strict +1); prior wraps torn down.
    let p2 = parse_stage(pg_stage(file, 2, owner, None, FileType::Blog)).unwrap();
    db.store.stage_version(p2, TS + 2).await.unwrap();
    db.store
        .finalize_version(file, 2, owner, TS + 3)
        .await
        .unwrap();
    assert_eq!(
        db.store
            .get_file(file, VersionSelector::Latest, owner)
            .await
            .unwrap()
            .unwrap()
            .version,
        2
    );
    assert!(db
        .store
        .get_file(file, VersionSelector::Specific(1), owner)
        .await
        .unwrap()
        .is_none());

    db.teardown().await;
}

#[tokio::test]
async fn finalize_strict_plus_one_and_non_owner_rejected_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xF2u8; 16];
    db.seed_user(owner, "owner").await;

    let p1 = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(p1, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();

    // Stage v3 (skipping v2) then finalize → VersionConflict (expected 2).
    let p3 = parse_stage(pg_stage(file, 3, owner, None, FileType::Blog)).unwrap();
    db.store.stage_version(p3, TS + 2).await.unwrap();
    assert_eq!(
        db.store.finalize_version(file, 3, owner, TS + 3).await,
        Err(FinalizeError::VersionConflict {
            expected: 2,
            got: 3
        })
    );

    // Finalizing v1 again → AlreadyFinalized (immutability guard).
    assert_eq!(
        db.store.finalize_version(file, 1, owner, TS + 4).await,
        Err(FinalizeError::AlreadyFinalized)
    );

    // A stranger cannot rotate the file (coarse owner check, D29).
    let attacker = parse_stage(pg_stage(file, 2, [0x77; 16], None, FileType::Blog)).unwrap();
    assert_eq!(
        db.store.stage_version(attacker, TS + 5).await,
        Err(StageError::NotOwner)
    );

    db.teardown().await;
}

/// Same as [`pg_stage`] but with an explicit `listed` flag (Task 1.4 regression).
fn pg_stage_listed(
    file: [u8; 16],
    version: u64,
    owner: [u8; 16],
    genesis: Option<GenesisInput>,
    ftype: FileType,
    listed: bool,
) -> StageInput {
    StageInput {
        listed,
        ..pg_stage(file, version, owner, genesis, ftype)
    }
}

#[tokio::test]
async fn listing_filters_by_type_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    db.seed_user(owner, "owner").await;
    let blog = [0xB1u8; 16];
    let video = [0x71u8; 16];

    let pb = parse_stage(pg_stage(
        blog,
        1,
        owner,
        Some(pg_genesis(blog, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(pb, TS).await.unwrap();
    db.store
        .finalize_version(blog, 1, owner, TS + 100)
        .await
        .unwrap();
    let pv = parse_stage(pg_stage(
        video,
        1,
        owner,
        Some(pg_genesis(video, owner)),
        FileType::Video,
    ))
    .unwrap();
    db.store.stage_version(pv, TS).await.unwrap();
    db.store
        .finalize_version(video, 1, owner, TS + 200)
        .await
        .unwrap();

    let all = db
        .store
        .list_files(ListFilter {
            limit: 10,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert_eq!(all.entries.len(), 2);
    assert_eq!(all.entries[0].file_id, video); // newest first
    assert_eq!(all.total, 2, "`total` counts the same set as the page");
    assert!(all.entries[0].small_streams.iter().all(|(t, _)| *t != 1)); // content excluded

    let blogs = db
        .store
        .list_files(ListFilter {
            file_type: Some(FileType::Blog as u8 as i16),
            limit: 10,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert_eq!(blogs.entries.len(), 1);
    assert_eq!(blogs.entries[0].file_id, blog);
    assert_eq!(blogs.total, 1, "`total` is filtered by type too");

    // A caller with no wrap for these files sees nothing (caller-scoped listing).
    let stranger = db
        .store
        .list_files(ListFilter::for_caller([0x77u8; 16]))
        .await
        .unwrap();
    assert!(stranger.entries.is_empty(), "pg listing is caller-scoped");
    assert_eq!(stranger.total, 0, "`total` is caller-scoped too");

    db.teardown().await;
}

#[tokio::test]
async fn listing_excludes_bundle_members_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    db.seed_user(owner, "owner").await;
    let bundle = [0xB1u8; 16];
    let member = [0x71u8; 16];

    // A listed bundle and an unlisted member (listed=false), both finalized.
    // `listed` is a post-scan filter on files_listing_idx; the PG query drops
    // members with `AND listed = true` so they never reach the public feed.
    let pb = parse_stage(pg_stage_listed(
        bundle,
        1,
        owner,
        Some(pg_genesis(bundle, owner)),
        FileType::Blog,
        true,
    ))
    .unwrap();
    db.store.stage_version(pb, TS).await.unwrap();
    db.store
        .finalize_version(bundle, 1, owner, TS + 100)
        .await
        .unwrap();
    let pm = parse_stage(pg_stage_listed(
        member,
        1,
        owner,
        Some(pg_genesis(member, owner)),
        FileType::Blog,
        false,
    ))
    .unwrap();
    db.store.stage_version(pm, TS).await.unwrap();
    db.store
        .finalize_version(member, 1, owner, TS + 200)
        .await
        .unwrap();

    let all = db
        .store
        .list_files(ListFilter::for_caller(owner))
        .await
        .unwrap();
    assert_eq!(all.entries.len(), 1);
    assert_eq!(all.entries[0].file_id, bundle);
    assert_eq!(all.total, 1, "an unlisted member is out of `total` too");
    assert!(all.entries.iter().all(|e| e.file_id != member)); // member hidden

    db.teardown().await;
}

// ---- F3a: server-side paging / sort / owner filter over Postgres ----

/// Stage v1 of `file` owned by `owner`, finalize it, and PIN `files.updated_at`
/// — the listing's sort key — to exactly `at_ms`.
///
/// The explicit `UPDATE` is not belt-and-braces: `PgStore::finalize_version`
/// stamps `updated_at = now()` (the DATABASE clock) and ignores its `now_ms`
/// argument, where `MemoryStore::finalize_version` uses `now_ms`. In production
/// those coincide (both are "now"), but a test that wants a deterministic order
/// has to set the column itself rather than assume the argument reaches it.
async fn seed_finalized(db: &TestDb, file: [u8; 16], owner: [u8; 16], ftype: FileType, at_ms: u64) {
    let p = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        ftype,
    ))
    .unwrap();
    db.store.stage_version(p, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, at_ms)
        .await
        .unwrap();
    sqlx::query("UPDATE files SET updated_at = to_timestamp($2::double precision / 1000.0) WHERE file_id = $1")
        .bind(&file[..])
        .bind(at_ms as f64)
        .execute(db.store.pool())
        .await
        .unwrap();
}

/// F3a — OFFSET paging, `sort`, `owner=me` and `total` over REAL Postgres.
///
/// The load-bearing assertion is the PARTITION: in a quiescent set, the pages
/// together are exactly the whole set, with no duplicate and no gap. An ORDER BY
/// that is not total (no `file_id` tiebreak) fails precisely here, and it fails
/// as *silently missing user content*.
#[tokio::test]
async fn listing_pages_sorts_and_filters_by_owner_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let other = [0x22u8; 16];
    db.seed_user(owner, "owner").await;
    db.seed_user(other, "other").await;

    // Five files owned by `owner`, finalized at strictly increasing times …
    let mine: Vec<[u8; 16]> = (0..5u8).map(|i| [0xA0 + i; 16]).collect();
    for (i, id) in mine.iter().enumerate() {
        seed_finalized(&db, *id, owner, FileType::Blog, TS + 100 + (i as u64) * 10).await;
    }
    // … and one owned by SOMEBODY ELSE, re-shared to `owner`. Visible to `owner`
    // (they hold a wrap) but it must drop out under `owner=me`. Its `updated_at`
    // lands on the add_wrap timestamp — oldest of the six.
    let foreign = [0xEEu8; 16];
    seed_finalized(&db, foreign, other, FileType::Blog, TS + 50).await;
    db.store
        .add_wrap(foreign, wrap_row(owner, other, 0xB0), other, TS + 60)
        .await
        .unwrap();

    // Newest-first over the whole visible set.
    let newest_all: Vec<[u8; 16]> = vec![mine[4], mine[3], mine[2], mine[1], mine[0], foreign];

    let page1 = db
        .store
        .list_files(ListFilter {
            limit: 2,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert_eq!(page1.total, 6, "`total` must ignore `limit`");
    assert_eq!(
        page1.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        newest_all[0..2]
    );

    // Pages 2 and 3, then the PARTITION check.
    let mut walked: Vec<[u8; 16]> = page1.entries.iter().map(|e| e.file_id).collect();
    for off in [2u64, 4] {
        let p = db
            .store
            .list_files(ListFilter {
                limit: 2,
                offset: off,
                ..ListFilter::for_caller(owner)
            })
            .await
            .unwrap();
        assert_eq!(p.total, 6, "`total` must ignore `offset` too");
        walked.extend(p.entries.iter().map(|e| e.file_id));
    }
    assert_eq!(
        walked, newest_all,
        "three pages of 2 must partition the set: no duplicate, no gap"
    );

    // An offset past the end is an empty page, not an error — and `total` still
    // reports the real size, so a pager can clamp instead of hanging.
    let past = db
        .store
        .list_files(ListFilter {
            limit: 2,
            offset: 999,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert!(past.entries.is_empty());
    assert_eq!(past.total, 6);

    // `sort=oldest` is the exact reverse of `sort=newest` (no ties here, so the
    // shared `file_id ASC` tiebreak cannot make them differ).
    let oldest = db
        .store
        .list_files(ListFilter {
            limit: 50,
            sort: ListSort::Oldest,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    let mut reversed = newest_all.clone();
    reversed.reverse();
    assert_eq!(
        oldest.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        reversed
    );
    assert_eq!(oldest.total, 6, "`total` is sort-independent");

    // `owner=me` — "My Content": the caller's OWN posts only. The re-shared file
    // is in the plain feed and absent here, and `total` shrinks with it (else the
    // pager renders a page that does not exist).
    let mut owned = db
        .store
        .list_files(ListFilter {
            limit: 50,
            owner_only: true,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert_eq!(owned.total, 5, "`total` follows the owner filter");
    assert_eq!(owned.entries.len(), 5);
    assert!(
        owned.entries.iter().all(|e| e.file_id != foreign),
        "a file shared TO me is not a file I own"
    );
    owned.entries.sort_by_key(|e| e.file_id);
    assert_eq!(
        owned.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        mine
    );

    // `owner=me` composes with `type` and with paging.
    let owned_page = db
        .store
        .list_files(ListFilter {
            file_type: Some(FileType::Blog as u8 as i16),
            limit: 2,
            offset: 4,
            owner_only: true,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert_eq!(owned_page.total, 5);
    assert_eq!(
        owned_page
            .entries
            .iter()
            .map(|e| e.file_id)
            .collect::<Vec<_>>(),
        vec![mine[0]],
        "the last page of the owner-filtered set is the single oldest own file"
    );

    db.teardown().await;
}

/// The honest cost of OFFSET paging over a MUTABLE sort key, asserted as the
/// behaviour that actually happens rather than papered over.
///
/// `files.updated_at` is bumped by `finalize_version` AND by `add_wrap` — i.e.
/// by every re-share. So a re-share landing between two page fetches reorders
/// the set under the pager: an item already shown on page 1 slides down into
/// page 2 (shown TWICE) and the item that was going to be on page 2 is pushed to
/// the top, past the reader (never shown).
///
/// ACCEPTED, not fixed: the only stable alternative is to sort by the immutable
/// `created_at`, which would stop a re-shared file surfacing in the recipient's
/// feed at all — a product regression, and a schema change besides. This test
/// exists so the trade-off cannot quietly become a stability claim nobody checked.
#[tokio::test]
async fn a_reshare_mid_walk_can_repeat_and_skip_a_page_entry_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let bob = [0x22u8; 16];
    db.seed_user(owner, "owner").await;
    db.seed_user(bob, "bob").await;

    // f1 … f4, newest-first order f4, f3, f2, f1.
    let f: Vec<[u8; 16]> = (1..=4u8).map(|i| [0xC0 + i; 16]).collect();
    for (i, id) in f.iter().enumerate() {
        seed_finalized(&db, *id, owner, FileType::Blog, TS + 100 + (i as u64) * 10).await;
    }

    let page1 = db
        .store
        .list_files(ListFilter {
            limit: 2,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert_eq!(
        page1.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        vec![f[3], f[2]]
    );

    // The reader is now looking at page 1. A re-share of the OLDEST file lands.
    db.store
        .add_wrap(f[0], wrap_row(bob, owner, 0xB0), owner, TS + 500)
        .await
        .unwrap();
    // Order is now f1, f4, f3, f2 — everything after f1 shifted one slot down.

    let page2 = db
        .store
        .list_files(ListFilter {
            limit: 2,
            offset: 2,
            ..ListFilter::for_caller(owner)
        })
        .await
        .unwrap();
    assert_eq!(
        page2.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        vec![f[2], f[1]],
        "offset 2 of the REORDERED set"
    );

    // The consequence, as an assertion rather than a comment:
    let seen: Vec<[u8; 16]> = page1
        .entries
        .iter()
        .chain(page2.entries.iter())
        .map(|e| e.file_id)
        .collect();
    assert_eq!(
        seen.iter().filter(|id| **id == f[2]).count(),
        2,
        "f3 was on page 1 and slid into page 2 — the reader sees it TWICE"
    );
    assert!(
        !seen.contains(&f[0]),
        "f1 was pushed to the top of the set, above the reader — it is MISSED"
    );

    db.teardown().await;
}

// ---- Phase 4 P4.3: re-share + soft-revoke over Postgres ----

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

#[tokio::test]
async fn reshare_and_soft_revoke_persist_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r = [0x22u8; 16];
    let v = [0x33u8; 16];
    let file = [0xF5u8; 16];
    db.seed_user(owner, "owner5").await;

    let p1 = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(p1, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();

    // Owner re-shares to R (author-rooted), R re-shares to V (re-share edge).
    db.store
        .add_wrap(file, wrap_row(r, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();
    db.store
        .add_wrap(file, wrap_row(v, r, 0xC0), r, TS + 3)
        .await
        .unwrap();

    // V's view via a fresh pool: leaf grant + the ancestor chain [R's grant].
    let fresh = db.reopen().await;
    let vv = fresh
        .get_file(file, VersionSelector::Latest, v)
        .await
        .unwrap()
        .expect("V holds a re-shared wrap");
    assert_eq!(vv.my_wrap.grant_bytes, vec![0xC0; 8]);
    assert_eq!(
        vv.my_wrap.ancestor_grants,
        vec![(vec![0xB0; 8], [0xB0; 64])]
    );

    // The owner enumerates recipients for rotation: owner + R + V, V chained to
    // the author via R; a non-owner gets None (no oracle).
    let recips = fresh
        .list_recipients(file, owner)
        .await
        .unwrap()
        .expect("owner lists");
    assert_eq!(recips.len(), 3);
    let vr = recips.iter().find(|r| r.recipient_id == v).unwrap();
    assert_eq!(vr.ancestor_grants, vec![(vec![0xB0; 8], [0xB0; 64])]);
    assert!(fresh.list_recipients(file, v).await.unwrap().is_none());

    // A non-holder cannot re-share (no oracle → NoAccess).
    assert_eq!(
        db.store
            .add_wrap(
                file,
                wrap_row([0x44; 16], [0x77; 16], 0xD0),
                [0x77; 16],
                TS + 4
            )
            .await,
        Err(AddWrapError::NoAccess)
    );

    // Soft-revoke: the granter R revokes V; an unrelated user cannot revoke R;
    // the owner can.
    db.store
        .delete_wrap(file, v, r)
        .await
        .expect("granter revokes grantee");
    assert!(db
        .store
        .get_file(file, VersionSelector::Latest, v)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.store.delete_wrap(file, r, [0x88; 16]).await,
        Err(DeleteWrapError::NotAuthorized)
    );
    db.store
        .delete_wrap(file, r, owner)
        .await
        .expect("owner revokes");
    assert!(db
        .store
        .get_file(file, VersionSelector::Latest, r)
        .await
        .unwrap()
        .is_none());

    db.teardown().await;
}

// ---- Task 1.5: owner-only permanent delete of a FINALIZED file + cascade ----

/// This is the test that PROVES the transaction-local GUC carve-out
/// (`SET LOCAL maxsecu.allow_owner_delete = 'on'`) actually defeats the append-only
/// triggers on `file_versions` (finalized) and `file_genesis` over REAL Postgres —
/// that a non-owner delete is refused and removes NOTHING, and that the cascade is
/// OWNER-SCOPED (a member another user pointed at the bundle survives).
#[tokio::test]
async fn delete_finalized_file_cascades_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let stranger = [0x22u8; 16];
    db.seed_user(owner, "owner_del").await;
    db.seed_user(stranger, "stranger_del").await;
    let bundle = [0xB1u8; 16];
    let m1 = [0xB2u8; 16];
    let m2 = [0xB3u8; 16];
    let foreign = [0xB4u8; 16]; // owned by `stranger`, but points at `owner`'s bundle

    // A finalized bundle (file_type=Bundle, listed) + two members it owns.
    let pb = parse_stage(pg_stage_listed(
        bundle,
        1,
        owner,
        Some(pg_genesis(bundle, owner)),
        FileType::Bundle,
        true,
    ))
    .unwrap();
    db.store.stage_version(pb, TS).await.unwrap();
    db.store
        .finalize_version(bundle, 1, owner, TS + 1)
        .await
        .unwrap();
    for m in [m1, m2] {
        let pm = parse_stage(StageInput {
            bundle_id: Some(bundle),
            ..pg_stage_listed(
                m,
                1,
                owner,
                Some(pg_genesis(m, owner)),
                FileType::Blog,
                false,
            )
        })
        .unwrap();
        db.store.stage_version(pm, TS).await.unwrap();
        db.store
            .finalize_version(m, 1, owner, TS + 2)
            .await
            .unwrap();
    }
    // `stranger` legitimately points THEIR OWN file at `owner`'s bundle_id.
    let pf = parse_stage(StageInput {
        bundle_id: Some(bundle),
        ..pg_stage_listed(
            foreign,
            1,
            stranger,
            Some(pg_genesis(foreign, stranger)),
            FileType::Blog,
            false,
        )
    })
    .unwrap();
    db.store.stage_version(pf, TS).await.unwrap();
    db.store
        .finalize_version(foreign, 1, stranger, TS + 2)
        .await
        .unwrap();

    // A NON-owner delete is refused (no oracle) AND removes nothing — the finalized
    // rows survive precisely because the GUC is unset on this path (immutability
    // holds), so the triggers would fire even if the code tried.
    assert_eq!(
        db.store.delete_file(bundle, [0x77; 16]).await,
        Err(DeleteError::NotFound)
    );
    assert!(db.store.get_file_meta(bundle).await.unwrap().is_some());
    assert!(db.store.get_file_meta(m1).await.unwrap().is_some());

    // The OWNER permanently deletes the finalized bundle: the GUC carve-out lets
    // the delete pass the file_versions + file_genesis triggers; the OWNED members
    // cascade; every removed stream's blob_ref comes back for the caller to purge.
    let refs = db
        .store
        .delete_file(bundle, owner)
        .await
        .expect("owner delete succeeds over real triggers");
    assert_eq!(refs.len(), 6); // 2 streams (content+metadata) × 3 OWNED files — NOT the foreign member

    // Prove durability via a FRESH pool — the owned rows are gone, and the
    // foreign-owned member (owner-scoped predicate) SURVIVED intact.
    let fresh = db.reopen().await;
    assert!(fresh.get_file_meta(bundle).await.unwrap().is_none());
    assert!(fresh.get_file_meta(m1).await.unwrap().is_none());
    assert!(fresh.get_file_meta(m2).await.unwrap().is_none());
    assert!(
        fresh.get_file_meta(foreign).await.unwrap().is_some(),
        "a foreign-owned member must survive the owner's bundle delete (owner-scoped cascade)"
    );
    // The stranger can still read their surviving file.
    assert!(fresh
        .get_file(foreign, VersionSelector::Latest, stranger)
        .await
        .unwrap()
        .is_some());
    let listed = fresh
        .list_files(ListFilter::for_caller(owner))
        .await
        .unwrap();
    assert!(listed.entries.is_empty()); // all remaining files are unlisted members

    db.teardown().await;
}

// ---- migration 0002: file_tombstones + wrap_revocations ----

// Absence is meaningful in the file family, and until 0002 nothing recorded it: a
// hard-deleted file and a soft-revoked wrap are both represented ONLY by a row
// that is no longer there. A backup restore that merges back what the bundle
// still holds would therefore resurrect a file its owner destroyed, and hand a
// de-authorized recipient their wrapped DEK back — silently, on a file that was
// never deleted. These two tables are the record that makes those absences
// survivable. Nothing on the serving path reads them; they are written here and
// read by the restore merge, which is why they carry no Store method.

/// Both tables are append-only under the SHARED `maxsecu_forbid_update_delete`
/// guard, which — unlike the dedicated `file_genesis_guard()` /
/// `file_versions_guard()` — never consults `maxsecu.allow_owner_delete`. So a
/// tombstone is immutable even inside `delete_file`'s own GUC-enabled
/// transaction, the one place where the rest of the file family is deletable.
#[tokio::test]
async fn tombstones_stay_immutable_inside_the_owner_delete_guc_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xD1u8; 16];
    db.seed_user(owner, "owner_tomb_immut").await;

    let p = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(p, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();
    db.store.delete_file(file, owner).await.unwrap();

    // The exact carve-out delete_file itself runs under. If the tombstone were
    // guarded by one of the GUC-aware guards, this would succeed and a restore
    // could be talked into forgetting the delete.
    let mut tx = db.store.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL maxsecu.allow_owner_delete = 'on'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let err = sqlx::query("DELETE FROM file_tombstones WHERE file_id = $1")
        .bind(&file[..])
        .execute(&mut *tx)
        .await
        .expect_err("a tombstone must not be deletable, GUC or no GUC");
    assert!(
        err.to_string()
            .contains("append-only table file_tombstones"),
        "expected the shared append-only guard to raise, got: {err}"
    );
    drop(tx);

    let mut tx = db.store.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL maxsecu.allow_owner_delete = 'on'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let err = sqlx::query("UPDATE file_tombstones SET deleted_at = now() WHERE file_id = $1")
        .bind(&file[..])
        .execute(&mut *tx)
        .await
        .expect_err("a tombstone must not be updatable");
    assert!(
        err.to_string()
            .contains("append-only table file_tombstones"),
        "expected the shared append-only guard to raise, got: {err}"
    );
    drop(tx);

    db.teardown().await;
}

/// `delete_file` deletes a SET — the target plus every bundle member it owns — so
/// every id in that set needs its own tombstone. A member left untombstoned is a
/// member a restore would resurrect on its own, orphaned from the bundle that
/// gave it meaning.
#[tokio::test]
async fn delete_file_tombstones_every_owned_target_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let stranger = [0x22u8; 16];
    db.seed_user(owner, "owner_tomb_set").await;
    db.seed_user(stranger, "stranger_tomb_set").await;
    let bundle = [0xC1u8; 16];
    let m1 = [0xC2u8; 16];
    let foreign = [0xC4u8; 16]; // stranger's file, pointed at owner's bundle

    let pb = parse_stage(pg_stage_listed(
        bundle,
        1,
        owner,
        Some(pg_genesis(bundle, owner)),
        FileType::Bundle,
        true,
    ))
    .unwrap();
    db.store.stage_version(pb, TS).await.unwrap();
    db.store
        .finalize_version(bundle, 1, owner, TS + 1)
        .await
        .unwrap();
    for (m, who) in [(m1, owner), (foreign, stranger)] {
        let pm = parse_stage(StageInput {
            bundle_id: Some(bundle),
            ..pg_stage_listed(m, 1, who, Some(pg_genesis(m, who)), FileType::Blog, false)
        })
        .unwrap();
        db.store.stage_version(pm, TS).await.unwrap();
        db.store.finalize_version(m, 1, who, TS + 2).await.unwrap();
    }

    // A refused delete must leave no trace: the early return rolls the txn back,
    // so a non-owner cannot write a tombstone for someone else's file.
    assert_eq!(
        db.store.delete_file(bundle, [0x77; 16]).await,
        Err(DeleteError::NotFound)
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM file_tombstones")
        .fetch_one(db.store.pool())
        .await
        .unwrap();
    assert_eq!(n, 0, "a rejected delete must not tombstone anything");

    db.store.delete_file(bundle, owner).await.unwrap();

    // Durability via a fresh pool: the fact lives in the DB, not in this process.
    let fresh = db.reopen().await;
    for (id, want, why) in [
        (bundle, 1i64, "the deleted target"),
        (m1, 1i64, "an owned bundle member that cascaded"),
        (
            foreign,
            0i64,
            "a foreign-owned member, which the owner-scoped cascade never touched",
        ),
    ] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM file_tombstones WHERE file_id = $1")
            .bind(&id[..])
            .fetch_one(fresh.pool())
            .await
            .unwrap();
        assert_eq!(n, want, "tombstone for {why} — expected {want}");
    }

    db.teardown().await;
}

/// A `file_id` is client-generated and `stage_version` re-creates a deleted one
/// with no tombstone check, so the same id can be deleted twice. Under a plain
/// INSERT the second delete hits the PK, `DeleteError::Store` becomes an HTTP
/// 500, and the owner can NEVER delete that file again — an owner locked out of
/// their own delete by the very table meant to protect them.
#[tokio::test]
async fn deleting_a_recreated_file_id_tombstones_idempotently_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let file = [0xD2u8; 16];
    db.seed_user(owner, "owner_tomb_reuse").await;

    for round in 0..2 {
        let p = parse_stage(pg_stage(
            file,
            1,
            owner,
            Some(pg_genesis(file, owner)),
            FileType::Blog,
        ))
        .unwrap();
        db.store.stage_version(p, TS).await.unwrap();
        db.store
            .finalize_version(file, 1, owner, TS + 1)
            .await
            .unwrap();
        db.store.delete_file(file, owner).await.unwrap_or_else(|e| {
            panic!(
                "delete #{} of a re-created file_id failed: {e:?}",
                round + 1
            )
        });
    }

    // Still exactly one tombstone: the id is the identity, and the first delete
    // already recorded it.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM file_tombstones WHERE file_id = $1")
        .bind(&file[..])
        .fetch_one(db.store.pool())
        .await
        .unwrap();
    assert_eq!(n, 1);

    db.teardown().await;
}

/// The revocation record and the wrap's removal must land together. They do only
/// because `delete_wrap` now runs in a transaction — before 0002 its statements
/// were three separate autocommits, and a crash between the DELETE and this
/// INSERT would leave the wrap gone with no record, so a later restore would
/// re-insert it and hand the de-authorized recipient their DEK back.
#[tokio::test]
async fn delete_wrap_records_a_revocation_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r = [0x22u8; 16];
    let file = [0xD3u8; 16];
    db.seed_user(owner, "owner_revoke_rec").await;

    let p = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(p, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();
    db.store
        .add_wrap(file, wrap_row(r, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();

    // A refused revoke must record nothing — the authz gate returns before the
    // txn commits, so an unrelated caller cannot poison the restore with a
    // revocation that never happened.
    assert_eq!(
        db.store.delete_wrap(file, r, [0x88; 16]).await,
        Err(DeleteWrapError::NotAuthorized)
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM wrap_revocations")
        .fetch_one(db.store.pool())
        .await
        .unwrap();
    assert_eq!(n, 0, "a rejected revoke must not record a revocation");

    db.store.delete_wrap(file, r, owner).await.unwrap();

    // Keyed to the version the wrap actually lived on (files.current_version),
    // which is what the restore merge gates on.
    let fresh = db.reopen().await;
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wrap_revocations \
         WHERE file_id = $1 AND file_version = $2 AND recipient_id = $3",
    )
    .bind(&file[..])
    .bind(1i64)
    .bind(&r[..])
    .fetch_one(fresh.pool())
    .await
    .unwrap();
    assert_eq!(n, 1);

    db.teardown().await;
}

/// F2 — the escrow wrap cannot be revoked, and the refusal leaves NOTHING behind.
///
/// This is the load-bearing test of the fix. The DELETE and the
/// `wrap_revocations` INSERT live in one transaction, so a guard placed *after*
/// the INSERT would still "refuse" the request while leaving a permanent
/// tombstone — and that table is append-only (the `maxsecu_forbid_update_delete`
/// trigger), so nobody could ever remove it. A later restore-merge reads that
/// tombstone as "the recovery wrap was revoked on purpose" and drops the wrap for
/// good. Asserting only that the wrap ROW survives would pass against exactly
/// that broken ordering; the `wrap_revocations` count is what catches it.
///
/// The blinding itself is unrecoverable online: `add_wrap` hard-rejects
/// `recipient_id == RECOVERY_ID` in both stores, so nothing can put the wrap back
/// at the file's current version.
#[tokio::test]
async fn the_recovery_wrap_cannot_be_revoked_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r = [0x22u8; 16];
    let file = [0xD9u8; 16];
    db.seed_user(owner, "owner_recovery_wrap").await;

    let p = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(p, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();

    // The OWNER — the most privileged caller this route has — is refused.
    assert_eq!(
        db.store.delete_wrap(file, RECOVERY_ID.0, owner).await,
        Err(DeleteWrapError::RecoveryProtected),
        "not even the owner may strip the escrow wrap"
    );

    // (1) the wrap ROW survived …
    let fresh = db.reopen().await;
    let wraps: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM file_key_wraps \
         WHERE file_id = $1 AND file_version = 1 AND recipient_id = $2",
    )
    .bind(&file[..])
    .bind(&RECOVERY_ID.0[..])
    .fetch_one(fresh.pool())
    .await
    .unwrap();
    assert_eq!(wraps, 1, "the recovery wrap must still be there");

    // (2) … AND no tombstone was written. Without this assertion the test passes
    // even when the guard runs after the INSERT — the exact bug it exists for.
    let tombs: i64 = sqlx::query_scalar("SELECT count(*) FROM wrap_revocations")
        .fetch_one(fresh.pool())
        .await
        .unwrap();
    assert_eq!(
        tombs, 0,
        "a refused revoke must leave NO wrap_revocations row — that table is \
         append-only, so a stray tombstone is permanent and a restore-merge \
         would read it as a deliberate revocation of the escrow wrap"
    );

    // (3) the recovery principal can still OPEN the file (the point of the wrap).
    assert!(db
        .store
        .get_file(file, VersionSelector::Latest, RECOVERY_ID.0)
        .await
        .unwrap()
        .is_some());

    // (4) no over-blocking: an ORDINARY recipient is still revocable, and THAT
    // one does record its tombstone.
    db.store
        .add_wrap(file, wrap_row(r, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();
    db.store.delete_wrap(file, r, owner).await.unwrap();
    let tombs: i64 = sqlx::query_scalar("SELECT count(*) FROM wrap_revocations")
        .fetch_one(db.store.pool())
        .await
        .unwrap();
    assert_eq!(
        tombs, 1,
        "the guard must not break ordinary soft-revoke or its revocation record"
    );

    db.teardown().await;
}

/// Re-sharing to a recipient you previously revoked, then revoking again, hits
/// the same `(file_id, file_version, recipient_id)` PK a second time. Without
/// `ON CONFLICT DO NOTHING` that aborts the caller's transaction and the owner
/// cannot re-revoke someone they chose to give a second chance.
#[tokio::test]
async fn re_revoking_a_re_shared_recipient_does_not_abort_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r = [0x22u8; 16];
    let file = [0xD4u8; 16];
    db.seed_user(owner, "owner_rerevoke").await;

    let p = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(p, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();

    for round in 0..2 {
        db.store
            .add_wrap(file, wrap_row(r, owner, 0xB0), owner, TS + 2)
            .await
            .unwrap();
        db.store
            .delete_wrap(file, r, owner)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "revoke #{} of a re-shared recipient failed: {e:?}",
                    round + 1
                )
            });
    }

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM wrap_revocations WHERE file_id = $1")
        .bind(&file[..])
        .fetch_one(db.store.pool())
        .await
        .unwrap();
    assert_eq!(
        n, 1,
        "the revocation is a fact about a recipient, not a counter"
    );

    db.teardown().await;
}

/// `finalize_version` drops the PRIOR version's wraps — that is supersession, not
/// revocation: it is recipient-blind, and every recipient keeps access through
/// the new version's own wrap. Recording it here would make every rotation look
/// like a revocation and permanently block the merge of wraps nobody revoked.
#[tokio::test]
async fn finalize_version_records_no_revocation_in_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let r = [0x22u8; 16];
    let file = [0xD5u8; 16];
    db.seed_user(owner, "owner_rotate_norec").await;

    let p1 = parse_stage(pg_stage(
        file,
        1,
        owner,
        Some(pg_genesis(file, owner)),
        FileType::Blog,
    ))
    .unwrap();
    db.store.stage_version(p1, TS).await.unwrap();
    db.store
        .finalize_version(file, 1, owner, TS + 1)
        .await
        .unwrap();
    db.store
        .add_wrap(file, wrap_row(r, owner, 0xB0), owner, TS + 2)
        .await
        .unwrap();

    // Rotate to v2: v1's wraps (including R's) are deleted by supersession.
    let p2 = parse_stage(pg_stage(file, 2, owner, None, FileType::Blog)).unwrap();
    db.store.stage_version(p2, TS + 3).await.unwrap();
    db.store
        .finalize_version(file, 2, owner, TS + 4)
        .await
        .unwrap();

    let gone: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM file_key_wraps WHERE file_id = $1 AND file_version = 1",
    )
    .bind(&file[..])
    .fetch_one(db.store.pool())
    .await
    .unwrap();
    assert_eq!(gone, 0, "supersession really did drop v1's wraps");

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM wrap_revocations")
        .fetch_one(db.store.pool())
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "a rotation is not a revocation — recording one here would make every \
         rotation permanently un-mergeable"
    );

    db.teardown().await;
}

// ---- F3a: the opaque list cursor, end to end (real Postgres + real router) ----

/// `GET /v1/files` paging over the HTTP surface, backed by a live Postgres.
///
/// The store-level tests above prove the SQL; this one proves the wire contract
/// the client actually codes against:
///
///  * `next_cursor` is populated (it was hardcoded `null` before) and round-trips
///    to the next page;
///  * the two pages PARTITION the set;
///  * `total` is present and ignores `limit`/`offset` — its ABSENCE is how an
///    upgraded client detects an un-upgraded server and renders no pager at all,
///    so it must never be omitted here;
///  * a cursor replayed under a DIFFERENT `type` is a loud `400`, not a silently
///    wrong page of a different result set;
///  * `sort`/`owner` reject an unknown value.
#[tokio::test]
async fn list_paging_and_cursor_over_http_and_postgres() {
    let db = db_or_skip!();
    let owner = [0x11u8; 16];
    let other = [0x22u8; 16];
    db.seed_user(owner, "owner_http_pager").await;
    db.seed_user(other, "other_http_pager").await;

    // Three blogs owned by `owner`, one video, and one foreign blog shared to
    // `owner` (so `owner=me` has something to exclude).
    let blogs: Vec<[u8; 16]> = (0..3u8).map(|i| [0x30 + i; 16]).collect();
    for (i, id) in blogs.iter().enumerate() {
        seed_finalized(&db, *id, owner, FileType::Blog, TS + 100 + (i as u64) * 10).await;
    }
    let video = [0x40u8; 16];
    seed_finalized(&db, video, owner, FileType::Video, TS + 200).await;
    let foreign = [0x50u8; 16];
    seed_finalized(&db, foreign, other, FileType::Blog, TS + 40).await;
    db.store
        .add_wrap(foreign, wrap_row(owner, other, 0xB0), other, TS + 45)
        .await
        .unwrap();

    // A session bound to the fixed test exporter — the same thing a real login
    // mints, without replaying the whole enrollment.
    let token = [0x5Au8; 32];
    let token_hex = hex(&token);
    db.store
        .insert_session(
            sha256(&token),
            SessionRecord {
                // 2100-01-01, not u64::MAX: the ms→TIMESTAMPTZ conversion is a
                // real date, and the validator compares against the wall clock.
                user_id: owner,
                tls_exporter: EXPORTER,
                expires_at_ms: 4_102_444_800_000,
                revoked: false,
            },
        )
        .await
        .unwrap();

    let app = router(AppState {
        auth: Arc::new(AuthService::new(db.store.clone(), AuthConfig::default())),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    })
    .layer(Extension(TlsExporter(EXPORTER)));

    let ids = |v: &serde_json::Value| -> Vec<String> {
        v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["file_id"].as_str().unwrap().to_owned())
            .collect()
    };

    // --- page 1 of the blogs (3 own + 1 shared = 4) ---
    let (st, p1) = list_http(&app, "/v1/files?type=blog&limit=2", &token_hex).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(p1["total"].as_u64().unwrap(), 4, "`total` ignores `limit`");
    assert_eq!(ids(&p1).len(), 2);
    let cursor = p1["next_cursor"]
        .as_str()
        .expect("more entries exist, so next_cursor must be populated")
        .to_owned();

    // --- page 2 via the cursor ---
    let (st, p2) = list_http(
        &app,
        &format!("/v1/files?type=blog&limit=2&cursor={cursor}"),
        &token_hex,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(p2["total"].as_u64().unwrap(), 4);
    assert_eq!(ids(&p2).len(), 2);
    assert!(
        p2["next_cursor"].is_null(),
        "the last page must not hand out a cursor"
    );

    // --- the two pages PARTITION the set ---
    let mut walked = ids(&p1);
    walked.extend(ids(&p2));
    let mut sorted = walked.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 4, "no entry appears on both pages");
    assert!(
        !walked.iter().any(|f| f == &hex(&video)),
        "the type filter still holds across pages"
    );

    // --- offset= reaches the same page the cursor did ---
    let (st, by_offset) = list_http(&app, "/v1/files?type=blog&limit=2&offset=2", &token_hex).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        ids(&by_offset),
        ids(&p2),
        "cursor and offset must address the same page"
    );

    // --- a cursor replayed under a DIFFERENT type is refused, loudly ---
    let (st, body) = list_http(
        &app,
        &format!("/v1/files?type=video&limit=2&cursor={cursor}"),
        &token_hex,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "a cursor minted for type=blog must not silently page a type=video set"
    );
    assert_eq!(body["code"], "cursor_query_mismatch");

    // …and so is a cursor replayed under a different sort or owner filter.
    for uri in [
        format!("/v1/files?type=blog&limit=2&sort=oldest&cursor={cursor}"),
        format!("/v1/files?type=blog&limit=2&owner=me&cursor={cursor}"),
    ] {
        let (st, body) = list_http(&app, &uri, &token_hex).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body["code"], "cursor_query_mismatch", "{uri}");
    }

    // --- a malformed cursor is a distinct 400 ---
    let (st, body) = list_http(&app, "/v1/files?limit=2&cursor=%21%21not-b64", &token_hex).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "bad_cursor");

    // --- unknown sort / owner values are refused (both are NEW parameters, so no
    //     shipped client can hit this) ---
    let (st, body) = list_http(&app, "/v1/files?sort=sideways", &token_hex).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "bad_sort");
    let (st, body) = list_http(&app, "/v1/files?owner=someone-else", &token_hex).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "`owner` is not an arbitrary user id — that would be an enumeration oracle"
    );
    assert_eq!(body["code"], "bad_owner");

    // --- owner=me drops the file that was shared TO the caller ---
    let (st, mine) = list_http(&app, "/v1/files?type=blog&owner=me&limit=50", &token_hex).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(mine["total"].as_u64().unwrap(), 3);
    assert!(
        !ids(&mine).contains(&hex(&foreign)),
        "a file shared TO me is not a file I own"
    );

    // --- an unknown type still matches nothing rather than erroring the browse,
    //     and reports total = 0 (NOT an absent `total`, which an upgraded client
    //     reads as "this server does not paginate") ---
    let (st, none) = list_http(&app, "/v1/files?type=nonsense", &token_hex).await;
    assert_eq!(st, StatusCode::OK);
    assert!(ids(&none).is_empty());
    assert!(none["next_cursor"].is_null());
    assert_eq!(none["total"].as_u64().unwrap(), 0);

    // --- the pre-paging request shape is UNCHANGED: no offset, no cursor, no
    //     sort, no owner, and the 50/200 limit contract intact ---
    let (st, legacy) = list_http(&app, "/v1/files?limit=200", &token_hex).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        ids(&legacy).len(),
        5,
        "limit=200 must still be honoured — live-smoke and the bundle e2e send it"
    );
    assert!(legacy["next_cursor"].is_null());

    db.teardown().await;
}

/// `GET` a listing URI with a session token, returning `(status, body)`.
async fn list_http(app: &Router, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

// ---------------------------------------------------------------------------
// The bounded, expiry-only auth-row prune, over REAL Postgres.
//
// `sessions` and `auth_nonces` are the only two tables the server ever wrote
// without ever deleting from: a logout is an UPDATE of `revoked_at`, a consumed
// nonce is an UPDATE of `used_at`. These tests are the whole delete surface, and
// every one of them fails without the prune.
//
// They mirror `store.rs`'s `prune_tests` shape for shape, deliberately: the
// safety argument only holds if both backings agree on what "prunable" means,
// and only Postgres exercises the epoch-ms -> TIMESTAMPTZ cutoff conversion.
// ---------------------------------------------------------------------------

const PRUNE_HOUR_MS: u64 = 3_600_000;
/// Expired long enough ago to be prunable.
const PRUNE_LONG_DEAD: u64 = TS - AUTH_PRUNE_GRACE_MS - PRUNE_HOUR_MS;
/// Expired, but only an hour ago — inside the grace window.
const PRUNE_JUST_DEAD: u64 = TS - PRUNE_HOUR_MS;
/// Still valid.
const PRUNE_LIVE: u64 = TS + PRUNE_HOUR_MS;

fn prune_session(expires_at_ms: u64) -> SessionRecord {
    SessionRecord {
        user_id: [0xA1; 16],
        tls_exporter: EXPORTER,
        expires_at_ms,
        // Only `insert_session`'s four written columns matter here; `revoked_at`
        // is set by `revoke_session`, never by the insert.
        revoked: false,
    }
}

async fn row_count(db: &TestDb, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(db.store.pool())
        .await
        .unwrap()
}

async fn nonce_exists(db: &TestDb, nonce: &[u8; 32]) -> bool {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_nonces WHERE nonce = $1")
        .bind(&nonce[..])
        .fetch_one(db.store.pool())
        .await
        .unwrap();
    n == 1
}

/// The four shapes, over real SQL: only a row that is expired **and** past the
/// grace window is deleted. The other three — expired-but-recent, unexpired, and
/// revoked-but-unexpired — all survive.
#[tokio::test]
async fn prune_removes_only_rows_expired_beyond_the_grace_window_in_postgres() {
    let db = db_or_skip!();

    let long_dead = [0x01; 32];
    let just_dead = [0x02; 32];
    let live = [0x03; 32];
    let revoked_live = [0x04; 32];
    for (h, exp) in [
        (long_dead, PRUNE_LONG_DEAD),
        (just_dead, PRUNE_JUST_DEAD),
        (live, PRUNE_LIVE),
        (revoked_live, PRUNE_LIVE),
    ] {
        db.store
            .insert_session(h, prune_session(exp))
            .await
            .unwrap();
    }
    // A real logout: revoked in the DB, but nowhere near expiry.
    db.store.revoke_session(&revoked_live).await.unwrap();

    let n_long_dead = [0x11; 32];
    let n_just_dead = [0x12; 32];
    let n_live = [0x13; 32];
    let n_used_live = [0x14; 32];
    for (n, exp) in [
        (n_long_dead, PRUNE_LONG_DEAD),
        (n_just_dead, PRUNE_JUST_DEAD),
        (n_live, PRUNE_LIVE),
        (n_used_live, PRUNE_LIVE),
    ] {
        db.store.insert_nonce(n, "alice", exp).await.unwrap();
    }
    // A real login: consumed, but nowhere near expiry.
    db.store.consume_nonce(&n_used_live).await.unwrap();

    let c = db
        .store
        .prune_expired_auth_rows(TS, AUTH_PRUNE_GRACE_MS, AUTH_PRUNE_BATCH)
        .await
        .unwrap();
    assert_eq!(
        (c.sessions, c.nonces),
        (1, 1),
        "exactly one row per table was prunable"
    );

    assert!(
        db.store.get_session(&long_dead).await.unwrap().is_none(),
        "a session expired beyond the grace window is deleted"
    );
    assert!(
        db.store.get_session(&just_dead).await.unwrap().is_some(),
        "a session expired only an hour ago is INSIDE the grace window and survives"
    );
    assert!(
        db.store.get_session(&live).await.unwrap().is_some(),
        "an unexpired session survives — deleting one would sign out a working user"
    );

    // The one that would be a security bug. A revoked-but-unexpired row MUST
    // stay, because the restore merge re-inserts the backup bundle's copy with a
    // bare ON CONFLICT DO NOTHING: with the live row gone there is nothing to
    // conflict with, and the pre-logout copy (revoked_at NULL) comes back as a
    // working token.
    let still = db
        .store
        .get_session(&revoked_live)
        .await
        .unwrap()
        .expect("a revoked, unexpired session must still be present");
    assert!(
        still.revoked,
        "and it must still be revoked — the row keeps its revoked_at"
    );

    assert!(
        !nonce_exists(&db, &n_long_dead).await,
        "a nonce expired beyond the grace window is deleted"
    );
    for n in [&n_just_dead, &n_live, &n_used_live] {
        assert!(
            nonce_exists(&db, n).await,
            "every other nonce shape survives, consumed or not"
        );
    }
    assert_eq!(
        db.store.outstanding_nonces("alice", TS).await.unwrap(),
        vec![n_live],
        "and a login in flight still finds its challenge"
    );

    db.teardown().await;
}

/// Neither `revoked_at` nor `used_at` may appear in the predicate in *either*
/// direction: a revoked session and a consumed nonce that are also long expired
/// go on their expiry alone, exactly like their untouched twins. Resurrecting one
/// of *those* from a backup is inert — it returns with its original past
/// `expires_at`, which every reader already rejects.
#[tokio::test]
async fn revoked_and_used_rows_are_pruned_on_expiry_alone_in_postgres() {
    let db = db_or_skip!();

    let revoked_long_dead = [0x21; 32];
    db.store
        .insert_session(revoked_long_dead, prune_session(PRUNE_LONG_DEAD))
        .await
        .unwrap();
    db.store.revoke_session(&revoked_long_dead).await.unwrap();

    let used_long_dead = [0x22; 32];
    db.store
        .insert_nonce(used_long_dead, "alice", PRUNE_LONG_DEAD)
        .await
        .unwrap();
    db.store.consume_nonce(&used_long_dead).await.unwrap();

    let c = db
        .store
        .prune_expired_auth_rows(TS, AUTH_PRUNE_GRACE_MS, AUTH_PRUNE_BATCH)
        .await
        .unwrap();
    assert_eq!((c.sessions, c.nonces), (1, 1));
    assert_eq!(row_count(&db, "sessions").await, 0);
    assert_eq!(row_count(&db, "auth_nonces").await, 0);

    db.teardown().await;
}

/// The grace boundary is strict, and it survives the epoch-ms -> TIMESTAMPTZ
/// conversion: `expires_at == now - grace` stays, one millisecond older goes.
#[tokio::test]
async fn the_grace_boundary_is_exclusive_in_postgres() {
    let db = db_or_skip!();
    let on_the_line = [0x31; 32];
    db.store
        .insert_session(on_the_line, prune_session(TS - AUTH_PRUNE_GRACE_MS))
        .await
        .unwrap();

    let c = db
        .store
        .prune_expired_auth_rows(TS, AUTH_PRUNE_GRACE_MS, AUTH_PRUNE_BATCH)
        .await
        .unwrap();
    assert_eq!(
        c.sessions, 0,
        "a row exactly `grace` old is not yet past the window"
    );
    let c = db
        .store
        .prune_expired_auth_rows(TS + 1, AUTH_PRUNE_GRACE_MS, AUTH_PRUNE_BATCH)
        .await
        .unwrap();
    assert_eq!(c.sessions, 1, "one millisecond later it is");

    db.teardown().await;
}

/// The batch bound is a real `LIMIT`, and the leftovers are picked up on the next
/// pass. This is what keeps the very first prune of a table that has never been
/// pruned from becoming one long transaction holding row locks while logins wait.
#[tokio::test]
async fn a_prune_pass_is_bounded_and_resumes_in_postgres() {
    let db = db_or_skip!();
    for i in 0..5u8 {
        let mut h = [0u8; 32];
        h[0] = i;
        db.store
            .insert_session(h, prune_session(PRUNE_LONG_DEAD))
            .await
            .unwrap();
        db.store
            .insert_nonce(h, "alice", PRUNE_LONG_DEAD)
            .await
            .unwrap();
    }

    let first = db
        .store
        .prune_expired_auth_rows(TS, AUTH_PRUNE_GRACE_MS, 2)
        .await
        .unwrap();
    assert_eq!(
        (first.sessions, first.nonces),
        (2, 2),
        "capped at the batch limit"
    );
    assert_eq!(row_count(&db, "sessions").await, 3);

    let second = db
        .store
        .prune_expired_auth_rows(TS, AUTH_PRUNE_GRACE_MS, 2)
        .await
        .unwrap();
    assert_eq!((second.sessions, second.nonces), (2, 2));
    let third = db
        .store
        .prune_expired_auth_rows(TS, AUTH_PRUNE_GRACE_MS, 2)
        .await
        .unwrap();
    assert_eq!((third.sessions, third.nonces), (1, 1), "the remainder");
    let fourth = db
        .store
        .prune_expired_auth_rows(TS, AUTH_PRUNE_GRACE_MS, 2)
        .await
        .unwrap();
    assert_eq!(
        (fourth.sessions, fourth.nonces),
        (0, 0),
        "and then it is idempotently empty"
    );
    assert_eq!(row_count(&db, "sessions").await, 0);
    assert_eq!(row_count(&db, "auth_nonces").await, 0);

    db.teardown().await;
}

/// A clock earlier than the grace window itself must prune nothing rather than
/// everything — the cutoff saturates at zero instead of wrapping around.
#[tokio::test]
async fn an_absurdly_early_clock_prunes_nothing_in_postgres() {
    let db = db_or_skip!();
    db.store
        .insert_session([0x41; 32], prune_session(1))
        .await
        .unwrap();
    db.store.insert_nonce([0x42; 32], "alice", 1).await.unwrap();

    let c = db
        .store
        .prune_expired_auth_rows(0, AUTH_PRUNE_GRACE_MS, AUTH_PRUNE_BATCH)
        .await
        .unwrap();
    assert_eq!(
        (c.sessions, c.nonces),
        (0, 0),
        "now_ms=0 must not underflow into a cutoff that empties both tables"
    );
    assert_eq!(row_count(&db, "sessions").await, 1);
    assert_eq!(row_count(&db, "auth_nonces").await, 1);

    db.teardown().await;
}
