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
    parse_stage, AddWrapError, AuthConfig, AuthService, DeleteError, DeleteWrapError,
    EnrollOutcome, FinalizeError, GenesisInput, ListFilter, PgStore, RecoveryAccount,
    SessionRecord, StageError, StageInput, Store, StoredBinding, VersionSelector, WrapInput,
};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};

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
            file_type: None,
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].file_id, video); // newest first
    assert!(all[0].small_streams.iter().all(|(t, _)| *t != 1)); // content excluded

    let blogs = db
        .store
        .list_files(ListFilter {
            file_type: Some(FileType::Blog as u8 as i16),
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(blogs.len(), 1);
    assert_eq!(blogs[0].file_id, blog);

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
        .list_files(ListFilter {
            file_type: None,
            limit: 50,
        })
        .await
        .unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].file_id, bundle);
    assert!(all.iter().all(|e| e.file_id != member)); // member hidden from the feed

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
        .list_files(ListFilter {
            file_type: None,
            limit: 50,
        })
        .await
        .unwrap();
    assert!(listed.is_empty()); // all remaining files are unlisted members

    db.teardown().await;
}
