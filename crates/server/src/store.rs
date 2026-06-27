//! Persistence abstraction for the auth state machine. The server holds only
//! inert/ephemeral auth state (DESIGN §4.3 / schema.sql Phase-1 tables): public
//! user material, single-use challenge nonces, and channel-bound sessions —
//! never a salt, KDF param, or private key (D4).
//!
//! [`MemoryStore`] is the test/dev backing; a Postgres-backed `Store` (sqlx over
//! `users`/`auth_nonces`/`sessions`) is the production adapter (next increment).
//! Methods take `&self` and the impl owns its synchronization, so the service
//! is `Sync` for concurrent request handling.

use async_trait::async_trait;
use maxsecu_crypto::random_array;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Public identity material the server stores for a user (schema.sql `users`).
#[derive(Clone, Debug)]
pub struct UserRecord {
    pub user_id: [u8; 16],
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
}

/// A single-use login challenge (schema.sql `auth_nonces`).
#[derive(Clone, Debug)]
pub struct NonceRecord {
    pub username: String,
    pub expires_at_ms: u64,
    pub used: bool,
}

/// A channel-bound session (schema.sql `sessions`); keyed by `SHA-256(token)`.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub user_id: [u8; 16],
    pub tls_exporter: [u8; 32],
    pub expires_at_ms: u64,
    pub revoked: bool,
}

/// Async because the production backing is sqlx/Postgres. `Send + Sync` so the
/// service can be shared across axum request tasks.
#[async_trait]
pub trait Store: Send + Sync {
    /// Create an unsigned user, assigning a fresh 16-byte `user_id`
    /// (api.md §5.1 / §1.4). Returns `None` if the username is taken (-> 409).
    async fn create_user(
        &self,
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
    ) -> Option<[u8; 16]>;
    /// Consume a one-time enrollment voucher; `true` iff it was valid and unused
    /// (the anti-spam gate for the unauthenticated `POST /v1/users`, api.md §5.1).
    async fn consume_voucher(&self, voucher_hash: &[u8; 32]) -> bool;
    async fn user_by_name(&self, username: &str) -> Option<UserRecord>;
    async fn insert_nonce(&self, nonce: [u8; 32], username: &str, expires_at_ms: u64);
    /// Fresh (unexpired, unused) nonces outstanding for `username`.
    async fn outstanding_nonces(&self, username: &str, now_ms: u64) -> Vec<[u8; 32]>;
    /// Mark a nonce used (single-use; idempotent).
    async fn consume_nonce(&self, nonce: &[u8; 32]);
    async fn insert_session(&self, token_hash: [u8; 32], rec: SessionRecord);
    async fn get_session(&self, token_hash: &[u8; 32]) -> Option<SessionRecord>;
    async fn revoke_session(&self, token_hash: &[u8; 32]);
}

#[derive(Default)]
struct Inner {
    users: HashMap<String, UserRecord>,
    nonces: HashMap<[u8; 32], NonceRecord>,
    sessions: HashMap<[u8; 32], SessionRecord>,
    vouchers: HashSet<[u8; 32]>, // unused enrollment voucher hashes
}

/// In-memory [`Store`] for tests and local dev.
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Seed an already-enrolled user (test/dev convenience).
    pub fn add_user(&self, username: &str, rec: UserRecord) {
        self.inner
            .lock()
            .unwrap()
            .users
            .insert(username.to_owned(), rec);
    }

    /// Seed a usable enrollment voucher by its `SHA-256` hash (issued in person).
    pub fn add_voucher(&self, voucher_hash: [u8; 32]) {
        self.inner.lock().unwrap().vouchers.insert(voucher_hash);
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn create_user(
        &self,
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
    ) -> Option<[u8; 16]> {
        let mut inner = self.inner.lock().unwrap();
        if inner.users.contains_key(username) {
            return None;
        }
        let user_id: [u8; 16] = random_array();
        inner.users.insert(
            username.to_owned(),
            UserRecord {
                user_id,
                enc_pub,
                sig_pub,
            },
        );
        Some(user_id)
    }

    async fn consume_voucher(&self, voucher_hash: &[u8; 32]) -> bool {
        self.inner.lock().unwrap().vouchers.remove(voucher_hash)
    }

    async fn user_by_name(&self, username: &str) -> Option<UserRecord> {
        self.inner.lock().unwrap().users.get(username).cloned()
    }

    async fn insert_nonce(&self, nonce: [u8; 32], username: &str, expires_at_ms: u64) {
        self.inner.lock().unwrap().nonces.insert(
            nonce,
            NonceRecord {
                username: username.to_owned(),
                expires_at_ms,
                used: false,
            },
        );
    }

    async fn outstanding_nonces(&self, username: &str, now_ms: u64) -> Vec<[u8; 32]> {
        self.inner
            .lock()
            .unwrap()
            .nonces
            .iter()
            .filter(|(_, r)| r.username == username && !r.used && r.expires_at_ms > now_ms)
            .map(|(n, _)| *n)
            .collect()
    }

    async fn consume_nonce(&self, nonce: &[u8; 32]) {
        if let Some(r) = self.inner.lock().unwrap().nonces.get_mut(nonce) {
            r.used = true;
        }
    }

    async fn insert_session(&self, token_hash: [u8; 32], rec: SessionRecord) {
        self.inner.lock().unwrap().sessions.insert(token_hash, rec);
    }

    async fn get_session(&self, token_hash: &[u8; 32]) -> Option<SessionRecord> {
        self.inner.lock().unwrap().sessions.get(token_hash).cloned()
    }

    async fn revoke_session(&self, token_hash: &[u8; 32]) {
        if let Some(s) = self.inner.lock().unwrap().sessions.get_mut(token_hash) {
            s.revoked = true;
        }
    }
}
