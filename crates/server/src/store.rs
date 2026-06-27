//! Persistence abstraction for the auth state machine. The server holds only
//! inert/ephemeral auth state (DESIGN §4.3 / schema.sql Phase-1 tables): public
//! user material, single-use challenge nonces, and channel-bound sessions —
//! never a salt, KDF param, or private key (D4).
//!
//! [`MemoryStore`] is the test/dev backing; a Postgres-backed `Store` (sqlx over
//! `users`/`auth_nonces`/`sessions`) is the production adapter (next increment).
//! Methods take `&self` and the impl owns its synchronization, so the service
//! is `Sync` for concurrent request handling.

use crate::control::decode_control;
use crate::error::{ControlAppendError, StoreError};
use async_trait::async_trait;
use maxsecu_crypto::random_array;
use maxsecu_encoding::types::Role;
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

/// A signed directory binding as served by `GET /v1/directory/...` (api.md §6.1):
/// the exact `canonical(dirbinding)` bytes and the offline D5 signature. Inert —
/// the client verifies it against the pinned root; the server forges neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBinding {
    pub binding_bytes: Vec<u8>,
    pub signature: [u8; 64],
}

/// One control-log record as served by `GET /v1/revocations` (api.md §7.1): the
/// opaque signed bytes, the issuer (and optional co-) signature, and the chain
/// `head` (advisory — the client recomputes it and checks the anchored head).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredControlRecord {
    pub kind: i16, // 6=revocation 7=reinstatement 8=key_compromise
    pub record_bytes: Vec<u8>,
    pub sig: [u8; 64],
    pub co_sig: Option<[u8; 64]>,
    pub head: [u8; 32],
}

/// Async because the production backing is sqlx/Postgres. `Send + Sync` so the
/// service can be shared across axum request tasks.
///
/// **Fallible by contract.** Every method returns `Result<_, StoreError>`: a
/// backend fault is a distinct outcome from a business `None`/`false`, so a
/// transient DB error is surfaced (→ 500, logged) rather than swallowed into a
/// fail-closed "not found" that silently denies (see [`StoreError`]). Callers
/// still fail *closed* — they map `Err` to denial — but now *observably*.
#[async_trait]
pub trait Store: Send + Sync {
    /// Create an unsigned user, assigning a fresh 16-byte `user_id` (api.md
    /// §5.1 / §1.4). `Ok(None)` iff the username is taken (→ 409); `Err` is a
    /// backend fault (→ 500), distinct from "taken".
    async fn create_user(
        &self,
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError>;
    /// Consume a one-time enrollment voucher; `Ok(true)` iff it was valid and
    /// unused (the anti-spam gate for the unauthenticated `POST /v1/users`,
    /// api.md §5.1). `Ok(false)` = invalid/used; `Err` = backend fault.
    async fn consume_voucher(&self, voucher_hash: &[u8; 32]) -> Result<bool, StoreError>;
    async fn user_by_name(&self, username: &str) -> Result<Option<UserRecord>, StoreError>;
    async fn insert_nonce(
        &self,
        nonce: [u8; 32],
        username: &str,
        expires_at_ms: u64,
    ) -> Result<(), StoreError>;
    /// Fresh (unexpired, unused) nonces outstanding for `username`.
    async fn outstanding_nonces(
        &self,
        username: &str,
        now_ms: u64,
    ) -> Result<Vec<[u8; 32]>, StoreError>;
    /// Mark a nonce used (single-use; idempotent).
    async fn consume_nonce(&self, nonce: &[u8; 32]) -> Result<(), StoreError>;
    async fn insert_session(
        &self,
        token_hash: [u8; 32],
        rec: SessionRecord,
    ) -> Result<(), StoreError>;
    async fn get_session(&self, token_hash: &[u8; 32])
        -> Result<Option<SessionRecord>, StoreError>;
    async fn revoke_session(&self, token_hash: &[u8; 32]) -> Result<(), StoreError>;

    // ---- Phase 2: signed key directory (DESIGN §7, api.md §6) ----

    /// Publish a ceremony-signed binding (`directory_bindings`, retained by
    /// `key_version`); idempotent re-put of the same `(user_id, key_version)` is
    /// allowed. Also marks the user's binding as signed.
    async fn put_binding(
        &self,
        user_id: [u8; 16],
        key_version: u64,
        binding_bytes: Vec<u8>,
        signature: [u8; 64],
    ) -> Result<(), StoreError>;
    /// The latest signed binding for a username (`GET /v1/directory/{username}`).
    /// `Ok(None)` if the account has no signed binding (→ 404, not a recipient).
    async fn binding_by_username(&self, username: &str)
        -> Result<Option<StoredBinding>, StoreError>;
    /// The latest signed binding for a `user_id` (`GET /v1/directory/by-id/...`).
    async fn binding_by_user_id(
        &self,
        user_id: &[u8; 16],
    ) -> Result<Option<StoredBinding>, StoreError>;

    // ---- Phase 2: revocation control-log (DESIGN §7.6/§11.5, api.md §7) ----

    /// Append a record to the single hash chain (`POST /v1/revocations|...`).
    /// The server derives `prev_head`/`head` from the record bytes and enforces
    /// `prev_head == current head` — `Conflict` on a mismatch, `Malformed` on
    /// non-canonical bytes. Returns the new chain head. The authoritative event
    /// is the *sink* anchoring (Phase 6); here the chain is built and linked.
    async fn append_control(
        &self,
        record_bytes: Vec<u8>,
        sig: [u8; 64],
        co_sig: Option<[u8; 64]>,
    ) -> Result<[u8; 32], ControlAppendError>;
    /// The full chain in append order (`GET /v1/revocations`); the client checks
    /// contiguity to the anchored head and fails closed on a gap.
    async fn control_records(&self) -> Result<Vec<StoredControlRecord>, StoreError>;
    /// The current chain head (`GENESIS_HEAD` if empty).
    async fn control_head(&self) -> Result<[u8; 32], StoreError>;
    /// The caller's advisory roles, for the **coarse** admin gate on control-log
    /// writes (§10.1). Not the security boundary — the client re-verifies every
    /// tombstone's authenticity independently.
    async fn user_roles(&self, user_id: &[u8; 16]) -> Result<Vec<Role>, StoreError>;
}

#[derive(Default)]
struct Inner {
    users: HashMap<String, UserRecord>,
    nonces: HashMap<[u8; 32], NonceRecord>,
    sessions: HashMap<[u8; 32], SessionRecord>,
    vouchers: HashSet<[u8; 32]>, // unused enrollment voucher hashes
    // Latest signed binding per user_id, with its key_version (newer replaces older).
    bindings: HashMap<[u8; 16], (u64, StoredBinding)>,
    // The single append-only control-log chain (in order) + its running head.
    // The default `[0; 32]` is exactly `GENESIS_HEAD` (encoding-spec §3).
    control_log: Vec<StoredControlRecord>,
    control_head: [u8; 32],
    // Advisory roles per user_id for the coarse admin gate (default {user}).
    roles: HashMap<[u8; 16], Vec<Role>>,
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

    /// Seed a user's advisory roles (test/dev) — drives the coarse admin gate.
    pub fn set_roles(&self, user_id: [u8; 16], roles: Vec<Role>) {
        self.inner.lock().unwrap().roles.insert(user_id, roles);
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

// The in-memory backing never faults; every method returns `Ok(...)`.
#[async_trait]
impl Store for MemoryStore {
    async fn create_user(
        &self,
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.users.contains_key(username) {
            return Ok(None);
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
        Ok(Some(user_id))
    }

    async fn consume_voucher(&self, voucher_hash: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self.inner.lock().unwrap().vouchers.remove(voucher_hash))
    }

    async fn user_by_name(&self, username: &str) -> Result<Option<UserRecord>, StoreError> {
        Ok(self.inner.lock().unwrap().users.get(username).cloned())
    }

    async fn insert_nonce(
        &self,
        nonce: [u8; 32],
        username: &str,
        expires_at_ms: u64,
    ) -> Result<(), StoreError> {
        self.inner.lock().unwrap().nonces.insert(
            nonce,
            NonceRecord {
                username: username.to_owned(),
                expires_at_ms,
                used: false,
            },
        );
        Ok(())
    }

    async fn outstanding_nonces(
        &self,
        username: &str,
        now_ms: u64,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .nonces
            .iter()
            .filter(|(_, r)| r.username == username && !r.used && r.expires_at_ms > now_ms)
            .map(|(n, _)| *n)
            .collect())
    }

    async fn consume_nonce(&self, nonce: &[u8; 32]) -> Result<(), StoreError> {
        if let Some(r) = self.inner.lock().unwrap().nonces.get_mut(nonce) {
            r.used = true;
        }
        Ok(())
    }

    async fn insert_session(
        &self,
        token_hash: [u8; 32],
        rec: SessionRecord,
    ) -> Result<(), StoreError> {
        self.inner.lock().unwrap().sessions.insert(token_hash, rec);
        Ok(())
    }

    async fn get_session(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<SessionRecord>, StoreError> {
        Ok(self.inner.lock().unwrap().sessions.get(token_hash).cloned())
    }

    async fn revoke_session(&self, token_hash: &[u8; 32]) -> Result<(), StoreError> {
        if let Some(s) = self.inner.lock().unwrap().sessions.get_mut(token_hash) {
            s.revoked = true;
        }
        Ok(())
    }

    async fn put_binding(
        &self,
        user_id: [u8; 16],
        key_version: u64,
        binding_bytes: Vec<u8>,
        signature: [u8; 64],
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.bindings.entry(user_id);
        let rec = StoredBinding {
            binding_bytes,
            signature,
        };
        match entry {
            std::collections::hash_map::Entry::Occupied(mut o) => {
                if key_version >= o.get().0 {
                    *o.get_mut() = (key_version, rec); // newer (or same) replaces
                }
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert((key_version, rec));
            }
        }
        Ok(())
    }

    async fn binding_by_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredBinding>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let Some(user) = inner.users.get(username) else {
            return Ok(None);
        };
        Ok(inner.bindings.get(&user.user_id).map(|(_, b)| b.clone()))
    }

    async fn binding_by_user_id(
        &self,
        user_id: &[u8; 16],
    ) -> Result<Option<StoredBinding>, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .bindings
            .get(user_id)
            .map(|(_, b)| b.clone()))
    }

    async fn append_control(
        &self,
        record_bytes: Vec<u8>,
        sig: [u8; 64],
        co_sig: Option<[u8; 64]>,
    ) -> Result<[u8; 32], ControlAppendError> {
        let d = decode_control(&record_bytes).ok_or(ControlAppendError::Malformed)?;
        let mut inner = self.inner.lock().unwrap();
        if d.prev_head != inner.control_head {
            return Err(ControlAppendError::Conflict); // gap/stale/concurrent
        }
        inner.control_head = d.head;
        inner.control_log.push(StoredControlRecord {
            kind: d.kind,
            record_bytes,
            sig,
            co_sig,
            head: d.head,
        });
        Ok(d.head)
    }

    async fn control_records(&self) -> Result<Vec<StoredControlRecord>, StoreError> {
        Ok(self.inner.lock().unwrap().control_log.clone())
    }

    async fn control_head(&self) -> Result<[u8; 32], StoreError> {
        Ok(self.inner.lock().unwrap().control_head)
    }

    async fn user_roles(&self, user_id: &[u8; 16]) -> Result<Vec<Role>, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .roles
            .get(user_id)
            .cloned()
            .unwrap_or_else(|| vec![Role::User]))
    }
}

/// A [`Store`] whose every method returns `Err(StoreError)` — used to prove the
/// service/HTTP layers surface a backend fault as `Internal`/`500` rather than
/// swallowing it into a fail-closed `401`/`403` (the bug this fallible contract
/// fixes). Test-only.
#[cfg(test)]
pub(crate) struct FaultyStore;

#[cfg(test)]
impl FaultyStore {
    fn fault(op: &'static str) -> StoreError {
        StoreError::new(op, "injected backend fault")
    }
}

#[cfg(test)]
#[async_trait]
impl Store for FaultyStore {
    async fn create_user(
        &self,
        _username: &str,
        _enc_pub: [u8; 32],
        _sig_pub: [u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        Err(Self::fault("create_user"))
    }
    async fn consume_voucher(&self, _voucher_hash: &[u8; 32]) -> Result<bool, StoreError> {
        Err(Self::fault("consume_voucher"))
    }
    async fn user_by_name(&self, _username: &str) -> Result<Option<UserRecord>, StoreError> {
        Err(Self::fault("user_by_name"))
    }
    async fn insert_nonce(
        &self,
        _nonce: [u8; 32],
        _username: &str,
        _expires_at_ms: u64,
    ) -> Result<(), StoreError> {
        Err(Self::fault("insert_nonce"))
    }
    async fn outstanding_nonces(
        &self,
        _username: &str,
        _now_ms: u64,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        Err(Self::fault("outstanding_nonces"))
    }
    async fn consume_nonce(&self, _nonce: &[u8; 32]) -> Result<(), StoreError> {
        Err(Self::fault("consume_nonce"))
    }
    async fn insert_session(
        &self,
        _token_hash: [u8; 32],
        _rec: SessionRecord,
    ) -> Result<(), StoreError> {
        Err(Self::fault("insert_session"))
    }
    async fn get_session(
        &self,
        _token_hash: &[u8; 32],
    ) -> Result<Option<SessionRecord>, StoreError> {
        Err(Self::fault("get_session"))
    }
    async fn revoke_session(&self, _token_hash: &[u8; 32]) -> Result<(), StoreError> {
        Err(Self::fault("revoke_session"))
    }
    async fn put_binding(
        &self,
        _user_id: [u8; 16],
        _key_version: u64,
        _binding_bytes: Vec<u8>,
        _signature: [u8; 64],
    ) -> Result<(), StoreError> {
        Err(Self::fault("put_binding"))
    }
    async fn binding_by_username(
        &self,
        _username: &str,
    ) -> Result<Option<StoredBinding>, StoreError> {
        Err(Self::fault("binding_by_username"))
    }
    async fn binding_by_user_id(
        &self,
        _user_id: &[u8; 16],
    ) -> Result<Option<StoredBinding>, StoreError> {
        Err(Self::fault("binding_by_user_id"))
    }
    async fn append_control(
        &self,
        _record_bytes: Vec<u8>,
        _sig: [u8; 64],
        _co_sig: Option<[u8; 64]>,
    ) -> Result<[u8; 32], ControlAppendError> {
        Err(ControlAppendError::Store(Self::fault("append_control")))
    }
    async fn control_records(&self) -> Result<Vec<StoredControlRecord>, StoreError> {
        Err(Self::fault("control_records"))
    }
    async fn control_head(&self) -> Result<[u8; 32], StoreError> {
        Err(Self::fault("control_head"))
    }
    async fn user_roles(&self, _user_id: &[u8; 16]) -> Result<Vec<Role>, StoreError> {
        Err(Self::fault("user_roles"))
    }
}
