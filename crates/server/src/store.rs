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
use crate::files::{
    FinalizeError, ListFilter, ParsedStage, StageError, StreamRow, VersionSelector, WrapInput,
};
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

/// The caller's own key-wrap + read-grant as served by `GET /v1/files` (api.md
/// §8.5 `my_wrap`). Inert bytes — the client unwraps and verifies them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapView {
    pub wrapped_dek: Vec<u8>,
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
}

/// One stream's framing as served (api.md §8.5 `streams[]`): enough for the
/// client to fetch its chunks (§9). The per-stream digest is in the manifest the
/// client already verifies, so it is not repeated here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamView {
    pub stream_type: i16,
    pub chunk_count: u64,
    pub chunk_size: u32,
    pub blob_ref: String,
}

/// Everything a downloader needs to verify and decrypt one file version
/// (`GET /v1/files/{id}`, api.md §8.5). Only the **caller's** wrap is included —
/// never another user's, never the recovery *wrap* (only its grant, for the
/// presence check). Absence of a wrap row for the caller is a `404` (no oracle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileView {
    pub version: u64,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
    pub my_wrap: WrapView,
    /// The recovery recipient's grant (bytes + sig only) for the §12.5 presence
    /// check, or `None` if no recovery grant is stored (a flagged anomaly).
    pub recovery_grant: Option<(Vec<u8>, [u8; 64])>,
    pub streams: Vec<StreamView>,
}

/// One listing entry (api.md §8.6 / D35): the authenticated `file_type` + the
/// small-stream structure/sizes only — never their values. `content` is excluded
/// (the listing exists precisely to avoid fetching it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileListEntry {
    pub file_id: [u8; 16],
    pub file_type: i16,
    pub version: u64,
    pub updated_at_ms: u64,
    /// `(stream_type, total_bytes)` for the small streams (metadata/thumbnail/
    /// preview) present in the current version.
    pub small_streams: Vec<(i16, u64)>,
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

    // ---- Phase 3: file records (DESIGN §11.2/§11.7/§12.2, api.md §8) ----

    /// Stage a version's record set (`POST /v1/files` / `.../versions`). The
    /// version is **not visible** until [`finalize_version`](Store::finalize_version).
    /// For v1 (`parsed.genesis` present) the file is created and its owner
    /// recorded; for vN the file must already exist and the caller be its owner
    /// (coarse, D29). Idempotent by `(file_id, version)` while still staged — a
    /// re-stage overwrites the staged rows (api.md §12); re-staging a *finalized*
    /// version is `AlreadyFinalized`. Returns the staged `version`.
    async fn stage_version(
        &self,
        parsed: ParsedStage,
        now_ms: u64,
    ) -> Result<u64, StageError>;

    /// Atomically commit a staged version (`POST .../finalize`, api.md §8.4).
    /// Enforces the serialize-on-`(file_id, version)` strict `+1` rule and flips
    /// the version visible; the prior version's streams + wraps are dropped
    /// (genesis retained, §12.9). Coarse owner check; `VersionConflict` on a lost
    /// race (→ 409). *Chunk-completeness verification is added in P3.7.*
    async fn finalize_version(
        &self,
        file_id: [u8; 16],
        version: u64,
        caller_id: [u8; 16],
        now_ms: u64,
    ) -> Result<(), FinalizeError>;

    /// Serve a finalized version for the caller (`GET /v1/files/{id}`, api.md
    /// §8.5). `Ok(None)` (→ 404) if the file/version is absent, not yet finalized,
    /// or the caller holds no wrap row for it — the missing and forbidden cases
    /// are indistinguishable (no access oracle).
    async fn get_file(
        &self,
        file_id: [u8; 16],
        selector: VersionSelector,
        caller_id: [u8; 16],
    ) -> Result<Option<FileView>, StoreError>;

    /// List finalized files (`GET /v1/files`, api.md §8.6 / D35): the
    /// authenticated `file_type` + small-stream structure/sizes only, newest
    /// first, filtered/limited per `filter`.
    async fn list_files(&self, filter: ListFilter) -> Result<Vec<FileListEntry>, StoreError>;
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
    // Phase 3 file records (schema files/file_genesis/file_versions/file_streams/
    // file_key_wraps), keyed by file_id.
    files: HashMap<[u8; 16], FileEntry>,
}

/// In-memory mirror of one `files` row plus its genesis and versions.
struct FileEntry {
    owner_id: [u8; 16],
    file_type: i16,
    current_version: u64, // 0 while only-staged (schema files.current_version)
    updated_at_ms: u64,
    // Immutable genesis (set on the v1 stage); retained across rotations (§11.7).
    genesis_bytes: Vec<u8>,
    genesis_sig: [u8; 64],
    versions: HashMap<u64, VersionEntry>,
}

/// In-memory mirror of one `file_versions` row plus its streams and wraps.
struct VersionEntry {
    manifest_bytes: Vec<u8>,
    manifest_sig: [u8; 64],
    finalized: bool,
    streams: Vec<StreamRow>,
    wraps: Vec<WrapInput>,
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

    async fn stage_version(&self, parsed: ParsedStage, now_ms: u64) -> Result<u64, StageError> {
        let mut inner = self.inner.lock().unwrap();
        let version = parsed.version;
        let new_ver = VersionEntry {
            manifest_bytes: parsed.manifest_bytes,
            manifest_sig: parsed.manifest_sig,
            finalized: false,
            streams: parsed.streams,
            wraps: parsed.wraps,
        };
        match parsed.genesis {
            // Version 1 / create: the file may be new, or a re-stage of a
            // still-staged v1 (idempotent overwrite). A finalized v1 is immutable.
            Some(g) => {
                if let Some(f) = inner.files.get(&parsed.file_id) {
                    if f.versions.get(&version).is_some_and(|v| v.finalized) {
                        return Err(StageError::AlreadyFinalized);
                    }
                }
                let entry = inner.files.entry(parsed.file_id).or_insert_with(|| FileEntry {
                    owner_id: g.owner_id,
                    file_type: parsed.file_type,
                    current_version: 0,
                    updated_at_ms: now_ms,
                    genesis_bytes: g.genesis_bytes,
                    genesis_sig: g.genesis_sig,
                    versions: HashMap::new(),
                });
                entry.versions.insert(version, new_ver);
            }
            // Rotation (vN): the file must exist and the caller own it. parse_stage
            // already required author == caller; here caller == owner closes D29.
            None => {
                let Some(entry) = inner.files.get_mut(&parsed.file_id) else {
                    return Err(StageError::NoSuchFile);
                };
                if entry.owner_id != parsed.author_id {
                    return Err(StageError::NotOwner);
                }
                if entry.versions.get(&version).is_some_and(|v| v.finalized) {
                    return Err(StageError::AlreadyFinalized);
                }
                entry.versions.insert(version, new_ver);
            }
        }
        Ok(version)
    }

    async fn finalize_version(
        &self,
        file_id: [u8; 16],
        version: u64,
        caller_id: [u8; 16],
        now_ms: u64,
    ) -> Result<(), FinalizeError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(entry) = inner.files.get_mut(&file_id) else {
            return Err(FinalizeError::NoSuchVersion);
        };
        if entry.owner_id != caller_id {
            return Err(FinalizeError::NotOwner);
        }
        match entry.versions.get(&version) {
            None => return Err(FinalizeError::NoSuchVersion),
            Some(v) if v.finalized => return Err(FinalizeError::AlreadyFinalized),
            Some(_) => {}
        }
        // Serialize-on-(file_id, version): accept iff a strict +1 of the current.
        let expected = entry.current_version + 1;
        if version != expected {
            return Err(FinalizeError::VersionConflict {
                expected,
                got: version,
            });
        }
        let prior = entry.current_version;
        entry.versions.get_mut(&version).unwrap().finalized = true;
        entry.current_version = version;
        entry.updated_at_ms = now_ms;
        // Drop the prior version's chunks (streams) + wraps; genesis + the prior
        // manifest are retained (api.md §8.4 / §12.9).
        if prior >= 1 {
            if let Some(pv) = entry.versions.get_mut(&prior) {
                pv.streams.clear();
                pv.wraps.clear();
            }
        }
        Ok(())
    }

    async fn get_file(
        &self,
        file_id: [u8; 16],
        selector: VersionSelector,
        caller_id: [u8; 16],
    ) -> Result<Option<FileView>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let Some(entry) = inner.files.get(&file_id) else {
            return Ok(None);
        };
        let version = match selector {
            VersionSelector::Latest => entry.current_version,
            VersionSelector::Specific(v) => v,
        };
        if version == 0 {
            return Ok(None); // nothing finalized yet
        }
        let Some(ver) = entry.versions.get(&version) else {
            return Ok(None);
        };
        if !ver.finalized {
            return Ok(None); // staged, not yet visible
        }
        // Only the caller's own wrap — its absence is indistinguishable from a
        // missing file (no access oracle, api.md §8.5).
        let Some(my) = ver.wraps.iter().find(|w| w.recipient_id == caller_id) else {
            return Ok(None);
        };
        let recovery_grant = ver
            .wraps
            .iter()
            .find(|w| w.recipient_type == 2) // 2 = recovery (schema file_key_wraps)
            .map(|w| (w.grant_bytes.clone(), w.grant_sig));
        let streams = ver
            .streams
            .iter()
            .map(|s| StreamView {
                stream_type: s.stream_type,
                chunk_count: s.chunk_count,
                chunk_size: s.chunk_size,
                blob_ref: s.blob_ref.clone(),
            })
            .collect();
        Ok(Some(FileView {
            version,
            manifest_bytes: ver.manifest_bytes.clone(),
            manifest_sig: ver.manifest_sig,
            genesis_bytes: entry.genesis_bytes.clone(),
            genesis_sig: entry.genesis_sig,
            my_wrap: WrapView {
                wrapped_dek: my.wrapped_dek.clone(),
                grant_bytes: my.grant_bytes.clone(),
                grant_sig: my.grant_sig,
            },
            recovery_grant,
            streams,
        }))
    }

    async fn list_files(&self, filter: ListFilter) -> Result<Vec<FileListEntry>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<FileListEntry> = inner
            .files
            .iter()
            .filter(|(_, f)| f.current_version >= 1) // finalized only
            .filter(|(_, f)| filter.file_type.is_none_or(|t| t == f.file_type))
            .filter_map(|(id, f)| {
                let ver = f.versions.get(&f.current_version)?;
                let small_streams = ver
                    .streams
                    .iter()
                    .filter(|s| s.stream_type != 1) // exclude content
                    .map(|s| (s.stream_type, s.total_bytes))
                    .collect();
                Some(FileListEntry {
                    file_id: *id,
                    file_type: f.file_type,
                    version: f.current_version,
                    updated_at_ms: f.updated_at_ms,
                    small_streams,
                })
            })
            .collect();
        // Newest first, then file_id for a stable order (schema files_listing_idx).
        out.sort_by(|a, b| {
            b.updated_at_ms
                .cmp(&a.updated_at_ms)
                .then(a.file_id.cmp(&b.file_id))
        });
        out.truncate(filter.limit);
        Ok(out)
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
    async fn stage_version(&self, _parsed: ParsedStage, _now_ms: u64) -> Result<u64, StageError> {
        Err(StageError::Store(Self::fault("stage_version")))
    }
    async fn finalize_version(
        &self,
        _file_id: [u8; 16],
        _version: u64,
        _caller_id: [u8; 16],
        _now_ms: u64,
    ) -> Result<(), FinalizeError> {
        Err(FinalizeError::Store(Self::fault("finalize_version")))
    }
    async fn get_file(
        &self,
        _file_id: [u8; 16],
        _selector: VersionSelector,
        _caller_id: [u8; 16],
    ) -> Result<Option<FileView>, StoreError> {
        Err(Self::fault("get_file"))
    }
    async fn list_files(&self, _filter: ListFilter) -> Result<Vec<FileListEntry>, StoreError> {
        Err(Self::fault("list_files"))
    }
}
