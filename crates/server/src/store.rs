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
    AddWrapError, DeleteWrapError, DiscardError, FinalizeError, ListFilter, ParsedStage, StageError,
    StreamRow, VersionSelector, WrapInput,
};
use async_trait::async_trait;
use maxsecu_crypto::random_array;
use maxsecu_encoding::structs::MLKEM768_PUB_LEN;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Public identity material the server stores for a user (schema.sql `users`).
#[derive(Clone, Debug)]
pub struct UserRecord {
    pub user_id: [u8; 16],
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
}

/// The single escrow **recovery account**'s PUBLIC keys (schema.sql
/// `recovery_account`; T3). The recovery identity uses the same key types as a
/// normal Identity (spec §3), which today is PQ-hybrid: an X25519 `enc_pub`
/// **and** an optional ML-KEM-768 `mlkem_pub`. Wraps to recovery encapsulate to
/// both so an upload stays `Suite::V2` (dropping `mlkem_pub` would silently
/// downgrade every recovery-wrapped upload to classical V1). `mlkem_pub` is
/// `None` only for a classical-only recovery account. Mirrors
/// [`DirBinding.mlkem_pub`](maxsecu_encoding::structs::DirBinding). No private
/// key is ever stored (D4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAccount {
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
    pub mlkem_pub: Option<[u8; MLKEM768_PUB_LEN]>,
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
    /// The re-share ancestor grants chaining this wrap's leaf grant to the
    /// version author (api.md §8.5 `my_wrap.ancestor_grants`), nearest-first.
    /// Empty for an author-rooted wrap. Advisory: assembled by walking the
    /// server's own `granted_by` edges — the client re-verifies it (P4.1).
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
}

/// One **user** recipient of a file's current version, as served to the **owner**
/// for rotation carry-forward (`GET /v1/files/{id}/recipients`, §12.9 step 2).
/// Carries the recipient's leaf grant + its ancestor chain so the owner can
/// re-verify the §12.5 chain before carrying it forward. The wrapped DEK is
/// *not* included — the owner re-wraps the fresh DEK to the recipient's
/// directory-verified `enc_pub` (resolved out of band), it does not need anyone
/// else's ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientView {
    pub recipient_id: [u8; 16],
    pub granted_by: [u8; 16],
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
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

/// One stream's chunk-slot framing for the blob tier (api.md §9): its
/// server-assigned `blob_ref`, expected `chunk_count`, and `chunk_size` bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkSlot {
    pub stream_type: i16,
    pub blob_ref: String,
    pub chunk_count: u64,
    pub chunk_size: u32,
}

/// Staging/visibility metadata for one file version, used by the chunk endpoints
/// (api.md §9) and the finalize completeness check (§8.4): the coarse `owner_id`,
/// whether the version is `finalized` (visible / immutable), and its stream slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionMeta {
    pub owner_id: [u8; 16],
    pub finalized: bool,
    pub streams: Vec<ChunkSlot>,
}

/// File-level metadata independent of any version (schema `files`): the coarse
/// `owner_id`, the advisory `file_type`, and the set-once-at-genesis feed
/// visibility (`listed`) + owning-bundle pointer (`bundle_id`) — Task 1.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMeta {
    pub owner_id: [u8; 16],
    pub file_type: i16,
    pub listed: bool,
    pub bundle_id: Option<[u8; 16]>,
}

/// Async because the production backing is sqlx/Postgres. `Send + Sync` so the
/// service can be shared across axum request tasks.
///
/// **Fallible by contract.** Every method returns `Result<_, StoreError>`: a
/// backend fault is a distinct outcome from a business `None`/`false`, so a
/// transient DB error is surfaced (→ 500, logged) rather than swallowed into a
/// fail-closed "not found" that silently denies (see [`StoreError`]). Callers
/// still fail *closed* — they map `Err` to denial — but now *observably*.
/// The outcome of the atomic registration-key [`enroll`](Store::enroll) unit of
/// work (T4). A backend fault is the separate `Err` arm — these are the clean
/// business outcomes, each leaving the store in a fully-consistent state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// The registration key was unknown / already used / expired. NOTHING was
    /// written — the key is not consumed, no user created (→ 403). A retry with a
    /// valid key still works.
    KeyInvalid,
    /// The username is taken. The whole unit rolled back — the key is NOT consumed
    /// and no partial row remains (→ 409). A retry with a free username + the same
    /// key works.
    UsernameTaken,
    /// The user was created, the first-admin slot resolved, and the matching
    /// server-signed binding stored — ALL atomically (→ 201). `is_admin` reports
    /// whether this registrant claimed the one-time admin slot.
    Enrolled { is_admin: bool },
}

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

    // ---- Registration keys (single-use enrollment secrets; T2) ----

    /// Persist a fresh single-use **registration key** by its `SHA-256` hash
    /// (never the plaintext), with an absolute expiry. Unlike a voucher there is
    /// no `issued_by` — these are handed out by the operator, not an in-app admin.
    /// Idempotent re-issue of the same hash is allowed.
    async fn issue_registration_key(
        &self,
        key_hash: [u8; 32],
        expires_at_ms: u64,
    ) -> Result<(), StoreError>;
    /// Consume a registration key by its hash; `Ok(true)` iff it was present,
    /// unused and unexpired (deleted-on-consume — atomic single-use). `Ok(false)`
    /// = unknown/used/expired; `Err` = fault.
    async fn consume_registration_key(&self, key_hash: &[u8; 32])
        -> Result<bool, StoreError>;
    /// Atomically claim the ONE-TIME "first admin" slot: `Ok(true)` for exactly
    /// the first caller ever, `Ok(false)` thereafter. The race-safe primitive
    /// backing [`enroll`](Store::enroll)'s admin decision — a singleton row claimed
    /// via `ON CONFLICT DO NOTHING` (the same pattern as [`set_recovery_account`]),
    /// so two concurrent first-registrants can never both become admin. Exposed on
    /// the trait so tests can pre-claim the slot (mark a genesis admin) before
    /// exercising later enrollments; the enrollment path itself performs the claim
    /// *inside* [`enroll`](Store::enroll)'s transaction, not via this method.
    ///
    /// [`set_recovery_account`]: Store::set_recovery_account
    async fn claim_first_admin(&self) -> Result<bool, StoreError>;
    /// **Atomic registration-key enrollment (T4).** Performs the entire unit of
    /// work — consume the single-use key, create the user, resolve the one-time
    /// first-admin slot, and store the matching **already-signed** binding — in ONE
    /// transaction (PgStore) / under the single lock (MemoryStore), so a fault
    /// mid-way leaves NO partial state: the key is not consumed, no orphan user, no
    /// dangling admin claim, and a retry with the same key works. Signing is pure
    /// and done by the caller *before* this call; the two candidate bindings
    /// (`user_binding` = `{User}`, `admin_binding` = `{User, Admin}`) are signed
    /// for the SAME `user_id`, and this method stores exactly the one matching the
    /// atomic first-admin decision. `key_version` is always 1 (enrollment).
    ///
    /// Returns [`EnrollOutcome`]; `Err` is a backend fault (→ 500). Closes the
    /// first-enrollment "zero-admins" hole that a non-transactional
    /// consume→create→claim→put sequence left on a mid-sequence fault.
    #[allow(clippy::too_many_arguments)]
    async fn enroll(
        &self,
        reg_key_hash: [u8; 32],
        user_id: [u8; 16],
        username: &str,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
        user_binding: &StoredBinding,
        admin_binding: &StoredBinding,
    ) -> Result<EnrollOutcome, StoreError>;

    // ---- Recovery account (the single escrow identity; T3) ----

    /// Register the ONE recovery account by its PUBLIC keys — an X25519 `enc_pub`
    /// (recovery challenges wrap to it; clients compare it to their embedded pin),
    /// an Ed25519 `sig_pub`, and an OPTIONAL ML-KEM-768 `mlkem_pub` (the PQ-hybrid
    /// encapsulation half; `None` = classical-only recovery). **Once-only**:
    /// `Ok(true)` iff this call stored the account; `Ok(false)` iff one already
    /// exists (the stored keys are left UNCHANGED — no overwrite). Race-safe: a
    /// single-row table means exactly one of any concurrent setters wins. `Err`
    /// is a backend fault. Never stores a private key (public material only, D4).
    async fn set_recovery_account(
        &self,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
        mlkem_pub: Option<[u8; MLKEM768_PUB_LEN]>,
    ) -> Result<bool, StoreError>;
    /// The registered recovery account's public keys, or `Ok(None)` if none has
    /// been registered yet (`GET`-served to clients for the pin compare + used as
    /// the PQ-hybrid recovery wrap target).
    async fn recovery_account(&self) -> Result<Option<RecoveryAccount>, StoreError>;

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

    /// Staging metadata for one version — owner, finalized flag, and stream
    /// slots — for the chunk PUT/GET bound checks and the finalize completeness
    /// check (api.md §9 / §8.4). `Ok(None)` if no such (file, version) is staged.
    async fn version_meta(
        &self,
        file_id: [u8; 16],
        version: u64,
    ) -> Result<Option<VersionMeta>, StoreError>;

    /// File-level metadata (owner, type, and the set-once feed-visibility fields
    /// `listed`/`bundle_id`) regardless of any version's finalize state — Task 1.3.
    /// `Ok(None)` if no such file exists.
    async fn get_file_meta(
        &self,
        file_id: [u8; 16],
    ) -> Result<Option<FileMeta>, StoreError>;

    /// Add a read re-share wrap to the file's current finalized version
    /// (`POST /v1/files/{id}/wraps`, api.md §10.1). Coarse-gated: the posted
    /// `granted_by` must be `caller_id`, the recipient must be a user (not
    /// recovery), and the caller must already hold a wrap for that version
    /// (§12.4b). Idempotent by recipient (a re-share replaces an existing row).
    /// The wrap bytes are inert; the client re-verifies the grant.
    async fn add_wrap(
        &self,
        file_id: [u8; 16],
        wrap: WrapInput,
        caller_id: [u8; 16],
        now_ms: u64,
    ) -> Result<(), AddWrapError>;

    /// Soft-revoke a recipient (`DELETE /v1/files/{id}/wraps/{recipient}`, api.md
    /// §10.2): delete their wrap from the current finalized version so the server
    /// stops serving them. Coarse-gated: the caller must be the file **owner** or
    /// the wrap's **`granted_by`**. A server-side denial only, **not** a
    /// cryptographic boundary (§12.8).
    async fn delete_wrap(
        &self,
        file_id: [u8; 16],
        recipient_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<(), DeleteWrapError>;

    /// List the **user** recipients of a file's current finalized version with
    /// their grant chains, for the **owner** to drive rotation carry-forward
    /// (`GET /v1/files/{id}/recipients`, §12.9 step 2). `Ok(None)` (→ 404) if the
    /// file is absent **or** the caller is not the owner — same code, no oracle.
    /// Excludes the recovery recipient (the owner always re-adds it).
    async fn list_recipients(
        &self,
        file_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<Option<Vec<RecipientView>>, StoreError>;

    /// Discard a staged-but-never-finalized upload (`DELETE /v1/files/{id}`).
    /// Returns the `blob_ref` strings of the freed streams so the handler can
    /// call `BlobStore::delete_stream` on each. Returns `Ok(vec![])` if the file
    /// is absent or has no staged version (idempotent success). Rejects if any
    /// finalized version exists (append-only model, §11.7). Owner-only:
    /// missing-or-not-owner collapses to `NotFound` (no oracle, §9.3).
    async fn discard_unfinalized(
        &self,
        file_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<Vec<String>, DiscardError>;
}

/// Defensive cap on the server-assembled re-share ancestor chain (mirrors the
/// client's `MAX_GRANT_CHAIN_DEPTH`, parameters §1.5): malformed stored
/// `granted_by` edges cannot drive an unbounded walk.
const MAX_ANCESTOR_CHAIN: usize = 32;

/// Walk `granted_by` from `leaf` up to `author`, collecting each ancestor wrap's
/// grant (bytes + sig), nearest-first (api.md §8.5). Stops at the author, a
/// missing edge, a repeated granter (cycle), or the depth cap — all fail-safe;
/// the client re-verifies the chain it returns (P4.1).
pub(crate) fn ancestor_chain(
    wraps: &[WrapInput],
    leaf: &WrapInput,
    author: [u8; 16],
) -> Vec<(Vec<u8>, [u8; 64])> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut granted_by = leaf.granted_by;
    while granted_by != author && out.len() < MAX_ANCESTOR_CHAIN && seen.insert(granted_by) {
        let Some(anc) = wraps.iter().find(|w| w.recipient_id == granted_by) else {
            break;
        };
        out.push((anc.grant_bytes.clone(), anc.grant_sig));
        granted_by = anc.granted_by;
    }
    out
}

#[derive(Default)]
struct Inner {
    users: HashMap<String, UserRecord>,
    nonces: HashMap<[u8; 32], NonceRecord>,
    sessions: HashMap<[u8; 32], SessionRecord>,
    reg_keys: HashSet<[u8; 32]>, // unused single-use registration-key hashes (T2)
    // The one-time first-admin claim (T4): `true` once the first registrant has
    // claimed admin; every later `claim_first_admin` observes `true` and loses.
    first_admin_claimed: bool,
    // The single recovery account's PUBLIC keys (X25519 + optional ML-KEM-768);
    // once set, never overwritten (T3). `None` until registered.
    recovery_account: Option<RecoveryAccount>,
    // Latest signed binding per user_id, with its key_version (newer replaces older).
    bindings: HashMap<[u8; 16], (u64, StoredBinding)>,
    // The single append-only control-log chain (in order) + its running head.
    // The default `[0; 32]` is exactly `GENESIS_HEAD` (encoding-spec §3).
    control_log: Vec<StoredControlRecord>,
    control_head: [u8; 32],
    // Phase 3 file records (schema files/file_genesis/file_versions/file_streams/
    // file_key_wraps), keyed by file_id.
    files: HashMap<[u8; 16], FileEntry>,
}

/// In-memory mirror of one `files` row plus its genesis and versions.
struct FileEntry {
    owner_id: [u8; 16],
    file_type: i16,
    // Set once at v1 creation (Task 1.3); unchanged across rotations. `listed`
    // false = a bundle member hidden from the feed listing (Task 1.4).
    listed: bool,
    bundle_id: Option<[u8; 16]>,
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
        let mut inner = self.inner.lock().unwrap();
        inner.users.insert(username.to_owned(), rec);
    }

    /// Seed a usable single-use registration key by its `SHA-256` hash (T4 tests).
    pub fn add_reg_key(&self, key_hash: [u8; 32]) {
        self.inner.lock().unwrap().reg_keys.insert(key_hash);
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

    async fn issue_registration_key(
        &self,
        key_hash: [u8; 32],
        _expires_at_ms: u64,
    ) -> Result<(), StoreError> {
        self.inner.lock().unwrap().reg_keys.insert(key_hash);
        Ok(())
    }

    async fn consume_registration_key(
        &self,
        key_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        Ok(self.inner.lock().unwrap().reg_keys.remove(key_hash))
    }

    async fn claim_first_admin(&self) -> Result<bool, StoreError> {
        // Once-only under the single lock: the first caller flips the flag and
        // wins (→ admin); every later caller observes `true` and loses. The
        // MemoryStore analogue of the singleton PK's `ON CONFLICT DO NOTHING`.
        let mut inner = self.inner.lock().unwrap();
        if inner.first_admin_claimed {
            return Ok(false);
        }
        inner.first_admin_claimed = true;
        Ok(true)
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
        // Everything happens under the single `Inner` lock. Preconditions are
        // checked FIRST and the maps are only mutated once all pass, so an early
        // return leaves the store byte-for-byte unchanged (the MemoryStore analogue
        // of a Pg transaction rolled back before any write).
        let mut inner = self.inner.lock().unwrap();
        // 1. Single-use key (the dev store tracks membership only, no expiry).
        if !inner.reg_keys.contains(&reg_key_hash) {
            return Ok(EnrollOutcome::KeyInvalid); // nothing consumed
        }
        // 2. Username uniqueness — bail BEFORE consuming the key.
        if inner.users.contains_key(username) {
            return Ok(EnrollOutcome::UsernameTaken); // key NOT consumed
        }
        // 3. First-admin slot (same flag as `claim_first_admin`).
        let is_admin = !inner.first_admin_claimed;
        let binding = if is_admin { admin_binding } else { user_binding };
        // All preconditions passed — commit every mutation together.
        inner.reg_keys.remove(&reg_key_hash);
        inner.first_admin_claimed = true;
        inner.users.insert(
            username.to_owned(),
            UserRecord {
                user_id,
                enc_pub,
                sig_pub,
            },
        );
        inner.bindings.insert(
            user_id,
            (
                1,
                StoredBinding {
                    binding_bytes: binding.binding_bytes.clone(),
                    signature: binding.signature,
                },
            ),
        );
        Ok(EnrollOutcome::Enrolled { is_admin })
    }

    async fn set_recovery_account(
        &self,
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
        mlkem_pub: Option<[u8; MLKEM768_PUB_LEN]>,
    ) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        // Once-only under the single lock: a second setter observes `Some` and
        // loses without overwriting (the MemoryStore analogue of the singleton
        // PK's `ON CONFLICT DO NOTHING`).
        if inner.recovery_account.is_some() {
            return Ok(false);
        }
        inner.recovery_account = Some(RecoveryAccount {
            enc_pub,
            sig_pub,
            mlkem_pub,
        });
        Ok(true)
    }

    async fn recovery_account(&self) -> Result<Option<RecoveryAccount>, StoreError> {
        Ok(self.inner.lock().unwrap().recovery_account.clone())
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
                    listed: parsed.listed,
                    bundle_id: parsed.bundle_id,
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
        // Walk the server's own `granted_by` edges to assemble the re-share
        // ancestor chain up to the author (owner-only write, §11.7) — advisory;
        // the client re-verifies it (P4.1). Defensively depth-capped + cycle-
        // guarded so malformed stored edges cannot loop (parameters §1.5).
        let ancestor_grants = ancestor_chain(&ver.wraps, my, entry.owner_id);
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
                ancestor_grants,
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

    async fn version_meta(
        &self,
        file_id: [u8; 16],
        version: u64,
    ) -> Result<Option<VersionMeta>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let Some(entry) = inner.files.get(&file_id) else {
            return Ok(None);
        };
        let Some(ver) = entry.versions.get(&version) else {
            return Ok(None);
        };
        let streams = ver
            .streams
            .iter()
            .map(|s| ChunkSlot {
                stream_type: s.stream_type,
                blob_ref: s.blob_ref.clone(),
                chunk_count: s.chunk_count,
                chunk_size: s.chunk_size,
            })
            .collect();
        Ok(Some(VersionMeta {
            owner_id: entry.owner_id,
            finalized: ver.finalized,
            streams,
        }))
    }

    async fn get_file_meta(
        &self,
        file_id: [u8; 16],
    ) -> Result<Option<FileMeta>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let Some(entry) = inner.files.get(&file_id) else {
            return Ok(None);
        };
        Ok(Some(FileMeta {
            owner_id: entry.owner_id,
            file_type: entry.file_type,
            listed: entry.listed,
            bundle_id: entry.bundle_id,
        }))
    }

    async fn add_wrap(
        &self,
        file_id: [u8; 16],
        wrap: WrapInput,
        caller_id: [u8; 16],
        now_ms: u64,
    ) -> Result<(), AddWrapError> {
        // Body consistency: the re-sharer signs as themselves, and re-share
        // targets a user — never the recovery recipient (§12.4b/§12.9).
        if wrap.granted_by != caller_id
            || wrap.recipient_type != 1
            || wrap.recipient_id == maxsecu_encoding::RECOVERY_ID.0
        {
            return Err(AddWrapError::BadRequest);
        }
        let mut inner = self.inner.lock().unwrap();
        let Some(entry) = inner.files.get_mut(&file_id) else {
            return Err(AddWrapError::NoAccess);
        };
        let version = entry.current_version;
        if version == 0 {
            return Err(AddWrapError::NoAccess);
        }
        let Some(ver) = entry.versions.get_mut(&version) else {
            return Err(AddWrapError::NoAccess);
        };
        if !ver.finalized {
            return Err(AddWrapError::NoAccess);
        }
        // Coarse §10.1: the caller must already hold a wrap for this version.
        if !ver.wraps.iter().any(|w| w.recipient_id == caller_id) {
            return Err(AddWrapError::NoAccess);
        }
        // Idempotent by recipient — a re-share replaces any existing row.
        ver.wraps.retain(|w| w.recipient_id != wrap.recipient_id);
        ver.wraps.push(wrap);
        entry.updated_at_ms = now_ms;
        Ok(())
    }

    async fn delete_wrap(
        &self,
        file_id: [u8; 16],
        recipient_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<(), DeleteWrapError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(entry) = inner.files.get_mut(&file_id) else {
            return Err(DeleteWrapError::NotFound);
        };
        let owner_id = entry.owner_id;
        let version = entry.current_version;
        if version == 0 {
            return Err(DeleteWrapError::NotFound);
        }
        let Some(ver) = entry.versions.get_mut(&version) else {
            return Err(DeleteWrapError::NotFound);
        };
        let Some(target) = ver.wraps.iter().find(|w| w.recipient_id == recipient_id) else {
            return Err(DeleteWrapError::NotFound);
        };
        // Coarse owner-or-granter gate (§14.5 "cut the subtree" intuition).
        if caller_id != owner_id && caller_id != target.granted_by {
            return Err(DeleteWrapError::NotAuthorized);
        }
        ver.wraps.retain(|w| w.recipient_id != recipient_id);
        Ok(())
    }

    async fn list_recipients(
        &self,
        file_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<Option<Vec<RecipientView>>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let Some(entry) = inner.files.get(&file_id) else {
            return Ok(None);
        };
        // Owner-only (no oracle: a non-owner is indistinguishable from missing).
        if entry.owner_id != caller_id {
            return Ok(None);
        }
        let version = entry.current_version;
        if version == 0 {
            return Ok(None);
        }
        let Some(ver) = entry.versions.get(&version) else {
            return Ok(None);
        };
        let out = ver
            .wraps
            .iter()
            .filter(|w| w.recipient_type == 1) // user recipients only (no recovery)
            .map(|w| RecipientView {
                recipient_id: w.recipient_id,
                granted_by: w.granted_by,
                grant_bytes: w.grant_bytes.clone(),
                grant_sig: w.grant_sig,
                ancestor_grants: ancestor_chain(&ver.wraps, w, entry.owner_id),
            })
            .collect();
        Ok(Some(out))
    }

    async fn discard_unfinalized(
        &self,
        file_id: [u8; 16],
        caller_id: [u8; 16],
    ) -> Result<Vec<String>, DiscardError> {
        let mut inner = self.inner.lock().unwrap();
        // Phase 1: checks + collect blob_refs (immutable borrow of inner.files).
        let (staged_keys, blob_refs) = {
            let Some(entry) = inner.files.get(&file_id) else {
                return Ok(vec![]); // idempotent: absent file has no staged version
            };
            if entry.owner_id != caller_id {
                return Err(DiscardError::NotFound); // no oracle
            }
            if entry.current_version >= 1 {
                return Err(DiscardError::HasFinalizedVersion);
            }
            let mut blob_refs: Vec<String> = Vec::new();
            let staged_keys: Vec<u64> = entry
                .versions
                .iter()
                .filter_map(|(k, v)| {
                    if !v.finalized {
                        for s in &v.streams {
                            blob_refs.push(s.blob_ref.clone());
                        }
                        Some(*k)
                    } else {
                        None
                    }
                })
                .collect();
            (staged_keys, blob_refs)
        };
        // Phase 2: remove the staged version entries (phase-1 borrow now dropped).
        if let Some(entry) = inner.files.get_mut(&file_id) {
            for k in staged_keys {
                entry.versions.remove(&k);
            }
        }
        Ok(blob_refs)
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
    async fn issue_registration_key(
        &self,
        _key_hash: [u8; 32],
        _expires_at_ms: u64,
    ) -> Result<(), StoreError> {
        Err(Self::fault("issue_registration_key"))
    }
    async fn consume_registration_key(
        &self,
        _key_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        Err(Self::fault("consume_registration_key"))
    }
    async fn claim_first_admin(&self) -> Result<bool, StoreError> {
        Err(Self::fault("claim_first_admin"))
    }
    async fn enroll(
        &self,
        _reg_key_hash: [u8; 32],
        _user_id: [u8; 16],
        _username: &str,
        _enc_pub: [u8; 32],
        _sig_pub: [u8; 32],
        _user_binding: &StoredBinding,
        _admin_binding: &StoredBinding,
    ) -> Result<EnrollOutcome, StoreError> {
        Err(Self::fault("enroll"))
    }
    async fn set_recovery_account(
        &self,
        _enc_pub: [u8; 32],
        _sig_pub: [u8; 32],
        _mlkem_pub: Option<[u8; MLKEM768_PUB_LEN]>,
    ) -> Result<bool, StoreError> {
        Err(Self::fault("set_recovery_account"))
    }
    async fn recovery_account(&self) -> Result<Option<RecoveryAccount>, StoreError> {
        Err(Self::fault("recovery_account"))
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
    async fn version_meta(
        &self,
        _file_id: [u8; 16],
        _version: u64,
    ) -> Result<Option<VersionMeta>, StoreError> {
        Err(Self::fault("version_meta"))
    }
    async fn get_file_meta(
        &self,
        _file_id: [u8; 16],
    ) -> Result<Option<FileMeta>, StoreError> {
        Err(Self::fault("get_file_meta"))
    }

    async fn add_wrap(
        &self,
        _file_id: [u8; 16],
        _wrap: WrapInput,
        _caller_id: [u8; 16],
        _now_ms: u64,
    ) -> Result<(), AddWrapError> {
        Err(AddWrapError::Store(Self::fault("add_wrap")))
    }

    async fn delete_wrap(
        &self,
        _file_id: [u8; 16],
        _recipient_id: [u8; 16],
        _caller_id: [u8; 16],
    ) -> Result<(), DeleteWrapError> {
        Err(DeleteWrapError::Store(Self::fault("delete_wrap")))
    }

    async fn list_recipients(
        &self,
        _file_id: [u8; 16],
        _caller_id: [u8; 16],
    ) -> Result<Option<Vec<RecipientView>>, StoreError> {
        Err(Self::fault("list_recipients"))
    }

    async fn discard_unfinalized(
        &self,
        _file_id: [u8; 16],
        _caller_id: [u8; 16],
    ) -> Result<Vec<String>, DiscardError> {
        Err(DiscardError::Store(Self::fault("discard_unfinalized")))
    }
}

#[cfg(test)]
mod memory_store_tests {
    use super::*;
    use crate::files::{GenesisRow, ParsedStage};

    /// Build a version-1 [`ParsedStage`] the way `parse_stage` would, carrying the
    /// file-level `listed`/`bundle_id` set once at genesis (Task 1.3).
    fn v1_parsed(
        file: [u8; 16],
        owner: [u8; 16],
        listed: bool,
        bundle_id: Option<[u8; 16]>,
    ) -> ParsedStage {
        ParsedStage {
            file_id: file,
            file_type: 3, // blog
            version: 1,
            author_id: owner,
            alg: 1,
            manifest_bytes: vec![0x01, 0x02, 0x03],
            manifest_sig: [0u8; 64],
            genesis: Some(GenesisRow {
                owner_id: owner,
                owner_key_version: 1,
                genesis_bytes: vec![0x0A, 0x0B],
                genesis_sig: [0u8; 64],
            }),
            streams: vec![],
            wraps: vec![],
            recovery_present: true,
            listed,
            bundle_id,
        }
    }

    #[tokio::test]
    async fn stage_records_listed_and_bundle_id() {
        let store = MemoryStore::new();

        // A bundle member: listed=false, bundle_id=Some(..) → round-trips.
        store
            .stage_version(v1_parsed([1u8; 16], [7u8; 16], false, Some([9u8; 16])), 1_000)
            .await
            .unwrap();
        let rec = store.get_file_meta([1u8; 16]).await.unwrap().unwrap();
        assert!(!rec.listed);
        assert_eq!(rec.bundle_id, Some([9u8; 16]));
        assert_eq!(rec.file_type, 3);
        assert_eq!(rec.owner_id, [7u8; 16]);

        // Fields defaulted → listed=true, bundle_id=None.
        store
            .stage_version(v1_parsed([2u8; 16], [7u8; 16], true, None), 1_000)
            .await
            .unwrap();
        let rec2 = store.get_file_meta([2u8; 16]).await.unwrap().unwrap();
        assert!(rec2.listed);
        assert_eq!(rec2.bundle_id, None);

        // Unknown file → Ok(None).
        assert!(store.get_file_meta([0xEEu8; 16]).await.unwrap().is_none());
    }
}
