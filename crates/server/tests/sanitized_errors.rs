//! P6.7 — sanitized-error proof suite (DESIGN §16.2 / api.md §3).
//!
//! Drives every server error path over the HTTP stack (`tower` oneshot) and
//! proves two invariants the §16.2 "fail closed, sanitized" rule demands:
//!
//! 1. **No internals leak.** An error body carries NONE of: a filesystem path
//!    fragment, SQL/driver text, the surfaced [`StoreError`] `detail`/`context`,
//!    panic/backtrace markers, or thread/line info. The server's generic shape
//!    for an error is a **bare status with an empty body**; the one sanctioned
//!    distinct signal is `429` + `Retry-After`, and the one structured-but-
//!    constant body is `403 {"code":"direct_disabled"}` — all asserted to leak
//!    nothing. To make the proof load-bearing, the injected store fault embeds
//!    *every* forbidden token in its `detail`/`context`; the test then asserts
//!    that token set never reaches the wire (it only ever hits `log_internal`).
//!
//! 2. **No existence oracle.** An UNKNOWN resource and a KNOWN-but-unauthorized
//!    one return an INDISTINGUISHABLE status+body on the directory/file/recipients
//!    /chunk routes (api.md §8.5 "404 no-oracle"), so a `file_id`/username a
//!    caller cannot access is byte-for-byte the same as a missing one.
//!
//! The suite reuses the `FaultyStore` pattern (a [`Store`] whose methods return
//! `Err(StoreError)`) to force 500s, building the stack via the public API exactly
//! as `http.rs`'s in-crate tests do.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::{Extension, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::json;
use tower::ServiceExt; // oneshot

use maxsecu_admin_core::DirectorySigner;
use maxsecu_crypto::{sha256, SigningKey};
use maxsecu_encoding::encode;
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{
    AuthProofContext, DirBinding, Genesis, Manifest, Revocation, Stream,
};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileScope, FileType, Id, Role, RoleSet, StreamType, Suite, Text,
    Timestamp,
};
use maxsecu_server::{
    router, AddWrapError, AppState, AuthConfig, AuthService, ControlAppendError, DeleteWrapError,
    DiscardError, FileListEntry, FileView, FinalizeError, ListFilter, MemoryBlobStore, MemoryStore,
    NullAuditSink, ParsedStage, PendingUser, RecipientView, SessionRecord, StageError, Store,
    StoreError, StoredBinding, StoredControlRecord, TlsExporter, UserRecord, VersionMeta,
    VersionSelector, WrapInput,
};

const EXPORTER: [u8; 32] = [0xE7; 32];
const ADMIN_ID: [u8; 16] = [0xAD; 16];
const BOB_ID: [u8; 16] = [0xB0; 16];

/// A single string carrying **every** kind of internal detail the server must
/// never surface — SQL/driver text, a filesystem path (both separators), source
/// extensions/dirs, and panic/backtrace markers. It is fed into the injected
/// `StoreError` so that, if any handler ever echoed an error into a body, the
/// substring scan below would catch it.
const LEAK_BAIT: &str = "sqlx error: SELECT secret FROM relation users column ssn WHERE id=1; \
     postgres backend at /mnt/data/maxsecu.db src\\store.rs crates/server panic \
     backtrace RUST_BACKTRACE=1 thread 'main' line 42";

/// Substrings (matched case-insensitively) that must never appear in any error
/// body: path fragments, SQL/driver text, the `StoreError` detail/context tags,
/// and panic/backtrace/thread-line markers.
const FORBIDDEN: &[&str] = &[
    "\\",
    "/mnt/",
    ".rs",
    "crates",
    "sqlx",
    "select",
    "column",
    "relation",
    "postgres",
    "panic",
    "backtrace",
    "rust_backtrace",
    "thread '",
    "line 42",
    // The injected StoreError detail/context tags themselves.
    "injected",
    "store error",
    "secret",
    "ssn",
    // Faulty-store op tags (StoreError.context) — must stay server-side.
    "get_file",
    "list_files",
    "insert_nonce",
    "consume_voucher",
];

// ---- A backend that faults on every call (forces 500 on any path) ----

fn bait(op: &'static str) -> StoreError {
    StoreError::new(op, LEAK_BAIT)
}

struct FaultyStore;

#[async_trait]
impl Store for FaultyStore {
    async fn create_user(
        &self,
        _u: &str,
        _e: [u8; 32],
        _s: [u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        Err(bait("create_user"))
    }
    async fn consume_voucher(&self, _h: &[u8; 32]) -> Result<bool, StoreError> {
        Err(bait("consume_voucher"))
    }
    async fn user_by_name(&self, _u: &str) -> Result<Option<UserRecord>, StoreError> {
        Err(bait("user_by_name"))
    }
    async fn insert_nonce(&self, _n: [u8; 32], _u: &str, _e: u64) -> Result<(), StoreError> {
        Err(bait("insert_nonce"))
    }
    async fn outstanding_nonces(&self, _u: &str, _n: u64) -> Result<Vec<[u8; 32]>, StoreError> {
        Err(bait("outstanding_nonces"))
    }
    async fn consume_nonce(&self, _n: &[u8; 32]) -> Result<(), StoreError> {
        Err(bait("consume_nonce"))
    }
    async fn insert_session(&self, _t: [u8; 32], _r: SessionRecord) -> Result<(), StoreError> {
        Err(bait("insert_session"))
    }
    async fn get_session(&self, _t: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError> {
        Err(bait("get_session"))
    }
    async fn revoke_session(&self, _t: &[u8; 32]) -> Result<(), StoreError> {
        Err(bait("revoke_session"))
    }
    async fn put_binding(
        &self,
        _u: [u8; 16],
        _k: u64,
        _b: Vec<u8>,
        _s: [u8; 64],
    ) -> Result<(), StoreError> {
        Err(bait("put_binding"))
    }
    async fn binding_by_username(&self, _u: &str) -> Result<Option<StoredBinding>, StoreError> {
        Err(bait("binding_by_username"))
    }
    async fn binding_by_user_id(&self, _u: &[u8; 16]) -> Result<Option<StoredBinding>, StoreError> {
        Err(bait("binding_by_user_id"))
    }
    async fn has_any_binding(&self) -> Result<bool, StoreError> {
        Err(bait("has_any_binding"))
    }
    async fn list_pending_users(&self) -> Result<Vec<PendingUser>, StoreError> {
        Err(bait("list_pending_users"))
    }
    async fn issue_voucher(&self, _h: [u8; 32], _i: [u8; 16], _e: u64) -> Result<(), StoreError> {
        Err(bait("issue_voucher"))
    }
    async fn issue_registration_key(&self, _h: [u8; 32], _e: u64) -> Result<(), StoreError> {
        Err(bait("issue_registration_key"))
    }
    async fn consume_registration_key(&self, _h: &[u8; 32]) -> Result<bool, StoreError> {
        Err(bait("consume_registration_key"))
    }
    async fn any_user_exists(&self) -> Result<bool, StoreError> {
        Err(bait("any_user_exists"))
    }
    async fn append_control(
        &self,
        _r: Vec<u8>,
        _s: [u8; 64],
        _c: Option<[u8; 64]>,
    ) -> Result<[u8; 32], ControlAppendError> {
        Err(ControlAppendError::Store(bait("append_control")))
    }
    async fn control_records(&self) -> Result<Vec<StoredControlRecord>, StoreError> {
        Err(bait("control_records"))
    }
    async fn control_head(&self) -> Result<[u8; 32], StoreError> {
        Err(bait("control_head"))
    }
    async fn stage_version(&self, _p: ParsedStage, _n: u64) -> Result<u64, StageError> {
        Err(StageError::Store(bait("stage_version")))
    }
    async fn finalize_version(
        &self,
        _f: [u8; 16],
        _v: u64,
        _c: [u8; 16],
        _n: u64,
    ) -> Result<(), FinalizeError> {
        Err(FinalizeError::Store(bait("finalize_version")))
    }
    async fn get_file(
        &self,
        _f: [u8; 16],
        _s: VersionSelector,
        _c: [u8; 16],
    ) -> Result<Option<FileView>, StoreError> {
        Err(bait("get_file"))
    }
    async fn list_files(&self, _f: ListFilter) -> Result<Vec<FileListEntry>, StoreError> {
        Err(bait("list_files"))
    }
    async fn version_meta(
        &self,
        _f: [u8; 16],
        _v: u64,
    ) -> Result<Option<VersionMeta>, StoreError> {
        Err(bait("version_meta"))
    }
    async fn add_wrap(
        &self,
        _f: [u8; 16],
        _w: WrapInput,
        _c: [u8; 16],
        _n: u64,
    ) -> Result<(), AddWrapError> {
        Err(AddWrapError::Store(bait("add_wrap")))
    }
    async fn delete_wrap(
        &self,
        _f: [u8; 16],
        _r: [u8; 16],
        _c: [u8; 16],
    ) -> Result<(), DeleteWrapError> {
        Err(DeleteWrapError::Store(bait("delete_wrap")))
    }
    async fn list_recipients(
        &self,
        _f: [u8; 16],
        _c: [u8; 16],
    ) -> Result<Option<Vec<RecipientView>>, StoreError> {
        Err(bait("list_recipients"))
    }
    async fn discard_unfinalized(
        &self,
        _file_id: [u8; 16],
        _caller_id: [u8; 16],
    ) -> Result<Vec<String>, DiscardError> {
        Err(DiscardError::Store(bait("discard_unfinalized")))
    }
}

/// A backend that authenticates normally (delegates auth/session to an inner
/// [`MemoryStore`]) but faults on every **file-record** method — so a request can
/// log in and reach a file handler whose own `internal_error` mapping is then
/// exercised (proving the handler-level 500 is bare, not just the auth-extractor).
struct FileFaultyStore {
    inner: MemoryStore,
}

#[async_trait]
impl Store for FileFaultyStore {
    // --- delegated auth/session/directory/control (login must succeed) ---
    async fn create_user(
        &self,
        u: &str,
        e: [u8; 32],
        s: [u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        self.inner.create_user(u, e, s).await
    }
    async fn consume_voucher(&self, h: &[u8; 32]) -> Result<bool, StoreError> {
        self.inner.consume_voucher(h).await
    }
    async fn user_by_name(&self, u: &str) -> Result<Option<UserRecord>, StoreError> {
        self.inner.user_by_name(u).await
    }
    async fn insert_nonce(&self, n: [u8; 32], u: &str, e: u64) -> Result<(), StoreError> {
        self.inner.insert_nonce(n, u, e).await
    }
    async fn outstanding_nonces(&self, u: &str, n: u64) -> Result<Vec<[u8; 32]>, StoreError> {
        self.inner.outstanding_nonces(u, n).await
    }
    async fn consume_nonce(&self, n: &[u8; 32]) -> Result<(), StoreError> {
        self.inner.consume_nonce(n).await
    }
    async fn insert_session(&self, t: [u8; 32], r: SessionRecord) -> Result<(), StoreError> {
        self.inner.insert_session(t, r).await
    }
    async fn get_session(&self, t: &[u8; 32]) -> Result<Option<SessionRecord>, StoreError> {
        self.inner.get_session(t).await
    }
    async fn revoke_session(&self, t: &[u8; 32]) -> Result<(), StoreError> {
        self.inner.revoke_session(t).await
    }
    async fn put_binding(
        &self,
        u: [u8; 16],
        k: u64,
        b: Vec<u8>,
        s: [u8; 64],
    ) -> Result<(), StoreError> {
        self.inner.put_binding(u, k, b, s).await
    }
    async fn binding_by_username(&self, u: &str) -> Result<Option<StoredBinding>, StoreError> {
        self.inner.binding_by_username(u).await
    }
    async fn binding_by_user_id(&self, u: &[u8; 16]) -> Result<Option<StoredBinding>, StoreError> {
        self.inner.binding_by_user_id(u).await
    }
    async fn has_any_binding(&self) -> Result<bool, StoreError> {
        self.inner.has_any_binding().await
    }
    async fn list_pending_users(&self) -> Result<Vec<PendingUser>, StoreError> {
        self.inner.list_pending_users().await
    }
    async fn issue_voucher(&self, h: [u8; 32], i: [u8; 16], e: u64) -> Result<(), StoreError> {
        self.inner.issue_voucher(h, i, e).await
    }
    async fn issue_registration_key(&self, h: [u8; 32], e: u64) -> Result<(), StoreError> {
        self.inner.issue_registration_key(h, e).await
    }
    async fn consume_registration_key(&self, h: &[u8; 32]) -> Result<bool, StoreError> {
        self.inner.consume_registration_key(h).await
    }
    async fn any_user_exists(&self) -> Result<bool, StoreError> {
        self.inner.any_user_exists().await
    }
    async fn control_head(&self) -> Result<[u8; 32], StoreError> {
        self.inner.control_head().await
    }
    // --- faulted file-record methods (→ handler internal_error → bare 500) ---
    async fn append_control(
        &self,
        _r: Vec<u8>,
        _s: [u8; 64],
        _c: Option<[u8; 64]>,
    ) -> Result<[u8; 32], ControlAppendError> {
        Err(ControlAppendError::Store(bait("append_control")))
    }
    async fn control_records(&self) -> Result<Vec<StoredControlRecord>, StoreError> {
        Err(bait("control_records"))
    }
    async fn stage_version(&self, _p: ParsedStage, _n: u64) -> Result<u64, StageError> {
        Err(StageError::Store(bait("stage_version")))
    }
    async fn finalize_version(
        &self,
        _f: [u8; 16],
        _v: u64,
        _c: [u8; 16],
        _n: u64,
    ) -> Result<(), FinalizeError> {
        Err(FinalizeError::Store(bait("finalize_version")))
    }
    async fn get_file(
        &self,
        _f: [u8; 16],
        _s: VersionSelector,
        _c: [u8; 16],
    ) -> Result<Option<FileView>, StoreError> {
        Err(bait("get_file"))
    }
    async fn list_files(&self, _f: ListFilter) -> Result<Vec<FileListEntry>, StoreError> {
        Err(bait("list_files"))
    }
    async fn version_meta(
        &self,
        _f: [u8; 16],
        _v: u64,
    ) -> Result<Option<VersionMeta>, StoreError> {
        Err(bait("version_meta"))
    }
    async fn add_wrap(
        &self,
        _f: [u8; 16],
        _w: WrapInput,
        _c: [u8; 16],
        _n: u64,
    ) -> Result<(), AddWrapError> {
        Err(AddWrapError::Store(bait("add_wrap")))
    }
    async fn delete_wrap(
        &self,
        _f: [u8; 16],
        _r: [u8; 16],
        _c: [u8; 16],
    ) -> Result<(), DeleteWrapError> {
        Err(DeleteWrapError::Store(bait("delete_wrap")))
    }
    async fn list_recipients(
        &self,
        _f: [u8; 16],
        _c: [u8; 16],
    ) -> Result<Option<Vec<RecipientView>>, StoreError> {
        Err(bait("list_recipients"))
    }
    async fn discard_unfinalized(
        &self,
        _file_id: [u8; 16],
        _caller_id: [u8; 16],
    ) -> Result<Vec<String>, DiscardError> {
        Err(DiscardError::Store(bait("discard_unfinalized")))
    }
}

// ---- harness ----

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn b64_fixed32(s: &str) -> [u8; 32] {
    B64.decode(s).unwrap().try_into().unwrap()
}

fn state_router<S: Store + 'static>(store: S) -> Router {
    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    router(state).layer(Extension(TlsExporter(EXPORTER)))
}

/// Like [`state_router`] but with a caller-supplied [`AuthConfig`] — needed to
/// exercise the Phase-2 endpoints whose handlers gate on a pinned D5 directory
/// key (`with_directory_pub`) or a configured bootstrap secret
/// (`with_bootstrap_secret_hash`).
fn router_with_config<S: Store + 'static>(store: S, cfg: AuthConfig) -> Router {
    let state = AppState {
        auth: Arc::new(AuthService::new(store, cfg)),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    router(state).layer(Extension(TlsExporter(EXPORTER)))
}

/// A `MemoryStore`-backed app with admin (role Admin) + bob (plain), both with a
/// `sig_pub` whose private half is returned for login.
async fn app() -> (Router, SigningKey, SigningKey) {
    let store = MemoryStore::new();
    let admin = SigningKey::generate();
    store.add_user(
        "admin",
        UserRecord {
            user_id: ADMIN_ID,
            enc_pub: [0xE1; 32],
            sig_pub: admin.verifying_key().to_bytes(),
        },
    );
    // Admin authority via a D5-signed {User, Admin} binding (D-K), verified by the
    // server's AdminSession gate — not the advisory roles table.
    let d5 = DirectorySigner::generate();
    let admin_binding = DirBinding {
        username: Text::new("admin").unwrap(),
        user_id: Id(ADMIN_ID),
        enc_pub: Bytes32([0xE1; 32]),
        sig_pub: Bytes32(admin.verifying_key().to_bytes()),
        key_version: 1,
        roles: RoleSet::new([Role::User, Role::Admin]),
        not_before: Timestamp(0),
        not_after: Timestamp(4_102_444_800_000),
        mlkem_pub: None,
    };
    let signed = d5.sign_binding(&admin_binding, None);
    store
        .put_binding(ADMIN_ID, 1, encode(&signed.binding), signed.signature)
        .await
        .unwrap();
    let bob = SigningKey::generate();
    store.add_user(
        "bob",
        UserRecord {
            user_id: BOB_ID,
            enc_pub: [0xE2; 32],
            sig_pub: bob.verifying_key().to_bytes(),
        },
    );
    let state = AppState {
        auth: Arc::new(AuthService::new(
            store,
            AuthConfig::default().with_directory_pub(d5.public_key()),
        )),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    let router = router(state).layer(Extension(TlsExporter(EXPORTER)));
    (router, admin, bob)
}

fn req_json(method: &str, uri: &str, body: &serde_json::Value, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header(AUTHORIZATION, format!("MaxSecu-Session {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn req_get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        b = b.header(AUTHORIZATION, format!("MaxSecu-Session {t}"));
    }
    b.body(Body::empty()).unwrap()
}

fn req_put_bytes(uri: &str, bytes: Vec<u8>, token: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
        .body(Body::from(bytes))
        .unwrap()
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 21)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn make_proof(sk: &SigningKey, server_id: &str, nonce: &[u8; 32], ts: u64) -> String {
    let ctx = AuthProofContext {
        server_id: Text::new(server_id).unwrap(),
        tls_exporter: Bytes32(EXPORTER),
        nonce: Bytes32(*nonce),
        timestamp: Timestamp(ts),
    };
    B64.encode(sk.sign_canonical(labels::AUTH, &ctx))
}

async fn login(router: &Router, username: &str, sk: &SigningKey) -> String {
    let (_s, _h, body) = send(
        router,
        req_json("POST", "/v1/session/challenge", &json!({ "username": username }), None),
    )
    .await;
    let ch: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let nonce = b64_fixed32(ch["nonce_b64"].as_str().unwrap());
    let server_id = ch["server_id"].as_str().unwrap();
    let ts = 1_719_500_000_000u64;
    let proof = make_proof(sk, server_id, &nonce, ts);
    let (_s, _h, body) = send(
        router,
        req_json(
            "POST",
            "/v1/session/proof",
            &json!({ "username": username, "timestamp": ts, "proof_b64": proof }),
            None,
        ),
    )
    .await;
    let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
    res["session_token"].as_str().unwrap().to_owned()
}

// --- file fixtures (mirror http.rs's in-crate tests; sigs are placeholders) ---

fn manifest_b64(file: [u8; 16], version: u64, author: [u8; 16]) -> String {
    let m = Manifest {
        file_id: Id(file),
        version,
        file_type: FileType::Blog,
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
        created_at: Timestamp(1_719_500_000_000 + version),
    };
    B64.encode(maxsecu_encoding::encode(&m))
}

fn genesis_b64(file: [u8; 16], owner: [u8; 16]) -> String {
    B64.encode(maxsecu_encoding::encode(&Genesis {
        file_id: Id(file),
        owner_id: Id(owner),
        owner_key_version: 1,
        created_at: Timestamp(1_719_500_000_000),
    }))
}

fn wraps_json(owner: [u8; 16]) -> serde_json::Value {
    json!([
        { "recipient_id": hex(&owner), "recipient_type": "user",
          "wrapped_dek_b64": B64.encode([0xA1u8; 48]), "wrap_alg": 1,
          "granted_by": hex(&owner), "grant_b64": B64.encode([0xB1u8; 8]),
          "grant_sig_b64": B64.encode([0xC1u8; 64]) },
        { "recipient_id": "recovery", "recipient_type": "recovery",
          "wrapped_dek_b64": B64.encode([0xA2u8; 48]), "wrap_alg": 1,
          "granted_by": hex(&owner), "grant_b64": B64.encode([0xB2u8; 8]),
          "grant_sig_b64": B64.encode([0xC2u8; 64]) },
    ])
}

fn create_file_body(file: [u8; 16], owner: [u8; 16]) -> serde_json::Value {
    json!({
        "file_id": hex(&file),
        "file_type": "blog",
        "genesis_b64": genesis_b64(file, owner),
        "genesis_sig_b64": B64.encode([0x9Au8; 64]),
        "manifest_b64": manifest_b64(file, 1, owner),
        "manifest_sig_b64": B64.encode([0x9Bu8; 64]),
        "streams": [ {"stream_type":"content","chunk_count":2,"chunk_size":1048576,"total_bytes":2000000},
                     {"stream_type":"metadata","chunk_count":1,"chunk_size":1048576,"total_bytes":256} ],
        "wraps": wraps_json(owner),
    })
}

fn chunk_uri(file: [u8; 16], version: u64, stream: &str, index: u64) -> String {
    format!(
        "/v1/files/{}/versions/{version}/streams/{stream}/chunks/{index}",
        hex(&file)
    )
}

/// Stage + upload declared chunks + finalize a v1 blog owned by admin.
async fn create_finalize_v1(router: &Router, file: [u8; 16], token: &str) {
    let (st, _, _) = send(
        router,
        req_json("POST", "/v1/files", &create_file_body(file, ADMIN_ID), Some(token)),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    for (stream, idx, n) in [("content", 0, 32), ("content", 1, 32), ("metadata", 0, 16)] {
        let (st, _, _) = send(
            router,
            req_put_bytes(&chunk_uri(file, 1, stream, idx), vec![0x10; n], token),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, _, _) = send(
        router,
        req_json(
            "POST",
            &format!("/v1/files/{}/versions/1/finalize", hex(&file)),
            &json!({}),
            Some(token),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

fn revocation_b64(prev_head: [u8; 32], epoch: u64, victim: u8) -> serde_json::Value {
    let rec = Revocation {
        scope: FileScope::Specific(Id([0x0A; 16])),
        revoked_user_id: Id([victim; 16]),
        revoked_capability: None,
        from_version: 1,
        revocation_epoch: epoch,
        prev_head: Bytes32(prev_head),
        issued_by: Id(ADMIN_ID),
        co_signed_by: None,
        created_at: Timestamp(1_719_500_000_000),
    };
    json!({
        "record_b64": B64.encode(maxsecu_encoding::encode(&rec)),
        "sig_b64": B64.encode([0xCC; 64]),
    })
}

// ---- assertions ----

fn assert_no_leak(label: &str, body: &[u8]) {
    let hay = String::from_utf8_lossy(body).to_ascii_lowercase();
    for needle in FORBIDDEN {
        assert!(
            !hay.contains(&needle.to_ascii_lowercase()),
            "{label}: error body leaked forbidden substring {needle:?} — body: {hay:?}"
        );
    }
}

/// The generic error shape this server emits is a bare status with an EMPTY body.
fn assert_generic(label: &str, body: &[u8]) {
    assert!(
        body.is_empty(),
        "{label}: expected the generic (empty-body) error shape, got: {:?}",
        String::from_utf8_lossy(body)
    );
    assert_no_leak(label, body);
}

#[tokio::test]
async fn error_responses_never_leak_internals() {
    // ===== 500 on an AUTH path (store fault → bare generic 500) =====
    let faulty = state_router(FaultyStore);
    // challenge → insert_nonce faults
    let (st, _, body) = send(
        &faulty,
        req_json("POST", "/v1/session/challenge", &json!({ "username": "alice" }), None),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_generic("500 challenge", &body);
    // register → consume_voucher faults
    let sk = SigningKey::generate();
    let (st, _, body) = send(
        &faulty,
        req_json(
            "POST",
            "/v1/users",
            &json!({
                "username": "x",
                "enc_pub_b64": B64.encode([0x11; 32]),
                "sig_pub_b64": B64.encode(sk.verifying_key().to_bytes()),
                "enrollment_voucher": "code",
            }),
            None,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_generic("500 register", &body);
    // An authenticated file route over the all-faulty store 500s at the
    // session-extractor (get_session faults) — still bare.
    let (st, _, body) = send(
        &faulty,
        req_get(&format!("/v1/files/{}", hex(&[0xF1; 16])), Some(&hex(&[0x01; 32]))),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_generic("500 file-route auth-extractor", &body);

    // ===== 500 on a FILE handler path (auth OK, file op faults) =====
    let inner = MemoryStore::new();
    let admin_sk = SigningKey::generate();
    inner.add_user(
        "admin",
        UserRecord {
            user_id: ADMIN_ID,
            enc_pub: [0xE1; 32],
            sig_pub: admin_sk.verifying_key().to_bytes(),
        },
    );
    let file_faulty = state_router(FileFaultyStore { inner });
    let ftoken = login(&file_faulty, "admin", &admin_sk).await;
    // get_file faults inside the handler → internal_error → bare 500
    let (st, _, body) = send(
        &file_faulty,
        req_get(&format!("/v1/files/{}", hex(&[0xF1; 16])), Some(&ftoken)),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_generic("500 get_file handler", &body);
    // list_files faults inside the handler → bare 500
    let (st, _, body) = send(&file_faulty, req_get("/v1/files", Some(&ftoken))).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_generic("500 list_files handler", &body);

    // ===== the MemoryStore-backed app for the 4xx paths =====
    let (router, admin, bob) = app().await;
    let admin_tok = login(&router, "admin", &admin).await;
    let bob_tok = login(&router, "bob", &bob).await;

    // ----- 400 malformed body -----
    // bad base64 proof
    let (st, _, body) = send(
        &router,
        req_json(
            "POST",
            "/v1/session/proof",
            &json!({ "username": "admin", "timestamp": 1u64, "proof_b64": "!!!not-base64!!!" }),
            None,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_generic("400 bad proof base64", &body);
    // bad hex user_id on the directory-by-id route
    let (st, _, body) = send(&router, req_get("/v1/directory/by-id/NOT-HEX", None)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_generic("400 bad hex user_id", &body);
    // bad hex file_id on a file create
    let mut bad = create_file_body([0xF5; 16], ADMIN_ID);
    bad["file_id"] = json!("zz");
    let (st, _, body) = send(&router, req_json("POST", "/v1/files", &bad, Some(&admin_tok))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_generic("400 bad hex file_id", &body);

    // ----- 404 absent (file + directory) -----
    let (st, _, body) = send(&router, req_get("/v1/directory/ghost", None)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_generic("404 unknown directory username", &body);
    let (st, _, body) = send(
        &router,
        req_get(&format!("/v1/files/{}", hex(&[0xDE; 16])), Some(&bob_tok)),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_generic("404 unknown file", &body);

    // ----- 403 non-admin control append -----
    let (st, _, body) = send(
        &router,
        req_json("POST", "/v1/revocations", &revocation_b64([0u8; 32], 1, 0x99), Some(&bob_tok)),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_generic("403 non-admin control append", &body);

    // ----- 403 non-owner action (chunk PUT by non-owner) -----
    let file = [0xF2; 16];
    let (st, _, _) = send(
        &router,
        req_json("POST", "/v1/files", &create_file_body(file, ADMIN_ID), Some(&admin_tok)),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _, body) = send(
        &router,
        req_put_bytes(&chunk_uri(file, 1, "content", 0), vec![0x10; 32], &bob_tok),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_generic("403 non-owner chunk PUT", &body);

    // ----- 409 conflict (stale control append) -----
    let (st, _, _) = send(
        &router,
        req_json("POST", "/v1/revocations", &revocation_b64([0u8; 32], 1, 0x11), Some(&admin_tok)),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _, body) = send(
        &router,
        req_json("POST", "/v1/revocations", &revocation_b64([0u8; 32], 2, 0x12), Some(&admin_tok)),
    )
    .await; // prev_head=GENESIS again, but the head has moved → Conflict
    assert_eq!(st, StatusCode::CONFLICT);
    assert_generic("409 stale control append", &body);

    // ----- 413 payload too large (chunk index past the framing) -----
    let (st, _, body) = send(
        &router,
        req_put_bytes(&chunk_uri(file, 1, "content", 99), vec![0x10; 32], &admin_tok),
    )
    .await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    assert_generic("413 chunk index past framing", &body);

    // ----- 429 rate-limited (the one distinct shape: 429 + Retry-After) -----
    let (rl, admin2, _bob) = app().await;
    for i in 0..30 {
        let (st, _, _) = send(
            &rl,
            req_json("POST", "/v1/session/challenge", &json!({ "username": "admin" }), None),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "challenge #{i}");
    }
    let (st, headers, body) = send(
        &rl,
        req_json("POST", "/v1/session/challenge", &json!({ "username": "admin" }), None),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        headers.get(RETRY_AFTER).is_some(),
        "429 must carry Retry-After (the sanctioned distinct signal)"
    );
    // The Retry-After value is a bare integer second-count — no internals.
    assert!(headers[RETRY_AFTER]
        .to_str()
        .unwrap()
        .chars()
        .all(|c| c.is_ascii_digit()));
    assert_no_leak("429 rate-limited body", &body);
    let _ = admin2;

    // ----- the one structured-but-constant error body: 403 direct_disabled -----
    let (st, _, body) = send(
        &router,
        req_json(
            "POST",
            &format!("{}/direct-link", chunk_uri(file, 1, "content", 0)),
            &json!({}),
            Some(&admin_tok),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v, json!({ "code": "direct_disabled" }));
    assert_no_leak("403 direct_disabled body", &body);
}

#[tokio::test]
async fn no_existence_oracle() {
    let (router, admin, bob) = app().await;
    let admin_tok = login(&router, "admin", &admin).await;
    let bob_tok = login(&router, "bob", &bob).await;

    // A KNOWN, finalized file owned by admin; bob holds no wrap for it.
    let known = [0xF7; 16];
    create_finalize_v1(&router, known, &admin_tok).await;
    let unknown = [0xEE; 16];

    // --- directory: unknown username vs a known user with no signed binding ---
    // (bob is enrolled but never ceremony-signed → binding is None → 404, exactly
    // as for a wholly unknown username. admin DOES carry a D5 binding now, since
    // that is how admin authority is conferred — so bob is the unsigned probe.)
    let (us, _, ub) = send(&router, req_get("/v1/directory/ghost", None)).await;
    let (ks, _, kb) = send(&router, req_get("/v1/directory/bob", None)).await;
    assert_eq!(us, StatusCode::NOT_FOUND);
    assert_eq!((us, &ub), (ks, &kb), "directory: unknown vs unsigned must match");
    assert_generic("directory no-oracle", &ub);

    // --- file get-wrap route: unknown file vs known-but-unauthorized ---
    let (us, _, ub) = send(
        &router,
        req_get(&format!("/v1/files/{}", hex(&unknown)), Some(&bob_tok)),
    )
    .await;
    let (ks, _, kb) = send(
        &router,
        req_get(&format!("/v1/files/{}", hex(&known)), Some(&bob_tok)),
    )
    .await;
    assert_eq!(us, StatusCode::NOT_FOUND);
    assert_eq!((us, &ub), (ks, &kb), "get_file: unknown vs unauthorized must match");
    assert_generic("get_file no-oracle", &ub);

    // --- recipients route (owner-only): unknown vs known-non-owner ---
    let (us, _, ub) = send(
        &router,
        req_get(&format!("/v1/files/{}/recipients", hex(&unknown)), Some(&bob_tok)),
    )
    .await;
    let (ks, _, kb) = send(
        &router,
        req_get(&format!("/v1/files/{}/recipients", hex(&known)), Some(&bob_tok)),
    )
    .await;
    assert_eq!(us, StatusCode::NOT_FOUND);
    assert_eq!((us, &ub), (ks, &kb), "recipients: unknown vs non-owner must match");
    assert_generic("recipients no-oracle", &ub);

    // --- chunk download: unknown file vs known-but-unauthorized ---
    let (us, _, ub) = send(
        &router,
        req_get(&chunk_uri(unknown, 1, "content", 0), Some(&bob_tok)),
    )
    .await;
    let (ks, _, kb) = send(
        &router,
        req_get(&chunk_uri(known, 1, "content", 0), Some(&bob_tok)),
    )
    .await;
    assert_eq!(us, StatusCode::NOT_FOUND);
    assert_eq!((us, &ub), (ks, &kb), "chunk get: unknown vs unauthorized must match");
    assert_generic("chunk get no-oracle", &ub);
}

// ===== Phase-2 endpoints (bootstrap / publish / pending) =====

/// `POST /v1/bootstrap` over a faulting store: the handler's gating order is
/// secret-configured? → `has_any_binding()` → secret check, so the injected
/// `has_any_binding` fault hits the `internal_error` path BEFORE the secret is
/// ever checked. A backend fault must surface as a bare `500` with an empty body
/// — never a misleading `401`/`201`/`409`.
#[tokio::test]
async fn bootstrap_backend_fault_is_bare_500() {
    let app = router_with_config(
        FaultyStore,
        AuthConfig::default().with_bootstrap_secret_hash(sha256(b"X")),
    );
    // Well-formed body with the CORRECT secret — proves the 500 comes from the
    // store fault, not from a body/secret rejection.
    let (st, _, body) = send(
        &app,
        req_json(
            "POST",
            "/v1/bootstrap",
            &json!({
                "username": "root",
                "enc_pub_b64": B64.encode([0x11; 32]),
                "sig_pub_b64": B64.encode([0x22; 32]),
                "bootstrap_secret": "X",
            }),
            None,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_generic("500 bootstrap has_any_binding fault", &body);
}

/// `GET /v1/pending` is admin-gated with no cause oracle: a request with NO
/// session is a uniform `401` (empty body); an AUTHENTIC session that lacks a
/// D5-verified admin binding is `403` (empty body). Neither carries a reason.
#[tokio::test]
async fn pending_requires_admin_no_oracle() {
    let (router, _admin, bob) = app().await;

    // No Authorization header → uniform 401, empty body (no "missing token" hint).
    let (st, _, body) = send(&router, req_get("/v1/pending", None)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_generic("401 pending no-token", &body);

    // bob is an authentic session but has no published binding ⇒ not an admin →
    // 403, empty body (no "not an admin" hint).
    let bob_tok = login(&router, "bob", &bob).await;
    let (st, _, body) = send(&router, req_get("/v1/pending", Some(&bob_tok))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_generic("403 pending non-admin", &body);
}

/// `POST /v1/directory` with a canonical binding but a forged (all-zero)
/// directory signature must be rejected `403` with an empty body — the
/// verification failure leaks no detail (not even "bad signature").
#[tokio::test]
async fn publish_binding_rejects_forged_without_detail() {
    let d5 = DirectorySigner::generate();
    let app = router_with_config(
        MemoryStore::new(),
        AuthConfig::default().with_directory_pub(d5.public_key()),
    );
    let binding = DirBinding {
        username: Text::new("mallory").unwrap(),
        user_id: Id([0x4D; 16]),
        enc_pub: Bytes32([0xE4; 32]),
        sig_pub: Bytes32([0x5F; 32]),
        key_version: 1,
        roles: RoleSet::new([Role::User]),
        not_before: Timestamp(0),
        not_after: Timestamp(4_102_444_800_000),
        mlkem_pub: None,
    };
    let (st, _, body) = send(
        &app,
        req_json(
            "POST",
            "/v1/directory",
            &json!({
                "binding_b64": B64.encode(encode(&binding)),
                "directory_signature_b64": B64.encode([0u8; 64]),
            }),
            None,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_generic("403 forged publish", &body);
}
