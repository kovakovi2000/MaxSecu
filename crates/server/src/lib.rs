//! MaxSecu secret-free app server (DESIGN §4.1).
//!
//! Phase 1 ships the **auth state machine** (challenge-response with TLS-exporter
//! channel binding, §9.2) over a persistence-agnostic [`store::Store`]. The
//! server is untrusted for confidentiality/integrity and enforces only coarse
//! authorization (§4.2/§10) — every cryptographic fact is re-checked client-side.
//!
//! The HTTP (axum), DB (sqlx/Postgres), and TLS (tokio-rustls, supplying the
//! per-connection exporter) adapters wrap this core in the next increment.

#![forbid(unsafe_code)]

mod control;
mod error;

pub mod audit;
pub mod auth;
pub mod blob;
pub mod detect;
pub mod dropbox_tier;
pub mod files;
pub mod http;
// The Postgres Store lives behind the default-on `postgres` feature so the crate
// can be linked without `sqlx` by the client-side e2e crate (see Cargo.toml).
#[cfg(feature = "postgres")]
pub mod pg;
pub mod ratelimit;
mod reg_keys;
pub mod serve;
pub mod store;
pub mod tier;
pub mod writeback_tier;

pub use auth::{AuthConfig, AuthService, Challenge, SessionToken};
pub use audit::{
    AuditSink, GrantAction, GrantEdge, HttpSinkPublisher, MemoryAuditSink, NullAuditSink,
};
pub use blob::{
    BlobError, BlobStore, ChunkStatus, DirectLink, FetchSource, FsBlobStore, MemoryBlobStore,
};
pub use detect::{
    analyze, Alert, AlertSink, AuditEvent, MemoryAlertSink, NullAlertSink, Thresholds,
};
pub use dropbox_tier::{DropboxTier, HyperDropboxHttp};
pub use error::{AuthError, ChallengeError, ControlAppendError, ProveError, StoreError};
pub use http::{router, AppState, AuthedSession, TlsExporter};
#[cfg(feature = "postgres")]
pub use pg::PgStore;
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use serve::{export_channel_binding, serve, CHANNEL_BINDING_LABEL, CHANNEL_BINDING_LEN};
pub use tier::{CacheIndex, ChunkKey, ColdTier, FsColdTier, MemoryColdTier, TieredBlobStore};
pub use writeback_tier::{Clock, WriteBackTier};
pub use files::{
    parse_stage, AddWrapError, DeleteWrapError, DiscardError, FinalizeError, GenesisInput,
    ListFilter, ParsedStage, StageError, StageInput, VersionSelector, WrapInput,
};
pub use store::{
    ChunkSlot, FileListEntry, FileView, MemoryStore, NonceRecord, PendingUser, RecipientView,
    SessionRecord, StoredBinding, StoredControlRecord, Store, StreamView, UserRecord, VersionMeta,
    WrapView,
};
