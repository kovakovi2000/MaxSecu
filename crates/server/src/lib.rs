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
pub mod files;
pub mod http;
pub mod pg;
pub mod ratelimit;
pub mod serve;
pub mod store;

pub use auth::{AuthConfig, AuthService, Challenge, SessionToken};
pub use audit::{AuditSink, GrantAction, GrantEdge, MemoryAuditSink, NullAuditSink};
pub use blob::{BlobError, BlobStore, FsBlobStore, MemoryBlobStore};
pub use error::{AuthError, ChallengeError, ControlAppendError, ProveError, StoreError};
pub use http::{router, AppState, AuthedSession, TlsExporter};
pub use pg::PgStore;
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use serve::{export_channel_binding, serve, CHANNEL_BINDING_LABEL, CHANNEL_BINDING_LEN};
pub use files::{
    parse_stage, AddWrapError, DeleteWrapError, FinalizeError, GenesisInput, ListFilter,
    ParsedStage, StageError, StageInput, VersionSelector, WrapInput,
};
pub use store::{
    ChunkSlot, FileListEntry, FileView, MemoryStore, NonceRecord, SessionRecord, StoredBinding,
    StoredControlRecord, Store, StreamView, UserRecord, VersionMeta, WrapView,
};
