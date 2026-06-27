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

mod error;

pub mod auth;
pub mod http;
pub mod pg;
pub mod ratelimit;
pub mod serve;
pub mod store;

pub use auth::{AuthConfig, AuthService, Challenge, SessionToken};
pub use error::{AuthError, ChallengeError, ProveError, StoreError};
pub use http::{router, AppState, AuthedSession, TlsExporter};
pub use pg::PgStore;
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use serve::{export_channel_binding, serve, CHANNEL_BINDING_LABEL, CHANNEL_BINDING_LEN};
pub use store::{MemoryStore, NonceRecord, SessionRecord, Store, UserRecord};
