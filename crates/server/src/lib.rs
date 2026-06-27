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
pub mod store;

pub use auth::{AuthConfig, AuthService, Challenge, SessionToken};
pub use error::AuthError;
pub use http::{router, AppState, AuthedSession, TlsExporter};
pub use store::{MemoryStore, NonceRecord, SessionRecord, Store, UserRecord};
