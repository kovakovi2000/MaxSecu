//! MaxSecu client core (DESIGN §4.1 / §9, Phase 1).
//!
//! The trusted computing base of the native client: identity key custody, the
//! at-rest `local_key_blob`, the channel-bound login proof, and password policy.
//! Everything here is transport-agnostic and testable without a live TLS stack
//! or server — the transport layer feeds in the TLS exporter and carries the
//! opaque records this crate (and `maxsecu-crypto`/`maxsecu-encoding`) produce.

#![forbid(unsafe_code)]

mod error;

pub mod auth;
pub mod directory;
pub mod identity;
pub mod keyblob;
pub mod password;
pub mod revocation;

pub use directory::{
    AuthorizedRecipient, DirectoryVerifier, MemoryTrustStore, TrustRecord, TrustStore,
    VerifiedBinding, VerifyError,
};
pub use error::{ClientError, PasswordError};
pub use revocation::{TombstoneError, TombstoneSet};
pub use identity::Identity;

// Re-export the Argon2 profiles so callers select a calibrated profile without
// reaching into the crypto crate directly (parameters §1.1).
pub use maxsecu_crypto::{Argon2Params, ARGON2_DESKTOP_TARGET, ARGON2_FLOOR};
