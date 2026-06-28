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
pub mod download;
pub mod identity;
pub mod keyblob;
pub mod limits;
pub mod password;
pub mod revocation;
pub mod upload;
pub mod version_memory;

pub use directory::{
    AuthorizedRecipient, DirectoryVerifier, MemoryTrustStore, TrustRecord, TrustStore,
    VerifiedBinding, VerifyError,
};
pub use download::{
    verify_and_open, version_acceptable, DownloadBundle, OpenedFile, OpenedStream, StreamChunks,
    VerifyContext,
};
pub use error::{ClientError, DownloadError, PasswordError, UploadError};
pub use revocation::{TombstoneError, TombstoneSet};
pub use identity::Identity;
pub use version_memory::{open_and_remember, FileVersionRecord, MemoryVersionStore, VersionStore};
pub use upload::{
    build_upload, PlaintextStreams, SealedStreamOut, UploadBundle, UploadParams, WrapOut,
};

// Re-export the Argon2 profiles so callers select a calibrated profile without
// reaching into the crypto crate directly (parameters §1.1).
pub use maxsecu_crypto::{Argon2Params, ARGON2_DESKTOP_TARGET, ARGON2_FLOOR};
