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
pub mod budget;
pub mod directory;
pub mod download;
pub mod identity;
pub mod keyblob;
pub mod limits;
pub mod media;
pub mod password;
pub mod reshare;
pub mod revocation;
pub mod rotate;
pub mod sandbox;
pub mod sanitize;
pub mod upload;
pub mod version_memory;

pub use directory::{
    AuthorizedRecipient, DirectoryVerifier, MemoryTrustStore, TrustRecord, TrustStore,
    VerifiedBinding, VerifyError,
};
pub use download::{
    verify_and_open, verify_and_stream_content, version_acceptable, DownloadBundle, OpenedFile,
    OpenedHeader, OpenedStream, StreamChunks, StreamHeader, VerifyContext, NO_GRANTERS,
};
pub use budget::{plan_unlock, AuditEvent, UnlockPlan};
pub use error::{ClientError, DownloadError, PasswordError, TranscodeError, UploadError};
pub use media::{
    CanonicalStreams, FfmpegVideo, MediaBounds, RustImageCodec, Transcoder, MEDIA_MAX_PIXELS,
    PREVIEW_MAX_DIM, THUMBNAIL_MAX_DIM,
};
pub use sandbox::{
    validate_decoded, DecodeError, DecodedImage, InProcessFakeDecoder, OutputReject,
    SandboxedDecoder,
};
pub use revocation::{TombstoneError, TombstoneSet};
pub use sanitize::{safe_export_path, sanitize_filename, SanitizeError};
pub use identity::Identity;
pub use version_memory::{open_and_remember, FileVersionRecord, MemoryVersionStore, VersionStore};
pub use upload::{
    build_upload, PlaintextStreams, SealedStreamOut, UploadBundle, UploadParams, WrapOut,
};
pub use reshare::{build_reshare, ReshareError, ReshareParams};
pub use rotate::{
    build_next_version, CarryForwardCandidate, RotateError, RotateParams, RotationBundle,
};

// Re-export the Argon2 profiles so callers select a calibrated profile without
// reaching into the crypto crate directly (parameters §1.1).
pub use maxsecu_crypto::{Argon2Params, ARGON2_DESKTOP_TARGET, ARGON2_FLOOR};
