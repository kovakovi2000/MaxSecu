//! MaxSecu client core (DESIGN §4.1 / §9, Phase 1).
//!
//! The trusted computing base of the native client: identity key custody, the
//! at-rest `local_key_blob`, the channel-bound login proof, and password policy.
//! Everything here is transport-agnostic and testable without a live TLS stack
//! or server — the transport layer feeds in the TLS exporter and carries the
//! opaque records this crate (and `maxsecu-crypto`/`maxsecu-encoding`) produce.

#![forbid(unsafe_code)]

mod error;
mod util;

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
pub mod sink;
pub mod transparency;
pub mod update;
pub mod upload;
pub mod version_memory;
pub mod video;

pub use directory::{
    AuthorizedRecipient, DirectoryVerifier, MemoryTrustStore, TrustRecord, TrustStore,
    VerifiedBinding, VerifyError,
};
pub use download::{
    open_content_decryptor, verify_and_open, verify_and_open_headers, verify_and_stream_content,
    version_acceptable, CompromiseCheck, ContentDecryptor, DownloadBundle, OpenedFile,
    OpenedHeader, OpenedStream, StreamChunks, StreamHeader, VerifyContext, NO_ADMINS, NO_GRANTERS,
};
pub use budget::{plan_unlock, AuditEvent, UnlockPlan};
pub use error::{ClientError, DownloadError, PasswordError, TranscodeError, UploadError};
pub use media::{
    decode_transcode_request, decode_transcode_result, encode_transcode_request,
    encode_transcode_result, CanonicalStreams, FfmpegVideo, FragmentEntry, MediaBounds,
    RustImageCodec, Transcoder, TranscodeProtoError, TranscodeRequest, TranscodeResult,
    MAX_TRANSCODE_BYTES, MAX_TRANSCODE_FRAGMENTS, MEDIA_MAX_PIXELS, PREVIEW_MAX_DIM,
    THUMBNAIL_MAX_DIM,
};
pub use sandbox::{decode_rgba_bounded, validate_decoded, DecodeError, DecodedImage, OutputReject};
pub use revocation::{ControlRecordIn, IssuerInfo, TombstoneError, TombstoneSet};
pub use sink::{verify_anchor_proof, AnchorProof, AnchoredHead, FakeSink, SinkClient, SinkError};
#[cfg(feature = "net")]
pub use sink::{confirm_anchored, HttpSinkClient};
pub use transparency::{
    confirm_binding_logged, verify_binding_in_log, InclusionProof, KtCheckpoint, KtCheckpointStore,
    KtContext, KtError, MemoryKtCheckpointStore,
};
pub use sanitize::{safe_export_path, sanitize_filename, SanitizeError};
pub use update::{verify_update, LogInclusion, UpdateError, UpdateManifest, Verified};
pub use identity::Identity;
pub use video::VideoBounds;
pub use version_memory::{open_and_remember, FileVersionRecord, MemoryVersionStore, VersionStore};
pub use upload::{
    build_upload, resume_content_sealer, ContentStreamSealer, PlaintextStreams, SealedStreamOut,
    SmallStreams, StreamingUploadBuilder, UploadBundle, UploadParams, UploadRecords, WrapOut,
};
pub use reshare::{build_reshare, ReshareError, ReshareParams};
pub use rotate::{
    build_next_version, CarryForwardCandidate, RotateError, RotateParams, RotationBundle,
};

// Re-export the Argon2 profiles so callers select a calibrated profile without
// reaching into the crypto crate directly (parameters §1.1).
pub use maxsecu_crypto::{Argon2Params, ARGON2_DESKTOP_TARGET, ARGON2_FLOOR};
