//! Client-core errors. All fail-closed; none carries secret material.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The password did not unlock the `local_key_blob` (AEAD auth failed).
    WrongPassword,
    /// The `local_key_blob` is malformed (bad magic/length/structure).
    CorruptBlob,
    /// The blob's stored Argon2id params are below the mandatory floor
    /// (parameters §1.1) — refused, fail closed.
    BelowArgonFloor,
    /// The blob format version is not supported by this client.
    UnsupportedBlobVersion(u8),
    /// A password failed policy (length / breach blocklist, DESIGN §9.4).
    Password(PasswordError),
    /// A server challenge field was malformed (e.g. `server_id` too long).
    BadChallenge,
    /// A login proof failed to verify, or the `sig_pub` was malformed (§9.2).
    /// Single shape — no oracle distinguishing the cause (DESIGN §9.3).
    BadProof,
}

/// Errors building a file upload (DESIGN §12.2, Phase 3). All fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// `chunk_size` is outside the accepted framing range [4 KiB, 8 MiB]
    /// (parameters §1.2 / DESIGN §12.10) — rejected before allocation.
    ChunkSizeOutOfRange { chunk_size: u32 },
    /// A cryptographic step (HPKE wrap) failed — e.g. a malformed recipient key.
    Crypto(maxsecu_crypto::CryptoError),
    /// A freshly-built wrap did not unwrap back to the committed DEK — the
    /// author's pre-upload self-check (DESIGN §12.2 step 7 / §12.3) failed.
    WrapSelfCheckFailed,
}

impl From<maxsecu_crypto::CryptoError> for UploadError {
    fn from(e: maxsecu_crypto::CryptoError) -> Self {
        UploadError::Crypto(e)
    }
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use UploadError::*;
        match self {
            ChunkSizeOutOfRange { chunk_size } => {
                write!(f, "chunk_size {chunk_size} outside [4 KiB, 8 MiB]")
            }
            Crypto(e) => write!(f, "crypto failure: {e}"),
            WrapSelfCheckFailed => write!(f, "wrap self-check failed (does not open to the DEK)"),
        }
    }
}

impl std::error::Error for UploadError {}

/// Errors verifying & opening a downloaded file (DESIGN §12.5, Phase 3). Every
/// variant means "reject and surface a sanitized error" (§12.5 step 7) — fail
/// closed. A *missing/invalid recovery grant* is not here: per §12.5 step 5 it
/// is an anomaly flagged in [`crate::download::OpenedFile::recovery_grant_ok`],
/// not a hard rejection of the downloader's own read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadError {
    /// A signed record failed strict canonical decode (the re-encode guard) —
    /// the server supplied bytes that don't decode to one canonical value.
    BadManifest,
    BadGenesis,
    BadGrant,
    /// The author's `manifest_sig` did not verify against their directory key.
    ManifestSignature,
    /// The owner's `genesis_sig` did not verify against the owner binding.
    GenesisSignature,
    /// The recipient's read-grant signature did not verify against the granter.
    GrantSignature,
    /// `author_id != genesis.owner_id` — a non-owner authored this version
    /// (owner-only write, D29 / §12.5 author-entitlement).
    AuthorNotOwner,
    /// A record's `file_id` did not match the requested file (substitution).
    FileIdMismatch,
    /// Served `version` is older than the highest trust-on-last-use record (§7.5).
    VersionRollback { seen_max: u64, served: u64 },
    /// Served `version` exceeds the highest seen by more than 1 — rollback-memory
    /// poisoning guard (§7.5 / D23).
    VersionTooHigh { seen_max: u64, served: u64 },
    /// First contact (no prior record) and `version` exceeds the absolute sanity
    /// ceiling (parameters §4 / D23).
    FirstContactCeiling { served: u64 },
    /// The served `version` equals the highest remembered, but its content digest
    /// differs — a fork/equivocation at a reused version number (§7.5). The
    /// monotonic-by-1 rule means two distinct contents cannot share a version.
    VersionForked { version: u64 },
    /// A grant field did not match the manifest/context (file/version/recipient/
    /// dek_commit/granted_by) — the wrap is treated as absent (§12.3a).
    GrantMismatch(&'static str),
    /// The HPKE unwrap of the recipient's wrap failed (wrong key/context).
    DekUnwrap,
    /// The unwrapped DEK did not match the manifest `dek_commit` — the
    /// self-validating access proof (§12.5 step 6): a garbage wrap yields denial.
    DekCommitMismatch,
    /// A manifest-declared stream was not provided by the server.
    StreamMissing(maxsecu_encoding::types::StreamType),
    /// A stream's chunked-AEAD framing failed (tamper, truncation, reorder).
    StreamFraming(maxsecu_encoding::types::StreamType),
    /// A stream's recomputed chunk-tag digest did not match the signed manifest.
    StreamDigestMismatch(maxsecu_encoding::types::StreamType),
    /// A framing field (chunk_size / chunk_count) is out of bounds, or the served
    /// chunk count disagrees with the signed manifest — bound-checked before any
    /// allocation (§12.10).
    FramingBoundsExceeded(&'static str),
    /// A stream declared a compression the v1 client cannot yet apply (Phase 3
    /// leaves everything uncompressed; zstd is a later increment).
    CompressionUnsupported,
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DownloadError::*;
        match self {
            BadManifest => write!(f, "malformed manifest"),
            BadGenesis => write!(f, "malformed genesis"),
            BadGrant => write!(f, "malformed grant"),
            ManifestSignature => write!(f, "manifest signature verification failed"),
            GenesisSignature => write!(f, "genesis signature verification failed"),
            GrantSignature => write!(f, "grant signature verification failed"),
            AuthorNotOwner => write!(f, "author is not the file owner"),
            FileIdMismatch => write!(f, "record file_id does not match the request"),
            VersionRollback { seen_max, served } => {
                write!(f, "version rollback: served {served} < seen {seen_max}")
            }
            VersionTooHigh { seen_max, served } => {
                write!(f, "version {served} exceeds seen {seen_max} by more than 1")
            }
            FirstContactCeiling { served } => {
                write!(f, "first-contact version {served} above sanity ceiling")
            }
            VersionForked { version } => {
                write!(f, "version {version} reused with different content (fork)")
            }
            GrantMismatch(what) => write!(f, "grant mismatch: {what}"),
            DekUnwrap => write!(f, "DEK unwrap failed"),
            DekCommitMismatch => write!(f, "DEK does not match manifest commitment"),
            StreamMissing(_) => write!(f, "a manifest stream was not provided"),
            StreamFraming(_) => write!(f, "stream framing verification failed"),
            StreamDigestMismatch(_) => write!(f, "stream digest does not match manifest"),
            FramingBoundsExceeded(what) => write!(f, "framing bounds exceeded: {what}"),
            CompressionUnsupported => write!(f, "unsupported stream compression"),
        }
    }
}

impl std::error::Error for DownloadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    /// Below the minimum length (parameters §2: 15).
    TooShort { min: usize },
    /// Above the maximum length (parameters §2: 128).
    TooLong { max: usize },
    /// On the known-breached / common-password blocklist (DESIGN §9.4).
    Breached,
}

impl From<PasswordError> for ClientError {
    fn from(e: PasswordError) -> Self {
        ClientError::Password(e)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ClientError::*;
        match self {
            WrongPassword => write!(f, "incorrect password"),
            CorruptBlob => write!(f, "corrupt local key blob"),
            BelowArgonFloor => write!(f, "Argon2id params below floor"),
            UnsupportedBlobVersion(v) => write!(f, "unsupported blob version {v}"),
            Password(p) => write!(f, "password policy: {p}"),
            BadChallenge => write!(f, "malformed server challenge"),
            BadProof => write!(f, "login proof verification failed"),
        }
    }
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PasswordError::*;
        match self {
            TooShort { min } => write!(f, "too short (min {min})"),
            TooLong { max } => write!(f, "too long (max {max})"),
            Breached => write!(f, "on the breached/common-password blocklist"),
        }
    }
}

impl std::error::Error for ClientError {}
impl std::error::Error for PasswordError {}
