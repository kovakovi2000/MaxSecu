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
