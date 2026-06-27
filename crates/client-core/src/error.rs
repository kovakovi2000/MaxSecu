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
