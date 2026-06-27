//! Server auth errors — fail-closed and **single-shape** (DESIGN §9.3 / §16.2):
//! every login failure (unknown user, bad proof, stale/missing nonce, channel
//! mismatch, expired/revoked session) surfaces the same `Unauthorized`, so the
//! API exposes no user-existence or cause oracle.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The one and only login/session failure shape (maps to HTTP 401).
    Unauthorized,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Unauthorized => write!(f, "unauthorized"),
        }
    }
}

impl std::error::Error for AuthError {}
