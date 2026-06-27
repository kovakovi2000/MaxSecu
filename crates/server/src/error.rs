//! Server auth errors — fail-closed and **single-shape** (DESIGN §9.3 / §16.2):
//! every login failure (unknown user, bad proof, stale/missing nonce, channel
//! mismatch, expired/revoked session) surfaces the same `Unauthorized`, so the
//! API exposes no user-existence or cause oracle.
//!
//! Rate-limiting is the **one** intentionally-distinct signal: a throttled
//! request maps to HTTP `429` (with `Retry-After`), not `401`. This leaks no
//! existence/password oracle — the throttle is keyed on the *claimed* username
//! regardless of existence and is, by construction, attacker-induced state the
//! attacker already knows about (parameters.md §3 / DESIGN §9.3).

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

/// A throttle signal carrying how long the caller should wait (whole seconds).
/// Returned by challenge issuance when the per-account cap is hit (HTTP 429).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimited {
    pub retry_after_s: u64,
}

/// Outcome of a failed `prove`: either the uniform `Unauthorized` (401, no
/// oracle) or a `RateLimited` throttle (429). Success returns the token instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    Unauthorized,
    RateLimited { retry_after_s: u64 },
}
