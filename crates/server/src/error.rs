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

/// A persistence-backend failure (DB unreachable, query/decode error). Carried
/// up for **observability**: the previous *infallible* `Store` contract forced
/// `PgStore` to swallow these as fail-closed `None`/`false`, which denied access
/// *silently* and indistinguishably from a legitimate "not found"/"taken". A
/// surfaced `StoreError` lets the transport layer log it and answer `500` (a
/// *server* fault) instead of a misleading `401`/`403`/`409`.
///
/// **Not an oracle (§9.3).** A store fault is credential-independent — it occurs
/// regardless of the claimed username — so mapping it to `500` rather than the
/// uniform `401` reveals only that the server is unhealthy, which is not a
/// function of attacker input. `detail` stays server-side (logs); the HTTP layer
/// emits a bare `500` with no body, so nothing leaks to the client (§16.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    context: &'static str,
    detail: String,
}

impl StoreError {
    /// `context` is a static operation tag (e.g. `"insert_nonce"`); `detail` is
    /// the sanitized backend message (server-side only).
    pub fn new(context: &'static str, detail: impl Into<String>) -> Self {
        StoreError {
            context,
            detail: detail.into(),
        }
    }

    pub fn context(&self) -> &'static str {
        self.context
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store error [{}]: {}", self.context, self.detail)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The one and only login/session *decision* failure shape (maps to HTTP
    /// 401): unknown user, bad proof, stale nonce, channel mismatch, expired or
    /// revoked session — all indistinguishable (no oracle, §9.3).
    Unauthorized,
    /// A backend fault while resolving the request — maps to HTTP 500, never
    /// 401, so a transient DB error is observable rather than masquerading as an
    /// auth decision.
    Internal(StoreError),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Unauthorized => write!(f, "unauthorized"),
            AuthError::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Outcome of a failed `challenge`: a throttle (429) or a backend fault (500).
/// A well-formed challenge is otherwise always issued (no existence oracle, §9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeError {
    RateLimited { retry_after_s: u64 },
    Internal(StoreError),
}

/// Outcome of a failed `prove`: the uniform `Unauthorized` (401, no oracle), a
/// `RateLimited` throttle (429), or a backend `Internal` fault (500). Success
/// returns the token instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    Unauthorized,
    RateLimited { retry_after_s: u64 },
    Internal(StoreError),
}

/// Outcome of appending a control-log record (api.md §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAppendError {
    /// The record's `prev_head` did not match the current chain head — a stale
    /// or concurrent append (→ 409). The issuer must re-fetch the head and rebuild.
    Conflict,
    /// The bytes were not a canonical revocation/reinstatement/key-compromise
    /// record (→ 400).
    Malformed,
    /// A backend fault (→ 500).
    Store(StoreError),
}
