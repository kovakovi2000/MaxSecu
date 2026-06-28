//! MaxSecu offline ceremony / signing core (Phase 2, P2.1).
//!
//! Pure, transport-agnostic logic for the **air-gapped trust root** (DESIGN
//! §4.1): the D5 directory-signing key produces long-lived identity bindings
//! (§7.1) at the fingerprint-confirmed enrollment ceremony (§12.1), and admins
//! issue the hash-chained control-log records — revocation tombstones,
//! reinstatements, key-compromise cutoffs (§11.5/§11.5a/§11.7, §7.6).
//!
//! This crate performs **no I/O**: it builds, links, and signs records. A thin
//! binary drives it at the actual ceremony; the server (Phase 2 P2.3) merely
//! stores and serves the opaque signed bytes — it can forge none of them. The
//! external-sink anchoring of the chain head is Phase 6; here the chain is built
//! and linked, and callers carry the head forward.

#![forbid(unsafe_code)]

mod control;
mod directory;
mod recovery;
mod subtree;

pub use control::{
    ControlChain, ControlRecord, CoSign, KeyCompromiseParams, ReinstateParams, RevokeParams,
    SignedControlRecord,
};
pub use directory::{DirectorySigner, SignedBinding};
pub use recovery::{build_recovery_grant, RecoveryError, RecoveryGrantOut, RecoveryGrantParams};
pub use subtree::{revocation_subtree, GrantEdge};

use core::fmt;

/// A ceremony precondition was not met. Both variants are *refusals to sign* —
/// the offline tool fails closed rather than producing an unsafe record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyError {
    /// The binding's key-pair fingerprint did not match the value the admin
    /// confirmed in person (§12.1 / D9) — the binding is never signed.
    FingerprintMismatch,
    /// A mass/account-wide or privilege-restoring action was attempted without
    /// the mandatory second admin (dual control, §10.1 / §11.5a).
    DualControlRequired,
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CeremonyError::FingerprintMismatch => {
                write!(f, "binding fingerprint does not match the confirmed value")
            }
            CeremonyError::DualControlRequired => {
                write!(f, "operation requires a second admin co-signature")
            }
        }
    }
}

impl std::error::Error for CeremonyError {}
