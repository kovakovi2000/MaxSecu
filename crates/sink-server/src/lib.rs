//! The external **sink** service core (DESIGN §7.6/§16.5,
//! `docs/sink-interface.md`).
//!
//! The app server serves the tombstone *records*; the sink independently attests
//! *what the current head is* over a channel the app operator does not control —
//! so a client that holds a sink-anchored head rejects any server-served chain
//! that is shorter, forked, or rolled back (caught by
//! `maxsecu_client_core::revocation::TombstoneSet`).
//!
//! This crate is the PURE CORE (no HTTP — a later increment wraps it): an
//! append-only [`ControlLogStore`] that recomputes the head EXACTLY as clients
//! do (mirroring `client-core::revocation`) and rejects any rewrite/reorder/
//! malformed append (§6.1), and an [`Anchorer`] that emits BOTH anchor-proof
//! forms — a separate-custodian Ed25519 co-signature and an RFC 6962
//! transparency-log inclusion proof — that `client-core::sink::verify_anchor_proof`
//! accepts. The head/checkpoint signing bytes come from the single source of
//! truth in `maxsecu-encoding`, so client and sink construct identical bytes.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod chain;

pub use anchor::{AnchorBundle, AnchorProofParts, Anchorer};
pub use chain::{AnchoredHead, AppendError, ControlLogStore};
