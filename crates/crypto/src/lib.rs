//! MaxSecu cryptographic primitive wrappers (DESIGN.md §5, Phase 0).
//!
//! Thin, hard-to-misuse wrappers over audited RustCrypto + dalek crates,
//! mapping 1:1 to the primitives table in DESIGN §5 and wiring each to the
//! canonical encoding (`maxsecu-encoding`): HPKE `info` and AEAD `AAD` are
//! `canonical(wrap_context)` / `canonical(chunk_aad)`, and every Ed25519
//! signature covers the domain-separated, length-framed `signing_input` (§6).
//!
//! Secrets are `zeroize`d on drop; AEAD/wrap/verify failures are fail-closed.

#![forbid(unsafe_code)]

mod aead;
mod dek;
mod delegation;
mod hash;
mod hybrid;
mod kdf;
pub mod merkle;
mod pin_fp;
mod pwkdf;
mod rng;
mod sign;
mod wrap;

pub use aead::{
    open, open_chunk, open_stream, open_stream_streaming, seal, seal_chunk, seal_stream,
    seal_stream_streaming, stream_digest, SealedStream,
};
pub use dek::{fingerprint, Dek};
pub use delegation::{
    parse as parse_delegation, sign as sign_delegation, verify as verify_delegation,
    DirectoryDelegation, DELEGATION_BODY_LEN, DELEGATION_CLOCK_SKEW_SECS, DELEGATION_VERSION,
    DELEGATION_WIRE_LEN,
};
pub use hash::sha256;
pub use hybrid::{
    deserialize_hybrid_wrap, generate_hybrid_keypair, generate_mlkem_keypair,
    mlkem_public_from_seed, serialize_hybrid_wrap, unwrap_dek_hybrid, wrap_dek_hybrid,
    x25519_public_from_secret, HybridEncPublicKey, HybridEncSecretKey, HybridWrappedDek,
};
pub use kdf::hkdf_sha256_32;
pub use pin_fp::pin_fingerprint;
pub use pwkdf::{derive_key, Argon2Params, ARGON2_DESKTOP_TARGET, ARGON2_FLOOR};
pub use rng::{fill_random, random_array};
pub use sign::{SigningKey, VerifyingKey};
pub use wrap::{
    generate_enc_keypair, unwrap_dek, wrap_dek, EncPublicKey, EncSecretKey, WrappedDek,
};

use core::fmt;

/// A fail-closed cryptographic error. Carries no secret material and is safe to
/// surface as a generic rejection (DESIGN §16.2 sanitized errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD open/authentication failed — tamper, wrong key/nonce, or wrong AAD.
    Aead,
    /// HPKE decapsulation/open failed — wrong recipient key or wrong `info`/context.
    WrapOpen,
    /// Ed25519 strict verification failed.
    Signature,
    /// A public key (verifying or enc) was malformed / not a valid point.
    BadPublicKey,
    /// A recovered/unwrapped DEK did not match the manifest `dek_commit` (§12.3).
    DekCommitMismatch,
    /// A chunk-framing invariant was violated (truncation, reorder, bad index,
    /// missing `is_last`, oversized framing) — DESIGN §12.10.
    Framing(&'static str),
    /// Argon2id parameters were below the mandatory floor (parameters §1.1).
    BelowArgonFloor,
    /// Argon2id failed internally (e.g. an invalid parameter combination).
    Argon2,
    /// A byte input had an unexpected length.
    BadLength,
    /// A directory-delegation cert's signature was valid but `now` fell outside
    /// its `[valid_from, valid_until]` window (spec §4). Distinct from
    /// [`CryptoError::Signature`] so the client can tell "expired" from "invalid"
    /// and fail closed accordingly.
    DelegationExpired,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CryptoError::*;
        match self {
            Aead => write!(f, "AEAD authentication failed"),
            WrapOpen => write!(f, "HPKE unwrap failed"),
            Signature => write!(f, "signature verification failed"),
            BadPublicKey => write!(f, "malformed public key"),
            DekCommitMismatch => write!(f, "DEK does not match commitment"),
            Framing(why) => write!(f, "chunk framing violation: {why}"),
            BelowArgonFloor => write!(f, "Argon2id parameters below floor"),
            Argon2 => write!(f, "Argon2id failure"),
            BadLength => write!(f, "unexpected input length"),
            DelegationExpired => write!(f, "delegation outside its validity window"),
        }
    }
}

impl std::error::Error for CryptoError {}
