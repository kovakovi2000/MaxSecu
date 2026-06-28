//! MaxSecu canonical injective binary encoding (docs/encoding-spec.md, Phase 0).
//!
//! This crate is the *single* encoder implementation in the system
//! (encoding-spec §0): the client core, the server's optional early-reject
//! path, and the air-gapped ceremony tools all link these exact bytes. Every
//! signature, digest, fingerprint, and AEAD-AAD in DESIGN.md is computed over
//! `canonical(...)` as defined here.
//!
//! The contract (encoding-spec §1) is **injective** (one value → one byte
//! string), **canonical** (one accepted byte string → one value, enforced by
//! the re-encode guard, §7 rule 5), and **fail-closed** (any deviation is a
//! hard reject).

mod error;
mod primitives;
pub mod structs;
pub mod types;

pub use error::DecodeError;
pub use primitives::{Reader, Writer};

use types::{Bytes32, Hash, Id};

// ---- Pinned encoding limits & sentinels (parameters.md §1.5) ----

/// Maximum NFC byte length of any `text` field (encoding-spec §2 / parameters §1.5).
pub const MAX_TEXT: usize = 1024;

/// The recovery recipient's id — 16 zero bytes (encoding-spec §3).
pub const RECOVERY_ID: Id = Id([0u8; 16]);

/// `prev_head` seed of the first record in the anchored control-log — 32 zero
/// bytes (encoding-spec §3 / DESIGN §7.6).
pub const GENESIS_HEAD: Hash = Bytes32([0u8; 32]);

/// Current algorithm-suite codepoint (encoding-spec §3, parameters §1.5).
pub const SUITE_V1: u16 = 0x0001;

// ---- The canonical struct trait & registry (encoding-spec §4, §5) ----

/// A top-level signed/hashed structure: a `u16 type_id` (§5) followed by its
/// fields in declared order. There is exactly one canonical byte form per value.
///
/// Only this crate implements `Canonical` (the 12 structures of §4); callers
/// use [`encode`] / [`decode`].
pub trait Canonical: Sized {
    /// The `u16` registry codepoint (encoding-spec §5).
    const TYPE_ID: u16;
    /// Emit the body (fields only — `encode` writes the `type_id`).
    fn encode_body(&self, w: &mut Writer);
    /// Decode the body (the matching `type_id` has already been consumed).
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError>;
}

/// Is `id` a defined struct codepoint? `0x0004` (write_grant, removed D29) is
/// reserved and is **not** registered — it is rejected like any unknown id
/// (encoding-spec §5, V-2/V-13).
const fn is_registered(id: u16) -> bool {
    matches!(
        id,
        0x0001
            | 0x0002
            | 0x0003
            | 0x0005
            | 0x0006
            | 0x0007
            | 0x0008
            | 0x0009
            | 0x000A
            | 0x000B
            | 0x000C
            | 0x000D
    )
}

/// Read a `type_id`-tagged struct from `r` (used at the top level and for the
/// embedded `Stream` elements of a manifest). Does **not** check for trailing
/// bytes or run the canonical guard — those are top-level concerns of [`decode`].
pub(crate) fn read_struct<T: Canonical>(r: &mut Reader) -> Result<T, DecodeError> {
    let id = r.u16()?;
    if id != T::TYPE_ID {
        return Err(if is_registered(id) {
            DecodeError::WrongTypeId {
                expected: T::TYPE_ID,
                got: id,
            }
        } else {
            DecodeError::UnknownTypeId(id)
        });
    }
    T::decode_body(r)
}

/// Encode a structure to its one canonical byte string (`type_id` ‖ body).
pub fn encode<T: Canonical>(v: &T) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(T::TYPE_ID);
    v.encode_body(&mut w);
    w.into_bytes()
}

/// Strictly decode a structure from `bytes`, enforcing every §7 rule:
/// declared-order field reads, **no trailing bytes**, and the **master
/// re-encode guard** (`encode(decode(b)) == b`) that makes canonicality
/// mechanical — so a server cannot supply bytes that verify yet decode to a
/// different value (§7 rule 6).
pub fn decode<T: Canonical>(bytes: &[u8]) -> Result<T, DecodeError> {
    let mut r = Reader::new(bytes);
    let v = read_struct::<T>(&mut r)?;
    r.finish()?; // §7 rule 2: reject trailing bytes
    if encode(&v) != bytes {
        // §7 rule 5: caught a non-canonical-but-parseable form a field rule missed.
        return Err(DecodeError::NonCanonical);
    }
    Ok(v)
}

// ---- Signing input framing & domain separation (encoding-spec §6) ----

/// The exact bytes an Ed25519 signature covers (encoding-spec §6):
/// `u32 len(label) ‖ label ‖ canonical(struct)`. The length-prefixed label
/// makes the label/struct boundary unambiguous regardless of label choice
/// (strengthens DESIGN §5's raw `"label" ‖ canonical(x)` notation).
pub fn signing_input(label: &str, canonical_bytes: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.var(label.as_bytes()); // u32 len(label) ‖ label
    w.fixed(canonical_bytes);
    w.into_bytes()
}

/// Convenience: `signing_input(label, encode(v))` for a typed structure.
pub fn signing_message<T: Canonical>(label: &str, v: &T) -> Vec<u8> {
    signing_input(label, &encode(v))
}

/// The exact bytes signed for an external-sink **anchored head**
/// (`docs/sink-interface.md` §4): the domain-framed, fixed-width
/// `chain_seq (8, big-endian) ‖ head (32)` under [`labels::SINK_HEAD`]. This is
/// the SINGLE source of truth for the head signing bytes — the client verifier
/// hashes these (the transparency-proof leaf value) and the sink signs these
/// (custodian co-signature), so the two must construct them identically.
pub fn sink_head_signing_input(chain_seq: u64, head: &[u8; 32]) -> Vec<u8> {
    let mut m = [0u8; 40];
    m[..8].copy_from_slice(&chain_seq.to_be_bytes());
    m[8..].copy_from_slice(head);
    signing_input(labels::SINK_HEAD, &m)
}

/// The exact bytes a transparency log signs for a **checkpoint**
/// (`docs/sink-interface.md` §4, RFC 6962): the domain-framed, fixed-width
/// `tree_size (8, big-endian) ‖ root (32)` under [`labels::SINK_CHECKPOINT`].
/// Mirrors [`sink_head_signing_input`] under the distinct checkpoint label.
pub fn sink_checkpoint_signing_input(tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut m = [0u8; 40];
    m[..8].copy_from_slice(&tree_size.to_be_bytes());
    m[8..].copy_from_slice(root);
    signing_input(labels::SINK_CHECKPOINT, &m)
}

/// Versioned domain-separation labels for every Ed25519 signature role
/// (DESIGN §5 / encoding-spec §6). Distinct and mutually non-prefix; combined
/// with the length-framed [`signing_input`], a signature in one role can never
/// be reinterpreted as valid in another.
pub mod labels {
    pub const DIRBINDING: &str = "MaxSecu-dirbinding-v1";
    pub const MANIFEST: &str = "MaxSecu-manifest-v1";
    pub const GRANT: &str = "MaxSecu-grant-v1";
    pub const GENESIS: &str = "MaxSecu-genesis-v1";
    pub const REVOCATION: &str = "MaxSecu-revocation-v1";
    pub const REINSTATEMENT: &str = "MaxSecu-reinstatement-v1";
    pub const KEY_COMPROMISE: &str = "MaxSecu-key-compromise-v1";
    pub const AUTH: &str = "MaxSecu-auth-v1";
    /// The external sink's anchored-head co-signature (DESIGN §7.6/§16.5,
    /// `docs/sink-interface.md` §4) — a separate-custodian attestation over
    /// `{chain_seq, head}`, a different trust domain from D5/D6 and the server.
    pub const SINK_HEAD: &str = "MaxSecu-sink-head-v1";
    /// A transparency log's signed checkpoint over `{tree_size, root}`
    /// (`docs/sink-interface.md` §4, RFC 6962). Distinct from and not a prefix
    /// of [`SINK_HEAD`]: the checkpoint attests the log *state*, while the head
    /// co-signature attests a single `{chain_seq, head}` directly.
    pub const SINK_CHECKPOINT: &str = "MaxSecu-sink-checkpoint-v1";
}
