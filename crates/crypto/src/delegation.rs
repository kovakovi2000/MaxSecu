//! Directory-delegation certificate (offline-D5 ceremony, spec §4).
//!
//! The admin-held **D5 root** (offline) signs a short-lived **delegation cert**
//! that authorizes the server's **operational key** to sign directory bindings
//! within a validity window. Clients still pin the D5 public key; they insert
//! one hop — verify the delegation against the pinned D5, extract
//! `operational_pub`, then verify enrollment bindings against that — and **fail
//! closed** if the delegation is missing, tampered, wrong-signer, or expired.
//!
//! Wire/on-disk layout is a FIXED little-endian body plus a raw 64-byte
//! signature (NOT a `Canonical` struct — no `type_id`, no re-encode guard):
//!
//! ```text
//! version:         u8        = 1
//! operational_pub: [u8; 32]
//! valid_from:      u64 LE    (unix seconds)
//! valid_until:     u64 LE    (unix seconds)
//! signature:       [u8; 64]  (Ed25519 over signing_input(DIRECTORY_DELEGATION, body))
//! ```
//!
//! body = 1 + 32 + 8 + 8 = **49 bytes**; wire = body ‖ sig = **113 bytes**.

use crate::sign::{SigningKey, VerifyingKey};
use crate::CryptoError;
use maxsecu_encoding::{labels, signing_input};

/// Length of the canonical signed body (`version ‖ operational_pub ‖ valid_from
/// ‖ valid_until`), fixed little-endian: 1 + 32 + 8 + 8.
pub const DELEGATION_BODY_LEN: usize = 1 + 32 + 8 + 8;

/// Length of the full on-disk / wire cert: `body ‖ signature[64]`.
pub const DELEGATION_WIRE_LEN: usize = DELEGATION_BODY_LEN + 64;

/// The only supported delegation-cert version.
pub const DELEGATION_VERSION: u8 = 1;

/// Tolerated clock skew (seconds) between the admin PC that *signs* a delegation
/// and the internet-facing server that *verifies* it. The single source of truth
/// for the offline-D5 ceremony's skew handling:
///
/// * the client SIGNERS (ceremony + renewal) back-date `valid_from` by this amount
///   (`valid_from = now - DELEGATION_CLOCK_SKEW_SECS`) so a delegation still passes
///   the server's strict `now >= valid_from` check when the server clock trails the
///   client clock by up to this much;
/// * the server's `sane_window` tolerates a `valid_from` up to this far in the
///   *future* (the mirror direction).
///
/// `verify()` itself stays STRICT (no tolerance): the skew handling lives entirely
/// on the signing side, so the relaxed lower bound is baked into the signed bytes
/// and every verifier applies it uniformly. Back-dating has zero security cost —
/// `valid_until` (expiry) is unchanged, so the delegation is not extended, only its
/// start moves earlier; the resulting window (typ. 90d + this) stays far under any
/// sane-window cap.
pub const DELEGATION_CLOCK_SKEW_SECS: u64 = 24 * 3_600;

/// A parsed directory-delegation certificate (spec §4). The **issuer is
/// implicit** — the signature verifies against the pinned `directory_pub` (D5),
/// so no issuer field is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryDelegation {
    version: u8,
    operational_pub: [u8; 32],
    valid_from: u64,
    valid_until: u64,
    signature: [u8; 64],
}

/// Assemble the 49-byte canonical signed body (fixed LE layout).
fn body_bytes(
    operational_pub: &[u8; 32],
    valid_from: u64,
    valid_until: u64,
) -> [u8; DELEGATION_BODY_LEN] {
    let mut b = [0u8; DELEGATION_BODY_LEN];
    b[0] = DELEGATION_VERSION;
    b[1..33].copy_from_slice(operational_pub);
    b[33..41].copy_from_slice(&valid_from.to_le_bytes());
    b[41..49].copy_from_slice(&valid_until.to_le_bytes());
    b
}

impl DirectoryDelegation {
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The Ed25519 public key the server signs enrollment bindings with.
    pub fn operational_pub(&self) -> [u8; 32] {
        self.operational_pub
    }

    /// Window start (unix seconds), inclusive.
    pub fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// Window end (unix seconds), inclusive.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }

    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }

    /// The 113-byte wire form: `body ‖ signature[64]`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DELEGATION_WIRE_LEN);
        out.extend_from_slice(&body_bytes(
            &self.operational_pub,
            self.valid_from,
            self.valid_until,
        ));
        out.extend_from_slice(&self.signature);
        out
    }
}

/// Sign a fresh delegation: the D5 root authorizes `operational_pub` for the
/// window `[valid_from, valid_until]`. Returns the 113-byte wire cert
/// (`body ‖ sig`).
pub fn sign(
    d5_secret: &SigningKey,
    operational_pub: &[u8; 32],
    valid_from: u64,
    valid_until: u64,
) -> Vec<u8> {
    let body = body_bytes(operational_pub, valid_from, valid_until);
    let sig = d5_secret.sign_raw(&signing_input(labels::DIRECTORY_DELEGATION, &body));
    let mut out = Vec::with_capacity(DELEGATION_WIRE_LEN);
    out.extend_from_slice(&body);
    out.extend_from_slice(&sig);
    out
}

/// Parse the 113-byte wire form. Checks length and version only — **no**
/// signature check (use [`verify`] for that).
pub fn parse(bytes: &[u8]) -> Result<DirectoryDelegation, CryptoError> {
    if bytes.len() != DELEGATION_WIRE_LEN {
        return Err(CryptoError::BadLength);
    }
    let version = bytes[0];
    if version != DELEGATION_VERSION {
        return Err(CryptoError::BadLength);
    }
    let mut operational_pub = [0u8; 32];
    operational_pub.copy_from_slice(&bytes[1..33]);
    let mut vf = [0u8; 8];
    vf.copy_from_slice(&bytes[33..41]);
    let mut vu = [0u8; 8];
    vu.copy_from_slice(&bytes[41..49]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[49..DELEGATION_WIRE_LEN]);
    Ok(DirectoryDelegation {
        version,
        operational_pub,
        valid_from: u64::from_le_bytes(vf),
        valid_until: u64::from_le_bytes(vu),
        signature,
    })
}

/// Verify a delegation cert against the pinned D5 public key and enforce the
/// window. **Fail-closed**: the signature is verified first (strict Ed25519),
/// and a window failure returns a DISTINCT error ([`CryptoError::DelegationExpired`])
/// so the client can tell "invalid" ([`CryptoError::Signature`]/[`CryptoError::BadLength`]/
/// [`CryptoError::BadPublicKey`]) apart from "out of window".
///
/// On success returns the authorized `operational_pub`. Window bounds are
/// **inclusive**: `valid_from <= now <= valid_until`.
pub fn verify(d5_pub: &[u8; 32], bytes: &[u8], now: u64) -> Result<[u8; 32], CryptoError> {
    let cert = parse(bytes)?;
    let vk = VerifyingKey::from_bytes(d5_pub)?;
    let body = body_bytes(&cert.operational_pub, cert.valid_from, cert.valid_until);
    vk.verify_raw(
        &signing_input(labels::DIRECTORY_DELEGATION, &body),
        &cert.signature,
    )?;
    if now < cert.valid_from || now > cert.valid_until {
        return Err(CryptoError::DelegationExpired);
    }
    Ok(cert.operational_pub)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deterministic operational public key (not signed with — just carried).
    fn op_pub() -> [u8; 32] {
        SigningKey::from_seed(&[7u8; 32]).verifying_key().to_bytes()
    }

    fn d5() -> SigningKey {
        SigningKey::from_seed(&[1u8; 32])
    }

    const VF: u64 = 1_700_000_000;
    const VU: u64 = 1_700_000_000 + 90 * 86_400;

    #[test]
    fn round_trip_sign_parse_serialize_and_verify() {
        let d5 = d5();
        let op = op_pub();
        let wire = sign(&d5, &op, VF, VU);

        // parse then serialize is byte-identical.
        let cert = parse(&wire).unwrap();
        assert_eq!(cert.serialize(), wire);
        assert_eq!(cert.version(), 1);
        assert_eq!(cert.operational_pub(), op);
        assert_eq!(cert.valid_from(), VF);
        assert_eq!(cert.valid_until(), VU);

        // verify inside the window returns the exact operational_pub.
        let d5_pub = d5.verifying_key().to_bytes();
        let got = verify(&d5_pub, &wire, VF + 42).unwrap();
        assert_eq!(got, op);
    }

    #[test]
    fn lengths_are_49_and_113() {
        assert_eq!(DELEGATION_BODY_LEN, 49);
        assert_eq!(DELEGATION_WIRE_LEN, 113);
        let wire = sign(&d5(), &op_pub(), VF, VU);
        assert_eq!(wire.len(), 113);
        assert_eq!(body_bytes(&op_pub(), VF, VU).len(), 49);
    }

    #[test]
    fn window_is_inclusive_on_both_ends() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let op = op_pub();
        let wire = sign(&d5, &op, VF, VU);

        // Boundaries PASS (inclusive).
        assert_eq!(verify(&d5_pub, &wire, VF).unwrap(), op);
        assert_eq!(verify(&d5_pub, &wire, VU).unwrap(), op);

        // Just outside FAIL with the window error (not the signature error).
        assert_eq!(
            verify(&d5_pub, &wire, VF - 1),
            Err(CryptoError::DelegationExpired)
        );
        assert_eq!(
            verify(&d5_pub, &wire, VU + 1),
            Err(CryptoError::DelegationExpired)
        );
    }

    #[test]
    fn tampering_any_region_fails_verification() {
        let d5 = d5();
        let d5_pub = d5.verifying_key().to_bytes();
        let wire = sign(&d5, &op_pub(), VF, VU);

        // Representative positions across each region: version(0),
        // operational_pub(1,32), valid_from(33,40), valid_until(41,48),
        // signature(49,80,112).
        for pos in [0usize, 1, 32, 33, 40, 41, 48, 49, 80, 112] {
            let mut t = wire.clone();
            t[pos] ^= 0x01;
            let res = verify(&d5_pub, &t, VF + 1);
            assert!(
                res.is_err(),
                "flip at byte {pos} unexpectedly verified: {res:?}"
            );
        }
    }

    #[test]
    fn wrong_signer_fails_with_signature_error() {
        let a = SigningKey::from_seed(&[1u8; 32]);
        let b = SigningKey::from_seed(&[2u8; 32]);
        let wire = sign(&a, &op_pub(), VF, VU);
        let b_pub = b.verifying_key().to_bytes();
        assert_eq!(verify(&b_pub, &wire, VF + 1), Err(CryptoError::Signature));
    }

    #[test]
    fn parse_rejects_wrong_lengths() {
        assert_eq!(parse(&[]), Err(CryptoError::BadLength));
        assert_eq!(parse(&[0u8; 112]), Err(CryptoError::BadLength));
        assert_eq!(parse(&[0u8; 114]), Err(CryptoError::BadLength));
    }

    #[test]
    fn parse_rejects_bad_version() {
        let mut wire = sign(&d5(), &op_pub(), VF, VU);
        wire[0] = 2;
        assert_eq!(parse(&wire), Err(CryptoError::BadLength));
    }
}
