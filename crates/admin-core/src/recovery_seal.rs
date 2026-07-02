//! Passphrase-sealed file for the offline recovery secret (T6, design D-B).
//!
//! A small companion to `client-core`'s `local_key_blob` (`keyblob.rs`), mirroring
//! its audited construction exactly rather than inventing new crypto: a
//! passphrase is stretched with **Argon2id** (`maxsecu_crypto::derive_key`, the
//! same KDF/params discipline as the keyblob) and the 32-byte recovery scalar is
//! sealed under **AES-256-GCM** (`maxsecu_crypto::seal`/`open`) with a fixed,
//! self-describing header authenticated as the AEAD AAD.
//!
//! The recovery secret is the [`EncSecretKey`] scalar handed out at the offline
//! ceremony (§16.3). At rest this file is **ciphertext only**: the bare scalar is
//! never present. A wrong passphrase fails closed on AEAD authentication — no
//! partial or best-effort scalar is ever returned.
//!
//! ```text
//! magic "MXRS" (4) | version u8 | argon m_kib u32 | t u32 | p u32
//!   | salt[16] | nonce[12]                 <-- 45-byte header, also the AEAD AAD
//! ciphertext = AES-256-GCM(pw_key, nonce, aad=header, scalar[32])   (32 + 16 tag)
//! ```
//!
//! `pw_key = Argon2id(passphrase, salt, params)`. The full `(m,t,p,salt)` is
//! stored with the file so a re-tuned file still opens; params below the floor
//! are refused. A fresh random `salt` + `nonce` is drawn on every seal, so the
//! AES-GCM nonce is never reused across passphrases.

use core::fmt;
use maxsecu_crypto::{self as crypto, Argon2Params, EncSecretKey};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"MXRS";
const VERSION_V1: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + 16 + 12; // 45
const SCALAR_LEN: usize = 32;
const TAG_LEN: usize = 16;
const FILE_LEN: usize = HEADER_LEN + SCALAR_LEN + TAG_LEN; // 93

/// A fail-closed error from opening a sealed recovery-secret file. Carries no
/// secret material and is safe to surface as a generic rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverySealError {
    /// Wrong passphrase or tampered ciphertext — AEAD authentication failed. No
    /// partial plaintext is ever returned (fail closed).
    WrongPassphrase,
    /// The file was truncated, had a bad magic, or a wrong length.
    CorruptFile,
    /// The file's version byte is not one this build understands.
    UnsupportedVersion(u8),
    /// The file's stored Argon2id params are below the mandatory floor.
    BelowArgonFloor,
}

impl fmt::Display for RecoverySealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoverySealError::WrongPassphrase => write!(f, "wrong passphrase or tampered file"),
            RecoverySealError::CorruptFile => write!(f, "corrupt recovery-secret file"),
            RecoverySealError::UnsupportedVersion(v) => {
                write!(f, "unsupported recovery-secret file version {v}")
            }
            RecoverySealError::BelowArgonFloor => write!(f, "Argon2id parameters below floor"),
        }
    }
}

impl std::error::Error for RecoverySealError {}

fn build_header(
    version: u8,
    params: Argon2Params,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = version;
    h[5..9].copy_from_slice(&params.m_kib.to_be_bytes());
    h[9..13].copy_from_slice(&params.t.to_be_bytes());
    h[13..17].copy_from_slice(&params.p.to_be_bytes());
    h[17..33].copy_from_slice(salt);
    h[33..45].copy_from_slice(nonce);
    h
}

/// Seal the recovery `secret` scalar under `passphrase` with `params`, producing
/// the at-rest file bytes. A fresh random salt + nonce is drawn each call.
pub fn seal_recovery_secret(
    secret: &EncSecretKey,
    passphrase: &str,
    params: Argon2Params,
) -> Result<Vec<u8>, RecoverySealError> {
    let salt: [u8; 16] = crypto::random_array();
    let nonce: [u8; 12] = crypto::random_array();
    let pw_key = crypto::derive_key(passphrase.as_bytes(), &salt, params)
        .map_err(|_| RecoverySealError::BelowArgonFloor)?;

    // Transient copy of the bare scalar, wiped on drop; never logged.
    let scalar = Zeroizing::new(secret.expose_bytes());
    let header = build_header(VERSION_V1, params, &salt, &nonce);
    let ct = crypto::seal(&pw_key, &nonce, &header, &scalar[..]);

    let mut out = Vec::with_capacity(header.len() + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a [`seal_recovery_secret`] file with `passphrase`, returning the
/// byte-identical recovery scalar as an [`EncSecretKey`]. Wrong passphrase,
/// tamper, unknown version, or below-floor params all fail closed.
pub fn open_recovery_secret(
    sealed: &[u8],
    passphrase: &str,
) -> Result<EncSecretKey, RecoverySealError> {
    // Read magic + version before trusting any length.
    if sealed.len() < HEADER_LEN {
        return Err(RecoverySealError::CorruptFile);
    }
    if &sealed[0..4] != MAGIC {
        return Err(RecoverySealError::CorruptFile);
    }
    let version = sealed[4];
    if version != VERSION_V1 {
        return Err(RecoverySealError::UnsupportedVersion(version));
    }
    if sealed.len() != FILE_LEN {
        return Err(RecoverySealError::CorruptFile);
    }
    let m_kib = u32::from_be_bytes(sealed[5..9].try_into().unwrap());
    let t = u32::from_be_bytes(sealed[9..13].try_into().unwrap());
    let p = u32::from_be_bytes(sealed[13..17].try_into().unwrap());
    let params = Argon2Params { m_kib, t, p };

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&sealed[17..33]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[33..45]);
    let header = &sealed[0..HEADER_LEN];
    let ct = &sealed[HEADER_LEN..];

    // Below-floor params are refused before any work (parameters §1.1).
    let pw_key = crypto::derive_key(passphrase.as_bytes(), &salt, params)
        .map_err(|_| RecoverySealError::BelowArgonFloor)?;

    // Fail closed: a wrong passphrase / tamper is an AEAD auth failure with no
    // partial plaintext. The decrypted scalar is wiped on drop.
    let plaintext = Zeroizing::new(
        crypto::open(&pw_key, &nonce, header, ct)
            .map_err(|_| RecoverySealError::WrongPassphrase)?,
    );
    if plaintext.len() != SCALAR_LEN {
        return Err(RecoverySealError::CorruptFile);
    }
    let mut scalar = [0u8; SCALAR_LEN];
    scalar.copy_from_slice(&plaintext);
    // `from_bytes` takes ownership into a Zeroizing store; wipe our stack copy.
    let key = EncSecretKey::from_bytes(scalar);
    scalar.iter_mut().for_each(|b| *b = 0);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Floor params keep the (memory-hard) tests fast while exercising the real KDF.
    fn params() -> Argon2Params {
        maxsecu_crypto::ARGON2_FLOOR
    }

    #[test]
    fn seal_open_round_trips_scalar() {
        let scalar = [0x42u8; 32];
        let secret = EncSecretKey::from_bytes(scalar);
        let pw = "correct horse battery staple recovery!";
        let sealed = seal_recovery_secret(&secret, pw, params()).unwrap();
        assert_eq!(sealed.len(), FILE_LEN);
        assert_eq!(&sealed[0..4], MAGIC);
        assert_eq!(sealed[4], VERSION_V1);

        let back = open_recovery_secret(&sealed, pw).unwrap();
        // Byte-identical scalar recovered.
        assert_eq!(back.expose_bytes(), scalar);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let secret = EncSecretKey::from_bytes([0x11u8; 32]);
        let sealed = seal_recovery_secret(&secret, "the-right-passphrase-123", params()).unwrap();
        // No partial output — a hard Err, never a best-effort scalar.
        assert_eq!(
            open_recovery_secret(&sealed, "the-wrong-passphrase-123").map(|_| ()),
            Err(RecoverySealError::WrongPassphrase)
        );
    }

    #[test]
    fn sealed_bytes_never_contain_the_plaintext_scalar() {
        // A distinctive scalar so a substring match is meaningful.
        let scalar: [u8; 32] = core::array::from_fn(|i| i as u8 ^ 0xA5);
        let secret = EncSecretKey::from_bytes(scalar);
        let sealed = seal_recovery_secret(&secret, "substring-check-passphrase", params()).unwrap();
        // The bare 32-byte scalar must not appear anywhere in the at-rest file.
        let appears = sealed.windows(scalar.len()).any(|w| w == scalar);
        assert!(!appears, "plaintext scalar leaked into the sealed file");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let secret = EncSecretKey::from_bytes([0x33u8; 32]);
        let mut sealed = seal_recovery_secret(&secret, "tamper-passphrase", params()).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(
            open_recovery_secret(&sealed, "tamper-passphrase").map(|_| ()),
            Err(RecoverySealError::WrongPassphrase)
        );
    }

    #[test]
    fn tampered_header_param_is_rejected() {
        // The header is the AEAD AAD, so flipping a stored Argon2 cost (still
        // ≥ floor) changes the derived key and the open fails closed.
        let secret = EncSecretKey::from_bytes([0x44u8; 32]);
        let mut sealed = seal_recovery_secret(&secret, "header-aad-binding", params()).unwrap();
        sealed[12] = sealed[12].wrapping_add(1); // bump t within the valid range
        assert!(open_recovery_secret(&sealed, "header-aad-binding").is_err());
    }

    #[test]
    fn below_floor_params_file_is_refused() {
        let secret = EncSecretKey::from_bytes([0x55u8; 32]);
        let mut sealed = seal_recovery_secret(&secret, "below-floor", params()).unwrap();
        // Set m_kib (bytes 5..9) to 1 MiB << 19 MiB floor.
        sealed[5..9].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(
            open_recovery_secret(&sealed, "below-floor").map(|_| ()),
            Err(RecoverySealError::BelowArgonFloor)
        );
    }

    #[test]
    fn corrupt_and_unsupported_shapes_are_rejected() {
        assert_eq!(
            open_recovery_secret(&[0u8; 10], "x").map(|_| ()),
            Err(RecoverySealError::CorruptFile)
        );
        let secret = EncSecretKey::from_bytes([0x66u8; 32]);
        let mut sealed = seal_recovery_secret(&secret, "shape-test", params()).unwrap();
        let mut bad_magic = sealed.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            open_recovery_secret(&bad_magic, "shape-test").map(|_| ()),
            Err(RecoverySealError::CorruptFile)
        );
        sealed[4] = 99; // unknown version
        assert_eq!(
            open_recovery_secret(&sealed, "shape-test").map(|_| ()),
            Err(RecoverySealError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn fresh_salt_and_nonce_per_seal() {
        let secret = EncSecretKey::from_bytes([0x77u8; 32]);
        let a = seal_recovery_secret(&secret, "same-pw", params()).unwrap();
        let b = seal_recovery_secret(&secret, "same-pw", params()).unwrap();
        // salt (17..33) and nonce (33..45) differ, so the ciphertext differs too.
        assert_ne!(&a[17..45], &b[17..45]);
        assert_ne!(a, b);
    }
}
