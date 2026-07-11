//! `d5_seed_blob` — a password-encrypted store of a **single 32-byte Ed25519
//! seed** (the offline-D5 directory root), for the offline-D5 ceremony (spec §7)
//! and its recovery backup (spec §5).
//!
//! This is deliberately a SEPARATE primitive from [`keyblob`](crate::keyblob):
//! `keyblob` seals a whole [`Identity`](crate::Identity) (enc + sig + ML-KEM
//! material) and is byte-shaped as a client `local_key_blob`. The D5 root is a
//! bare Ed25519 signing seed, and it must never be confusable with a keyblob —
//! so this format uses a DISTINCT magic (`MXD5`), which is bound into the AEAD as
//! additional authenticated data. A `keyblob` (`MXKB`) can therefore never be
//! opened as a seedblob and vice-versa (domain separation), and both fail closed.
//!
//! ```text
//! magic "MXD5" (4) | version u8 = 1 | argon m_kib u32 | t u32 | p u32
//!   | salt[16] | nonce[12]              <-- 45-byte header, also the AEAD AAD
//! ciphertext = AES-256-GCM(pw_key, nonce, aad=header, seed[32])   (32 + 16 tag)
//! ```
//!
//! `pw_key = Argon2id(password, salt, params)` — the same KDF the keyblob uses,
//! with the full `(m,t,p,salt)` stored so a re-tuned/older blob still opens.
//! Params below the floor are refused (fail closed). A fresh random `salt` +
//! `nonce` is generated on every seal.

use crate::error::ClientError;
use maxsecu_crypto::{self as crypto, random_array, Argon2Params};
use zeroize::Zeroizing;

/// Magic distinct from the keyblob's `MXKB` — the whole point of this module.
const MAGIC: &[u8; 4] = b"MXD5";
const VERSION_V1: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + 16 + 12; // 45
const SEED_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// The exact on-disk length of a v1 D5 seed blob.
pub const SEEDBLOB_V1_LEN: usize = HEADER_LEN + SEED_LEN + TAG_LEN; // 93

fn build_header(params: Argon2Params, salt: &[u8; 16], nonce: &[u8; 12]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = VERSION_V1;
    h[5..9].copy_from_slice(&params.m_kib.to_be_bytes());
    h[9..13].copy_from_slice(&params.t.to_be_bytes());
    h[13..17].copy_from_slice(&params.p.to_be_bytes());
    h[17..33].copy_from_slice(salt);
    h[33..45].copy_from_slice(nonce);
    h
}

/// Seal the 32-byte `seed` under `password` with `params`, producing the at-rest
/// blob bytes. Pure CPU (Argon2id + one AEAD seal); no I/O.
pub fn seal_seed(
    password: &str,
    seed: &[u8; SEED_LEN],
    params: Argon2Params,
) -> Result<Vec<u8>, ClientError> {
    let salt: [u8; 16] = random_array();
    let nonce: [u8; 12] = random_array();
    let pw_key = crypto::derive_key(password.as_bytes(), &salt, params)
        .map_err(|_| ClientError::BelowArgonFloor)?;
    let header = build_header(params, &salt, &nonce);
    // The seed is copied into a Zeroizing buffer so the plaintext handed to the
    // AEAD is wiped after use (the caller's `seed` is theirs to manage).
    let pt = Zeroizing::new(*seed);
    let ct = crypto::seal(&pw_key, &nonce, &header, &pt[..]);
    let mut out = Vec::with_capacity(header.len() + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unseal a D5 seed blob with `password`, returning the 32-byte seed (zeroized on
/// drop). Wrong password, tamper, wrong magic (e.g. a keyblob), below-floor
/// params, or wrong length all fail closed.
pub fn unseal_seed(password: &str, blob: &[u8]) -> Result<Zeroizing<[u8; SEED_LEN]>, ClientError> {
    if blob.len() != SEEDBLOB_V1_LEN {
        return Err(ClientError::CorruptBlob);
    }
    if &blob[0..4] != MAGIC {
        return Err(ClientError::CorruptBlob);
    }
    let version = blob[4];
    if version != VERSION_V1 {
        return Err(ClientError::UnsupportedBlobVersion(version));
    }
    let m_kib = u32::from_be_bytes(blob[5..9].try_into().unwrap());
    let t = u32::from_be_bytes(blob[9..13].try_into().unwrap());
    let p = u32::from_be_bytes(blob[13..17].try_into().unwrap());
    let params = Argon2Params { m_kib, t, p };

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blob[17..33]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[33..45]);
    let header = &blob[0..HEADER_LEN];
    let ct = &blob[HEADER_LEN..];

    // Below-floor params are refused before any work (parameters §1.1).
    let pw_key = crypto::derive_key(password.as_bytes(), &salt, params)
        .map_err(|_| ClientError::BelowArgonFloor)?;
    let plaintext = Zeroizing::new(
        crypto::open(&pw_key, &nonce, header, ct).map_err(|_| ClientError::WrongPassword)?,
    );
    if plaintext.len() != SEED_LEN {
        return Err(ClientError::CorruptBlob);
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&plaintext[..]);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyblob;
    use crate::Identity;

    fn params() -> Argon2Params {
        maxsecu_crypto::ARGON2_FLOOR
    }

    #[test]
    fn seal_unseal_round_trips_the_seed() {
        let seed = [0x5au8; 32];
        let pw = "correct horse battery staple d5!";
        let blob = seal_seed(pw, &seed, params()).unwrap();
        assert_eq!(blob.len(), SEEDBLOB_V1_LEN);
        assert_eq!(&blob[0..4], MAGIC);
        let back = unseal_seed(pw, &blob).unwrap();
        assert_eq!(*back, seed);
    }

    #[test]
    fn blob_is_ciphertext_not_the_bare_seed() {
        // The seed must not appear verbatim anywhere in the sealed bytes.
        let seed = [0x11u8; 32];
        let blob = seal_seed("a-strong-d5-passphrase-here", &seed, params()).unwrap();
        assert!(
            !blob.windows(SEED_LEN).any(|w| w == seed),
            "the plaintext seed leaked into the sealed blob"
        );
    }

    #[test]
    fn wrong_password_is_rejected() {
        let seed = [0x77u8; 32];
        let blob = seal_seed("the-right-d5-password-123", &seed, params()).unwrap();
        assert_eq!(
            unseal_seed("the-wrong-d5-password-123", &blob).map(|_| ()),
            Err(ClientError::WrongPassword)
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let seed = [0x22u8; 32];
        let pw = "tamper-test-d5-passphrase";
        let mut blob = seal_seed(pw, &seed, params()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            unseal_seed(pw, &blob).map(|_| ()),
            Err(ClientError::WrongPassword)
        );
    }

    #[test]
    fn below_floor_params_are_refused_on_unseal() {
        let seed = [0x33u8; 32];
        let mut blob = seal_seed("below-floor-d5-test-passphrase", &seed, params()).unwrap();
        // Set m_kib (bytes 5..9) to 1 MiB << the 19 MiB floor.
        blob[5..9].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(
            unseal_seed("below-floor-d5-test-passphrase", &blob).map(|_| ()),
            Err(ClientError::BelowArgonFloor)
        );
    }

    #[test]
    fn corrupt_shapes_are_rejected() {
        assert_eq!(
            unseal_seed("x", &[0u8; 10]).map(|_| ()),
            Err(ClientError::CorruptBlob)
        );
        let mut blob = seal_seed("magic-test-d5-passphrase", &[9u8; 32], params()).unwrap();
        blob[0] = b'X'; // break magic
        assert_eq!(
            unseal_seed("magic-test-d5-passphrase", &blob).map(|_| ()),
            Err(ClientError::CorruptBlob)
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut blob = seal_seed("version-test-d5-passphrase", &[3u8; 32], params()).unwrap();
        blob[4] = 99;
        assert_eq!(
            unseal_seed("version-test-d5-passphrase", &blob).map(|_| ()),
            Err(ClientError::UnsupportedBlobVersion(99))
        );
    }

    // ---- domain separation: a keyblob is NOT a seedblob and vice-versa ----

    #[test]
    fn a_keyblob_is_not_accepted_as_a_seedblob() {
        // Seal a full identity as a keyblob (MXKB), then try to unseal it as a D5
        // seedblob (MXD5) with the SAME password: it must fail on the magic, never
        // yield a seed. (Domain separation.)
        let id = Identity::generate();
        let pw = "shared-passphrase-domain-sep-1";
        let keyblob = keyblob::seal(pw, &id, params()).unwrap();
        assert_eq!(
            unseal_seed(pw, &keyblob).map(|_| ()),
            Err(ClientError::CorruptBlob),
            "a keyblob must never open as a D5 seedblob"
        );
    }

    #[test]
    fn a_seedblob_is_not_accepted_as_a_keyblob() {
        // And the reverse: a D5 seedblob (MXD5) must never open via keyblob::unlock
        // (MXKB) — it fails on the magic (CorruptBlob), never yields an Identity.
        let pw = "shared-passphrase-domain-sep-2";
        let seedblob = seal_seed(pw, &[0x44u8; 32], params()).unwrap();
        assert_eq!(
            keyblob::unlock(pw, &seedblob).map(|_| ()),
            Err(ClientError::CorruptBlob),
            "a D5 seedblob must never open as a keyblob"
        );
    }
}
