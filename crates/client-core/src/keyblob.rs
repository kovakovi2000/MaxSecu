//! `local_key_blob` — the device-only, password-encrypted store of the user's
//! private keys (DESIGN §9.1, parameters §1.1, stack §5.2 portable mode).
//!
//! The blob never leaves the device and is **ciphertext only** at rest. Its
//! layout is a fixed, self-describing header (authenticated as AEAD AAD) plus
//! an AES-256-GCM sealing of the private material. Two versions coexist:
//!
//! ```text
//! magic "MXKB" (4) | version u8 | argon m_kib u32 | t u32 | p u32
//!   | salt[16] | nonce[12]            <-- 45-byte header, also the AEAD AAD
//! v1 ciphertext = AES-256-GCM(pw_key, nonce, aad=header,
//!     enc_sk[32] ‖ enc_pk[32] ‖ sig_seed[32])                  (96 + 16 tag)
//! v2 ciphertext = AES-256-GCM(pw_key, nonce, aad=header,
//!     enc_sk[32] ‖ enc_pk[32] ‖ sig_seed[32] ‖ mlkem_seed[64]) (160 + 16 tag)
//! ```
//!
//! `version 2` (Phase 7) adds the 64-byte ML-KEM-768 decapsulation-key seed of a
//! PQ-enrolled identity; the public key is re-derived from the seed on unlock.
//! `seal` writes v2 for a PQ identity (every freshly-generated identity is PQ)
//! and v1 for a legacy non-PQ identity (e.g. a resealed v1 blob). `unlock`
//! accepts **both** versions; a v1 blob yields an identity with no ML-KEM key.
//!
//! `pw_key = Argon2id(password, salt, params)`. The full `(m,t,p,salt)` is
//! stored with the blob (M3) so a re-tuned/older blob still opens; params below
//! the floor are refused (parameters §1.1). A fresh random `salt` + `nonce` is
//! generated on every seal, so the deterministic-AEAD nonce is never reused
//! across passwords.

use crate::error::ClientError;
use crate::identity::Identity;
use maxsecu_crypto::{self as crypto, random_array, Argon2Params};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"MXKB";
const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + 16 + 12; // 45
const PLAINTEXT_V1_LEN: usize = 32 + 32 + 32; // enc_sk ‖ enc_pk ‖ sig_seed = 96
const PLAINTEXT_V2_LEN: usize = PLAINTEXT_V1_LEN + 64; // + mlkem_seed = 160
const TAG_LEN: usize = 16;
const BLOB_V1_LEN: usize = HEADER_LEN + PLAINTEXT_V1_LEN + TAG_LEN; // 157
const BLOB_V2_LEN: usize = HEADER_LEN + PLAINTEXT_V2_LEN + TAG_LEN; // 221

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

/// Seal `id` under `password` with `params`, producing the at-rest blob bytes.
/// A PQ identity (with an ML-KEM key) seals as v2; a legacy non-PQ identity as
/// v1.
pub fn seal(password: &str, id: &Identity, params: Argon2Params) -> Result<Vec<u8>, ClientError> {
    let salt: [u8; 16] = random_array();
    let nonce: [u8; 12] = random_array();
    let pw_key = crypto::derive_key(password.as_bytes(), &salt, params)
        .map_err(|_| ClientError::BelowArgonFloor)?;

    let (enc_sk, enc_pk, sig_seed, mlkem_seed) = id.secret_bytes();
    // Transient combined plaintext, wiped on drop (DESIGN §8.1). Sized to the
    // version we are writing (v2 when the identity carries an ML-KEM seed).
    let (version, plaintext) = match mlkem_seed {
        Some(seed) => {
            let mut pt = Zeroizing::new(vec![0u8; PLAINTEXT_V2_LEN]);
            pt[0..32].copy_from_slice(&enc_sk);
            pt[32..64].copy_from_slice(&enc_pk);
            pt[64..96].copy_from_slice(&sig_seed);
            pt[96..160].copy_from_slice(&seed);
            (VERSION_V2, pt)
        }
        None => {
            let mut pt = Zeroizing::new(vec![0u8; PLAINTEXT_V1_LEN]);
            pt[0..32].copy_from_slice(&enc_sk);
            pt[32..64].copy_from_slice(&enc_pk);
            pt[64..96].copy_from_slice(&sig_seed);
            (VERSION_V1, pt)
        }
    };

    let header = build_header(version, params, &salt, &nonce);
    let ct = crypto::seal(&pw_key, &nonce, &header, &plaintext[..]);

    let mut out = Vec::with_capacity(header.len() + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unlock the blob with `password`, returning the in-memory [`Identity`].
/// Accepts both v1 (no ML-KEM) and v2 (PQ) blobs. Wrong password, tamper, or
/// below-floor params all fail closed.
pub fn unlock(password: &str, blob: &[u8]) -> Result<Identity, ClientError> {
    // Need at least the header to read magic + version; full length is checked
    // per-version once the version is known.
    if blob.len() < HEADER_LEN {
        return Err(ClientError::CorruptBlob);
    }
    if &blob[0..4] != MAGIC {
        return Err(ClientError::CorruptBlob);
    }
    let version = blob[4];
    let (blob_len, plaintext_len) = match version {
        VERSION_V1 => (BLOB_V1_LEN, PLAINTEXT_V1_LEN),
        VERSION_V2 => (BLOB_V2_LEN, PLAINTEXT_V2_LEN),
        other => return Err(ClientError::UnsupportedBlobVersion(other)),
    };
    if blob.len() != blob_len {
        return Err(ClientError::CorruptBlob);
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
    if plaintext.len() != plaintext_len {
        return Err(ClientError::CorruptBlob);
    }
    let mut enc_sk = [0u8; 32];
    let mut enc_pk = [0u8; 32];
    let mut sig_seed = [0u8; 32];
    enc_sk.copy_from_slice(&plaintext[0..32]);
    enc_pk.copy_from_slice(&plaintext[32..64]);
    sig_seed.copy_from_slice(&plaintext[64..96]);
    let mlkem_seed = if version == VERSION_V2 {
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&plaintext[96..160]);
        Some(seed)
    } else {
        None
    };
    Ok(Identity::from_secret_bytes(
        enc_sk, enc_pk, sig_seed, mlkem_seed,
    ))
}

/// Password change (DESIGN §9.5): unlock with the old password, re-seal under
/// the new one with a **fresh salt** and (possibly re-tuned) params. The caller
/// writes the result atomically and destroys the old blob.
pub fn reseal(
    blob: &[u8],
    old_password: &str,
    new_password: &str,
    params: Argon2Params,
) -> Result<Vec<u8>, ClientError> {
    let id = unlock(old_password, blob)?;
    seal(new_password, &id, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Floor params keep the (memory-hard) tests fast while exercising the real KDF.
    fn params() -> Argon2Params {
        maxsecu_crypto::ARGON2_FLOOR
    }

    #[test]
    fn seal_unlock_round_trips_identity() {
        let id = Identity::generate();
        let pw = "correct horse battery staple!";
        let blob = seal(pw, &id, params()).unwrap();
        // A fresh (PQ) identity seals as v2.
        assert_eq!(blob.len(), BLOB_V2_LEN);
        assert_eq!(blob[4], VERSION_V2);
        let back = unlock(pw, &blob).unwrap();
        assert_eq!(back.enc_pub_bytes(), id.enc_pub_bytes());
        assert_eq!(back.sig_pub_bytes(), id.sig_pub_bytes());
        assert_eq!(back.fingerprint(), id.fingerprint());
    }

    #[test]
    fn keyblob_v2_roundtrips_with_mlkem() {
        // A fresh PQ identity seals as v2 and unlocks to a working ML-KEM half:
        // the recovered seed re-derives the same public key, and a hybrid wrap to
        // {enc_pub, mlkem_pub} unwraps with the recovered identity's secret parts.
        use maxsecu_crypto::{
            unwrap_dek_hybrid, wrap_dek_hybrid, Dek, HybridEncPublicKey, HybridEncSecretKey,
        };
        use maxsecu_encoding::structs::WrapContext;
        use maxsecu_encoding::types::Id;

        let id = Identity::generate();
        let pw = "pq-keyblob-roundtrip-passphrase";
        let blob = seal(pw, &id, params()).unwrap();
        assert_eq!(blob.len(), BLOB_V2_LEN);

        let back = unlock(pw, &blob).unwrap();
        assert!(back.mlkem_pub_bytes().is_some());
        assert_eq!(back.mlkem_pub_bytes(), id.mlkem_pub_bytes());

        // Prove the recovered seed is correct: build a hybrid recipient from the
        // recovered identity and round-trip a DEK.
        let pk = HybridEncPublicKey {
            x25519: back.enc_pub_bytes(),
            mlkem: back.mlkem_pub_bytes().unwrap(),
        };
        let sk = HybridEncSecretKey::from_components(
            back.enc_secret().expose_bytes(),
            back.mlkem_seed().unwrap(),
        );
        let dek = Dek::from_bytes([0x77; 32]);
        let ctx = WrapContext {
            file_id: Id([3; 16]),
            version: 7,
            recipient_id: Id([4; 16]),
        };
        let w = wrap_dek_hybrid(&pk, &dek, &ctx).unwrap();
        assert_eq!(
            unwrap_dek_hybrid(&sk, &w, &ctx).unwrap().expose(),
            dek.expose()
        );
    }

    #[test]
    fn keyblob_v1_still_loads() {
        // A legacy (non-PQ) identity — reconstructed with no ML-KEM seed — seals
        // as a v1 blob and unlocks to an identity with no ML-KEM key.
        let pq = Identity::generate();
        let (esk, epk, seed, _) = pq.secret_bytes();
        let v1_id = Identity::from_secret_bytes(esk, epk, seed, None);
        assert!(v1_id.mlkem_pub_bytes().is_none());

        let pw = "legacy-v1-blob-passphrase";
        let blob = seal(pw, &v1_id, params()).unwrap();
        assert_eq!(blob.len(), BLOB_V1_LEN);
        assert_eq!(blob[4], VERSION_V1);

        let back = unlock(pw, &blob).unwrap();
        assert!(back.mlkem_pub_bytes().is_none());
        assert_eq!(back.fingerprint(), v1_id.fingerprint());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let id = Identity::generate();
        let blob = seal("the-right-password-123", &id, params()).unwrap();
        assert_eq!(
            unlock("the-wrong-password-123", &blob).map(|_| ()),
            Err(ClientError::WrongPassword)
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let id = Identity::generate();
        let pw = "tamper-test-passphrase";
        let mut blob = seal(pw, &id, params()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            unlock(pw, &blob).map(|_| ()),
            Err(ClientError::WrongPassword)
        );
    }

    #[test]
    fn tampered_header_param_is_rejected() {
        // Flipping a stored Argon2 cost (still ≥ floor) changes the derived key,
        // so the AEAD (with the header as AAD) fails to open.
        let id = Identity::generate();
        let pw = "header-aad-binding-test";
        let mut blob = seal(pw, &id, params()).unwrap();
        // bump t (bytes 9..13) from floor (2) to 3 — still valid, but different.
        blob[12] = blob[12].wrapping_add(1);
        assert!(unlock(pw, &blob).is_err());
    }

    #[test]
    fn below_floor_params_blob_is_refused() {
        // A blob whose stored params fall below the floor is refused (parameters §1.1).
        let id = Identity::generate();
        let pw = "below-floor-params-test";
        let mut blob = seal(pw, &id, params()).unwrap();
        // Set m_kib (bytes 5..9) to 1024 KiB (1 MiB) << 19 MiB floor.
        blob[5..9].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(
            unlock(pw, &blob).map(|_| ()),
            Err(ClientError::BelowArgonFloor)
        );
    }

    #[test]
    fn corrupt_blob_shapes_are_rejected() {
        assert_eq!(
            unlock("x", &[0u8; 10]).map(|_| ()),
            Err(ClientError::CorruptBlob)
        );
        let id = Identity::generate();
        let mut blob = seal("len-and-magic-test-pw", &id, params()).unwrap();
        blob[0] = b'X'; // break magic
        assert_eq!(
            unlock("len-and-magic-test-pw", &blob).map(|_| ()),
            Err(ClientError::CorruptBlob)
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let id = Identity::generate();
        let mut blob = seal("version-test-passphrase", &id, params()).unwrap();
        blob[4] = 99;
        assert_eq!(
            unlock("version-test-passphrase", &blob).map(|_| ()),
            Err(ClientError::UnsupportedBlobVersion(99))
        );
    }

    #[test]
    fn password_change_reseals_and_old_password_stops_working() {
        let id = Identity::generate();
        let old = "old-passphrase-abcdef";
        let new = "new-passphrase-ghijkl";
        let blob = seal(old, &id, params()).unwrap();
        let blob2 = reseal(&blob, old, new, params()).unwrap();
        // New blob opens with the new password, same identity.
        let back = unlock(new, &blob2).unwrap();
        assert_eq!(back.fingerprint(), id.fingerprint());
        // New password does not open the OLD blob; old password does not open the NEW.
        assert!(unlock(new, &blob).is_err());
        assert!(unlock(old, &blob2).is_err());
        // Fresh salt: the two blobs differ in their salt region.
        assert_ne!(&blob[17..33], &blob2[17..33]);
    }
}
