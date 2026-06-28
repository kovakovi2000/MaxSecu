//! Post-quantum **hybrid** DEK wrap (DESIGN §5 / stack.md §1.3, Phase 7).
//!
//! Phase 7 wraps the per-file DEK under a *hybrid* KEM combiner: the classical
//! X25519 (dalek) half AND the post-quantum FIPS 203 ML-KEM-768 (RustCrypto
//! `ml-kem`) half. A future quantum adversary who breaks X25519 still cannot
//! recover the DEK without also breaking ML-KEM, and vice-versa — the wrap
//! survives a CRQC unless **both** primitives fall.
//!
//! ## Combiner construction (X-Wing style — security critical)
//! For each wrap we draw a fresh X25519 ephemeral and a fresh ML-KEM encaps:
//!   * `(eph_x_pub, ss1) = X25519(eph, recipient_x_pub)` — ephemeral-static DH.
//!   * `(ct_pq, ss2)     = ML-KEM-768.encaps(recipient_mlkem_pub)`.
//!   * `kek = HKDF-SHA256(ikm = ss1 ‖ ss2, salt = ∅,
//!            info = LABEL ‖ canonical(WrapContext) ‖ eph_x_pub ‖ ct_pq)`.
//!   * `aead_ct = AES-256-GCM(kek, nonce = 0¹², aad = ∅, dek_bytes)`.
//!   * wire = `eph_x_pub(32) ‖ ct_pq(1088) ‖ aead_ct(48)` = 1168 bytes.
//!
//! **Both** KEM ciphertexts (`eph_x_pub` AND `ct_pq`) are folded into the KEK
//! `info`, so neither leg can be re-bound to a different ciphertext (an attacker
//! cannot swap one shared secret while keeping the other). The all-zero GCM
//! nonce is safe **only** here: every wrap uses a fresh ephemeral + fresh
//! ML-KEM encaps, so each KEK is single-use (exactly one message per KEK), which
//! is precisely the condition GCM nonce-reuse safety requires.

use crate::dek::Dek;
use crate::CryptoError;
use maxsecu_encoding::encode;
use maxsecu_encoding::structs::WrapContext;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit, TryKeyInit};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// HKDF `info` domain-separation label for the hybrid wrap (v2 suite).
const HYBRID_WRAP_LABEL: &[u8] = b"MaxSecu-hybrid-wrap-v2";

/// X25519 public key / shared secret length.
const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation (public) key length (FIPS 203).
const MLKEM_PUB_LEN: usize = 1184;
/// ML-KEM-768 decapsulation-key *seed* length (the `ml-kem` 0.3 preferred,
/// constant-size secret encoding; the live key is derived deterministically).
const MLKEM_SEED_LEN: usize = 64;
/// ML-KEM-768 ciphertext length.
const MLKEM_CT_LEN: usize = 1088;
/// AES-256-GCM ciphertext of the 32-byte DEK: 32 body + 16 tag.
const AEAD_CT_LEN: usize = 48;
/// Serialized hybrid wrap length: `eph_x_pub ‖ ct_pq ‖ aead_ct`.
const HYBRID_WRAP_LEN: usize = X25519_LEN + MLKEM_CT_LEN + AEAD_CT_LEN;

/// A recipient's hybrid public key: the X25519 half (directory `enc_pub`) and
/// the ML-KEM-768 encapsulation key. Both are wire-form bytes (the directory
/// binding / keyblob can store them verbatim).
#[derive(Clone)]
pub struct HybridEncPublicKey {
    /// X25519 public key (32 bytes).
    pub x25519: [u8; X25519_LEN],
    /// ML-KEM-768 encapsulation (public) key (1184 bytes).
    pub mlkem: [u8; MLKEM_PUB_LEN],
}

/// A recipient's hybrid secret key (unwrap only), zeroized on drop. Holds the
/// raw X25519 scalar and the 64-byte ML-KEM decapsulation-key seed; the live
/// ML-KEM key is reconstructed deterministically from the seed at unwrap time.
pub struct HybridEncSecretKey {
    x25519: Zeroizing<[u8; X25519_LEN]>,
    mlkem_seed: Zeroizing<[u8; MLKEM_SEED_LEN]>,
}

/// A hybrid-wrapped DEK: the X25519 ephemeral public key, the ML-KEM
/// ciphertext, and the AEAD ciphertext of the DEK under the combined KEK.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridWrappedDek {
    /// X25519 ephemeral public key (32 bytes).
    pub eph_x_pub: [u8; X25519_LEN],
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub ct_pq: Vec<u8>,
    /// AES-256-GCM ciphertext of the 32-byte DEK (48 bytes: body ‖ tag).
    pub aead_ct: Vec<u8>,
}

impl HybridEncSecretKey {
    /// Reconstruct a hybrid secret key from its parts (e.g. after unsealing the
    /// on-device `local_key_blob`, P7.4). `mlkem_seed` is the 64-byte ML-KEM
    /// decapsulation-key seed. Never send either value anywhere.
    pub fn from_components(
        x25519: [u8; X25519_LEN],
        mlkem_seed: [u8; MLKEM_SEED_LEN],
    ) -> HybridEncSecretKey {
        HybridEncSecretKey {
            x25519: Zeroizing::new(x25519),
            mlkem_seed: Zeroizing::new(mlkem_seed),
        }
    }

    /// Expose the raw X25519 secret scalar — only for sealing into the on-device
    /// keyblob (DESIGN §9.1). Never send this anywhere.
    pub fn x25519_secret_bytes(&self) -> [u8; X25519_LEN] {
        *self.x25519
    }

    /// Expose the 64-byte ML-KEM decapsulation-key seed — only for sealing into
    /// the on-device keyblob. Never send this anywhere.
    pub fn mlkem_seed_bytes(&self) -> [u8; MLKEM_SEED_LEN] {
        *self.mlkem_seed
    }
}

/// Generate a fresh hybrid keypair (X25519 + ML-KEM-768) from the OS CSPRNG.
pub fn generate_hybrid_keypair() -> (HybridEncSecretKey, HybridEncPublicKey) {
    // Classical X25519 half (static recipient key).
    let x_sec = StaticSecret::random_from_rng(OsRng);
    let x_pub = PublicKey::from(&x_sec);

    // Post-quantum ML-KEM-768 half (OS-RNG keygen via the `getrandom` feature).
    let (dk, ek) = MlKem768::generate_keypair();
    let mlkem_pub = ek_to_bytes(&ek);
    let mlkem_seed = dk_to_seed(&dk);

    let secret = HybridEncSecretKey {
        x25519: Zeroizing::new(x_sec.to_bytes()),
        mlkem_seed: Zeroizing::new(mlkem_seed),
    };
    let public = HybridEncPublicKey {
        x25519: x_pub.to_bytes(),
        mlkem: mlkem_pub,
    };
    (secret, public)
}

/// Serialize an ML-KEM encapsulation key to its 1184-byte wire form.
fn ek_to_bytes(ek: &EncapsulationKey<MlKem768>) -> [u8; MLKEM_PUB_LEN] {
    let mut out = [0u8; MLKEM_PUB_LEN];
    out.copy_from_slice(ek.to_bytes().as_slice());
    out
}

/// Serialize an ML-KEM decapsulation key to its 64-byte seed form.
fn dk_to_seed(dk: &DecapsulationKey<MlKem768>) -> [u8; MLKEM_SEED_LEN] {
    let mut out = [0u8; MLKEM_SEED_LEN];
    out.copy_from_slice(
        dk.to_seed()
            .expect("freshly generated key is seed-initialized")
            .as_slice(),
    );
    out
}

/// Derive the single-use KEK that binds both KEM ciphertexts (re-binding
/// resistance): `HKDF-SHA256(ss1 ‖ ss2, info = LABEL ‖ ctx ‖ eph_x_pub ‖ ct_pq)`.
fn derive_kek(
    ss1: &[u8; 32],
    ss2: &[u8; 32],
    ctx: &WrapContext,
    eph_x_pub: &[u8; X25519_LEN],
    ct_pq: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss1);
    ikm[32..].copy_from_slice(ss2);

    let ctx_enc = encode(ctx);
    let mut info =
        Vec::with_capacity(HYBRID_WRAP_LABEL.len() + ctx_enc.len() + X25519_LEN + ct_pq.len());
    info.extend_from_slice(HYBRID_WRAP_LABEL);
    info.extend_from_slice(&ctx_enc);
    info.extend_from_slice(eph_x_pub);
    info.extend_from_slice(ct_pq);

    Zeroizing::new(crate::kdf::hkdf_sha256_32(&ikm[..], &info))
}

/// Wrap `dek` to `recipient` under the hybrid KEM combiner, binding the
/// `ctx` (file_id/version/recipient_id) into the KEK (DESIGN §5, R19).
pub fn wrap_dek_hybrid(
    recipient: &HybridEncPublicKey,
    dek: &Dek,
    ctx: &WrapContext,
) -> Result<HybridWrappedDek, CryptoError> {
    // X25519 ephemeral-static DH → ss1.
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_x_pub = PublicKey::from(&eph).to_bytes();
    let recipient_x_pub = PublicKey::from(recipient.x25519);
    let ss1 = Zeroizing::new(eph.diffie_hellman(&recipient_x_pub).to_bytes());

    // ML-KEM-768 encapsulation → (ct_pq, ss2).
    let ek = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(&recipient.mlkem)
        .map_err(|_| CryptoError::BadPublicKey)?;
    let (ct, ss2_arr) = ek.encapsulate();
    let ct_pq = ct.as_slice().to_vec();
    let mut ss2 = Zeroizing::new([0u8; 32]);
    ss2.copy_from_slice(ss2_arr.as_slice());

    // Combined single-use KEK, then seal the DEK under a zero nonce.
    let kek = derive_kek(&ss1, &ss2, ctx, &eph_x_pub, &ct_pq);
    let aead_ct = crate::aead::seal(&kek, &[0u8; 12], &[], dek.expose());

    Ok(HybridWrappedDek {
        eph_x_pub,
        ct_pq,
        aead_ct,
    })
}

/// Unwrap a hybrid-wrapped DEK with `recipient`'s secret key. The `ctx` MUST
/// match the wrap's (else the KEK `info` differs and the AEAD open fails — the
/// context binding). On success the caller MUST still verify
/// `dek.commit() == manifest.dek_commit` (DESIGN §12.5).
pub fn unwrap_dek_hybrid(
    recipient: &HybridEncSecretKey,
    wrapped: &HybridWrappedDek,
    ctx: &WrapContext,
) -> Result<Dek, CryptoError> {
    if wrapped.ct_pq.len() != MLKEM_CT_LEN || wrapped.aead_ct.len() != AEAD_CT_LEN {
        return Err(CryptoError::WrapOpen);
    }

    // X25519 static-ephemeral DH → ss1.
    let x_sec = StaticSecret::from(*recipient.x25519);
    let eph_pub = PublicKey::from(wrapped.eph_x_pub);
    let ss1 = Zeroizing::new(x_sec.diffie_hellman(&eph_pub).to_bytes());

    // ML-KEM-768 decapsulation → ss2 (implicit rejection ⇒ a wrong key yields a
    // pseudo-random ss2, so the KEK simply mismatches and the AEAD open fails).
    let dk = <DecapsulationKey<MlKem768> as KeyInit>::new_from_slice(&recipient.mlkem_seed[..])
        .map_err(|_| CryptoError::WrapOpen)?;
    let ss2_arr = dk
        .decapsulate_slice(&wrapped.ct_pq)
        .map_err(|_| CryptoError::WrapOpen)?;
    let mut ss2 = Zeroizing::new([0u8; 32]);
    ss2.copy_from_slice(ss2_arr.as_slice());

    // Recompute the KEK and open. Any wrong leg / wrong ctx / tamper fails here.
    let kek = derive_kek(&ss1, &ss2, ctx, &wrapped.eph_x_pub, &wrapped.ct_pq);
    let pt = crate::aead::open(&kek, &[0u8; 12], &[], &wrapped.aead_ct)
        .map_err(|_| CryptoError::WrapOpen)?;
    if pt.len() != 32 {
        return Err(CryptoError::WrapOpen);
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&pt);
    Ok(Dek::from_bytes(*k))
}

/// Serialize a hybrid wrap to its wire form: `eph_x_pub ‖ ct_pq ‖ aead_ct`.
pub fn serialize_hybrid_wrap(w: &HybridWrappedDek) -> Vec<u8> {
    let mut out = Vec::with_capacity(HYBRID_WRAP_LEN);
    out.extend_from_slice(&w.eph_x_pub);
    out.extend_from_slice(&w.ct_pq);
    out.extend_from_slice(&w.aead_ct);
    out
}

/// Parse a hybrid wrap from its wire form, strictly rejecting any wrong total or
/// per-leg length (no panics / out-of-bounds on attacker bytes — fail closed).
pub fn deserialize_hybrid_wrap(b: &[u8]) -> Result<HybridWrappedDek, CryptoError> {
    if b.len() != HYBRID_WRAP_LEN {
        return Err(CryptoError::BadLength);
    }
    let mut eph_x_pub = [0u8; X25519_LEN];
    eph_x_pub.copy_from_slice(&b[..X25519_LEN]);
    let ct_pq = b[X25519_LEN..X25519_LEN + MLKEM_CT_LEN].to_vec();
    let aead_ct = b[X25519_LEN + MLKEM_CT_LEN..].to_vec();
    Ok(HybridWrappedDek {
        eph_x_pub,
        ct_pq,
        aead_ct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_encoding::types::Id;

    fn ctx(recipient: u8, version: u64) -> WrapContext {
        WrapContext {
            file_id: Id([0x11; 16]),
            version,
            recipient_id: Id([recipient; 16]),
        }
    }

    /// ML-KEM-768 (FIPS 203) keygen → encapsulate → decapsulate round-trips, and
    /// the sender's and receiver's shared secrets are byte-equal (P7.1 adoption
    /// smoke test, kept as a KEM-contract regression).
    #[test]
    fn mlkem_keygen_encaps_decaps_roundtrip() {
        let (dk, ek) = MlKem768::generate_keypair();
        let (ct, k_send) = ek.encapsulate();
        let k_recv = dk.decapsulate(&ct);
        assert_eq!(k_send, k_recv, "ML-KEM-768 shared secrets must match");
    }

    #[test]
    fn hybrid_wrap_then_unwrap_recovers_the_dek() {
        let (sk, pk) = generate_hybrid_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let c = ctx(0x55, 1);
        let wrapped = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        let out = unwrap_dek_hybrid(&sk, &wrapped, &c).unwrap();
        assert_eq!(out.expose(), dek.expose());
    }

    #[test]
    fn hybrid_unwrap_wrong_x25519_key_fails() {
        // Same ML-KEM key, different X25519 secret → ss1 mismatches → fail.
        let (sk1, pk1) = generate_hybrid_keypair();
        let (sk2, _pk2) = generate_hybrid_keypair();
        let mixed = HybridEncSecretKey::from_components(
            sk2.x25519_secret_bytes(),
            sk1.mlkem_seed_bytes(),
        );
        let dek = Dek::from_bytes([0x42; 32]);
        let c = ctx(0x55, 1);
        let wrapped = wrap_dek_hybrid(&pk1, &dek, &c).unwrap();
        assert_eq!(
            unwrap_dek_hybrid(&mixed, &wrapped, &c).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
    }

    #[test]
    fn hybrid_unwrap_wrong_mlkem_key_fails() {
        // Same X25519 key, different ML-KEM secret → ss2 mismatches → fail.
        let (sk1, pk1) = generate_hybrid_keypair();
        let (sk2, _pk2) = generate_hybrid_keypair();
        let mixed = HybridEncSecretKey::from_components(
            sk1.x25519_secret_bytes(),
            sk2.mlkem_seed_bytes(),
        );
        let dek = Dek::from_bytes([0x42; 32]);
        let c = ctx(0x55, 1);
        let wrapped = wrap_dek_hybrid(&pk1, &dek, &c).unwrap();
        assert_eq!(
            unwrap_dek_hybrid(&mixed, &wrapped, &c).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
    }

    #[test]
    fn hybrid_unwrap_wrong_context_fails() {
        let (sk, pk) = generate_hybrid_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let wrapped = wrap_dek_hybrid(&pk, &dek, &ctx(0x55, 1)).unwrap();
        // Different recipient_id.
        assert_eq!(
            unwrap_dek_hybrid(&sk, &wrapped, &ctx(0x56, 1)).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
        // Different version.
        assert_eq!(
            unwrap_dek_hybrid(&sk, &wrapped, &ctx(0x55, 2)).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
    }

    #[test]
    fn hybrid_tampered_ct_fails() {
        let (sk, pk) = generate_hybrid_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let c = ctx(0x55, 1);

        // Flip a byte in eph_x_pub.
        let mut w = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        w.eph_x_pub[0] ^= 0x01;
        assert_eq!(
            unwrap_dek_hybrid(&sk, &w, &c).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );

        // Flip a byte in ct_pq.
        let mut w = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        w.ct_pq[0] ^= 0x01;
        assert_eq!(
            unwrap_dek_hybrid(&sk, &w, &c).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );

        // Flip a byte in aead_ct.
        let mut w = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        let last = w.aead_ct.len() - 1;
        w.aead_ct[last] ^= 0x01;
        assert_eq!(
            unwrap_dek_hybrid(&sk, &w, &c).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
    }

    #[test]
    fn hybrid_wrap_is_randomized() {
        // Two wraps of the same DEK to the same recipient differ (fresh
        // ephemeral + fresh ML-KEM encaps), and both still unwrap.
        let (sk, pk) = generate_hybrid_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let c = ctx(0x55, 1);
        let a = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        let b = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        assert_ne!(a.eph_x_pub, b.eph_x_pub);
        assert_ne!(a.ct_pq, b.ct_pq);
        assert_ne!(a.aead_ct, b.aead_ct);
        assert_eq!(unwrap_dek_hybrid(&sk, &a, &c).unwrap().expose(), dek.expose());
        assert_eq!(unwrap_dek_hybrid(&sk, &b, &c).unwrap().expose(), dek.expose());
    }

    #[test]
    fn serialize_then_deserialize_roundtrips() {
        let (sk, pk) = generate_hybrid_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let c = ctx(0x55, 1);
        let wrapped = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        let bytes = serialize_hybrid_wrap(&wrapped);
        assert_eq!(bytes.len(), HYBRID_WRAP_LEN);
        let back = deserialize_hybrid_wrap(&bytes).unwrap();
        assert_eq!(back, wrapped);
        // The reparsed wrap still opens.
        assert_eq!(
            unwrap_dek_hybrid(&sk, &back, &c).unwrap().expose(),
            dek.expose()
        );
    }

    #[test]
    fn deserialize_rejects_wrong_length() {
        let (_sk, pk) = generate_hybrid_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let wrapped = wrap_dek_hybrid(&pk, &dek, &ctx(0x55, 1)).unwrap();
        let good = serialize_hybrid_wrap(&wrapped);

        // Truncated.
        assert_eq!(
            deserialize_hybrid_wrap(&good[..good.len() - 1]).map(|_| ()),
            Err(CryptoError::BadLength)
        );
        // Over-long.
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            deserialize_hybrid_wrap(&long).map(|_| ()),
            Err(CryptoError::BadLength)
        );
        // Empty.
        assert_eq!(
            deserialize_hybrid_wrap(&[]).map(|_| ()),
            Err(CryptoError::BadLength)
        );
    }

    #[test]
    fn secret_key_components_round_trip() {
        // from_components(expose) reconstructs a working unwrap key (keyblob path).
        let (sk, pk) = generate_hybrid_keypair();
        let sk2 = HybridEncSecretKey::from_components(
            sk.x25519_secret_bytes(),
            sk.mlkem_seed_bytes(),
        );
        let dek = Dek::from_bytes([7; 32]);
        let c = ctx(0x55, 1);
        let w = wrap_dek_hybrid(&pk, &dek, &c).unwrap();
        assert_eq!(unwrap_dek_hybrid(&sk2, &w, &c).unwrap().expose(), dek.expose());
    }
}
