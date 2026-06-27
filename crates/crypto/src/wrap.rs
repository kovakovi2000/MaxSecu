//! HPKE base-mode key wrapping (DESIGN §5, RFC 9180): X25519 + HKDF-SHA256 +
//! AES-256-GCM. The HPKE `info` is `canonical(wrap_context)` (encoding-spec §4),
//! so a wrap is cryptographically bound to its `(file_id, version, recipient_id)`
//! and cannot be reinterpreted for another file/version/recipient (§5, R19).
//!
//! Auth mode is **not** used (simplification pass): provenance comes from the
//! signed manifest + per-wrap grant, so base mode suffices.

use crate::dek::Dek;
use crate::CryptoError;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use maxsecu_encoding::encode;
use maxsecu_encoding::structs::WrapContext;
use rand_core::OsRng;
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha256;
type KemPub = <Kem as KemTrait>::PublicKey;
type KemPriv = <Kem as KemTrait>::PrivateKey;
type KemEncapped = <Kem as KemTrait>::EncappedKey;

/// A recipient's X25519 public key (the directory `enc_pub`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncPublicKey([u8; 32]);

/// A recipient's X25519 private key (unwrap only), zeroized on drop.
pub struct EncSecretKey(Zeroizing<[u8; 32]>);

/// An HPKE-wrapped DEK: the encapsulated key plus the AEAD ciphertext.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WrappedDek {
    /// Encapsulated ephemeral public key (32 bytes for X25519).
    pub enc: [u8; 32],
    /// AES-256-GCM ciphertext of the 32-byte DEK (body ‖ 16-byte tag).
    pub ct: Vec<u8>,
}

impl EncPublicKey {
    pub fn from_bytes(b: [u8; 32]) -> EncPublicKey {
        EncPublicKey(b)
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl EncSecretKey {
    pub fn from_bytes(b: [u8; 32]) -> EncSecretKey {
        EncSecretKey(Zeroizing::new(b))
    }
}

fn ser32<T: Serializable>(x: &T) -> Result<[u8; 32], CryptoError> {
    let b = x.to_bytes();
    if b.len() != 32 {
        return Err(CryptoError::BadLength);
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&b);
    Ok(o)
}

/// Generate a fresh X25519 keypair (the user `enc` key, DESIGN §6.1).
pub fn generate_enc_keypair() -> (EncSecretKey, EncPublicKey) {
    let (sk, pk) = Kem::gen_keypair(&mut OsRng);
    let skb = ser32(&sk).expect("X25519 private key is 32 bytes");
    let pkb = ser32(&pk).expect("X25519 public key is 32 bytes");
    (EncSecretKey(Zeroizing::new(skb)), EncPublicKey(pkb))
}

/// Wrap `dek` to `recipient` with `ctx`-bound HPKE `info` (DESIGN §5/§12.2).
pub fn wrap_dek(
    recipient: &EncPublicKey,
    dek: &Dek,
    ctx: &WrapContext,
) -> Result<WrappedDek, CryptoError> {
    let pk = KemPub::from_bytes(&recipient.0).map_err(|_| CryptoError::BadPublicKey)?;
    let info = encode(ctx);
    let (encapped, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        &info,
        dek.expose(),
        &[],
        &mut OsRng,
    )
    .map_err(|_| CryptoError::WrapOpen)?;
    Ok(WrappedDek {
        enc: ser32(&encapped)?,
        ct,
    })
}

/// Unwrap with `recipient`'s private key; the `ctx` MUST match the wrap's
/// (otherwise the AEAD `info` differs and open fails — the context binding).
/// On success the result is checked against the DEK length only; callers MUST
/// still verify `dek.commit() == manifest.dek_commit` (DESIGN §12.5 step 6).
pub fn unwrap_dek(
    recipient: &EncSecretKey,
    wrapped: &WrappedDek,
    ctx: &WrapContext,
) -> Result<Dek, CryptoError> {
    let sk = KemPriv::from_bytes(&recipient.0[..]).map_err(|_| CryptoError::BadPublicKey)?;
    let encapped = KemEncapped::from_bytes(&wrapped.enc).map_err(|_| CryptoError::WrapOpen)?;
    let info = encode(ctx);
    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &info,
        &wrapped.ct,
        &[],
    )
    .map_err(|_| CryptoError::WrapOpen)?;
    if pt.len() != 32 {
        return Err(CryptoError::BadLength);
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&pt);
    Ok(Dek::from_bytes(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_encoding::types::Id;

    fn ctx(recipient: u8) -> WrapContext {
        WrapContext {
            file_id: Id([0x11; 16]),
            version: 1,
            recipient_id: Id([recipient; 16]),
        }
    }

    #[test]
    fn wrap_then_unwrap_recovers_the_dek() {
        let (sk, pk) = generate_enc_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let c = ctx(0x55);
        let wrapped = wrap_dek(&pk, &dek, &c).unwrap();
        let out = unwrap_dek(&sk, &wrapped, &c).unwrap();
        assert_eq!(out.expose(), dek.expose());
    }

    #[test]
    fn unwrap_with_wrong_context_fails() {
        // The HPKE info is bound to (file_id, version, recipient_id): a mismatched
        // context cannot open the wrap (DESIGN §5 context binding / R19).
        let (sk, pk) = generate_enc_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let wrapped = wrap_dek(&pk, &dek, &ctx(0x55)).unwrap();
        assert_eq!(
            unwrap_dek(&sk, &wrapped, &ctx(0x56)).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let (_sk, pk) = generate_enc_keypair();
        let (other_sk, _other_pk) = generate_enc_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let wrapped = wrap_dek(&pk, &dek, &ctx(0x55)).unwrap();
        assert_eq!(
            unwrap_dek(&other_sk, &wrapped, &ctx(0x55)).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (sk, pk) = generate_enc_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let mut wrapped = wrap_dek(&pk, &dek, &ctx(0x55)).unwrap();
        let last = wrapped.ct.len() - 1;
        wrapped.ct[last] ^= 0x01;
        assert_eq!(
            unwrap_dek(&sk, &wrapped, &ctx(0x55)).map(|_| ()),
            Err(CryptoError::WrapOpen)
        );
    }

    #[test]
    fn encapsulation_is_randomized() {
        // Two wraps of the same DEK to the same recipient differ (fresh ephemeral).
        let (_sk, pk) = generate_enc_keypair();
        let dek = Dek::from_bytes([0x42; 32]);
        let a = wrap_dek(&pk, &dek, &ctx(0x55)).unwrap();
        let b = wrap_dek(&pk, &dek, &ctx(0x55)).unwrap();
        assert_ne!(a.enc, b.enc);
        assert_ne!(a.ct, b.ct);
    }
}
