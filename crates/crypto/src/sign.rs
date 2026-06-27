//! Ed25519 (DESIGN §5): challenge-response auth and all record signatures.
//! Verification is **strict** (`verify_strict`) to reject malleable encodings
//! (stack §1.3). Every signed message is the domain-separated, length-framed
//! `signing_input` (encoding-spec §6).

use crate::rng::random_array;
use crate::CryptoError;
use ed25519_dalek::{Signature, Signer};
use maxsecu_encoding::{signing_message, Canonical};

/// An Ed25519 signing key (private). Zeroized on drop by `ed25519-dalek`.
pub struct SigningKey(ed25519_dalek::SigningKey);

/// An Ed25519 verifying key (public).
#[derive(Clone)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl SigningKey {
    /// Fresh random key from the OS CSPRNG.
    pub fn generate() -> SigningKey {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(&random_array::<32>()))
    }

    /// Deterministic key from a 32-byte seed (e.g. an unlocked `local_key_blob`).
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Expose the 32-byte Ed25519 seed — only for sealing into the on-device
    /// `local_key_blob` (DESIGN §9.1). Never send this anywhere.
    pub fn to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Sign a raw message (used for the auth challenge, which is assembled by
    /// the caller). Prefer [`SigningKey::sign_canonical`] for record signatures.
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }

    /// Sign a canonical record under its domain-separation `label` — i.e. over
    /// `signing_input(label, encode(v))` (encoding-spec §6).
    pub fn sign_canonical<T: Canonical>(&self, label: &str, v: &T) -> [u8; 64] {
        self.sign_raw(&signing_message(label, v))
    }
}

impl VerifyingKey {
    pub fn from_bytes(b: &[u8; 32]) -> Result<VerifyingKey, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(b)
            .map(VerifyingKey)
            .map_err(|_| CryptoError::BadPublicKey)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Strictly verify a raw-message signature.
    pub fn verify_raw(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), CryptoError> {
        let s = Signature::from_bytes(sig);
        self.0
            .verify_strict(msg, &s)
            .map_err(|_| CryptoError::Signature)
    }

    /// Strictly verify a canonical record signature under its `label`.
    pub fn verify_canonical<T: Canonical>(
        &self,
        label: &str,
        v: &T,
        sig: &[u8; 64],
    ) -> Result<(), CryptoError> {
        self.verify_raw(&signing_message(label, v), sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_encoding::labels;
    use maxsecu_encoding::structs::Genesis;
    use maxsecu_encoding::types::{Id, Timestamp};

    fn genesis() -> Genesis {
        Genesis {
            file_id: Id([0x11; 16]),
            owner_id: Id([0x22; 16]),
            owner_key_version: 1,
            created_at: Timestamp(1_700_000_000_000),
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let g = genesis();
        let sig = sk.sign_canonical(labels::GENESIS, &g);
        assert!(vk.verify_canonical(labels::GENESIS, &g, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_value() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign_canonical(labels::GENESIS, &genesis());
        let mut tampered = genesis();
        tampered.owner_key_version = 2;
        assert_eq!(
            vk.verify_canonical(labels::GENESIS, &tampered, &sig),
            Err(CryptoError::Signature)
        );
    }

    #[test]
    fn verify_rejects_wrong_domain_label() {
        // A genesis signature must not verify under a different role's label
        // (the V-9 domain-separation property, enforced at the crypto layer).
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let g = genesis();
        let sig = sk.sign_canonical(labels::GENESIS, &g);
        assert_eq!(
            vk.verify_canonical(labels::REVOCATION, &g, &sig),
            Err(CryptoError::Signature)
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk = SigningKey::generate();
        let other = SigningKey::generate();
        let g = genesis();
        let sig = sk.sign_canonical(labels::GENESIS, &g);
        assert_eq!(
            other
                .verifying_key()
                .verify_canonical(labels::GENESIS, &g, &sig),
            Err(CryptoError::Signature)
        );
    }

    #[test]
    fn seed_round_trip_reconstructs_key() {
        let sk = SigningKey::generate();
        let sk2 = SigningKey::from_seed(&sk.to_seed());
        assert_eq!(
            sk.verifying_key().to_bytes(),
            sk2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn verifying_key_serializes_round_trip() {
        let sk = SigningKey::from_seed(&[3u8; 32]);
        let vk = sk.verifying_key();
        let bytes = vk.to_bytes();
        let vk2 = VerifyingKey::from_bytes(&bytes).unwrap();
        let g = genesis();
        let sig = sk.sign_canonical(labels::GENESIS, &g);
        assert!(vk2.verify_canonical(labels::GENESIS, &g, &sig).is_ok());
    }
}
