//! The user's device-local identity (DESIGN §9.1): a random X25519 `enc`
//! keypair (unwrap DEKs) and a random Ed25519 `sig` keypair (auth + record
//! signing). Private halves never leave the device; they live only in RAM and,
//! at rest, sealed in the `local_key_blob` (see [`crate::keyblob`]).

use maxsecu_crypto::{
    fingerprint, generate_enc_keypair, EncPublicKey, EncSecretKey, SigningKey, VerifyingKey,
};

/// An unlocked identity: both keypairs in memory.
pub struct Identity {
    enc_sk: EncSecretKey,
    enc_pk: EncPublicKey,
    sig: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG (registration, §9.1 steps 1).
    pub fn generate() -> Identity {
        let (enc_sk, enc_pk) = generate_enc_keypair();
        Identity {
            enc_sk,
            enc_pk,
            sig: SigningKey::generate(),
        }
    }

    /// Reconstruct from raw secret bytes (used only by [`crate::keyblob`] on unlock).
    pub(crate) fn from_secret_bytes(
        enc_sk: [u8; 32],
        enc_pk: [u8; 32],
        sig_seed: [u8; 32],
    ) -> Identity {
        Identity {
            enc_sk: EncSecretKey::from_bytes(enc_sk),
            enc_pk: EncPublicKey::from_bytes(enc_pk),
            sig: SigningKey::from_seed(&sig_seed),
        }
    }

    // --- public material (safe to publish / send to the server) ---

    pub fn enc_pub_bytes(&self) -> [u8; 32] {
        self.enc_pk.to_bytes()
    }

    pub fn sig_pub_bytes(&self) -> [u8; 32] {
        self.sig.verifying_key().to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.sig.verifying_key()
    }

    /// The identity fingerprint confirmed in person at enrollment (DESIGN §7.1/D9):
    /// `SHA-256(canonical(fingerprint_input))`, rendered elsewhere as base64/QR.
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.enc_pub_bytes(), &self.sig_pub_bytes())
    }

    // --- operations (keys never leave the type, except keyblob sealing) ---

    /// The signing key, for building the login proof (§9.2) and record signatures.
    pub fn signing_key(&self) -> &SigningKey {
        &self.sig
    }

    /// The unwrap key, for opening HPKE-wrapped DEKs (§12.5).
    pub fn enc_secret(&self) -> &EncSecretKey {
        &self.enc_sk
    }

    // --- secret serialization (crate-internal, only for the at-rest blob) ---

    pub(crate) fn secret_bytes(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (
            self.enc_sk.expose_bytes(),
            self.enc_pk.to_bytes(),
            self.sig.to_seed(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_distinct_keypairs() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.enc_pub_bytes(), b.enc_pub_bytes());
        assert_ne!(a.sig_pub_bytes(), b.sig_pub_bytes());
        // enc and sig keys are independent (not the same 32 bytes).
        assert_ne!(a.enc_pub_bytes(), a.sig_pub_bytes());
    }

    #[test]
    fn from_secret_bytes_reconstructs_public_material() {
        let id = Identity::generate();
        let (esk, epk, seed) = id.secret_bytes();
        let id2 = Identity::from_secret_bytes(esk, epk, seed);
        assert_eq!(id.enc_pub_bytes(), id2.enc_pub_bytes());
        assert_eq!(id.sig_pub_bytes(), id2.sig_pub_bytes());
        assert_eq!(id.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let id = Identity::generate();
        assert_eq!(id.fingerprint(), id.fingerprint());
    }
}
