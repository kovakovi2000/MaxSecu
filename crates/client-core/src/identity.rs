//! The user's device-local identity (DESIGN §9.1): a random X25519 `enc`
//! keypair (unwrap DEKs), a random Ed25519 `sig` keypair (auth + record
//! signing), and — for PQ-enrolled identities (Phase 7) — a random ML-KEM-768
//! keypair. The single X25519 `enc` key doubles as the classical leg of the
//! Suite::V2 hybrid wrap, so a PQ identity adds *only* the ML-KEM half (there is
//! never a second, throwaway X25519 key). Private halves never leave the device;
//! they live only in RAM and, at rest, sealed in the `local_key_blob` (see
//! [`crate::keyblob`]).

use maxsecu_crypto::{
    fingerprint, generate_enc_keypair, generate_mlkem_keypair, mlkem_public_from_seed,
    EncPublicKey, EncSecretKey, SigningKey, VerifyingKey,
};
use zeroize::Zeroizing;

/// The ML-KEM-768 half of a PQ-enrolled identity: the 64-byte decapsulation-key
/// seed (secret, zeroized) and the derived 1184-byte encapsulation (public) key.
struct MlKemKeypair {
    seed: Zeroizing<[u8; 64]>,
    public: [u8; 1184],
}

/// An unlocked identity: the X25519 `enc` keypair, the Ed25519 `sig` keypair,
/// and (for a PQ-enrolled / v2-blob identity) the ML-KEM-768 keypair.
pub struct Identity {
    enc_sk: EncSecretKey,
    enc_pk: EncPublicKey,
    sig: SigningKey,
    /// `Some` for a freshly-generated or v2-blob identity; `None` after loading a
    /// legacy v1 blob (which predates PQ enrollment).
    mlkem: Option<MlKemKeypair>,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG (registration, §9.1 steps 1).
    /// Every fresh identity is PQ-capable: it always gets an ML-KEM-768 keypair.
    pub fn generate() -> Identity {
        let (enc_sk, enc_pk) = generate_enc_keypair();
        let (mlkem_seed, mlkem_pub) = generate_mlkem_keypair();
        Identity {
            enc_sk,
            enc_pk,
            sig: SigningKey::generate(),
            mlkem: Some(MlKemKeypair {
                seed: Zeroizing::new(mlkem_seed),
                public: mlkem_pub,
            }),
        }
    }

    /// Reconstruct from raw secret bytes (used only by [`crate::keyblob`] on
    /// unlock). `mlkem_seed` is `Some` for a v2 blob (PQ) and `None` for a legacy
    /// v1 blob; when present, the ML-KEM public key is re-derived from the seed.
    pub(crate) fn from_secret_bytes(
        enc_sk: [u8; 32],
        enc_pk: [u8; 32],
        sig_seed: [u8; 32],
        mlkem_seed: Option<[u8; 64]>,
    ) -> Identity {
        let mlkem = mlkem_seed.map(|seed| MlKemKeypair {
            // Any 64 bytes are a valid ML-KEM seed (FIPS 203 deterministic
            // expansion); reconstruction cannot fail on a fixed-length seed.
            public: mlkem_public_from_seed(&seed)
                .expect("64-byte ML-KEM seed always derives a public key"),
            seed: Zeroizing::new(seed),
        });
        Identity {
            enc_sk: EncSecretKey::from_bytes(enc_sk),
            enc_pk: EncPublicKey::from_bytes(enc_pk),
            sig: SigningKey::from_seed(&sig_seed),
            mlkem,
        }
    }

    /// Test-support: reconstruct an [`Identity`] from raw secret seeds — the
    /// X25519 `enc` scalar, an Ed25519 `sig` seed, and the ML-KEM-768 `mlkem`
    /// seed. Both public keys are re-derived from their seeds. Gated behind
    /// `test-support`, so it is compiled out of production builds entirely
    /// (mirroring how the recovery-pin *private* seeds are `unpinned-dev`-only).
    ///
    /// The single use is the holistic e2e (`client-e2e/full_flow_e2e.rs`), which
    /// must register the singleton recovery account AND drive the recovery login
    /// with the SAME keypair whose enc half equals the embedded (unpinned-dev)
    /// recovery pin. The pin is enc-only, so a login — which also *signs* the
    /// channel-bound proof — needs a chosen signing seed alongside the fixed enc
    /// seeds. **NEVER call this on a real key; it takes raw secret bytes.**
    #[cfg(feature = "test-support")]
    pub fn from_test_seeds(
        x25519_secret: [u8; 32],
        sig_seed: [u8; 32],
        mlkem_seed: [u8; 64],
    ) -> Identity {
        let enc_pk = maxsecu_crypto::x25519_public_from_secret(&x25519_secret);
        Identity::from_secret_bytes(x25519_secret, enc_pk, sig_seed, Some(mlkem_seed))
    }

    // --- public material (safe to publish / send to the server) ---

    pub fn enc_pub_bytes(&self) -> [u8; 32] {
        self.enc_pk.to_bytes()
    }

    /// The ML-KEM-768 encapsulation (public) key for a PQ-enrolled identity, to
    /// publish in the directory binding (`mlkem_pub`). `None` for a v1-blob
    /// identity. Not part of the fingerprint (§7.1).
    pub fn mlkem_pub_bytes(&self) -> Option<[u8; 1184]> {
        self.mlkem.as_ref().map(|m| m.public)
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

    /// The 64-byte ML-KEM-768 decapsulation-key seed, for a PQ-enrolled identity
    /// (`None` for a legacy v1-blob identity). This is the post-quantum leg of the
    /// hybrid unwrap key: paired with [`Self::enc_secret`] it opens a `Suite::V2`
    /// hybrid wrap on a *local* download (`VerifyContext.recipient_mlkem_seed`).
    ///
    /// Like [`maxsecu_crypto::EncSecretKey::expose_bytes`] (and the X25519 secret it
    /// already reaches), this exposes secret key material: **never send this
    /// anywhere**. It is only for the at-rest `local_key_blob` and the local hybrid
    /// download/unwrap path; it never leaves the device.
    pub fn mlkem_seed(&self) -> Option<[u8; 64]> {
        self.mlkem.as_ref().map(|m| *m.seed)
    }

    // --- secret serialization (crate-internal, only for the at-rest blob) ---

    /// The X25519 secret, X25519 public, Ed25519 seed, and — for a PQ identity —
    /// the ML-KEM seed. Consumed only by [`crate::keyblob::seal`].
    pub(crate) fn secret_bytes(&self) -> ([u8; 32], [u8; 32], [u8; 32], Option<[u8; 64]>) {
        (
            self.enc_sk.expose_bytes(),
            self.enc_pk.to_bytes(),
            self.sig.to_seed(),
            self.mlkem_seed(),
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
        let (esk, epk, seed, mlkem_seed) = id.secret_bytes();
        let id2 = Identity::from_secret_bytes(esk, epk, seed, mlkem_seed);
        assert_eq!(id.enc_pub_bytes(), id2.enc_pub_bytes());
        assert_eq!(id.sig_pub_bytes(), id2.sig_pub_bytes());
        assert_eq!(id.fingerprint(), id2.fingerprint());
        // The ML-KEM half round-trips too (seed re-derives the same public key).
        assert_eq!(id.mlkem_pub_bytes(), id2.mlkem_pub_bytes());
        assert!(id2.mlkem_pub_bytes().is_some());
    }

    #[test]
    fn from_secret_bytes_without_mlkem_yields_no_pq_key() {
        // A v1-blob reconstruction (no ML-KEM seed) ⇒ a non-PQ identity.
        let id = Identity::generate();
        let (esk, epk, seed, _) = id.secret_bytes();
        let v1 = Identity::from_secret_bytes(esk, epk, seed, None);
        assert!(v1.mlkem_pub_bytes().is_none());
        // The classical material is unaffected.
        assert_eq!(v1.enc_pub_bytes(), id.enc_pub_bytes());
        assert_eq!(v1.fingerprint(), id.fingerprint());
    }

    #[test]
    fn identity_has_hybrid_enc_key() {
        // A fresh identity exposes both an X25519 enc key and an ML-KEM-768 key,
        // and the two halves pair into a working hybrid recipient: a wrap to
        // {enc_pub, mlkem_pub} unwraps with {enc_secret, mlkem_seed}.
        use maxsecu_crypto::{
            unwrap_dek_hybrid, wrap_dek_hybrid, Dek, HybridEncPublicKey, HybridEncSecretKey,
        };
        use maxsecu_encoding::structs::WrapContext;
        use maxsecu_encoding::types::Id;

        let id = Identity::generate();
        let pk = HybridEncPublicKey {
            x25519: id.enc_pub_bytes(),
            mlkem: id.mlkem_pub_bytes().unwrap(),
        };
        let sk = HybridEncSecretKey::from_components(
            id.enc_secret().expose_bytes(),
            id.mlkem_seed().unwrap(),
        );
        let dek = Dek::from_bytes([0x33; 32]);
        let ctx = WrapContext {
            file_id: Id([1; 16]),
            version: 1,
            recipient_id: Id([2; 16]),
        };
        let w = wrap_dek_hybrid(&pk, &dek, &ctx).unwrap();
        assert_eq!(
            unwrap_dek_hybrid(&sk, &w, &ctx).unwrap().expose(),
            dek.expose()
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let id = Identity::generate();
        assert_eq!(id.fingerprint(), id.fingerprint());
    }
}
