//! The D5 directory-signing key and the enrollment ceremony (DESIGN §7.1/§12.1).

use crate::CeremonyError;
use maxsecu_crypto::{fingerprint, CryptoError, SigningKey, VerifyingKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::MlKemPub;

/// The offline **directory-signing key** (D5). It signs username→keys identity
/// bindings and nothing else; its public half is the pinned trust root compiled
/// into every client (§7.3). Kept air-gapped — this type models the key *at the
/// ceremony*, not on any networked machine.
pub struct DirectorySigner(SigningKey);

impl DirectorySigner {
    /// Fresh random D5 key (key-generation ceremony).
    pub fn generate() -> DirectorySigner {
        DirectorySigner(SigningKey::generate())
    }

    /// Reconstruct D5 from its 32-byte Ed25519 seed (sealed cold backup, §16.3).
    pub fn from_seed(seed: &[u8; 32]) -> DirectorySigner {
        DirectorySigner(SigningKey::from_seed(seed))
    }

    /// The directory-signing **public** key — the value clients pin (§7.3) and
    /// verify every binding against (§7.2 step 2).
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign a binding into the directory (`"MaxSecu-dirbinding-v1"`, §7.1),
    /// carrying an optional ML-KEM-768 encapsulation key for a PQ-enrolled
    /// identity (Phase 7, P7.4). `mlkem_pub` is written into the binding before
    /// signing, so the existing D5 Ed25519 signature over `canonical(binding)`
    /// authenticates the PQ field for free — no new signature semantics. Pass
    /// `None` for a classical (v1) binding. The caller is responsible for the
    /// fingerprint confirmation; prefer [`DirectorySigner::sign_enrollment`],
    /// which enforces it.
    pub fn sign_binding(
        &self,
        binding: &DirBinding,
        mlkem_pub: Option<MlKemPub>,
    ) -> SignedBinding {
        let mut binding = binding.clone();
        binding.mlkem_pub = mlkem_pub;
        SignedBinding {
            signature: self.0.sign_canonical(labels::DIRBINDING, &binding),
            binding,
        }
    }

    /// Sign a binding **only if** its key-pair fingerprint matches the value the
    /// admin confirmed in person (§12.1 / D9). A mismatch is a hard refusal — the
    /// MITM defense: a server-substituted key never gets an offline signature.
    pub fn sign_enrollment(
        &self,
        binding: &DirBinding,
        confirmed_fingerprint: &[u8; 32],
    ) -> Result<SignedBinding, CeremonyError> {
        if &fingerprint(&binding.enc_pub.0, &binding.sig_pub.0) != confirmed_fingerprint {
            return Err(CeremonyError::FingerprintMismatch);
        }
        // Preserve any PQ key already present on the binding (the fingerprint
        // covers only enc_pub ‖ sig_pub, so the ML-KEM key is orthogonal to it).
        Ok(self.sign_binding(binding, binding.mlkem_pub))
    }
}

/// A directory binding plus its offline D5 signature — the unit the server
/// stores and serves verbatim (`directory_bindings`), and clients verify against
/// the pinned root before trusting the bound keys (§7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBinding {
    pub binding: DirBinding,
    pub signature: [u8; 64],
}

impl SignedBinding {
    /// The in-person identity fingerprint `SHA-256(canonical(enc_pub ‖ sig_pub))`
    /// (§7.1) — what the admin confirms and a client may display on key change.
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.binding.enc_pub.0, &self.binding.sig_pub.0)
    }

    /// Verify the binding under a directory-signing public key (the pinned root).
    /// Fails closed on a malformed key or a bad/forged signature.
    pub fn verify(&self, dir_pub: &[u8; 32]) -> Result<(), CryptoError> {
        VerifyingKey::from_bytes(dir_pub)?.verify_canonical(
            labels::DIRBINDING,
            &self.binding,
            &self.signature,
        )
    }
}
