//! Post-quantum hybrid DEK wrap (DESIGN §5 / stack.md §1.3, Phase 7).
//!
//! Phase 7 wraps the per-file DEK under a *hybrid* KEM: the classical X25519
//! (dalek) half AND the post-quantum FIPS 203 ML-KEM-768 (RustCrypto `ml-kem`)
//! half, so that a future quantum adversary who breaks X25519 still cannot
//! recover the DEK without also breaking ML-KEM (and vice-versa).
//!
//! P7.1 only *adopts and vets* the `ml-kem` crate (the central supply-chain
//! risk): it is pure-Rust, pulls no C/`*-sys`/second-TLS dependency, and clears
//! `cargo deny`/`cargo audit`. The real hybrid wrap/unwrap lands in P7.2 — this
//! module currently carries only the keygen/encaps/decaps smoke test that proves
//! the KEM round-trips and the adopted API works (sender SS == receiver SS).

#[cfg(test)]
mod tests {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{Kem, MlKem768};

    /// ML-KEM-768 (FIPS 203) keygen → encapsulate → decapsulate round-trips, and
    /// the sender's and receiver's shared secrets are byte-equal.
    ///
    /// This is the P7.1 adoption smoke test: it asserts the KEM CONTRACT we will
    /// build the hybrid wrap on — `k_send == k_recv` — using the OS-RNG-backed
    /// convenience API the adopted `ml-kem` 0.3 exposes under its `getrandom`
    /// feature (no explicit RNG handle to thread).
    #[test]
    fn mlkem_keygen_encaps_decaps_roundtrip() {
        // Receiver generates a (decapsulation, encapsulation) keypair.
        let (dk, ek) = MlKem768::generate_keypair();

        // Sender encapsulates to the public encapsulation key, obtaining the
        // ciphertext and the sender-side shared secret.
        let (ct, k_send) = ek.encapsulate();

        // Receiver decapsulates with the secret decapsulation key.
        let k_recv = dk.decapsulate(&ct);

        // CONTRACT: sender shared secret == receiver shared secret.
        assert_eq!(k_send, k_recv, "ML-KEM-768 shared secrets must match");
    }
}
