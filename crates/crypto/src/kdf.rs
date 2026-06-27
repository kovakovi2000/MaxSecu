//! HKDF-SHA256 (DESIGN §5 / parameters §1.3): all subkey and commitment
//! derivations expand to `L = 32`. Salt is empty — the design derives every
//! subkey from a high-entropy root (the DEK) under a distinct `info` label, so
//! extract-with-zero-salt then expand is the standard construction.

use hkdf::Hkdf;
use sha2::Sha256;

/// `HKDF-SHA256(ikm, info, L = 32)` with an empty salt.
pub fn hkdf_sha256_32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is within HKDF's 255*HashLen output limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = hkdf_sha256_32(b"root-key-material", b"MaxSecu-content-v1");
        let b = hkdf_sha256_32(b"root-key-material", b"MaxSecu-content-v1");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_info_yields_distinct_keys() {
        // Domain separation: different `info` ⇒ independent PRF outputs (§5.1 note).
        let ck = hkdf_sha256_32(b"root", b"MaxSecu-content-v1");
        let mk = hkdf_sha256_32(b"root", b"MaxSecu-metadata-v1");
        assert_ne!(ck, mk);
    }

    #[test]
    fn output_is_not_the_ikm() {
        let ikm = [7u8; 32];
        assert_ne!(hkdf_sha256_32(&ikm, b"MaxSecu-dek-commit-v1"), ikm);
    }
}
