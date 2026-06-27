//! SHA-256 (DESIGN §5): content/manifest digests, fingerprints, tombstone chain.

use sha2::{Digest, Sha256};

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_abc() {
        // FIPS 180-4 / NIST: SHA-256("abc").
        let got = sha256(b"abc");
        let want = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn empty_input_known_answer() {
        // SHA-256("") = e3b0c442...
        let got = sha256(b"");
        assert_eq!(got[0..4], [0xe3, 0xb0, 0xc4, 0x42]);
    }
}
