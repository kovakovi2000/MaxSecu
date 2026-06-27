//! The per-file Data Encryption Key and its derivations (DESIGN §5/§12.3/§13).
//!
//! The DEK is **only ever a KDF root** (L-5/R33): the content/metadata/thumbnail/
//! preview AEAD keys and the `dek_commit` are all `HKDF(DEK, "MaxSecu-<…>-v1")`,
//! never the raw DEK directly.

use crate::hash::sha256;
use crate::kdf::hkdf_sha256_32;
use crate::rng::random_array;
use maxsecu_encoding::encode;
use maxsecu_encoding::structs::FingerprintInput;
use maxsecu_encoding::types::{Bytes32, StreamType};
use zeroize::Zeroizing;

/// `info` for the DEK commitment (DESIGN §12.3).
const DEK_COMMIT_INFO: &[u8] = b"MaxSecu-dek-commit-v1";

/// The per-stream subkey `info` label (DESIGN §13 / D33 / encoding-spec §6).
fn stream_info(t: StreamType) -> &'static [u8] {
    match t {
        StreamType::Content => b"MaxSecu-content-v1",
        StreamType::Metadata => b"MaxSecu-metadata-v1",
        StreamType::Thumbnail => b"MaxSecu-thumbnail-v1",
        StreamType::Preview => b"MaxSecu-preview-v1",
    }
}

/// A 256-bit per-file DEK, zeroized on drop.
pub struct Dek(Zeroizing<[u8; 32]>);

impl Dek {
    /// Fresh random DEK from the OS CSPRNG (parameters §1.2).
    pub fn generate() -> Dek {
        Dek(Zeroizing::new(random_array::<32>()))
    }

    /// Reconstruct a DEK from raw bytes (e.g. after an HPKE unwrap).
    pub fn from_bytes(b: [u8; 32]) -> Dek {
        Dek(Zeroizing::new(b))
    }

    /// The raw DEK bytes (only for wrapping / KDF roots — never an AEAD key).
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// `dek_commit = HKDF-SHA256(DEK, "MaxSecu-dek-commit-v1", 32)` (DESIGN §12.3).
    /// A derived commitment, not a hash of the raw key (R12).
    pub fn commit(&self) -> [u8; 32] {
        hkdf_sha256_32(self.expose(), DEK_COMMIT_INFO)
    }

    /// The per-stream AEAD subkey `ck_<type> = HKDF(DEK, "MaxSecu-<type>-v1", 32)`.
    pub fn stream_subkey(&self, t: StreamType) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(hkdf_sha256_32(self.expose(), stream_info(t)))
    }
}

/// Identity fingerprint `SHA-256(canonical(fingerprint_input))` (DESIGN §7.1).
/// The value confirmed in person at enrollment (D9).
pub fn fingerprint(enc_pub: &[u8; 32], sig_pub: &[u8; 32]) -> [u8; 32] {
    sha256(&encode(&FingerprintInput {
        enc_pub: Bytes32(*enc_pub),
        sig_pub: Bytes32(*sig_pub),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_is_deterministic_and_not_raw_key() {
        let dek = Dek::from_bytes([9u8; 32]);
        assert_eq!(dek.commit(), dek.commit());
        assert_ne!(dek.commit(), *dek.expose());
    }

    #[test]
    fn distinct_deks_have_distinct_commitments() {
        assert_ne!(
            Dek::from_bytes([1u8; 32]).commit(),
            Dek::from_bytes([2u8; 32]).commit()
        );
    }

    #[test]
    fn each_stream_has_an_independent_subkey() {
        let dek = Dek::from_bytes([5u8; 32]);
        let c = dek.stream_subkey(StreamType::Content);
        let m = dek.stream_subkey(StreamType::Metadata);
        let t = dek.stream_subkey(StreamType::Thumbnail);
        let p = dek.stream_subkey(StreamType::Preview);
        // All four disjoint, and none equals the commitment or the raw DEK.
        let keys = [*c, *m, *t, *p];
        for i in 0..keys.len() {
            assert_ne!(keys[i], *dek.expose());
            assert_ne!(keys[i], dek.commit());
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "stream subkeys must be independent");
            }
        }
    }

    #[test]
    fn fingerprint_matches_sha256_of_canonical_input() {
        let enc = [0xE1u8; 32];
        let sig = [0x51u8; 32];
        let fp = fingerprint(&enc, &sig);
        let expected = sha256(&encode(&FingerprintInput {
            enc_pub: Bytes32(enc),
            sig_pub: Bytes32(sig),
        }));
        assert_eq!(fp, expected);
        // Order matters: swapping the keys changes the fingerprint.
        assert_ne!(fp, fingerprint(&sig, &enc));
    }
}
