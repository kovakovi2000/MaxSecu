//! Per-process ephemeral seal: a random AES-256-GCM key, RAM-only, never persisted.
//!
//! Full image/blog payloads (MediaCache `Content`) and feed-card meta (ThumbCache
//! `Card`) are sealed under it before they rest in a RAM/disk cache, so any OS
//! page-out / hibernation of the cache spills only ciphertext, and zeroizing this
//! key on close makes even a spilled copy unrecoverable.
//!
//! Reuses the workspace AEAD/RNG (`maxsecu_crypto`) — no new crypto dependency.
use maxsecu_crypto::{open, random_array, seal};
use zeroize::Zeroizing;

/// A per-process ephemeral AES-256-GCM key. The `key` is [`Zeroizing`], so
/// dropping the `SessionSeal` (which the Exit hook does in Task 7) wipes the key
/// from RAM automatically — no explicit `Drop` impl is needed.
pub struct SessionSeal {
    key: Zeroizing<[u8; 32]>,
}

impl SessionSeal {
    /// Generate a fresh ephemeral key from the OS CSPRNG. Never persisted.
    pub fn generate() -> Self {
        Self {
            key: Zeroizing::new(random_array::<32>()),
        }
    }

    /// `random 12-byte nonce ‖ AES-256-GCM(key, nonce, aad=[], pt)`. A fresh
    /// random nonce per call means the same plaintext seals to different bytes.
    pub fn seal(&self, pt: &[u8]) -> Vec<u8> {
        let nonce = random_array::<12>();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&seal(&self.key, &nonce, &[], pt));
        out
    }

    /// Fail-closed unseal: too-short input, tamper, or wrong key → `None`.
    pub fn open(&self, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if blob.len() < 12 {
            return None;
        }
        let (nonce, ct) = blob.split_at(12);
        let nonce: &[u8; 12] = nonce.try_into().ok()?;
        open(&self.key, nonce, &[], ct).ok().map(Zeroizing::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seal_open_round_trips() {
        let s = SessionSeal::generate();
        let pt = b"card-meta-or-content-bytes".to_vec();
        let blob = s.seal(&pt);
        assert_ne!(blob, pt); // not plaintext
        assert_eq!(&*s.open(&blob).unwrap(), &pt[..]);
    }
    #[test]
    fn distinct_nonces_per_seal() {
        let s = SessionSeal::generate();
        assert_ne!(s.seal(b"x"), s.seal(b"x")); // random nonce → different ciphertext
    }
    #[test]
    fn tampered_blob_fails() {
        let s = SessionSeal::generate();
        let mut blob = s.seal(b"hello");
        *blob.last_mut().unwrap() ^= 0xff;
        assert!(s.open(&blob).is_none());
    }
    #[test]
    fn wrong_key_fails() {
        let a = SessionSeal::generate();
        let b = SessionSeal::generate();
        assert!(b.open(&a.seal(b"hello")).is_none());
    }
    #[test]
    fn truncated_blob_is_none() {
        let s = SessionSeal::generate();
        assert!(s.open(&[0u8; 4]).is_none()); // shorter than nonce
    }
}
