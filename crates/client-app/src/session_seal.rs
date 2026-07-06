//! Per-process ephemeral seal: a random AES-256-GCM key, RAM-only, never persisted.
//!
//! Full image/blog payloads (MediaCache `Content`) and feed-card meta (ThumbCache
//! `Card`) are sealed under it before they rest in a RAM/disk cache, so any OS
//! page-out / hibernation of the cache spills only ciphertext, and zeroizing this
//! key on close makes even a spilled copy unrecoverable.
//!
//! Reuses the workspace AEAD/RNG (`maxsecu_crypto`) — no new crypto dependency.
use maxsecu_crypto::{open, random_array, seal};
use zeroize::{Zeroize, Zeroizing};

/// A per-process ephemeral AES-256-GCM key. The `key` lives behind a `Mutex` for
/// interior mutability so the Exit hook (Task 7) can explicitly [`zeroize`] it in
/// place via `&self` while the managed `Arc<SessionSeal>` is still alive — a
/// managed-state drop is NOT guaranteed on shutdown, so relying on the `Zeroizing`
/// drop alone would not reliably wipe the key. The inner value stays [`Zeroizing`]
/// so a plain drop still wipes it (defense-in-depth). After the Exit hook runs, any
/// paged/hibernated sealed blob is unrecoverable.
pub struct SessionSeal {
    key: std::sync::Mutex<Zeroizing<[u8; 32]>>,
}

impl SessionSeal {
    /// Generate a fresh ephemeral key from the OS CSPRNG. Never persisted.
    pub fn generate() -> Self {
        Self {
            key: std::sync::Mutex::new(Zeroizing::new(random_array::<32>())),
        }
    }

    /// `random 12-byte nonce ‖ AES-256-GCM(key, nonce, aad=[], pt)`. A fresh
    /// random nonce per call means the same plaintext seals to different bytes.
    ///
    /// The 96-bit random nonce is safe for the expected ≪2^32 seals per process
    /// key (birthday bound; the bounded ephemeral caches never approach it). A
    /// future reader reusing this helper at much higher volume must reconsider.
    pub fn seal(&self, pt: &[u8]) -> Vec<u8> {
        let nonce = random_array::<12>();
        // Poison-safe: a panic elsewhere must not brick the seal (mirrors the old
        // ContentCache guard). The lock is brief and holds no `.await`.
        let guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = nonce.to_vec();
        out.extend_from_slice(&seal(&**guard, &nonce, &[], pt));
        out
    }

    /// Fail-closed unseal: too-short input, tamper, or wrong key → `None`. After
    /// [`zeroize`](Self::zeroize) the key is all-zeros, so a blob sealed before the
    /// wipe no longer opens (that is the point).
    pub fn open(&self, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if blob.len() < 12 {
            return None;
        }
        let (nonce, ct) = blob.split_at(12);
        let nonce: &[u8; 12] = nonce.try_into().ok()?;
        let guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        open(&**guard, nonce, &[], ct).ok().map(Zeroizing::new)
    }

    /// Explicitly wipe the key in place (overwrite with zeros). Called by the Exit
    /// hook (Task 7) via `&self` while the managed `Arc<SessionSeal>` is still
    /// alive — after this any paged/hibernated sealed blob is unrecoverable, and
    /// subsequent `open`s of pre-zeroize blobs fail closed.
    pub fn zeroize(&self) {
        let mut guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        (**guard).zeroize();
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
    #[test]
    fn empty_plaintext_round_trips() {
        let s = SessionSeal::generate();
        let blob = s.seal(b"");
        assert_eq!(&*s.open(&blob).unwrap(), b""); // zero-length seals/opens cleanly
    }
    #[test]
    fn exactly_nonce_len_blob_is_none() {
        let s = SessionSeal::generate();
        // 12 bytes passes the `< 12` guard but leaves no room for a GCM tag,
        // so the split path must still fail closed — not only the length guard.
        assert!(s.open(&[0u8; 12]).is_none());
    }
    #[test]
    fn zeroize_wipes_key_so_prior_blobs_no_longer_open() {
        let s = SessionSeal::generate();
        let blob = s.seal(b"card-meta");
        assert!(s.open(&blob).is_some(), "opens before the wipe");
        s.zeroize();
        // After the explicit wipe the key is all-zeros → the pre-wipe blob (sealed
        // under the original key) no longer authenticates.
        assert!(s.open(&blob).is_none(), "pre-zeroize blob is unrecoverable");
    }
}
