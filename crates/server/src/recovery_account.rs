//! The single **recovery account** (T3): an escrow identity of which the server
//! persists ONLY its two PUBLIC keys — an X25519 **encryption** pubkey (what
//! recovery challenges wrap to, and what clients compare against their embedded
//! pin) and an Ed25519 **signing** pubkey. Registration is ONCE-ONLY: a second
//! attempt must not overwrite the stored keys. The store methods themselves live
//! on the [`Store`](crate::store::Store) trait next to the registration-key ones
//! they mirror; this module exercises them.

#[cfg(test)]
mod tests {
    use crate::store::{MemoryStore, Store};

    #[tokio::test]
    async fn recovery_account_is_none_before_any_set() {
        let s = MemoryStore::new();
        assert!(
            s.recovery_account().await.unwrap().is_none(),
            "no recovery account exists before any set"
        );
    }

    #[tokio::test]
    async fn recovery_account_registers_once_and_returns_pubkeys() {
        let s = MemoryStore::new();
        let enc = [0x11u8; 32];
        let sig = [0x22u8; 32];
        assert!(
            s.set_recovery_account(enc, sig).await.unwrap(),
            "the first registration wins"
        );
        assert_eq!(
            s.recovery_account().await.unwrap(),
            Some((enc, sig)),
            "the stored pubkeys are served back verbatim"
        );
    }

    #[tokio::test]
    async fn second_set_does_not_overwrite() {
        let s = MemoryStore::new();
        let enc = [0x11u8; 32];
        let sig = [0x22u8; 32];
        assert!(s.set_recovery_account(enc, sig).await.unwrap());
        // A second attempt with DIFFERENT keys must lose and must NOT overwrite.
        assert!(
            !s.set_recovery_account([0xAAu8; 32], [0xBBu8; 32])
                .await
                .unwrap(),
            "a second registration is rejected (once-only)"
        );
        assert_eq!(
            s.recovery_account().await.unwrap(),
            Some((enc, sig)),
            "the ORIGINAL keys are preserved (no overwrite)"
        );
    }
}
