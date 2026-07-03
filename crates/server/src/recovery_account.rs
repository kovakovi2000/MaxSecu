//! The single **recovery account** (T3): an escrow identity of which the server
//! persists ONLY its PUBLIC keys — an X25519 **encryption** pubkey (what recovery
//! challenges wrap to, and what clients compare against their embedded pin), an
//! Ed25519 **signing** pubkey, and an OPTIONAL ML-KEM-768 encapsulation pubkey
//! (the PQ-hybrid half, so recovery-wrapped uploads stay `Suite::V2` rather than
//! silently downgrading to classical V1). Registration is ONCE-ONLY: a second
//! attempt must not overwrite the stored keys. The store methods themselves live
//! on the [`Store`](crate::store::Store) trait next to the registration-key ones
//! they mirror; this module exercises them.

#[cfg(test)]
mod tests {
    use crate::store::{MemoryStore, RecoveryAccount, Store};
    use maxsecu_encoding::structs::MLKEM768_PUB_LEN;

    #[tokio::test]
    async fn recovery_account_is_none_before_any_set() {
        let s = MemoryStore::new();
        assert!(
            s.recovery_account().await.unwrap().is_none(),
            "no recovery account exists before any set"
        );
    }

    #[tokio::test]
    async fn registers_once_with_mlkem_and_round_trips() {
        let s = MemoryStore::new();
        let enc = [0x11u8; 32];
        let sig = [0x22u8; 32];
        let mlkem = [0x33u8; MLKEM768_PUB_LEN];
        assert!(
            s.set_recovery_account(enc, sig, Some(mlkem)).await.unwrap(),
            "the first registration wins"
        );
        assert_eq!(
            s.recovery_account().await.unwrap(),
            Some(RecoveryAccount {
                enc_pub: enc,
                sig_pub: sig,
                mlkem_pub: Some(mlkem),
            }),
            "the PQ-hybrid pubkeys (incl. ML-KEM) are served back verbatim"
        );
    }

    #[tokio::test]
    async fn registers_once_classical_only_mlkem_none() {
        let s = MemoryStore::new();
        let enc = [0x44u8; 32];
        let sig = [0x55u8; 32];
        assert!(s.set_recovery_account(enc, sig, None).await.unwrap());
        let got = s.recovery_account().await.unwrap().expect("registered");
        assert_eq!(got.enc_pub, enc);
        assert_eq!(got.sig_pub, sig);
        assert_eq!(
            got.mlkem_pub, None,
            "classical-only recovery has no ML-KEM key"
        );
    }

    #[tokio::test]
    async fn second_set_does_not_overwrite() {
        let s = MemoryStore::new();
        let enc = [0x11u8; 32];
        let sig = [0x22u8; 32];
        let mlkem = [0x33u8; MLKEM768_PUB_LEN];
        assert!(s
            .set_recovery_account(enc, sig, Some(mlkem))
            .await
            .unwrap());
        // A second attempt with DIFFERENT keys (and a different ML-KEM posture)
        // must lose and must NOT overwrite.
        assert!(
            !s.set_recovery_account([0xAAu8; 32], [0xBBu8; 32], None)
                .await
                .unwrap(),
            "a second registration is rejected (once-only)"
        );
        assert_eq!(
            s.recovery_account().await.unwrap(),
            Some(RecoveryAccount {
                enc_pub: enc,
                sig_pub: sig,
                mlkem_pub: Some(mlkem),
            }),
            "the ORIGINAL keys (incl. ML-KEM) are preserved (no overwrite)"
        );
    }
}
