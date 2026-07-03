//! Single-use **registration keys** (T2): strong enrollment secrets of which the
//! server persists ONLY `sha256(key)` (never the plaintext), plus a cheap
//! "does any user exist yet?" probe used to decide the first-admin. The store
//! methods themselves live on the [`Store`](crate::store::Store) trait next to
//! the enrollment-voucher ones they mirror; this module exercises them.

#[cfg(test)]
mod tests {
    use crate::store::{MemoryStore, Store};

    // A far-future absolute expiry so the TTL predicate never trips in tests
    // (mirrors the voucher tests' `4_102_444_800_000` = year 2100).
    const NEVER: u64 = 4_102_444_800_000;

    #[tokio::test]
    async fn registration_key_is_single_use() {
        let s = MemoryStore::new();
        let h = maxsecu_crypto::sha256(b"reg-key-abc");
        s.issue_registration_key(h, NEVER).await.unwrap();
        assert!(
            s.consume_registration_key(&h).await.unwrap(),
            "fresh issued registration key consumes"
        );
        assert!(
            !s.consume_registration_key(&h).await.unwrap(),
            "second consume fails (single-use / deleted on consume)"
        );
    }

    #[tokio::test]
    async fn unknown_registration_key_does_not_consume() {
        let s = MemoryStore::new();
        let h = maxsecu_crypto::sha256(b"never-issued");
        assert!(
            !s.consume_registration_key(&h).await.unwrap(),
            "an unknown hash consumes to false"
        );
    }

    #[tokio::test]
    async fn any_user_exists_flips_on_first_user() {
        let s = MemoryStore::new();
        assert!(
            !s.any_user_exists().await.unwrap(),
            "no user exists before the first is created"
        );
        s.create_user("alice", [1u8; 32], [2u8; 32])
            .await
            .unwrap()
            .expect("username is free");
        assert!(
            s.any_user_exists().await.unwrap(),
            "a user exists after create_user"
        );
    }
}
