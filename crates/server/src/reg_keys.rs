//! Single-use **registration keys** (T2): strong enrollment secrets of which the
//! server persists ONLY `sha256(key)` (never the plaintext). The store methods
//! themselves live on the [`Store`](crate::store::Store) trait; this module
//! exercises them and the atomic first-admin [`enroll`](crate::store::Store::enroll).

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

    // A distinct byte pattern per binding so the test can tell which one `enroll`
    // stored (the store never decodes these bytes — arbitrary is fine).
    fn bindings() -> (crate::store::StoredBinding, crate::store::StoredBinding) {
        use crate::store::StoredBinding;
        (
            StoredBinding {
                binding_bytes: vec![0xAA, 0xAA],
                signature: [0x11; 64],
            }, // {User}
            StoredBinding {
                binding_bytes: vec![0xDD, 0xDD],
                signature: [0x22; 64],
            }, // {User, Admin}
        )
    }

    #[tokio::test]
    async fn enroll_is_all_or_nothing_and_first_is_admin() {
        use crate::store::EnrollOutcome;
        let s = MemoryStore::new();
        let (ub, ab) = bindings();
        let kh = maxsecu_crypto::sha256(b"rk-1");

        // An invalid (unseeded) key writes NOTHING: no user, no binding.
        assert_eq!(
            s.enroll(kh, [7u8; 16], "alice", [1; 32], [2; 32], &ub, &ab)
                .await
                .unwrap(),
            EnrollOutcome::KeyInvalid
        );
        assert!(
            s.user_by_name("alice").await.unwrap().is_none(),
            "KeyInvalid created no user"
        );
        assert!(s.binding_by_username("alice").await.unwrap().is_none());

        // Seed the key; the FIRST enrollment claims admin and stores the ADMIN
        // binding, atomically consuming the key.
        s.issue_registration_key(kh, NEVER).await.unwrap();
        assert_eq!(
            s.enroll(kh, [7u8; 16], "alice", [1; 32], [2; 32], &ub, &ab)
                .await
                .unwrap(),
            EnrollOutcome::Enrolled { is_admin: true }
        );
        assert!(
            !s.consume_registration_key(&kh).await.unwrap(),
            "the key was consumed inside enroll (single-use)"
        );
        assert_eq!(
            s.binding_by_username("alice")
                .await
                .unwrap()
                .unwrap()
                .binding_bytes,
            vec![0xDD, 0xDD],
            "the admin binding was the one stored"
        );

        // A SECOND enrollment (fresh key, fresh id) is User-only → user binding.
        let kh2 = maxsecu_crypto::sha256(b"rk-2");
        s.issue_registration_key(kh2, NEVER).await.unwrap();
        assert_eq!(
            s.enroll(kh2, [8u8; 16], "bob", [3; 32], [4; 32], &ub, &ab)
                .await
                .unwrap(),
            EnrollOutcome::Enrolled { is_admin: false }
        );
        assert_eq!(
            s.binding_by_username("bob")
                .await
                .unwrap()
                .unwrap()
                .binding_bytes,
            vec![0xAA, 0xAA],
            "the user binding was the one stored"
        );
    }

    #[tokio::test]
    async fn enroll_username_taken_leaves_key_unconsumed() {
        use crate::store::EnrollOutcome;
        let s = MemoryStore::new();
        let (ub, ab) = bindings();
        // A pre-existing account holds the name.
        s.create_user("alice", [9; 32], [9; 32])
            .await
            .unwrap()
            .unwrap();
        let kh = maxsecu_crypto::sha256(b"rk");
        s.issue_registration_key(kh, NEVER).await.unwrap();

        // The username collision rolls the whole unit back — the key is NOT burned.
        assert_eq!(
            s.enroll(kh, [7u8; 16], "alice", [1; 32], [2; 32], &ub, &ab)
                .await
                .unwrap(),
            EnrollOutcome::UsernameTaken
        );
        // Proof the key survived: a retry with a FREE username succeeds on it.
        assert_eq!(
            s.enroll(kh, [7u8; 16], "carol", [1; 32], [2; 32], &ub, &ab)
                .await
                .unwrap(),
            EnrollOutcome::Enrolled { is_admin: true }
        );
    }
}
