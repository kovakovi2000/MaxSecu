//! Randomized property tests for the Phase-1 client core: `local_key_blob`
//! round-trip / wrong-password rejection, and login-proof build→verify with
//! channel-binding (relay) resistance.

use maxsecu_client_core::{auth, identity::Identity, keyblob, ARGON2_FLOOR};
use proptest::prelude::*;

// A printable-ASCII passphrase of policy-valid length (>= 15).
fn passphrase() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[ -~]{15,40}").unwrap()
}

proptest! {
    // Login proof: build then verify holds for arbitrary contexts, and a proof
    // is bound to its exporter (a different channel never verifies).
    #[test]
    fn proof_build_verify_and_channel_binding(
        server_id in proptest::string::string_regex("[a-z0-9-]{1,32}").unwrap(),
        exporter in any::<[u8; 32]>(),
        other_exporter in any::<[u8; 32]>(),
        nonce in any::<[u8; 32]>(),
        ts in any::<u64>(),
    ) {
        prop_assume!(exporter != other_exporter);
        let id = Identity::generate();
        let proof = auth::build_login_proof(&id, &server_id, &exporter, &nonce, ts).unwrap();
        prop_assert!(
            auth::verify_login_proof(&id.sig_pub_bytes(), &server_id, &exporter, &nonce, ts, &proof).is_ok()
        );
        // Relayed to a different TLS channel ⇒ rejected.
        prop_assert!(
            auth::verify_login_proof(&id.sig_pub_bytes(), &server_id, &other_exporter, &nonce, ts, &proof).is_err()
        );
    }
}

proptest! {
    // Argon2id is memory-hard, so keep the case count modest.
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn keyblob_round_trips_and_rejects_wrong_password(
        pw in passphrase(),
        wrong in passphrase(),
    ) {
        prop_assume!(pw != wrong);
        let id = Identity::generate();
        let blob = keyblob::seal(&pw, &id, ARGON2_FLOOR).unwrap();
        let back = keyblob::unlock(&pw, &blob).unwrap();
        prop_assert_eq!(back.fingerprint(), id.fingerprint());
        prop_assert!(keyblob::unlock(&wrong, &blob).is_err());
    }
}
