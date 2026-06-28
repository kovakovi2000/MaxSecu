//! Login orchestration. The transport does challenge→proof; this module builds
//! the channel-bound proof from the unlocked Identity and the live exporter.

use maxsecu_client_core::auth::build_login_proof;
use maxsecu_client_core::Identity;
use crate::error::UiError;

/// Build the base64 proof the client posts to /v1/session/proof.
pub fn make_proof(
    id: &Identity,
    server_id: &str,
    exporter: &[u8; 32],
    nonce: &[u8; 32],
    timestamp_ms: u64,
) -> Result<[u8; 64], UiError> {
    build_login_proof(id, server_id, exporter, nonce, timestamp_ms)
        .map_err(|_| UiError::new("unauthorized", "Sign-in failed."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::auth::verify_login_proof;

    #[test]
    fn built_proof_verifies_like_the_server_would() {
        let id = Identity::generate();
        let server_id = "maxsecu-test-1";
        let exporter = [0x42u8; 32];
        let nonce = [0x07u8; 32];
        let ts = 1_719_500_000_000u64;
        let proof = make_proof(&id, server_id, &exporter, &nonce, ts).unwrap();
        // Exactly what the server runs in api.md §2.2:
        assert!(verify_login_proof(&id.sig_pub_bytes(), server_id, &exporter, &nonce, ts, &proof).is_ok());
    }

    #[test]
    fn proof_is_channel_bound() {
        let id = Identity::generate();
        let proof = make_proof(&id, "s", &[1u8; 32], &[2u8; 32], 1).unwrap();
        // A different exporter (relayed connection) must not verify.
        assert!(verify_login_proof(&id.sig_pub_bytes(), "s", &[9u8; 32], &[2u8; 32], 1, &proof).is_err());
    }
}
