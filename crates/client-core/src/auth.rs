//! Login proof — the channel-bound challenge-response (DESIGN §9.2).
//!
//! The client signs `auth_proof_context = {server_id, tls_exporter, nonce,
//! timestamp}` (encoding-spec §4) under the `"MaxSecu-auth-v1"` label. Binding
//! the **TLS exporter** (RFC 5705) makes the proof non-relayable to another
//! connection; the single-use `nonce` makes it non-replayable. The `tls_exporter`
//! is supplied by the transport layer (rustls `export_keying_material`); these
//! functions are pure and testable without a live TLS stack.

use crate::error::ClientError;
use crate::identity::Identity;
use maxsecu_crypto::VerifyingKey;
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::AuthProofContext;
use maxsecu_encoding::types::{Bytes32, Text, Timestamp};

fn context(
    server_id: &str,
    tls_exporter: &[u8; 32],
    nonce: &[u8; 32],
    timestamp: u64,
) -> Result<AuthProofContext, ClientError> {
    Ok(AuthProofContext {
        server_id: Text::new(server_id).map_err(|_| ClientError::BadChallenge)?,
        tls_exporter: Bytes32(*tls_exporter),
        nonce: Bytes32(*nonce),
        timestamp: Timestamp(timestamp),
    })
}

/// Build the client's Ed25519 login proof over the channel-bound context (§9.2 step 4).
pub fn build_login_proof(
    id: &Identity,
    server_id: &str,
    tls_exporter: &[u8; 32],
    nonce: &[u8; 32],
    timestamp: u64,
) -> Result<[u8; 64], ClientError> {
    let ctx = context(server_id, tls_exporter, nonce, timestamp)?;
    Ok(id.signing_key().sign_canonical(labels::AUTH, &ctx))
}

/// Verify a login proof against the recorded `sig_pub` (server side, §9.2 step 5).
/// Pure: the caller supplies the live connection's exporter and the issued nonce;
/// a proof bound to a *different* exporter or nonce fails — defeating relay/replay.
/// Returns a single error shape (no oracle, DESIGN §9.3).
pub fn verify_login_proof(
    sig_pub: &[u8; 32],
    server_id: &str,
    tls_exporter: &[u8; 32],
    nonce: &[u8; 32],
    timestamp: u64,
    proof: &[u8; 64],
) -> Result<(), ClientError> {
    let ctx = context(server_id, tls_exporter, nonce, timestamp)?;
    let vk = VerifyingKey::from_bytes(sig_pub).map_err(|_| ClientError::BadProof)?;
    vk.verify_canonical(labels::AUTH, &ctx, proof)
        .map_err(|_| ClientError::BadProof)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "maxsecu-prod-1";
    const EXPORTER: [u8; 32] = [0xE7; 32];
    const NONCE: [u8; 32] = [0x9c; 32];
    const TS: u64 = 1_719_500_000_000;

    fn proof_for(id: &Identity) -> [u8; 64] {
        build_login_proof(id, SERVER, &EXPORTER, &NONCE, TS).unwrap()
    }

    #[test]
    fn valid_proof_verifies() {
        let id = Identity::generate();
        let proof = proof_for(&id);
        assert!(
            verify_login_proof(&id.sig_pub_bytes(), SERVER, &EXPORTER, &NONCE, TS, &proof).is_ok()
        );
    }

    #[test]
    fn proof_bound_to_exporter_is_not_relayable() {
        // A different TLS channel (exporter) ⇒ the proof must not verify (§9.2).
        let id = Identity::generate();
        let proof = proof_for(&id);
        let other_channel = [0x00; 32];
        assert_eq!(
            verify_login_proof(
                &id.sig_pub_bytes(),
                SERVER,
                &other_channel,
                &NONCE,
                TS,
                &proof
            ),
            Err(ClientError::BadProof)
        );
    }

    #[test]
    fn proof_bound_to_nonce_is_not_replayable() {
        let id = Identity::generate();
        let proof = proof_for(&id);
        let other_nonce = [0x11; 32];
        assert_eq!(
            verify_login_proof(
                &id.sig_pub_bytes(),
                SERVER,
                &EXPORTER,
                &other_nonce,
                TS,
                &proof
            ),
            Err(ClientError::BadProof)
        );
    }

    #[test]
    fn proof_bound_to_server_id_and_timestamp() {
        let id = Identity::generate();
        let proof = proof_for(&id);
        assert!(verify_login_proof(
            &id.sig_pub_bytes(),
            "evil-server",
            &EXPORTER,
            &NONCE,
            TS,
            &proof
        )
        .is_err());
        assert!(verify_login_proof(
            &id.sig_pub_bytes(),
            SERVER,
            &EXPORTER,
            &NONCE,
            TS + 1,
            &proof
        )
        .is_err());
    }

    #[test]
    fn proof_does_not_verify_under_wrong_key() {
        let id = Identity::generate();
        let other = Identity::generate();
        let proof = proof_for(&id);
        assert_eq!(
            verify_login_proof(
                &other.sig_pub_bytes(),
                SERVER,
                &EXPORTER,
                &NONCE,
                TS,
                &proof
            ),
            Err(ClientError::BadProof)
        );
    }
}
