//! The channel-bound challenge-response auth state machine (DESIGN §9.2),
//! transport- and persistence-agnostic over a [`Store`]. The transport layer
//! supplies the live connection's TLS exporter; these methods are pure given
//! `(store, now_ms, exporter)` and fully testable without TLS or a DB.

use crate::error::AuthError;
use crate::store::{SessionRecord, Store};
use maxsecu_crypto::{random_array, sha256, VerifyingKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::AuthProofContext;
use maxsecu_encoding::types::{Bytes32, Text, Timestamp};

/// A login challenge handed to the client (`POST /v1/session/challenge`).
#[derive(Clone, Debug)]
pub struct Challenge {
    pub nonce: [u8; 32],
    pub server_id: String,
    pub expires_in_s: u64,
}

/// An opaque session token. Held server-side only as `SHA-256(token)`; the raw
/// bytes go to the client once and are presented per request (api.md §1.5/§2.3).
pub struct SessionToken([u8; 32]);

impl SessionToken {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Auth configuration (values from parameters §2).
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub server_id: String,
    pub nonce_ttl_ms: u64,
    pub session_ttl_ms: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            server_id: "maxsecu-dev-1".to_owned(),
            nonce_ttl_ms: 60_000,      // 60 s (parameters §2)
            session_ttl_ms: 3_600_000, // 60 min (parameters §2)
        }
    }
}

pub struct AuthService<S: Store> {
    store: S,
    cfg: AuthConfig,
}

impl<S: Store> AuthService<S> {
    pub fn new(store: S, cfg: AuthConfig) -> Self {
        AuthService { store, cfg }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn server_id(&self) -> &str {
        &self.cfg.server_id
    }

    /// Issue a fresh single-use challenge. A well-formed challenge is returned
    /// **even for unknown usernames** — no user-existence oracle (§9.3).
    pub async fn challenge(&self, username: &str, now_ms: u64) -> Challenge {
        let nonce: [u8; 32] = random_array();
        self.store
            .insert_nonce(nonce, username, now_ms + self.cfg.nonce_ttl_ms)
            .await;
        Challenge {
            nonce,
            server_id: self.cfg.server_id.clone(),
            expires_in_s: self.cfg.nonce_ttl_ms / 1000,
        }
    }

    /// Verify a login proof and, on success, mint a channel-bound session.
    ///
    /// * `exporter` is the **live** connection's TLS exporter — a proof built
    ///   for another channel fails (relay-resistant, §9.2).
    /// * The matched nonce is consumed on success — a valid proof cannot be
    ///   replayed (§9.2 / L4).
    /// * Every failure returns `Unauthorized` (no oracle, §9.3).
    pub async fn prove(
        &self,
        username: &str,
        timestamp: u64,
        proof: &[u8; 64],
        exporter: &[u8; 32],
        now_ms: u64,
    ) -> Result<SessionToken, AuthError> {
        let user = self.store.user_by_name(username).await;
        for nonce in self.store.outstanding_nonces(username, now_ms).await {
            let verified = match &user {
                Some(u) => verify_proof(
                    &u.sig_pub,
                    &self.cfg.server_id,
                    exporter,
                    &nonce,
                    timestamp,
                    proof,
                ),
                // Unknown user: do comparable work against a throwaway key so the
                // known/unknown paths are not trivially distinguishable by timing,
                // then fail (no oracle, §9.3).
                None => {
                    let _ = verify_proof(
                        &[0u8; 32],
                        &self.cfg.server_id,
                        exporter,
                        &nonce,
                        timestamp,
                        proof,
                    );
                    false
                }
            };
            if verified {
                self.store.consume_nonce(&nonce).await; // single-use ⇒ no replay
                let u = user.expect("verified implies a known user");
                let token: [u8; 32] = random_array();
                self.store
                    .insert_session(
                        sha256(&token),
                        SessionRecord {
                            user_id: u.user_id,
                            tls_exporter: *exporter,
                            expires_at_ms: now_ms + self.cfg.session_ttl_ms,
                            revoked: false,
                        },
                    )
                    .await;
                return Ok(SessionToken(token));
            }
        }
        Err(AuthError::Unauthorized)
    }

    /// Validate a presented session token on the current connection. The token
    /// is accepted **only** on the channel it was minted on (exporter match);
    /// a lifted/replayed token on another connection is rejected (api.md §1.5).
    pub async fn validate_session(
        &self,
        token: &[u8; 32],
        exporter: &[u8; 32],
        now_ms: u64,
    ) -> Result<[u8; 16], AuthError> {
        let s = self
            .store
            .get_session(&sha256(token))
            .await
            .ok_or(AuthError::Unauthorized)?;
        if s.revoked || s.expires_at_ms <= now_ms || &s.tls_exporter != exporter {
            return Err(AuthError::Unauthorized);
        }
        Ok(s.user_id)
    }

    /// Revoke a token server-side (`POST /v1/session/logout`).
    pub async fn logout(&self, token: &[u8; 32]) {
        self.store.revoke_session(&sha256(token)).await;
    }
}

/// Verify an Ed25519 login proof over `canonical(auth_proof_context)` under the
/// `"MaxSecu-auth-v1"` label (encoding-spec §6). The `server_id` is the server's
/// own (valid) identifier, so context construction cannot fail here.
fn verify_proof(
    sig_pub: &[u8; 32],
    server_id: &str,
    exporter: &[u8; 32],
    nonce: &[u8; 32],
    timestamp: u64,
    proof: &[u8; 64],
) -> bool {
    let ctx = match Text::new(server_id) {
        Ok(server_id) => AuthProofContext {
            server_id,
            tls_exporter: Bytes32(*exporter),
            nonce: Bytes32(*nonce),
            timestamp: Timestamp(timestamp),
        },
        Err(_) => return false,
    };
    VerifyingKey::from_bytes(sig_pub)
        .and_then(|vk| vk.verify_canonical(labels::AUTH, &ctx, proof))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, UserRecord};
    use maxsecu_crypto::SigningKey;

    const EXPORTER: [u8; 32] = [0xE7; 32];
    const TS: u64 = 1_719_500_000_000;

    struct TestUser {
        sk: SigningKey,
        rec: UserRecord,
    }

    fn enroll(store: &MemoryStore, username: &str, uid: u8) -> TestUser {
        let sk = SigningKey::generate();
        let rec = UserRecord {
            user_id: [uid; 16],
            enc_pub: [0xE1; 32],
            sig_pub: sk.verifying_key().to_bytes(),
        };
        store.add_user(username, rec.clone());
        TestUser { sk, rec }
    }

    // Mirrors the client: sign the channel-bound context (this IS client-core's
    // build_login_proof, re-expressed here so the server test is self-contained).
    fn make_proof(
        sk: &SigningKey,
        server_id: &str,
        exporter: &[u8; 32],
        nonce: &[u8; 32],
        ts: u64,
    ) -> [u8; 64] {
        let ctx = AuthProofContext {
            server_id: Text::new(server_id).unwrap(),
            tls_exporter: Bytes32(*exporter),
            nonce: Bytes32(*nonce),
            timestamp: Timestamp(ts),
        };
        sk.sign_canonical(labels::AUTH, &ctx)
    }

    fn service() -> AuthService<MemoryStore> {
        AuthService::new(MemoryStore::new(), AuthConfig::default())
    }

    #[tokio::test]
    async fn login_succeeds_and_session_validates() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await;
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        let token = svc.prove("alice", TS, &proof, &EXPORTER, TS).await.unwrap();
        // Session validates on the same channel and resolves to the user.
        assert_eq!(
            svc.validate_session(token.as_bytes(), &EXPORTER, TS + 1)
                .await
                .unwrap(),
            user.rec.user_id
        );
    }

    #[tokio::test]
    async fn replay_of_a_valid_proof_is_rejected() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await;
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        assert!(svc.prove("alice", TS, &proof, &EXPORTER, TS).await.is_ok());
        // Same proof again — the nonce was consumed (single-use).
        assert_eq!(
            svc.prove("alice", TS, &proof, &EXPORTER, TS).await.err(),
            Some(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn relay_to_a_different_channel_is_rejected() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await;
        // Proof built for EXPORTER, presented on a different connection's exporter.
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        assert_eq!(
            svc.prove("alice", TS, &proof, &[0x00; 32], TS).await.err(),
            Some(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn expired_nonce_is_rejected() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await;
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        // 61 s later the nonce has expired (TTL 60 s).
        assert_eq!(
            svc.prove("alice", TS, &proof, &EXPORTER, TS + 61_000)
                .await
                .err(),
            Some(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn no_user_existence_oracle() {
        let svc = service();
        // A well-formed challenge is issued for an unknown username (§9.3).
        let ch = svc.challenge("nobody", TS).await;
        assert_eq!(ch.nonce.len(), 32);
        assert_eq!(ch.server_id, svc.server_id());
        // And proving for an unknown user fails with the SAME shape as a bad proof.
        let bogus = [0u8; 64];
        assert_eq!(
            svc.prove("nobody", TS, &bogus, &EXPORTER, TS).await.err(),
            Some(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn wrong_key_proof_is_rejected() {
        let svc = service();
        let _alice = enroll(svc.store(), "alice", 0x01);
        let attacker = SigningKey::generate();
        let ch = svc.challenge("alice", TS).await;
        let proof = make_proof(&attacker, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        assert_eq!(
            svc.prove("alice", TS, &proof, &EXPORTER, TS).await.err(),
            Some(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn session_rejected_on_wrong_channel_expiry_and_logout() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await;
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        let token = svc.prove("alice", TS, &proof, &EXPORTER, TS).await.unwrap();

        // Wrong channel (lifted token replayed on another connection).
        assert_eq!(
            svc.validate_session(token.as_bytes(), &[0x00; 32], TS + 1)
                .await
                .err(),
            Some(AuthError::Unauthorized)
        );
        // Expired.
        assert_eq!(
            svc.validate_session(token.as_bytes(), &EXPORTER, TS + 3_600_001)
                .await
                .err(),
            Some(AuthError::Unauthorized)
        );
        // Revoked by logout.
        svc.logout(token.as_bytes()).await;
        assert_eq!(
            svc.validate_session(token.as_bytes(), &EXPORTER, TS + 1)
                .await
                .err(),
            Some(AuthError::Unauthorized)
        );
    }
}
