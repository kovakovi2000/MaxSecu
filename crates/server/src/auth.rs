//! The channel-bound challenge-response auth state machine (DESIGN §9.2),
//! transport- and persistence-agnostic over a [`Store`]. The transport layer
//! supplies the live connection's TLS exporter; these methods are pure given
//! `(store, now_ms, exporter)` and fully testable without TLS or a DB.

use crate::error::{AuthError, ChallengeError, ProveError, StoreError};
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use crate::store::{SessionRecord, Store};
use maxsecu_crypto::{random_array, sha256, SigningKey, VerifyingKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::AuthProofContext;
use maxsecu_encoding::types::{Bytes32, Text, Timestamp};
use std::sync::Arc;

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
    /// Mint a token from raw bytes — used by the recovery login (`recovery.rs`),
    /// which reuses the same session store as the normal login path.
    pub(crate) fn from_bytes(b: [u8; 32]) -> SessionToken {
        SessionToken(b)
    }
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Auth configuration (values from parameters §2/§3).
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub server_id: String,
    pub nonce_ttl_ms: u64,
    pub session_ttl_ms: u64,
    /// Anti-automation tunables (parameters §3).
    pub rate_limit: RateLimitConfig,
    /// The pinned offline **directory-signing (D5) public key** (DESIGN §7.3).
    /// `Some` enables D5-verified admin authz + the binding-publish gate; `None`
    /// fails those closed. The server holds only the *public* half — it verifies
    /// bindings, it cannot forge them.
    pub directory_pub: Option<[u8; 32]>,
}

impl AuthConfig {
    /// Pin the offline D5 directory-signing public key (enables admin authz).
    pub fn with_directory_pub(mut self, dir_pub: [u8; 32]) -> Self {
        self.directory_pub = Some(dir_pub);
        self
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            server_id: "maxsecu-dev-1".to_owned(),
            nonce_ttl_ms: 60_000,      // 60 s (parameters §2)
            session_ttl_ms: 3_600_000, // 60 min (parameters §2)
            rate_limit: RateLimitConfig::default(),
            directory_pub: None,
        }
    }
}

pub struct AuthService<S: Store> {
    store: S,
    cfg: AuthConfig,
    limiter: RateLimiter,
    /// The directory-signing PRIVATE key the server signs enrollment bindings
    /// with (registration-key enrollment, DESIGN §5). `None` = enrollment
    /// disabled (`POST /v1/users` → 403). Its public half is `cfg.directory_pub`
    /// (the value clients pin); the private seed lives ONLY here and is never put
    /// into any DTO, response, or log. `Arc` so cloning `AppState` is a bump.
    dir_signer: Option<Arc<SigningKey>>,
}

impl<S: Store> AuthService<S> {
    pub fn new(store: S, cfg: AuthConfig) -> Self {
        let limiter = RateLimiter::new(cfg.rate_limit.clone());
        AuthService {
            store,
            cfg,
            limiter,
            dir_signer: None,
        }
    }

    /// Give the service the directory-signing key so it can sign enrollment
    /// bindings server-side (§5). The caller must pass the key whose public half
    /// equals `cfg.directory_pub` — the server verifies bindings against that pub
    /// and signs new ones with this private key. Builder form so existing
    /// `AuthService::new(..)` call sites are unaffected.
    pub fn with_dir_signer(mut self, signer: Arc<SigningKey>) -> Self {
        self.dir_signer = Some(signer);
        self
    }

    /// The directory-signing key, if enrollment signing is enabled (§5). Returns
    /// a clone of the `Arc` (a refcount bump); the private seed never escapes.
    pub fn dir_signer(&self) -> Option<Arc<SigningKey>> {
        self.dir_signer.clone()
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn server_id(&self) -> &str {
        &self.cfg.server_id
    }

    /// The pinned D5 directory-signing public key, if configured (§7.3).
    pub fn directory_pub(&self) -> Option<[u8; 32]> {
        self.cfg.directory_pub
    }
    /// The single-use challenge nonce TTL (ms). Exposed so the recovery login
    /// (`recovery.rs`) reuses the same expiry the normal login path applies.
    pub fn nonce_ttl_ms(&self) -> u64 {
        self.cfg.nonce_ttl_ms
    }
    /// The minted-session TTL (ms) — shared with the recovery login path.
    pub fn session_ttl_ms(&self) -> u64 {
        self.cfg.session_ttl_ms
    }

    /// Issue a fresh single-use challenge. A well-formed challenge is returned
    /// **even for unknown usernames** — no user-existence oracle (§9.3) — unless
    /// the per-account issuance cap is hit, in which case the caller is throttled
    /// (`Err(RateLimited)` → HTTP 429, parameters §3).
    pub async fn challenge(
        &self,
        username: &str,
        now_ms: u64,
    ) -> Result<Challenge, ChallengeError> {
        if let Err(retry_after_s) = self.limiter.admit_challenge(username, now_ms) {
            return Err(ChallengeError::RateLimited { retry_after_s });
        }
        let nonce: [u8; 32] = random_array();
        // A backend fault here is surfaced (→ 500), not swallowed: a silently
        // un-stored nonce would deny the *later* proof as a misleading 401.
        self.store
            .insert_nonce(nonce, username, now_ms + self.cfg.nonce_ttl_ms)
            .await
            .map_err(ChallengeError::Internal)?;
        Ok(Challenge {
            nonce,
            server_id: self.cfg.server_id.clone(),
            expires_in_s: self.cfg.nonce_ttl_ms / 1000,
        })
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
    ) -> Result<SessionToken, ProveError> {
        // Per-account failed-proof backoff (parameters §3): reject while in the
        // backoff window *before* doing verification work, and without consuming
        // a nonce. Never a hard lock — the wait is bounded (cap) and a success
        // resets it.
        if let Err(retry_after_s) = self.limiter.admit_proof(username, now_ms) {
            return Err(ProveError::RateLimited { retry_after_s });
        }
        // A store fault is surfaced (→ 500), never masked as a 401: masking would
        // make a transient DB outage indistinguishable from a bad credential.
        let user = self
            .store
            .user_by_name(username)
            .await
            .map_err(ProveError::Internal)?;
        for nonce in self
            .store
            .outstanding_nonces(username, now_ms)
            .await
            .map_err(ProveError::Internal)?
        {
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
                // single-use ⇒ no replay; a fault here must not hand back a token
                // whose nonce wasn't consumed, so surface it rather than swallow.
                self.store
                    .consume_nonce(&nonce)
                    .await
                    .map_err(ProveError::Internal)?;
                self.limiter.record_proof(username, now_ms, true); // clears backoff
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
                    .await
                    .map_err(ProveError::Internal)?; // don't return an unpersisted token
                return Ok(SessionToken(token));
            }
        }
        // No nonce verified — one failed attempt; extend the per-account backoff.
        self.limiter.record_proof(username, now_ms, false);
        Err(ProveError::Unauthorized)
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
        // A backend fault is surfaced (→ 500); a genuinely absent session is the
        // uniform 401. Distinguishing them is the whole point of the fallible Store.
        let s = self
            .store
            .get_session(&sha256(token))
            .await
            .map_err(AuthError::Internal)?
            .ok_or(AuthError::Unauthorized)?;
        if s.revoked || s.expires_at_ms <= now_ms || &s.tls_exporter != exporter {
            return Err(AuthError::Unauthorized);
        }
        Ok(s.user_id)
    }

    /// Revoke a token server-side (`POST /v1/session/logout`). Propagates a
    /// backend fault (→ 500) rather than reporting a false success.
    pub async fn logout(&self, token: &[u8; 32]) -> Result<(), StoreError> {
        self.store.revoke_session(&sha256(token)).await
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
    use crate::store::{FaultyStore, MemoryStore, UserRecord};
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

    #[test]
    fn config_carries_pinned_d5() {
        let cfg = AuthConfig::default().with_directory_pub([0x7D; 32]);
        let svc = AuthService::new(MemoryStore::new(), cfg);
        assert_eq!(svc.directory_pub(), Some([0x7D; 32]));
        // Default is absent (admin endpoints fail closed until configured).
        let bare = AuthService::new(MemoryStore::new(), AuthConfig::default());
        assert_eq!(bare.directory_pub(), None);
    }

    #[tokio::test]
    async fn login_succeeds_and_session_validates() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await.unwrap();
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
        let ch = svc.challenge("alice", TS).await.unwrap();
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        assert!(svc.prove("alice", TS, &proof, &EXPORTER, TS).await.is_ok());
        // Same proof again — the nonce was consumed (single-use).
        assert_eq!(
            svc.prove("alice", TS, &proof, &EXPORTER, TS).await.err(),
            Some(ProveError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn relay_to_a_different_channel_is_rejected() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await.unwrap();
        // Proof built for EXPORTER, presented on a different connection's exporter.
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        assert_eq!(
            svc.prove("alice", TS, &proof, &[0x00; 32], TS).await.err(),
            Some(ProveError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn expired_nonce_is_rejected() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await.unwrap();
        let proof = make_proof(&user.sk, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        // 61 s later the nonce has expired (TTL 60 s).
        assert_eq!(
            svc.prove("alice", TS, &proof, &EXPORTER, TS + 61_000)
                .await
                .err(),
            Some(ProveError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn no_user_existence_oracle() {
        let svc = service();
        // A well-formed challenge is issued for an unknown username (§9.3).
        let ch = svc.challenge("nobody", TS).await.unwrap();
        assert_eq!(ch.nonce.len(), 32);
        assert_eq!(ch.server_id, svc.server_id());
        // And proving for an unknown user fails with the SAME shape as a bad proof.
        let bogus = [0u8; 64];
        assert_eq!(
            svc.prove("nobody", TS, &bogus, &EXPORTER, TS).await.err(),
            Some(ProveError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn wrong_key_proof_is_rejected() {
        let svc = service();
        let _alice = enroll(svc.store(), "alice", 0x01);
        let attacker = SigningKey::generate();
        let ch = svc.challenge("alice", TS).await.unwrap();
        let proof = make_proof(&attacker, svc.server_id(), &EXPORTER, &ch.nonce, TS);
        assert_eq!(
            svc.prove("alice", TS, &proof, &EXPORTER, TS).await.err(),
            Some(ProveError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn store_fault_surfaces_as_internal_not_swallowed() {
        // A backend fault must be a distinct, observable outcome (Internal → 500),
        // NOT swallowed into the fail-closed business answer (a silent 401/no-op).
        let svc = AuthService::new(FaultyStore, AuthConfig::default());

        // challenge: insert_nonce faults → Internal, not a bogus Ok challenge.
        assert!(
            matches!(
                svc.challenge("alice", TS).await,
                Err(ChallengeError::Internal(_))
            ),
            "challenge must surface a store fault as Internal"
        );

        // prove: user_by_name/outstanding_nonces fault → Internal, not Unauthorized.
        let proof = [0u8; 64];
        assert!(
            matches!(
                svc.prove("alice", TS, &proof, &EXPORTER, TS).await,
                Err(ProveError::Internal(_))
            ),
            "prove must surface a store fault as Internal, not mask it as 401"
        );

        // validate_session: get_session fault → Internal, not Unauthorized.
        assert!(
            matches!(
                svc.validate_session(&[0u8; 32], &EXPORTER, TS).await,
                Err(AuthError::Internal(_))
            ),
            "validate_session must surface a store fault as Internal, not mask it as 401"
        );

        // logout: revoke_session fault propagates as the StoreError.
        assert!(
            svc.logout(&[0u8; 32]).await.is_err(),
            "logout must surface a store fault"
        );
    }

    #[tokio::test]
    async fn session_rejected_on_wrong_channel_expiry_and_logout() {
        let svc = service();
        let user = enroll(svc.store(), "alice", 0x01);
        let ch = svc.challenge("alice", TS).await.unwrap();
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
        svc.logout(token.as_bytes()).await.unwrap();
        assert_eq!(
            svc.validate_session(token.as_bytes(), &EXPORTER, TS + 1)
                .await
                .err(),
            Some(AuthError::Unauthorized)
        );
    }
}
