//! The **trusted-server recovery login** — a channel-bound, one-time
//! challenge-response that grants an *admin* session but NEVER the recovery
//! private key (spec §6 / §0-D6).
//!
//! The server persists only the recovery account's PUBLIC keys (T3). Recovery
//! authenticates like a normal user, but against the escrow identity:
//!
//!  1. `recovery_challenge` mints a fresh random 32-byte nonce, stores it
//!     single-use with a short TTL (reusing the login nonce store, keyed by an
//!     opaque `challenge_id`), and **wraps the nonce to the recovery encryption
//!     pubkey** — hybrid (X25519 + ML-KEM) when an ML-KEM key is registered, else
//!     classical X25519. Only the holder of the recovery *private* key can unwrap
//!     it, so learning the nonce proves possession of the cold key.
//!  2. `recovery_verify` reconstructs the channel-bound
//!     [`AuthProofContext`] `{server_id, this-connection's tls_exporter, nonce,
//!     timestamp}` and checks the proof under the recovery **signing** pubkey.
//!     The nonce is consumed (single-use ⇒ no replay); a proof bound to another
//!     channel fails (relay-hardened). On success it mints a session whose
//!     principal is the reserved [`RECOVERY_ID`] — recognized as admin by the
//!     [`AdminSession`](crate::http::AdminSession) extractor without a user
//!     binding, since the escrow identity is not a users-table user.
//!
//! A stolen recovery *session* is tightly bounded: `AuthedSession` bars the
//! recovery principal from every file/content endpoint, so it authorizes only
//! coarse admin *server* actions (e.g. minting registration keys) — never a file
//! read/write — and it yields no private key, so it can never decrypt content
//! (spec §9). The recovery private key stays in the operator's cold file; the
//! server only ever holds its public halves.

use crate::auth::AuthService;
use crate::auth::SessionToken;
use crate::error::StoreError;
use crate::store::{SessionRecord, Store};
use maxsecu_crypto::{
    random_array, serialize_hybrid_wrap, sha256, wrap_dek, wrap_dek_hybrid, Dek, EncPublicKey,
    HybridEncPublicKey, VerifyingKey,
};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{AuthProofContext, WrapContext};
use maxsecu_encoding::types::{Bytes32, Id, Text, Timestamp};
use maxsecu_encoding::RECOVERY_ID;

/// A minted recovery challenge: an opaque `challenge_id` handle and the wrapped
/// nonce blob. `hybrid` records which suite the wrap used (so the client parses
/// it correctly): `true` = hybrid (`eph_x_pub ‖ ct_pq ‖ aead_ct`), `false` =
/// classical (`enc ‖ ct`).
pub struct RecoveryChallenge {
    pub challenge_id: [u8; 16],
    pub wrapped_blob: Vec<u8>,
    pub hybrid: bool,
}

/// Recovery-login failure. Kept coarse (no oracle): `verify` maps both
/// `Unauthorized` and `NoAccount` to a uniform `401`.
pub enum RecoveryError {
    /// No recovery account is registered (challenge → 404).
    NoAccount,
    /// The proof failed for any reason (expired/replayed/wrong-exporter/wrong-key
    /// /bad-proof) — a single shape, no cause detail.
    Unauthorized,
    /// Wrapping the challenge nonce to the stored recovery pubkey failed (a
    /// malformed stored pubkey — a server-config fault, surfaced as `500`).
    WrapFailed,
    /// A backend fault (→ 500).
    Internal(StoreError),
}

/// The nonce-store association key for a recovery challenge. The login nonce
/// store keys nonces by an opaque "username"; recovery reuses it with a key that
/// embeds the `challenge_id` and a leading NUL (which a real [`Text`] username can
/// never contain), so recovery nonces can never collide with a user's.
fn recovery_nonce_key(challenge_id: &[u8; 16]) -> String {
    let mut s = String::with_capacity("\u{0}recovery\u{0}".len() + 32);
    s.push_str("\u{0}recovery\u{0}");
    for b in challenge_id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The [`WrapContext`] a recovery challenge wrap is bound to (spec §6): the
/// `challenge_id` as `file_id`, version 0, `recipient_id = RECOVERY_ID`. Binding
/// the challenge_id makes each wrap unique to its challenge; the client
/// reconstructs the same context from the returned `challenge_id` to unwrap.
fn challenge_wrap_ctx(challenge_id: &[u8; 16]) -> WrapContext {
    WrapContext {
        file_id: Id(*challenge_id),
        version: 0,
        recipient_id: RECOVERY_ID,
    }
}

/// Classical wrap wire form: `enc(32) ‖ ct`. The client splits at 32.
fn serialize_classical_wrap(w: &maxsecu_crypto::WrappedDek) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + w.ct.len());
    out.extend_from_slice(&w.enc);
    out.extend_from_slice(&w.ct);
    out
}

/// Verify the channel-bound recovery proof under the recovery signing pubkey.
/// Mirrors the login `verify_proof` (auth.rs): a proof over a different exporter,
/// nonce, server_id, or timestamp fails — defeating relay and replay.
fn verify_recovery_proof(
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

impl<S: Store> AuthService<S> {
    /// Mint a fresh single-use recovery challenge: a random nonce (stored with a
    /// short TTL) wrapped to the recovery **encryption** pubkey. `404`-mapped
    /// [`RecoveryError::NoAccount`] if no recovery account is registered.
    pub async fn recovery_challenge(
        &self,
        now_ms: u64,
    ) -> Result<RecoveryChallenge, RecoveryError> {
        let acct = self
            .store()
            .recovery_account()
            .await
            .map_err(RecoveryError::Internal)?
            .ok_or(RecoveryError::NoAccount)?;

        let nonce: [u8; 32] = random_array();
        let challenge_id: [u8; 16] = random_array();
        // Store the nonce single-use under an opaque, per-challenge key (mirrors
        // the login-challenge store; a fault here is a 500, never a silent no-op).
        self.store()
            .insert_nonce(
                nonce,
                &recovery_nonce_key(&challenge_id),
                now_ms + self.nonce_ttl_ms(),
            )
            .await
            .map_err(RecoveryError::Internal)?;

        let ctx = challenge_wrap_ctx(&challenge_id);
        let dek = Dek::from_bytes(nonce); // wrap the nonce exactly like a DEK
        let (wrapped_blob, hybrid) = match acct.mlkem_pub {
            Some(mlkem) => {
                let pk = HybridEncPublicKey {
                    x25519: acct.enc_pub,
                    mlkem,
                };
                let w = wrap_dek_hybrid(&pk, &dek, &ctx).map_err(|_| RecoveryError::WrapFailed)?;
                (serialize_hybrid_wrap(&w), true)
            }
            None => {
                let pk = EncPublicKey::from_bytes(acct.enc_pub);
                let w = wrap_dek(&pk, &dek, &ctx).map_err(|_| RecoveryError::WrapFailed)?;
                (serialize_classical_wrap(&w), false)
            }
        };
        Ok(RecoveryChallenge {
            challenge_id,
            wrapped_blob,
            hybrid,
        })
    }

    /// Verify a channel-bound recovery proof and, on success, mint an **admin**
    /// session (principal = [`RECOVERY_ID`]). The matched nonce is consumed
    /// (single-use ⇒ no replay); the proof is bound to `exporter` (relay-proof)
    /// and verified under the recovery signing pubkey. Every failure is the
    /// uniform [`RecoveryError::Unauthorized`] (no oracle).
    pub async fn recovery_verify(
        &self,
        challenge_id: &[u8; 16],
        timestamp: u64,
        proof: &[u8; 64],
        exporter: &[u8; 32],
        now_ms: u64,
    ) -> Result<SessionToken, RecoveryError> {
        // No account ⇒ the same shape as a bad proof (no existence oracle).
        let acct = self
            .store()
            .recovery_account()
            .await
            .map_err(RecoveryError::Internal)?
            .ok_or(RecoveryError::Unauthorized)?;

        for nonce in self
            .store()
            .outstanding_nonces(&recovery_nonce_key(challenge_id), now_ms)
            .await
            .map_err(RecoveryError::Internal)?
        {
            if verify_recovery_proof(
                &acct.sig_pub,
                self.server_id(),
                exporter,
                &nonce,
                timestamp,
                proof,
            ) {
                // Single-use: consume before minting; a fault must not hand back a
                // token whose nonce wasn't burned, so surface it rather than swallow.
                self.store()
                    .consume_nonce(&nonce)
                    .await
                    .map_err(RecoveryError::Internal)?;
                let token: [u8; 32] = random_array();
                self.store()
                    .insert_session(
                        sha256(&token),
                        SessionRecord {
                            // The reserved recovery principal — no user binding. The
                            // AdminSession extractor admits it for admin server
                            // actions, while AuthedSession bars it from every
                            // file/content endpoint (spec §9 blast radius).
                            user_id: RECOVERY_ID.0,
                            tls_exporter: *exporter,
                            expires_at_ms: now_ms + self.session_ttl_ms(),
                            revoked: false,
                        },
                    )
                    .await
                    .map_err(RecoveryError::Internal)?;
                return Ok(SessionToken::from_bytes(token));
            }
        }
        Err(RecoveryError::Unauthorized)
    }
}
