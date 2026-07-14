//! The **trusted-server recovery login** on the client side (spec §6 / §0-D6): a
//! channel-bound, one-time challenge-response that establishes an *admin* session
//! from the operator's COLD recovery key — without the recovery private key ever
//! crossing the Tauri seam, being logged, or leaving this process.
//!
//! The recovery private key is an ordinary [`Identity`] (X25519 + Ed25519 + — for
//! a hybrid account — ML-KEM-768) that the operator sealed into a keyblob file via
//! `maxsecu-setup`. Here it is:
//!   * loaded from that file and UNSEALED with the operator passphrase entirely in
//!     Rust ([`load_recovery_identity`]),
//!   * used to UNWRAP the server's challenge blob to a 32-byte nonce (mirroring the
//!     server's `WrapContext { file_id = challenge_id, version = 0, recipient_id =
//!     RECOVERY_ID }`, classical `enc‖ct` vs hybrid wire), and
//!   * used to SIGN the channel-bound [`AuthProofContext`] proof (same primitive as
//!     a normal login — see [`crate::session::make_proof`]).
//!
//! Between the two Tauri commands the unlocked recovery `Identity` and the nonce
//! live only in Rust-managed state ([`RecoveryLogin`]); both are dropped/zeroized
//! the moment the pending challenge is answered, cleared, or superseded. Only DTOs
//! (an opaque status + the public `server_id`) ever cross the seam. Every failure
//! collapses to a single sanitized `recovery_failed` shape (no unwrap oracle).

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use maxsecu_client_core::{keyblob, Identity};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, unwrap_dek, unwrap_dek_hybrid, HybridEncSecretKey, WrappedDek,
};
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::types::Id;
use maxsecu_encoding::RECOVERY_ID;

use crate::dto::{RecoveryChallengeDto, RecoveryLoginDto};
use crate::error::UiError;
use crate::http_client::post_json;
use crate::session::make_proof;

use super::auth::{AppDir, ConnectLock, Session};
use super::connection::{open_conn, server_of};

/// The single sanitized recovery-login failure. Unwrap failure (wrong/corrupt key
/// file), a rejected/expired/replayed proof, and a network fault all collapse to
/// this one shape so the UI can never distinguish them (no oracle).
fn recovery_failed() -> UiError {
    UiError::new("recovery_failed", "Recovery sign-in failed.")
}

/// Where the operator's sealed cold recovery keyblob lives in the portable layout:
/// `<app-dir>/recovery/recovery_key_blob`, beside the exe (mirrors
/// [`crate::keystore::keystore_path`]). Produced by `maxsecu-setup`.
pub fn recovery_key_path(dir: &Path) -> PathBuf {
    dir.join("recovery").join("recovery_key_blob")
}

/// Load + UNSEAL the cold recovery [`Identity`] from its keyblob file. The private
/// key stays entirely in Rust (returned as an opaque `Identity`, never a DTO). A
/// missing file → `no_recovery_key`; a wrong passphrase / corrupt blob →
/// `unauthorized` (mirrors [`crate::keystore::unlock`], no oracle).
pub fn load_recovery_identity(path: &Path, passphrase: &str) -> Result<Identity, UiError> {
    let blob = std::fs::read(path)
        .map_err(|_| UiError::new("no_recovery_key", "No recovery key file on this device."))?;
    keyblob::unlock(passphrase, &blob)
        .map_err(|_| UiError::new("unauthorized", "Recovery sign-in failed."))
}

/// The [`WrapContext`] a recovery challenge wrap is bound to (spec §6): the
/// `challenge_id` as `file_id`, version 0, `recipient_id = RECOVERY_ID`. The client
/// reconstructs it from the returned `challenge_id` to unwrap — mirrors the server's
/// `recovery::challenge_wrap_ctx`.
fn challenge_wrap_ctx(challenge_id: &[u8; 16]) -> WrapContext {
    WrapContext {
        file_id: Id(*challenge_id),
        version: 0,
        recipient_id: RECOVERY_ID,
    }
}

/// Unwrap the server's challenge blob to the 32-byte nonce with the recovery
/// private key. `hybrid` selects the wire form: hybrid (`eph_x_pub ‖ ct_pq ‖
/// aead_ct`, opened with the ML-KEM + X25519 legs) vs classical (`enc(32) ‖ ct`,
/// X25519 HPKE). Any failure (malformed wire, missing PQ leg, AEAD reject) →
/// [`recovery_failed`] — a single shape, no cause detail. The nonce is returned
/// zeroize-on-drop.
fn unwrap_challenge(
    recovery: &Identity,
    hybrid: bool,
    challenge_id: &[u8; 16],
    blob: &[u8],
) -> Result<Zeroizing<[u8; 32]>, UiError> {
    let ctx = challenge_wrap_ctx(challenge_id);
    let dek = if hybrid {
        let wrapped = deserialize_hybrid_wrap(blob).map_err(|_| recovery_failed())?;
        // Rebuild the hybrid secret from the recovery Identity's classical X25519
        // scalar + its ML-KEM seed (a classical-only recovery Identity cannot open
        // a hybrid wrap → fail closed).
        let mlkem_seed = recovery.mlkem_seed().ok_or_else(recovery_failed)?;
        let sk =
            HybridEncSecretKey::from_components(recovery.enc_secret().expose_bytes(), mlkem_seed);
        unwrap_dek_hybrid(&sk, &wrapped, &ctx).map_err(|_| recovery_failed())?
    } else {
        if blob.len() < 32 {
            return Err(recovery_failed());
        }
        let wrapped = WrappedDek {
            enc: blob[..32].try_into().map_err(|_| recovery_failed())?,
            ct: blob[32..].to_vec(),
        };
        unwrap_dek(recovery.enc_secret(), &wrapped, &ctx).map_err(|_| recovery_failed())?
    };
    Ok(Zeroizing::new(*dek.expose()))
}

/// A minted-and-unwrapped recovery challenge, held between the two login steps. The
/// nonce is zeroized on drop; nothing here is ever serialized to the UI. `server_id`
/// is public (safe to display); `challenge_id` (hex) is echoed back to `/verify`.
pub struct RecoveryChallenge {
    pub server_id: String,
    challenge_id: String,
    nonce: Zeroizing<[u8; 32]>,
    hybrid: bool,
}

impl RecoveryChallenge {
    /// Whether the served challenge used the hybrid (Suite::V2) wrap — for the e2e
    /// gate that both wrap suites round-trip.
    pub fn suite_is_hybrid(&self) -> bool {
        self.hybrid
    }
}

/// Build the `POST /v1/recovery/challenge` body — PURE, so the wire shape is
/// testable without a network (`tests/compat.rs`). Deliberately EMPTY: the
/// recovery account is the singleton the server already knows, so the challenge
/// carries no identifier (the server wraps the nonce to the pinned recovery key).
/// Adding a REQUIRED key here would break every shipped client.
pub fn build_recovery_challenge_body() -> serde_json::Value {
    serde_json::json!({})
}

/// Build the `POST /v1/recovery/verify` body — PURE (see above). All three keys
/// are read by the server's `recovery_verify` handler; dropping any of them makes
/// the channel-bound recovery proof unverifiable and destroys the ONLY
/// account-recovery path (there is no admin escape hatch).
pub fn build_recovery_verify_body(
    challenge_id: &str,
    proof_b64: &str,
    timestamp_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "challenge_id": challenge_id,
        "proof_b64": proof_b64,
        "timestamp": timestamp_ms,
    })
}

/// `POST /v1/recovery/challenge` over an already-connected, channel-bound sender,
/// then UNWRAP the returned blob to the nonce with `recovery`. Mirrors the first
/// half of a normal `login_exchange`; all failures collapse to [`recovery_failed`].
pub async fn request_challenge_exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    recovery: &Identity,
) -> Result<RecoveryChallenge, UiError> {
    let (status, ch) = post_json(
        sender,
        "/v1/recovery/challenge",
        &build_recovery_challenge_body(),
        None,
        host,
    )
    .await
    .map_err(|_| recovery_failed())?;
    if !status.is_success() {
        return Err(recovery_failed());
    }
    let server_id = ch
        .get("server_id")
        .and_then(|v| v.as_str())
        .ok_or_else(recovery_failed)?
        .to_owned();
    let challenge_id_hex = ch
        .get("challenge_id")
        .and_then(|v| v.as_str())
        .ok_or_else(recovery_failed)?
        .to_owned();
    let challenge_id = hex16(&challenge_id_hex).ok_or_else(recovery_failed)?;
    // Absent/"v1" → classical; "v2" → hybrid (matches the server's suite tag).
    let hybrid = ch.get("suite").and_then(|v| v.as_str()) == Some("v2");
    let blob = ch
        .get("wrapped_blob_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(recovery_failed)?;
    let blob = B64.decode(blob).map_err(|_| recovery_failed())?;
    let nonce = unwrap_challenge(recovery, hybrid, &challenge_id, &blob)?;
    Ok(RecoveryChallenge {
        server_id,
        challenge_id: challenge_id_hex,
        nonce,
        hybrid,
    })
}

/// Build the channel-bound proof over `(nonce, server_id, exporter, timestamp)`
/// with the recovery SIGNING key and `POST /v1/recovery/verify`. On success returns
/// the ADMIN session token. Mirrors the second half of `login_exchange`; every
/// failure (rejected/expired/replayed proof, relay, network) → [`recovery_failed`].
pub async fn verify_exchange(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    recovery: &Identity,
    challenge: &RecoveryChallenge,
    exporter: &[u8; 32],
    now_ms: u64,
) -> Result<String, UiError> {
    let proof = make_proof(recovery, &challenge.server_id, exporter, &challenge.nonce, now_ms)
        .map_err(|_| recovery_failed())?;
    let (status, res) = post_json(
        sender,
        "/v1/recovery/verify",
        &build_recovery_verify_body(&challenge.challenge_id, &B64.encode(proof), now_ms),
        None,
        host,
    )
    .await
    .map_err(|_| recovery_failed())?;
    if !status.is_success() {
        return Err(recovery_failed());
    }
    res.get("session_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(recovery_failed)
}

/// Parse a 32-char lowercase-hex `challenge_id` to 16 bytes. `None` (fail closed)
/// on any non-hex / wrong-length input.
fn hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

// --------------------------------------------------------------------------
// Managed state + Tauri commands (only DTOs cross the seam).
// --------------------------------------------------------------------------

/// A minted challenge parked between the two login steps: the live channel + the
/// unlocked recovery `Identity` + the nonce (the ONLY place the cold private key
/// lives in this process). Dropped/zeroized the moment the phase transitions away.
struct Challenged {
    sender: SendRequest<Full<Bytes>>,
    host: String,
    exporter: [u8; 32],
    identity: Identity,
    challenge: RecoveryChallenge,
}

/// An established recovery session: only the live authenticated channel + the
/// opaque token — NO key material. Kept so the channel-bound admin token stays
/// usable for a later admin action (routing through it is a future task).
struct Authenticated {
    #[allow(dead_code)]
    sender: SendRequest<Full<Bytes>>,
    #[allow(dead_code)]
    host: String,
    #[allow(dead_code)]
    token: String,
}

/// The in-RAM recovery-login phase (boxed variants — `Challenged` carries a large
/// `Identity`, so boxing keeps the enum small).
enum Phase {
    Idle,
    Challenged(Box<Challenged>),
    // Held (not yet read) purely to keep the channel-bound admin connection alive
    // after a successful recovery login; admin routing over it is a future task.
    #[allow(dead_code)]
    Authenticated(Box<Authenticated>),
}

/// Async-aware managed wrapper for the recovery-login phase (commands are `async`).
/// The inner phase is module-private: only this module's commands touch it, and it
/// holds the cold recovery private key, which must never be reachable elsewhere.
pub struct RecoveryLogin(Mutex<Phase>);

impl RecoveryLogin {
    pub fn new() -> Self {
        Self(Mutex::new(Phase::Idle))
    }
}

impl Default for RecoveryLogin {
    fn default() -> Self {
        Self::new()
    }
}

/// `request_recovery_challenge` — open the pinned-TLS connection, `POST
/// /v1/recovery/challenge`, load+unseal the cold recovery key with `passphrase`,
/// and UNWRAP the challenge to the nonce. The unlocked recovery `Identity` + the
/// nonce are held in Rust-managed state (`RecoveryLogin`) for the answer step; the
/// passphrase is zeroized on every path. Returns only an opaque status + the public
/// `server_id` — never the nonce, never any key.
#[tauri::command]
pub async fn request_recovery_challenge(
    passphrase: String,
    dir: tauri::State<'_, AppDir>,
    recovery: tauri::State<'_, RecoveryLogin>,
    connect_lock: tauri::State<'_, ConnectLock>,
) -> Result<RecoveryChallengeDto, UiError> {
    // Scrub the passphrase on every exit path (success, failure, panic).
    let passphrase = Zeroizing::new(passphrase);
    // Serialize against `connect`/`reauth` (they share the transient-identity dance
    // and the single logical connection slot). Held only for this command.
    let _guard = connect_lock
        .0
        .try_lock()
        .map_err(|_| UiError::new("busy", "A connection attempt is already in progress."))?;

    let server = server_of(&dir.0)?;
    // Unseal the cold recovery Identity BEFORE dialing (fail fast on a bad key).
    let id = load_recovery_identity(&recovery_key_path(&dir.0), passphrase.as_str())?;
    let (mut sender, host, exporter) = open_conn(&dir.0, &server).await?;
    let challenge = request_challenge_exchange(&mut sender, &host, &id).await?;
    let server_id = challenge.server_id.clone();

    // Park the live channel + the cold Identity + the nonce for the answer step.
    // Replacing whatever was there drops any prior pending secret (zeroized).
    *recovery.0.lock().await = Phase::Challenged(Box::new(Challenged {
        sender,
        host,
        exporter,
        identity: id,
        challenge,
    }));
    Ok(RecoveryChallengeDto {
        status: "challenge-ready".into(),
        server_id,
    })
}

/// `answer_recovery_challenge` — build the channel-bound proof with the held
/// recovery signing key and `POST /v1/recovery/verify` on the SAME channel. On
/// success stores the returned ADMIN token where normal sessions live and keeps the
/// live authenticated channel (no key material) for a later admin action; the cold
/// recovery `Identity` + the nonce are dropped/zeroized regardless of outcome.
#[tauri::command]
pub async fn answer_recovery_challenge(
    session: tauri::State<'_, Session>,
    recovery: tauri::State<'_, RecoveryLogin>,
) -> Result<RecoveryLoginDto, UiError> {
    let now = now_ms();
    let mut phase = recovery.0.lock().await;
    // Take the pending challenge OUT (leaving Idle) so the cold Identity + nonce are
    // dropped/zeroized on every path below — success or failure.
    let Challenged {
        mut sender,
        host,
        exporter,
        identity,
        challenge,
    } = match std::mem::replace(&mut *phase, Phase::Idle) {
        Phase::Challenged(c) => *c,
        other => {
            // Nothing pending (Idle) or already authenticated — restore + refuse.
            *phase = other;
            return Err(UiError::new(
                "no_challenge",
                "Request a recovery challenge first.",
            ));
        }
    };

    let server_id = challenge.server_id.clone();
    let result = verify_exchange(&mut sender, &host, &identity, &challenge, &exporter, now).await;
    // Explicitly drop the cold private key + nonce NOW (both zeroize on drop),
    // before touching the shared session state.
    drop(identity);
    drop(challenge);

    let token = result?;

    // Store the admin token where a normal session lives (the UI never sees it).
    {
        let mut s = session.0.lock().await;
        s.token = Some(token.clone());
        s.server_id = server_id.clone();
        // Recovery sessions have no user binding; leave `username`/`identity` as-is
        // (a recovery login neither unlocks a user identity nor supports the
        // username-based `reauth` path — admin routing over this channel is Task 13).
    }
    // Keep the live authenticated channel alive so the channel-bound admin token
    // stays usable (dropping the sender would close the connection and void it).
    *phase = Phase::Authenticated(Box::new(Authenticated {
        sender,
        host,
        token,
    }));
    Ok(RecoveryLoginDto {
        status: "admin-session".into(),
        server_id,
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex16_roundtrips_and_rejects_bad_input() {
        assert_eq!(hex16(&"ab".repeat(16)), Some([0xab; 16]));
        assert_eq!(hex16("00"), None, "too short");
        assert_eq!(hex16(&"zz".repeat(16)), None, "non-hex");
        // Non-ASCII of the right byte-length must not slice-panic (rejected).
        assert_eq!(hex16(&"é".repeat(16)), None, "non-ascii rejected");
    }

    #[test]
    fn recovery_key_path_is_beside_the_exe() {
        let p = recovery_key_path(Path::new("/app"));
        assert!(p.ends_with("recovery/recovery_key_blob") || p.ends_with("recovery\\recovery_key_blob"));
    }

    #[test]
    fn classical_wrap_shorter_than_32_fails_closed() {
        // A truncated classical blob must fail closed, never panic on the split.
        let id = Identity::generate();
        let err = unwrap_challenge(&id, false, &[0u8; 16], &[0u8; 8]).unwrap_err();
        assert_eq!(err.code, "recovery_failed");
    }
}
