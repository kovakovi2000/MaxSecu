//! Offline-D5 delegation auto-renew + manual renew (workstream W5, spec §7
//! "Auto-renew on login" / "Manual fallback").
//!
//! The admin-held D5 root signs a short-lived (90-day) delegation authorizing the
//! server's operational key. This module keeps that window fresh:
//!
//!   * **auto-renew on login** ([`auto_renew_on_login`]): a best-effort, detached
//!     task spawned right after the keystore unlocks. Only an ADMIN PC holds the
//!     sealed `d5_key.blob`; on any other device (no blob) OR when the login
//!     passphrase is not the recovery passphrase (the blob won't unseal) this is a
//!     SILENT no-op. It NEVER blocks the unlock command and NEVER surfaces a hard
//!     error — every outcome is only logged.
//!   * **manual renew** ([`renew_delegation`]): a Tauri admin command that runs the
//!     same flow on demand and returns a human-readable result (or a UiError).
//!
//! Trust posture (fail-closed): the served `directory_pub` is only ever COMPARED to
//! the compiled/pinned D5 (`config/directory_pub.der`) — never trusted on its own —
//! and the fresh delegation is D5-signed locally. The server re-checks the renewed
//! cert (operational-key match + sane window) before installing it. Best-effort
//! renewal can never WEAKEN trust: a failure just leaves the existing (still-valid,
//! or soon-to-expire) delegation in place, and the client verify-hop keeps failing
//! closed on an expired one.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::Zeroizing;

use maxsecu_client_core::unseal_seed;
use maxsecu_crypto::{parse_delegation, sign_delegation, SigningKey, DELEGATION_CLOCK_SKEW_SECS};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::config::load_directory_pub;
use crate::error::UiError;
use crate::http_client::{get_json, post_json};

/// Renew when the current delegation is within this many seconds of `valid_until`
/// (spec §2/§7: 21 days). At/under the threshold ⇒ due.
pub const RENEW_THRESHOLD_SECS: u64 = 21 * 86_400;

/// The fresh window a renewal signs (spec §2/§7: 90 days).
pub const RENEW_WINDOW_SECS: u64 = 90 * 86_400;

/// The at-rest sealed D5 root on an admin PC. Kept beside the other pinned trust
/// material (`config/`), sealed under the recovery passphrase. Its PRESENCE is the
/// "this is the admin PC" signal; its ABSENCE means auto-renew is a silent no-op.
pub fn d5_blob_path(app_dir: &Path) -> PathBuf {
    app_dir.join("config").join("d5_key.blob")
}

/// The outcome of one renew attempt. All variants are non-fatal: the caller either
/// logs them (auto-renew) or maps them to a UiError/string (the command). None of
/// them ever panics or blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewOutcome {
    /// A fresh 90-day delegation was signed and accepted (`200`). Carries the new
    /// `valid_until` (unix seconds).
    Renewed { valid_until: u64 },
    /// The delegation is not within the renew threshold and `force` was not set.
    NotDue { valid_until: u64 },
    /// No `d5_key.blob` — this is not an admin PC. Silent no-op.
    NoD5,
    /// A `d5_key.blob` exists but did not unseal with the entered passphrase (the
    /// login passphrase is not the recovery passphrase). Silent no-op.
    UnsealFailed,
    /// The server holds no delegation to renew (`404` / awaiting). Nothing to do.
    NotDelegated,
    /// Any network/auth/server failure. Non-fatal; the message is for the log/UI.
    PushFailed(String),
}

/// True when a renewal should fire: `force`, or the window ends within
/// [`RENEW_THRESHOLD_SECS`] of `now_secs` (inclusive). Pure; the single home for
/// the threshold rule shared by the command, the on-login hook, and `maxsecu-setup`.
pub fn is_due(current_valid_until: u64, now_secs: u64, force: bool) -> bool {
    force || current_valid_until <= now_secs.saturating_add(RENEW_THRESHOLD_SECS)
}

/// Sign a fresh 90-day delegation with the D5 root over `op_pub`. `valid_from` is
/// back-dated by [`DELEGATION_CLOCK_SKEW_SECS`] so the cert still passes the server's
/// strict `now >= valid_from` check when the server clock trails this (client) clock
/// by up to that margin; `valid_until = now + 90d` is UNCHANGED (expiry not extended).
/// Returns `(cert_wire_bytes, valid_until)`. Pure; the single home for the renewal
/// window + signing shared by every renew path.
pub fn sign_renewal(d5: &SigningKey, op_pub: &[u8; 32], now_secs: u64) -> (Vec<u8>, u64) {
    let valid_from = now_secs.saturating_sub(DELEGATION_CLOCK_SKEW_SECS);
    let valid_until = now_secs.saturating_add(RENEW_WINDOW_SECS);
    (
        sign_delegation(d5, op_pub, valid_from, valid_until),
        valid_until,
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unseal the admin PC's D5 root with `password`. `NoD5` when the blob is absent
/// (not an admin PC), `UnsealFailed` when it exists but the passphrase is wrong.
/// Pure/offline: this is exactly the branch the "skips cleanly" tests exercise
/// without any network.
fn load_d5(app_dir: &Path, password: &str) -> Result<SigningKey, RenewOutcome> {
    let path = d5_blob_path(app_dir);
    let blob = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return Err(RenewOutcome::NoD5),
    };
    match unseal_seed(password, &blob) {
        Ok(seed) => Ok(SigningKey::from_seed(&seed)),
        Err(_) => Err(RenewOutcome::UnsealFailed),
    }
}

/// The full renew flow (locate+unseal D5 → admin-authenticated push). Best-effort
/// and total: every failure maps to a [`RenewOutcome`] variant, never a panic and
/// never a block. Shared by the command and the on-login hook.
///
/// It reuses the admin `reauth` path for the session (so it only ever succeeds for
/// a real, currently-signed-in admin), fetches the current delegation to read
/// `valid_until`, applies the [`is_due`] threshold, and — only when due — signs a
/// fresh 90-day cert and POSTs it to `/v1/admin/delegation`.
pub async fn run_renew(
    app_dir: &Path,
    password: &str,
    session: &Session,
    connect_lock: &ConnectLock,
    force: bool,
) -> RenewOutcome {
    // (1) D5 gate — offline. Absent ⇒ non-admin (NoD5); present-but-wrong-pass ⇒
    //     UnsealFailed. Both are silent no-ops for the on-login hook.
    let d5 = match load_d5(app_dir, password) {
        Ok(d5) => d5,
        Err(o) => return o,
    };

    // (2) Reuse the admin reauth path for a fresh admin session. If there is no
    //     active session (unlocked but not connected), this fails "locked"/"Sign
    //     in first" — a benign skip, not an error the user should see.
    let server = match server_of(app_dir) {
        Ok(s) => s,
        Err(e) => return RenewOutcome::PushFailed(e.message),
    };
    let (mut sender, host, token) = match reauth(app_dir, &server, session, connect_lock).await {
        Ok(t) => t,
        Err(e) => return RenewOutcome::PushFailed(e.message),
    };

    // (3) Read the current delegation to learn valid_until, and confirm we are still
    //     talking to OUR directory root (served directory_pub == pinned D5). A 404
    //     means the server is awaiting/legacy — nothing to renew.
    let pinned = match load_directory_pub(app_dir) {
        Ok(p) => p,
        Err(e) => return RenewOutcome::PushFailed(e.message),
    };
    let (status, doc) = match get_json(&mut sender, "/v1/bootstrap/delegation", None, &host).await {
        Ok(r) => r,
        Err(e) => return RenewOutcome::PushFailed(e.message),
    };
    match status {
        hyper::StatusCode::OK => {}
        hyper::StatusCode::NOT_FOUND => return RenewOutcome::NotDelegated,
        s => return RenewOutcome::PushFailed(format!("delegation fetch: {s}")),
    }
    let (served_dir, cert) = match parse_delegation_doc(&doc) {
        Ok(v) => v,
        Err(m) => return RenewOutcome::PushFailed(m),
    };
    if served_dir != pinned {
        return RenewOutcome::PushFailed(
            "served directory key does not match the pinned key".into(),
        );
    }
    let valid_until = match parse_delegation(&cert) {
        Ok(d) => d.valid_until(),
        Err(_) => return RenewOutcome::PushFailed("served delegation is malformed".into()),
    };

    // (4) Threshold. Not due (and not forced) ⇒ a clean no-op.
    let now = now_secs();
    if !is_due(valid_until, now, force) {
        return RenewOutcome::NotDue { valid_until };
    }

    // (5) The server's current operational key (authoritative, unauthenticated) —
    //     the renewal MUST authorize the SAME op-key (the server rejects otherwise).
    let op_pub = match fetch_operational_pub(&mut sender, &host).await {
        Ok(p) => p,
        Err(m) => return RenewOutcome::PushFailed(m),
    };

    // (6) Sign a fresh 90-day delegation and push it admin-authenticated.
    let (renewal, new_valid_until) = sign_renewal(&d5, &op_pub, now);
    let body = serde_json::json!({ "delegation_cert_b64": B64.encode(&renewal) });
    match post_json(
        &mut sender,
        "/v1/admin/delegation",
        &body,
        Some(&token),
        &host,
    )
    .await
    {
        Ok((hyper::StatusCode::OK, _)) => RenewOutcome::Renewed {
            valid_until: new_valid_until,
        },
        Ok((s, _)) => RenewOutcome::PushFailed(format!("delegation push rejected: {s}")),
        Err(e) => RenewOutcome::PushFailed(e.message),
    }
}

/// Decode `{directory_pub_b64, delegation_cert_b64}` (STANDARD base64). Any bad
/// field is a soft failure string (never a panic; the server is untrusted transport).
fn parse_delegation_doc(json: &serde_json::Value) -> Result<([u8; 32], Vec<u8>), String> {
    let bad = || "malformed delegation document".to_string();
    let dir_vec = B64
        .decode(json["directory_pub_b64"].as_str().ok_or_else(bad)?)
        .map_err(|_| bad())?;
    let directory_pub: [u8; 32] = dir_vec.try_into().map_err(|_| bad())?;
    let cert = B64
        .decode(json["delegation_cert_b64"].as_str().ok_or_else(bad)?)
        .map_err(|_| bad())?;
    Ok((directory_pub, cert))
}

/// GET `/v1/bootstrap/operational-key` → the server's 32-byte operational pub.
async fn fetch_operational_pub(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
    host: &str,
) -> Result<[u8; 32], String> {
    let (status, json) = get_json(sender, "/v1/bootstrap/operational-key", None, host)
        .await
        .map_err(|e| e.message)?;
    if status != hyper::StatusCode::OK {
        return Err(format!("operational-key fetch: {status}"));
    }
    json["operational_pub_b64"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "malformed operational_pub".to_string())
}

/// Log a renew outcome. Best-effort diagnostics only (the GUI has no console, but a
/// dev/terminal run and the E2E harness surface these). Never carries key material.
fn log_outcome(outcome: &RenewOutcome) {
    match outcome {
        RenewOutcome::Renewed { valid_until } => {
            eprintln!("[d5-renew] renewed (valid until {valid_until})")
        }
        RenewOutcome::NotDue { valid_until } => {
            eprintln!("[d5-renew] not due (valid until {valid_until})")
        }
        RenewOutcome::NoD5 => eprintln!("[d5-renew] no d5_key.blob (non-admin device) — skipped"),
        RenewOutcome::UnsealFailed => {
            eprintln!("[d5-renew] d5_key.blob did not unseal (passphrase mismatch) — skipped")
        }
        RenewOutcome::NotDelegated => {
            eprintln!("[d5-renew] server holds no delegation to renew — skipped")
        }
        RenewOutcome::PushFailed(m) => eprintln!("[d5-renew] not renewed: {m}"),
    }
}

/// Best-effort auto-renew, spawned (detached) right after `unlock_keystore`. Reads
/// the managed state off the `AppHandle`, runs [`run_renew`] with `force = false`,
/// and only LOGS the outcome. Any absence (no D5), mismatch (wrong pass), or network
/// failure degrades to a no-op — it never blocks unlock and never surfaces an error.
pub async fn auto_renew_on_login(app: tauri::AppHandle, password: Zeroizing<String>) {
    use tauri::Manager;
    let app_dir = app.state::<AppDir>();
    let session = app.state::<Session>();
    let connect_lock = app.state::<ConnectLock>();
    let outcome = run_renew(
        &app_dir.0,
        password.as_str(),
        &session,
        &connect_lock,
        false,
    )
    .await;
    log_outcome(&outcome);
}

/// `renew_delegation` — the manual admin fallback (spec §7). Runs the SAME flow as
/// auto-renew on demand, but SURFACES its outcome: a no-op / success returns a
/// human string; a real failure returns a UiError so the admin sees it. `force`
/// (default `false`) renews regardless of the threshold. `password` unseals the
/// admin PC's D5 root (the login passphrase must equal the recovery passphrase).
///
/// Scalar args are camelCase in JS (`{ password, force }`).
#[tauri::command]
pub async fn renew_delegation(
    password: String,
    force: Option<bool>,
    dir: tauri::State<'_, AppDir>,
    session: tauri::State<'_, Session>,
    connect_lock: tauri::State<'_, ConnectLock>,
) -> Result<String, UiError> {
    let password = Zeroizing::new(password);
    let outcome = run_renew(
        &dir.0,
        password.as_str(),
        &session,
        &connect_lock,
        force.unwrap_or(false),
    )
    .await;
    match outcome {
        RenewOutcome::Renewed { valid_until } => Ok(format!(
            "Directory delegation renewed (valid until {valid_until})."
        )),
        RenewOutcome::NotDue { valid_until } => Ok(format!(
            "Directory delegation is not due for renewal (valid until {valid_until})."
        )),
        RenewOutcome::NoD5 => Err(UiError::new(
            "not_admin",
            "This device does not hold the directory root key.",
        )),
        RenewOutcome::UnsealFailed => Err(UiError::new(
            "unseal_failed",
            "The directory key could not be unlocked with this password.",
        )),
        RenewOutcome::NotDelegated => Err(UiError::new(
            "not_delegated",
            "The server has no directory delegation to renew.",
        )),
        RenewOutcome::PushFailed(m) => Err(UiError::new(
            "renew_failed",
            &format!("The directory delegation could not be renewed: {m}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::seal_seed;
    use maxsecu_crypto::{verify_delegation, ARGON2_FLOOR, DELEGATION_CLOCK_SKEW_SECS};

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_700_000_000;

    fn d5() -> SigningKey {
        SigningKey::from_seed(&[1u8; 32])
    }
    fn op_pub() -> [u8; 32] {
        SigningKey::from_seed(&[7u8; 32]).verifying_key().to_bytes()
    }

    // ---- pure threshold: is_due ----

    #[test]
    fn is_due_fires_at_or_within_the_21_day_threshold() {
        // Exactly at now+21d ⇒ due (inclusive).
        assert!(is_due(NOW + 21 * DAY, NOW, false));
        // Inside the window ⇒ due.
        assert!(is_due(NOW + 10 * DAY, NOW, false));
        // Already expired ⇒ due.
        assert!(is_due(NOW - DAY, NOW, false));
    }

    #[test]
    fn is_due_no_ops_when_farther_out_unless_forced() {
        // Just past the threshold ⇒ NOT due.
        assert!(!is_due(NOW + 21 * DAY + 1, NOW, false));
        assert!(!is_due(NOW + 89 * DAY, NOW, false));
        // …but --force overrides regardless of how far out.
        assert!(is_due(NOW + 89 * DAY, NOW, true));
        assert!(is_due(NOW + 10_000 * DAY, NOW, true));
    }

    // ---- pure signing: sign_renewal ----

    #[test]
    fn sign_renewal_is_for_the_same_op_pub_and_a_sane_90_day_window() {
        let d5 = d5();
        let op = op_pub();
        let (cert, valid_until) = sign_renewal(&d5, &op, NOW);

        // A fresh 90-day window starting now.
        assert_eq!(valid_until, NOW + RENEW_WINDOW_SECS);
        assert_eq!(RENEW_WINDOW_SECS, 90 * DAY);

        let parsed = parse_delegation(&cert).expect("renewal parses");
        // Same operational_pub (the server requires this).
        assert_eq!(parsed.operational_pub(), op);
        // valid_from is BACK-DATED by the clock-skew margin so the cert still passes
        // the server's strict `now >= valid_from` check when the server clock trails
        // this (client) clock. valid_until is UNCHANGED (expiry not extended).
        assert_eq!(parsed.valid_from(), NOW - DELEGATION_CLOCK_SKEW_SECS);
        assert_eq!(parsed.valid_until(), NOW + 90 * DAY);

        // Within the server's "sane window" (spec §6): non-empty, ends in future,
        // ≤ 366 days (90d + the 24h back-date = 91d), and valid_from not in the
        // future (it is back-dated, so trivially ≤ now + the forward-skew).
        let (vf, vu) = (parsed.valid_from(), parsed.valid_until());
        assert!(
            vu > NOW && vu >= vf && vu - vf <= 366 * DAY && vf <= NOW + DELEGATION_CLOCK_SKEW_SECS
        );
        assert_eq!(vu - vf, 90 * DAY + DELEGATION_CLOCK_SKEW_SECS);
    }

    // The whole point of the back-date: a renewal signed against THIS (client) clock
    // must still verify on a server whose clock TRAILS ours by up to the skew margin.
    #[test]
    fn signed_renewal_verifies_on_a_server_clock_behind_by_up_to_the_skew_margin() {
        let d5 = d5();
        let op = op_pub();
        let (cert, _) = sign_renewal(&d5, &op, NOW);
        let d5_pub = d5.verifying_key().to_bytes();

        // Server exactly the skew margin behind ⇒ now == valid_from ⇒ passes (inclusive).
        assert!(
            verify_delegation(&d5_pub, &cert, NOW - DELEGATION_CLOCK_SKEW_SECS).is_ok(),
            "server behind by exactly the margin must still verify"
        );
        // One second past the margin ⇒ before valid_from ⇒ fails closed.
        assert!(
            verify_delegation(&d5_pub, &cert, NOW - DELEGATION_CLOCK_SKEW_SECS - 1).is_err(),
            "server behind by MORE than the margin must fail closed"
        );
    }

    #[test]
    fn signed_renewal_verifies_against_the_d5_pub_inside_its_window() {
        let d5 = d5();
        let op = op_pub();
        let (cert, _) = sign_renewal(&d5, &op, NOW);
        let d5_pub = d5.verifying_key().to_bytes();
        // Verifies + extracts the exact op-key inside the window.
        let extracted = verify_delegation(&d5_pub, &cert, NOW + DAY).expect("verifies in-window");
        assert_eq!(extracted, op);
        // Fails closed once past the window (defense-in-depth on the fresh cert).
        assert!(verify_delegation(&d5_pub, &cert, NOW + 91 * DAY).is_err());
    }

    // ---- fail-closed: run_renew skips cleanly with no network ----

    fn tempdir() -> PathBuf {
        let rand: String = maxsecu_crypto::random_array::<8>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let p = std::env::temp_dir().join(format!("maxsecu-renew-{}-{rand}", std::process::id()));
        std::fs::create_dir_all(p.join("config")).unwrap();
        p
    }

    // The on-login hook (via run_renew) must SKIP silently when there is no
    // d5_key.blob — the non-admin case — without touching the network/session.
    #[tokio::test]
    async fn run_renew_no_d5_blob_is_a_silent_noop() {
        let dir = tempdir();
        let outcome = run_renew(
            &dir,
            "any-passphrase-at-all",
            &Session::new(),
            &ConnectLock::new(),
            false,
        )
        .await;
        assert_eq!(outcome, RenewOutcome::NoD5);
    }

    // And it must SKIP silently when the blob exists but the entered passphrase is
    // not the recovery passphrase (the D5 won't unseal) — still no network/session.
    #[tokio::test]
    async fn run_renew_wrong_passphrase_is_a_silent_noop() {
        let dir = tempdir();
        let seed = d5().to_seed();
        let blob = seal_seed("the-real-recovery-passphrase", &seed, ARGON2_FLOOR).unwrap();
        std::fs::write(d5_blob_path(&dir), &blob).unwrap();

        let outcome = run_renew(
            &dir,
            "a-different-wrong-passphrase",
            &Session::new(),
            &ConnectLock::new(),
            false,
        )
        .await;
        assert_eq!(outcome, RenewOutcome::UnsealFailed);
    }

    // With a good blob + right passphrase but NO active session (unlocked, not
    // connected), the reauth path fails "locked" and we degrade to PushFailed — a
    // benign, non-blocking skip. Proves the hook never blocks and never panics even
    // when it gets past the D5 gate.
    #[tokio::test]
    async fn run_renew_without_a_session_degrades_to_push_failed_not_panic() {
        let dir = tempdir();
        // A configured server so we reach the reauth step (which then fails locked).
        std::fs::write(
            dir.join("config").join("connection.json"),
            serde_json::json!({ "server": "127.0.0.1:1", "use_tor": false, "auto_connect": false })
                .to_string(),
        )
        .unwrap();
        let blob = seal_seed("pw", &d5().to_seed(), ARGON2_FLOOR).unwrap();
        std::fs::write(d5_blob_path(&dir), &blob).unwrap();

        let outcome = run_renew(&dir, "pw", &Session::new(), &ConnectLock::new(), false).await;
        assert!(
            matches!(outcome, RenewOutcome::PushFailed(_)),
            "no session ⇒ soft PushFailed, got {outcome:?}"
        );
    }
}
