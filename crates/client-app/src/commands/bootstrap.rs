//! Unauthenticated account-provisioning commands (spec §4.1/§4.2): glass-break
//! emergency creds, the first-admin keystore, and voucher-gated user enrollment.
//! Each opens a fresh pinned-TLS connection (no session — these run BEFORE login)
//! and posts to the server's `POST /v1/bootstrap` or `POST /v1/users`.

use std::path::Path;

use maxsecu_client_core::Identity;
use tauri::State;

use crate::commands::auth::AppDir;
use crate::commands::connection::open_conn;
use crate::config::ConnectionConfig;
use crate::dto::{
    AccountStatusRequest, BootstrapRequest, FirstAdminRequest, GlassbreakResponse,
    RegisterUserRequest,
};
use crate::error::UiError;
use crate::http_client::{get_json, post_json};
use crate::state::AccountState;
use crate::{bootstrap, keystore};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hyper::StatusCode;

fn b64(bytes: impl AsRef<[u8]>) -> String {
    B64.encode(bytes.as_ref())
}

fn server_of(dir: &Path) -> Result<String, UiError> {
    let cfg = ConnectionConfig::load(dir);
    if cfg.server.is_empty() {
        return Err(UiError::new("no_server", "No server is configured."));
    }
    Ok(cfg.server)
}

/// `register_glassbreak` — generate emergency creds, seal them (NOT a login),
/// optionally also seal into `save_path`, and register via /v1/bootstrap.
#[tauri::command]
pub async fn register_glassbreak(
    req: BootstrapRequest,
    dir: State<'_, AppDir>,
) -> Result<GlassbreakResponse, UiError> {
    let creds = bootstrap::generate_glassbreak();
    bootstrap::ensure_strong(&creds.password)?;
    // Fail fast BEFORE the network call so a server rejection never leaves an
    // orphaned sealed blob (which would wedge the next attempt). Nothing is
    // written to disk until the server has accepted the registration.
    let gb_dir = dir.0.join("glassbreak");
    keystore::precheck(&gb_dir, &creds.password)?;
    if let Some(path) = req.save_path.as_deref() {
        keystore::precheck(Path::new(path), &creds.password)?;
    }
    let server = server_of(&dir.0)?;
    let (mut sender, host, _exp) = open_conn(&dir.0, &server).await?;
    let body = serde_json::json!({
        "username": creds.username,
        "enc_pub_b64": b64(creds.identity.enc_pub_bytes()),
        "sig_pub_b64": b64(creds.identity.sig_pub_bytes()),
        "bootstrap_secret": req.bootstrap_secret,
    });
    let (status, json) = post_json(&mut sender, "/v1/bootstrap", &body, None, &host).await?;
    let user_id = bootstrap_user_id(status, &json)?; // Err on non-201 → nothing sealed
                                                     // Only now persist the emergency identity (offline, never auto-loaded).
    keystore::seal_identity(&gb_dir, &creds.password, &creds.identity)?;
    if let Some(path) = req.save_path.as_deref() {
        keystore::seal_identity(Path::new(path), &creds.password, &creds.identity)?;
    }
    Ok(GlassbreakResponse {
        username: creds.username,
        password: creds.password,
        user_id,
    })
}

/// `create_first_admin` — create the operator's chosen admin account (the MAIN
/// keystore) via /v1/bootstrap. Admin role is conferred later by the ceremony.
#[tauri::command]
pub async fn create_first_admin(
    req: FirstAdminRequest,
    dir: State<'_, AppDir>,
) -> Result<String, UiError> {
    keystore::precheck(&dir.0, &req.password)?; // fail fast, no disk write
    let id = Identity::generate();
    let server = server_of(&dir.0)?;
    let (mut sender, host, _exp) = open_conn(&dir.0, &server).await?;
    let body = serde_json::json!({
        "username": req.username,
        "enc_pub_b64": b64(id.enc_pub_bytes()),
        "sig_pub_b64": b64(id.sig_pub_bytes()),
        "bootstrap_secret": req.bootstrap_secret,
    });
    let (status, json) = post_json(&mut sender, "/v1/bootstrap", &body, None, &host).await?;
    let user_id = bootstrap_user_id(status, &json)?; // Err on non-201 → nothing sealed
    keystore::seal_identity(&dir.0, &req.password, &id)?; // only now persist
    Ok(user_id)
}

/// `register_user` — voucher-gated enrollment via /v1/users (post-bootstrap path).
#[tauri::command]
pub async fn register_user(
    req: RegisterUserRequest,
    dir: State<'_, AppDir>,
) -> Result<String, UiError> {
    keystore::precheck(&dir.0, &req.password)?; // fail fast, no disk write
    let id = Identity::generate();
    let server = server_of(&dir.0)?;
    let (mut sender, host, _exp) = open_conn(&dir.0, &server).await?;
    let body = serde_json::json!({
        "username": req.username,
        "enc_pub_b64": b64(id.enc_pub_bytes()),
        "sig_pub_b64": b64(id.sig_pub_bytes()),
        "enrollment_voucher": req.voucher,
    });
    let (status, json) = post_json(&mut sender, "/v1/users", &body, None, &host).await?;
    match status {
        StatusCode::CREATED => {
            let uid = json["user_id"]
                .as_str()
                .map(|s| s.to_owned())
                .ok_or_else(|| UiError::new("internal", "Malformed server response."))?;
            keystore::seal_identity(&dir.0, &req.password, &id)?; // only now persist
            Ok(uid)
        }
        StatusCode::CONFLICT => Err(UiError::new("username_taken", "That username is taken.")),
        StatusCode::FORBIDDEN => Err(UiError::new(
            "bad_voucher",
            "That invite code is invalid or used.",
        )),
        _ => Err(UiError::new("register_failed", "Registration failed.")),
    }
}

/// `account_status` — poll whether the signed-in account has been approved (its
/// binding published). `404` → Pending; `200` → Active. Status only — the
/// directory body is opaque here (the client TCB re-verifies it elsewhere).
///
/// SECURITY: the served directory body is intentionally ignored (`_json`). This
/// is a coarse status poll only; the full client-side D5/TOFU re-verification of
/// a served binding lives in the TCB / trust-store flow, NOT in this check — so
/// we never treat an unverified served binding as trusted here.
#[tauri::command]
pub async fn account_status(
    req: AccountStatusRequest,
    dir: State<'_, AppDir>,
) -> Result<AccountState, UiError> {
    let server = server_of(&dir.0)?;
    let (mut sender, host, _exp) = open_conn(&dir.0, &server).await?;
    let (status, _json) = get_json(
        &mut sender,
        &format!("/v1/directory/{}", req.username),
        None,
        &host,
    )
    .await?;
    match status {
        StatusCode::OK => Ok(AccountState::Active),
        StatusCode::NOT_FOUND => Ok(AccountState::Pending),
        _ => Err(UiError::new(
            "status_failed",
            "Could not check account status.",
        )),
    }
}

fn bootstrap_user_id(status: StatusCode, json: &serde_json::Value) -> Result<String, UiError> {
    match status {
        StatusCode::CREATED => json["user_id"]
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| UiError::new("internal", "Malformed server response.")),
        StatusCode::CONFLICT => Err(UiError::new(
            "bootstrap_unavailable",
            "Bootstrap is closed or that username is taken.",
        )),
        StatusCode::UNAUTHORIZED => Err(UiError::new(
            "bad_secret",
            "The bootstrap secret is incorrect.",
        )),
        _ => Err(UiError::new("bootstrap_failed", "Bootstrap failed.")),
    }
}
