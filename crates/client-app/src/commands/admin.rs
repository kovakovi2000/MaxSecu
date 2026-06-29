//! Admin commands: list the approval queue, issue invite vouchers, and prepare
//! ceremony work-items. The running app CANNOT confer admin or sign bindings
//! (the D5 key is offline, D-K) — `request_approval` only shapes the data the
//! air-gapped ceremony needs. Channel-bound sessions can't be reused across
//! connections, so each authenticated command re-auths on a fresh channel.

use tauri::State;

use crate::admin;
use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::reauth;
use crate::config::ConnectionConfig;
use crate::dto::{ApprovalRequest, CeremonyWorkItem, IssueVoucherResponse, PendingUserDto};
use crate::error::UiError;
use crate::http_client::{get_json, post_json};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hyper::StatusCode;

fn server_of(dir: &std::path::Path) -> Result<String, UiError> {
    let cfg = ConnectionConfig::load(dir);
    if cfg.server.is_empty() {
        return Err(UiError::new("no_server", "No server is configured."));
    }
    Ok(cfg.server)
}

/// `list_pending` — the admin approval queue (D-G). Requires an admin session
/// (re-authed on a fresh channel).
#[tauri::command]
pub async fn list_pending(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<PendingUserDto>, UiError> {
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let (status, json) = get_json(&mut sender, "/v1/pending", Some(&token), &host).await?;
    match status {
        StatusCode::OK => Ok(json["pending"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|u| PendingUserDto {
                        user_id: u["user_id"].as_str().unwrap_or_default().to_owned(),
                        username: u["username"].as_str().unwrap_or_default().to_owned(),
                        created_at: u["created_at"].as_u64().unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(UiError::new("forbidden", "Admin access required."))
        }
        _ => Err(UiError::new(
            "pending_failed",
            "Could not load the approval queue.",
        )),
    }
}

/// `issue_voucher` — generate an invite, post its hash, return the code to show.
#[tauri::command]
pub async fn issue_voucher(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<IssueVoucherResponse, UiError> {
    let server = server_of(&dir.0)?;
    let voucher = admin::generate_voucher();
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let body = serde_json::json!({ "voucher_hash_b64": B64.encode(voucher.hash) });
    let (status, _json) =
        post_json(&mut sender, "/v1/vouchers", &body, Some(&token), &host).await?;
    match status {
        StatusCode::CREATED => Ok(IssueVoucherResponse { code: voucher.code }),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(UiError::new("forbidden", "Admin access required."))
        }
        _ => Err(UiError::new("voucher_failed", "Could not issue an invite.")),
    }
}

/// `request_approval` — produce a ceremony work-item for a pending user (D-K).
/// The running app cannot sign (the D5 key is offline); this hands the operator
/// the data the air-gapped ceremony needs. Pure/local — no network.
#[tauri::command]
pub fn request_approval(req: ApprovalRequest) -> Result<CeremonyWorkItem, UiError> {
    Ok(CeremonyWorkItem {
        user_id: req.user_id,
        roles: vec!["user".to_owned()],
        note: "Confirm the candidate's fingerprint in person, then D5-sign at the ceremony."
            .to_owned(),
    })
}
