//! Admin commands: list the approval queue, mint single-use registration keys, and
//! prepare ceremony work-items. The running app CANNOT confer admin or sign
//! bindings (the D5 key is offline, D-K) — `request_approval` only shapes the data
//! the air-gapped ceremony needs. Channel-bound sessions can't be reused across
//! connections, so each authenticated command re-auths on a fresh channel.

use tauri::State;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::dto::{ApprovalRequest, CeremonyWorkItem, IssueVoucherResponse, PendingUserDto};
use crate::error::UiError;
use crate::http_client::{get_json, post_json};

use hyper::StatusCode;

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

/// `issue_voucher` — mint a single-use **registration key** (T4). The server
/// generates a strong key, stores only its `sha256`, and returns the plaintext
/// ONCE via `POST /v1/registration-keys` (admin-gated). The returned code is the
/// registration key the enrollee types into the enrollment panel; whoever enrolls
/// first with it becomes admin (here it is always a User-only key, since an admin
/// already exists). The key is never logged — only the DTO crosses the seam.
#[tauri::command]
pub async fn issue_voucher(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<IssueVoucherResponse, UiError> {
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let body = serde_json::json!({});
    let (status, json) =
        post_json(&mut sender, "/v1/registration-keys", &body, Some(&token), &host).await?;
    match status {
        StatusCode::CREATED => {
            let code = json["registration_key"]
                .as_str()
                .ok_or_else(|| {
                    UiError::new("key_failed", "Server returned no registration key.")
                })?
                .to_owned();
            Ok(IssueVoucherResponse { code })
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(UiError::new("forbidden", "Admin access required."))
        }
        _ => Err(UiError::new(
            "key_failed",
            "Could not mint a registration key.",
        )),
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
