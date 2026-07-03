//! Admin commands: mint single-use registration keys. In the trusted-server
//! recovery model the SERVER is the enrollment authority and signs every binding
//! itself (spec §5) — there is no offline ceremony, no approval queue, and no
//! voucher/pending flow. The only admin action the running app performs is asking
//! the server to mint a fresh registration key. Channel-bound sessions can't be
//! reused across connections, so this authenticated command re-auths on a fresh
//! channel.

use tauri::State;

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{reauth, server_of};
use crate::dto::MintedKeyResponse;
use crate::error::UiError;
use crate::http_client::post_json;

use hyper::StatusCode;

/// `mint_registration_key` — mint a single-use **registration key** (T4). The
/// server generates a strong key, stores only its `sha256`, and returns the
/// plaintext ONCE via `POST /v1/registration-keys` (admin-gated). The returned
/// value is the registration key the enrollee types into the enrollment panel; it
/// is always a User-only key (only the first-ever registrant is admin). The key is
/// never logged — only the DTO crosses the seam.
#[tauri::command]
pub async fn mint_registration_key(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<MintedKeyResponse, UiError> {
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let body = serde_json::json!({});
    let (status, json) =
        post_json(&mut sender, "/v1/registration-keys", &body, Some(&token), &host).await?;
    match status {
        StatusCode::CREATED => {
            let registration_key = json["registration_key"]
                .as_str()
                .ok_or_else(|| {
                    UiError::new("key_failed", "Server returned no registration key.")
                })?
                .to_owned();
            Ok(MintedKeyResponse { registration_key })
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
