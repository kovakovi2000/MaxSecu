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
use crate::error::UiError;
use crate::http_client::post_json;

use hyper::StatusCode;
use zeroize::Zeroizing;

/// `mint_registration_key` — mint a single-use **registration key** (T4) and write
/// it straight to `dest_path` (the file the admin chose in the native Save
/// dialog). The server generates a strong key, stores only its `sha256`, and
/// returns the plaintext ONCE via `POST /v1/registration-keys` (admin-gated). The
/// plaintext is a User-only key (only the first-ever registrant is admin).
///
/// Security: the key is a capability token, so it is deliberately **never returned
/// across the UI seam and never logged** — it is held in `Zeroizing` (wiped after
/// use) and written to the operator-chosen file inside the TCB. Only the saved
/// path is returned, for the confirmation line. The file format matches
/// `maxsecu-setup`'s `register.key`: the raw key bytes, no trailing newline.
#[tauri::command]
pub async fn mint_registration_key(
    dest_path: String,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<String, UiError> {
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let body = serde_json::json!({});
    let (status, json) =
        post_json(&mut sender, "/v1/registration-keys", &body, Some(&token), &host).await?;
    match status {
        StatusCode::CREATED => {
            let registration_key = Zeroizing::new(
                json["registration_key"]
                    .as_str()
                    .ok_or_else(|| {
                        UiError::new("key_failed", "Server returned no registration key.")
                    })?
                    .to_owned(),
            );
            std::fs::write(&dest_path, registration_key.as_bytes()).map_err(|_| {
                UiError::new(
                    "write_failed",
                    "Could not save the registration key to that location.",
                )
            })?;
            Ok(dest_path)
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
