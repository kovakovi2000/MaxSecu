//! Settings commands. Settings are non-secret local preferences persisted to
//! <dir>/config/settings.json; nothing here holds key/secret material.
use tauri::State;

use crate::commands::auth::AppDir;
use crate::config::SettingsConfig;
use crate::dto::{ChangePasswordRequest, ExportKeystoreRequest};
use crate::error::UiError;
use crate::keystore;

/// `system_cores` — the machine's available parallelism (logical CPUs), used by
/// the Settings UI as the upper bound (`max`) for the transcode/decode thread
/// budgets. Mirrors `config::default_cpu_threads`'s saturating fallback so the
/// UI's `max` and the backend's clamp agree. Non-secret; no state needed.
#[tauri::command]
pub async fn system_cores() -> Result<u16, UiError> {
    Ok(std::thread::available_parallelism()
        .map(|n| n.get().min(u16::MAX as usize) as u16)
        .unwrap_or(1))
}

/// `get_settings` — load the persisted settings (defaults if absent), normalized.
#[tauri::command]
pub async fn get_settings(dir: State<'_, AppDir>) -> Result<SettingsConfig, UiError> {
    Ok(SettingsConfig::load(&dir.0))
}

/// `set_settings` — persist the settings (normalized/clamped) and return the
/// normalized value so the UI reflects any clamping.
#[tauri::command]
pub async fn set_settings(
    settings: SettingsConfig,
    dir: State<'_, AppDir>,
    media: State<'_, crate::media_cache::MediaCache>,
    thumb: State<'_, crate::thumb_cache::ThumbCache>,
) -> Result<SettingsConfig, UiError> {
    let norm = settings.normalized();
    norm.save(&dir.0)
        .map_err(|_| UiError::new("settings_failed", "Could not save settings."))?;
    // Apply BOTH (normalized) RAM-cache caps live: a smaller cap evicts now.
    // TODO(Task 7): gate on Memory mode (a Disk cache is uncapped `None`).
    media
        .0
        .lock()
        .await
        .set_cap(norm.performance.media_cache_cap_mb as u64 * 1024 * 1024);
    thumb.set_cap_mb(norm.performance.thumb_cache_cap_mb).await;
    // TODO(Task 7): rebuild both caches on cache_location change (until then a
    // location change takes effect on the next app restart).
    Ok(norm)
}

/// `change_password` — re-seal the at-rest keystore under a new password. Passwords
/// are zeroized; the keystore module enforces wrong-old → unauthorized, weak-new →
/// weak_password (before any write), atomic replace. No key material returned.
#[tauri::command]
pub async fn change_password(
    req: ChangePasswordRequest,
    dir: State<'_, AppDir>,
) -> Result<(), UiError> {
    let old = zeroize::Zeroizing::new(req.old_password);
    let new = zeroize::Zeroizing::new(req.new_password);
    keystore::change_password(&dir.0, old.as_str(), new.as_str())
}

/// `export_keystore` — copy the already-sealed (ciphertext) key blob to a chosen
/// path (portable backup / recovery). Never decrypts.
#[tauri::command]
pub async fn export_keystore(
    req: ExportKeystoreRequest,
    dir: State<'_, AppDir>,
) -> Result<(), UiError> {
    keystore::export_keystore(&dir.0, &req.dest_path)
}
