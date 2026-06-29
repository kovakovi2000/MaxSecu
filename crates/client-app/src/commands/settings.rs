//! Settings commands. Settings are non-secret local preferences persisted to
//! <dir>/config/settings.json; nothing here holds key/secret material.
use tauri::State;

use crate::commands::auth::AppDir;
use crate::config::SettingsConfig;
use crate::error::UiError;

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
) -> Result<SettingsConfig, UiError> {
    let norm = settings.normalized();
    norm.save(&dir.0)
        .map_err(|_| UiError::new("settings_failed", "Could not save settings."))?;
    Ok(norm)
}
