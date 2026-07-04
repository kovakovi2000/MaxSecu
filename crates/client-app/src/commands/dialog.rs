//! Native file-picker command. The upload screen's "Browse…" button calls this
//! to open the OS "open file" dialog and receive the chosen path as a string; the
//! UI then drops that path into the existing file-path field and stages as before.
//!
//! Security note: this command is UNAUTHENTICATED and touches no server channel,
//! keystore, or identity. It returns only a filesystem PATH string — never any
//! file bytes (the staging path reads/transcodes the file inside the TCB). It is
//! therefore safe to call without the connect lock / reauth dance.

use crate::error::UiError;

/// `pick_file` — open the native "open file" dialog and return the selected path,
/// or `None` if the user cancelled. `extensions` (lowercase, no dot) optionally
/// narrows the dialog's default filter; an empty list shows all files.
///
/// The blocking native dialog runs on a dedicated blocking thread (via
/// `spawn_blocking`) so it never stalls the async command runtime.
#[tauri::command]
pub async fn pick_file(extensions: Vec<String>) -> Result<Option<String>, UiError> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = rfd::FileDialog::new();
        if !extensions.is_empty() {
            let refs: Vec<&str> = extensions.iter().map(String::as_str).collect();
            dialog = dialog.add_filter("Supported files", &refs);
        }
        dialog.pick_file()
    })
    .await
    .map_err(|_| UiError::new("dialog_failed", "Could not open the file dialog."))?;

    Ok(picked.map(|p| p.to_string_lossy().into_owned()))
}

/// `save_file` — open the native "save file" dialog pre-filled with
/// `default_name` and return the chosen destination path, or `None` if the user
/// cancelled. The download screen (Task 5.2) calls this with
/// `suggested_filename(...)` to obtain a `save_path` for `download_content`.
///
/// Like [`pick_file`], this is UNAUTHENTICATED, touches no server channel /
/// keystore / identity, and returns only a filesystem PATH string (never any file
/// bytes — the decrypt-and-write happens inside the TCB in `download_content`).
/// The blocking native dialog runs on a `spawn_blocking` thread.
#[tauri::command]
pub async fn save_file(default_name: String) -> Result<Option<String>, UiError> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_file_name(&default_name)
            .save_file()
    })
    .await
    .map_err(|_| UiError::new("dialog_failed", "Could not open the file dialog."))?;

    Ok(picked.map(|p| p.to_string_lossy().into_owned()))
}
