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

/// `pick_files` — like [`pick_file`] but allows selecting MULTIPLE files in one
/// dialog, returning all chosen paths (empty vec if the user cancelled). The
/// bundle composer's "Add media" calls this so members can be added in a single
/// pick instead of one-by-one.
///
/// Same security posture as [`pick_file`]: UNAUTHENTICATED, touches no server
/// channel / keystore / identity, returns only filesystem PATH strings (never any
/// file bytes). The blocking native dialog runs on a `spawn_blocking` thread.
#[tauri::command]
pub async fn pick_files(extensions: Vec<String>) -> Result<Vec<String>, UiError> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = rfd::FileDialog::new();
        if !extensions.is_empty() {
            let refs: Vec<&str> = extensions.iter().map(String::as_str).collect();
            dialog = dialog.add_filter("Supported files", &refs);
        }
        dialog.pick_files()
    })
    .await
    .map_err(|_| UiError::new("dialog_failed", "Could not open the file dialog."))?;

    Ok(picked
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect())
}

/// `pick_folder` — open the native "select folder" dialog and return the chosen
/// directory path, or `None` if the user cancelled. The bundle screen's
/// "Download all" (Task 5.2) calls this to pick ONE destination directory into
/// which each member is then written (via `download_content`).
///
/// Like [`pick_file`]/[`save_file`], this is UNAUTHENTICATED, touches no server
/// channel / keystore / identity, and returns only a filesystem PATH string. The
/// blocking native dialog runs on a `spawn_blocking` thread.
#[tauri::command]
pub async fn pick_folder() -> Result<Option<String>, UiError> {
    let picked = tauri::async_runtime::spawn_blocking(move || rfd::FileDialog::new().pick_folder())
        .await
        .map_err(|_| UiError::new("dialog_failed", "Could not open the folder dialog."))?;

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
