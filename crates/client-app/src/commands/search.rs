//! Search over the local encrypted index (D-F). `search_local` returns only
//! `SearchHit`s of matches; the whole index never leaves the TCB.

use tauri::State;

use crate::commands::auth::{AppDir, Session};
use crate::dto::{SearchHit, SearchRequest};
use crate::error::UiError;
use crate::index;

/// `search_local` — case-insensitive title+tag search over the local index.
#[tauri::command]
pub async fn search_local(
    req: SearchRequest,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
) -> Result<Vec<SearchHit>, UiError> {
    // Borrow the unlocked identity under the lock to derive the index key + search
    // (synchronous; no await held, so the session identity is never disturbed).
    let guard = session.0.lock().await;
    let identity = guard
        .identity
        .as_ref()
        .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
    let idx = index::load(&dir.0, identity)?;
    Ok(idx.search(&req.query))
}
