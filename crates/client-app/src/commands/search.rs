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
    // Namespaced per principal so a recovery session never reads (and fails closed
    // on) a user's index, and vice versa — but a MISSING principal is not an error
    // here. This is a purely local read of `<dir>/index/search.idx`; it only ever
    // needed an unlocked identity, and "unlocked but not connected" is a normal,
    // reachable state (`unlock_keystore` sets `identity` on its own; `principal` is
    // not set until `connect`). Requiring one would be a new failure mode for an
    // ordinary offline user.
    //
    // Defaulting that state to the USER namespace is exact, not a guess: a recovery
    // identity is only ever installed TOGETHER with `Principal::Recovery`, under one
    // lock (`answer_recovery_challenge`), so an identity without a principal is
    // always a keystore identity — and the user file is the one this command has
    // always read.
    let idx = match guard.principal.as_ref() {
        Some(principal) => index::load_for(&dir.0, identity, principal)?,
        None => index::load(&dir.0, identity)?,
    };
    Ok(idx.search(&req.query))
}
