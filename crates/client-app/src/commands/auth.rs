//! Keystore + session-lifecycle commands and the app's managed state.
//!
//! `Session` holds the unlocked `Identity` and the opaque session token entirely
//! inside the TCB. Neither ever crosses the command boundary to the UI (only the
//! public `server_id` does, via `connect`).

use std::path::PathBuf;

use maxsecu_client_core::Identity;
use tokio::sync::Mutex;

use crate::error::UiError;
use crate::keystore;

/// The portable app directory (keystore + config + pinned cert live beneath it).
/// Resolved at startup beside the executable so the folder travels (stack.md §5.2).
pub struct AppDir(pub PathBuf);

/// The in-RAM session: the unlocked identity, the last server's id, and the
/// opaque session token. `Identity` has no `Default`, but `Option<Identity>`
/// does (`None`), so the whole thing derives `Default`.
#[derive(Default)]
pub struct SessionInner {
    pub identity: Option<Identity>,
    pub server_id: String,
    pub token: Option<String>,
}

/// Async-aware managed wrapper (commands are `async`, so the guard must be a
/// `tokio::sync::Mutex`, not `std::sync::Mutex`).
pub struct Session(pub Mutex<SessionInner>);

impl Session {
    pub fn new() -> Self {
        Self(Mutex::new(SessionInner::default()))
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializes `connect`: Tauri commands can be invoked re-entrantly (double-click
/// / retry-while-pending). Because `connect` takes the `Identity` out of `Session`
/// and releases that lock across its HTTP awaits, two concurrent connects would
/// race (B sees `None`, fails spuriously, and could clobber A's terminal state).
/// `connect` `try_lock`s this for its whole duration so only one runs at a time.
pub struct ConnectLock(pub Mutex<()>);

impl ConnectLock {
    pub fn new() -> Self {
        Self(Mutex::new(()))
    }
}

impl Default for ConnectLock {
    fn default() -> Self {
        Self::new()
    }
}

#[tauri::command]
pub async fn unlock_keystore(
    password: String,
    dir: tauri::State<'_, AppDir>,
    session: tauri::State<'_, Session>,
) -> Result<(), UiError> {
    // Scrub the password buffer on every exit path: `Zeroizing` zeroes the heap
    // bytes on drop whether unlock succeeds, fails, or panics.
    let password = zeroize::Zeroizing::new(password);
    // `keystore::unlock` already returns `Result<Identity, UiError>` with the
    // sanitized codes (no_keystore / unauthorized) — no `?`-From needed.
    let id = keystore::unlock(&dir.0, password.as_str())?;
    session.0.lock().await.identity = Some(id);
    Ok(())
}

#[tauri::command]
pub async fn logout(session: tauri::State<'_, Session>) -> Result<(), UiError> {
    let mut s = session.0.lock().await;
    s.token = None;
    s.identity = None; // forget the unlocked key on logout
    s.server_id.clear();
    Ok(())
}
