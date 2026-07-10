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
    /// The username this session authenticated as. Stored so channel-bound admin
    /// commands can RE-AUTHENTICATE on a fresh connection (the connect-minted
    /// token is bound to a closed channel and unusable elsewhere).
    pub username: Option<String>,
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

    /// Acquire the connect lock for a `reauth`, tolerating a brief collision with a
    /// concurrent SIBLING reauth. `connect` holds this lock across its whole
    /// (possibly slow) run via `try_lock`; a per-call `reauth` that overlaps another
    /// reauth for a few milliseconds must not instantly fail with "busy". Wait up to
    /// a small budget (`RETRIES × STEP`) for the lock, then fail honestly if it is
    /// still held.
    ///
    /// Discipline preserved: only ONE reauth ever holds this guard at a time, so the
    /// transient `Identity` take/restore in `reauth` can never overlap another's —
    /// collisions just queue briefly instead of erroring.
    pub(crate) async fn acquire_reauth(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, UiError> {
        const RETRIES: u32 = 5;
        const STEP: std::time::Duration = std::time::Duration::from_millis(50);
        for _ in 0..RETRIES {
            if let Ok(guard) = self.0.try_lock() {
                return Ok(guard);
            }
            tokio::time::sleep(STEP).await;
        }
        // Final attempt so a lock freed exactly on the last tick still succeeds.
        self.0
            .try_lock()
            .map_err(|_| UiError::new("busy", "A connection attempt is already in progress."))
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
    app: tauri::AppHandle,
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

    // Best-effort offline-D5 delegation auto-renew (spec §7). Spawned DETACHED so
    // it never blocks the unlock returning. On a non-admin device (no `d5_key.blob`)
    // or when the login passphrase is not the recovery passphrase (the D5 won't
    // unseal) this is a SILENT no-op; every outcome is only logged, never surfaced,
    // and a failure can never weaken trust (the existing delegation stands and the
    // verify-hop keeps failing closed on an expired one).
    let pw = zeroize::Zeroizing::new(password.as_str().to_owned());
    tauri::async_runtime::spawn(async move {
        crate::commands::renew::auto_renew_on_login(app, pw).await;
    });
    Ok(())
}

#[tauri::command]
pub async fn logout(session: tauri::State<'_, Session>) -> Result<(), UiError> {
    let mut s = session.0.lock().await;
    s.token = None;
    s.identity = None; // forget the unlocked key on logout
    s.server_id.clear();
    s.username = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ConnectLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // Two concurrent reauths must NOT spuriously fail with "busy": the second
    // briefly waits for the (short) first to release, then succeeds. Mutual
    // exclusion is preserved — the in-flight counter never exceeds 1, which is
    // exactly the guarantee that the identity-take window can never overlap.
    #[tokio::test]
    async fn concurrent_reauth_lock_serializes_without_spurious_busy() {
        let lock = Arc::new(ConnectLock::new());
        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        async fn hold(lock: Arc<ConnectLock>, inflight: Arc<AtomicUsize>, peak: Arc<AtomicUsize>) {
            let g = lock
                .acquire_reauth()
                .await
                .expect("a sibling reauth must not spuriously return busy");
            let n = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            // Hold well under the wait budget so the sibling can acquire in time.
            tokio::time::sleep(Duration::from_millis(80)).await;
            inflight.fetch_sub(1, Ordering::SeqCst);
            drop(g);
        }

        let a = tokio::spawn(hold(lock.clone(), inflight.clone(), peak.clone()));
        let b = tokio::spawn(hold(lock.clone(), inflight.clone(), peak.clone()));
        a.await.unwrap();
        b.await.unwrap();

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two reauths must never hold the connect lock at the same time"
        );
    }

    // If the lock is genuinely held past the wait budget (e.g. a slow real
    // `connect` holding it for a Tor bootstrap), a reauth fails HONESTLY with the
    // stable `busy` code rather than hanging forever.
    #[tokio::test]
    async fn reauth_lock_fails_closed_when_held_past_budget() {
        let lock = ConnectLock::new();
        let _held = lock.0.lock().await; // hold for the whole test
        let err = lock
            .acquire_reauth()
            .await
            .expect_err("a lock held past the budget must fail closed");
        assert_eq!(err.code, "busy");
    }
}
