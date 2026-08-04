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

/// WHO this session authenticated as. An enum (not a `username` plus an
/// `is_recovery` flag) because the recovery principal has NO username *by
/// construction* — `recovery_register` only stores the recovery account's keys, it
/// never creates a `users` row nor publishes a directory binding — so the pair
/// `username = Some(..) + is_recovery = true` must not even be representable. It
/// also makes the compiler force a decision at every reader: an upload must refuse
/// a recovery principal, a browse must not.
///
/// In-RAM only: never serialized, never persisted, never crosses the Tauri seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    /// An ordinary enrolled user, authenticated by `/v1/session/{challenge,proof}`.
    User { username: String },
    /// The trusted-server RECOVERY account (`RECOVERY_ID`), authenticated by
    /// `/v1/recovery/{challenge,verify}`. Reads everything, uploads nothing.
    Recovery,
}

/// The in-RAM session: the unlocked identity, the last server's id, and the
/// opaque session token. `Identity` has no `Default`, but `Option<Identity>`
/// does (`None`), so the whole thing derives `Default`.
#[derive(Default)]
pub struct SessionInner {
    /// The unlocked key of WHICHEVER principal is signed in — a user's keystore
    /// identity, or the operator's cold recovery identity.
    pub identity: Option<Identity>,
    pub server_id: String,
    pub token: Option<String>,
    /// The principal this session authenticated as. Stored so channel-bound
    /// commands can RE-AUTHENTICATE on a fresh connection (the connect-minted
    /// token is bound to a closed channel and unusable elsewhere).
    pub principal: Option<Principal>,
}

impl SessionInner {
    /// The signed-in username, or `None` for a not-signed-in / recovery session.
    pub fn username(&self) -> Option<&str> {
        match &self.principal {
            Some(Principal::User { username }) => Some(username.as_str()),
            _ => None,
        }
    }

    /// Whether the RECOVERY account is signed in (read-everything, upload-nothing).
    pub fn is_recovery(&self) -> bool {
        matches!(self.principal, Some(Principal::Recovery))
    }
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
pub async fn logout(
    session: tauri::State<'_, Session>,
    pool: tauri::State<'_, crate::commands::pool::AppPool>,
) -> Result<(), UiError> {
    // ORDER IS LOAD-BEARING: clear the session FIRST, drain the pool SECOND.
    //
    // Draining first leaves a window. `drain_idle` bumps the pool's generation, so
    // an `acquire` that ENTERS after the bump is stamped with the new generation --
    // but if the principal is still set it will happily mint a live token for the
    // user who is signing out, and `Drop` then sees `born == current` and re-pools
    // it. That is a signed-out principal's channel-bound token sitting in the idle
    // set; on the recovery path it is a token that can open every user's content.
    //
    // Clearing first closes it from both sides: an acquire that entered BEFORE the
    // clear is stamped with the OLD generation and the drain below makes it born
    // stale, so its channel is discarded on drop; an acquire that enters AFTER the
    // clear finds no principal and no identity, so it cannot mint anything at all.
    {
        let mut s = session.0.lock().await;
        s.token = None;
        s.identity = None; // forget the unlocked key on logout
        s.server_id.clear();
        s.principal = None;
    }
    // Now discard every pooled channel: each holds a live authed connection and a
    // token minted for the principal just cleared.
    pool.drain_idle();
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
