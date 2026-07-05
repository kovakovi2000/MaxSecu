//! An authed **connection pool** so feed-card decodes can run concurrently.
//!
//! Every authed read command re-authenticates on a FRESH channel via
//! [`crate::commands::connection::reauth`], which `try_lock`s the ONE `ConnectLock`
//! for the whole login handshake and transiently `take`s the single non-`Clone`
//! `Identity` out of the session. That serializes reads: a SECOND concurrent
//! `reauth` gets `Err("busy")` and a concurrent command sees the taken identity as
//! `None`. So two `decrypt_card` calls can't overlap (why the UI serializes them).
//!
//! Because the session token is **channel-bound** (bound to the TLS channel's
//! exporter by `login_exchange`), a token can't be shared across channels — each
//! concurrent request needs its OWN channel+token. This pool caches whole authed
//! channels (`{sender, host, token}` as ONE unit) and hands each concurrent borrower
//! a DIFFERENT cached channel: no `reauth`, no `ConnectLock`, no identity-take on the
//! hot path. When a fresh channel MUST be minted the pool calls the existing `reauth`
//! under an INTERNAL async **auth gate** so `reauth` is never invoked concurrently
//! (its `try_lock` therefore never fails) — and only on cold-start / expiry, not per
//! read.
//!
//! Security discipline: a token NEVER leaves its channel (channel-bound); the three
//! parts are reused as one unit. Channel creation reuses `reauth` VERBATIM (its
//! ConnectLock + identity-take discipline unchanged) — the pool only ensures it's
//! serialized. A pooled channel older than [`REUSE_WINDOW_MS`] (well under the server
//! session TTL) is discarded and re-minted; a borrower that hits a `401`/transport
//! error marks its channel bad so it is discarded, never returned. Channels live in
//! the TCB (Tauri managed state) and never cross the Tauri seam.

use std::future::Future;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::UiError;

/// Reuse window for a pooled channel (ms). The server session TTL is 60 min
/// (`server::auth` `session_ttl_ms = 3_600_000`); we re-mint a channel older than
/// **20 min** — a conservative one-third of the TTL, leaving 40 min of headroom so a
/// reused token can never be close to expiry. A `401` mid-use is still handled
/// (fail-closed: discard + re-auth) via [`PooledGuard::mark_bad`].
pub const REUSE_WINDOW_MS: u64 = 20 * 60 * 1000;

/// A monotonic-ish wall clock (ms since epoch). Injectable so the expiry unit test
/// can drive time without sleeping.
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One idle pooled channel plus the wall-clock time it was minted (for expiry).
struct PooledConn<C> {
    channel: C,
    minted_at_ms: u64,
}

/// An authed connection pool generic over the channel type `C`. Production uses
/// `C = crate::jobs::AuthedChannel` (see [`AppPool`]); unit tests use a trivial fake.
///
/// * a [`Semaphore`] of `cap` permits caps the number of LIVE channels;
/// * an idle set (`std::sync::Mutex<Vec<PooledConn<C>>>`) holds returned channels for
///   reuse — a plain `std` mutex so the guard's `Drop` (synchronous) can return a
///   channel without awaiting; the lock is only ever held for a trivial push/pop,
///   never across an `.await`;
/// * an async **auth gate** (`tokio::sync::Mutex<()>`) serializes channel MINTING so
///   the underlying `reauth` is never called concurrently.
pub struct AuthedPool<C> {
    idle: Arc<Mutex<Vec<PooledConn<C>>>>,
    permits: Arc<Semaphore>,
    auth_gate: tokio::sync::Mutex<()>,
    reuse_window_ms: u64,
    clock: Clock,
}

impl<C: Send + 'static> AuthedPool<C> {
    /// A pool capping live channels at `cap` (clamped to at least 1), with the
    /// production reuse window and wall clock.
    pub fn new(cap: usize) -> Self {
        Self::with_config(cap, REUSE_WINDOW_MS, Arc::new(now_ms))
    }

    /// Construct with an explicit reuse window + clock (used by the unit tests to
    /// drive expiry deterministically).
    fn with_config(cap: usize, reuse_window_ms: u64, clock: Clock) -> Self {
        let cap = cap.max(1);
        Self {
            idle: Arc::new(Mutex::new(Vec::new())),
            permits: Arc::new(Semaphore::new(cap)),
            auth_gate: tokio::sync::Mutex::new(()),
            reuse_window_ms,
            clock,
        }
    }

    /// Acquire an EXCLUSIVE channel for the duration of the returned guard. Reuses a
    /// non-expired idle channel if one exists (no auth); otherwise mints a fresh one
    /// via `mint` under the auth gate (so the real `reauth` is never concurrent).
    /// The guard returns the channel to the idle set on drop (unless marked bad) and
    /// releases the permit.
    ///
    /// `mint` is the channel-creation step: production supplies a `reauth`-backed
    /// closure; tests supply a fake. It is only ever awaited while the auth gate is
    /// held, so it is never run concurrently with itself.
    pub async fn acquire<F, Fut>(&self, mint: F) -> Result<PooledGuard<C>, UiError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<C, UiError>>,
    {
        // 1) Cap live channels. The permit rides in the guard and is released on drop.
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| UiError::new("pool_closed", "The connection pool is unavailable."))?;

        // 2) Reuse a non-expired idle channel if one is available (no auth, no gate).
        if let Some(conn) = self.take_fresh_idle() {
            return Ok(self.guard_from(conn, permit));
        }

        // 3) No reusable idle channel — mint under the auth gate so channel creation
        //    (the real `reauth`) is serialized and its `ConnectLock` try_lock never
        //    races. Re-check idle after taking the gate: a concurrent borrower may
        //    have returned a channel while we waited, avoiding an over-mint.
        let _gate = self.auth_gate.lock().await;
        if let Some(conn) = self.take_fresh_idle() {
            return Ok(self.guard_from(conn, permit));
        }
        let channel = mint().await?;
        let conn = PooledConn {
            channel,
            minted_at_ms: (self.clock)(),
        };
        Ok(self.guard_from(conn, permit))
    }

    /// Discard ALL cached idle channels (clear the idle set). A `401` on an authed
    /// GET means the SESSION token was rejected — server restart or session
    /// invalidation makes EVERY pooled sibling channel (same-era token) stale, not
    /// just the one that hit the 401. So a caller that saw a 401 drains the whole idle
    /// set; the next [`acquire`](Self::acquire) then finds it empty and is FORCED to
    /// mint a fresh channel via `reauth`, instead of drawing another stale sibling.
    /// Permits for currently-BORROWED channels are untouched (their guards still hold
    /// them); those channels are individually discarded by their borrowers via
    /// [`PooledGuard::mark_bad`].
    pub fn drain_idle(&self) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.clear();
    }

    /// Pop the newest idle channel that is still within the reuse window, discarding
    /// (dropping/closing) any expired ones encountered.
    fn take_fresh_idle(&self) -> Option<PooledConn<C>> {
        let now = (self.clock)();
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(conn) = idle.pop() {
            if now.saturating_sub(conn.minted_at_ms) <= self.reuse_window_ms {
                return Some(conn);
            }
            // Expired: drop `conn` (closes the stale channel); keep looking.
        }
        None
    }

    fn guard_from(&self, conn: PooledConn<C>, permit: OwnedSemaphorePermit) -> PooledGuard<C> {
        PooledGuard {
            channel: Some(conn.channel),
            minted_at_ms: conn.minted_at_ms,
            idle: self.idle.clone(),
            _permit: permit,
            bad: false,
        }
    }
}

/// An exclusive borrow of a pooled channel. Derefs to the channel `C` so callers use
/// its fields directly. On drop the channel is returned to the pool's idle set (for
/// reuse) UNLESS [`mark_bad`](Self::mark_bad) was called (a `401`/transport error), in
/// which case it is discarded. The semaphore permit is released on drop either way.
pub struct PooledGuard<C> {
    channel: Option<C>,
    minted_at_ms: u64,
    idle: Arc<Mutex<Vec<PooledConn<C>>>>,
    _permit: OwnedSemaphorePermit,
    bad: bool,
}

impl<C> PooledGuard<C> {
    /// Mark this channel as unusable (e.g. a `401` — the token expired, or a transport
    /// error). It is DISCARDED on drop instead of returned to the pool, so a stale
    /// token can never be reused: fail-closed.
    pub fn mark_bad(&mut self) {
        self.bad = true;
    }
}

impl<C> std::ops::Deref for PooledGuard<C> {
    type Target = C;
    fn deref(&self) -> &C {
        // `channel` is `Some` for the guard's whole life; only `Drop` takes it.
        self.channel.as_ref().expect("pooled channel present until drop")
    }
}

impl<C> std::ops::DerefMut for PooledGuard<C> {
    fn deref_mut(&mut self) -> &mut C {
        self.channel.as_mut().expect("pooled channel present until drop")
    }
}

impl<C> Drop for PooledGuard<C> {
    fn drop(&mut self) {
        if self.bad {
            return; // discard the bad channel; the permit releases as `_permit` drops.
        }
        if let Some(channel) = self.channel.take() {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            idle.push(PooledConn {
                channel,
                minted_at_ms: self.minted_at_ms,
            });
        }
    }
}

/// The production pool type: an [`AuthedPool`] of real authed HTTP/1.1 channels.
/// Registered as Tauri managed state and injected into `decrypt_card` by type.
pub type AppPool = AuthedPool<crate::jobs::AuthedChannel>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// A trivial fake channel: just an id so tests can tell distinct mints apart.
    #[derive(Debug)]
    struct FakeChan {
        id: u64,
    }

    /// A fake authenticator: counts total mints AND tracks the max number of mints
    /// running concurrently (to prove the auth gate serializes channel creation).
    #[derive(Default)]
    struct FakeAuth {
        total: AtomicUsize,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        slow_ms: u64,
    }
    impl FakeAuth {
        async fn mint(&self) -> Result<FakeChan, UiError> {
            let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(cur, Ordering::SeqCst);
            if self.slow_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.slow_ms)).await;
            }
            let id = self.total.fetch_add(1, Ordering::SeqCst) as u64;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(FakeChan { id })
        }
    }

    #[tokio::test]
    async fn authed_pool_reuses_idle_channel() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        // First acquire mints; dropping the guard returns the channel to idle.
        let first_id = {
            let g = pool.acquire(|| auth.mint()).await.unwrap();
            g.id
        };
        // Second acquire finds the idle channel and REUSES it — no second mint.
        let second_id = {
            let g = pool.acquire(|| auth.mint()).await.unwrap();
            g.id
        };
        assert_eq!(auth.total.load(Ordering::SeqCst), 1, "auth must run only once");
        assert_eq!(first_id, second_id, "the same channel is reused");
    }

    #[tokio::test]
    async fn authed_pool_caps_channels_and_never_auths_concurrently() {
        const N: usize = 4;
        let pool = Arc::new(AuthedPool::<FakeChan>::new(N));
        let auth = Arc::new(FakeAuth {
            slow_ms: 25,
            ..Default::default()
        });
        // All N borrowers hold their channels simultaneously (barrier) so each acquire
        // is forced to MINT (nothing returns to idle mid-flight) — proving up to N,
        // and no more than N, channels are created.
        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let mut handles = Vec::new();
        for _ in 0..N {
            let pool = pool.clone();
            let auth = auth.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let _g = pool.acquire(|| auth.mint()).await.unwrap();
                barrier.wait().await; // hold the channel until all N are acquired
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(auth.total.load(Ordering::SeqCst), N, "exactly N channels minted");
        assert_eq!(
            auth.max_in_flight.load(Ordering::SeqCst),
            1,
            "auth must never run concurrently (serialized by the auth gate)"
        );
    }

    #[tokio::test]
    async fn authed_pool_reauths_expired_channel() {
        let clock = Arc::new(AtomicU64::new(0));
        let clock_r = clock.clone();
        let pool =
            AuthedPool::<FakeChan>::with_config(2, 1_000, Arc::new(move || clock_r.load(Ordering::SeqCst)));
        let auth = FakeAuth::default();

        // Mint at t=0, return to idle.
        drop(pool.acquire(|| auth.mint()).await.unwrap());
        // Advance the clock past the reuse window — the idle channel is now expired.
        clock.store(2_000, Ordering::SeqCst);
        // Next acquire must DISCARD the expired channel and re-auth (mint again).
        drop(pool.acquire(|| auth.mint()).await.unwrap());
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            2,
            "an expired channel is re-authed, not reused"
        );
    }

    #[tokio::test]
    async fn authed_pool_discards_bad_channel_on_drop() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        // Acquire, mark bad (as a 401 would), drop — the channel is NOT returned.
        {
            let mut g = pool.acquire(|| auth.mint()).await.unwrap();
            g.mark_bad();
        }
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a bad channel is discarded, not pooled"
        );
        // The next acquire must mint a fresh channel (nothing to reuse).
        drop(pool.acquire(|| auth.mint()).await.unwrap());
        assert_eq!(auth.total.load(Ordering::SeqCst), 2, "bad channel forces a re-auth");
    }

    #[tokio::test]
    async fn authed_pool_drain_idle_forces_fresh_mint_over_a_stale_sibling() {
        // cap=2 so a sibling channel can sit idle while another is (was) borrowed.
        let pool = AuthedPool::<FakeChan>::new(2);
        let auth = FakeAuth::default();

        // Mint two channels, return BOTH to idle (2 stale siblings pooled).
        let a = pool.acquire(|| auth.mint()).await.unwrap();
        let b = pool.acquire(|| auth.mint()).await.unwrap();
        let (a_id, b_id) = (a.id, b.id);
        drop(a);
        drop(b);
        assert_eq!(auth.total.load(Ordering::SeqCst), 2);
        assert_eq!(pool.idle.lock().unwrap().len(), 2, "two siblings pooled");

        // Simulate the decrypt_card 401 path: the current channel is bad AND the whole
        // session is stale — drain ALL idle siblings, then re-acquire.
        pool.drain_idle();
        assert!(pool.idle.lock().unwrap().is_empty(), "drain cleared every sibling");

        // The retry acquire is now FORCED to mint a fresh channel (id 2) — it can NOT
        // hand back a stale sibling (ids 0/1), which is the bug being guarded against.
        let fresh = pool.acquire(|| auth.mint()).await.unwrap();
        assert_eq!(auth.total.load(Ordering::SeqCst), 3, "drain forces a fresh mint");
        assert_ne!(fresh.id, a_id);
        assert_ne!(fresh.id, b_id);
        assert_eq!(fresh.id, 2);
    }

    #[tokio::test]
    async fn authed_pool_releases_permit_on_mint_error() {
        let pool = AuthedPool::<FakeChan>::new(1);
        // A failing mint must not leak the single permit.
        let err = pool
            .acquire(|| async { Err::<FakeChan, _>(UiError::new("boom", "nope")) })
            .await;
        assert!(err.is_err());
        // The permit is back — a subsequent successful acquire proceeds (would hang
        // forever if the permit had leaked, so the test would time out on failure).
        let auth = FakeAuth::default();
        let g = pool.acquire(|| auth.mint()).await.unwrap();
        assert_eq!(g.id, 0);
    }
}
