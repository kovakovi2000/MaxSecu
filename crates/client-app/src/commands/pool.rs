//! An authed **connection pool** so authed reads reuse a login instead of minting
//! one each.
//!
//! Without it, every authed read command re-authenticates on a FRESH channel via
//! [`crate::commands::connection::reauth`], which `try_lock`s the ONE `ConnectLock`
//! for the whole login handshake and transiently `take`s the single non-`Clone`
//! `Identity` out of the session. That serializes reads: a SECOND concurrent
//! `reauth` gets `Err("busy")` and a concurrent command sees the taken identity as
//! `None`. So two `decrypt_card` calls can't overlap (why the UI serializes them).
//!
//! It is also what keeps the app under the SERVER's anti-automation cap. The server
//! admits at most **30 challenges per account per rolling 60 s**
//! (`server::ratelimit`, `challenge_max_per_window`) and answers the 31st with a
//! `429`. A login per read blew straight through that on an ordinary browse — open a
//! few posts, page the feed, play a video and the account is throttled, which the
//! client then reported as "Sign-in failed." Every authed read now borrows a warm
//! channel from here, so an ordinary session mints a handful of logins, not one per
//! click. (Raising the server cap instead would have weakened a real anti-automation
//! control to paper over a client bug.)
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
//!
//! A pooled channel is ALSO keyed on the [`Principal`] it was minted under, and a
//! borrow only ever gets a channel whose principal matches the caller's. A channel
//! carries a session token that speaks for exactly one principal, so handing a
//! recovery-minted channel to a user request (or one user's channel to another's)
//! would answer with the WRONG account's data. The session's principal can change
//! under the pool's feet — `connect` overwrites it in place, and `logout` /
//! `end_recovery_session` clear it while a borrowed channel is still in flight and
//! about to be returned to the idle set — so this is enforced structurally at the
//! reuse decision rather than assumed to be drained in time. (Those two commands do
//! also [`drain_idle`](AuthedPool::drain_idle) so the dropped principal's live
//! channels and tokens don't linger in RAM.)
//!
//! **What the semaphore actually caps.** `cap` permits bound the number of channels
//! borrowed CONCURRENTLY — it is not a cap on live sockets, because two kinds of
//! channel are alive without holding a permit: the idle set (bounded to `cap`
//! entries by [`return_lent`](AuthedPool::return_lent); a borrow's own return is
//! permit-covered) and channels LENT out via [`lend`](AuthedPool::lend) for a
//! long-lived session (one per open video). So live ≈ borrows(≤cap) + idle(≤cap) +
//! one per open video session. Lent channels deliberately escape the permit: an
//! open video holds its channel for the whole playback, and pinning a permit for
//! minutes would starve every other reader — which is exactly why they are LENT
//! (bookkeeping parked in the pool, permit released) and not simply taken away.
//! A lent channel is handed BACK on `cancel_video`, so N sequential video opens
//! cost ONE login rather than N.
//!
//! **Drain is retroactive.** A channel borrowed (or lent) BEFORE a
//! [`drain_idle`](AuthedPool::drain_idle) must not silently re-pool itself
//! afterwards — that is how a logged-out principal's live token used to linger. The
//! pool therefore carries a monotonic `generation` that `drain_idle` bumps; a guard
//! (or a loan) remembers the generation it was born under and is DISCARDED on
//! return when the pool has been drained since. `logout` / `end_recovery_session`
//! therefore genuinely close every channel of the principal they clear.
//!
//! **When a borrow is BORN matters as much as the counter.** A channel that has to
//! be MINTED is born when the mint STARTS, not when it finishes: the mint is a real
//! `reauth` that reads the session's principal and takes the identity up front, so a
//! `logout` landing mid-mint still yields a token for the principal being cleared.
//! Sampling the generation after `mint().await` (which is what the first version of
//! this did) gave such a channel the POST-drain generation, so its `Drop` saw a
//! match and put a just-signed-out principal's live token straight back into the
//! idle set — the very leak the paragraph above claims is closed, and on the
//! recovery path a token that can open every user's content. The birth generation is
//! therefore sampled at [`acquire`](AuthedPool::acquire) ENTRY, before anything that
//! can produce a channel; a mint that straddles a drain is then born stale and is
//! discarded. A REUSED idle channel instead takes its birth generation at the pop,
//! read under the same lock `drain_idle` bumps under (see
//! [`take_fresh_idle`](AuthedPool::take_fresh_idle)) — a channel drawn from the idle
//! set after a drain belongs to the new era and must not be thrown away for a drain
//! that predates it.
//!
//! Every "is this channel's era still current?" test — `Drop`, `return_lent` — is
//! made while HOLDING the idle lock, and `drain_idle` bumps the counter while
//! holding it too. Otherwise a return could read the pre-drain generation, be
//! preempted, and push its channel into the set only after the drain had cleared it.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::commands::auth::Principal;
use crate::error::UiError;

/// Reuse window for a pooled channel (ms). The server session TTL is 60 min
/// (`server::auth` `session_ttl_ms = 3_600_000`); we re-mint a channel older than
/// **20 min** — a conservative one-third of the TTL, leaving 40 min of headroom so a
/// reused token can never be close to expiry. A `401` mid-use is still handled
/// (fail-closed: discard + re-auth) via [`PooledGuard::mark_bad`].
pub const REUSE_WINDOW_MS: u64 = 20 * 60 * 1000;

/// Floor on the pool's live-channel cap. Production sizes the pool from
/// `performance.feed_concurrency`, which a user may set as low as **1**
/// (`config.rs` clamps to `1..=8`). Now that EVERY authed read borrows from this
/// pool — not just `decrypt_card` — a cap of 1 would let one long-running borrow
/// (a multi-minute `download_content` of a large video) hold the only channel and
/// stall every other read behind it. Two channels guarantee at least one is free
/// for a concurrent read while a long download runs. This only ever RAISES the
/// cap, so no configuration loses concurrency it had before.
const MIN_CAP: usize = 2;

/// How long a throttled (`429`) mint may be waited out INSIDE a command before the
/// throttle is reported to the user instead. The server's `Retry-After` can be up to
/// ~60 s (a spent challenge window) and no Tauri command may block that long, so a
/// wait only happens when the server says the window frees up almost immediately —
/// the "one request over the line" case. Anything longer is handed to the UI as
/// `rate_limited` + `retry_after_s` so it can say how long to wait.
///
/// This wait lives HERE, not inside `reauth`, and deliberately runs with the auth
/// gate released and the semaphore permit dropped: sleeping while holding either
/// would stall every OTHER borrower behind one throttled cold mint (including warm
/// reuses, which need only a permit).
const THROTTLE_WAIT_BUDGET_MS: u64 = 2_000;

/// The minimum wait for a `429` that arrived with no (or a zero) `Retry-After`:
/// retrying instantly would just burn another challenge slot.
const THROTTLE_MIN_WAIT_MS: u64 = 250;

/// Hard cap on throttle retries, INDEPENDENT of the time budget. A short (or zero)
/// `Retry-After` would otherwise let the time budget alone permit several attempts,
/// and every attempt is a fresh TLS dial that asks for another challenge — the very
/// thing the throttle is defending against. One retry is enough for the "one request
/// over the line" case; beyond that the honest answer is to tell the user to wait.
const THROTTLE_MAX_RETRIES: u32 = 1;

/// A monotonic-ish wall clock (ms since epoch). Injectable so the expiry unit test
/// can drive time without sleeping.
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One idle pooled channel, the wall-clock time it was minted (for expiry), and the
/// [`Principal`] whose credentials minted it (for the reuse match — see the module
/// docs).
struct PooledConn<C> {
    channel: C,
    minted_at_ms: u64,
    principal: Principal,
}

/// Bookkeeping for one channel LENT out of the pool ([`AuthedPool::lend`]) under a
/// borrower-chosen key (production: the video session's `file_id_hex`). The channel
/// itself lives with the borrower — only what is needed to put it BACK is parked
/// here: when it was minted (so its reuse window is not silently extended), whose
/// credentials minted it, and the drain generation it was born under (so a loan that
/// straddles a `drain_idle` is discarded rather than re-pooled).
struct Loan {
    minted_at_ms: u64,
    principal: Principal,
    generation: u64,
}

/// An authed connection pool generic over the channel type `C`. Production uses
/// `C = crate::jobs::AuthedChannel` (see [`AppPool`]); unit tests use a trivial fake.
///
/// * a [`Semaphore`] of `cap` permits caps CONCURRENT BORROWS (see the module docs
///   for what that does and does not bound — lent channels hold no permit);
/// * an idle set (`std::sync::Mutex<Vec<PooledConn<C>>>`) holds returned channels for
///   reuse — a plain `std` mutex so the guard's `Drop` (synchronous) can return a
///   channel without awaiting; the lock is only ever held for a trivial push/pop,
///   never across an `.await`;
/// * a `lent` map records the channels handed out for a long-lived session
///   ([`lend`](Self::lend)) so they can be returned later;
/// * `generation` is bumped by [`drain_idle`](Self::drain_idle) so a borrow/loan that
///   straddles a drain is discarded on return instead of re-pooled;
/// * an async **auth gate** (`tokio::sync::Mutex<()>`) serializes channel MINTING so
///   the underlying `reauth` is never called concurrently.
pub struct AuthedPool<C> {
    idle: Arc<Mutex<Vec<PooledConn<C>>>>,
    lent: Mutex<HashMap<String, Loan>>,
    generation: Arc<AtomicU64>,
    permits: Arc<Semaphore>,
    auth_gate: tokio::sync::Mutex<()>,
    cap: usize,
    reuse_window_ms: u64,
    clock: Clock,
}

impl<C: Send + 'static> AuthedPool<C> {
    /// A pool capping live channels at `cap` (clamped to at least [`MIN_CAP`]),
    /// with the production reuse window and wall clock.
    pub fn new(cap: usize) -> Self {
        Self::with_config(cap.max(MIN_CAP), REUSE_WINDOW_MS, Arc::new(now_ms))
    }

    /// Construct with an explicit reuse window + clock (used by the unit tests to
    /// drive expiry deterministically).
    fn with_config(cap: usize, reuse_window_ms: u64, clock: Clock) -> Self {
        let cap = cap.max(1);
        Self {
            idle: Arc::new(Mutex::new(Vec::new())),
            lent: Mutex::new(HashMap::new()),
            generation: Arc::new(AtomicU64::new(0)),
            permits: Arc::new(Semaphore::new(cap)),
            auth_gate: tokio::sync::Mutex::new(()),
            cap,
            reuse_window_ms,
            clock,
        }
    }

    /// Acquire an EXCLUSIVE channel for the duration of the returned guard. Reuses a
    /// non-expired idle channel **minted under the same `principal`** if one exists
    /// (no auth); otherwise mints a fresh one via `mint` under the auth gate (so the
    /// real `reauth` is never concurrent). The guard returns the channel to the idle
    /// set on drop (unless marked bad) and releases the permit.
    ///
    /// `principal` is WHO the caller is authenticated as right now; `mint` must
    /// authenticate as that same principal (production passes a `reauth`-backed
    /// closure, and `reauth` reads the principal from the same session). A channel is
    /// never handed to a different principal than the one that minted it — see the
    /// module docs.
    ///
    /// `mint` is the channel-creation step: production supplies a `reauth`-backed
    /// closure; tests supply a fake. It is only ever awaited while the auth gate is
    /// held, so it is never run concurrently with itself. It is `Fn` (not `FnOnce`)
    /// because a throttled (`429`) mint is waited out and retried — see
    /// [`THROTTLE_MAX_RETRIES`].
    ///
    /// A drain landing anywhere between this call and the guard's drop discards the
    /// channel rather than re-pooling it — including one that lands mid-`mint` (see
    /// the module docs).
    pub async fn acquire<F, Fut>(
        &self,
        principal: &Principal,
        mint: F,
    ) -> Result<PooledGuard<C>, UiError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<C, UiError>>,
    {
        self.acquire_inner(principal, mint, true).await
    }

    /// Like [`acquire`](Self::acquire) but NEVER reuses an idle channel: it always
    /// mints. For the ONE case where reuse is provably wrong — the retry after a
    /// borrowed channel turned out to be DEAD. Whatever killed that socket (server
    /// restart, NAT/conntrack reap, the laptop changing network) killed every idle
    /// sibling at the same instant, so drawing another idle channel would usually
    /// fail the retry too. This is the "or falls back to a genuinely fresh mint" half
    /// of [`get_on_pooled_channel`]'s contract. It does NOT drain the siblings (their
    /// TOKENS may be perfectly valid — only the sockets are suspect); each is
    /// discarded individually when its own first request fails.
    pub async fn acquire_fresh<F, Fut>(
        &self,
        principal: &Principal,
        mint: F,
    ) -> Result<PooledGuard<C>, UiError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<C, UiError>>,
    {
        self.acquire_inner(principal, mint, false).await
    }

    async fn acquire_inner<F, Fut>(
        &self,
        principal: &Principal,
        mint: F,
        reuse_idle: bool,
    ) -> Result<PooledGuard<C>, UiError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<C, UiError>>,
    {
        // The birth generation for a channel this call has to MINT, sampled BEFORE
        // anything that could mint one — and before the caller's principal can be
        // cleared out from under us. A mint is a real `reauth`: it reads the
        // session's principal and takes the identity at its START, so the token it
        // returns speaks for whoever was signed in THEN. Sampling after the mint (as
        // this used to) hands a channel minted across a `logout`'s drain the
        // POST-drain generation, and `Drop` then re-pools a signed-out principal's
        // live token. Sampling here makes such a channel born stale ⇒ discarded.
        //
        // It cannot cause a false discard in ordinary operation: the counter only
        // ever moves in `drain_idle`, so with no drain in flight birth == current and
        // every minted channel is pooled exactly as before. When a drain DOES land
        // mid-acquire the channel is still fully usable for this borrow — only its
        // re-pooling is given up, costing at most one later login, in the fail-closed
        // direction.
        let born_if_minted = self.generation.load(Ordering::Acquire);
        let mut throttle_retries = THROTTLE_MAX_RETRIES;
        loop {
            // 1) Cap concurrent borrows. The permit rides in the guard and is released
            //    on drop.
            let permit =
                self.permits.clone().acquire_owned().await.map_err(|_| {
                    UiError::new("pool_closed", "The connection pool is unavailable.")
                })?;

            // 2) Reuse a non-expired SAME-PRINCIPAL idle channel if one is available
            //    (no auth, no gate). Such a channel is born at the POP — it belongs
            //    to whatever era the idle set is in right now, which may be newer
            //    than `born_if_minted`.
            if reuse_idle {
                if let Some((conn, born)) = self.take_fresh_idle(principal) {
                    return Ok(self.guard_from(conn, born, permit));
                }
            }

            // 3) No reusable idle channel — mint under the auth gate so channel
            //    creation (the real `reauth`) is serialized and its `ConnectLock`
            //    try_lock never races. Re-check idle after taking the gate: a
            //    concurrent borrower may have returned a channel while we waited,
            //    avoiding an over-mint.
            let gate = self.auth_gate.lock().await;
            if reuse_idle {
                if let Some((conn, born)) = self.take_fresh_idle(principal) {
                    return Ok(self.guard_from(conn, born, permit));
                }
            }
            let minted = mint().await;
            match minted {
                Ok(channel) => {
                    let conn = PooledConn {
                        channel,
                        minted_at_ms: (self.clock)(),
                        principal: principal.clone(),
                    };
                    return Ok(self.guard_from(conn, born_if_minted, permit));
                }
                // The server's anti-automation throttle. Wait it out ONCE — but with
                // the gate RELEASED and the permit DROPPED first, so one throttled
                // cold mint does not stall every other borrower behind it (the whole
                // reason this wait lives here and not inside `reauth`).
                Err(e)
                    if e.code == crate::session::RATE_LIMITED
                        && throttle_retries > 0
                        && throttle_wait_ms(e.retry_after_s).is_some() =>
                {
                    let wait_ms = throttle_wait_ms(e.retry_after_s).unwrap_or(0);
                    throttle_retries -= 1; // strictly decreasing ⇒ the loop terminates
                    drop(gate);
                    drop(permit);
                    tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Discard ALL cached idle channels (clear the idle set) and INVALIDATE every
    /// channel currently borrowed or lent out. A `401` on an authed GET means the
    /// SESSION token was rejected — server restart or session invalidation makes
    /// EVERY pooled sibling channel (same-era token) stale, not just the one that hit
    /// the 401. So a caller that saw a 401 drains the whole idle set; the next
    /// [`acquire`](Self::acquire) then finds it empty and is FORCED to mint a fresh
    /// channel via `reauth`, instead of drawing another stale sibling.
    ///
    /// Currently-BORROWED (and lent) channels cannot be closed from here — their
    /// holders own them — but they are marked stale by bumping `generation`, so they
    /// are DISCARDED rather than re-pooled when they come back. That is what makes
    /// `logout` / `end_recovery_session` genuinely close the cleared principal's
    /// channels: without it, a guard borrowed a moment before the drain quietly put
    /// its live token back in the pool a moment after.
    pub fn drain_idle(&self) {
        // Bump and clear UNDER ONE HOLD of the idle lock, so the two are atomic with
        // respect to every reader of the counter — all of which (the guard's `Drop`,
        // `return_lent`, `take_fresh_idle`) also hold this lock. Bumping outside it
        // left a real, if narrow, hole: a returning guard could read the pre-drain
        // generation, be preempted, and push its channel into the idle set only after
        // the clear had run — leaving exactly the token this drain exists to destroy
        // sitting in the pool.
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        self.generation.fetch_add(1, Ordering::AcqRel);
        idle.clear();
        // Loans are left in place: they are pure bookkeeping, and `return_lent`
        // compares each loan's generation against the (now bumped) current one, so a
        // lent channel that comes back after this is discarded and its record cleared.
    }

    /// Pop the newest idle channel that was minted under `principal` AND is still
    /// within the reuse window, together with the generation it is popped IN (its
    /// birth generation as a borrow).
    ///
    /// The counter is read under the SAME lock hold as the pop, and `drain_idle`
    /// bumps it under that lock too, so the pair cannot straddle a drain: either the
    /// pop wins and reads the pre-drain generation (⇒ the borrow is discarded on
    /// drop, which is right — that channel was in the set the drain destroyed), or
    /// the drain wins and the set is empty (⇒ a fresh mint). Reading the counter
    /// afterwards, outside the lock, could label a pre-drain channel with the
    /// post-drain generation and re-pool it.
    ///
    /// Expired and FOREIGN-PRINCIPAL entries are dropped (closing the channel, so its
    /// token dies with it) across the WHOLE set, not just the ones walked past on the
    /// way to a match: stopping at the first same-principal hit left a signed-out
    /// user's live token sitting underneath it indefinitely. A foreign channel can
    /// never become useful again — its token speaks for the other principal — so
    /// discarding it is both correct and the cheapest cleanup.
    fn take_fresh_idle(&self, principal: &Principal) -> Option<(PooledConn<C>, u64)> {
        let now = (self.clock)();
        let reuse_window_ms = self.reuse_window_ms;
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.retain(|conn| {
            &conn.principal == principal && now.saturating_sub(conn.minted_at_ms) <= reuse_window_ms
        });
        let conn = idle.pop()?; // newest survivor, or None
        Some((conn, self.generation.load(Ordering::Acquire)))
    }

    /// Wrap a channel in its borrow guard. `born_generation` is the era the channel
    /// belongs to — the pop generation for a reused one, the pre-mint generation for
    /// a freshly minted one (see [`acquire_inner`](Self::acquire_inner)) — and NOT
    /// simply "now": sampling it here would make a mint that straddles a drain look
    /// current and re-pool a signed-out principal's token.
    fn guard_from(
        &self,
        conn: PooledConn<C>,
        born_generation: u64,
        permit: OwnedSemaphorePermit,
    ) -> PooledGuard<C> {
        PooledGuard {
            channel: Some(conn.channel),
            minted_at_ms: conn.minted_at_ms,
            principal: conn.principal,
            idle: self.idle.clone(),
            generation: self.generation.clone(),
            born_generation,
            _permit: permit,
            bad: false,
        }
    }

    /// LEND this borrowed channel out of the pool under `key`, returning the raw
    /// channel and releasing the permit.
    ///
    /// For the one borrower whose channel outlives its command — an open video
    /// session, which moves the authed channel into its `VideoJob` and drives every
    /// `stream://` range fetch over it until `cancel_video`. Holding a `PooledGuard`
    /// for a whole playback would pin a permit for minutes; lending the channel
    /// instead lets the pool immediately serve other readers.
    ///
    /// Unlike simply taking the channel away, a LOAN is remembered: `key` (production
    /// passes the session's `file_id_hex`) maps to the mint time + principal +
    /// generation needed to put the channel BACK with [`return_lent`](Self::return_lent)
    /// when the session ends. That is what makes N sequential video opens cost ONE
    /// login instead of N. Lending under a key that is already on loan REPLACES the
    /// record — the superseded channel is the caller's to drop (production: a re-open
    /// of the same video, whose old channel dies with the old job).
    ///
    /// Ownership discipline is unchanged: the `{sender, host, token}` unit still
    /// travels together and the token still never leaves its channel. NB a lent
    /// channel may be up to [`REUSE_WINDOW_MS`] old, so its token has at least 40 min
    /// of the server's 60 min session TTL left rather than the full 60 — a playback
    /// session that runs past that gets a fail-closed `player_err` and re-opens,
    /// exactly as it already did at the 60 min mark.
    pub fn lend(&self, mut guard: PooledGuard<C>, key: &str) -> C {
        // Suppress the Drop re-pool: this channel is now the borrower's until it is
        // handed back through `return_lent`.
        guard.bad = true;
        let channel = guard
            .channel
            .take()
            .expect("pooled channel present until drop");
        let loan = Loan {
            minted_at_ms: guard.minted_at_ms,
            principal: guard.principal.clone(),
            generation: guard.born_generation,
        };
        self.lent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_owned(), loan);
        channel
        // `guard` drops here → the permit is released.
    }

    /// Hand a lent channel BACK to the pool so the next reader reuses it instead of
    /// minting a login. It re-enters the idle set under its ORIGINAL mint time and
    /// principal, so lending can never silently extend a token's reuse window.
    ///
    /// The channel is DISCARDED instead (fail-closed) when: `key` is not on loan (it
    /// was superseded or already returned), the pool was drained since the loan began
    /// (`logout` — the token must not come back), or the idle set is already at `cap`
    /// (a lent channel holds no permit, so returning it is the one path that could
    /// grow the idle set without bound).
    pub fn return_lent(&self, key: &str, channel: C) {
        let loan = self
            .lent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        let Some(loan) = loan else { return };
        // Test the era UNDER the idle lock (which `drain_idle` bumps under), so this
        // check-then-push cannot straddle a drain and re-pool a channel into a set
        // that was cleared a moment ago.
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if loan.generation != self.generation.load(Ordering::Acquire) {
            return; // drained (e.g. logout) since the loan began — never re-pool it
        }
        if idle.len() >= self.cap {
            return;
        }
        idle.push(PooledConn {
            channel,
            minted_at_ms: loan.minted_at_ms,
            principal: loan.principal,
        });
    }

    /// Forget a loan whose channel CANNOT be handed back (production: a range fetch
    /// still holds the session's channel `Arc` when the session ends, so the channel
    /// is not ours to return — it dies with that fetch). Bookkeeping only.
    pub fn forget_lent(&self, key: &str) {
        self.lent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    /// How many loans are outstanding. Test-only visibility into the `lent`
    /// bookkeeping so a caller's tests (`commands::video`) can assert that a loan is
    /// never recorded for a session that has already ended — a record nobody would
    /// ever return or forget lives for the process lifetime.
    #[cfg(test)]
    pub(crate) fn lent_count(&self) -> usize {
        self.lent.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// How long to wait out a `429` before retrying, or `None` when the server's
/// interval is longer than a command may block for (⇒ report the throttle to the
/// user instead). `saturating_mul` keeps an absurd `Retry-After` from wrapping and
/// the `max` keeps a missing or zero one from becoming an instant retry that just
/// burns another challenge slot. Pure — unit-tested.
fn throttle_wait_ms(retry_after_s: Option<u64>) -> Option<u64> {
    let wait_ms = retry_after_s
        .unwrap_or(0)
        .saturating_mul(1_000)
        .max(THROTTLE_MIN_WAIT_MS);
    (wait_ms <= THROTTLE_WAIT_BUDGET_MS).then_some(wait_ms)
}

/// An exclusive borrow of a pooled channel. Derefs to the channel `C` so callers use
/// its fields directly. On drop the channel is returned to the pool's idle set (for
/// reuse) UNLESS [`mark_bad`](Self::mark_bad) was called (a `401`/transport error) or
/// the pool was drained since the borrow began, in which case it is discarded. The
/// semaphore permit is released on drop either way.
pub struct PooledGuard<C> {
    channel: Option<C>,
    minted_at_ms: u64,
    principal: Principal,
    idle: Arc<Mutex<Vec<PooledConn<C>>>>,
    /// The pool's live drain counter, and the era this channel belongs to: the
    /// generation it was POPPED in (reuse) or the one current when its `acquire`
    /// STARTED (mint — a mint that straddles a drain must be born stale, see the
    /// module docs). A mismatch on drop means a
    /// [`drain_idle`](AuthedPool::drain_idle) happened mid-borrow ⇒ discard instead
    /// of re-pooling.
    generation: Arc<AtomicU64>,
    born_generation: u64,
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
        self.channel
            .as_ref()
            .expect("pooled channel present until drop")
    }
}

impl<C> std::ops::DerefMut for PooledGuard<C> {
    fn deref_mut(&mut self) -> &mut C {
        self.channel
            .as_mut()
            .expect("pooled channel present until drop")
    }
}

impl<C> Drop for PooledGuard<C> {
    fn drop(&mut self) {
        if self.bad {
            return; // discard the bad channel; the permit releases as `_permit` drops.
        }
        let Some(channel) = self.channel.take() else {
            return;
        };
        // Take the idle lock FIRST and test the era UNDER it. `drain_idle` bumps the
        // counter while holding this same lock, so the test cannot go stale between
        // here and the push — reading it outside the lock let a return be preempted
        // after a passing check and land in the set only after the drain cleared it.
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if self.generation.load(Ordering::Acquire) != self.born_generation {
            // The pool was drained while this channel was out (logout, or a `401`
            // that invalidated the whole token era), or it was minted ACROSS such a
            // drain. Returning it now would put the very token the drain was meant to
            // destroy back into the pool. `channel` drops here instead: the socket
            // closes and the channel-bound token dies with it.
            return;
        }
        idle.push(PooledConn {
            channel,
            minted_at_ms: self.minted_at_ms,
            // Returned under the principal that MINTED it, never the one that is
            // signed in now — a principal change mid-borrow must not relabel this
            // channel's token.
            principal: self.principal.clone(),
        });
    }
}

/// The production pool type: an [`AuthedPool`] of real authed HTTP/1.1 channels.
/// Registered as Tauri managed state and injected into every authed read command
/// by type.
pub type AppPool = AuthedPool<crate::jobs::AuthedChannel>;

/// Borrow a pooled authed channel and VALIDATE it with the caller's own first
/// authed `GET` — the single implementation of the fail-closed channel-health
/// discipline every authed read now shares.
///
/// A pooled channel is REUSED, so the first request over it is where a stale token
/// or a dead socket shows up; that request is therefore the check, and it is the
/// caller's real first request, not an extra round trip:
///
/// * **`401`** — the SESSION token was rejected (it expired mid-life, or the server
///   restarted / invalidated the session). That makes EVERY pooled sibling
///   (same-era token) stale, not just this one, so [`drain_idle`](AuthedPool::drain_idle)
///   the whole idle set AND [`mark_bad`](PooledGuard::mark_bad) this channel, then
///   re-acquire ONCE: with idle empty the pool is FORCED to mint a genuinely fresh
///   that fresh mint is a genuinely-expired session — surfaced as `locked`
///   ("reconnect"), NOT as the caller's `not_ok` (which would mislabel it
///   "unavailable").
/// * **transport error** — only THIS pooled connection is known dead, so only this
///   channel is discarded (the siblings' tokens may be perfectly valid — nothing
///   here says otherwise). The retry then goes through
///   [`acquire_fresh`](AuthedPool::acquire_fresh) rather than reuse: whatever kills
///   an idle socket (server restart, NAT/conntrack reap, a network change) tends to
///   kill every idle sibling at the same instant, so drawing another idle channel
///   would usually fail the retry too. One retry, and it is a guaranteed-live mint.
/// * **`200`** — the channel + token are validated for the rest of the caller's
///   fetches (all within the same instant), so the caller's sequence cannot `401`
///   downstream. A downstream transport failure returns the channel to the pool and
///   is caught by the NEXT reuse's validating GET — self-healing, never a persistent
///   poison.
/// * any other status ⇒ the caller's own `not_ok` (e.g. `fetch_failed`/`feed_failed`),
///   with the channel returned to the pool (the server answered — the channel is fine).
///
/// `mint` is called only on a cold/expired/drained pool and runs under the pool's
/// internal auth gate, so the real `reauth` is never concurrent. It is `Fn` (not
/// `FnOnce`) because the retry may need to mint again.
pub(crate) async fn get_on_pooled_channel<F, Fut>(
    pool: &AppPool,
    principal: &Principal,
    uri: &str,
    not_ok: UiError,
    mint: F,
) -> Result<(PooledGuard<crate::jobs::AuthedChannel>, serde_json::Value), UiError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<crate::jobs::AuthedChannel, UiError>>,
{
    get_on_pooled_channel_with(pool, principal, not_ok, mint, &HttpGet { uri }).await
}

/// One authed `GET` over a borrowed channel, as a trait so the retry/drain/locked
/// semantics above can be exercised by unit tests against a scripted transport
/// ([`get_on_pooled_channel_with`]). Production has exactly one implementor,
/// [`HttpGet`], which performs the real `http_client::get_json`.
///
/// `&'a self` and `&'a mut C` share one lifetime so an implementor may hold borrowed
/// request data (the URI) and still borrow the channel into the returned future.
pub(crate) trait ChannelGet<C> {
    fn get<'a>(&'a self, chan: &'a mut C) -> ChannelGetFut<'a>;
}

/// The boxed future a [`ChannelGet`] returns: the same `(status, json)` pair
/// `http_client::get_json` produces. Boxed because the trait is used generically.
type ChannelGetFut<'a> = std::pin::Pin<
    Box<dyn Future<Output = Result<(hyper::StatusCode, serde_json::Value), UiError>> + Send + 'a>,
>;

/// The production [`ChannelGet`]: a real authed `GET uri` over the channel, using
/// the channel's OWN host + token (a token never leaves its channel).
struct HttpGet<'u> {
    uri: &'u str,
}

impl ChannelGet<crate::jobs::AuthedChannel> for HttpGet<'_> {
    fn get<'a>(&'a self, chan: &'a mut crate::jobs::AuthedChannel) -> ChannelGetFut<'a> {
        Box::pin(async move {
            let host = chan.host.clone();
            let token = chan.token.clone();
            crate::http_client::get_json(&mut chan.sender, self.uri, Some(&token), &host).await
        })
    }
}

/// The channel-health discipline itself, generic over the channel type and the GET
/// so it is unit-testable. See [`get_on_pooled_channel`] for the semantics; this is
/// the single implementation of them.
pub(crate) async fn get_on_pooled_channel_with<C, F, Fut, G>(
    pool: &AuthedPool<C>,
    principal: &Principal,
    not_ok: UiError,
    mint: F,
    get: &G,
) -> Result<(PooledGuard<C>, serde_json::Value), UiError>
where
    C: Send + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<C, UiError>>,
    G: ChannelGet<C> + ?Sized,
{
    // `first` is also the retry bound: every arm below either returns or falls
    // through to a SECOND (and final) attempt.
    let mut first = true;
    loop {
        // Keyed on the principal so a channel minted for a DIFFERENT principal (a
        // recovery session, or another user after a sign-out/sign-in that raced an
        // in-flight borrow) can never be handed to this call.
        let mut chan = if first {
            pool.acquire(principal, &mint).await?
        } else {
            // The retry NEVER reuses: attempt 1 already told us either that this
            // token era is dead (401 ⇒ the idle set was drained) or that idle
            // sockets are dying (transport error). Both want a genuinely fresh mint.
            pool.acquire_fresh(principal, &mint).await?
        };
        // Bind the outcome before matching so the borrow of `chan` inside the GET
        // future ends before `chan.mark_bad()` in the arms.
        let outcome = get.get(&mut chan).await;
        match outcome {
            Ok((hyper::StatusCode::UNAUTHORIZED, _)) if first => {
                pool.drain_idle();
                chan.mark_bad();
                first = false;
                continue;
            }
            Ok((hyper::StatusCode::UNAUTHORIZED, _)) => {
                chan.mark_bad();
                return Err(UiError::new("locked", "Your session expired. Reconnect."));
            }
            Ok((hyper::StatusCode::OK, json)) => return Ok((chan, json)),
            Ok(_) => return Err(not_ok),
            Err(_) if first => {
                chan.mark_bad(); // dead pooled connection — discard + retry once.
                first = false;
                continue;
            }
            Err(e) => {
                // The retry — on a FRESHLY minted channel — also failed to reach the
                // server. That is a real outage, not a stale pooled socket. Still
                // mark it bad: a connection that just proved it cannot carry a
                // request must not go back into the pool for the next reader to
                // rediscover.
                chan.mark_bad();
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// The ordinary-user principal the reuse tests borrow as.
    fn alice() -> Principal {
        Principal::User {
            username: "alice".into(),
        }
    }

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

    /// Unwrap the ERROR of a result whose `Ok` side is not `Debug` — a
    /// `PooledGuard` deliberately is not (it owns a live channel), so `expect_err`
    /// cannot be used on it.
    fn err_of<T>(r: Result<T, UiError>, what: &str) -> UiError {
        match r {
            Ok(_) => panic!("expected an error: {what}"),
            Err(e) => e,
        }
    }

    /// Generous upper bound on an `acquire` that must succeed promptly.
    const ACQUIRE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// `acquire` a channel that MUST arrive promptly, FAILING (not hanging) if it
    /// does not. Several of these tests assert that a permit was released or that
    /// the auth gate is free; the natural failure mode of all of them is an
    /// indefinite block on the semaphore/gate, which in CI is a stalled job rather
    /// than a red test. Every such await goes through here so a regression is a
    /// FAILURE with a message.
    async fn must_acquire(
        pool: &AuthedPool<FakeChan>,
        auth: &FakeAuth,
        what: &str,
    ) -> PooledGuard<FakeChan> {
        tokio::time::timeout(ACQUIRE_TIMEOUT, pool.acquire(&alice(), || auth.mint()))
            .await
            .unwrap_or_else(|_| {
                panic!("acquire blocked forever ({what}): a permit leaked or the auth gate is held")
            })
            .expect("acquire must succeed")
    }

    #[tokio::test]
    async fn authed_pool_reuses_idle_channel() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        // First acquire mints; dropping the guard returns the channel to idle.
        let first_id = {
            let g = pool.acquire(&alice(), || auth.mint()).await.unwrap();
            g.id
        };
        // Second acquire finds the idle channel and REUSES it — no second mint.
        let second_id = {
            let g = pool.acquire(&alice(), || auth.mint()).await.unwrap();
            g.id
        };
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            1,
            "auth must run only once"
        );
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
                let _g = pool.acquire(&alice(), || auth.mint()).await.unwrap();
                barrier.wait().await; // hold the channel until all N are acquired
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            N,
            "exactly N channels minted"
        );
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
        let pool = AuthedPool::<FakeChan>::with_config(
            2,
            1_000,
            Arc::new(move || clock_r.load(Ordering::SeqCst)),
        );
        let auth = FakeAuth::default();

        // Mint at t=0, return to idle.
        drop(pool.acquire(&alice(), || auth.mint()).await.unwrap());
        // Advance the clock past the reuse window — the idle channel is now expired.
        clock.store(2_000, Ordering::SeqCst);
        // Next acquire must DISCARD the expired channel and re-auth (mint again).
        drop(pool.acquire(&alice(), || auth.mint()).await.unwrap());
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
            let mut g = pool.acquire(&alice(), || auth.mint()).await.unwrap();
            g.mark_bad();
        }
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a bad channel is discarded, not pooled"
        );
        // The next acquire must mint a fresh channel (nothing to reuse).
        drop(pool.acquire(&alice(), || auth.mint()).await.unwrap());
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            2,
            "bad channel forces a re-auth"
        );
    }

    // A channel minted under one principal must NEVER be handed to another, even
    // though it is fresh and idle: its token speaks for the wrong account, so reusing
    // it would answer with the wrong account's data. This holds without any drain,
    // which is the point — `logout`/`end_recovery_session` cannot drain a channel that
    // is still borrowed when the principal changes.
    #[tokio::test]
    async fn authed_pool_never_reuses_a_channel_across_principals() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        // Recovery borrows and returns a perfectly fresh channel to the idle set.
        let recovery_id = {
            let g = pool
                .acquire(&Principal::Recovery, || auth.mint())
                .await
                .unwrap();
            g.id
        };
        assert_eq!(pool.idle.lock().unwrap().len(), 1, "the channel is pooled");

        // A USER borrow must not receive it — a fresh mint is forced instead.
        let user_id = {
            let g = pool.acquire(&alice(), || auth.mint()).await.unwrap();
            g.id
        };
        assert_ne!(user_id, recovery_id, "no channel crosses principals");
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            2,
            "a foreign-principal channel forces a fresh auth"
        );

        // ...and the reverse direction, between two DIFFERENT users.
        let bob = Principal::User {
            username: "bob".into(),
        };
        let bob_id = {
            let g = pool.acquire(&bob, || auth.mint()).await.unwrap();
            g.id
        };
        assert_ne!(bob_id, user_id, "one user's channel never serves another's");

        // Same principal still reuses (the fast path is not broken by the keying).
        let again = {
            let g = pool.acquire(&bob, || auth.mint()).await.unwrap();
            g.id
        };
        assert_eq!(again, bob_id, "the same principal still reuses its channel");
    }

    #[tokio::test]
    async fn authed_pool_drain_idle_forces_fresh_mint_over_a_stale_sibling() {
        // cap=2 so a sibling channel can sit idle while another is (was) borrowed.
        let pool = AuthedPool::<FakeChan>::new(2);
        let auth = FakeAuth::default();

        // Mint two channels, return BOTH to idle (2 stale siblings pooled).
        let a = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        let b = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        let (a_id, b_id) = (a.id, b.id);
        drop(a);
        drop(b);
        assert_eq!(auth.total.load(Ordering::SeqCst), 2);
        assert_eq!(pool.idle.lock().unwrap().len(), 2, "two siblings pooled");

        // Simulate the decrypt_card 401 path: the current channel is bad AND the whole
        // session is stale — drain ALL idle siblings, then re-acquire.
        pool.drain_idle();
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "drain cleared every sibling"
        );

        // The retry acquire is now FORCED to mint a fresh channel (id 2) — it can NOT
        // hand back a stale sibling (ids 0/1), which is the bug being guarded against.
        let fresh = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            3,
            "drain forces a fresh mint"
        );
        assert_ne!(fresh.id, a_id);
        assert_ne!(fresh.id, b_id);
        assert_eq!(fresh.id, 2);
    }

    /// `lend` hands the channel to a long-lived owner (an open video session): it
    /// must NOT sit in the idle set while the session runs, and the permit must be
    /// released so the pool can immediately serve other readers.
    #[tokio::test]
    async fn lend_takes_the_channel_out_and_frees_the_permit() {
        // cap=1 (raised to MIN_CAP internally) — a leaked permit would block the
        // second acquire, which the timeout below turns into a FAILURE, not a hang.
        let pool = AuthedPool::<FakeChan>::new(1);
        let auth = FakeAuth::default();

        let guard = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        let lent = pool.lend(guard, "video-1");
        assert_eq!(lent.id, 0, "the session owns the channel");
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a lent channel is not in the idle set while the session runs"
        );

        // The pool is free to serve another reader (would BLOCK on a leaked permit).
        let g = must_acquire(&pool, &auth, "after lend").await;
        assert_eq!(g.id, 1, "a fresh channel serves the next reader");
    }

    /// THE HEADLINE CLAIM: N sequential video sessions cost ONE login, not N.
    /// Each session borrows, `lend`s the channel out for its playback, then hands it
    /// back on cancel — so the next open reuses it instead of re-authing. (Before
    /// this, the channel was taken out of the pool and dropped at cancel, so N opens
    /// = N logins — exactly the 429 cause the pooling work was written to remove.)
    #[tokio::test]
    async fn n_sequential_lent_sessions_cost_one_login() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        const SESSIONS: usize = 6;
        let mut ids = Vec::new();
        for _ in 0..SESSIONS {
            let guard = must_acquire(&pool, &auth, "session open").await;
            let chan = pool.lend(guard, "video-1"); // open_video
            ids.push(chan.id);
            pool.return_lent("video-1", chan); // cancel_video
        }
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            1,
            "{SESSIONS} sequential video sessions must cost ONE login, not {SESSIONS}"
        );
        assert!(
            ids.iter().all(|id| *id == ids[0]),
            "every session reused the same channel: {ids:?}"
        );
        assert_eq!(
            pool.lent.lock().unwrap().len(),
            0,
            "a returned loan leaves no bookkeeping behind"
        );
        assert_eq!(pool.idle.lock().unwrap().len(), 1, "the channel is pooled");
    }

    /// A loan that straddles a `drain_idle` (logout) must NOT come back: the whole
    /// point of the drain is that the cleared principal's token stops existing.
    #[tokio::test]
    async fn a_lent_channel_is_discarded_when_the_pool_was_drained_meanwhile() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        let guard = must_acquire(&pool, &auth, "open").await;
        let chan = pool.lend(guard, "video-1");
        pool.drain_idle(); // logout while the video session is open
        pool.return_lent("video-1", chan); // cancel_video afterwards
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a logged-out principal's lent channel must never re-enter the pool"
        );
        assert!(
            pool.lent.lock().unwrap().is_empty(),
            "the loan record is cleared either way"
        );
    }

    /// The same rule for an ordinary BORROW: a guard taken before `logout` drained
    /// the pool must be discarded on drop, not quietly re-pooled afterwards (that is
    /// how a signed-out user's live token used to linger).
    #[tokio::test]
    async fn a_borrow_that_straddles_a_drain_is_discarded_on_drop() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        let guard = must_acquire(&pool, &auth, "borrow").await;
        pool.drain_idle(); // logout mid-borrow
        drop(guard); // the in-flight read finishes and returns its channel
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a channel borrowed before the drain must not re-pool after it"
        );
    }

    /// Drive one `acquire` whose MINT is still in flight when `drain_idle` lands —
    /// the `logout` / `end_recovery_session` interleaving the pool must survive.
    ///
    /// This is the shape of the real race: both commands bump the generation FIRST
    /// (`pool.drain_idle()`) and only THEN take the session lock to clear the
    /// principal, so a `reauth` that has already read `s.principal` and taken the
    /// identity keeps running and returns a live token for the principal that just
    /// signed out. The gated mint below stands in for exactly that `reauth`.
    /// Returns the guard the borrower ended up with.
    async fn acquire_across_a_drain(pool: &Arc<AuthedPool<FakeChan>>) -> PooledGuard<FakeChan> {
        let mint_started = Arc::new(tokio::sync::Notify::new());
        let drain_done = Arc::new(tokio::sync::Notify::new());
        let borrower = {
            let pool = pool.clone();
            let mint_started = mint_started.clone();
            let drain_done = drain_done.clone();
            tokio::spawn(async move {
                pool.acquire(&alice(), || {
                    let mint_started = mint_started.clone();
                    let drain_done = drain_done.clone();
                    async move {
                        // The identity is already taken and the principal already
                        // read: this mint WILL produce a token for the principal that
                        // is about to be signed out.
                        mint_started.notify_one();
                        drain_done.notified().await;
                        Ok(FakeChan { id: 7 })
                    }
                })
                .await
                .expect("a mint that straddles a drain still succeeds for its borrower")
            })
        };
        // Log out UNDERNEATH the in-flight mint, then let the mint finish.
        mint_started.notified().await;
        pool.drain_idle();
        drain_done.notify_one();
        tokio::time::timeout(ACQUIRE_TIMEOUT, borrower)
            .await
            .expect("the gated mint must complete")
            .expect("the borrowing task must not panic")
    }

    /// A channel MINTED ACROSS a drain must not be re-pooled. Its token was minted
    /// from the credentials of the principal `logout` was in the middle of clearing,
    /// so re-pooling it leaves a live authed token for a signed-out user in the idle
    /// set — on the recovery path, one that can open every user's content.
    ///
    /// `a_borrow_that_straddles_a_drain_is_discarded_on_drop` cannot catch this: it
    /// acquires BEFORE the drain, so its birth generation is pre-drain either way.
    /// Here the channel is BORN during the drain, which is precisely the case that
    /// sampling the generation after `mint().await` got wrong.
    #[tokio::test]
    async fn a_channel_minted_across_a_drain_is_discarded_on_drop() {
        let pool = Arc::new(AuthedPool::<FakeChan>::new(2));

        let guard = acquire_across_a_drain(&pool).await;
        assert_eq!(guard.id, 7, "the borrow still gets its usable channel");
        drop(guard); // the in-flight read finishes and returns the channel

        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a channel minted across a logout's drain must never enter the idle set"
        );

        // …and the pool is still healthy: the next borrow simply mints.
        let auth = FakeAuth::default();
        let g = must_acquire(&pool, &auth, "after a straddling mint was discarded").await;
        assert_eq!(g.id, 0);
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            1,
            "the discarded channel is not handed to the next borrower"
        );
    }

    /// The same rule down the LEND path (`open_video` mints, lends the channel to the
    /// playback session, `cancel_video` hands it back): a loan whose channel was
    /// minted across a drain must be discarded by `return_lent`, not re-pooled.
    #[tokio::test]
    async fn a_channel_minted_across_a_drain_is_not_re_pooled_when_lent() {
        let pool = Arc::new(AuthedPool::<FakeChan>::new(2));

        let guard = acquire_across_a_drain(&pool).await;
        let chan = pool.lend(guard, "video-1"); // open_video
        assert_eq!(chan.id, 7);
        pool.return_lent("video-1", chan); // cancel_video afterwards

        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a logged-out principal's lent channel must never re-enter the pool"
        );
        assert!(
            pool.lent.lock().unwrap().is_empty(),
            "the loan record is cleared either way"
        );
    }

    /// `take_fresh_idle` must clear foreign-principal entries across the WHOLE idle
    /// set. It used to stop at the first same-principal match, so another
    /// principal's live token could sit underneath it forever.
    #[tokio::test]
    async fn foreign_principal_channels_are_dropped_even_under_a_matching_one() {
        let pool = AuthedPool::<FakeChan>::new(4);
        let auth = FakeAuth::default();

        // Build the idle set [recovery, alice] — alice's entry ends up ON TOP, so a
        // scan that stops at the first match never reaches the recovery one. (This
        // is the real interleaving: alice's read is still in flight when a recovery
        // session borrows and returns.)
        let alice_borrow = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        drop(
            pool.acquire(&Principal::Recovery, || auth.mint())
                .await
                .unwrap(),
        );
        drop(alice_borrow);
        assert_eq!(pool.idle.lock().unwrap().len(), 2);

        // Alice borrows: she gets her own channel AND the recovery channel below it
        // is closed rather than left holding a live recovery token.
        let g = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        assert_eq!(g.id, 0, "alice reused her own channel (minted first)");
        assert_eq!(auth.total.load(Ordering::SeqCst), 2, "no extra mint");
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "the foreign-principal channel underneath was dropped, not stranded"
        );
    }

    /// The production cap comes from `feed_concurrency`, which a user may set to 1.
    /// The floor keeps a second channel available so one long borrow (a big
    /// download) can't stall every other read.
    #[tokio::test]
    async fn cap_never_drops_below_the_floor() {
        let pool = Arc::new(AuthedPool::<FakeChan>::new(1));
        let auth = Arc::new(FakeAuth::default());
        // Hold one channel and prove a SECOND borrow still proceeds. With cap==1 the
        // second acquire blocks on the semaphore forever; the timeout turns that into
        // a red test instead of a CI hang.
        let held = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        let second = must_acquire(&pool, &auth, "second concurrent borrow").await;
        assert_ne!(held.id, second.id, "two channels are live at once");
        assert_eq!(auth.total.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn authed_pool_releases_permit_on_mint_error() {
        let pool = AuthedPool::<FakeChan>::new(1);
        // A failing mint must not leak the single permit.
        let err = pool
            .acquire(&alice(), || async {
                Err::<FakeChan, _>(UiError::new("boom", "nope"))
            })
            .await;
        assert!(err.is_err());
        // The permit is back — a subsequent successful acquire proceeds. A leaked
        // permit would block it forever; the timeout makes that a FAILURE, not a hang.
        let auth = FakeAuth::default();
        let g = must_acquire(&pool, &auth, "after a failed mint").await;
        assert_eq!(g.id, 0);
    }

    // ---- the 429 throttle wait: bounded, and OUTSIDE the gate + permit ----

    #[test]
    fn throttle_wait_is_bounded_by_the_budget_and_floored() {
        // No/zero interval ⇒ the floor, never an instant retry.
        assert_eq!(throttle_wait_ms(None), Some(THROTTLE_MIN_WAIT_MS));
        assert_eq!(throttle_wait_ms(Some(0)), Some(THROTTLE_MIN_WAIT_MS));
        // A short interval is honoured as-is.
        assert_eq!(throttle_wait_ms(Some(2)), Some(2_000));
        // Longer than a command may block for ⇒ report the throttle instead.
        assert_eq!(throttle_wait_ms(Some(3)), None);
        assert_eq!(throttle_wait_ms(Some(60)), None);
        // An absurd interval must not wrap into a tiny wait.
        assert_eq!(throttle_wait_ms(Some(u64::MAX)), None);
    }

    /// A throttled mint is waited out once and then succeeds — and the wait does not
    /// stall an unrelated cold mint, because the auth gate and the permit are both
    /// released before sleeping. The ordering assertion is what proves it: with the
    /// wait inside the gate (where it used to live, in `reauth`), B could not
    /// possibly finish first.
    #[tokio::test]
    async fn a_throttled_mint_waits_outside_the_gate_and_permit() {
        // cap=2 (the floor): A holds neither gate nor permit while it sleeps, so B's
        // own cold mint must complete during A's wait.
        let pool = Arc::new(AuthedPool::<FakeChan>::new(2));
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let throttled_once = Arc::new(AtomicUsize::new(0));

        let a = {
            let pool = pool.clone();
            let order = order.clone();
            let throttled_once = throttled_once.clone();
            tokio::spawn(async move {
                let g = pool
                    .acquire(&alice(), || {
                        let throttled_once = throttled_once.clone();
                        async move {
                            // First mint: the server's 429 with no Retry-After ⇒ the
                            // pool waits THROTTLE_MIN_WAIT_MS and retries once.
                            if throttled_once.fetch_add(1, Ordering::SeqCst) == 0 {
                                return Err(UiError::new(
                                    crate::session::RATE_LIMITED,
                                    "slow down",
                                ));
                            }
                            Ok(FakeChan { id: 100 })
                        }
                    })
                    .await
                    .expect("the throttle is waited out, not surfaced");
                order.lock().unwrap().push("a");
                g.id
            })
        };

        // Let A reach its throttle wait before B starts.
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let auth = FakeAuth::default();
        let b = must_acquire(&pool, &auth, "unrelated cold mint during a throttle").await;
        order.lock().unwrap().push("b");
        assert_eq!(b.id, 0, "B minted its own channel");

        let a_id = a.await.unwrap();
        assert_eq!(a_id, 100, "A got the channel from its retried mint");
        assert_eq!(
            *order.lock().unwrap(),
            vec!["b", "a"],
            "B's cold mint must not queue behind A's throttle wait"
        );
        assert_eq!(
            throttled_once.load(Ordering::SeqCst),
            2,
            "exactly one retry after the throttle"
        );
    }

    /// A throttle the pool may NOT wait out (interval past the budget) is surfaced
    /// verbatim — code and interval intact — instead of being retried into another
    /// challenge slot or mislabelled as a sign-in failure.
    #[tokio::test]
    async fn an_unwaitable_throttle_is_surfaced_with_its_interval() {
        let pool = AuthedPool::<FakeChan>::new(2);
        let attempts = AtomicUsize::new(0);
        let err = err_of(
            pool.acquire(&alice(), || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<FakeChan, _>(
                        UiError::new(crate::session::RATE_LIMITED, "too many")
                            .with_retry_after(Some(45)),
                    )
                }
            })
            .await,
            "a 45 s throttle must not be waited out inside a command",
        );
        assert_eq!(err.code, crate::session::RATE_LIMITED);
        assert_eq!(err.retry_after_s, Some(45));
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "no retry — that would just burn another challenge slot"
        );
        // …and the permit was released, so the pool still works.
        let auth = FakeAuth::default();
        let _g = must_acquire(&pool, &auth, "after an unwaitable throttle").await;
    }

    // ---- get_on_pooled_channel: the shared channel-health discipline ----

    /// One scripted reply for the fake transport: an HTTP status (+ body) the server
    /// would answer with, or a dead socket.
    enum Reply {
        Status(hyper::StatusCode),
        Transport,
    }

    /// A scripted [`ChannelGet`]: pops the next reply and records WHICH channel id
    /// each attempt ran on (so a test can prove the retry ran on a fresh mint rather
    /// than another stale sibling). Runs out ⇒ `200`.
    struct ScriptedGet {
        replies: Mutex<std::collections::VecDeque<Reply>>,
        seen: Mutex<Vec<u64>>,
    }

    impl ScriptedGet {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn seen(&self) -> Vec<u64> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl ChannelGet<FakeChan> for ScriptedGet {
        fn get<'a>(&'a self, chan: &'a mut FakeChan) -> ChannelGetFut<'a> {
            Box::pin(async move {
                self.seen.lock().unwrap().push(chan.id);
                match self.replies.lock().unwrap().pop_front() {
                    Some(Reply::Status(s)) => Ok((s, serde_json::json!({ "ok": true }))),
                    Some(Reply::Transport) => {
                        Err(UiError::new("offline", "The server did not respond."))
                    }
                    None => Ok((hyper::StatusCode::OK, serde_json::json!({ "ok": true }))),
                }
            })
        }
    }

    fn not_ok() -> UiError {
        UiError::new("feed_failed", "The feed could not be loaded.")
    }

    /// Pool two idle channels (ids 0 and 1) so a test can tell "reused a stale
    /// sibling" apart from "minted a genuinely fresh channel".
    async fn pool_with_two_idle(auth: &FakeAuth) -> AuthedPool<FakeChan> {
        let pool = AuthedPool::<FakeChan>::new(2);
        let a = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        let b = pool.acquire(&alice(), || auth.mint()).await.unwrap();
        drop(a);
        drop(b);
        assert_eq!(pool.idle.lock().unwrap().len(), 2);
        pool
    }

    /// A `401` means the whole token era is dead: drain every sibling, then retry
    /// ONCE on a genuinely fresh mint — never on another same-era sibling.
    #[tokio::test]
    async fn pooled_get_401_drains_and_retries_on_a_fresh_mint() {
        let auth = FakeAuth::default();
        let pool = pool_with_two_idle(&auth).await;
        let get = ScriptedGet::new(vec![
            Reply::Status(hyper::StatusCode::UNAUTHORIZED),
            Reply::Status(hyper::StatusCode::OK),
        ]);

        let (guard, json) =
            get_on_pooled_channel_with(&pool, &alice(), not_ok(), || auth.mint(), &get)
                .await
                .expect("the retry on a fresh channel succeeds");
        assert_eq!(json["ok"], true);
        assert_eq!(
            get.seen(),
            vec![1, 2],
            "attempt 1 used the pooled sibling; the retry used a NEWLY minted channel"
        );
        assert_eq!(guard.id, 2);
        assert_eq!(
            auth.total.load(Ordering::SeqCst),
            3,
            "exactly one extra login: the forced fresh mint"
        );
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "the 401 drained every same-era sibling (id 0 included)"
        );
    }

    /// A SECOND `401`, after the forced fresh mint, is a genuinely expired session:
    /// it must surface as `locked` ("reconnect"), NOT as the caller's `not_ok` —
    /// which would tell the user the item is unavailable when they simply need to
    /// sign in again. And the retry is bounded to ONE.
    #[tokio::test]
    async fn pooled_get_second_401_is_locked_not_the_callers_not_ok() {
        let auth = FakeAuth::default();
        let pool = pool_with_two_idle(&auth).await;
        let get = ScriptedGet::new(vec![
            Reply::Status(hyper::StatusCode::UNAUTHORIZED),
            Reply::Status(hyper::StatusCode::UNAUTHORIZED),
        ]);

        let err = err_of(
            get_on_pooled_channel_with(&pool, &alice(), not_ok(), || auth.mint(), &get).await,
            "two 401s in a row is an expired session",
        );
        assert_eq!(err.code, "locked");
        assert_ne!(err.code, not_ok().code);
        assert_eq!(get.seen().len(), 2, "bounded to exactly one retry");
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "both the drained siblings and the 401'd fresh channel are discarded"
        );
    }

    /// A non-200 / non-401 is the CALLER's outcome (`not_ok`) — the server answered,
    /// so the channel itself is healthy and goes back to the pool for reuse.
    #[tokio::test]
    async fn pooled_get_other_status_returns_not_ok_and_repools_the_channel() {
        let auth = FakeAuth::default();
        let pool = AuthedPool::<FakeChan>::new(2);
        let get = ScriptedGet::new(vec![Reply::Status(hyper::StatusCode::NOT_FOUND)]);

        let err = err_of(
            get_on_pooled_channel_with(&pool, &alice(), not_ok(), || auth.mint(), &get).await,
            "a 404 is the caller's own failure",
        );
        assert_eq!(err.code, not_ok().code);
        assert_eq!(get.seen().len(), 1, "no retry for a real server answer");
        assert_eq!(auth.total.load(Ordering::SeqCst), 1, "no extra login");
        assert_eq!(
            pool.idle.lock().unwrap().len(),
            1,
            "the channel is healthy and returns to the pool"
        );
    }

    /// A first-attempt TRANSPORT error discards ONLY that channel — the siblings'
    /// tokens are not implicated, so they are left pooled — but the retry still runs
    /// on a genuinely fresh mint, because whatever killed one idle socket usually
    /// killed the rest at the same instant.
    #[tokio::test]
    async fn pooled_get_transport_error_discards_only_that_channel_and_retries_fresh() {
        let auth = FakeAuth::default();
        let pool = pool_with_two_idle(&auth).await;
        let get = ScriptedGet::new(vec![Reply::Transport, Reply::Status(hyper::StatusCode::OK)]);

        let (guard, _json) =
            get_on_pooled_channel_with(&pool, &alice(), not_ok(), || auth.mint(), &get)
                .await
                .expect("the retry on a fresh channel succeeds");
        assert_eq!(
            get.seen(),
            vec![1, 2],
            "the dead channel was discarded and the retry used a fresh mint"
        );
        assert_eq!(guard.id, 2);
        assert_eq!(auth.total.load(Ordering::SeqCst), 3, "one forced mint");
        let idle = pool.idle.lock().unwrap();
        assert_eq!(idle.len(), 1, "the untouched sibling stays pooled");
        assert_eq!(idle[0].channel.id, 0, "…and it is the one never used");
    }

    /// A SECOND transport error (already on a freshly minted channel) is the real
    /// answer: the network is down. It surfaces as the transport error itself, not
    /// as an endless retry.
    #[tokio::test]
    async fn pooled_get_second_transport_error_is_surfaced() {
        let auth = FakeAuth::default();
        let pool = AuthedPool::<FakeChan>::new(2);
        let get = ScriptedGet::new(vec![Reply::Transport, Reply::Transport]);

        let err = err_of(
            get_on_pooled_channel_with(&pool, &alice(), not_ok(), || auth.mint(), &get).await,
            "a dead network is a dead network",
        );
        assert_eq!(err.code, "offline");
        assert_eq!(get.seen().len(), 2, "bounded to exactly one retry");
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "both dead channels are discarded"
        );
    }
}
