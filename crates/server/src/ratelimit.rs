//! Per-account anti-automation (parameters.md §3 / DESIGN §9.3). Pure and
//! in-memory: a server-instance-local throttle, **not** persisted (a restart
//! resets it; sustained abuse is caught by sink-anchored alerting, §16.5).
//!
//! Two independent controls, both keyed on the **claimed username** regardless
//! of whether it exists (so throttling leaks no user-existence oracle, §9.3):
//!
//! * **Failed-proof backoff** — exponential per account (`1s, 2s, 4s … cap 60s`).
//!   A correct password is never *locked out*, only *slowed*: the cap bounds the
//!   wait, and a success resets the counter. This is the decided posture —
//!   **rate-limit, never a hard account-lock** (a hard lock on a public username
//!   would be a third-party griefing/DoS vector, parameters.md §3).
//! * **Challenge-issuance cap** — at most `N` challenges per account per sliding
//!   window (default 30 / 60 s), bounding nonce-table churn and automation.
//!
//! Per-source (IP) caps are deliberately omitted: Tor (D34) collapses source IP,
//! so per-account is the primary, reliable signal (parameters.md §3).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Tunables (parameters.md §3 defaults).
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// First backoff step after one failure (doubles each subsequent failure).
    pub backoff_base_ms: u64,
    /// Maximum backoff — the wait never exceeds this (no hard lock).
    pub backoff_cap_ms: u64,
    /// Sliding window for the challenge-issuance cap.
    pub challenge_window_ms: u64,
    /// Max challenges issued per account within the window.
    pub challenge_max_per_window: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            backoff_base_ms: 1_000,        // 1 s (parameters.md §3)
            backoff_cap_ms: 60_000,        // 60 s cap
            challenge_window_ms: 60_000,   // per minute
            challenge_max_per_window: 30,  // 30 / account / minute
        }
    }
}

#[derive(Default)]
struct Account {
    /// Consecutive failed proofs; resets on success.
    fail_count: u32,
    /// No proof attempt is admitted before this instant (epoch-ms).
    blocked_until_ms: u64,
    /// Issuance instants of recent challenges (pruned to the window).
    challenges: VecDeque<u64>,
}

/// In-memory per-account throttle. `&self` everywhere (interior `Mutex`), so it
/// is shared across request tasks behind the `AuthService`.
pub struct RateLimiter {
    cfg: RateLimitConfig,
    accounts: Mutex<HashMap<String, Account>>,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        RateLimiter {
            cfg,
            accounts: Mutex::new(HashMap::new()),
        }
    }

    /// May a challenge be issued for `username` now? `Err(retry_after_s)` when
    /// the issuance cap is hit. On `Ok` the issuance is recorded.
    pub fn admit_challenge(&self, username: &str, now_ms: u64) -> Result<(), u64> {
        let mut accounts = self.accounts.lock().unwrap();
        let a = accounts.entry(username.to_owned()).or_default();
        let window = self.cfg.challenge_window_ms;
        // Drop issuances that have fully aged out of the sliding window.
        while let Some(&front) = a.challenges.front() {
            if front + window <= now_ms {
                a.challenges.pop_front();
            } else {
                break;
            }
        }
        if a.challenges.len() as u32 >= self.cfg.challenge_max_per_window {
            let oldest = *a.challenges.front().expect("len >= max ≥ 1");
            return Err(secs_until(now_ms, oldest + window));
        }
        a.challenges.push_back(now_ms);
        Ok(())
    }

    /// May a proof attempt proceed for `username` now? `Err(retry_after_s)` while
    /// in backoff. Does **not** itself record the attempt — call [`record_proof`].
    pub fn admit_proof(&self, username: &str, now_ms: u64) -> Result<(), u64> {
        let accounts = self.accounts.lock().unwrap();
        if let Some(a) = accounts.get(username) {
            if now_ms < a.blocked_until_ms {
                return Err(secs_until(now_ms, a.blocked_until_ms));
            }
        }
        Ok(())
    }

    /// Record a proof attempt's outcome: `success` resets the account's backoff;
    /// a failure bumps the exponential backoff (`base · 2^(n-1)`, capped).
    pub fn record_proof(&self, username: &str, now_ms: u64, success: bool) {
        let mut accounts = self.accounts.lock().unwrap();
        let a = accounts.entry(username.to_owned()).or_default();
        if success {
            a.fail_count = 0;
            a.blocked_until_ms = 0;
            return;
        }
        a.fail_count = a.fail_count.saturating_add(1);
        // base · 2^(fail_count-1), saturating on shift/multiply overflow, then
        // pinned to the cap — so the wait is bounded (never a hard lock).
        let factor = 1u64.checked_shl(a.fail_count - 1).unwrap_or(u64::MAX);
        let step = self
            .cfg
            .backoff_base_ms
            .saturating_mul(factor)
            .min(self.cfg.backoff_cap_ms);
        a.blocked_until_ms = now_ms + step;
    }
}

/// Whole seconds to wait until `until`, rounded up; `0` if already elapsed.
fn secs_until(now_ms: u64, until_ms: u64) -> u64 {
    if until_ms <= now_ms {
        0
    } else {
        (until_ms - now_ms).div_ceil(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl() -> RateLimiter {
        RateLimiter::new(RateLimitConfig::default())
    }

    const T: u64 = 1_000_000;

    #[test]
    fn first_proof_attempt_is_admitted() {
        let rl = rl();
        assert!(rl.admit_proof("alice", T).is_ok());
    }

    #[test]
    fn failure_triggers_one_second_backoff_then_clears() {
        let rl = rl();
        assert!(rl.admit_proof("alice", T).is_ok());
        rl.record_proof("alice", T, false); // 1 failure → blocked until T+1000
        assert_eq!(
            rl.admit_proof("alice", T + 500).err(),
            Some(1),
            "still blocked 500ms in, ~1s to wait"
        );
        assert!(
            rl.admit_proof("alice", T + 1000).is_ok(),
            "backoff elapsed at T+1000"
        );
    }

    #[test]
    fn backoff_doubles_per_consecutive_failure() {
        let rl = rl();
        rl.record_proof("bob", T, false); // #1 → 1s (until T+1000)
        rl.record_proof("bob", T + 1000, false); // #2 → 2s (until T+3000)
        assert_eq!(rl.admit_proof("bob", T + 1001).err(), Some(2));
        rl.record_proof("bob", T + 3000, false); // #3 → 4s (until T+7000)
        assert_eq!(rl.admit_proof("bob", T + 3001).err(), Some(4));
    }

    #[test]
    fn backoff_is_capped_at_sixty_seconds() {
        let rl = rl();
        for _ in 0..12 {
            rl.record_proof("carol", T, false); // huge fail_count, all recorded at T
        }
        // 1000 * 2^11 would be ~2_000_000ms but the cap pins it to 60s.
        assert_eq!(rl.admit_proof("carol", T + 1).err(), Some(60));
    }

    #[test]
    fn success_resets_the_backoff_counter() {
        let rl = rl();
        rl.record_proof("dave", T, false); // #1 → blocked until T+1000
        assert!(rl.admit_proof("dave", T + 1000).is_ok());
        rl.record_proof("dave", T + 1000, true); // success resets
        // The NEXT failure must be a 1s step again (not 2s), proving the reset.
        rl.record_proof("dave", T + 1000, false);
        assert_eq!(rl.admit_proof("dave", T + 1001).err(), Some(1));
    }

    #[test]
    fn challenge_cap_blocks_the_thirty_first_then_recovers_after_window() {
        let rl = rl();
        for i in 0..30 {
            assert!(rl.admit_challenge("erin", T).is_ok(), "challenge #{i}");
        }
        assert!(
            rl.admit_challenge("erin", T).is_err(),
            "31st challenge in the window is capped"
        );
        assert!(
            rl.admit_challenge("erin", T + 60_001).is_ok(),
            "after the window slides, issuance resumes"
        );
    }

    #[test]
    fn throttle_keys_on_username_only_no_existence_oracle() {
        // Two distinct usernames have fully independent state; an unknown name is
        // throttled exactly like a known one (the limiter has no notion of either).
        let rl = rl();
        rl.record_proof("ghost", T, false);
        assert!(rl.admit_proof("ghost", T + 1).is_err());
        assert!(
            rl.admit_proof("realuser", T + 1).is_ok(),
            "a different account is unaffected"
        );
    }
}
