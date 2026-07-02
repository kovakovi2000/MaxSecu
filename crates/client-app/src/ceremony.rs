//! In-process state for the T6 Shamir recovery-key ceremony (spec §8): the
//! collected shares of an in-progress reconstruct, and any key(s) reconstructed
//! from them, live ONLY here — they never cross the Tauri command boundary.
//!
//! Mirrors `commands/auth.rs`'s `Session`/`ConnectLock` managed-state shape
//! (`commands/auth.rs:23-60`), but guarded by a **`std::sync::Mutex`**, not the
//! app's usual async `tokio::sync::Mutex`: per spec §8, every command that
//! touches this state (`add_recovery_share`, `reconstruct_recovery_key`,
//! `prove_reconstructed_key`, `discard_ceremony_session`) is local/offline —
//! plain `fn`, not `async fn`, with no `.await` in its body — so a sync mutex
//! is both sufficient and the correct fit, exactly the reasoning
//! `VideoPrepareCancel` already documents (`jobs.rs:141-144`) for the same
//! "sync command, never held across an await" case.

use std::collections::HashMap;
use std::sync::Mutex;

use maxsecu_crypto::{EncSecretKey, Share};
use zeroize::Zeroize;

/// The in-progress state of ONE reconstruct ceremony.
///
/// Holds the shares collected so far, the session's `label` and required
/// threshold `need` (both fixed by the FIRST accepted share — spec §5's MSHARE1
/// encoding carries `label`/`k`/`n` on every share, so the session adopts
/// whichever the custodian pastes in first), and any key(s) already
/// reconstructed from a complete set, keyed by an opaque `ceremony_handle`.
///
/// This type only accumulates/exposes counts — it does NOT itself decide
/// whether a new share's own label/k/n agrees with an already-fixed session;
/// that cross-validation is the `add_recovery_share` command's job (out of
/// this task's scope). `Debug` is deliberately NOT derived: `Share`'s own
/// `Debug` already elides its body (`crypto/shamir.rs:41-51`), but eliding one
/// more field by hand here would still let a derive print `reconstructed`'s
/// keys/labels; simplest to just not have one.
#[derive(Default)]
pub struct CeremonySessionInner {
    shares: Vec<Share>,
    label: Option<String>,
    need: Option<u8>,
    reconstructed: HashMap<String, EncSecretKey>,
}

impl CeremonySessionInner {
    /// Accept one already-decoded, already-checksum-verified share into the
    /// in-progress set. The first call in a session fixes `label`/`need`;
    /// later calls append without touching them.
    pub fn add_share(&mut self, share: Share, label: String, k: u8) {
        if self.label.is_none() {
            self.label = Some(label);
            self.need = Some(k);
        }
        self.shares.push(share);
    }

    /// How many shares have been collected so far.
    pub fn have(&self) -> u8 {
        self.shares.len() as u8
    }

    /// The threshold fixed by the first accepted share, or `0` before any
    /// share has been added (nothing to compare against yet).
    pub fn need(&self) -> u8 {
        self.need.unwrap_or(0)
    }

    /// The session's label (operator-chosen, non-secret), if any share has
    /// been accepted yet.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// A read-only view of the shares collected so far (e.g. for `combine`
    /// once `have() >= need()`).
    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    /// Store a freshly reconstructed key under a fresh opaque handle. The
    /// caller (the `reconstruct_recovery_key` command, out of this task's
    /// scope) mints `handle` — e.g. random hex — and returns ONLY that handle
    /// to the UI, never these bytes.
    pub fn insert_reconstructed(&mut self, handle: String, key: EncSecretKey) {
        self.reconstructed.insert(handle, key);
    }

    /// Borrow a previously reconstructed key by its opaque handle (e.g. for
    /// `prove_reconstructed_key`).
    pub fn reconstructed(&self, handle: &str) -> Option<&EncSecretKey> {
        self.reconstructed.get(handle)
    }

    /// Discard everything: the collected shares (their bodies explicitly
    /// zeroized — `Share` itself does not zeroize on drop, only `shamir::split`'s
    /// own transient coefficient buffers do, per the module doc at
    /// `crypto/shamir.rs:1-20`), the label/threshold, and any reconstructed
    /// key(s) (`EncSecretKey` already zeroizes itself via its internal
    /// `Zeroizing` wrapper, `crypto/wrap.rs:32`, so clearing the map suffices
    /// there). Called by the `discard_ceremony_session` command and by `Drop`.
    pub fn reset(&mut self) {
        for mut share in self.shares.drain(..) {
            share.body.zeroize();
        }
        self.label = None;
        self.need = None;
        self.reconstructed.clear();
    }
}

impl Drop for CeremonySessionInner {
    fn drop(&mut self) {
        self.reset();
    }
}

/// Managed state: at most one in-progress ceremony (mirrors `Session`,
/// `commands/auth.rs:23-60`). See the module doc for why this is a
/// `std::sync::Mutex`, not the app's usual async one.
#[derive(Default)]
pub struct CeremonySession(pub Mutex<CeremonySessionInner>);

impl CeremonySession {
    pub fn new() -> Self {
        Self(Mutex::new(CeremonySessionInner::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(index: u8, body: &[u8]) -> Share {
        Share {
            index,
            body: body.to_vec(),
        }
    }

    #[test]
    fn fresh_session_has_no_shares_label_or_threshold() {
        let inner = CeremonySessionInner::default();
        assert_eq!(inner.have(), 0);
        assert_eq!(inner.need(), 0);
        assert_eq!(inner.label(), None);
        assert!(inner.shares().is_empty());
    }

    #[test]
    fn add_share_accumulates_and_reports_have_need() {
        let mut inner = CeremonySessionInner::default();
        inner.add_share(share(1, b"aaa"), "recovery-2026-07".into(), 3);
        assert_eq!(inner.have(), 1);
        assert_eq!(inner.need(), 3);
        assert_eq!(inner.label(), Some("recovery-2026-07"));

        inner.add_share(share(2, b"bbb"), "recovery-2026-07".into(), 3);
        assert_eq!(inner.have(), 2);
        assert_eq!(inner.need(), 3);

        inner.add_share(share(4, b"ccc"), "recovery-2026-07".into(), 3);
        assert_eq!(inner.have(), 3);
        assert_eq!(inner.need(), 3);
        assert_eq!(
            inner.shares().iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![1, 2, 4]
        );
    }

    #[test]
    fn label_and_need_are_fixed_by_the_first_accepted_share() {
        let mut inner = CeremonySessionInner::default();
        inner.add_share(share(1, b"aaa"), "first-label".into(), 3);
        // A later add with a DIFFERENT label/k does not overwrite the session's
        // fixed label/need (cross-validating that mismatch is the command
        // layer's job — this type just doesn't clobber its own state).
        inner.add_share(share(2, b"bbb"), "different-label".into(), 5);
        assert_eq!(inner.label(), Some("first-label"));
        assert_eq!(inner.need(), 3);
        assert_eq!(inner.have(), 2);
    }

    #[test]
    fn reset_clears_shares_label_need_and_reconstructed() {
        let mut inner = CeremonySessionInner::default();
        inner.add_share(share(1, b"aaa"), "label".into(), 2);
        inner.add_share(share(2, b"bbb"), "label".into(), 2);
        inner.insert_reconstructed("handle-1".into(), EncSecretKey::from_bytes([0x42; 32]));
        assert_eq!(inner.have(), 2);
        assert!(inner.reconstructed("handle-1").is_some());

        inner.reset();

        assert_eq!(inner.have(), 0);
        assert_eq!(inner.need(), 0);
        assert_eq!(inner.label(), None);
        assert!(inner.shares().is_empty());
        assert!(inner.reconstructed("handle-1").is_none());
    }

    #[test]
    fn insert_and_fetch_reconstructed_by_handle() {
        let mut inner = CeremonySessionInner::default();
        let key = EncSecretKey::from_bytes([0x07; 32]);
        inner.insert_reconstructed("h1".into(), key);
        let got = inner.reconstructed("h1").expect("present");
        assert_eq!(got.expose_bytes(), [0x07; 32]);
        assert!(inner.reconstructed("nope").is_none());
    }

    #[test]
    fn drop_runs_reset_without_panicking() {
        // No direct way to observe zeroization of freed memory from a safe
        // test; this pins that constructing then dropping a populated session
        // (exercising the `Drop` → `reset` path) does not panic and that a
        // fresh session built afterward starts clean — the meaningful,
        // testable half of the "zero-on-drop" contract.
        {
            let mut inner = CeremonySessionInner::default();
            inner.add_share(share(1, b"aaa"), "label".into(), 2);
            inner.insert_reconstructed("h".into(), EncSecretKey::from_bytes([0x99; 32]));
        } // dropped here
        let inner = CeremonySessionInner::default();
        assert_eq!(inner.have(), 0);
    }

    #[test]
    fn managed_state_new_and_default_agree() {
        let a = CeremonySession::new();
        let b = CeremonySession::default();
        assert_eq!(a.0.lock().unwrap().have(), b.0.lock().unwrap().have());
    }
}
