# Security review — reauth bounded-wait ConnectLock acquisition (2026-07-06)

**Branch:** `fix/bundle-viewer-settings-ux`
**Scope:** the bundle-viewer & settings UX fixes. Security-relevant surface: the
`ConnectLock::acquire_reauth` bounded-wait acquisition wired into `reauth`
(`crates/client-app/src/commands/auth.rs`, `crates/client-app/src/commands/connection.rs`).
The remaining changes are UI/CSS (bundle-screen debounce, video-player focus
guard, settings `<form>`→`<div>` layout, `.bundle-gallery`/settings CSS) with no
security surface.

**Verdict: PASS** — no Critical/High/Medium findings.

## The change

`reauth` previously did a single `connect_lock.0.try_lock()`, instantly returning
`busy` on any contention. It now calls `ConnectLock::acquire_reauth`, which polls
`try_lock` up to 5×50 ms (then a final attempt) before failing closed with the
same sanitized `busy` `UiError`. `connect` keeps its own fast-failing `try_lock`
(unchanged). `stream_media` and the feed pool's `reauth_channel` both call
`reauth`, so they inherit the behaviour via one DRY change.

## Why the lock/identity discipline is intact

- **Mutual exclusion preserved (no `Identity` double-take).** `acquire_reauth`
  returns a `MutexGuard<'_, ()>` from `try_lock`; at most one holder exists.
  `reauth` holds it (`_guard`) across the whole transient `Identity::take()` →
  `login_exchange` → restore sequence, so two reauths can never overlap that
  window. Unit-tested: `concurrent_reauth_lock_serializes_without_spurious_busy`
  asserts peak concurrency == 1; `reauth_lock_fails_closed_when_held_past_budget`
  asserts the honest `busy` fail-closed.
- **Fail-closed.** After the budget a final `try_lock` failure returns `busy`; the
  `?` propagates before any identity is taken. No hang, no proceeding unlocked.
- **No deadlock / ordering change.** Single mutex; the `sleep` runs with no guard
  held; the session mutex is still acquired after and released on every path; no
  nested ConnectLock acquisition.
- **No new information leak / route change.** Same `busy` code+message; the Tor /
  download-route fail-closed logic in `connection.rs` is untouched (no clearnet
  fallback introduced).

## UI/CSS

No injection/auth/data-exposure vectors. Settings markup stays fully static (a11y
XSS lint — no unescaped `${` in innerHTML — passes); the expanded Privacy copy is
static text.

## Gate at review time

client-app lib tests 283 passing (incl. the 2 new); UI `npm test` 168 + a11y 46;
typecheck clean; UI build + client-app binary compile clean.
