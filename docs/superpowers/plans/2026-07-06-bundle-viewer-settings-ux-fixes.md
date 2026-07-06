# Bundle-viewer & Settings UX Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four client-app UX defects — the "connection attempt already in progress" error on rapid bundle view-toggling, mismatched bundle gallery tiles, scroll-jumping in stacked mode, and the broken/illegally-nested Settings layout.

**Architecture:** Client-app only. Four independent fixes: (1) a bounded-wait retry on the `ConnectLock` inside `reauth` (the single choke point for pool-mint / open-download / video-stream), paired with a bundle-screen render-generation guard + debounce; (2) a `.bundle-gallery` CSS rule cloning the feed `#grid` tile grid; (3) skip focus-stealing for embedded video players; (4) convert the Settings prefs `<form>` to a `<div>` grid and fold Account + Privacy into it. No wire/protocol/server change.

**Tech Stack:** Rust (Tauri command layer, `tokio::sync::Mutex`), TypeScript (vanilla Web Components), CSS. Tests: `node:test` source-regex style + Rust `#[tokio::test]`.

---

## File Structure

- `crates/client-app/src/commands/auth.rs` — add `ConnectLock::acquire_reauth` (bounded-wait acquisition) + Rust unit tests. Owns `ConnectLock`.
- `crates/client-app/src/commands/connection.rs` — `reauth` swaps its raw `try_lock` for `acquire_reauth`. Single DRY change; `stream_media` (video.rs) and pool-mint (`reauth_channel`, feed.rs) both call `reauth`, so they inherit it.
- `crates/client-app/ui/src/components/bundle-screen.ts` — render-generation token + debounced `setMode` + teardown on disconnect.
- `crates/client-app/ui/src/components/video-player.ts` — read an `embedded` attribute; skip focus when embedded.
- `crates/client-app/ui/src/components/media-viewer.ts` — pass `embedded` through to the `<video-player>` it mounts.
- `crates/client-app/ui/styles.css` — `.bundle-gallery` tile grid; Settings grid group `align-self`, Account/Privacy placement, `.privacy` full-width; drop the now-dead `main > fieldset` rule.
- `crates/client-app/ui/src/components/settings-screen.ts` — `<form id="set-form">` → `<div id="set-form">`; move Account + Privacy fieldsets inside; expanded Privacy copy.
- Tests extend existing (already in `npm test`'s explicit file list, so **no package.json change**): `bundle-screen.test.ts`, `video-player.test.ts`, `settings-screen.test.ts`.

**Key facts verified in-repo:**
- `reauth` (connection.rs:217) does `connect_lock.0.try_lock().map_err(|_| UiError::new("busy", "A connection attempt is already in progress."))?`. `connect` (connection.rs:40) has its OWN `try_lock` — **leave it unchanged** (user-initiated; "already in progress" is correct there).
- `ConnectLock(pub Mutex<()>)` is defined in auth.rs:54; `Mutex` is `tokio::sync::Mutex` (auth.rs:10). tokio has `time` + `macros` + `rt-multi-thread` features (Cargo.toml:60).
- `UiError { pub code: String, pub message: String }` (error.rs) — `.code` is readable in same-crate tests.
- `npm test` runs an explicit file list; `bundle-screen.test.ts`, `video-player.test.ts`, `settings-screen.test.ts` are all already in it. `a11y.test.ts` runs under `npm run test:a11y` (NOT part of `npm test`) but we keep it green anyway.
- a11y lint requires settings-screen.ts to keep `id="main"` + `tabindex="-1"` + `.focus()` and no `${` in innerHTML except `${esc(`. video-player.ts must keep `.focus()` literal, `tabindex="-1"`, `aria-live`. Our changes preserve all of these.
- Feed tile grid (styles.css:1641): `#grid { grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr)); align-items: stretch; }` with `gap: clamp(0.9rem, 2vw, 1.25rem)` (from the base `#grid` at :442). No `.bundle-gallery` / `.bundle-stack` rule exists today (confirmed) — that is the Issue-2 root cause.
- Settings block (styles.css:576-588): `settings-screen #set-form { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:1rem; … }`, `settings-screen #set-form fieldset { margin:0; }`, `settings-screen main > fieldset { max-width:760px; }`.

**Known tradeoff (accepted, per spec "change listener unchanged"):** after Account's `<form id="pw-form">`/`<form id="exp-form">` move inside the `#set-form` div, a `change` on a password/dest field bubbles to the `#set-form` change listener and triggers a harmless no-op settings re-save ("Saved." flash in `#set-status`, separate from `#acct-status`). The spec explicitly keeps the listener unchanged; if review objects, the minimal fix is an early-return in `onPrefChange` when `e.target.closest("#pw-form,#exp-form")`. We follow the spec.

---

### Task 0: Branch off main

- [ ] **Step 1: Create the feature branch**

Run:
```bash
git checkout main
git checkout -b fix/bundle-viewer-settings-ux
```
Expected: `Switched to a new branch 'fix/bundle-viewer-settings-ux'`.

(Client-app-only change — a plain branch is sufficient; no worktree needed.)

---

### Task 1: Backend — bounded-wait ConnectLock acquisition for reauth (Issue 1 backend)

**Files:**
- Modify: `crates/client-app/src/commands/auth.rs` (add method to `ConnectLock` impl at :56-60; add a test module)
- Modify: `crates/client-app/src/commands/connection.rs:230-233`
- Test: `crates/client-app/src/commands/auth.rs` (inline `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests** in `auth.rs` — append this module at the end of the file:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-client-app acquire_reauth reauth_lock concurrent_reauth 2>&1 | tail -20`
Expected: FAIL to COMPILE with `no method named acquire_reauth found for ... ConnectLock`.

- [ ] **Step 3: Implement `acquire_reauth`** — add to the existing `impl ConnectLock` block in `auth.rs` (currently just `new`, lines 56-60):

```rust
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
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, crate::error::UiError> {
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
            .map_err(|_| crate::error::UiError::new("busy", "A connection attempt is already in progress."))
    }
}
```

- [ ] **Step 4: Wire `reauth` to use it** — in `connection.rs`, replace lines 230-233:

```rust
    let _guard = connect_lock
        .0
        .try_lock()
        .map_err(|_| UiError::new("busy", "A connection attempt is already in progress."))?;
```

with:

```rust
    // Tolerate a transient overlap with a sibling reauth (bounded wait+retry)
    // instead of instantly erroring "busy" — rapid view-switches that fan out
    // several reauth-bound calls should queue briefly, not fail. Still fails
    // closed if a real `connect` holds the lock past the budget.
    let _guard = connect_lock.acquire_reauth().await?;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-client-app 2>&1 | tail -25`
Expected: PASS — the two new tests plus the whole client-app suite green. (Note the two tests take ~0.2s each due to real sleeps.)

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/commands/auth.rs crates/client-app/src/commands/connection.rs
git commit -m "fix(client): bounded-wait ConnectLock acquisition for reauth (no spurious busy)"
```

---

### Task 2: Frontend — bundle-screen render-generation guard + debounce (Issue 1 frontend)

**Files:**
- Modify: `crates/client-app/ui/src/components/bundle-screen.ts`
- Test: `crates/client-app/ui/src/components/bundle-screen.test.ts`

- [ ] **Step 1: Write the failing source-structural tests** — append to `bundle-screen.test.ts` (the `src` const already exists at line 86):

```typescript
// --- Issue 1 (frontend): render-generation guard + debounced view switch -----
// Rapid Gallery⇄Stacked toggling must not fan out overlapping member loads that
// race the connect lock. setMode debounces the expensive re-render and tags each
// scheduled render with a generation token so a superseded one is dropped;
// re-render tears down prior children (replaceChildren) so their in-flight loads
// are abandoned. disconnect clears any pending timer.

test("bundle-screen carries a render-generation token", () => {
  assert.match(src, /renderGen/, "must track a render generation");
});

test("setMode debounces the re-render with a timer", () => {
  assert.match(src, /setTimeout\(/, "setMode must schedule the re-render on a timer");
  assert.match(src, /clearTimeout\(/, "a pending re-render timer must be cancellable");
});

test("a superseded scheduled render is dropped via the generation guard", () => {
  // The scheduled callback bails when its captured generation is stale.
  assert.match(src, /!==\s*this\.renderGen/, "scheduled render must guard on a stale generation");
});

test("disconnect clears the pending re-render timer", () => {
  assert.match(src, /disconnectedCallback\(\)\s*\{[\s\S]*clearTimeout/, "must clear the timer on disconnect");
});
```

- [ ] **Step 2: Run to verify they fail**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -25`
Expected: FAIL — the four new bundle-screen assertions don't match yet.

- [ ] **Step 3: Implement the guard + debounce** in `bundle-screen.ts`.

3a. Add fields + a constant. After the class's existing fields (`private view` / `private mode`, lines 36-37), add:

```typescript
  private view: BundleView | null = null;
  private mode: BundleViewMode = readBundleViewMode();
  // Render-generation guard (Issue 1): a monotonically increasing token. A
  // debounced setMode schedules a re-render tagged with the current generation;
  // if a newer toggle bumps the generation first, the stale scheduled render is
  // dropped. This shrinks the window in which rapid toggles fan out overlapping
  // member loads that would contend the connect lock.
  private renderGen = 0;
  private modeTimer: ReturnType<typeof setTimeout> | null = null;
```

3b. Replace `setMode` (lines 128-134):

```typescript
  // Switch view mode: persist the choice and re-render the already-fetched
  // members (no re-fetch — mode is a pure presentation concern). The toggle's
  // visual state flips immediately for feedback; the expensive member re-render
  // is debounced and generation-guarded so a burst of toggles collapses to the
  // final mode and never leaves a superseded render running.
  private setMode(mode: BundleViewMode) {
    if (mode === this.mode) return;
    this.mode = mode;
    writeBundleViewMode(mode);
    this.syncToggle();
    const gen = ++this.renderGen;
    if (this.modeTimer !== null) clearTimeout(this.modeTimer);
    this.modeTimer = setTimeout(() => {
      this.modeTimer = null;
      if (gen !== this.renderGen) return; // superseded by a newer toggle
      this.render();
    }, MODE_DEBOUNCE_MS);
  }
```

3c. Add a `disconnectedCallback` (the class has none today). Place it right after `setMode`:

```typescript
  disconnectedCallback() {
    // Drop any pending debounced re-render so it can't fire into a torn-down view.
    if (this.modeTimer !== null) {
      clearTimeout(this.modeTimer);
      this.modeTimer = null;
    }
  }
```

3d. Bump the generation whenever `render()` runs directly (from `load()`), so a debounced render scheduled before the fetch resolved is superseded by the real one. At the top of `render()` (line 223, right after the signature), add:

```typescript
  private render() {
    // Any direct render (e.g. the initial load) supersedes a pending debounced one.
    this.renderGen++;
    const container = this.querySelector("#bd-members") as HTMLElement;
```

3e. Add the debounce constant near the top of the file, just after the imports (before the class):

```typescript
// Debounce window for the Gallery⇄Stacked re-render. Long enough to collapse a
// burst of toggles, short enough to feel immediate.
const MODE_DEBOUNCE_MS = 150;
```

- [ ] **Step 4: Run to verify they pass**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -15`
Expected: PASS — new bundle-screen tests green, existing ones still green.

- [ ] **Step 5: Typecheck**

Run (from `crates/client-app/ui`): `npm run typecheck`
Expected: no output (clean).

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/ui/src/components/bundle-screen.ts crates/client-app/ui/src/components/bundle-screen.test.ts
git commit -m "fix(ui): debounce + generation-guard bundle view switch (no torn-down races)"
```

---

### Task 3: Gallery tiles match the feed grid (Issue 2)

**Files:**
- Modify: `crates/client-app/ui/styles.css`
- Test: `crates/client-app/ui/src/components/bundle-screen.test.ts`

- [ ] **Step 1: Write the failing CSS-presence test** — append to `bundle-screen.test.ts` (add the css read once, near the top after the `src` const if not already present):

```typescript
// --- Issue 2: the bundle gallery reuses the feed's tile grid ------------------
const css = readFileSync("styles.css", "utf8");

test(".bundle-gallery is a tile grid matching the feed #grid", () => {
  // The gallery must lay <media-card>s out on the SAME auto-fit tile grid the
  // feed uses (repeat(auto-fit, minmax(min(100%, 280px), 1fr))), not block flow.
  assert.match(
    css,
    /\.bundle-gallery\s*\{[\s\S]*?display:\s*grid[\s\S]*?repeat\(auto-fit,\s*minmax\(min\(100%,\s*280px\),\s*1fr\)\)/,
    ".bundle-gallery must define the feed's auto-fit tile grid",
  );
});
```

Note: `bundle-screen.test.ts` runs from the `crates/client-app/ui` working dir (that's where `npm test` runs), so `readFileSync("styles.css", …)` and `readFileSync("src/components/bundle-screen.ts", …)` both resolve — the latter already works in the existing suite.

- [ ] **Step 2: Run to verify it fails**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -15`
Expected: FAIL — no `.bundle-gallery` rule exists.

- [ ] **Step 3: Add the CSS rule.** In `styles.css`, immediately after the feed `#grid` block at lines 1641-1644 (the `repeat(auto-fit …)` one), insert:

```css
/* Bundle gallery view (Issue 2): render bundle members on the SAME tile grid the
   feed uses, so <media-card>s look identical in both places. Without this rule
   the cards fall back to block flow (one per line). */
.bundle-gallery {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr));
  gap: clamp(0.9rem, 2vw, 1.25rem);
  align-items: stretch;
}
```

- [ ] **Step 4: Run to verify it passes**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -12`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/styles.css crates/client-app/ui/src/components/bundle-screen.test.ts
git commit -m "fix(ui): bundle gallery uses the feed tile grid (.bundle-gallery)"
```

---

### Task 4: Stacked mode stops scroll-jumping (Issue 3)

**Files:**
- Modify: `crates/client-app/ui/src/components/video-player.ts`
- Modify: `crates/client-app/ui/src/components/media-viewer.ts:195-197`
- Test: `crates/client-app/ui/src/components/video-player.test.ts`

- [ ] **Step 1: Write the failing source tests** — append to `video-player.test.ts`:

```typescript
import { readFileSync } from "node:fs";

// --- Issue 3: embedded (stacked) players must not steal focus -----------------
// video-player.focus() on mount scrolls the element into view. In a Stacked
// bundle, each member that loads would grab focus and scroll-jump the page. When
// the player is embedded, it must NOT steal focus; the routed full-screen viewer
// keeps focus for a11y (WCAG 2.4.3).
const vpSrc = readFileSync("src/components/video-player.ts", "utf8");

test("video-player reads an embedded flag", () => {
  assert.match(vpSrc, /hasAttribute\("embedded"\)/, "must detect the embedded attribute");
});

test("focus on mount is guarded by the embedded flag", () => {
  // The region focus() is only called when NOT embedded.
  assert.match(
    vpSrc,
    /if\s*\(!this\.embedded\)\s*\{[\s\S]{0,120}?\.focus\(\)/,
    "focus() must be skipped for embedded players",
  );
});
```

Also assert media-viewer forwards the flag — append to the SAME file:

```typescript
const mvSrc = readFileSync("src/components/media-viewer.ts", "utf8");

test("media-viewer forwards embedded to the video-player it mounts", () => {
  assert.match(
    mvSrc,
    /this\.embedded[\s\S]{0,120}?setAttribute\("embedded"/,
    "an embedded media-viewer must pass embedded to its <video-player>",
  );
});
```

- [ ] **Step 2: Run to verify they fail**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -15`
Expected: FAIL — three new video-player assertions unmatched.

- [ ] **Step 3a: Implement the embedded flag in `video-player.ts`.** Add a field alongside the others (after `private native = false;`, line 35):

```typescript
  // True when mounted inside an embedded (Stacked bundle-member) media-viewer.
  // Embedded players must not steal focus — each member that loads would
  // otherwise scroll-jump the page. Set from the `embedded` attribute on mount.
  private embedded = false;
```

- [ ] **Step 3b: Guard the focus call in `connectNative`.** Replace line 92:

```typescript
    (this.querySelector("#vp-region") as HTMLElement).focus();
```

with:

```typescript
    // Routed viewer: move focus to the media region (WCAG 2.4.3). Embedded
    // (Stacked bundle) instances must NOT — a loading member grabbing focus
    // scroll-jumps the page.
    this.embedded = this.hasAttribute("embedded");
    if (!this.embedded) {
      (this.querySelector("#vp-region") as HTMLElement).focus();
    }
```

- [ ] **Step 3c: Forward the flag from `media-viewer.ts`.** In the video branch (lines 195-198), after `(vp as unknown as VideoPlayer).fileId = this.reqId;` add:

```typescript
      const vp = document.createElement("video-player");
      vp.setAttribute("file-id", this.reqId);
      (vp as unknown as VideoPlayer).fileId = this.reqId;
      // Embedded (Stacked bundle) viewers must not let their player steal focus.
      if (this.embedded) vp.setAttribute("embedded", "");
      body.appendChild(vp);
```

- [ ] **Step 4: Run to verify they pass**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -12`
Expected: PASS.

- [ ] **Step 5: Keep a11y lint green** (video-player still has `.focus()` present, so its lint passes):

Run (from `crates/client-app/ui`): `npm run test:a11y 2>&1 | tail -8`
Expected: PASS (no regressions).

- [ ] **Step 6: Typecheck + commit**

Run (from `crates/client-app/ui`): `npm run typecheck`
Expected: clean.

```bash
git add crates/client-app/ui/src/components/video-player.ts crates/client-app/ui/src/components/media-viewer.ts crates/client-app/ui/src/components/video-player.test.ts
git commit -m "fix(ui): embedded video players don't steal focus (no stacked scroll-jump)"
```

---

### Task 5: Settings unified single grid (Issue 4)

**Files:**
- Modify: `crates/client-app/ui/src/components/settings-screen.ts`
- Modify: `crates/client-app/ui/styles.css`
- Test: `crates/client-app/ui/src/components/settings-screen.test.ts`

- [ ] **Step 1: Write the failing tests** — append to `settings-screen.test.ts` (the `src` const already exists at line 11):

```typescript
// --- Issue 4: unified single-grid Settings layout ----------------------------
// The prefs container is a <div> grid (not a <form> — no submit is used, and it
// must legally contain Account's own <form>s). Account and Privacy live INSIDE
// the grid; Privacy spans both columns; the Privacy copy is expanded + accurate.
const setCss = readFileSync("styles.css", "utf8");

test("prefs container is a <div id=\"set-form\"> grid, not a <form>", () => {
  assert.match(src, /<div id="set-form">/, "set-form must be a <div>");
  assert.doesNotMatch(src, /<form id="set-form">/, "set-form must NOT be a <form>");
});

test("Account and Privacy fieldsets live inside the set-form grid", () => {
  // Both legends appear before the set-form div closes (i.e. nested in it).
  assert.match(
    src,
    /<div id="set-form">[\s\S]*<legend>Account<\/legend>[\s\S]*<legend>Privacy<\/legend>[\s\S]*<\/div>/,
    "Account + Privacy must be inside the #set-form grid",
  );
});

test("Privacy fieldset is tagged for full-width and spans both columns", () => {
  assert.match(src, /<fieldset class="privacy">/, "Privacy fieldset needs the .privacy class");
  assert.match(
    setCss,
    /\.privacy\s*\{[\s\S]*?grid-column:\s*1\s*\/\s*-1/,
    ".privacy must span both grid columns",
  );
});

test("grid groups align to the top (no stretched short groups)", () => {
  assert.match(
    setCss,
    /settings-screen #set-form > fieldset\s*\{[\s\S]*?align-self:\s*start/,
    "grid group fieldsets must align-self: start",
  );
});

test("Privacy copy is expanded and accurate", () => {
  for (const phrase of [/ciphertext/i, /zeroiz/i, /telemetry/i, /\bTor\b/, /on this device/i]) {
    assert.match(src, phrase, `Privacy copy must mention ${phrase}`);
  }
});
```

- [ ] **Step 2: Run to verify they fail**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -25`
Expected: FAIL — the five new settings assertions unmatched.

- [ ] **Step 3a: Convert `#set-form` to a `<div>` and fold Account + Privacy inside** — in `settings-screen.ts`, replace the whole markup from the opening `<form id="set-form">` (line 29) through the standalone Privacy `</fieldset>` (line 114), i.e. lines 29-114, with:

```html
        <div id="set-form">
          <fieldset>
            <legend>Appearance</legend>
            <label>Theme
              <select name="theme">
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select></label>
          </fieldset>

          <fieldset>
            <legend>Accessibility</legend>
            <label><input type="checkbox" name="reduced_motion" /> Reduce motion</label>
            <label><input type="checkbox" name="high_contrast" /> High contrast</label>
            <label>Text size
              <select name="text_size">
                <option value="normal">Normal</option>
                <option value="large">Large</option>
                <option value="larger">Larger</option>
              </select></label>
          </fieldset>

          <fieldset>
            <legend>Performance</legend>
            <label>Media cache (MB)
              <input type="range" name="media_range" step="1" />
              <input type="number" name="media_cache_cap_mb" step="1" /></label>
            <label>Thumbnails cache (MB)
              <input type="number" name="thumb_cache_cap_mb" step="1" /></label>
            <p id="ram-hint" class="hint"></p>
            <label>Feed concurrency (cards decoded in parallel)
              <input type="number" name="feed_concurrency" min="1" max="8" step="1" /></label>
            <label>Transcode threads
              <input type="number" name="transcode_threads" min="1" step="1" /></label>
            <label>Decode threads
              <input type="number" name="decode_threads" min="1" step="1" /></label>
            <p id="cores-hint" class="hint"></p>
            <label>Cache location
              <select name="cache_location">
                <option value="Memory">Memory (RAM only)</option>
                <option value="Disk">Disk</option>
              </select></label>
            <p class="hint">Memory keeps cached ciphertext in RAM only, bounded by the caps above. Disk spills ciphertext to a temp dir (no cap) and is wiped on start and exit.</p>
          </fieldset>

          <fieldset>
            <legend>Behavior</legend>
            <label><input type="checkbox" name="confirm_destructive" /> Confirm destructive actions</label>
          </fieldset>

          <fieldset>
            <legend>Connection</legend>
            <label>Download route
              <select name="route_mode">
                <option value="prefer-server">Prefer server (default)</option>
                <option value="prefer-dropbox">Prefer Dropbox offload</option>
                <option value="tor-only">Tor only</option>
              </select></label>
            <p class="hint">Prefer server proxies all media through the server. Prefer Dropbox downloads offloaded media directly from cloud storage when available (still verified locally). Tor only routes everything over Tor and fails closed.</p>
          </fieldset>

          <fieldset>
            <legend>Account</legend>
            <p id="acct-status" role="status" aria-live="polite"></p>
            <form id="pw-form">
              <label>Current password
                <input type="password" name="oldpw" autocomplete="current-password" /></label>
              <label>New password
                <input type="password" name="newpw" autocomplete="new-password" /></label>
              <button type="submit">Change password</button>
            </form>
            <form id="exp-form">
              <p id="exp-warn" role="note">Back up the keystore file securely — it is only as safe as your password.</p>
              <label>Export keystore to path
                <input type="text" name="dest" autocomplete="off" /></label>
              <button type="submit">Export keystore</button>
            </form>
          </fieldset>

          <fieldset class="privacy">
            <legend>Privacy</legend>
            <p>Your content is encrypted on this device with keys only you hold before
              it ever leaves — the server stores and serves only ciphertext and can
              never read your posts. Cached ciphertext is wiped and your keys are
              zeroized from memory when the app closes. Settings stay on this device;
              no analytics or telemetry are collected. You can optionally route all
              traffic over Tor from the Connection settings above.</p>
          </fieldset>
        </div>
```

**Note:** this DELETES the two standalone `<fieldset>` blocks that were at lines 91-114 (Account + Privacy) and moves them inside the div (Account keeps its `<form>`s — now legal because the container is a `<div>`, not a `<form>`). The `#acct-status`, `#pw-form`, `#exp-form`, `#exp-warn`, `#ram-hint`, `#cores-hint`, `#set-status` ids are all preserved, so every `querySelector` in the class still resolves.

- [ ] **Step 3b: Update the container cast** — in `connectedCallback`, line 118:

```typescript
    const prefForm = this.querySelector("#set-form") as HTMLFormElement;
```

becomes:

```typescript
    const prefForm = this.querySelector("#set-form") as HTMLElement;
```

(`change` still bubbles to a `<div>`, so the live-save listener is unchanged.)

- [ ] **Step 3c: Add the CSS** — in `styles.css`, replace the `settings-screen main > fieldset { max-width: 760px; }` rule at line 588 (now dead — no direct-child fieldsets remain) and extend the settings block. Change lines 587-588 from:

```css
settings-screen #set-form fieldset { margin: 0; }
settings-screen main > fieldset { max-width: 760px; }
```

to:

```css
settings-screen #set-form fieldset { margin: 0; }
/* Grid groups align to the top so a short group (e.g. Behavior) doesn't stretch
   to match a tall neighbour (Performance). Issue 4. */
settings-screen #set-form > fieldset { align-self: start; }
/* Privacy spans the full width beneath the two columns. */
settings-screen #set-form > fieldset.privacy { grid-column: 1 / -1; }
```

- [ ] **Step 4: Run to verify they pass**

Run (from `crates/client-app/ui`): `npm test 2>&1 | tail -15`
Expected: PASS — new settings tests green, existing settings/a11y-relevant assertions still green.

- [ ] **Step 5: a11y lint + typecheck** (settings-screen keeps `#main`/`tabindex="-1"`/`.focus()`; no `${` in innerHTML):

Run (from `crates/client-app/ui`): `npm run test:a11y 2>&1 | tail -8 && npm run typecheck`
Expected: a11y PASS, typecheck clean.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/ui/src/components/settings-screen.ts crates/client-app/ui/styles.css crates/client-app/ui/src/components/settings-screen.test.ts
git commit -m "fix(ui): unified Settings grid — div container, Account/Privacy in-grid, full-width Privacy + accurate copy"
```

---

### Task 6: Full gate + real-app verification

**Files:** none (verification only).

- [ ] **Step 1: UI gate**

Run (from `crates/client-app/ui`):
```bash
npm run typecheck && npm test && npm run test:a11y && npm run build
```
Expected: typecheck clean; all `npm test` files PASS; a11y PASS; build writes `dist/main.js` + `dist/styles.css` with no error.

- [ ] **Step 2: Rust gate**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test -p maxsecu-client-app 2>&1 | tail -20`
Expected: PASS (incl. the two new `acquire_reauth`/`reauth_lock` tests).

- [ ] **Step 3: client-app binary compiles**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo build -p maxsecu-client-app 2>&1 | tail -8`
Expected: `Finished` with no errors.

- [ ] **Step 4: Real-app verification (`verify` skill).** Launch the app, open a bundle, and confirm all four fixes by observation:
  1. Rapid-toggle Gallery⇄Stacked repeatedly — no "connection attempt already in progress" toast; items either load or show a real failure.
  2. In Gallery, member tiles look identical to the feed / My-Content cards.
  3. In Stacked with a video member, the page does not scroll-jump as members load.
  4. Open Settings — one unified grid; Behavior isn't stretched; Account sits in the right column; Privacy spans full width with the expanded copy; Change-password and Export still work.

  If a windowed GUI smoke isn't runnable in this environment, record it as a user-run manual smoke (matching the repo's convention) and note it in the completion summary — do NOT claim it passed unobserved.

---

### Task 7: Security review of the #1 reauth change

**Files:** none (review only); may produce `docs/security-review-2026-07-06-reauth-bounded-wait.md`.

- [ ] **Step 1: Run the security-review skill** scoped to the ConnectLock/reauth change. Confirm:
  - Only ONE reauth holds the guard at a time (mutual exclusion preserved) → the transient `Identity` `take()`/restore in `reauth` can never overlap another's; the identity is never double-taken.
  - `connect`'s own `try_lock` is unchanged (user-initiated connect still fails fast with "already in progress").
  - The bounded wait fails closed (`busy`) rather than hanging when a real `connect` holds the lock past budget.
  - No new lock is held across the `Identity` take without restore; no lock ordering / deadlock introduced (single lock, guard dropped on all paths).

- [ ] **Step 2: Record the verdict** (PASS + one-paragraph rationale) inline in the completion summary, or as a short `docs/security-review-2026-07-06-reauth-bounded-wait.md` if the review warrants a file. Do not fabricate a PASS — if anything is off, fix it and re-review.

---

## Self-Review

**Spec coverage:**
- Issue 1 frontend (generation token, ~150ms debounce, teardown, ignore stale) → Task 2. ✓
- Issue 1 backend (bounded 5×50ms wait+retry on ConnectLock, one DRY change covering pool-mint / open-download / stream, fail-honest) → Task 1. ✓ (`reauth` is the single choke point; `stream_media` and `reauth_channel` both call it.)
- Issue 2 (`.bundle-gallery` = feed grid) → Task 3. ✓
- Issue 3 (embedded player no focus-steal; routed keeps focus) → Task 4. ✓
- Issue 4 (form→div grid, move Account/Privacy in, align-self start, Privacy full-width + expanded copy, no illegal nested forms) → Task 5. ✓
- Testing (UI unit tests for all four; Rust bounded-wait test; gate; security review) → Tasks 1-2-3-4-5 tests + Task 6 gate + Task 7. ✓
- Non-goals respected: no autoplay change, no bundle data-model change, no server/protocol change, no settings semantics change (layout + copy only). ✓

**Type/name consistency:** `acquire_reauth` used in Task 1 impl, its test, and connection.rs wiring — consistent. `renderGen`/`modeTimer`/`MODE_DEBOUNCE_MS` consistent across Task 2 code + tests. `embedded` field + `hasAttribute("embedded")` + `setAttribute("embedded", "")` consistent across video-player, media-viewer, and Task 4 tests. `.bundle-gallery` / `.privacy` / `#set-form` selectors consistent across CSS + settings/bundle tests. `UiError.code == "busy"` matches error.rs.

**Placeholder scan:** none — every code step shows full content.
