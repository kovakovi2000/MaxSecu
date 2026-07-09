# Keep All Client Storage Inside the Portable Folder — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure the client stores nothing outside its portable `<app_dir>` folder, while still remembering theme, player volume, bundle-view mode, and skin across runs.

**Architecture:** (1) Redirect the WebView2 user-data folder into `<app_dir>/webview/` and wipe it on exit — this pulls `localStorage` and all WebView2 byproducts inside the folder. (2) Move the three `localStorage`-backed prefs (skin, bundle-view, volume) into the backend `config/settings.json`, with the skin injected pre-paint via a Tauri initialization script so there is no flash. (3) Ship a ProcMon capture+analyzer to prove no write lands outside the folder.

**Tech Stack:** Rust + Tauri 2.11.5 (`WebviewWindowBuilder::data_directory` / `initialization_script`, both confirmed present), wry 0.55.1, vanilla-TS UI tested with `node:test`, esbuild bundler, Sysinternals Process Monitor.

---

## Environment / conventions (READ FIRST)

- **cargo is not on PATH.** Prefix every cargo command with:
  `export PATH="$HOME/.cargo/bin:$PATH";`
- **`client-app` is its OWN cargo workspace.** Build/test it with
  `--manifest-path crates/client-app/Cargo.toml` — NOT `-p` from the repo root.
- **NEVER run `cargo fmt --all`** (pre-existing rustfmt drift elsewhere).
- **UI commands** run from `crates/client-app/ui/`:
  - tests: `npm test`
  - typecheck: `npm run typecheck`
  - a single test file: `node --experimental-strip-types --test src/core/foo.test.ts`
- **Tauri v2 top-level scalar command args are camelCase in JS** (`{ fileId }`), but
  `settings:`/`req:` struct fields stay snake_case. The settings round-trip uses
  `call("set_settings", { settings })`.
- Commit after each task. Branch is `feat/webview-storage-in-folder` (already created).

---

## File map

**Rust (`crates/client-app/`):**
- `src/config.rs` — extend `SettingsConfig`: `appearance.frontend`, new `ui` + `playback` sections + normalization + tests. (Task 1)
- `src/layout.rs` — add `webview` to the created sub-dirs. (Task 2)
- `tauri.conf.json` — remove `app.windows` (window now created in Rust). (Task 3)
- `src/main.rs` — create the main window in Rust with `data_directory` + `initialization_script`; wipe `webview/` on exit. (Task 3)

**UI (`crates/client-app/ui/`):**
- `boot.js` — read injected `window.__MAXSECU_BOOT__.frontend` (localStorage fallback). (Task 4)
- `src/core/frontends.test.ts` — assert boot reads the injected global. (Task 4)
- `src/core/types.ts` + `src/core/settings.ts` — extend `Settings` + `DEFAULTS`. (Task 5)
- `src/core/frontends.ts` — store-backed `getFrontend`/`setFrontend`. (Task 6)
- `src/core/bundle-view.ts` + `src/components/bundle-screen.ts` + `src/components/bundle-screen.test.ts` — store-backed bundle-view. (Task 7)
- `src/components/video-player.ts` — restore/persist volume via settings. (Task 8)

**Audit (`tools/storage-audit/`):**
- `Analyze-Capture.ps1` + `RUNBOOK.md` — ProcMon capture + out-of-folder analyzer. (Task 9)

**Final:** full build + typecheck + test sweep. (Task 10)

---

### Task 1: Backend settings schema — skin, bundle-view, volume

**Files:**
- Modify: `crates/client-app/src/config.rs` (add fields/sections + `normalized_with_ram` clamps)
- Test: `crates/client-app/src/config.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `mod tests` in `config.rs`:

```rust
#[test]
fn appearance_frontend_defaults_and_normalizes() {
    let s = SettingsConfig::default();
    assert_eq!(s.appearance.frontend, "default");
    let mut bad = SettingsConfig::default();
    bad.appearance.frontend = "bogus".into();
    assert_eq!(bad.normalized().appearance.frontend, "default");
    for id in ["default", "pizza", "slot3"] {
        let mut ok = SettingsConfig::default();
        ok.appearance.frontend = id.into();
        assert_eq!(ok.normalized().appearance.frontend, id);
    }
}

#[test]
fn ui_bundle_view_defaults_and_normalizes() {
    let d = SettingsConfig::default();
    assert_eq!(d.ui.bundle_view, "gallery");
    let mut bad = SettingsConfig::default();
    bad.ui.bundle_view = "weird".into();
    assert_eq!(bad.normalized().ui.bundle_view, "gallery");
    let mut ok = SettingsConfig::default();
    ok.ui.bundle_view = "stacked".into();
    assert_eq!(ok.normalized().ui.bundle_view, "stacked");
}

#[test]
fn playback_defaults_and_volume_clamps() {
    let d = SettingsConfig::default();
    assert_eq!(d.playback.volume, 1.0);
    assert!(!d.playback.muted);
    let mut hi = SettingsConfig::default();
    hi.playback.volume = 5.0;
    assert_eq!(hi.normalized().playback.volume, 1.0);
    let mut lo = SettingsConfig::default();
    lo.playback.volume = -3.0;
    assert_eq!(lo.normalized().playback.volume, 0.0);
    let mut nan = SettingsConfig::default();
    nan.playback.volume = f32::NAN;
    assert_eq!(nan.normalized().playback.volume, 1.0);
}

#[test]
fn old_settings_file_without_new_sections_still_loads() {
    // A pre-migration file (no ui/playback/frontend) loads with defaults.
    let json = r#"{"appearance":{"theme":"light"}}"#;
    let s: SettingsConfig = serde_json::from_str(json).unwrap();
    let n = s.normalized();
    assert_eq!(n.appearance.theme, "light");
    assert_eq!(n.appearance.frontend, "default");
    assert_eq!(n.ui.bundle_view, "gallery");
    assert_eq!(n.playback.volume, 1.0);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml config:: 2>&1 | tail -20`
Expected: FAIL to compile — `appearance.frontend`, `ui`, `playback` do not exist yet.

- [ ] **Step 3: Add the fields + sections**

In `config.rs`, extend `AppearanceSettings`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppearanceSettings {
    /// "dark" (default) | "light". Applied via `<html data-theme>` in the UI.
    pub theme: String,
    /// Active visual skin: "default" | "pizza" | "slot3". Non-secret UI pref;
    /// the source of truth for the skin (was UI-local localStorage). Injected
    /// pre-paint by `main.rs` via `window.__MAXSECU_BOOT__.frontend`.
    #[serde(default = "default_frontend")]
    pub frontend: String,
}
impl Default for AppearanceSettings {
    fn default() -> Self {
        Self { theme: "dark".into(), frontend: default_frontend() }
    }
}
fn default_frontend() -> String { "default".into() }
```

Add two new section structs near the other `*Settings` structs:

```rust
/// Non-secret UI-shape preferences that used to live in browser localStorage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UiSettings {
    /// Bundle view mode: "gallery" (default) | "stacked".
    pub bundle_view: String,
}
impl Default for UiSettings {
    fn default() -> Self { Self { bundle_view: "gallery".into() } }
}

/// Player playback preferences (non-secret).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlaybackSettings {
    /// Player volume, 0.0..=1.0 (default 1.0).
    pub volume: f32,
    /// Player mute state (default false).
    pub muted: bool,
}
impl Default for PlaybackSettings {
    fn default() -> Self { Self { volume: 1.0, muted: false } }
}
```

Note: `PlaybackSettings` derives `PartialEq` only (not `Eq`) because `f32` is not
`Eq`. Therefore `SettingsConfig` must also drop `Eq` (keep `PartialEq`).

Extend `SettingsConfig` (remove `Eq` from its derive list, keep `PartialEq`):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SettingsConfig {
    #[serde(default)]
    pub a11y: A11ySettings,
    #[serde(default)]
    pub behavior: BehaviorSettings,
    #[serde(default)]
    pub performance: PerformanceSettings,
    #[serde(default)]
    pub connection: ConnectionSettings,
    #[serde(default)]
    pub appearance: AppearanceSettings,
    #[serde(default)]
    pub ui: UiSettings,
    #[serde(default)]
    pub playback: PlaybackSettings,
}
```

In `normalized_with_ram`, before `s` is returned, add:

```rust
    if !matches!(s.appearance.frontend.as_str(), "default" | "pizza" | "slot3") {
        s.appearance.frontend = "default".into();
    }
    if !matches!(s.ui.bundle_view.as_str(), "gallery" | "stacked") {
        s.ui.bundle_view = "gallery".into();
    }
    // Clamp volume into [0,1]; a NaN (from a hand-edited file) resets to 1.0.
    s.playback.volume = if s.playback.volume.is_nan() {
        1.0
    } else {
        s.playback.volume.clamp(0.0, 1.0)
    };
```

If any OTHER `derive(... Eq ...)` on a struct that now transitively contains
`SettingsConfig`/`PlaybackSettings` fails to compile, drop `Eq` there too (keep
`PartialEq`). Search: `grep -n "Eq" crates/client-app/src/config.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml config:: 2>&1 | tail -20`
Expected: PASS (all `config::tests` including the 4 new ones).

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/config.rs
git commit -m "feat(config): add skin/bundle-view/volume to SettingsConfig

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Add `webview` to the portable layout

**Files:**
- Modify: `crates/client-app/src/layout.rs` (both the create loop and the doc comment)
- Test: `crates/client-app/src/layout.rs` (inline test asserts the dir is created)

- [ ] **Step 1: Update the failing test**

In `layout.rs`'s `mod tests`, change BOTH sub-dir arrays in
`ensure_creates_all_subdirs_idempotently` to include `"webview"`:

```rust
        for sub in ["config", "keystore", "index", "cache", "logs", "staging", "webview"] {
            assert!(tmp.join(sub).is_dir(), "{sub} should exist");
        }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml layout:: 2>&1 | tail -15`
Expected: FAIL — `webview` dir not created.

- [ ] **Step 3: Add `webview` to the create loop**

In `ensure_portable_layout`, add `"webview"`:

```rust
    for sub in ["config", "keystore", "index", "cache", "logs", "staging", "webview"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
```

Update the module doc `text` block to list `webview/  (WebView2 user-data folder; wiped on exit)`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml layout:: 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/layout.rs
git commit -m "feat(layout): create <app_dir>/webview for the WebView2 data folder

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Create the window in Rust — data_directory, init-script, exit-wipe

This task has no unit test (Tauri window creation is not unit-testable). Verification is a
successful compile; runtime behavior is proven by the Task 9 audit.

**Files:**
- Modify: `crates/client-app/tauri.conf.json` (remove `app.windows`)
- Modify: `crates/client-app/src/main.rs` (create window in `.setup`, wipe on exit)

- [ ] **Step 1: Remove the config-declared window**

In `tauri.conf.json`, delete the `"windows": [...]` entry so `app` becomes:

```json
  "app": {
    "security": {
      "csp": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; media-src 'self' stream: http://stream.localhost https://stream.localhost",
      "dangerousDisableAssetCspModification": ["style-src"]
    }
  },
```

- [ ] **Step 2: Compute the webview dir + boot script and create the window in `.setup`**

In `main.rs`, BEFORE the `.manage(AppDir(app_dir))` line moves `app_dir`, capture what the
setup closure needs (place these right after `let pool_cap = ...;`, i.e. after `normalized`
is available and before the builder):

```rust
    // WebView2 user-data folder lives INSIDE the portable folder so localStorage,
    // cache, cookies, and GPU cache never escape <app_dir>. Wiped on exit.
    let webview_dir = app_dir.join("webview");
    // The persisted skin, injected pre-paint via an initialization script so boot.js
    // can apply it before first paint with no flash (settings.json is the source of truth).
    let boot_frontend = normalized.appearance.frontend.clone();
```

Add a `.setup(...)` call to the `tauri::Builder` chain (anywhere before `.build(...)`,
conventionally right after the last `.manage(...)`), and move the captured values in:

```rust
        .setup(move |app| {
            use tauri::{WebviewUrl, WebviewWindowBuilder};
            // Set the injected global BEFORE any page script (incl. boot.js) runs.
            let boot_script = format!(
                "window.__MAXSECU_BOOT__ = {{ frontend: {} }};",
                serde_json::to_string(&boot_frontend).unwrap_or_else(|_| "\"default\"".into())
            );
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("MaxSecu")
                .inner_size(1100.0, 720.0)
                .resizable(true)
                .maximized(true)
                .data_directory(webview_dir.clone())
                .initialization_script(boot_script)
                .build()?;
            Ok(())
        })
```

`serde_json` and `format!` are already available in the crate. `WebviewUrl::App("index.html")`
matches the previous config-driven default (the `build.frontendDist` bundle root).

- [ ] **Step 3: Wipe the webview dir on exit**

In the `app.run(|app_handle, event| match event { ... })` handler, inside the existing
`tauri::RunEvent::Exit => { ... }` arm, add (after the existing cache zeroize calls):

```rust
            // Wipe the WebView2 user-data folder so no browser artifacts persist
            // between runs. Best-effort — never block or panic shutdown.
            if let Some(dir) = app_handle.try_state::<AppDir>() {
                let _ = std::fs::remove_dir_all(dir.0.join("webview"));
            }
```

`AppDir` is already imported at the top of `main.rs`
(`use maxsecu_client_app::commands::auth::{AppDir, ConnectLock, Session};`). Confirm its
`.0` field is the `PathBuf` (it is — `AppDir(app_dir)` is constructed from a `PathBuf`).

- [ ] **Step 4: Verify it compiles**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo build --manifest-path crates/client-app/Cargo.toml 2>&1 | tail -25`
Expected: builds successfully (warnings OK). If `AppDir.0` is private, use the crate's
public accessor instead; check `grep -n "struct AppDir" crates/client-app/src/commands/auth.rs`.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/tauri.conf.json crates/client-app/src/main.rs
git commit -m "feat(app): redirect WebView2 data dir into <app_dir>/webview + wipe on exit

Create the main window in Rust so its data_directory points inside the portable
folder; inject the persisted skin pre-paint via an initialization script.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: boot.js reads the injected skin (localStorage fallback)

**Files:**
- Modify: `crates/client-app/ui/boot.js`
- Test: `crates/client-app/ui/src/core/frontends.test.ts`

- [ ] **Step 1: Update the failing test**

In `frontends.test.ts`, replace the last test (`"boot.js applies the persisted frontend
pre-paint..."`) with:

```ts
test("boot.js prefers the injected __MAXSECU_BOOT__ skin, falls back to localStorage, mirrors the map", () => {
  assert.match(boot, /__MAXSECU_BOOT__/);
  assert.match(boot, /maxsecu\.frontend/); // legacy fallback still present
  assert.match(boot, /styles\.pizza\.css/);
  assert.match(boot, /styles\.slot3\.css/);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/core/frontends.test.ts 2>&1 | tail -15`
Expected: FAIL — `boot.js` has no `__MAXSECU_BOOT__`.

- [ ] **Step 3: Update boot.js**

Replace the body of `boot.js` with:

```js
/* Apply the persisted frontend before first paint (no flash). Runs as a same-origin
   classic script — the app CSP (default-src 'self', no script-src) blocks INLINE JS,
   so this must stay an external file. The skin id is injected by the Rust host via an
   initialization script (window.__MAXSECU_BOOT__.frontend, sourced from settings.json).
   A legacy localStorage value is the one-version migration fallback.
   Mirrors STYLESHEETS in src/core/frontends.ts. */
(function () {
  try {
    var boot = window.__MAXSECU_BOOT__ || {};
    var f = boot.frontend;
    if (!f) {
      try { f = localStorage.getItem("maxsecu.frontend"); } catch (e) { /* unavailable */ }
    }
    var map = { "default": "styles.css", "pizza": "styles.pizza.css", "slot3": "styles.slot3.css" };
    if (f && map[f]) {
      document.documentElement.setAttribute("data-frontend", f);
      var l = document.getElementById("frontend-css");
      if (l) l.setAttribute("href", map[f]);
    }
  } catch (e) { /* keep default */ }
})();
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/core/frontends.test.ts 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/boot.js crates/client-app/ui/src/core/frontends.test.ts
git commit -m "feat(ui): boot.js applies injected skin (localStorage fallback)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Extend the TS Settings type + DEFAULTS

**Files:**
- Modify: `crates/client-app/ui/src/core/types.ts` (the `Settings` interface)
- Modify: `crates/client-app/ui/src/core/settings.ts` (the `DEFAULTS` const)

No new test file — the shape is exercised by Tasks 6–8. Verified by `npm run typecheck`.

- [ ] **Step 1: Extend the `Settings` interface**

In `types.ts`, update the `Settings` interface: change `appearance` and add `ui` + `playback`:

```ts
  connection: { route_mode: RouteMode };
  appearance: { theme: "dark" | "light"; frontend: "default" | "pizza" | "slot3" };
  // Non-secret UI-shape prefs migrated out of browser localStorage into settings.json.
  ui: { bundle_view: "gallery" | "stacked" };
  playback: { volume: number; muted: boolean };
```

(Widen `theme` to `"dark" | "light"` — the backend already supports both; the old
`"dark"`-only literal was too narrow.)

- [ ] **Step 2: Extend `DEFAULTS`**

In `settings.ts`, update `DEFAULTS`:

```ts
const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { media_cache_cap_mb: 1024, thumb_cache_cap_mb: 256, feed_concurrency: 4, transcode_threads: 4, decode_threads: 4, cache_location: "Memory" },
  connection: { route_mode: "prefer-server" },
  appearance: { theme: "dark", frontend: "default" },
  ui: { bundle_view: "gallery" },
  playback: { volume: 1.0, muted: false },
};
```

- [ ] **Step 3: Verify typecheck passes**

Run: `cd crates/client-app/ui && npm run typecheck 2>&1 | tail -20`
Expected: no errors. (There may be pre-existing errors unrelated to this change; confirm
none reference `types.ts`/`settings.ts` newly.)

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/ui/src/core/types.ts crates/client-app/ui/src/core/settings.ts
git commit -m "feat(ui): add frontend/ui.bundle_view/playback to Settings type + defaults

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Store-backed skin (`frontends.ts`)

**Files:**
- Modify: `crates/client-app/ui/src/core/frontends.ts` (`getFrontend`/`setFrontend`)
- Test: `crates/client-app/ui/src/core/frontends.test.ts` (already updated in Task 4; no new asserts needed — these functions touch the store/DOM which node:test doesn't provide, so they stay integration-covered)

- [ ] **Step 1: Rewrite `getFrontend`/`setFrontend` to use the settings store**

In `frontends.ts`, replace the `FRONTEND_KEY` constant usage and the two functions.
Remove `const FRONTEND_KEY = "maxsecu.frontend";` and replace `getFrontend`/`setFrontend`:

```ts
import { settingsStore } from "./settings-store-instance.ts";
import { updateSettings } from "./settings.ts";

// ... keep normalizeFrontend / frontendStylesheet / applyFrontend / refreshFrontendDeco ...

export function getFrontend(): FrontendId {
  return normalizeFrontend(settingsStore.get().appearance.frontend);
}

export function setFrontend(value: unknown): FrontendId {
  const id = normalizeFrontend(value);
  applyFrontend(id); // apply immediately (sync, responsive)
  // Persist to settings.json (source of truth); fire-and-forget, never blocks the UI.
  void updateSettings({ appearance: { ...settingsStore.get().appearance, frontend: id } }).catch(() => {});
  return id;
}
```

> **Circular-import guard:** `settings.ts` imports `applyFrontend` from `frontends.ts`,
> and `frontends.ts` now needs `settingsStore` + `updateSettings`. To avoid a cycle,
> the shared `settingsStore` instance is exported from a tiny leaf module. Create
> `crates/client-app/ui/src/core/settings-store-instance.ts`:
>
> ```ts
> import { SettingsStore } from "./settings-store.ts";
> import type { Settings } from "./types.ts";
>
> const DEFAULTS: Settings = {
>   a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
>   behavior: { confirm_destructive: false },
>   performance: { media_cache_cap_mb: 1024, thumb_cache_cap_mb: 256, feed_concurrency: 4, transcode_threads: 4, decode_threads: 4, cache_location: "Memory" },
>   connection: { route_mode: "prefer-server" },
>   appearance: { theme: "dark", frontend: "default" },
>   ui: { bundle_view: "gallery" },
>   playback: { volume: 1.0, muted: false },
> };
>
> export const settingsStore = new SettingsStore(DEFAULTS);
> ```
>
> Then in `settings.ts`, DELETE its local `DEFAULTS` + `export const settingsStore = ...`
> and instead `export { settingsStore } from "./settings-store-instance.ts";` (re-export
> so existing `import { settingsStore } from "./settings.ts"` call sites keep working).
> `updateSettings` still lives in `settings.ts` (it imports `call`); `frontends.ts`
> importing `updateSettings` from `settings.ts` is a one-way edge (settings.ts →
> frontends.ts for `applyFrontend` only, frontends.ts → settings.ts for `updateSettings`
> only) — with the store in the leaf module there is no initialization cycle because
> neither top-level body calls the other at import time.

- [ ] **Step 2: Verify no remaining `maxsecu.frontend` in source (except boot.js fallback)**

Run: `cd crates/client-app/ui && grep -rn "maxsecu.frontend" src` 
Expected: no matches in `src/` (boot.js keeps it as the legacy fallback — that's fine).

- [ ] **Step 3: Run the affected tests + typecheck**

Run: `cd crates/client-app/ui && npm run typecheck 2>&1 | tail -20 && node --experimental-strip-types --test src/core/frontends.test.ts src/components/settings-screen.test.ts 2>&1 | tail -20`
Expected: typecheck clean; both test files PASS. If `settings-screen.test.ts` asserted
localStorage behavior for the skin, update those asserts to not reference localStorage
(the selector still round-trips via `getFrontend`/`setFrontend`).

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/ui/src/core/frontends.ts crates/client-app/ui/src/core/settings.ts crates/client-app/ui/src/core/settings-store-instance.ts crates/client-app/ui/src/components/settings-screen.test.ts
git commit -m "feat(ui): source the skin from settings.json instead of localStorage

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Store-backed bundle-view mode

**Files:**
- Modify: `crates/client-app/ui/src/core/bundle-view.ts`
- Modify: `crates/client-app/ui/src/components/bundle-screen.ts` (imports unchanged; behavior via store)
- Test: `crates/client-app/ui/src/components/bundle-screen.test.ts`

- [ ] **Step 1: Rewrite the bundle-view test to use the store, not localStorage**

Replace the localStorage-faking tests in `bundle-screen.test.ts` with store-based ones.
Keep the pure-normalizer test. New content for the persistence tests:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeBundleViewMode, readBundleViewMode, writeBundleViewMode } from "../core/bundle-view.ts";
import { settingsStore } from "../core/settings-store-instance.ts";

test("normalizeBundleViewMode coerces to a valid mode (default gallery)", () => {
  assert.equal(normalizeBundleViewMode("stacked"), "stacked");
  assert.equal(normalizeBundleViewMode("gallery"), "gallery");
  assert.equal(normalizeBundleViewMode("nope"), "gallery");
  assert.equal(normalizeBundleViewMode(null), "gallery");
  assert.equal(normalizeBundleViewMode(undefined), "gallery");
});

test("read reflects the settings store; write patches it locally", () => {
  settingsStore.patchLocal({ ui: { bundle_view: "stacked" } });
  assert.equal(readBundleViewMode(), "stacked");
  writeBundleViewMode("gallery");
  assert.equal(settingsStore.get().ui.bundle_view, "gallery");
  assert.equal(readBundleViewMode(), "gallery");
});
```

> Note: `writeBundleViewMode` calls `updateSettings`, which calls the Tauri `call` RPC.
> Under node:test there is no Tauri host, so `call` rejects — that's why `writeBundleViewMode`
> patches the store LOCALLY first (synchronously) and fires the persist as a caught,
> fire-and-forget promise (see Step 2). The test asserts the synchronous local patch.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/components/bundle-screen.test.ts 2>&1 | tail -20`
Expected: FAIL — `bundle-view.ts` still uses localStorage; `readBundleViewMode` won't see the store.

- [ ] **Step 3: Rewrite `bundle-view.ts` to use the store**

Replace `readBundleViewMode`/`writeBundleViewMode` (keep `BundleViewMode` +
`normalizeBundleViewMode`; drop `BUNDLE_VIEW_MODE_KEY`):

```ts
import { settingsStore } from "./settings-store-instance.ts";
import { updateSettings } from "./settings.ts";

export type BundleViewMode = "gallery" | "stacked";

/** Coerce any stored/candidate value to a valid mode; default "gallery". */
export function normalizeBundleViewMode(v: string | null | undefined): BundleViewMode {
  return v === "stacked" ? "stacked" : "gallery";
}

/** Read the persisted mode from the settings store (default "gallery"). */
export function readBundleViewMode(): BundleViewMode {
  return normalizeBundleViewMode(settingsStore.get().ui.bundle_view);
}

/** Persist the chosen mode to settings.json. Patches the store locally (sync) so the
 *  UI is responsive, then fires the backend persist fire-and-forget (never blocks the
 *  screen; a UI preference that can't persist must not break rendering). */
export function writeBundleViewMode(mode: BundleViewMode): void {
  settingsStore.patchLocal({ ui: { bundle_view: mode } });
  void updateSettings({ ui: { bundle_view: mode } }).catch(() => {});
}
```

`bundle-screen.ts` needs no change — it imports `readBundleViewMode`/`writeBundleViewMode`
and calls them exactly as before.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/components/bundle-screen.test.ts 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/bundle-view.ts crates/client-app/ui/src/components/bundle-screen.test.ts
git commit -m "feat(ui): source bundle-view mode from settings.json instead of localStorage

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Restore + persist player volume via settings

**Files:**
- Modify: `crates/client-app/ui/src/components/video-player.ts`
- Test: `crates/client-app/ui/src/components/video-player.test.ts` (add a pure-helper test)

The volume restore/persist logic itself runs against a live `<video>` (not available in
node:test), so extract a **pure debounce-free apply/read helper** and test that; the DOM
wiring is thin glue verified by the audit + manual smoke.

- [ ] **Step 1: Add a pure helper + its failing test**

Add to `video-player.ts` (module scope, exported):

```ts
import { settingsStore } from "../core/settings-store.ts";
import { updateSettings } from "../core/settings.ts";

// Pure: clamp a raw volume into [0,1] (NaN → 1). Mirrors the backend clamp so the
// UI and settings.json agree.
export function clampVolume(v: number): number {
  if (Number.isNaN(v)) return 1;
  return Math.min(1, Math.max(0, v));
}
```

Wait — `video-player.ts` imports `settingsStore` from `../core/settings.ts` (the re-export),
NOT `settings-store.ts` directly. Use: `import { settingsStore } from "../core/settings.ts";`

Add to `video-player.test.ts`:

```ts
import { clampVolume } from "./video-player.ts";
import { test } from "node:test";
import assert from "node:assert/strict";

test("clampVolume constrains volume to [0,1] and maps NaN to 1", () => {
  assert.equal(clampVolume(0.5), 0.5);
  assert.equal(clampVolume(-2), 0);
  assert.equal(clampVolume(5), 1);
  assert.equal(clampVolume(NaN), 1);
});
```

(If `video-player.test.ts` already has imports for `test`/`assert`, don't duplicate them.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/components/video-player.test.ts 2>&1 | tail -15`
Expected: FAIL — `clampVolume` not exported.

- [ ] **Step 3: Wire restore + persist into the player**

In `connectNative()`, after the `const video = this.querySelector("video") as HTMLVideoElement;`
line, restore from settings and add a debounced persist:

```ts
    // Restore persisted volume/mute (settings.json is the source of truth). Applied
    // after Media Chrome mounts so ours wins over its own localStorage copy.
    const pb = settingsStore.get().playback;
    video.volume = clampVolume(pb.volume);
    video.muted = pb.muted;
    let volTimer: ReturnType<typeof setTimeout> | undefined;
    video.addEventListener("volumechange", () => {
      const volume = clampVolume(video.volume);
      const muted = video.muted;
      settingsStore.patchLocal({ playback: { volume, muted } });
      if (volTimer) clearTimeout(volTimer);
      volTimer = setTimeout(() => {
        void updateSettings({ playback: { volume, muted } }).catch(() => {});
      }, 400);
    });
```

- [ ] **Step 4: Run the test + typecheck**

Run: `cd crates/client-app/ui && npm run typecheck 2>&1 | tail -15 && node --experimental-strip-types --test src/components/video-player.test.ts 2>&1 | tail -15`
Expected: typecheck clean; test PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/components/video-player.ts crates/client-app/ui/src/components/video-player.test.ts
git commit -m "feat(ui): restore+persist player volume via settings.json

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: ProcMon audit tooling

**Files:**
- Create: `tools/storage-audit/Analyze-Capture.ps1`
- Create: `tools/storage-audit/RUNBOOK.md`

No unit test (it analyzes an external CSV). Verified by a self-check run in Step 3.

- [ ] **Step 1: Write the analyzer**

Create `tools/storage-audit/Analyze-Capture.ps1`:

```powershell
<#
.SYNOPSIS
  Flag any client write that lands OUTSIDE the portable <app_dir> folder.
.DESCRIPTION
  Parses a Process Monitor CSV export and reports successful write/create/registry
  operations by MaxSecu.exe and its msedgewebview2.exe children whose target path is
  not under -AppDir. Prints a PASS/FAIL summary and the annotated residual list.
.EXAMPLE
  ./Analyze-Capture.ps1 -Csv capture.csv -AppDir 'D:\MaxSecuClient'
#>
param(
  [Parameter(Mandatory)] [string]$Csv,
  [Parameter(Mandatory)] [string]$AppDir
)

$app = (Resolve-Path $AppDir).Path.TrimEnd('\').ToLowerInvariant()
$procNames = @('maxsecu.exe','msedgewebview2.exe')
$writeOps  = @(
  'WriteFile','SetRenameInformationFile','SetEndOfFileInformationFile',
  'SetAllocationInformationFile','RegSetValue','RegCreateKey'
)

$rows = Import-Csv -Path $Csv
$flagged = foreach ($r in $rows) {
  $proc = ($r.'Process Name').ToLowerInvariant()
  if ($procNames -notcontains $proc) { continue }
  if ($r.Result -ne 'SUCCESS') { continue }
  $op = $r.Operation
  # CreateFile counts only when it actually creates/writes (Detail names the disposition).
  $isWrite = ($writeOps -contains $op) -or
             ($op -eq 'CreateFile' -and $r.Detail -match 'Disposition:\s*(Create|Overwrite|Supersede|OpenIf|OverwriteIf)')
  if (-not $isWrite) { continue }
  $path = $r.Path
  if ([string]::IsNullOrEmpty($path)) { continue }
  $isRegistry = $path -like 'HK*'
  $lower = $path.ToLowerInvariant()
  if (-not $isRegistry -and $lower.StartsWith($app)) { continue }  # inside the folder: OK
  [pscustomobject]@{ Kind = if ($isRegistry) {'REGISTRY'} else {'FILE'}; Process = $proc; Operation = $op; Path = $path }
}

$fileHits = @($flagged | Where-Object Kind -eq 'FILE')
$regHits  = @($flagged | Where-Object Kind -eq 'REGISTRY')

"== Out-of-folder FILE writes (must be zero for PASS) =="
if ($fileHits.Count -eq 0) { "  (none)" } else {
  $fileHits | Group-Object Path | Sort-Object Count -Descending |
    ForEach-Object { "  [{0,4}x] {1}" -f $_.Count, $_.Name }
}
""
"== Registry writes (review; shared-WebView2-runtime bookkeeping is expected) =="
if ($regHits.Count -eq 0) { "  (none)" } else {
  $regHits | Group-Object Path | Sort-Object Count -Descending |
    ForEach-Object { "  [{0,4}x] {1}" -f $_.Count, $_.Name }
}
""
if ($fileHits.Count -eq 0) {
  "RESULT: PASS — no client file write landed outside $AppDir."
  exit 0
} else {
  "RESULT: FAIL — $($fileHits.Count) file write(s) landed outside $AppDir (see above)."
  exit 1
}
```

- [ ] **Step 2: Write the runbook**

Create `tools/storage-audit/RUNBOOK.md`:

```markdown
# Storage audit — prove the client writes nothing outside its folder

Requires Sysinternals Process Monitor (`Procmon.exe`) and admin rights.

## 1. Start the capture (admin PowerShell)
```
Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile capture.pml
```

## 2. Exercise EVERY persistence-relevant flow in the built client
Launch `MaxSecuClient.exe` from its portable folder, then:
- register / first-run (if applicable), unlock/login
- change the theme; change the skin; change the bundle view (gallery ↔ stacked)
- play a video and change the volume + toggle mute
- upload a post; download a file
- log out, then fully exit the app (so the exit-wipe runs)

## 3. Stop + export
```
Procmon.exe /Terminate
Procmon.exe /OpenLog capture.pml /SaveAs capture.csv
```

## 4. Analyze
```
./Analyze-Capture.ps1 -Csv capture.csv -AppDir '<path-to-portable-folder>'
```
PASS = no FILE write outside the folder. The REGISTRY section is expected to list a
few shared-WebView2-runtime keys under HKCU (runtime bookkeeping, not user data);
review that they are not app data.
```

- [ ] **Step 3: Self-check the analyzer against a synthetic CSV**

Run (PowerShell):
```
cd tools/storage-audit
@'
"Time of Day","Process Name","PID","Operation","Path","Result","Detail"
"1","MaxSecu.exe","1","WriteFile","D:\App\config\settings.json","SUCCESS","Length: 20"
"2","msedgewebview2.exe","2","WriteFile","C:\Users\me\AppData\Local\org.maxsecu.client\EBWebView\x","SUCCESS","Length: 5"
"3","msedgewebview2.exe","2","RegSetValue","HKCU\Software\Microsoft\Edge\y","SUCCESS",""
'@ | Set-Content -Encoding utf8 sample.csv
./Analyze-Capture.ps1 -Csv sample.csv -AppDir 'D:\App'
```
Expected: the EBWebView write is FILE-flagged (outside `D:\App`) → `RESULT: FAIL`; the
settings.json write is NOT flagged; the Reg write shows under REGISTRY. Then delete
`sample.csv`.

- [ ] **Step 4: Commit**

```bash
git add tools/storage-audit/Analyze-Capture.ps1 tools/storage-audit/RUNBOOK.md
git commit -m "feat(tools): ProcMon storage audit (flag writes outside <app_dir>)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Full build + test sweep

**Files:** none (verification only)

- [ ] **Step 1: Rust build + tests**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cargo test --manifest-path crates/client-app/Cargo.toml 2>&1 | tail -30`
Expected: all tests pass (no `cargo fmt`).

- [ ] **Step 2: UI typecheck + full test suite**

Run: `cd crates/client-app/ui && npm run typecheck 2>&1 | tail -20 && npm test 2>&1 | tail -30`
Expected: typecheck clean; all `node:test` suites pass.

- [ ] **Step 3: UI bundle build (ensures esbuild + copy-assets still succeed)**

Run: `cd crates/client-app/ui && npm run build 2>&1 | tail -15`
Expected: `dist/main.js` written, assets copied, no errors.

- [ ] **Step 4: Report**

Summarize: tests green, build green, and remind the user to run the Task 9 audit runbook
against a real build to get the empirical PASS (the windowed app is user-driven).

---

## Self-review notes

- **Spec coverage:** Part 1 (redirect + wipe) → Tasks 2,3. Part 2 (migrate prefs) →
  Tasks 1,4,5,6,7,8. Part 3 (audit) → Task 9. Pre-paint no-flash → Tasks 3 (init-script) + 4
  (boot.js). Success criteria 1–5 → covered; empirical criterion 1 completed by the user via
  Task 9 runbook (windowed GUI is user-driven, per the chosen audit approach).
- **Type consistency:** `settingsStore` is the single instance exported from
  `settings-store-instance.ts` and re-exported by `settings.ts`; `updateSettings` stays in
  `settings.ts`; `Settings.ui.bundle_view` / `Settings.playback.{volume,muted}` /
  `Settings.appearance.frontend` match the Rust serde field names (`ui`, `playback`,
  `bundle_view`, `frontend`) exactly.
- **Known caveat (unchanged from spec):** the shared WebView2 runtime may write a few HKCU
  keys regardless; the audit lists them under REGISTRY for review rather than failing.
```
