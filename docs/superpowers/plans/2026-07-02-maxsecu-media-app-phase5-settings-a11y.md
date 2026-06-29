# MaxSecu Media App — Phase 5: Settings + Accessibility — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the Settings screen + ⚡ Quick-settings popover (Account, Connection, Performance/memory, Behavior, Accessibility, Privacy), persisted to `<dir>/config/settings.json`; apply the accessibility options (reduced-motion, high-contrast, text-size) live across the UI; provide the account actions that don't need a ceremony (change password, export the portable keystore); and add an automated accessibility check to CI plus the documented manual pass.

**Architecture:** Phase 5 has **no server interaction** — settings are local client-app config + UI, and the account actions reuse the existing `client-core::keyblob` (the at-rest sealed identity). No new server crypto, no new endpoints, no `client-core` change. `change_password` re-seals the local key blob under a new password (unlock-with-old → reseal-with-new, atomic replace); `export_keystore` copies the already-ciphertext blob to a user-chosen path (the portable backup / recovery path). Accessibility settings are applied by setting `data-*` attributes on the document root that a small stylesheet keys on (reduced-motion also respects the OS `prefers-reduced-motion`). The UI stays outside the TCB — settings are non-secret preferences; the only sensitive action is `change_password`, which takes the old+new passwords (zeroized), re-seals in the client-app, and never returns key material.

**Tech Stack:** Rust (Tauri commands, `client-core::keyblob` reseal, `serde`/`serde_json` config), vanilla TS + Web Components, the Node built-in test runner (`node --test`) for the a11y structural check. No new Rust deps; no bundled-runtime UI deps.

---

## Backend facts this plan is grounded in (read before coding)

- **Config pattern:** `crates/client-app/src/config.rs` — `ConnectionConfig { server, use_tor, auto_connect }` with `load(dir)` (read `<dir>/config/connection.json`, default on miss) / `save(dir)` (create `config/`, write pretty JSON). Mirror this for `SettingsConfig` → `<dir>/config/settings.json`. The test helper `n()` (nanos) is in the config tests module.
- **Keystore:** `crates/client-app/src/keystore.rs` — `keystore_path(dir)` = `<dir>/keystore/local_key_blob`; `exists(dir)`; `unlock(dir, password) -> Result<Identity, UiError>` (reads the blob, `keyblob::unlock`); `seal_identity(dir, password, &id)` (refuses overwrite); `create`. `password::check(password)` is the strength policy.
- **keyblob (client-core):** `crates/client-core/src/keyblob.rs` — `seal(password, &Identity, Argon2Params) -> Result<Vec<u8>>`, `unlock(password, &[u8]) -> Result<Identity>`, and **`reseal(...)`** (line 162 — the password-change primitive, DESIGN §9.5; READ its exact signature: likely `reseal(old_password, new_password, blob, params)` or `reseal(blob, old, new, params)` → new blob). `ARGON2_DESKTOP_TARGET` is the profile (`maxsecu_client_core::ARGON2_DESKTOP_TARGET`).
- **UI build/test:** `crates/client-app/ui/package.json` — `build` = `esbuild src/main.ts --bundle … && copy index.html`; `test` = `node --experimental-strip-types --test src/core/store.test.ts`; `typecheck` = `tsc --noEmit`. devDeps pinned: @tauri-apps/api 2.1.1, @types/node 20.14.2, esbuild 0.21.5, typescript 5.4.5. **The components import `@tauri-apps/api` (via core/rpc.ts), so they cannot be instantiated in a plain Node test without a Tauri mock + DOM** — the a11y CI check is therefore a **structural source lint** (Task 9), not a full axe-in-jsdom render (deferred — needs a Tauri-API mock + jsdom harness).
- **UI styling:** the components are currently unstyled; `index.html` is copied verbatim to `dist/`. Accessibility styling is added as a small `ui/styles.css` copied by the build and linked from `index.html`, keyed on `data-*` attributes on `<html>`.
- **Reuse from Phases 1–4:** `commands::auth::{AppDir, Session}`; `error::UiError`; `state.rs` event names; `core/{rpc,router,types,serial}.ts`; `app-shell.ts`; the `zeroize::Zeroizing` password-scrubbing idiom (see `commands/auth.rs::unlock_keystore`).

## Environment (tell every subagent)

- **cargo is NOT on the tool PATH.** Prefix: bash `export PATH="$HOME/.cargo/bin:$PATH"; ` / PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; `. Rust 1.96 MSVC.
- **No PostgreSQL** — `MAXSECU_PG_OPTIONAL=1` for the workspace test (Phase 5 adds no server tests, but the gate still runs the whole workspace).
- **Tauri GUI not available** — verify via `cargo build`/`tsc`/`npm run build`/`npm run test`/unit tests only.
- **fmt:** client-app + ui kept clean (`cargo fmt -p maxsecu-client-app -- --check`); client-core/server pre-existing drift OUT OF SCOPE (never `cargo fmt --all`; Phase 5 should not touch client-core).
- **clippy:** `cargo clippy -p maxsecu-client-app --all-targets -- -D warnings`, no blanket `#[allow]`.
- **deny/audit:** no new Rust deps expected. If the a11y lint needs an npm devDep, prefer ZERO new deps (a hand-rolled source scan); only add a pinned devDep if genuinely required.
- **Secrets:** passwords crossing the command boundary MUST be wrapped in `zeroize::Zeroizing` and never logged/returned. `change_password` returns `()`; `export_keystore` writes ciphertext only.

## Security model for Phase 5 (honor exactly)

- **Settings are non-secret preferences** — `settings.json` holds no secret (no passwords, no keys). Safe to persist in cleartext.
- **`change_password`** unlocks the blob with the old password and re-seals under the new one in the client-app TCB, then atomically replaces the blob file. Both passwords are `Zeroizing`. A wrong old password fails closed (`unauthorized`); a weak new password fails closed (`weak_password`) BEFORE the blob is touched. The identity never crosses the seam.
- **`export_keystore`** copies the **already-Argon2id-sealed** `local_key_blob` (ciphertext) to a user-chosen path — it is the portable backup. It never decrypts; no plaintext/key material is written. A warning is surfaced in the UI (the blob is only as safe as the password).
- **Accessibility CSS** keys on `data-*` attributes only; no untrusted data influences styles. No `innerHTML` interpolation.

---

## File structure

```
crates/client-app/src/
  config.rs        MODIFY — SettingsConfig { a11y, behavior, performance, connection } + load/save + clamps.
  keystore.rs      MODIFY — change_password(dir, old, new) (reseal + atomic replace); export_keystore(dir, dest).
  dto.rs           MODIFY — SettingsDto (mirrors SettingsConfig), ChangePasswordRequest, ExportKeystoreRequest.
  commands/settings.rs  NEW — get_settings, set_settings, change_password, export_keystore.
  commands/mod.rs  MODIFY — pub mod settings;
  main.rs          MODIFY — register the new commands.
  ui/src/core/types.ts         MODIFY — Settings TS type.
  ui/src/core/settings.ts      NEW — applySettings(s) sets data-* on <html>; load-on-boot helper.
  ui/styles.css                NEW — a11y rules keyed on data-reduced-motion/high-contrast/text-size.
  ui/index.html                MODIFY — <link rel="stylesheet" href="styles.css">.
  ui/package.json              MODIFY — build copies styles.css to dist/; add the a11y test script.
  ui/src/components/settings-screen.ts  NEW — the Settings screen.
  ui/src/components/quick-settings.ts   NEW — the ⚡ Quick-settings popover.
  ui/src/components/app-shell.ts        MODIFY — Settings nav → <settings-screen>; mount <quick-settings>; apply settings on boot.
  ui/src/core/router.ts                 MODIFY — add "settings" route.
  ui/src/a11y.test.ts          NEW — structural a11y lint over the component sources (node --test).
docs/
  security-review-phase5-mediaapp.md    NEW — Phase-5 sign-off.
```

---

## Task 1: `SettingsConfig` (load/save + clamps)

**Files:** Modify `crates/client-app/src/config.rs`.

- [ ] **Step 1: failing test** — add to the config tests module (reuse `n()`):

```rust
    #[test]
    fn settings_roundtrip_and_defaults_and_clamp() {
        let dir = std::env::temp_dir().join(format!("mxset-{}", n()));
        std::fs::create_dir_all(&dir).unwrap();
        // Missing → sane defaults.
        let d = SettingsConfig::load(&dir);
        assert!(!d.a11y.reduced_motion && !d.a11y.high_contrast);
        assert_eq!(d.a11y.text_size, "normal");
        assert_eq!(d.performance.ram_cache_cap_mb, 256);
        // Round-trip.
        let mut s = SettingsConfig::default();
        s.a11y.reduced_motion = true;
        s.a11y.text_size = "large".into();
        s.performance.ram_cache_cap_mb = 1024;
        s.save(&dir).unwrap();
        assert_eq!(SettingsConfig::load(&dir), s);
        // Clamp on save+load: an out-of-range cap and bad text_size are normalized.
        let mut bad = SettingsConfig::default();
        bad.performance.ram_cache_cap_mb = 99_999_999;
        bad.a11y.text_size = "huge".into();
        let norm = bad.normalized();
        assert!(norm.performance.ram_cache_cap_mb <= 4096);
        assert_eq!(norm.a11y.text_size, "normal");
        let _ = std::fs::remove_dir_all(&dir);
    }
```

- [ ] **Step 2: implement** in `config.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct A11ySettings { pub reduced_motion: bool, pub high_contrast: bool, pub text_size: String }
impl Default for A11ySettings { fn default() -> Self { Self { reduced_motion: false, high_contrast: false, text_size: "normal".into() } } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BehaviorSettings { pub confirm_destructive: bool }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PerformanceSettings { pub ram_cache_cap_mb: u32 }
impl Default for PerformanceSettings { fn default() -> Self { Self { ram_cache_cap_mb: 256 } } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConnectionSettings { pub use_tor: bool }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SettingsConfig {
    #[serde(default)] pub a11y: A11ySettings,
    #[serde(default)] pub behavior: BehaviorSettings,
    #[serde(default)] pub performance: PerformanceSettings,
    #[serde(default)] pub connection: ConnectionSettings,
}

impl SettingsConfig {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join("config").join("settings.json"))
            .ok().and_then(|b| serde_json::from_slice(&b).ok())
            .map(|s: SettingsConfig| s.normalized())
            .unwrap_or_default()
    }
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let p = dir.join("config");
        std::fs::create_dir_all(&p)?;
        std::fs::write(p.join("settings.json"), serde_json::to_vec_pretty(&self.normalized()).unwrap())
    }
    /// Clamp/normalize untrusted values (a hand-edited file or a UI bug): cap the
    /// RAM cache and constrain text_size to the known set.
    pub fn normalized(&self) -> SettingsConfig {
        let mut s = self.clone();
        s.performance.ram_cache_cap_mb = s.performance.ram_cache_cap_mb.clamp(16, 4096);
        if !matches!(s.a11y.text_size.as_str(), "normal" | "large" | "larger") {
            s.a11y.text_size = "normal".into();
        }
        s
    }
}
```

(`A11ySettings`/`PerformanceSettings` need a manual `Default` because of the non-default field values; the others derive it. `#[serde(default)]` on each section means an older/partial settings.json still loads.)

- [ ] **Step 3:** `cargo test -p maxsecu-client-app config::` ; build ; fmt/clippy clean. Commit `feat(client-app): SettingsConfig (settings.json load/save + clamps)`.

---

## Task 2: `get_settings` / `set_settings` commands

**Files:** Create `crates/client-app/src/commands/settings.rs`; Modify `dto.rs`, `commands/mod.rs`, `main.rs`.

- [ ] **Step 1: DTO** in `dto.rs` — `SettingsDto` mirroring `SettingsConfig` (or reuse `SettingsConfig` directly as the DTO since it's `Serialize`+`Deserialize` and non-secret — PREFER reusing `SettingsConfig` as the command's request/response type to avoid a parallel type; if you reuse it, no new DTO needed — note this in the report).

- [ ] **Step 2: commands** — `crates/client-app/src/commands/settings.rs`:

```rust
//! Settings + account-action commands. Settings are non-secret local preferences
//! persisted to <dir>/config/settings.json. The account actions (change_password /
//! export_keystore) reuse the at-rest key blob in the TCB; no key material crosses.
use tauri::State;
use crate::commands::auth::AppDir;
use crate::config::SettingsConfig;
use crate::error::UiError;

#[tauri::command]
pub async fn get_settings(dir: State<'_, AppDir>) -> Result<SettingsConfig, UiError> {
    Ok(SettingsConfig::load(&dir.0))
}

#[tauri::command]
pub async fn set_settings(settings: SettingsConfig, dir: State<'_, AppDir>) -> Result<SettingsConfig, UiError> {
    let norm = settings.normalized();
    norm.save(&dir.0).map_err(|_| UiError::new("settings_failed", "Could not save settings."))?;
    Ok(norm) // return the normalized value so the UI reflects any clamping
}
```

- [ ] **Step 3:** `pub mod settings;` in commands/mod.rs; register `get_settings`/`set_settings` in main.rs. Build/test; fmt/clippy clean. Commit `feat(client-app): get_settings/set_settings commands`.

---

## Task 3: `keystore::change_password` (reseal) + `export_keystore`

**Files:** Modify `crates/client-app/src/keystore.rs`.

- [ ] **Step 1: failing test** — add to keystore tests:

```rust
    #[test]
    fn change_password_reseals_blob() {
        let dir = tempdir();
        let old = "correct horse battery staple 9!";
        let id = create(&dir, old).unwrap();
        let want = id.sig_pub_bytes();
        change_password(&dir, old, "a different strong passphrase 7!").unwrap();
        // Old password no longer works; new one unlocks the SAME identity.
        assert_eq!(unlock(&dir, old).unwrap_err().code, "unauthorized");
        assert_eq!(unlock(&dir, "a different strong passphrase 7!").unwrap().sig_pub_bytes(), want);
    }

    #[test]
    fn change_password_rejects_wrong_old_and_weak_new() {
        let dir = tempdir();
        create(&dir, "correct horse battery staple 9!").unwrap();
        assert_eq!(change_password(&dir, "wrong", "another strong passphrase 7!").unwrap_err().code, "unauthorized");
        assert_eq!(change_password(&dir, "correct horse battery staple 9!", "weak").unwrap_err().code, "weak_password");
        // After a rejected change, the ORIGINAL password still works (no corruption).
        assert!(unlock(&dir, "correct horse battery staple 9!").is_ok());
    }

    #[test]
    fn export_keystore_copies_ciphertext_blob() {
        let dir = tempdir();
        create(&dir, "correct horse battery staple 9!").unwrap();
        let dest = dir.join("backup.blob");
        export_keystore(&dir, dest.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), std::fs::read(keystore_path(&dir)).unwrap());
    }
```

- [ ] **Step 2: implement** in `keystore.rs` (READ `keyblob::reseal`'s real signature first and adapt):

```rust
/// Change the keystore password: unlock with `old`, re-seal under `new`, and
/// atomically replace the blob. Wrong `old` → `unauthorized`; weak `new` →
/// `weak_password` (checked BEFORE touching the blob). The identity never leaves
/// this function.
pub fn change_password(dir: &Path, old: &str, new: &str) -> Result<(), UiError> {
    password::check(new).map_err(|_| UiError::new("weak_password", "Password is too weak."))?;
    let blob = std::fs::read(keystore_path(dir))
        .map_err(|_| UiError::new("no_keystore", "No keystore on this device."))?;
    // Prefer keyblob::reseal if it verifies the old password; else unlock+seal.
    let new_blob = keyblob::reseal(old, new, &blob, ARGON2_DESKTOP_TARGET)
        .map_err(|_| UiError::new("unauthorized", "Wrong password."))?;
    // Atomic replace: write to a temp file in the same dir, then rename over.
    let path = keystore_path(dir);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &new_blob).map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    std::fs::rename(&tmp, &path).map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    Ok(())
}

/// Copy the already-sealed (Argon2id ciphertext) key blob to `dest` — the portable
/// backup. Never decrypts; writes ciphertext only.
pub fn export_keystore(dir: &Path, dest: &str) -> Result<(), UiError> {
    let blob = std::fs::read(keystore_path(dir))
        .map_err(|_| UiError::new("no_keystore", "No keystore on this device."))?;
    std::fs::write(dest, &blob).map_err(|_| UiError::new("export_failed", "Could not write the backup."))?;
    Ok(())
}
```

> If `keyblob::reseal`'s signature differs (e.g. it takes the blob first, or doesn't verify the old password — in which case do `let id = keyblob::unlock(old, &blob).map_err(|_| unauthorized)?; let new_blob = keyblob::seal(new, &id, ARGON2_DESKTOP_TARGET)...`), ADAPT to the real API and note it. The behavioral contract (the three tests) is fixed: wrong old → unauthorized, weak new → weak_password (before any write), success reseals to the same identity, and a rejected change leaves the original blob intact.

- [ ] **Step 3:** `cargo test -p maxsecu-client-app keystore::` ; build ; fmt/clippy clean. Commit `feat(client-app): keystore change_password (reseal) + export_keystore`.

---

## Task 4: `change_password` / `export_keystore` commands

**Files:** Modify `crates/client-app/src/commands/settings.rs`, `dto.rs`, `main.rs`.

- [ ] **Step 1: DTOs** in `dto.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ChangePasswordRequest { pub old_password: String, pub new_password: String }
#[derive(Debug, Clone, Deserialize)]
pub struct ExportKeystoreRequest { pub dest_path: String }
```

- [ ] **Step 2: commands** appended to `commands/settings.rs` (passwords zeroized; see `commands/auth.rs::unlock_keystore` for the `Zeroizing` idiom):

```rust
use crate::dto::{ChangePasswordRequest, ExportKeystoreRequest};
use crate::keystore;

#[tauri::command]
pub async fn change_password(req: ChangePasswordRequest, dir: State<'_, AppDir>) -> Result<(), UiError> {
    let old = zeroize::Zeroizing::new(req.old_password);
    let new = zeroize::Zeroizing::new(req.new_password);
    keystore::change_password(&dir.0, old.as_str(), new.as_str())
}

#[tauri::command]
pub async fn export_keystore(req: ExportKeystoreRequest, dir: State<'_, AppDir>) -> Result<(), UiError> {
    keystore::export_keystore(&dir.0, &req.dest_path)
}
```

- [ ] **Step 3:** register both in main.rs; build/test; fmt/clippy clean. Commit `feat(client-app): change_password + export_keystore commands`.

---

## Task 5: UI — settings core (apply + load) + styles

**Files:** Create `ui/src/core/settings.ts`, `ui/styles.css`; Modify `ui/src/core/types.ts`, `ui/index.html`, `ui/package.json`.

- [ ] **Step 1: TS Settings type** in `core/types.ts` (mirror SettingsConfig serde shape):

```ts
export interface Settings {
  a11y: { reduced_motion: boolean; high_contrast: boolean; text_size: "normal" | "large" | "larger" };
  behavior: { confirm_destructive: boolean };
  performance: { ram_cache_cap_mb: number };
  connection: { use_tor: boolean };
}
```

- [ ] **Step 2: `core/settings.ts`** — apply settings to the document root + load-on-boot:

```ts
import { call } from "./rpc.ts";
import type { Settings } from "./types.ts";

// Apply accessibility settings by setting data-* attributes on <html>; styles.css
// keys on them. Reduced-motion ALSO respects the OS via the CSS media query.
export function applySettings(s: Settings): void {
  const root = document.documentElement;
  root.toggleAttribute("data-reduced-motion", s.a11y.reduced_motion);
  root.toggleAttribute("data-high-contrast", s.a11y.high_contrast);
  root.setAttribute("data-text-size", s.a11y.text_size);
}

// Load settings from the backend and apply them; safe to call on boot.
export async function loadAndApplySettings(): Promise<Settings | null> {
  try { const s = await call<Settings>("get_settings"); applySettings(s); return s; }
  catch { return null; }
}
```

- [ ] **Step 3: `ui/styles.css`** — a11y rules:

```css
:root { --mx-text-scale: 1; }
:root[data-text-size="large"]  { --mx-text-scale: 1.25; }
:root[data-text-size="larger"] { --mx-text-scale: 1.5; }
body { font-size: calc(1rem * var(--mx-text-scale)); }
:root[data-high-contrast] { filter: contrast(1.2); }
:root[data-high-contrast] a { text-decoration: underline; }
/* Reduced motion: explicit setting OR the OS preference. */
:root[data-reduced-motion] *, @media (prefers-reduced-motion: reduce) {
  * { animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important; scroll-behavior: auto !important; }
}
```
(If the combined selector above is invalid CSS, split into two blocks: one `:root[data-reduced-motion] * { … }` and one `@media (prefers-reduced-motion: reduce) { * { … } }`. Validate it builds.)

- [ ] **Step 4:** `index.html` — add `<link rel="stylesheet" href="styles.css">` in `<head>`. `package.json` build script — also copy `styles.css` to `dist/` (extend the existing `node -e` copy to also `copyFileSync('styles.css','dist/styles.css')`).

- [ ] **Step 5:** `npm run typecheck` + `npm run build` — clean; confirm `dist/styles.css` is produced. Commit `feat(ui): settings core (apply data-attrs) + a11y stylesheet`.

---

## Task 6: UI — `<settings-screen>`

**Files:** Create `ui/src/components/settings-screen.ts`; Modify `app-shell.ts`, `core/router.ts`.

- [ ] **Step 1: `<settings-screen>`** — sections (Accessibility: reduced-motion checkbox, high-contrast checkbox, text-size select; Performance: RAM cache cap number; Behavior: confirm-destructive checkbox; Connection: Tor checkbox [disabled w/ "arrives later" note]; Account: Change password [old/new inputs → `change_password`], Export keystore [path input → `export_keystore`, with a "store this securely" warning]; Privacy: a static note). On change of any pref control, call `set_settings(settings)` and `applySettings`. Accessible: landmark `#main` tabindex=-1 + focus, labelled controls, `role=status` for save/error feedback, errMsg narrowing, no `any`. Dynamic content via textContent; the only innerHTML is the static form shell.
- [ ] **Step 2:** route `settings` → `<settings-screen>` in app-shell; add `"settings"` to router; make the "Settings" nav a real `#/settings` link; call `loadAndApplySettings()` once on app-shell boot (so a11y prefs apply at startup). Keep focus-on-route-change.
- [ ] **Step 3:** typecheck + build clean. Commit `feat(ui): settings screen (a11y/performance/behavior/account)`.

---

## Task 7: UI — `<quick-settings>` (⚡ popover)

**Files:** Create `ui/src/components/quick-settings.ts`; Modify `app-shell.ts`.

- [ ] **Step 1: `<quick-settings>`** — a button (⚡) toggling a popover with the most-used toggles: reduced-motion, high-contrast, text-size, Tor (disabled), confirm-destructive. Each toggle calls `set_settings` + `applySettings` immediately (instant apply). Accessible: the toggle button has `aria-expanded`/`aria-controls`; the popover is keyboard-dismissible (Esc) and focus-managed; toggles are labelled. Loads current settings (`get_settings`) when opened.
- [ ] **Step 2:** mount `<quick-settings>` persistently in the shell header (next to `<status-pill>`/`<upload-tray>`), outside `#outlet`. Typecheck + build clean. Commit `feat(ui): quick-settings popover (instant-apply a11y toggles)`.

---

## Task 8: a11y — apply on boot + reduced-motion correctness pass

**Files:** Modify `app-shell.ts` (if not already booting settings in Task 6); verify the stylesheet.

- [ ] This task is a verification + polish step: confirm `loadAndApplySettings()` runs on boot (Task 6), the data-attrs drive the stylesheet, and reduced-motion respects both the explicit setting and `prefers-reduced-motion`. Add any missing focus-visible/contrast rule needed for WCAG AA (visible focus on all interactive controls; the skip-link contrast from Phase 1 is already AA). If everything is already in place from Tasks 5–7, fold this into the a11y-test task and skip a separate commit. (No code beyond polish; keep it minimal.)

---

## Task 9: a11y CI check — structural lint over the components

**Files:** Create `ui/src/a11y.test.ts`; Modify `ui/package.json` (add an a11y test script).

The components can't be rendered in plain Node (they import the Tauri API), so the automated CI a11y check is a **structural source lint** asserting each screen component carries the required accessibility affordances. (Full axe-in-jsdom with a Tauri-API mock is a documented deferral.)

- [ ] **Step 1: `ui/src/a11y.test.ts`** (node --test) — read each screen component's source and assert:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const screens = [
  "src/components/feed-screen.ts",
  "src/components/media-viewer.ts",
  "src/components/upload-screen.ts",
  "src/components/settings-screen.ts",
  "src/components/bootstrap-screen.ts",
  "src/components/pending-screen.ts",
  "src/components/admin-screen.ts",
];

for (const f of screens) {
  test(`${f} has a focusable main landmark`, () => {
    const src = readFileSync(f, "utf8");
    assert.match(src, /id="main"[^>]*tabindex="-1"/, `${f} must have <… id="main" tabindex="-1">`);
    assert.match(src, /#main[^]*\.focus\(\)/, `${f} must focus #main on mount`);
  });
  test(`${f} renders dynamic content without innerHTML interpolation`, () => {
    const src = readFileSync(f, "utf8");
    // Guard: no template-literal interpolation assigned to innerHTML.
    assert.doesNotMatch(src, /\.innerHTML\s*=\s*`[^`]*\$\{/, `${f} must not interpolate into innerHTML (XSS)`);
  });
}

test("status feedback uses an aria-live region somewhere in the screens", () => {
  const hits = screens.filter((f) => /aria-live=|role="status"/.test(readFileSync(f, "utf8")));
  assert.ok(hits.length >= screens.length - 1, "screens should use role=status/aria-live for feedback");
});
```

(Adjust the file list to the components that actually exist; tune the regexes to the real source if a screen legitimately differs — e.g. a screen that builds `#main` via createElement rather than innerHTML should still be detected, so make the landmark check tolerant: match either `id="main"` in a template OR `setAttribute("id", "main")` / `createElement` + `id = "main"`. The CONTRACT: every screen has a focusable main landmark, focuses it on mount, uses a live region for feedback, and never interpolates into innerHTML.)

- [ ] **Step 2: package.json** — add a script `"test:a11y": "node --experimental-strip-types --test src/a11y.test.ts"` (and optionally a `"test:all"` running both). Run `npm run test:a11y` → all pass. Also run the existing `npm run test` (store.test.ts) to confirm no regression.
- [ ] **Step 3:** typecheck + build clean. Commit `test(ui): structural a11y lint over screen components`.

---

## Task 10: Phase-5 gates green + security-review note

**Files:** Create `docs/security-review-phase5-mediaapp.md`.

- [ ] fmt (client-app + ui clean), clippy `-D warnings` (client-app), `cargo deny`, `cargo audit`, UI `npm run build` + `npm run typecheck` + `npm run test` + `npm run test:a11y`, `MAXSECU_PG_OPTIONAL=1 cargo test --workspace`.
- [ ] Write the note: settings are non-secret local prefs (no key/secret in settings.json); `change_password` reseals in the TCB with zeroized passwords, fail-closed (wrong-old/weak-new before any write, atomic replace, original intact on failure), identity never crosses; `export_keystore` copies ciphertext only (warned); a11y CSS keys on data-attrs only (no untrusted-data styling, no innerHTML interpolation); the a11y structural lint guards the affordances; the axe-in-jsdom-with-Tauri-mock full check is a documented deferral. Conclude PASS if green. Note deferrals (Tor real impl; Shamir K-of-N recovery UI; full axe DOM check; the Phase-4 UI-polish follow-ups if folded here).
- [ ] Commit `chore(phase5): gates green + security-review note`.

---

## Self-review checklist (done while writing)

- **Spec coverage (Phase 5 row of §10 + §5 Settings/Quick-settings + §7 a11y):** Settings screen with Account/Connection/Performance/Behavior/Accessibility/Privacy (Tasks 1–6) ✓; Quick-settings popover instant-apply (Task 7) ✓; RAM-cache cap + behavior toggles (Tasks 1, 6) ✓; a11y options reduced-motion/high-contrast/text-size applied live + OS-respecting reduced-motion (Tasks 5, 6, 8) ✓; export keystore + change password (Tasks 3, 4) ✓; CI a11y check (Task 9) ✓; WCAG-AA screens (Tasks 6, 7: landmarks/labels/live-regions/focus/non-color-only) ✓; sanitized errors + zeroized passwords (Tasks 3, 4) ✓; settings persist to config/settings.json (Task 1) ✓.
- **No server change / no client-core change:** Phase 5 is client-app config + keystore (reusing keyblob) + UI only ✓.
- **Type consistency:** `SettingsConfig`/`A11ySettings`/… (T1) reused as the command DTO (T2) + mirrored by `Settings` TS (T5); `keystore::{change_password, export_keystore}` (T3) wrapped by the commands (T4); `applySettings`/`loadAndApplySettings` (T5) used by settings-screen/quick-settings/app-shell (T6, T7); the a11y lint (T9) asserts the screens' affordances.
- **Known fill-ins flagged:** `keyblob::reseal` exact signature (T3 — read it; fall back to unlock+seal if it doesn't verify old); whether to reuse `SettingsConfig` as the DTO vs a separate `SettingsDto` (T2 — prefer reuse); the a11y-lint regexes tuned to the real component sources (T9); the styles.css reduced-motion media-query syntax validated (T5).

## Deferred (documented, not gaps)

- **Real Tor** transport (the toggle is a disabled placeholder; Phase-1 deferral).
- **Shamir K-of-N recovery UI** (admin-core::recovery) — an ops ceremony; `export_keystore` is the Phase-5 portable-backup path.
- **Full axe-core-in-jsdom a11y check** — needs a Tauri-API mock + jsdom harness; the structural lint is the Phase-5 CI guard.
- **RAM-cache cap enforcement** — Phase 5 persists the preference; wiring it to an actual in-memory cache bound is a later perf slice (no cache exists yet to bound).
- Optionally fold the **Phase-4 UI-polish follow-ups** (wire `upload_jobs`/`cancel_upload` into the tray; drop the dead `Encrypting` variant; cap staged jobs) into this phase's UI work.
