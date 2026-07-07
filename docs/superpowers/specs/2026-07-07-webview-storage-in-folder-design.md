# Keep every stored byte inside the client folder

**Date:** 2026-07-07
**Status:** Approved (design)
**Topic:** Eliminate all client-app persistence outside the portable `<app_dir>` folder.

## Problem

The portable client folder (`<app_dir>` = the directory holding `MaxSecuClient.exe`)
is meant to be the *only* place the client leaves a trace. Everything the Rust code
writes already obeys this: `config/`, `keystore/`, `index/`, `tofu/`, `kt/`, `cache/`,
`staging/`, `logs/`, and the transient `register.key` all live under `<app_dir>`.

The escape is entirely the **WebView2 (WebView) UI layer**:

1. **`localStorage`** is used for three user preferences:
   - bundle view mode — `core/bundle-view.ts`, key `bundleViewMode`
   - active skin / frontend — `core/frontends.ts`, key `maxsecu.frontend`
   - player volume + mute — the third-party **Media Chrome** component
     (`<media-volume-range>`/`<media-mute-button>` in `components/video-player.ts`)
     auto-persists to `localStorage` (`media-pref-*` keys)
2. `main.rs` **never sets a WebView2 user-data folder**, so WebView2 uses its default:
   `%LOCALAPPDATA%\org.maxsecu.client\EBWebView\`. That directory holds the
   `localStorage` above **plus** WebView2's own HTTP cache, cookies, GPU cache, and logs.

The theme preference is *not* affected — it already round-trips through the backend
`config/settings.json` via `get_settings`/`set_settings`.

Goal: after this change, **nothing the client stores lands outside `<app_dir>`**, while
still remembering theme, volume, bundle-view mode, and skin across runs.

## Approach (chosen)

Two independent, complementary fixes plus an empirical audit:

- **Part 1 (belt): redirect WebView2's user-data folder into `<app_dir>/webview/`**, and
  wipe it on exit. One change relocates `localStorage` *and* all WebView2 byproducts
  inside the folder.
- **Part 2 (suspenders): migrate the prefs we own into `config/settings.json`** so they
  are plaintext, inspectable, and travel with the folder.
- **Part 3 (proof): a repeatable ProcMon (Sysinternals) capture + analyzer** that flags
  any write outside `<app_dir>`.

Rejected alternatives:
- *Migrate prefs only, keep default WebView2 data dir* — leaves WebView2 cache/cookies/GPU
  cache in `%LOCALAPPDATA%`. Fails the requirement.
- *Redirect only, no pref migration* — meets "inside the folder" but leaves the prefs as
  opaque `localStorage` rather than human-readable settings; the user asked for the fuller
  solution.

## Part 1 — Redirect WebView2 into the folder + wipe on exit

### Data-directory override
The main window is currently declared in `crates/client-app/tauri.conf.json`
(`app.windows[0]`). To set the webview data directory it must be created in Rust so the
builder API is available.

- Remove `app.windows` from `tauri.conf.json` (keep `app.security`, `build`, `bundle`,
  identifier, etc.).
- In `main.rs` (Tauri `setup` closure or before `build`), create the main
  `WebviewWindow` in Rust with the same properties the config had
  (title `"MaxSecu"`, 1100×720, resizable, maximized) and set its
  **data directory to `<app_dir>/webview/`**.

**API to verify before coding:** on Windows the authoritative mechanism is one of:
  - `tauri::webview::WebviewWindowBuilder::data_directory(PathBuf)` (preferred if present
    in the vendored `@tauri-apps`/`tauri` version), or
  - setting the `WEBVIEW2_USER_DATA_FOLDER` environment variable **before** the webview is
    created (fallback).
The implementing agent MUST confirm which one the pinned Tauri 2 version honors (check the
`tauri` crate version in `Cargo.lock` and its `WebviewWindowBuilder` API) and use that;
do not assume. `ensure_portable_layout` gains `webview` to its created sub-dirs.

### Wipe on exit
In the existing `app.run(|app_handle, event| ...)` handler in `main.rs`, extend the
`RunEvent::Exit` arm to best-effort `remove_dir_all(<app_dir>/webview)` (ignore errors,
never block or panic shutdown — same discipline as the cache `clear_and_zeroize_sync`
calls). This keeps the folder free of persistent browser artifacts between runs; the
prefs survive because they live in `config/settings.json` (Part 2), not in the webview
data dir.

> Note: a mid-session crash could leave `webview/` behind; the next startup's
> `ensure_portable_layout` + wipe-on-exit tolerates a pre-existing dir (create is
> idempotent; the wipe is best-effort). Optionally the Exit-wipe logic can also run a
> best-effort clean at startup — implementer's discretion, but not required.

## Part 2 — Migrate owned prefs into `config/settings.json`

### Backend schema (`crates/client-app/src/config.rs`)
Extend `SettingsConfig` (all sections `#[serde(default)]`, partial/old files still load):

- `appearance`: add `frontend: String` (default `"default"`). `normalized()` constrains it
  to `default|pizza|slot3`, else `"default"`.
- new section `ui: UiSettings { bundle_view: String }` (default `"gallery"`);
  `normalized()` constrains to `gallery|stacked`, else `"gallery"`.
- new section `playback: PlaybackSettings { volume: f32, muted: bool }`
  (defaults `volume = 1.0`, `muted = false`); `normalized()` clamps `volume` to
  `0.0..=1.0` (and maps NaN → `1.0`).

Round-trip + normalization unit tests mirror the existing `config.rs` test style.

### Pre-paint skin injection (no flash-of-unstyled-content)
The skin is applied **before first paint** by `ui/boot.js` (an external classic script,
because the app CSP blocks inline JS). It currently reads `localStorage`. Moving the source
of truth to the backend must not reintroduce a flash, since an IPC call is async.

- `main.rs` reads the persisted `settings.json` at startup (it already loads
  `SettingsConfig` for cache caps) and passes the resolved `frontend` id into the webview
  via a Tauri **initialization script** that sets, before any page script runs:
  `window.__MAXSECU_BOOT__ = { frontend: "<id>" };`
- `ui/boot.js` reads `window.__MAXSECU_BOOT__?.frontend` first; if absent, falls back to
  the legacy `localStorage.getItem("maxsecu.frontend")` (one-version migration path), else
  default. It keeps applying `data-frontend` + the stylesheet href exactly as today.

### Frontend rewires (`crates/client-app/ui/src/`)
- **`core/types.ts`**: extend `Settings` with `appearance.frontend`, `ui: { bundle_view }`,
  `playback: { volume, muted }` matching the Rust serde shapes.
- **`core/settings.ts`**: extend `DEFAULTS` to match. `applyFrontend()` continues to key off
  the store; `applySettings()` calls `applyFrontend(store.appearance.frontend)`.
- **`core/frontends.ts`**: `getFrontend()`/`setFrontend()` read/write the shared settings
  store (`updateSettings({ appearance: { frontend } })`) instead of `localStorage`.
  `applyFrontend(value)` stays DOM-only and unchanged.
- **`core/bundle-view.ts`**: `readBundleViewMode()`/`writeBundleViewMode()` read/write the
  settings store (`ui.bundle_view`) instead of `localStorage`. Keep the pure
  `normalizeBundleViewMode` helper for tests. Update `components/bundle-screen.ts` and its
  test accordingly (test no longer fakes `localStorage`; it exercises the store or the pure
  normalizer).
- **`components/video-player.ts`**: on mount, after Media Chrome initializes, set
  `video.volume` / `video.muted` from `settingsStore.playback`; add a debounced
  `volumechange` listener that persists `{ playback: { volume, muted } }` via
  `updateSettings`. Media Chrome's own `localStorage` persistence is left in place (now
  in-folder and redundant); our settings copy is authoritative on restore.

No secret material crosses the Tauri seam — these are non-secret UI preferences, consistent
with the existing settings contract.

## Part 3 — ProcMon audit (proof of completeness)

Deliver a headless, repeatable capture + analysis under `tools/storage-audit/` (or
`docs/`), with a short runbook:

1. Start capture: `Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile capture.pml`
   (requires admin; runs while the app is exercised).
2. The user launches the **built** client and exercises every persistence-relevant flow:
   first-run/register, login, change theme, change volume, change bundle-view, swap skin,
   play a video, upload, download, logout, and app exit.
3. Stop capture: `Procmon.exe /Terminate`, then export:
   `Procmon.exe /OpenLog capture.pml /SaveAs capture.csv`.
4. **Analyzer** (PowerShell): parse the CSV; keep rows where
   - `Process Name` ∈ { `MaxSecu.exe`, `msedgewebview2.exe` (and its children) }, and
   - `Operation` ∈ { `WriteFile`, `CreateFile` with a write/create disposition,
     `SetRenameInformationFile`, `SetEndOfFileInformationFile`, `RegSetValue`,
     `RegCreateKey` }, and
   - `Result` = `SUCCESS`, and
   - target `Path` does **not** start with `<app_dir>` (case-insensitive, normalized).
   Emit the flagged rows grouped by path prefix so byproducts are easy to read.
5. Interpret: file/registry writes attributable to *our data* must be zero outside
   `<app_dir>`. Any residual is expected to be the **shared WebView2 runtime's own**
   `HKCU`/`%TEMP%` bookkeeping (see caveat) — enumerate and document it.

The script takes `<app_dir>` and the CSV path as parameters; it prints a PASS/FAIL summary
(FAIL if any our-data write lands outside the folder) plus the annotated residual list.

## Known caveat

The **shared WebView2 runtime** touches a small set of `HKCU` registry keys and possibly
`%TEMP%` regardless of the data-directory redirection. That is the runtime's own
bookkeeping, not user data, and is largely outside an application's control. This design
does **not** claim zero out-of-folder registry/temp activity up front; Part 3 enumerates
exactly what remains so it can be reviewed and judged, rather than asserted.

## Out of scope

- Changing where the confined `ffmpeg` / re-mux children write (already `<app_dir>/staging`
  and the confined temp under the app's control — the audit will confirm).
- The `arti`/Tor state (already under `<app_dir>/config/tor`).
- Any change to what is encrypted vs. plaintext (unchanged; the migrated prefs are
  non-secret, same as theme today).

## Implementation parallelization

Three largely independent tracks for parallel subagents:

- **Track A — WebView2 redirect + exit-wipe** (`main.rs`, `tauri.conf.json`, `layout.rs`).
  Independent. Must verify the Tauri-2 data-directory API first.
- **Track B — settings migration** (`config.rs` → init-script in `main.rs` → `boot.js` →
  `types.ts`/`settings.ts`/`frontends.ts`/`bundle-view.ts`/`video-player.ts` +
  `bundle-screen.ts`/tests). Self-contained but internally sequential (backend shape first,
  then frontend consumers).
- **Track C — ProcMon audit tooling** (`tools/storage-audit/` script + runbook).
  Independent.

Track A and Track B both edit `main.rs` (A: window creation + Exit arm; B: init-script +
reading `frontend` from the already-loaded settings). Coordinate the `main.rs` edits to
avoid a conflict — either sequence A→B on that file or have one agent own `main.rs`.

## Success criteria

1. Building and running the client, then exercising all flows and exiting, leaves **no
   client-written file or registry value outside `<app_dir>`** except documented
   shared-WebView2-runtime bookkeeping (proven by the Part 3 audit).
2. Theme, volume, bundle-view mode, and skin all persist across app restarts, sourced from
   `config/settings.json`.
3. No flash-of-unstyled-content on the skin at startup.
4. `<app_dir>/webview/` is wiped on clean exit.
5. All existing client-app Rust tests and UI (`node:test`) tests pass; new tests cover the
   settings additions and normalization.
