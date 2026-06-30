# MaxSecu Media App — UI Overhaul + Caching Design (2026-06-30)

**Status:** Approved direction (brainstorming complete). Application layer only —
no change to the TCB (`client-core`, `crypto`, `encoding`, `server`, `admin-core`).

**Goal.** Make the media client match its own approved design (`media-app-design.md`
§5 Layout-B shell + §6 feedback layer), look modern/"flashy", feel fast via an
in-memory decrypted cache, and fix the functional bugs the operator hit.

## 1. Decisions (from the up-front Q&A)

| Axis | Decision |
|------|----------|
| Visual direction | **Modern dark + flashy**, electric **blue→violet** accent, glassy surfaces, glow, micro-motion + skeleton loaders; **light-mode toggle** included (default dark). |
| Quick-settings (⚡) | Reduced to **Theme toggle + RAM cap (slider + number input)** only; **hidden whenever the Settings screen is open**. |
| Settings ⇄ quick-settings | **One shared reactive store** (single source of truth); both + the shell theme apply live. |
| Cache | **Decrypted bytes resident in RAM**, LRU-evicted by total bytes, **zeroized on eviction and on app close**. |
| RAM cap | Default = **10% of system RAM**; **max selectable = total RAM − 6 GB** (floor for small machines); read via `sysinfo`. |
| Delivery | **One cohesive redesign+fix** effort. |

## 2. Non-goals / out of scope

- No backend/TCB/crypto changes; no server or schema changes.
- No new framework (keep vanilla TS + Web Components, `D-J`); CSS is hand-rolled tokens.
- Real ffmpeg video ingest stays deferred (unchanged). Tor stays a disabled placeholder.

## 3. Visual design system

Rewrite `crates/client-app/ui/styles.css` into a token-driven system:

- **Tokens (`:root`):** color (base/surface-1/2/3, text, muted, border), an accent
  gradient (`--mx-accent-1` blue → `--mx-accent-2` violet), glow/elevation shadows,
  radii, spacing scale, type scale, and **motion tokens** (`--mx-dur-*`, `--mx-ease-*`).
- **Theming:** `<html data-theme="dark|light">` swaps the token block. Dark is default.
  Applied by the shared settings store (§7), so it's instant and persisted.
- **Text size:** the scale moves to **`:root` font-size** (`--mx-text-scale` →
  `html { font-size: calc(100% * var(--mx-text-scale)) }`) so every `rem`/`em` text
  grows. Components must use `rem`/`em`, not `px`, for type. (Today it keys `body`,
  which is why nothing visibly changed.)
- **Motion:** transitions/hover-glow/skeleton-shimmer use the motion tokens; the
  existing `:root[data-reduced-motion]` and `@media (prefers-reduced-motion)` blocks
  zero them out — so reduced-motion **finally has a visible effect**.
- **Surfaces:** nav rail, cards, popovers, viewer, toasts share a glassy surface
  treatment (subtle border + blur + elevation; accent glow on hover/focus).
- AA contrast preserved; status is **never color-only** (icon + text + ARIA).

## 4. Shell & navigation (`media-app-design.md` §5, Layout B)

`app-shell.ts`:

- Top **nav rail**: `Feed · My Content · Upload · Admin · Settings` — all real links
  with an **active state**. **"My Content" becomes a link** to `#/mine` (today it's a
  dead `<span>`).
- **Status strip** under the rail: connection pill (existing `<status-pill>`), a sync
  indicator, and an **active-tasks** count wired to the task/upload events.
- **⚡ quick-settings**: rendered in the header, but the trigger is **hidden when the
  current route is `#/settings`** (the shell toggles a `hidden` attr on route change).

`router.ts`: add `mine` to the route list. The shell renders `#/mine` as a
`<feed-screen mine>` (owner-filtered) — same component, `mine` attribute preset.

## 5. Feedback & loading layer (`media-app-design.md` §6)

- **Skeletons:** a `<skeleton-card>` shimmer fills the feed grid while `list_feed`
  runs; the viewer shows a skeleton block until content is ready. Shimmer is
  motion-token-driven (off under reduced-motion).
- **Toasts:** a new `<toast-host>` (singleton in the shell) + a `toast(kind, msg)`
  helper in `core/toast.ts`. Emits success/info/error toasts: **upload complete**,
  **settings saved**, and sanitized failures. ARIA-live `assertive` for errors,
  `polite` otherwise.
- **Upload tray:** `upload-tray.ts` made visible/prominent with per-item
  progress-meter (%, speed, ETA, retry — reuse `<progress-meter>`), and fires a
  success toast on completion. (The pipeline already emits `EVT_UPLOAD`; this wires
  it to visible UI.)

## 6. In-memory decrypted cache (Rust, `client-app`)

New module `crates/client-app/src/content_cache.rs`, registered as Tauri managed
state in `main.rs` so it lives for the whole process (survives UI navigation).

- **Entry:** `{ key: (file_id:[u8;16], version:u64), bytes: Zeroizing<Vec<u8>>,
  kind: Image|Blog, meta: small render metadata, last_used: monotonic seq }`.
  (Video stays out — frames live in the confined worker; only image/blog decrypted
  payloads are cached, which already cross to the WebView today.)
- **Store:** `Mutex<CacheInner>` with a map + total-byte counter + a monotonic
  LRU clock. API: `get(key) -> Option<clone>`, `put(key, kind, bytes, meta)`,
  `invalidate(key)`, `clear_and_zeroize()`.
- **LRU eviction:** on `put`, if `total + new > cap`, evict least-recently-used
  entries (zeroizing each) until it fits. An entry larger than the whole cap is not
  stored (served straight through, no caching).
- **Cap:** `cap_bytes` = current `SettingsConfig.performance.ram_cache_cap_mb`.
  Updated live when the setting changes (a `set_cap` that triggers eviction if the
  new cap is smaller).
- **Zeroize lifecycle:** `Zeroizing<Vec<u8>>` zeroizes on drop (eviction/replace).
  On app close, a Tauri **`WindowEvent::CloseRequested` / `RunEvent::Exit`** handler
  calls `clear_and_zeroize()` so no decrypted buffer survives shutdown.
- **Integration:** `commands/feed.rs::decrypt_card` and `commands/viewer.rs::open_content`
  check the cache first (instant hit, no re-fetch/re-decrypt); on miss they decrypt
  via the existing path and `put` the result. This is the core fix for slow feed,
  re-load-on-navigation, and the stuck viewer.

### 6.1 RAM sizing (`sysinfo`)

- New pinned dep `sysinfo` (pure-Rust; flagged for `cargo deny`/`cargo audit`).
- New command `ram_limits() -> { default_mb, min_mb, max_mb }`:
  - `total_mb` = `sysinfo` total physical RAM.
  - `max_mb` = `max(min_mb, total_mb - 6144)` (the **total − 6 GB** ceiling; floor
    keeps small machines usable).
  - `default_mb` = `clamp(total_mb / 10, min_mb, max_mb)` (**10%**).
  - `min_mb` = 64.
- `SettingsConfig.normalized()` clamps `ram_cache_cap_mb` into `[min_mb, max_mb]`
  using these computed bounds (replacing today's fixed `16..4096`). On first run
  (no settings file) the cap initializes to `default_mb`.
- The RAM controls (quick-settings + Settings screen) fetch `ram_limits()` to set
  the slider/number `min`/`max`/`step`, so the UI **cannot select above total − 6 GB**.

## 7. Settings model + shared reactive store

- **Config (`config.rs`):** add `appearance: { theme: "dark"|"light" }` (default
  `dark`) to `SettingsConfig` (`#[serde(default)]`, normalized to the known set).
  Reuse `performance.ram_cache_cap_mb`.
- **Shared store (`core/settings.ts`):** a small reactive store holding the current
  `Settings`, with `get()`, `update(patch)` (persists via `set_settings`, applies,
  and notifies subscribers), and `subscribe(fn)`. `applySettings` extends to set
  `data-theme` alongside the existing a11y data-attrs.
- **Live apply everywhere:** the full **Settings screen**, **quick-settings**, and
  the **shell theme** all read/write the store and re-render on its change event —
  so Settings ⇄ quick-settings always agree and changes apply instantly (today the
  full Settings screen persists but doesn't `applySettings`, and the two screens
  don't sync).
- **Quick-settings (`quick-settings.ts`)** reduced to: **Theme toggle** + **RAM cap
  (range slider bound to a number input, both clamped to `ram_limits`)**. Nothing else.

## 8. Functional bug fixes (folded in)

- **My Content** → real `#/mine` route + nav link (§4).
- **Viewer stuck on "loading"** → cache-hit bypass; viewer-open is prioritized over
  background card decrypts; in-flight card decrypts are **cancelled when leaving the
  feed** so a stalled card can't wedge the shared serial lock. Harden `core/serial.ts`
  so every task releases the lock on error/cancel and a high-priority task can jump
  the queue.
- **Feed reload each visit** → backend cache makes data instant; the feed retains its
  last view-state (entries + scroll) in a JS store so the grid doesn't visibly rebuild.
- **Text size does nothing** → root-font-size scaling (§3).
- **Reduced motion does nothing** → now gates real motion (§3).
- **No upload feedback** → visible tray + toasts (§5).

## 9. File change map

**UI (TS/CSS):** `styles.css` (rewrite to tokens), `components/app-shell.ts`,
`feed-screen.ts`, `media-card.ts`, `media-viewer.ts`, `quick-settings.ts`,
`settings-screen.ts`, `upload-tray.ts`, `upload-screen.ts`, `core/settings.ts`,
`core/serial.ts`, `core/router.ts`, `core/types.ts`; **new** `core/toast.ts`,
`components/toast-host.ts`, `components/skeleton-card.ts`.

**Rust (`client-app`):** **new** `src/content_cache.rs`; edit `src/config.rs`,
`src/commands/feed.rs`, `src/commands/viewer.rs`, `src/commands/settings.rs`,
`src/main.rs`, `Cargo.toml` (+`sysinfo`). Register `ram_limits` + cache state +
exit-zeroize hook.

## 10. Testing

- **UI logic (node:test):** settings store reduce/subscribe + clamp to `ram_limits`;
  serial queue priority/cancel/lock-release; router includes `mine`.
- **Rust unit:** `content_cache` LRU eviction by bytes, oversize-skip, `set_cap`
  shrink-evicts, `clear_and_zeroize` empties; `ram_limits` math incl. the small-RAM
  floor and the total−6 GB ceiling; `SettingsConfig.normalized()` clamps with bounds.
- **a11y lint:** extend the structural checks (nav links incl. My Content, toast
  ARIA-live, controls labelled).
- **e2e regression:** the existing `browse_view_e2e` / `upload_e2e` / `video_*` stay
  green (cache must not change verified outputs — it returns the same bytes).
- **Manual:** theme toggle, text-size visibly scales, reduced-motion stills motion,
  feed instant on return, viewer never hangs, upload shows progress + success toast.

## 11. Risks / tradeoffs

- **Decrypted plaintext resident in RAM** — deliberate UX choice; mitigated by
  zeroize-on-evict/close + the cap, never written to disk. Image/blog plaintext
  already crosses to the WebView, so no new exposure class for the cached kinds.
- **`sysinfo`** new dependency — pinned + audited; isolated to the RAM-sizing read.
- **Broad UI surface** — many files change, but each is a focused edit; the TCB and
  server are untouched, and e2e gates guard the data path.
