# MaxSecu Client — Codex UI Refinement Brief (round 2)

> **Paste-ready task for an OpenAI Codex frontend run.** This is the *task*; the
> *rules* live in **`FRONTEND-GUIDE.md`** (same folder). Read that guide first and in
> full — everything in its §3 (backend contract), §4 (serial queue), §5 (security &
> a11y invariants), and §6 (theming) is **binding** and must survive this run.

You are polishing an existing, working UI — **not** redesigning it from scratch. A
prior Codex run (commit `e4ccf0f`, 2026-06-30) established the current
**token-driven design system** in `styles.css` and restyled the shell + a handful of
core screens. Since then the app grew a lot of new surface that was built for
*function* and never went through that design pass. **Your job: bring the newer
surface up to the established system, and unify the whole app so it reads as one
coherent product in every theme.**

Work is in `crates/client-app/ui/`.

---

## 1. Mission (what "done" means)

1. **Unify** every screen/component to the existing token system in `styles.css`
   (the `--mx-*` custom properties: colour, surface, border, radius, spacing,
   elevation, motion, type scale). No new hard-coded colours, px radii, or ad-hoc
   spacing where a token exists. One consistent treatment per primitive across the
   whole app.
2. **Polish** the newer screens (§3) to the same fit-and-finish as the shell/feed:
   alignment, rhythm, empty/loading states, hover/active/focus states, motion.
3. **Preserve** the backend contract and all invariants (§4 below + the guide). This
   is a **look-and-feel-only** change. Do not touch `src/core/rpc.ts`, `types.ts`,
   command/event names, argument shapes, or the serial-queue behaviour.

This is a **restyle-and-reconcile** pass, scoped to bringing the app into one visual
language — **not** a wholesale reinvention of the design tokens. If a token genuinely
needs to be added (e.g. a missing semantic colour), add it to the token block in
`styles.css` and use it everywhere, rather than one-off inline values.

---

## 2. Where the drift is (start here)

The current CSS is disciplined — all colour literals are confined to the `:root`
token blocks, no component ships its own `<style>` block, and inline `style=` is only
used for genuinely dynamic values (gauge widths, video sizing). So the problem is
**not** rogue CSS. The problem is that `styles.css` grew organically across ~23
commits after the last redesign, so the **shared primitives have quietly diverged**
between the old screens and the new ones. Audit and reconcile these primitives so
there is exactly one of each:

- **Buttons** — one set of variants (primary / secondary / ghost / danger) with
  consistent size, radius, padding, disabled + `:focus-visible` states. Today
  different screens roll slightly different button looks.
- **Cards / tiles** — feed `media-card`, bundle tiles, upload/share tray rows, and
  bundle-composer items should share surface, border, radius, and elevation.
- **Dialogs / modals** — `share-dialog`, the owner-only delete confirm (`core/confirm.ts`),
  and any other overlay should share one modal shell (backdrop, panel, header, actions).
- **Form controls** — text inputs, selects, checkboxes, the resolution/bitrate menu,
  and the settings controls should share field styling, labels, help text, validation.
- **Chips / badges** — `state-badge`, bundle count badges, "already shared" markers,
  status pills — one chip system, all **non-colour-only** (icon/text + colour).
- **Section headers & page scaffold** — consistent screen title / subtitle / toolbar
  rhythm across feed, bundle, upload, settings, admin, register, recovery.
- **Empty, loading, error states** — `skeleton-card`, empty-list copy, inline error
  rows — one voice and one visual treatment everywhere.
- **Trays & gauges** — upload tray, share tray, `ram-gauge`, and the dual Media/Thumbnail
  cache gauges should share the meter/progress language (`core/gauge.ts`, `progress-meter`).

---

## 3. Focus areas — the surface added/changed since the last redesign

These are the elements the previous run never touched (or that changed heavily since).
**This is where most of your effort goes.** For each, match it to the unified
primitives from §2 and give it the same polish as the already-designed screens.

**New screens/components (never designed):**
- `bundle-screen.ts` — opened bundle with a **Gallery ⇄ Stacked** view toggle and a
  Download-all action. The Gallery view already reuses the feed tile grid
  (`.bundle-gallery`); make Stacked view (inline embedded viewers) equally clean.
- `bundle-composer.ts` — build a bundle: add / reorder / remove / preview / post.
  Needs a real composer layout (item list with drag-or-move affordances, per-item
  remove, a clear post/cancel action bar).
- `share-dialog.ts` + `share-tray.ts` — the reshare modal (tickable **contacts
  checklist** + manual username input, greyed already-shared rows) and its progress tray.
- `register-screen.ts` + `recovery-login-screen.ts` — enrollment and cold-recovery
  auth panels; should feel like siblings of `connect-screen` (which the last run polished).
- `trust-alarm.ts` — a security **alert banner** (directory split-view / first-contact).
  Must read as high-priority and be non-colour-only.
- `ram-gauge.ts` — the standalone header RAM meter (replaced the old ⚡ quick-settings).

**Heavily-churned existing screens (re-polish + reconcile):**
- `settings-screen.ts` — the biggest one. A recent pass moved it to a unified grid
  (Appearance / Accessibility / Account / **Privacy** / RAM+cache / **concurrency &
  thread budgets**). Make the whole grid cohere: consistent section cards, control
  rows, the **two stacked cache gauges** (Media / Thumbnails) with per-cache Clear +
  cap sliders + the Disk/Memory location toggle.
- `upload-screen.ts` — the **resolution + bitrate menu** for video, the local preview,
  and the confirm flow.
- `media-card.ts` — now carries a **bundle badge + counts** and **Download / owner-only
  Delete** actions layered over the tile; keep those affordances tidy and legible.
- `media-viewer.ts` + `video-player.ts` — the viewer now embeds a **native `<video>`**
  with Media Chrome controls (the old WebGL/sandbox surface is gone). Style the player
  chrome to sit inside the app's visual language; ensure embedded players don't fight
  page scroll/focus.
- `app-shell.ts` — header, nav rail, status strip, and the two persistent trays; the
  frame that ties every screen together — make sure it frames the newer screens as
  cleanly as the old ones.

---

## 4. Hard constraints — do NOT break these (see FRONTEND-GUIDE.md for detail)

- **Backend contract (guide §3):** every command/event is called with the exact name,
  args, and shape. Don't rename, don't change payloads, don't add/remove commands.
- **Serial queue (guide §4):** authenticated calls stay wrapped in
  `serial(...)`/`serialPriority(...)`; screens that enqueue background work still call
  `cancelPending()` on teardown. Don't fire authenticated calls bare.
- **CSP (guide §5.1):** `default-src 'self'; img-src 'self' data:; style-src 'self'
  'unsafe-inline'`. No remote fonts/CDN/scripts. Images stay `data:` URLs. Inline
  `<style>`/style attributes are allowed; **no inline `<script>`, no `eval`**.
- **No HTML injection (guide §5.2):** never interpolate values into `innerHTML`
  (`${…}` inside an `innerHTML` template literal **fails the a11y lint**). Use
  `textContent` / DOM construction. Static, value-free `innerHTML` scaffolding is fine.
- **No secrets in the UI (guide §5.3):** don't retain/log passwords or add any
  crypto/network/verification logic to the frontend.
- **WCAG 2.1 AA (guide §5.4), lint-gated:** every routed screen keeps a focusable
  `<main id="main" tabindex="-1">`, focus moves to `#main` on route change, a live
  region for async status, a working skip link, visible `:focus-visible`, and
  non-colour-only status. **Extend `src/a11y.test.ts` for new/changed screens; never
  weaken it.**
- **Theming (guide §6):** keep everything keyed off the four `<html>` attributes —
  `data-theme` (tech default / cheese / pottery), `data-reduced-motion`, `data-high-contrast`,
  `data-text-size` — and the `settingsStore`. Use `rem` for text so `data-text-size`
  scales. **Every screen must look correct in every theme preset, at high contrast, with
  reduced motion, and at all three text sizes.** Theme parity is a common gap on the
  newer screens — check it explicitly.
- **Stay vanilla** (guide §1): no framework, no new runtime deps. One runtime dep
  (`@tauri-apps/api`) only.

---

## 5. How to work and verify

Run from `crates/client-app/ui/`:

```bash
npm install
npm run typecheck      # must stay clean
npm test               # node:test unit tests — keep green, add tests for new logic
npm run test:a11y      # structural a11y lint — keep green, EXTEND for changed screens
npm run build          # esbuild bundle
```

- **Iterate visually without rebuilding Rust:** the bundle is plain ESM + Web
  Components. Point `core/rpc.ts` at a mock (or shim `@tauri-apps/api`) returning canned
  `Card` / `OpenedContent` / `FeedEntry[]` / `BundleView` objects (shapes in `types.ts`;
  sample data in the `*.test.ts` fixtures) and push fake events. Build the look against
  fixtures, then `npm run build` + rebuild the Rust app to see it live. (Guide §8.)
- **Check every screen in both themes** and at high-contrast / reduced-motion / each
  text size before calling a screen done.

## 6. Definition of done (the guide's §10 checklist, plus unification)

- [ ] `npm run typecheck` clean
- [ ] `npm test` green (new logic has tests)
- [ ] `npm run test:a11y` green **and extended** for new/changed screens
- [ ] `npm run build` succeeds; app rebuilt and visually verified
- [ ] Every command/event in guide §3 still called with the exact name/args/shape
- [ ] Authenticated calls go through `serial`/`serialPriority` (guide §4)
- [ ] No `${}` in `innerHTML`; content via `textContent`/DOM (guide §5.2)
- [ ] CSP unchanged; images via `data:` URLs (guide §5.1)
- [ ] WCAG AA preserved on every screen (guide §5.4)
- [ ] Theme/a11y still driven by the `data-*` attributes + `settingsStore` (guide §6)
- [ ] **Every screen verified in each theme preset + high-contrast + reduced-motion + all
      three text sizes**
- [ ] **One consistent treatment per primitive** (buttons, cards, dialogs, fields,
      chips, headers, empty/loading states, trays, gauges) across the whole app
- [ ] The focus-area screens in §3 read with the same fit-and-finish as feed/connect
- [ ] No keys/tokens/ciphertext handled in the UI (guide §5.3)
