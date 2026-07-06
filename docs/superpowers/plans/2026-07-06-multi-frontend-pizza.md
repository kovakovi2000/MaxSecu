# Multi-Frontend Support + Cheese-Pizza ZIP — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the MaxSecu client host three distinct, settings-switchable frontends (Default, Cheese Pizza, empty 3rd slot) over one shared backend + component tree, and produce a design-brief ZIP an external agent uses to author the cheese-pizza skin.

**Architecture:** One shared Web-Components component tree and backend, unchanged. A frontend = `{ id, label }` + a complete stylesheet it owns (`styles.<id>.css`) + an optional decoration module (`src/frontends/<id>/deco.ts`) that injects decorative DOM into named `data-deco-slot` mount points. A runtime `applyFrontend()` swaps the active `<link>` href + `data-frontend` attr + deco module; the choice persists UI-local in `localStorage["maxsecu.frontend"]`. Default keeps the existing `styles.css` verbatim; `pizza`/`slot3` ship as stubs that `@import` it. The real pizza CSS/deco is produced externally from the ZIP and dropped into the `pizza` slot.

**Tech Stack:** Vanilla TypeScript 5.4 + native Web Components, esbuild 0.21.5 bundle, `node --test` (`--experimental-strip-types`), Tauri 2 WebView. All work is under `crates/client-app/ui/`.

**Deliverable order (user priority):** The ZIP is delivered FIRST (Tasks 1–2). The brief docs are the authoritative integration contract; the scaffold (Tasks 3–8) is built afterward to match that contract exactly, so external work and scaffold proceed in parallel and integrate cleanly.

> **Deviation from spec §7 (intentional, lower-risk):** the Default frontend keeps the filename `styles.css` (NOT renamed to `styles.default.css`). This avoids breaking `settings-screen.test.ts` (which `readFileSync("styles.css")`) and the existing build copy. Only two NEW stylesheet files are added: `styles.pizza.css`, `styles.slot3.css`.

---

## File Structure

**New files**
- `crates/client-app/ui/assets/pizza.png` — the login image asset (copied from repo-root `pizza.png`).
- `crates/client-app/ui/PIZZA-BRIEF.md` — paste-ready external-agent task for the cheese-pizza frontend.
- `crates/client-app/ui/src/core/frontends.ts` — frontend registry + runtime switcher (replaces the theme-preset code in `settings.ts`).
- `crates/client-app/ui/src/core/frontends.test.ts` — unit + source-lint tests for the registry/switcher.
- `crates/client-app/ui/src/frontends/pizza/deco.ts` — stub pizza decoration module (`DecoModule`), replaced externally.
- `crates/client-app/ui/styles.pizza.css` — stub (`@import "styles.css"`), replaced externally.
- `crates/client-app/ui/styles.slot3.css` — stub (`@import "styles.css"`), empty 3rd slot.
- `crates/client-app/ui/scripts/copy-assets.mjs` — build copy step (all stylesheets + pizza.png → `dist/`).
- `maxsecu-pizza-frontend.zip` — the design-brief ZIP at repo root (build artifact; gitignored).

**Modified files**
- `crates/client-app/ui/FRONTEND-GUIDE.md` — append a "Multi-frontend architecture" section (the drop-in contract).
- `crates/client-app/ui/index.html` — `data-frontend="default"`, `<link id="frontend-css">`, pre-paint bootstrap script.
- `crates/client-app/ui/src/core/settings.ts` — drop `*ThemePreset`; call `applyFrontend()` in `applySettings`.
- `crates/client-app/ui/src/components/app-shell.ts` — add `app-bg`/`header` deco slots; call `refreshFrontendDeco()` after each route render.
- `crates/client-app/ui/src/components/connect-screen.ts`, `register-screen.ts`, `recovery-login-screen.ts` — add `data-deco-slot="login"` on the root `<main>`.
- `crates/client-app/ui/src/components/settings-screen.ts` — Appearance "Theme" select → "Frontend" select wired to `get/setFrontend`.
- `crates/client-app/ui/src/components/settings-screen.test.ts` — assert the Frontend select exists.
- `crates/client-app/ui/package.json` — `build` script calls `scripts/copy-assets.mjs`; `test` script adds `frontends.test.ts`.

---

## Task 1: Brief docs + pizza asset (the ZIP payload)

**Files:**
- Create: `crates/client-app/ui/assets/pizza.png`
- Create: `crates/client-app/ui/PIZZA-BRIEF.md`
- Modify: `crates/client-app/ui/FRONTEND-GUIDE.md` (append a section)

- [ ] **Step 1: Copy the pizza image into the UI as a tracked asset**

Run (from repo root):
```bash
mkdir -p crates/client-app/ui/assets && cp pizza.png crates/client-app/ui/assets/pizza.png && ls -la crates/client-app/ui/assets/pizza.png
```
Expected: the file exists (~1.06 MB, 1536×1536 PNG).

- [ ] **Step 2: Confirm it is not gitignored**

Run: `cd crates/client-app/ui && git check-ignore assets/pizza.png; echo "exit=$?"`
Expected: `exit=1` (NOT ignored). If it prints the path (exit=0), stop and inspect `crates/client-app/ui/.gitignore`.

- [ ] **Step 3: Append the multi-frontend architecture contract to `FRONTEND-GUIDE.md`**

Append this section verbatim to the END of `crates/client-app/ui/FRONTEND-GUIDE.md`:

```markdown

---

## 9. Multi-frontend architecture (the drop-in contract)

The client hosts **three switchable frontends** over ONE shared component tree and
backend. A frontend is a named visual skin with three parts:

- **Registry entry** `{ id, label }` in `src/core/frontends.ts` (`FRONTENDS`).
- **A complete stylesheet** it owns: `styles.<id>.css`, loaded via a single
  `<link id="frontend-css">` in `index.html`. Exactly one is active at a time.
- **An optional decoration module** `src/frontends/<id>/deco.ts` implementing
  `DecoModule` (below), bundled into `main.js`.

Registered ids: `default` (→ `styles.css`, today's design, verbatim),
`pizza` (→ `styles.pizza.css`, this brief), `slot3` (→ `styles.slot3.css`, empty).

Switching (`src/core/frontends.ts::applyFrontend`) rewrites the `<link>` href, sets
`data-frontend="<id>"` on `<html>`, unmounts the old deco module, mounts the new one,
and persists the id in `localStorage["maxsecu.frontend"]`. An inline bootstrap in
`index.html` applies the persisted frontend before first paint (no flash).

### The `DecoModule` interface

```ts
export interface DecoModule {
  // Idempotent. Called once on apply AND after every route render. Query your slot
  // (e.g. document.querySelector('[data-deco-slot="login"]')) and inject decoration
  // only if you have not already (guard by a data-attr/class you own). Safe no-op if
  // the slot is absent on the current screen.
  mount(doc: Document): void;
  // Remove every node your mount() injected (called when switching away).
  unmount(doc: Document): void;
}
```

### Decoration slots (stable mount points in the shared components)

- `data-deco-slot="login"` — on the `<main>` of connect / register / recovery-login.
- `data-deco-slot="app-bg"` — a body-level full-page layer in `app-shell`.
- `data-deco-slot="header"` — inside the app header.

Default/`slot3` leave these empty. Your `pizza` deco fills them. Slots are inert when
empty — do NOT change component markup, layout, or spacing; only add children to slots.

### What the pizza design delivers (drops into the `pizza` slot)

1. `styles.pizza.css` — a COMPLETE standalone stylesheet (replaces the stub, which is
   just `@import url("styles.css");`). **Preserve every spacing/layout/type token and
   the component structure** from `styles.css` — change only colour, texture, imagery,
   borders, shadows, and decorative styling. The spacing of elements must stay identical.
2. `src/frontends/pizza/deco.ts` — the real `DecoModule` (replaces the no-op stub),
   placing `assets/pizza.png` into `data-deco-slot="login"` and any cheese-drip layers.

Do NOT touch `src/core/rpc.ts`, `types.ts`, command/event names, argument shapes, the
serial queue (§4), or the security/a11y invariants (§5). This is look-and-feel only.
```

- [ ] **Step 4: Write `crates/client-app/ui/PIZZA-BRIEF.md`**

Create the file with this content:

```markdown
# MaxSecu Client — Cheese-Pizza Frontend Brief

> **Paste-ready task for an external frontend run.** The *rules* live in
> **`FRONTEND-GUIDE.md`** (same folder) — read it in full first. Its §3 (backend
> contract), §4 (serial queue), §5 (security & a11y), §6 (theming), and the new §9
> (multi-frontend architecture / drop-in contract) are **binding**.

## Mission

Author the **Cheese-Pizza** frontend: a full "melting / dripping cheese pizza" visual
skin for the existing MaxSecu client. You are **reskinning**, not rebuilding. The app,
its components, its layout, and the **spacing of every element must stay identical** —
you change only colour, texture, imagery, borders, shadows, gradients, and decoration.

## Deliverables (exactly two files — see FRONTEND-GUIDE §9)

1. **`styles.pizza.css`** — a COMPLETE standalone stylesheet. Start from a copy of
   `styles.css` and restyle it. Keep every `--mx-*` spacing/radius/type token and the
   component selectors/structure; retheme the colour/surface/border tokens and add
   pizza texture (golden crust, tomato-red accents, molten-cheese gradients, drip
   edges via pseudo-elements). Do not alter layout or spacing.
2. **`src/frontends/pizza/deco.ts`** — implement `DecoModule` (`mount`/`unmount`,
   idempotent; see §9). On the login screens, inject the supplied **`assets/pizza.png`**
   into `[data-deco-slot="login"]` as the hero image, plus optional cheese-drip layers
   into `[data-deco-slot="app-bg"]`. Remove all injected nodes in `unmount`.

## Login page (required)

The login/connect screen MUST prominently feature **`assets/pizza.png`** (the dripping
cheese-pizza slice). It is the centerpiece of the pizza frontend's sign-in.

## Constraints

- Preserve the backend contract, serial queue, and security/a11y invariants.
- No new dependencies. Framework-free, CSP-safe (no external URLs/fonts; inline or
  local assets only). `npm run build`, `npm run typecheck`, `npm test`, and
  `npm run test:a11y` must all stay green.
- Colour must never be the ONLY signal (a11y): keep text/icon cues.

## How to preview

`npm install` then `npm run build`; serve `dist/` and select "Cheese Pizza" in
Settings → Appearance → Frontend (or set `localStorage["maxsecu.frontend"]="pizza"`).
```

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/assets/pizza.png crates/client-app/ui/PIZZA-BRIEF.md crates/client-app/ui/FRONTEND-GUIDE.md
git commit -m "docs(ui): pizza asset + cheese-pizza brief + multi-frontend contract in FRONTEND-GUIDE"
```

---

## Task 2: Assemble and deliver the ZIP (FIRST deliverable)

**Files:**
- Create: `maxsecu-pizza-frontend.zip` (repo root)

- [ ] **Step 1: Confirm the ZIP name is gitignored (build artifact, not tracked)**

Run (from repo root): `git check-ignore maxsecu-pizza-frontend.zip; echo "exit=$?"`
Expected: `exit=0` (ignored). If `exit=1`, add `maxsecu-*.zip` to the root `.gitignore` and commit that one-line change with message `chore(gitignore): ignore design-brief ZIPs`.

- [ ] **Step 2: Stage the UI tree without node_modules/dist and zip it**

Run in PowerShell (from repo root):
```powershell
$stage = Join-Path $env:TEMP "maxsecu-ui-zip"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
robocopy "crates\client-app\ui" "$stage\ui" /E /XD node_modules dist .git /NFL /NDL /NJH /NJS | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
Remove-Item "maxsecu-pizza-frontend.zip" -Force -ErrorAction SilentlyContinue
Compress-Archive -Path "$stage\ui" -DestinationPath "maxsecu-pizza-frontend.zip" -Force
```
Expected: no error; `maxsecu-pizza-frontend.zip` created at repo root.

- [ ] **Step 3: Verify contents (no node_modules/dist; brief + asset present)**

Run in PowerShell:
```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path "maxsecu-pizza-frontend.zip"))
$names = $z.Entries.FullName
$z.Dispose()
"total entries: $($names.Count)"
"has PIZZA-BRIEF: $([bool]($names -match 'ui/PIZZA-BRIEF.md'))"
"has pizza.png:   $([bool]($names -match 'ui/assets/pizza.png'))"
"has FRONTEND-GUIDE: $([bool]($names -match 'ui/FRONTEND-GUIDE.md'))"
"has styles.css:  $([bool]($names -match 'ui/styles.css'))"
"leaks node_modules: $([bool]($names -match 'node_modules'))"
"leaks dist: $([bool]($names -match 'ui/dist/'))"
```
Expected: brief/png/guide/styles = True; leaks = False.

- [ ] **Step 4: Deliver the ZIP to the user**

Use SendUserFile with `maxsecu-pizza-frontend.zip` and a caption noting it contains the UI source snapshot, `assets/pizza.png`, `PIZZA-BRIEF.md`, and the multi-frontend contract in `FRONTEND-GUIDE.md §9`. (No commit — the ZIP is a gitignored artifact.)

---

## Task 3: Frontend registry + switcher core (`frontends.ts`)

**Files:**
- Create: `crates/client-app/ui/src/core/frontends.ts`
- Test: `crates/client-app/ui/src/core/frontends.test.ts`
- Modify: `crates/client-app/ui/package.json` (add test file to `test` script)

- [ ] **Step 1: Write the failing test (pure functions only)**

Create `crates/client-app/ui/src/core/frontends.test.ts`:
```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeFrontend, frontendStylesheet, FRONTENDS } from "./frontends.ts";

test("normalizeFrontend accepts the three ids", () => {
  assert.equal(normalizeFrontend("default"), "default");
  assert.equal(normalizeFrontend("pizza"), "pizza");
  assert.equal(normalizeFrontend("slot3"), "slot3");
});

test("normalizeFrontend falls back to default for anything else", () => {
  assert.equal(normalizeFrontend("nope"), "default");
  assert.equal(normalizeFrontend(null), "default");
  assert.equal(normalizeFrontend(undefined), "default");
  assert.equal(normalizeFrontend(42), "default");
});

test("frontendStylesheet maps each id to its stylesheet file", () => {
  assert.equal(frontendStylesheet("default"), "styles.css");
  assert.equal(frontendStylesheet("pizza"), "styles.pizza.css");
  assert.equal(frontendStylesheet("slot3"), "styles.slot3.css");
});

test("FRONTENDS lists exactly the three ids in order", () => {
  assert.deepEqual(FRONTENDS.map((f) => f.id), ["default", "pizza", "slot3"]);
  for (const f of FRONTENDS) assert.ok(f.label.length > 0);
});
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/core/frontends.test.ts`
Expected: FAIL (cannot resolve `./frontends.ts`).

- [ ] **Step 3: Create `src/core/frontends.ts`**

```ts
// Frontend registry + runtime switcher. A "frontend" is a named visual skin: a
// complete stylesheet it owns (styles.<id>.css, swapped on the #frontend-css link)
// plus an optional decoration module that injects decorative DOM into data-deco-slot
// mount points. One shared component tree/backend serves all frontends. The choice is
// UI-local (localStorage), exactly like the retired theme presets. DOM/storage access
// is guarded so this module imports cleanly under node:test.
import { pizzaDeco } from "../frontends/pizza/deco.ts";

export type FrontendId = "default" | "pizza" | "slot3";

export interface DecoModule {
  mount(doc: Document): void;
  unmount(doc: Document): void;
}

export const FRONTENDS: ReadonlyArray<{ id: FrontendId; label: string }> = [
  { id: "default", label: "Default" },
  { id: "pizza", label: "Cheese Pizza" },
  { id: "slot3", label: "Custom (empty slot)" },
];

const FRONTEND_KEY = "maxsecu.frontend";

const STYLESHEETS: Record<FrontendId, string> = {
  default: "styles.css",
  pizza: "styles.pizza.css",
  slot3: "styles.slot3.css",
};

const DECO: Partial<Record<FrontendId, DecoModule>> = {
  pizza: pizzaDeco,
};

let activeDeco: DecoModule | null = null;

export function normalizeFrontend(value: unknown): FrontendId {
  return value === "pizza" || value === "slot3" || value === "default"
    ? value
    : "default";
}

export function frontendStylesheet(id: FrontendId): string {
  return STYLESHEETS[id];
}

export function getFrontend(): FrontendId {
  try {
    return normalizeFrontend(window.localStorage.getItem(FRONTEND_KEY));
  } catch {
    return "default";
  }
}

// Effect the frontend: swap stylesheet href + data-frontend attr, then unmount the
// previous deco and mount the new one (both wrapped so a broken deco never bricks the
// swap). Idempotent per id.
export function applyFrontend(value: unknown = getFrontend()): FrontendId {
  const id = normalizeFrontend(value);
  const link = document.getElementById("frontend-css");
  if (link) link.setAttribute("href", frontendStylesheet(id));
  document.documentElement.setAttribute("data-frontend", id);

  const next = DECO[id] ?? null;
  if (activeDeco && activeDeco !== next) {
    try { activeDeco.unmount(document); } catch { /* deco is non-critical */ }
  }
  activeDeco = next;
  if (activeDeco) {
    try { activeDeco.mount(document); } catch { /* deco is non-critical */ }
  }
  return id;
}

export function setFrontend(value: unknown): FrontendId {
  const id = normalizeFrontend(value);
  try {
    window.localStorage.setItem(FRONTEND_KEY, id);
  } catch {
    // Storage can be unavailable in tests / locked-down webviews; the frontend still
    // applies for this session via the DOM.
  }
  applyFrontend(id);
  return id;
}

// Re-run the active deco's idempotent mount (call after each route render so login-
// screen decoration appears once the screen is in the DOM).
export function refreshFrontendDeco(): void {
  if (activeDeco) {
    try { activeDeco.mount(document); } catch { /* deco is non-critical */ }
  }
}
```

- [ ] **Step 4: Create the stub deco so the import resolves**

Create `crates/client-app/ui/src/frontends/pizza/deco.ts`:
```ts
import type { DecoModule } from "../../core/frontends.ts";

// STUB — replaced wholesale by the external cheese-pizza design (see PIZZA-BRIEF.md).
// The real module injects assets/pizza.png into [data-deco-slot="login"] and cheese-
// drip layers into [data-deco-slot="app-bg"], and removes them in unmount().
export const pizzaDeco: DecoModule = {
  mount() { /* no-op stub */ },
  unmount() { /* no-op stub */ },
};
```

- [ ] **Step 5: Run the test to confirm it passes**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/core/frontends.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 6: Wire the test into the `test` npm script**

In `crates/client-app/ui/package.json`, in the `"test"` script string, add `src/core/frontends.test.ts` to the list (e.g. immediately after `src/core/settings-store.test.ts`).

- [ ] **Step 7: Confirm typecheck stays clean**

Run: `cd crates/client-app/ui && npm run typecheck`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add crates/client-app/ui/src/core/frontends.ts crates/client-app/ui/src/core/frontends.test.ts crates/client-app/ui/src/frontends/pizza/deco.ts crates/client-app/ui/package.json
git commit -m "feat(ui): frontend registry + runtime switcher core (frontends.ts) + pizza deco stub"
```

---

## Task 4: Stub stylesheets

**Files:**
- Create: `crates/client-app/ui/styles.pizza.css`
- Create: `crates/client-app/ui/styles.slot3.css`

- [ ] **Step 1: Create `styles.pizza.css`**

```css
/* Cheese-Pizza frontend stylesheet — STUB.
   Until the external cheese-pizza design lands (see PIZZA-BRIEF.md) this simply
   renders like Default. The external design REPLACES this file with a complete
   standalone stylesheet (dropping the @import). */
@import url("styles.css");
```

- [ ] **Step 2: Create `styles.slot3.css`**

```css
/* Third frontend slot — intentionally empty; falls back to the Default look until a
   future design round fills it. Replace with a complete standalone stylesheet then. */
@import url("styles.css");
```

- [ ] **Step 3: Commit**

```bash
git add crates/client-app/ui/styles.pizza.css crates/client-app/ui/styles.slot3.css
git commit -m "feat(ui): stub pizza/slot3 stylesheets (import default until authored)"
```

---

## Task 5: Wire `index.html` (link id, data-frontend, pre-paint bootstrap)

**Files:**
- Modify: `crates/client-app/ui/index.html`
- Test: `crates/client-app/ui/src/core/frontends.test.ts` (append source-lint asserts)

- [ ] **Step 1: Add source-lint asserts (failing) to `frontends.test.ts`**

Append to `crates/client-app/ui/src/core/frontends.test.ts`:
```ts
import { readFileSync } from "node:fs";

const html = readFileSync("index.html", "utf8");

test("index.html has a swappable #frontend-css stylesheet link defaulting to styles.css", () => {
  assert.match(html, /<link[^>]*id="frontend-css"[^>]*href="styles\.css"|<link[^>]*href="styles\.css"[^>]*id="frontend-css"/);
});

test("index.html defaults data-frontend and boots the persisted frontend pre-paint", () => {
  assert.match(html, /data-frontend="default"/);
  assert.match(html, /maxsecu\.frontend/);
  assert.doesNotMatch(html, /data-theme="tech"/);
});
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/core/frontends.test.ts`
Expected: the two new tests FAIL (index.html still has `data-theme="tech"` and no `#frontend-css`).

- [ ] **Step 3: Edit `index.html`**

Change line 2 from:
```html
<html lang="en" data-theme="tech">
```
to:
```html
<html lang="en" data-frontend="default">
```

Change the stylesheet link (line 7) from:
```html
    <link rel="stylesheet" href="styles.css" />
```
to:
```html
    <link id="frontend-css" rel="stylesheet" href="styles.css" />
    <script>
      /* Apply the persisted frontend before first paint (no flash). Mirrors
         STYLESHEETS in src/core/frontends.ts. */
      (function () {
        try {
          var f = localStorage.getItem("maxsecu.frontend");
          var map = { "default": "styles.css", "pizza": "styles.pizza.css", "slot3": "styles.slot3.css" };
          if (f && map[f]) {
            document.documentElement.setAttribute("data-frontend", f);
            var l = document.getElementById("frontend-css");
            if (l) l.setAttribute("href", map[f]);
          }
        } catch (e) { /* storage unavailable — keep default */ }
      })();
    </script>
```

- [ ] **Step 4: Run to confirm pass**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/core/frontends.test.ts`
Expected: PASS (all tests, incl. the two new ones).

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/index.html crates/client-app/ui/src/core/frontends.test.ts
git commit -m "feat(ui): index.html swappable frontend stylesheet + pre-paint bootstrap"
```

---

## Task 6: Retire theme presets in `settings.ts`; deco slots + refresh in the shell

**Files:**
- Modify: `crates/client-app/ui/src/core/settings.ts`
- Modify: `crates/client-app/ui/src/components/app-shell.ts`
- Modify: `crates/client-app/ui/src/components/connect-screen.ts`
- Modify: `crates/client-app/ui/src/components/register-screen.ts`
- Modify: `crates/client-app/ui/src/components/recovery-login-screen.ts`

- [ ] **Step 1: Replace the theme-preset code in `settings.ts`**

In `crates/client-app/ui/src/core/settings.ts`:

Delete the block defining `ThemePreset`, `THEME_PRESET_KEY`, `normalizeThemePreset`, `getThemePreset`, `setThemePreset`, and `applyThemePreset` (lines 14–45).

Add near the top (after the existing imports):
```ts
import { applyFrontend } from "./frontends.ts";
```

In `applySettings`, replace the `applyThemePreset();` call with:
```ts
  applyFrontend();
```
(Leave the rest of `applySettings` — the a11y data-attrs and `decodePool.setSize` — unchanged. Update the nearby comment that says "visual theme preset" to "active frontend".)

- [ ] **Step 2: Add deco slots + deco refresh to `app-shell.ts`**

In `crates/client-app/ui/src/components/app-shell.ts`:

Add to the imports from `../core/settings.ts` is unchanged; add a new import line:
```ts
import { refreshFrontendDeco } from "../core/frontends.ts";
```

In the `this.innerHTML = \`...\`` template, add an `app-bg` slot as the FIRST child (right after the opening backtick) and a `header` slot inside `.header-actions`:

- Insert immediately after the template's opening backtick, before `<header`:
```html
      <div data-deco-slot="app-bg" aria-hidden="true"></div>
```
- Change `.header-actions` from:
```html
        <div class="header-actions">
          <ram-gauge id="ram"></ram-gauge>
        </div>
```
to:
```html
        <div class="header-actions">
          <span data-deco-slot="header" aria-hidden="true"></span>
          <ram-gauge id="ram"></ram-gauge>
        </div>
```

At the END of the `new Router((incomingRoute) => { ... })` callback body — immediately after the `main?.focus();` line — add:
```ts
      refreshFrontendDeco();
```

- [ ] **Step 3: Add the login deco slot to the three auth screens**

In each of `connect-screen.ts`, `register-screen.ts`, `recovery-login-screen.ts`, add `data-deco-slot="login"` to the root `<main ...>` element's attributes.

For `connect-screen.ts`, change:
```html
      <main id="main" class="connect-main" tabindex="-1" aria-labelledby="cn-h">
```
to:
```html
      <main id="main" class="connect-main" tabindex="-1" aria-labelledby="cn-h" data-deco-slot="login">
```

For `register-screen.ts` and `recovery-login-screen.ts`, locate their root `<main id="main" ...>` line and append `data-deco-slot="login"` to its attributes (keep all existing attributes). Verify each has exactly one such `<main>`.

- [ ] **Step 4: Typecheck + full unit tests + a11y (nothing broke)**

Run:
```bash
cd crates/client-app/ui && npm run typecheck && npm test && npm run test:a11y
```
Expected: typecheck clean; all unit tests pass; a11y green. (No test referenced `getThemePreset/setThemePreset` except `settings-screen.ts`, updated next task — if `npm test` currently includes settings-screen only as source-lint it stays green; the typecheck will flag settings-screen's stale imports, which Task 7 fixes. If typecheck fails ONLY on `settings-screen.ts` theme-preset imports, proceed to Task 7 then re-run — note this expectation.)

> Because `settings-screen.ts` still imports the now-deleted `getThemePreset/setThemePreset`, `npm run typecheck` will fail on THAT file until Task 7. That is expected. Do the commit below (settings.ts + shell changes are self-consistent) and immediately continue to Task 7; the combined typecheck must be green by end of Task 7.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/settings.ts crates/client-app/ui/src/components/app-shell.ts crates/client-app/ui/src/components/connect-screen.ts crates/client-app/ui/src/components/register-screen.ts crates/client-app/ui/src/components/recovery-login-screen.ts
git commit -m "feat(ui): apply frontend in applySettings + deco slots (login/app-bg/header) + per-route deco refresh"
```

---

## Task 7: Settings screen — Frontend selector

**Files:**
- Modify: `crates/client-app/ui/src/components/settings-screen.ts`
- Test: `crates/client-app/ui/src/components/settings-screen.test.ts`

- [ ] **Step 1: Add a failing source-lint test for the Frontend select**

Append to `crates/client-app/ui/src/components/settings-screen.test.ts`:
```ts
test("Appearance offers a Frontend selector wired to get/setFrontend", () => {
  // A named select with the three frontend options.
  assert.match(src, /<select name="frontend">/, "Frontend <select> missing");
  for (const id of ["default", "pizza", "slot3"]) {
    assert.match(src, new RegExp(`<option value="${id}"`), `frontend option ${id} missing`);
  }
  // Wired to the frontends module on both load and change.
  assert.match(src, /getFrontend\(\)/, "load path must read getFrontend()");
  assert.match(src, /setFrontend\(/, "change path must call setFrontend()");
  // The retired theme-preset select is gone.
  assert.doesNotMatch(src, /<select name="theme">/, "old theme select must be removed");
});
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/components/settings-screen.test.ts`
Expected: the new test FAILS.

- [ ] **Step 3: Update the import in `settings-screen.ts`**

Change line 2 from:
```ts
import { settingsStore, updateSettings, loadAndApplySettings, getThemePreset, setThemePreset } from "../core/settings.ts";
```
to:
```ts
import { settingsStore, updateSettings, loadAndApplySettings } from "../core/settings.ts";
import { getFrontend, setFrontend } from "../core/frontends.ts";
```

- [ ] **Step 4: Replace the Appearance select markup**

Change the Appearance fieldset body (lines 33–39) from:
```html
              <label>Theme
                <select name="theme">
                  <option value="tech">Tech (default)</option>
                  <option value="cheese">Cheese</option>
                  <option value="pottery">Pottery</option>
                </select></label>
              <p class="hint">Theme presets are placeholders for upcoming visual passes.</p>
```
to:
```html
              <label>Frontend
                <select name="frontend">
                  <option value="default">Default</option>
                  <option value="pizza">Cheese Pizza</option>
                  <option value="slot3">Custom (empty slot)</option>
                </select></label>
              <p class="hint">Switches the whole visual frontend (its own stylesheet &amp; decoration). Applies immediately.</p>
```

- [ ] **Step 5: Update the save path**

Change `setThemePreset(this.sel("theme").value);` (line 198) to:
```ts
    setFrontend(this.sel("frontend").value);
```

- [ ] **Step 6: Update the load path**

Change `this.sel("theme").value = getThemePreset();` (line 232) to:
```ts
    this.sel("frontend").value = getFrontend();
```

- [ ] **Step 7: Run the settings-screen test to confirm pass**

Run: `cd crates/client-app/ui && node --experimental-strip-types --test src/components/settings-screen.test.ts`
Expected: PASS (incl. the new test).

- [ ] **Step 8: Full typecheck + tests + a11y all green now**

Run:
```bash
cd crates/client-app/ui && npm run typecheck && npm test && npm run test:a11y
```
Expected: typecheck clean (the stale-import failure from Task 6 is resolved); all tests + a11y pass.

- [ ] **Step 9: Commit**

```bash
git add crates/client-app/ui/src/components/settings-screen.ts crates/client-app/ui/src/components/settings-screen.test.ts
git commit -m "feat(ui): Settings Appearance -> Frontend selector wired to get/setFrontend"
```

---

## Task 8: Build pipeline — copy all stylesheets + pizza.png into dist

**Files:**
- Create: `crates/client-app/ui/scripts/copy-assets.mjs`
- Modify: `crates/client-app/ui/package.json` (`build` script)

- [ ] **Step 1: Create `scripts/copy-assets.mjs`**

```js
// Post-bundle copy step: place index.html, every frontend stylesheet, and the pizza
// asset into dist/ (which the Tauri exe embeds at compile time).
import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist/assets", { recursive: true });

for (const f of ["index.html", "styles.css", "styles.pizza.css", "styles.slot3.css"]) {
  copyFileSync(f, `dist/${f}`);
}
copyFileSync("assets/pizza.png", "dist/assets/pizza.png");

console.log("copied: index.html + 3 stylesheets + assets/pizza.png -> dist/");
```

- [ ] **Step 2: Point the build script at it**

In `crates/client-app/ui/package.json`, replace the `"build"` script value:
```json
    "build": "esbuild src/main.ts --bundle --format=esm --outfile=dist/main.js && node scripts/copy-assets.mjs",
```

- [ ] **Step 3: Run the build**

Run: `cd crates/client-app/ui && npm run build`
Expected: esbuild succeeds; the copy step prints the "copied:" line; no errors.

- [ ] **Step 4: Verify dist contains all frontend assets**

Run: `cd crates/client-app/ui && ls dist && ls dist/assets`
Expected: `dist/` contains `main.js`, `index.html`, `styles.css`, `styles.pizza.css`, `styles.slot3.css`; `dist/assets/` contains `pizza.png`.

- [ ] **Step 5: Final full green (typecheck + tests + a11y + build)**

Run:
```bash
cd crates/client-app/ui && npm run typecheck && npm test && npm run test:a11y && npm run build
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/ui/scripts/copy-assets.mjs crates/client-app/ui/package.json
git commit -m "build(ui): copy all frontend stylesheets + pizza.png into dist"
```

---

## Task 9: Manual verification (webview switch)

**Files:** none (verification only)

- [ ] **Step 1: Verify the default frontend is unchanged**

Serve `crates/client-app/ui/dist/` (e.g. `npx serve dist` or the project's mock-bridge harness per FRONTEND-GUIDE §8) and load it. Confirm the app looks identical to before (default frontend, `data-frontend="default"` on `<html>`, `#frontend-css` → `styles.css`).

- [ ] **Step 2: Verify switching persists + swaps stylesheet**

In the served app, open Settings → Appearance → Frontend and select **Cheese Pizza**. Confirm: `<html data-frontend="pizza">`, `#frontend-css` href → `styles.pizza.css` (renders like Default via the stub `@import` — expected until the external design lands), and no console errors. Reload; confirm the choice persists (localStorage `maxsecu.frontend=pizza`, applied pre-paint with no flash to default). Switch back to **Default**; confirm it restores.

- [ ] **Step 3: Confirm the ZIP is still the intended handoff**

Re-open `maxsecu-pizza-frontend.zip` from Task 2 and confirm it contains `ui/PIZZA-BRIEF.md`, `ui/FRONTEND-GUIDE.md` (with §9), and `ui/assets/pizza.png`. (No need to re-zip unless UI source changed materially since Task 2 — if so, re-run Task 2's PowerShell to refresh, since the scaffold now makes the zipped source build the pizza slot end-to-end.)

---

## Self-Review notes (addressed)

- **Spec coverage:** frontend concept + registry (T3), complete stylesheet per id + stubs (T4), runtime switch/persist/no-flash (T3+T5), deco slots (T6), settings selector (T7), build + all-green tests (T3–T8), ZIP + brief + FRONTEND-GUIDE §9 (T1–T2). Non-goals (no backend/types/RPC change; empty slots inert) respected.
- **Deviation logged:** Default keeps `styles.css` (not renamed) — noted at top; lowers risk, keeps existing `styles.css` readers/tests green.
- **Type consistency:** `FrontendId`, `DecoModule.mount(doc)/unmount(doc)`, `normalizeFrontend`, `frontendStylesheet`, `getFrontend/setFrontend/applyFrontend/refreshFrontendDeco`, `STYLESHEETS` map, and the `index.html` bootstrap `map` all agree across tasks. `<select name="frontend">` values (`default/pizza/slot3`) match `normalizeFrontend` and the bootstrap map.
- **Ordering caveat:** Task 6 intentionally leaves typecheck red on `settings-screen.ts` stale imports until Task 7 — called out explicitly so the worker doesn't chase it.
