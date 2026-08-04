import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Source-structural assertions on the routed feed screen (F3 numbered paging).
// The screen imports the Tauri API (via core/rpc.ts) so it cannot be mounted in
// plain Node; the arithmetic it depends on lives in core/paging.ts and IS really
// unit-tested (core/paging.test.ts). What this file pins is the load-bearing
// wiring that a regression would quietly undo.
const src = readFileSync("src/components/feed-screen.ts", "utf8");
const css = readFileSync("styles.css", "utf8");
const pizza = readFileSync("styles.pizza.css", "utf8");
const slot3 = readFileSync("styles.slot3.css", "utf8");

// --- The request: paging parameters actually reach the backend --------------

test("feed-screen sends limit + offset on every listing fetch", () => {
  assert.match(src, /"list_feed"/, "the screen must drive list_feed");
  assert.match(src, /limit:\s*PAGE_SIZE/, "the fetch must carry an explicit limit");
  assert.match(src, /offset:\s*offsetFor\(/, "the fetch must carry a computed offset");
});

test("feed-screen asks the server for the owner filter on #/mine", () => {
  // #/mine is a REAL server-side owner-filtered listing now, not a per-card cull.
  assert.match(src, /owner_me:\s*this\.mineOnly/, "the fetch must carry the owner filter");
});

test("the seam field names stay snake_case inside the req struct", () => {
  // Tauri v2: top-level scalar args are camelCase in JS, but fields INSIDE a
  // `req:` struct stay snake_case. `owner_me` camelCased would bind to nothing.
  assert.doesNotMatch(src, /ownerMe:/, "owner_me must not be camelCased inside req");
});

// --- Page-1 reset semantics --------------------------------------------------

test("changing the type filter or the sort resets to page 1", () => {
  // The change handler reads both selects and must zero the page in the same
  // block — a different filter/sort is a different result set.
  const handler = src.match(/form\.addEventListener\("change"[\s\S]*?\n    \}\);/)?.[0];
  assert.ok(handler, "the controls form must have a change handler");
  assert.match(handler, /this\.filter\s*=/, "the handler must read the type filter");
  assert.match(handler, /this\.sort\s*=/, "the handler must read the sort");
  assert.match(handler, /this\.page\s*=\s*0/, "changing filter/sort must reset to page 1");
});

// --- THE OLD-SERVER RULE ------------------------------------------------------

test("no pager is rendered when the server reported no total", () => {
  // An un-upgraded server ignores offset/cursor and returns page 1 forever; its
  // body has no `total`. The screen must render NO pager in that case and fall
  // back to today's plain "N item(s)." line.
  assert.match(src, /shouldShowPager\(/, "the pager must be gated on shouldShowPager");
  assert.match(
    src,
    /if\s*\(this\.total === null\)\s*\{[\s\S]{0,400}?nav\.hidden = true/,
    "a null total must hide the pager outright",
  );
  assert.match(src, /item\(s\)\./, "the legacy status line must survive for an old server");
});

test("the old-server downgrade guard snaps back to page 1 and cannot loop", () => {
  // If a paginating server is replaced by an old one between two loads, the
  // response we get for offset>0 is really page 1 — snap to page 1 and reload
  // ONCE (bounded by `retried`), never in a loop.
  assert.match(src, /page\.total === null && offsetFor\(/, "must detect an ignored offset");
  assert.match(src, /this\.retried\s*=\s*true/, "the reload must be one-shot");
  assert.match(src, /!this\.retried/, "the retry must be guarded");
});

test("the per-card owner cull is wired ONLY on the legacy path", () => {
  // On a paginating server the owner filter already ran server-side, so the
  // media-card `mine-only` self-removal would be dead code that could only ever
  // silently drop a row — and would contradict the honest total.
  assert.match(
    src,
    /if\s*\(this\.mineOnly && this\.total === null\)\s*card\.setAttribute\("mine-only"/,
    "mine-only must be set only when the server did not filter",
  );
});

// --- Rendering + status -------------------------------------------------------

test("numbered pages REPLACE the grid (never append)", () => {
  const render = src.match(/private renderEntries\([\s\S]*?\n  \}/)?.[0];
  assert.ok(render, "renderEntries must exist");
  assert.match(render, /grid\.replaceChildren\(\)/, "each page must replace the grid");
});

test("the status line reports the honest total when the server paginates", () => {
  assert.match(src, /showingLabel\(this\.page, PAGE_SIZE, this\.total\)/,
    "a paginating server's status line must come from showingLabel");
});

test("the pager host is in the STATIC template and carries an accessible name", () => {
  // The a11y lint rejects `${}` inside an innerHTML template, so the <nav> host
  // must be static; its buttons are built by core/pager.ts via createElement.
  assert.match(
    src,
    /<nav id="fd-pager"[^>]*aria-label="Feed pages"[^>]*hidden><\/nav>/,
    "the pager host must be a static, labelled, initially-hidden <nav>",
  );
  assert.doesNotMatch(src, /onclick=/, "no inline handlers");
  assert.match(src, /renderPager\(/, "the pager must be built by the shared core/pager.ts helper");
});

test("local search hides the pager (it bypasses the paginated listing)", () => {
  const search = src.match(/private async runSearch\([\s\S]*?\n  \}\n\}/)?.[0];
  assert.ok(search, "runSearch must exist");
  assert.match(search, /nav\.hidden = true/, "search results must not show a page control");
  assert.match(search, /"search_local"/, "search still goes to the local index");
});

// --- The shared pager control: accessibility ---------------------------------

{
  const pager = readFileSync("src/core/pager.ts", "utf8");

  test("pager controls are real, labelled, keyboard-reachable buttons", () => {
    assert.match(pager, /createElement\("button"\)/, "controls must be real <button>s");
    assert.match(pager, /b\.type = "button"/, 'buttons need type="button"');
    assert.match(pager, /setAttribute\("aria-label", label\)/, "every control needs a name");
    assert.match(pager, /`Page \$\{slot \+ 1\}`/, "numbers need a spoken name, not a bare digit");
    assert.match(pager, /"Previous page"/, "Prev needs an accessible name");
    assert.match(pager, /"Next page"/, "Next needs an accessible name");
    assert.match(pager, /setAttribute\("aria-current", "page"\)/, "the current page must be marked");
  });

  test("the pager never traps focus on a destroyed button", () => {
    // Each page switch rebuilds the control; without this the focused button is
    // removed and focus falls to <body>.
    assert.match(pager, /wanted\?\.focus\(\)/, "focus must be restored after a re-render");
  });

  test("the ellipsis is decorative, not an announced control", () => {
    assert.match(
      pager,
      /gap\.setAttribute\("aria-hidden", "true"\)/,
      "the … slot must be hidden from assistive tech",
    );
  });
}

// --- The pager is styled in ALL THREE shipped skins ---------------------------

for (const [name, raw] of [["styles.css", css], ["styles.pizza.css", pizza], ["styles.slot3.css", slot3]] as const) {
  test(`${name} styles the numbered pager`, () => {
    // Strip /* … */ first. Each of these rules is DESCRIBED in a comment right
    // above it, so matching the raw text lets the comment satisfy the assertion:
    // deleting the whole real `.pager { display: flex; … }` block still passed
    // until the comment was edited too (proven by execution, not by reading).
    const sheet = raw.replace(/\/\*[\s\S]*?\*\//g, "");
    // Each skin redefines #grid and .feed-refresh independently, so an unstyled
    // pager in pizza or slot3 is a real bug, not a cosmetic one. `[^}]*` keeps the
    // match INSIDE the rule body — an unbounded `[\s\S]*?` was satisfied by any
    // later `display: flex` anywhere in the file.
    assert.match(sheet, /\.pager\s*\{[^}]*display:\s*flex/, `${name} must lay the pager out`);
    // Load-bearing: `.pager { display: flex }` outranks the UA's
    // `[hidden] { display: none }`, so without this rule the "no pager" state
    // (old server, or a single-page listing) would still paint an empty strip.
    assert.match(
      sheet,
      /\.pager\[hidden\]\s*\{\s*display:\s*none/,
      `${name} must keep a hidden pager hidden`,
    );
    assert.match(sheet, /\.pager-btn\s*\{/, `${name} must style the pager buttons`);
    assert.match(sheet, /\.pager-btn\.active/, `${name} must mark the current page`);
    assert.match(sheet, /\.pager-btn:disabled/, `${name} must style the disabled ends`);
    assert.match(sheet, /\.pager-gap\s*\{/, `${name} must style the ellipsis slot`);
  });
}
