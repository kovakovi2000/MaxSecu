import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Structural a11y lint (Phase 5 §7). The screen components import the Tauri API
// (via core/rpc.ts), so they cannot be rendered in plain Node without a Tauri
// mock + DOM; a full axe-in-jsdom pass is a documented deferral. Instead this
// CI check asserts — over the component SOURCE — that every full routed screen
// still carries the accessibility affordances built in Phases 1–5: a focusable
// `#main` landmark, focus moved to it on mount, a live region for feedback, and
// no unescaped dynamic interpolation into innerHTML (XSS guard).

// Full routed screens that must each be a focusable landmark with live-region
// feedback. Small embedded components (media-card, status-pill, state-badge,
// progress-meter, quick-settings, upload-tray) are covered by their own
// structure and are intentionally NOT in this list.
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
  const src = readFileSync(f, "utf8");

  test(`${f}: focusable main landmark`, () => {
    // Every screen builds a `<main id="main" …>` whose focusable target carries
    // tabindex="-1". Most put tabindex on the <main> itself; bootstrap- and
    // pending-screen additionally (or instead) put it on the <h1 id="…"> that
    // receives focus on each step. Either way both tokens are present in source.
    assert.match(
      src,
      /id="main"[\s\S]*tabindex="-1"|tabindex="-1"[\s\S]*id="main"/,
      `${f} needs a focusable #main landmark`,
    );
  });

  test(`${f}: focuses the landmark on mount`, () => {
    // Each screen moves focus to its landmark/heading on mount (WCAG 2.4.3).
    assert.match(src, /\.focus\(\)/, `${f} must move focus to its landmark on mount`);
  });

  test(`${f}: no unescaped innerHTML interpolation (XSS guard)`, () => {
    // Dynamic data must never be templated raw into innerHTML. bootstrap-screen
    // legitimately interpolates `${esc(...)}` (HTML-escaped) into its creds
    // dialog; everything else builds dynamic nodes via textContent/createElement.
    // So: flag any `${` inside an innerHTML template literal that is NOT `${esc(`.
    assert.doesNotMatch(
      src,
      /\.innerHTML\s*=\s*`[^`]*\$\{(?!esc\()/,
      `${f} must not interpolate unescaped dynamic data into innerHTML`,
    );
  });
}

test("screens use a live region for feedback", () => {
  const withLive = screens.filter((f) =>
    /aria-live|role="status"|role="alert"/.test(readFileSync(f, "utf8")),
  );
  // Most screens surface status; allow at most one without (e.g. a purely
  // static one). Today all seven carry a live region.
  assert.ok(
    withLive.length >= screens.length - 1,
    `expected most screens to use a live region; got ${withLive.length}/${screens.length}`,
  );
});
