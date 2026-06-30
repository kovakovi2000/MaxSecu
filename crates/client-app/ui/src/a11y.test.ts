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

// --- Phase 7 (sandboxed video) §5.3: <video-player> chrome -----------------
// <video-player> is a focusable media region with fully keyboard-operable,
// labeled transport controls and non-color-only (text + icon) state. It is an
// embedded component (mounted by media-viewer), NOT a routed screen, so it gets
// its own structural-lint block rather than joining the `screens` list above.
{
  const vpPath = "src/components/video-player.ts";
  const vp = readFileSync(vpPath, "utf8");

  test(`${vpPath}: focusable region + focus on mount + live region`, () => {
    // A labeled region with tabindex="-1" that receives focus on mount (WCAG
    // 2.4.3), plus an aria-live status region for the player state machine.
    assert.match(vp, /tabindex="-1"/, "video-player needs a focusable region (tabindex=-1)");
    assert.match(vp, /\.focus\(\)/, "video-player must move focus to its region on mount");
    assert.match(vp, /aria-live/, "video-player needs an aria-live status region");
  });

  test(`${vpPath}: transport controls are labeled + keyboard-operable`, () => {
    // play/pause, volume and mute are labeled (aria-label / <label>); the
    // scrubber is a native range (keyboard-operable, exposes its value) or
    // carries aria-valuenow, and shows a played-vs-loaded (buffered) indication.
    assert.match(vp, /aria-label|<label/, "controls must be labeled (aria-label / <label>)");
    for (const label of ["Play", "Pause", "Mute", "Volume"]) {
      assert.match(vp, new RegExp(label), `missing ${label} control text/label`);
    }
    assert.match(
      vp,
      /type="range"|aria-valuenow/,
      "scrubber must be an <input type=range> or carry aria-valuenow",
    );
    assert.match(vp, /loaded|buffered/i, "scrubber must show a loaded/buffered indication");
  });

  test(`${vpPath}: non-color-only state text + decode-worker-pending badge`, () => {
    // State is conveyed by TEXT (not color alone, WCAG 1.4.1): every phase has a
    // visible label, plus a "decode worker pending" badge.
    for (const s of ["Buffering", "Playing", "Stalled", "Error", "Codec unavailable"]) {
      assert.match(vp, new RegExp(s), `state text "${s}" must appear in source`);
    }
    assert.match(vp, /Decode worker pending/i, "a 'decode worker pending' badge text must appear");
  });

  test(`${vpPath}: HW-decode waiver default-off + prominent warning`, () => {
    // The hardware-decode waiver defaults OFF and carries an unmistakable TEXT
    // warning that enabling it trades sandbox containment (not recommended).
    assert.match(vp, /hardware|hw-decode|hwDecode/i, "HW-decode waiver toggle must be present");
    assert.match(vp, /not recommended/i, "HW-decode waiver must carry a prominent warning");
    assert.match(vp, /sandbox/i, "warning must explain the sandbox-containment trade-off");
  });

  test(`${vpPath}: no unescaped innerHTML interpolation (XSS guard)`, () => {
    assert.doesNotMatch(
      vp,
      /\.innerHTML\s*=\s*`[^`]*\$\{(?!esc\()/,
      "video-player must not interpolate unescaped dynamic data into innerHTML",
    );
  });
}

// --- UI-overhaul affordances (this plan) -----------------------------------
{
  const shell = readFileSync("src/components/app-shell.ts", "utf8");
  const toastHost = readFileSync("src/components/toast-host.ts", "utf8");

  test("shell exposes a real My Content link (not a dead span)", () => {
    // The shell builds nav hrefs from a NAV table (`href="#/${n.route}"`), so the
    // literal "#/mine" isn't in source — assert the mine route is wired into NAV.
    assert.match(shell, /#\/mine|route:\s*"mine"/, "shell must wire the #/mine route");
    assert.match(shell, /My Content/, "My Content label present");
    assert.doesNotMatch(
      shell,
      /<span>\s*My Content\s*<\/span>/,
      "My Content must be a link, not a span",
    );
  });

  test("shell status strip + active-tasks live region", () => {
    assert.match(shell, /status-strip/, "status strip present");
    assert.match(shell, /tasks-ind/, "active-tasks indicator present");
    assert.match(shell, /aria-live/, "status strip uses a live region");
  });

  test("toast host has assertive + polite live regions, no raw innerHTML interpolation", () => {
    assert.match(toastHost, /aria-live="assertive"/, "errors are assertive");
    assert.match(toastHost, /aria-live="polite"/, "non-errors are polite");
    assert.match(toastHost, /textContent/, "toast text via textContent");
    assert.doesNotMatch(
      toastHost,
      /\.innerHTML\s*=\s*`[^`]*\$\{(?!esc\()/,
      "toast-host must not interpolate unescaped data into innerHTML",
    );
  });

  test("quick-settings + settings expose a labelled Theme + RAM control", () => {
    const qs = readFileSync("src/components/quick-settings.ts", "utf8");
    const set = readFileSync("src/components/settings-screen.ts", "utf8");
    for (const src of [qs, set]) {
      assert.match(src, /Theme/, "Theme control present");
      assert.match(src, /aria-label|<label|name="theme"/, "controls labelled");
    }
    // quick-settings builds the slider via the DOM API (`range.type = "range"`),
    // not literal HTML — accept either form.
    assert.match(qs, /type="range"|\.type\s*=\s*"range"/, "quick-settings RAM uses a range slider");
  });
}
