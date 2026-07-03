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

  test(`${vpPath}: native transport controls are present + keyboard-operable`, () => {
    // Playback goes through a native <video> element driven by Media Chrome;
    // the library's custom elements are themselves keyboard-operable and
    // labeled, so this asserts the native transport is actually wired up.
    for (const el of [
      "<media-controller",
      "<media-play-button",
      "<media-mute-button",
      "<media-volume-range",
      "<media-time-range",
      "<media-playback-rate-button",
      "<media-loading-indicator",
      "<media-fullscreen-button",
    ]) {
      assert.match(vp, new RegExp(el.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), `missing ${el} native control`);
    }
    // Keyboard hotkeys (space/k play-pause, arrows seek, f fullscreen, m mute)
    // are enabled by default within a focused media-controller — must not be
    // disabled via the nohotkeys attribute.
    assert.doesNotMatch(vp, /nohotkeys/, "video-player must not disable Media Chrome keyboard hotkeys");
  });

  test(`${vpPath}: non-color-only state text (WCAG 1.4.1)`, () => {
    // State is conveyed by TEXT (not color alone): the aria-live status region
    // exists and carries a visible error message when the native decoder fails.
    assert.match(vp, /role="status"/, "video-player needs a role=status live region");
    assert.match(vp, /could not be played/i, "video-player must surface a text error state");
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

  test("upload-screen video resolution/bitrate controls are present + labelled", () => {
    const up = readFileSync("src/components/upload-screen.ts", "utf8");
    // The video flow ingests a REAL video file (no MXRAWV01 raw-frame sample).
    assert.doesNotMatch(up, /MXRAWV01|source_b64|sampleSourceB64/, "no raw-frame/source_b64 video path");
    // Resolution + bitrate menu controls must each be present and named so they
    // are picked up by FormData; each lives inside a wrapping <label>.
    for (const n of ["resolution", "cw", "ch", "kbps", "origbitrate"]) {
      assert.match(up, new RegExp(`name="${n}"`), `video upload missing the "${n}" control`);
    }
    // Wrapping-<label> pattern: a labelled <select> for resolution and labelled
    // number inputs for the custom dims + bitrate (no orphan controls).
    assert.match(up, /<label>Resolution[\s\S]*?name="resolution"/, "Resolution select must be labelled");
    assert.match(up, /<label>Custom width[\s\S]*?name="cw"/, "Custom width must be labelled");
    assert.match(up, /<label>Custom height[\s\S]*?name="ch"/, "Custom height must be labelled");
    assert.match(up, /<label>Bitrate[\s\S]*?name="kbps"/, "Bitrate input must be labelled");
    assert.match(up, /<label><input name="origbitrate"/, "Original-bitrate checkbox must be labelled");
  });

  test("upload-screen live transcode progress + Cancel are present + labelled", () => {
    const up = readFileSync("src/components/upload-screen.ts", "utf8");
    // A <progress> element carries an accessible name (aria-label) for the
    // transcode; status text goes through the existing #up-status live region.
    assert.match(up, /createElement\("progress"\)/, "transcode progress uses a <progress> element");
    assert.match(up, /"aria-label",\s*"Transcode progress"/, "the <progress> must be labelled");
    // A Cancel control that calls cancel_video_prepare and disables itself to
    // avoid a double-fire.
    assert.match(up, /"Cancel"/, "a Cancel control must be present");
    assert.match(up, /cancel_video_prepare/, "Cancel must call cancel_video_prepare");
    assert.match(up, /cancelBtn\.disabled\s*=\s*true/, "Cancel must disable itself on click");
    // Progress text is set via textContent, never innerHTML interpolation.
    assert.match(up, /status\.textContent\s*=/, "status updates via textContent");
  });

  test("settings screen exposes a labelled Theme + RAM control", () => {
    const set = readFileSync("src/components/settings-screen.ts", "utf8");
    assert.match(set, /Theme/, "Theme control present");
    assert.match(set, /aria-label|<label|name="theme"/, "controls labelled");
    // The RAM cache cap uses a range slider (built via DOM API or literal HTML).
    assert.match(set, /type="range"|\.type\s*=\s*"range"/, "RAM cap uses a range slider");
  });

  test("ram-gauge is a labelled meter", () => {
    const rg = readFileSync("src/components/ram-gauge.ts", "utf8");
    assert.match(rg, /role="meter"/, "RAM gauge is a meter");
    assert.match(rg, /aria-valuemin|aria-valuenow/, "RAM gauge exposes aria value");
    assert.match(rg, /aria-label/, "RAM gauge is labelled (non-colour-only)");
  });
}

// --- T4 multi-recipient sharing: <share-dialog> / <share-tray> -------------
// Neither is a full routed screen (share-dialog is a modal opened from
// media-viewer/feed-screen; share-tray is a background tray like
// upload-tray), so — matching how <video-player> and <ram-gauge> above get
// their own dedicated per-component blocks rather than joining `screens` —
// each gets its own structural-lint block here.
{
  const sdPath = "src/components/share-dialog.ts";
  const sd = readFileSync(sdPath, "utf8");

  test(`${sdPath}: labelled modal dialog`, () => {
    // The picker panel must be a properly labelled modal dialog (WCAG 4.1.2 /
    // 2.4.6): role="dialog", aria-modal="true", and an aria-labelledby
    // pointing at a real heading id.
    assert.match(sd, /role="dialog"/, "share-dialog panel needs role=\"dialog\"");
    assert.match(sd, /aria-modal="true"/, "share-dialog panel needs aria-modal=\"true\"");
    assert.match(sd, /aria-labelledby="sd-h"/, "share-dialog panel needs aria-labelledby");
    assert.match(sd, /id="sd-h"/, "the aria-labelledby target heading must exist");
  });

  test(`${sdPath}: focus trap + focus return on close`, () => {
    // A modal must trap Tab/Shift+Tab within itself (WCAG 2.4.3) and return
    // focus to the control that opened it once it closes.
    assert.match(sd, /e\.key === "Tab"/, "share-dialog must intercept Tab for its focus trap");
    assert.match(sd, /e\.shiftKey/, "share-dialog's trap must branch on Shift+Tab");
    assert.match(sd, /trapTab/, "share-dialog must have a dedicated trap-tab handler");
    assert.match(sd, /invoker\??\.focus\(\)/, "share-dialog must return focus to the invoker on close");
  });

  test(`${sdPath}: Escape closes the dialog`, () => {
    assert.match(sd, /e\.key === "Escape"/, "share-dialog must handle Escape to close");
  });

  test(`${sdPath}: recipient status is not color-only (state-badge + text label)`, () => {
    // Every row's status goes through <state-badge> with an explicit text
    // label (badgeFor() returns a `label` alongside `state`), never color
    // alone (WCAG 1.4.1).
    assert.match(sd, /createElement\("state-badge"\)/, "recipient rows must render a <state-badge>");
    assert.match(
      sd,
      /badge\.setAttribute\("label",\s*label\)/,
      "the state-badge must be given a text label, not just a state/colour",
    );
  });

  test(`${sdPath}: interactive controls are real focusable elements`, () => {
    // Add/Share/Retry/Remove/Close must be actual <button>/<input> elements
    // (keyboard- and AT-reachable by default), not click-only <div>/<span>.
    assert.match(sd, /id="sd-close"/, "Close must be a real button");
    assert.match(sd, /type="submit"/, "Add must submit a real <form> (keyboard-activatable)");
    assert.match(sd, /id="sd-username"/, "the username field must be a real <input>");
    assert.match(sd, /id="sd-share-btn"/, "Share must be a real button");
    assert.match(sd, /retry\.type\s*=\s*"button"/, "Retry rows must create a real <button>");
    assert.match(sd, /remove\.type\s*=\s*"button"/, "Remove rows must create a real <button>");
    // Guard against a regression to click-only divs: no element built via
    // createElement("div"/"span") should carry its own click listener in this
    // file (all actions above go through button/form elements instead).
    assert.doesNotMatch(
      sd,
      /createElement\("(div|span)"\)[\s\S]{0,200}addEventListener\("click"/,
      "share-dialog must not wire click handlers onto non-interactive div/span elements",
    );
  });

  test(`${sdPath}: no unescaped innerHTML interpolation (XSS guard)`, () => {
    assert.doesNotMatch(
      sd,
      /\.innerHTML\s*=\s*`[^`]*\$\{(?!esc\()/,
      "share-dialog must not interpolate unescaped dynamic data into innerHTML",
    );
  });

  const stPath = "src/components/share-tray.ts";
  const st = readFileSync(stPath, "utf8");

  test(`${stPath}: aria-live region for background progress`, () => {
    // The row list is a polite live region (background progress must not
    // require focus to be discovered) — mirrors upload-tray's pattern.
    assert.match(st, /id="st-list"\s+aria-live="polite"/, "share-tray list must be an aria-live=\"polite\" region");
  });

  test(`${stPath}: role="alert" is used ONLY for the terminal all-failed case`, () => {
    // A fully or partially successful outcome must stay polite (role removed
    // or absent); only shared==0 && failed>0 escalates to assertive. Assert
    // both branches exist: the escalation on allFailed, and an explicit
    // removeAttribute("role") on the partial/success branches so "alert" is
    // never left on from a prior render.
    assert.match(
      st,
      /allFailed[\s\S]{0,120}li\.setAttribute\("role",\s*"alert"\)/,
      "role=\"alert\" must be set only inside the allFailed branch",
    );
    const roleAlertCount = (st.match(/setAttribute\("role",\s*"alert"\)/g) ?? []).length;
    assert.equal(roleAlertCount, 1, "role=\"alert\" must be set from exactly one place (the allFailed branch)");
    const removeRoleCount = (st.match(/removeAttribute\("role"\)/g) ?? []).length;
    assert.ok(
      removeRoleCount >= 2,
      "the partial-success and full-success branches must both clear role=\"alert\" (no stale assertive state)",
    );
  });

  test(`${stPath}: status is not color-only (state-badge + text label)`, () => {
    assert.match(st, /createElement\("state-badge"\)/, "share-tray rows must render a <state-badge>");
    assert.match(
      st,
      /badge\.setAttribute\("label",/,
      "the state-badge must be given a text label, not just a state/colour",
    );
  });

  test(`${stPath}: Dismiss is a real keyboard-reachable button`, () => {
    assert.match(st, /createElement\("button"\)/, "Dismiss must be a real <button> element");
    assert.match(st, /btn\.type\s*=\s*"button"/, "Dismiss button must have type=\"button\"");
    assert.match(st, /"Dismiss"/, "Dismiss must carry a visible text label");
    assert.match(st, /aria-label",\s*"Dismiss sharing result"/, "Dismiss must have an accessible name");
  });

  test(`${stPath}: no unescaped innerHTML interpolation (XSS guard)`, () => {
    assert.doesNotMatch(
      st,
      /\.innerHTML\s*=\s*`[^`]*\$\{(?!esc\()/,
      "share-tray must not interpolate unescaped dynamic data into innerHTML",
    );
  });
}

