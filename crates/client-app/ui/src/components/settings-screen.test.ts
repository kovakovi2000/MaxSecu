import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Source-structural lint for the Settings screen's performance knobs (Bundles
// Task 7.4). The screen imports the Tauri API (via core/rpc.ts) so it cannot be
// mounted in plain Node; instead we assert — over the component SOURCE — that
// the three performance controls exist as labelled <input>s and are wired into
// both the load (writeControls) and save (onPrefChange) paths, and that the
// physical-core max is surfaced via the `system_cores` command.
const src = readFileSync("src/components/settings-screen.ts", "utf8");

const knobs = ["feed_concurrency", "transcode_threads", "decode_threads"];

for (const name of knobs) {
  test(`settings-screen has a labelled <input name="${name}">`, () => {
    // A named number/range input for the knob…
    assert.match(
      src,
      new RegExp(`<input[^>]*name="${name}"`),
      `missing the ${name} input control`,
    );
    // …that lives inside a wrapping <label> (the codebase's labelling pattern).
    assert.match(
      src,
      new RegExp(`<label>[^<]*<input[^>]*name="${name}"`),
      `the ${name} input must be wrapped in a <label>`,
    );
  });
}

test("feed_concurrency is bounded 1..=8", () => {
  assert.match(src, /name="feed_concurrency"[^>]*min="1"[^>]*max="8"|name="feed_concurrency"[^>]*max="8"[^>]*min="1"/,
    "feed_concurrency must carry min=1 max=8");
});

test("thread inputs carry min=1 (core max set dynamically)", () => {
  assert.match(src, /name="transcode_threads"[^>]*min="1"/, "transcode_threads needs min=1");
  assert.match(src, /name="decode_threads"[^>]*min="1"/, "decode_threads needs min=1");
});

test("the screen queries system_cores to set the thread-input max", () => {
  assert.match(src, /call<number>\("system_cores"\)|call<[^>]*>\("system_cores"\)/,
    "settings-screen must call the system_cores command");
  // The core max is surfaced on the thread inputs' max attribute.
  assert.match(src, /\.max\s*=/, "settings-screen must set an input .max from system_cores");
});

test("all three knobs are read in writeControls (load path)", () => {
  for (const name of knobs) {
    assert.match(
      src,
      new RegExp(`performance\\.${name}`),
      `writeControls/save must reference performance.${name}`,
    );
  }
});

test("all three knobs are written back in the save patch", () => {
  // The save patch's performance object mentions each knob key.
  for (const name of knobs) {
    assert.match(src, new RegExp(`${name}:`), `save patch must include ${name}`);
  }
});

// --- Issue 4: unified single-grid Settings layout ----------------------------
// The prefs container is a <div> grid (not a <form> — no submit is used, and it
// must legally contain Account's own <form>s). Account and Privacy live INSIDE
// the grid; Privacy spans both columns; the Privacy copy is expanded + accurate.
const setCss = readFileSync("styles.css", "utf8");

test('prefs container is a <div id="set-form"> grid, not a <form>', () => {
  assert.match(src, /<div id="set-form">/, "set-form must be a <div>");
  assert.doesNotMatch(src, /<form id="set-form">/, "set-form must NOT be a <form>");
});

test("Account and Privacy fieldsets live inside the set-form grid", () => {
  // Both legends appear before the set-form div closes (i.e. nested in it).
  assert.match(
    src,
    /<div id="set-form">[\s\S]*<legend>Account<\/legend>[\s\S]*<legend>Privacy<\/legend>[\s\S]*<\/div>/,
    "Account + Privacy must be inside the #set-form grid",
  );
});

test("Privacy fieldset is tagged for full-width and spans both columns", () => {
  assert.match(src, /<fieldset class="privacy">/, "Privacy fieldset needs the .privacy class");
  assert.match(
    setCss,
    /\.privacy\s*\{[\s\S]*?grid-column:\s*1\s*\/\s*-1/,
    ".privacy must span both grid columns",
  );
});

test("grid groups align to the top (no stretched short groups)", () => {
  assert.match(
    setCss,
    /settings-screen #set-form > fieldset\s*\{[\s\S]*?align-self:\s*start/,
    "grid group fieldsets must align-self: start",
  );
});

test("Privacy copy is expanded and accurate", () => {
  for (const phrase of [/ciphertext/i, /zeroiz/i, /telemetry/i, /\bTor\b/, /on this device/i]) {
    assert.match(src, phrase, `Privacy copy must mention ${phrase}`);
  }
});
