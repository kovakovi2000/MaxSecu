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

// --- Issue 4: two independent Settings columns -------------------------------
// The prefs container is a <div> grid (not a <form> — no submit is used, and it
// must legally contain Account's own <form>s). Cards are grouped into two
// independent vertical stacks so uneven card heights do not create grid holes.
const setCss = readFileSync("styles.css", "utf8");

test('prefs container is a <div id="set-form"> grid, not a <form>', () => {
  assert.match(src, /<div id="set-form">/, "set-form must be a <div>");
  assert.doesNotMatch(src, /<form id="set-form">/, "set-form must NOT be a <form>");
});

test("settings cards are grouped into two independent columns", () => {
  assert.match(src, /<div class="settings-column settings-column-left">/, "left settings column missing");
  assert.match(src, /<div class="settings-column settings-column-right">/, "right settings column missing");
  assert.match(
    src,
    /settings-column settings-column-right[\s\S]*<legend>Connection<\/legend>/,
    "Connection must live in the right settings column",
  );
  assert.match(
    setCss,
    /\.settings-column\s*\{[\s\S]*?display:\s*grid[\s\S]*?align-content:\s*start/,
    "each settings column must be an independent vertical grid",
  );
});

test("Privacy fieldset is a normal right-column card without a decorative logo", () => {
  assert.match(src, /<fieldset class="settings-card privacy">/, "Privacy fieldset needs card + privacy classes");
  assert.match(
    setCss,
    /settings-screen #set-form \.privacy::after\s*\{[\s\S]*?content:\s*none/,
    "Privacy logo pseudo-element must be disabled",
  );
});

test("Privacy copy is expanded and accurate", () => {
  for (const phrase of [/ciphertext/i, /zeroiz/i, /telemetry/i, /\bTor\b/, /on this device/i]) {
    assert.match(src, phrase, `Privacy copy must mention ${phrase}`);
  }
});

test("Appearance offers a Frontend selector wired to get/setFrontend", () => {
  assert.match(src, /<select name="frontend">/, "Frontend <select> missing");
  for (const id of ["default", "pizza", "slot3"]) {
    assert.match(src, new RegExp(`<option value="${id}"`), `frontend option ${id} missing`);
  }
  assert.match(src, /getFrontend\(\)/, "load path must read getFrontend()");
  assert.match(src, /setFrontend\(/, "change path must call setFrontend()");
  assert.doesNotMatch(src, /<select name="theme">/, "old theme select must be removed");
});
