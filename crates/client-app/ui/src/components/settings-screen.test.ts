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
