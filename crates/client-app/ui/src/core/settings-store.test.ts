import { test } from "node:test";
import assert from "node:assert/strict";
import { SettingsStore } from "./settings-store.ts";
import type { Settings } from "./types.ts";

function base(): Settings {
  return {
    a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
    behavior: { confirm_destructive: false },
    performance: { media_cache_cap_mb: 1024, thumb_cache_cap_mb: 256, feed_concurrency: 4, transcode_threads: 4, decode_threads: 4, cache_location: "Memory" },
    connection: { route_mode: "prefer-server" },
    appearance: { theme: "dark" },
  };
}

test("subscribe is called immediately with current state", () => {
  const s = new SettingsStore(base());
  let seen: Settings | null = null;
  s.subscribe((v) => (seen = v));
  assert.equal(seen!.appearance.theme, "dark");
});

test("patch merges a nested section and notifies", () => {
  const s = new SettingsStore(base());
  let seen: Settings | null = null;
  s.subscribe((v) => (seen = v));
  s.patchLocal({ appearance: { theme: "light" } });
  assert.equal(seen!.appearance.theme, "light");
  assert.equal(seen!.a11y.text_size, "normal", "other sections preserved");
});

test("unsubscribe stops notifications", () => {
  const s = new SettingsStore(base());
  let count = 0;
  const off = s.subscribe(() => count++);
  off();
  s.patchLocal({ appearance: { theme: "light" } });
  assert.equal(count, 1, "only the immediate call fired");
});
