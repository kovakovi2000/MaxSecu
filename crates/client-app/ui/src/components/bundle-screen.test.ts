import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  normalizeBundleViewMode,
  readBundleViewMode,
  writeBundleViewMode,
} from "../core/bundle-view.ts";
import { settingsStore } from "../core/settings-store-instance.ts";

// --- Store-backed view-mode persistence (DOM-free) -------------------------
// The chosen view mode ("gallery" | "stacked") is a non-secret UI preference now
// persisted in the backend settings.json (settings.ui.bundle_view) via the shared
// settings store — no browser localStorage. The helpers are pure/guardable so they
// unit-test without a DOM (the node harness has no Tauri host).

test("normalizeBundleViewMode coerces to a valid mode (default gallery)", () => {
  assert.equal(normalizeBundleViewMode("stacked"), "stacked");
  assert.equal(normalizeBundleViewMode("gallery"), "gallery");
  assert.equal(normalizeBundleViewMode("nope"), "gallery");
  assert.equal(normalizeBundleViewMode(null), "gallery");
  assert.equal(normalizeBundleViewMode(undefined), "gallery");
});

test("read reflects the settings store; write patches it locally", () => {
  settingsStore.patchLocal({ ui: { bundle_view: "stacked" } });
  assert.equal(readBundleViewMode(), "stacked");
  writeBundleViewMode("gallery");
  assert.equal(settingsStore.get().ui.bundle_view, "gallery");
  assert.equal(readBundleViewMode(), "gallery");
});

// --- Source-structural assertions on the routed screen ----------------------
// The screen imports the Tauri API (via core/rpc.ts) so it cannot be mounted in
// plain Node; the a11y source lint (a11y.test.ts) covers landmark/focus/live/XSS.
// Here we assert the load-bearing wiring: it reads the id from the hash, drives
// open_bundle, reuses <media-card> per member for Gallery, and renders distinct
// per-member blocks for Stacked, using the persistence helper.
const src = readFileSync("src/components/bundle-screen.ts", "utf8");

test("bundle-screen reads the id from the #/bundle?id= hash query", () => {
  assert.match(src, /URLSearchParams\(location\.hash\.split\("\?"\)\[1\]/);
  assert.match(src, /\.get\("id"\)/);
});

test("bundle-screen drives the open_bundle command with the file_id", () => {
  assert.match(src, /"open_bundle"/);
  assert.match(src, /file_id/);
});

test("Gallery mode renders a decrypt-on-tap <media-card> per member", () => {
  assert.match(src, /createElement\("media-card"\)/);
  assert.match(src, /setAttribute\("file-type"/);
});

test("Stacked mode renders a fully-opened embedded <media-viewer> per member", () => {
  assert.match(src, /createElement\("media-viewer"\)/);
  assert.match(src, /setAttribute\("file-id"/);
  assert.match(src, /setAttribute\("embedded"/);
  assert.match(src, /bundle-stack-item/);
});

test("Gallery and Stacked render provably distinct element types", () => {
  // The whole point of the two modes: cards vs inline-opened viewers.
  assert.match(src, /createElement\("media-card"\)/);
  assert.match(src, /createElement\("media-viewer"\)/);
});

test("bundle-screen has a two-button Gallery/Stacked toggle with aria state", () => {
  assert.match(src, /Gallery/);
  assert.match(src, /Stacked/);
  assert.match(src, /aria-pressed/);
});

test("bundle-screen persists the mode via the bundle-view helper", () => {
  assert.match(src, /readBundleViewMode/);
  assert.match(src, /writeBundleViewMode/);
});

// --- Issue 1 (frontend): render-generation guard + debounced view switch -----
// Rapid Gallery⇄Stacked toggling must not fan out overlapping member loads that
// race the connect lock. setMode debounces the expensive re-render and tags each
// scheduled render with a generation token so a superseded one is dropped;
// re-render tears down prior children (replaceChildren) so their in-flight loads
// are abandoned. disconnect clears any pending timer.

test("bundle-screen carries a render-generation token", () => {
  assert.match(src, /renderGen/, "must track a render generation");
});

test("setMode debounces the re-render with a timer", () => {
  assert.match(src, /setTimeout\(/, "setMode must schedule the re-render on a timer");
  assert.match(src, /clearTimeout\(/, "a pending re-render timer must be cancellable");
});

test("a superseded scheduled render is dropped via the generation guard", () => {
  // The scheduled callback bails when its captured generation is stale.
  assert.match(src, /!==\s*this\.renderGen/, "scheduled render must guard on a stale generation");
});

test("disconnect clears the pending re-render timer", () => {
  assert.match(src, /disconnectedCallback\(\)\s*\{[\s\S]*clearTimeout/, "must clear the timer on disconnect");
});

// --- Issue 2: the bundle gallery reuses the feed's tile grid ------------------
const css = readFileSync("styles.css", "utf8");

test(".bundle-gallery is a tile grid matching the feed #grid", () => {
  // The gallery must lay <media-card>s out on the SAME auto-fit tile grid the
  // feed uses (repeat(auto-fit, minmax(min(100%, 280px), 1fr))), not block flow.
  assert.match(
    css,
    /\.bundle-gallery\s*\{[\s\S]*?display:\s*grid[\s\S]*?repeat\(auto-fit,\s*minmax\(min\(100%,\s*280px\),\s*1fr\)\)/,
    ".bundle-gallery must define the feed's auto-fit tile grid",
  );
});
