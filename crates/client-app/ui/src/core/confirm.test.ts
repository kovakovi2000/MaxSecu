import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { needsConfirm } from "./confirm.ts";

// --- Pure confirm-decision helper (DOM-free) -------------------------------
// `confirm_destructive` (BehaviorSettings) is an opt-OUT: when true the user
// wants to be prompted before a destructive action; when false they have opted
// out of prompts. `needsConfirm` is that pure decision — trivially the flag
// itself — so a PERMANENT delete still prompts whenever the setting is on (the
// default-safe path). Pure/guardable so it unit-tests without a DOM.

test("needsConfirm returns the confirm_destructive flag verbatim", () => {
  assert.equal(needsConfirm(true), true);
  assert.equal(needsConfirm(false), false);
});

// --- Source-structural assertions on the confirm modal ----------------------
// confirm.ts also exports a DOM `confirmModal()` that builds an accessible modal
// (it touches `document`, so it is exercised structurally here, not mounted —
// matching the codebase convention for Tauri/DOM-bound UI). It must be a proper
// modal dialog: role="dialog"/aria-modal, focusable, ESC = cancel, Cancel focused
// on open, and no unescaped innerHTML interpolation.
const confirmSrc = readFileSync("src/core/confirm.ts", "utf8");

test("confirm.ts modal is a labelled role=dialog / aria-modal", () => {
  assert.match(confirmSrc, /role="dialog"/);
  assert.match(confirmSrc, /aria-modal="true"/);
  assert.match(confirmSrc, /aria-labelledby=/);
});

test("confirm.ts modal has Cancel + Delete actions and focuses Cancel on open", () => {
  assert.match(confirmSrc, /Cancel/);
  assert.match(confirmSrc, /Delete/);
  // The Cancel button is the initial focus target (safe default for a
  // destructive prompt).
  assert.match(confirmSrc, /cancel[\s\S]{0,40}\.focus\(\)/i);
});

test("confirm.ts modal handles Escape as cancel", () => {
  assert.match(confirmSrc, /e\.key === "Escape"/);
});

test("confirm.ts modal has no unescaped innerHTML interpolation (XSS guard)", () => {
  assert.doesNotMatch(confirmSrc, /\.innerHTML\s*=\s*`[^`]*\$\{(?!esc\()/);
});

test("confirm.ts sets its message via textContent, not innerHTML", () => {
  assert.match(confirmSrc, /textContent/);
});

// --- Source-structural assertions on the Delete flow ------------------------
// The viewer + bundle screen import Tauri (via core/rpc.ts) so cannot mount in
// plain Node; assert the load-bearing wiring over source.
const viewerSrc = readFileSync("src/components/media-viewer.ts", "utf8");
const bundleSrc = readFileSync("src/components/bundle-screen.ts", "utf8");

test("media-viewer renders a Delete button gated on ownership (mine)", () => {
  assert.match(viewerSrc, /\.mine/, "owner gate reads the `mine` flag");
  assert.match(viewerSrc, /createElement\("button"\)/);
  assert.match(viewerSrc, /"Delete"/);
});

test("media-viewer's Delete is only for the routed (non-embedded) viewer", () => {
  // A member delete would break the bundle, so the embedded/Stacked viewers
  // must not show a lone Delete — the gate references the embedded flag.
  assert.match(viewerSrc, /embedded/);
});

test("media-viewer's Delete calls delete_content then navigates to #/feed", () => {
  assert.match(viewerSrc, /"delete_content"/);
  assert.match(viewerSrc, /location\.hash\s*=\s*"#\/feed"/);
  // The permanent + downloaded-copies caveat must be surfaced in the prompt.
  assert.match(viewerSrc, /can't be undone/i);
});

test("media-viewer honors confirm_destructive via needsConfirm", () => {
  assert.match(viewerSrc, /needsConfirm/);
  assert.match(viewerSrc, /confirm_destructive/);
});

test("bundle-screen renders a Delete bundle button gated on view.mine", () => {
  assert.match(bundleSrc, /\.mine/, "owner gate reads the bundle view's `mine`");
  assert.match(bundleSrc, /Delete bundle/);
});

test("bundle-screen's Delete calls delete_content(bundleId) then navigates to #/feed", () => {
  assert.match(bundleSrc, /"delete_content"/);
  assert.match(bundleSrc, /location\.hash\s*=\s*"#\/feed"/);
  // The bundle prompt must note it removes the bundle AND all members.
  assert.match(bundleSrc, /member/i);
});
