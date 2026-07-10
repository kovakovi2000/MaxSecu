// Structural tests for the active-uploads tray. Like the other DOM/Tauri-bound
// components in this codebase (upload-tray imports core/rpc.ts → the Tauri API,
// so it cannot be mounted in plain Node), the tray is exercised over its SOURCE
// rather than rendered — matching the convention in a11y.test.ts / confirm.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const src = readFileSync("src/components/upload-tray.ts", "utf8");

// --- Dismiss on a failed row ------------------------------------------------
// A FAILED upload row used to expose only Retry and was otherwise stuck. It now
// also offers a Dismiss that clears the row so the user is never stuck with an
// un-removable failure.
test("failed rows offer a Dismiss beside Retry", () => {
  // The failed branch wires up both actions.
  assert.match(src, /this\.addRetry\(li, m\.job_id\)/, "failed rows still get Retry");
  assert.match(src, /this\.addDismiss\(li/, "failed rows also get a Dismiss");
  // Dismiss is a real, class-tagged button consistent with its sibling ut-retry.
  assert.match(src, /class(Name)?\s*=\s*"ut-dismiss"|"ut-dismiss"/, "Dismiss is a ut-dismiss button");
  assert.match(src, /addDismiss\s*\(/, "there is a dedicated addDismiss builder");
});

test("Dismiss removes a failed row and re-hides the empty tray", () => {
  // Isolate the addDismiss method body and assert it removes the <li> and calls
  // maybeHideTray() (so an emptied tray collapses again). This is the behaviour
  // the DOM would exhibit; verified structurally per the codebase convention.
  const body = src.slice(src.indexOf("private addDismiss"));
  const method = body.slice(0, body.indexOf("\n  private ", 1) + 1) || body;
  assert.match(method, /li\.remove\(\)/, "Dismiss must remove the row's <li>");
  assert.match(method, /this\.maybeHideTray\(\)/, "Dismiss must re-hide an emptied tray");
});

test("Dismiss carries an accessible name matching the Discard pattern", () => {
  // Mirror the pending-discard's `aria-label` shape ("Discard upload of …"); the
  // failed job carries no title, so a sensible generic name is acceptable.
  assert.match(
    src,
    /setAttribute\("aria-label",\s*"Dismiss (failed )?upload/,
    "Dismiss must expose an aria-label in the Dismiss-upload family",
  );
});
