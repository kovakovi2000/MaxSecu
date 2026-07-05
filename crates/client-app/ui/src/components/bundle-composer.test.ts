import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  reorderMember,
  removeMember,
  detectKind,
  basename,
  canBeginStage,
} from "../core/composer.ts";

// --- Pure member-list helpers (DOM-free) -----------------------------------
// The composer imports the Tauri API (rpc/dialog) so it cannot be mounted in
// plain Node; its member-list mutations are factored into pure helpers (mirroring
// core/card-retry.ts / core/bundle-view.ts) that unit-test without a browser.

test("reorderMember moves a row up and returns a new array", () => {
  const list = ["a", "b", "c"];
  const out = reorderMember(list, 1, "up");
  assert.deepEqual(out, ["b", "a", "c"]);
  assert.deepEqual(list, ["a", "b", "c"], "input is not mutated");
  assert.notEqual(out, list, "a new array is returned");
});

test("reorderMember moves a row down", () => {
  assert.deepEqual(reorderMember(["a", "b", "c"], 1, "down"), ["a", "c", "b"]);
});

test("reorderMember is a no-op at the boundaries", () => {
  assert.deepEqual(reorderMember(["a", "b", "c"], 0, "up"), ["a", "b", "c"]);
  assert.deepEqual(reorderMember(["a", "b", "c"], 2, "down"), ["a", "b", "c"]);
});

test("reorderMember is a no-op for an out-of-range index", () => {
  assert.deepEqual(reorderMember(["a", "b"], 5, "up"), ["a", "b"]);
  assert.deepEqual(reorderMember(["a", "b"], -1, "down"), ["a", "b"]);
});

test("removeMember drops exactly the row at index", () => {
  const list = ["a", "b", "c"];
  const out = removeMember(list, 1);
  assert.deepEqual(out, ["a", "c"]);
  assert.deepEqual(list, ["a", "b", "c"], "input is not mutated");
  assert.notEqual(out, list, "a new array is returned");
});

test("removeMember on the first and last rows", () => {
  assert.deepEqual(removeMember(["a", "b", "c"], 0), ["b", "c"]);
  assert.deepEqual(removeMember(["a", "b", "c"], 2), ["a", "b"]);
});

test("removeMember is a no-op for an out-of-range index", () => {
  assert.deepEqual(removeMember(["a", "b"], 9), ["a", "b"]);
  assert.deepEqual(removeMember(["a", "b"], -1), ["a", "b"]);
});

test("detectKind maps image extensions", () => {
  for (const f of ["a.png", "b.JPG", "c.jpeg", "d.webp", "photo.gif", "x.bmp"]) {
    assert.equal(detectKind(f), "image", f);
  }
});

test("detectKind maps video extensions", () => {
  for (const f of ["a.mp4", "b.MOV", "c.mkv", "d.webm", "clip.avi", "x.m4v"]) {
    assert.equal(detectKind(f), "video", f);
  }
});

test("detectKind falls back to generic for unknown / extensionless", () => {
  for (const f of ["notes.pdf", "archive.zip", "README", "a.", ".dotfile"]) {
    assert.equal(detectKind(f), "generic", f);
  }
});

test("detectKind accepts full paths (splits on / and \\\\)", () => {
  assert.equal(detectKind("C:\\Users\\me\\clip.mp4"), "video");
  assert.equal(detectKind("/home/me/photo.png"), "image");
});

test("canBeginStage is the single-flight gate (blocks a concurrent stage)", () => {
  assert.equal(canBeginStage(false), true, "idle ⇒ a stage may begin");
  assert.equal(canBeginStage(true), false, "a stage in flight ⇒ re-entry blocked");
});

test("basename returns the trailing path segment", () => {
  assert.equal(basename("C:\\Users\\me\\clip.mp4"), "clip.mp4");
  assert.equal(basename("/home/me/photo.png"), "photo.png");
  assert.equal(basename("bare.txt"), "bare.txt");
});

// --- Source-structural assertions on the composer component -----------------
// The component imports Tauri (rpc/dialog), so it cannot be mounted in Node; the
// a11y source lint covers landmark/focus/live/XSS. Here we assert the load-bearing
// wiring: real keyboard-operable ▲/▼/✕ controls, Add media/Add text, the
// Preview/Post actions, and the REAL stage/confirm/cancel_bundle calls.
const src = readFileSync("src/components/bundle-composer.ts", "utf8");

test("composer renders ▲/▼/✕ row controls as real <button>s", () => {
  assert.match(src, /createElement\("button"\)/, "row controls are real buttons");
  assert.match(src, /▲/, "an Up (▲) control is present");
  assert.match(src, /▼/, "a Down (▼) control is present");
  assert.match(src, /✕/, "a Remove (✕) control is present");
  // Keyboard/AT reachability: the reorder/remove controls carry accessible names.
  assert.match(src, /aria-label/, "row controls carry aria-labels");
});

test("composer uses the pure reorder/remove helpers", () => {
  assert.match(src, /reorderMember/);
  assert.match(src, /removeMember/);
  assert.match(src, /detectKind/);
});

test("composer offers Add media and Add text affordances", () => {
  assert.match(src, /Add media/i);
  assert.match(src, /Add text/i);
  assert.match(src, /"pick_files"/, "Add media opens the native multi-select file dialog");
});

test("composer previews via the REAL stage_bundle command in two modes", () => {
  assert.match(src, /"stage_bundle"/);
  assert.match(src, /Preview gallery/i);
  assert.match(src, /Preview stacked/i);
});

test("composer posts via the REAL confirm_bundle and cancels stale via cancel_bundle", () => {
  assert.match(src, /"confirm_bundle"/);
  assert.match(src, /"cancel_bundle"/);
  assert.match(src, /Post bundle/i);
});

test("composer lets an image OR video member be chosen as the bundle cover", () => {
  // A radio (single-select via a shared group name) marks the cover member;
  // buildRequest forwards its position as cover_index. Both image and video members
  // (which yield a thumbnail / poster frame) are cover-eligible.
  assert.match(src, /buildCoverToggle/, "cover-eligible rows offer a cover toggle");
  assert.match(src, /name = "bc-cover"/, "cover toggles share one radio group");
  assert.match(src, /Use as bundle cover/i, "the cover toggle is labelled");
  assert.match(
    src,
    /m\.kind === "image" \|\| m\.kind === "video"/,
    "image AND video members are cover-eligible",
  );
  assert.match(src, /req\.cover_index = coverIdx/, "buildRequest forwards cover_index");
  assert.match(src, /ensureCover/, "a default cover is kept valid across edits");
});

test("composer single-flight-guards preview/post against a concurrent stage", () => {
  // A `staging` flag gated by canBeginStage, flipped via setStagingBusy which
  // disables the Preview/Post buttons, guards both entry points.
  assert.match(src, /canBeginStage\(this\.staging\)/, "both entry points gate on canBeginStage");
  assert.match(src, /this\.staging\s*=\s*on/, "setStagingBusy toggles the staging flag");
  assert.match(src, /setStagingBusy\(true\)/, "a stage marks the guard busy before awaiting");
  assert.match(src, /b\.disabled\s*=\s*on/, "the Preview/Post buttons are disabled while staging");
});

test("composer reuses the transcode-opts builder for per-video members", () => {
  assert.match(src, /transcode-opts\.ts/);
  assert.match(src, /normalizeOptions|resolutionForPreset/);
});
