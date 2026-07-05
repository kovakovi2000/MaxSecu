// Source-level tests for the single-post upload screen's auto-detect + generic
// support (no DOM/Tauri — the node harness has neither). We assert the screen no
// longer shows a manual image/video/generic type picker, detects the kind from the
// chosen file, reveals the video controls only for a video, and routes text posts
// through an explicit "Text post" mode.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const src = readFileSync("src/components/upload-screen.ts", "utf8");

test("upload screen has no manual media type picker", () => {
  // The old 3-way <select name="kind"> image/blog/video picker is gone; the only
  // explicit choice is File vs Text (media kind auto-detects).
  assert.doesNotMatch(src, /name="kind"/, "the manual type <select> must be removed");
  assert.match(src, /name="mode"/, "a File/Text mode select is present");
  assert.match(src, /value="file"/, "File mode option present");
  assert.match(src, /value="text"/, "Text mode option present");
});

test("upload screen auto-detects the file kind (incl. generic)", () => {
  assert.match(src, /import \{ detectKind \}/, "kind detection is imported");
  assert.match(src, /this\.detectedKind = path \? detectKind\(path\)/, "kind is detected from the path");
  // Generic (download-only) is a first-class detected kind with a label.
  assert.match(src, /generic: "File \(download-only\)"/, "generic is a labelled detected kind");
  // The submit path uses the detected kind for a file post (no picker value).
  assert.match(src, /const kind = this\.detectedKind/, "submit uses the detected kind");
});

test("upload screen browses ANY file and reveals video controls only for a video", () => {
  // One Browse button, unfiltered (extensions: []), feeding the shared path field.
  assert.match(src, /"pick_file", \{ extensions: \[\] \}/, "browse is unfiltered (any file)");
  assert.match(src, /videoRow\.hidden = isText \|\| this\.detectedKind !== "video"/, "video controls show only for a detected video");
});

test("upload screen posts text via an explicit Text mode → blog kind", () => {
  assert.match(src, /if \(mode === "text"\)/, "Text mode is handled explicitly");
  assert.match(src, /req\.kind = "blog"/, "Text mode uploads as a blog post");
});
