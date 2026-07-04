import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { downloadName, dedupeName } from "./download-name.ts";

// --- downloadName: type + title → save-as suggestion -----------------------
// Pure, DOM-free (no Tauri import) so it runs in the node harness. Mirrors the
// Rust `suggested_filename` intent: image→.png, video→.mp4, blog→.txt, generic
// title-is-the-filename, safe default when the title is empty.

test("downloadName maps each viewable type to the right extension", () => {
  assert.equal(downloadName("image", "Sunset"), "Sunset.png");
  assert.equal(downloadName("video", "Clip"), "Clip.mp4");
  assert.equal(downloadName("blog", "My Post"), "My Post.txt");
});

test("downloadName treats a generic title as the filename (no forced ext)", () => {
  assert.equal(downloadName("generic", "report.pdf"), "report.pdf");
  // No extension in the title → leave it as-is (per convention).
  assert.equal(downloadName("generic", "Report 2026"), "Report 2026");
});

test("downloadName falls back to a safe default when the title is empty", () => {
  assert.equal(downloadName("image", ""), "download.png");
  assert.equal(downloadName("video", "   "), "download.mp4");
  assert.equal(downloadName("blog", ""), "download.txt");
  assert.equal(downloadName("generic", ""), "download.bin");
});

test("downloadName strips path-traversal / illegal filename chars", () => {
  assert.equal(downloadName("image", "../../etc/passwd"), "etcpasswd.png");
  const g = downloadName("generic", "a/b\\c:d.pdf");
  assert.ok(!g.includes("/") && !g.includes("\\") && !g.includes(":"));
  assert.equal(g, "abcd.pdf");
});

test("downloadName treats an unknown type as a neutral download", () => {
  assert.equal(downloadName("bundle", ""), "download.bin");
});

// --- dedupeName: collision suffixes for Download-all -----------------------

test("dedupeName returns an unused name unchanged and records it", () => {
  const used = new Set<string>();
  assert.equal(dedupeName("a.png", used), "a.png");
  assert.ok(used.has("a.png"));
});

test("dedupeName appends (2), (3)… before the extension on collision", () => {
  const used = new Set<string>();
  assert.equal(dedupeName("a.png", used), "a.png");
  assert.equal(dedupeName("a.png", used), "a (2).png");
  assert.equal(dedupeName("a.png", used), "a (3).png");
});

test("dedupeName de-dups an extension-less name by appending the suffix", () => {
  const used = new Set<string>();
  assert.equal(dedupeName("report", used), "report");
  assert.equal(dedupeName("report", used), "report (2)");
});

// --- Source-structural assertions: the Download controls exist -------------
// The components import the Tauri API (via core/rpc.ts) so they can't be mounted
// in plain Node; assert over their SOURCE that each Download affordance is wired.

test("media-viewer renders a Download button wired to the shared flow", () => {
  const src = readFileSync("src/components/media-viewer.ts", "utf8");
  assert.match(src, /createElement\("button"\)/);
  assert.match(src, /Download/);
  assert.match(src, /downloadPost/);
});

test("media-card enables the generic Download button (not disabled) + stops propagation", () => {
  const src = readFileSync("src/components/media-card.ts", "utf8");
  assert.match(src, /card-download/);
  assert.match(src, /stopPropagation/);
  assert.match(src, /downloadPost/);
  // The placeholder's `disabled = true` must be gone.
  assert.doesNotMatch(src, /dl\.disabled\s*=\s*true/);
  // The button must be a DIRECT child of the card shell (a sibling of the overlay
  // link), NOT trapped inside .card-footer's own z-index:1 stacking context — else
  // the z-index:5 can never beat the z-index:4 overlay and the click is swallowed.
  assert.match(src, /article\.appendChild\(dl\)/);
  assert.doesNotMatch(src, /footer\.appendChild\(dl\)/);
});

test("bundle-screen has a Download-all button driving pick_folder + per-member download", () => {
  const src = readFileSync("src/components/bundle-screen.ts", "utf8");
  assert.match(src, /Download all/);
  assert.match(src, /pick_folder/);
  assert.match(src, /download_content/);
  assert.match(src, /dedupeName/);
});
