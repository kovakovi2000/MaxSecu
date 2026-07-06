import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from "node:fs";
import { streamSrc, previewSrc } from './video-src.ts';

test('streamSrc builds the Windows WebView2 custom-protocol URL from the file id', () => {
  assert.equal(streamSrc('abc123'), 'http://stream.localhost/media/abc123');
});

test('previewSrc builds the preview-namespace custom-protocol URL from the job id', () => {
  assert.equal(previewSrc('job-xyz'), 'http://stream.localhost/preview/job-xyz');
});

// --- Issue 3: embedded (stacked) players must not steal focus -----------------
// video-player.focus() on mount scrolls the element into view. In a Stacked
// bundle, each member that loads would grab focus and scroll-jump the page. When
// the player is embedded, it must NOT steal focus; the routed full-screen viewer
// keeps focus for a11y (WCAG 2.4.3).
const vpSrc = readFileSync("src/components/video-player.ts", "utf8");

test("video-player reads an embedded flag", () => {
  assert.match(vpSrc, /hasAttribute\("embedded"\)/, "must detect the embedded attribute");
});

test("focus on mount is guarded by the embedded flag", () => {
  // The region focus() is only called when NOT embedded.
  assert.match(
    vpSrc,
    /if\s*\(!this\.embedded\)\s*\{[\s\S]{0,120}?\.focus\(\)/,
    "focus() must be skipped for embedded players",
  );
});

const mvSrc = readFileSync("src/components/media-viewer.ts", "utf8");

test("media-viewer forwards embedded to the video-player it mounts", () => {
  assert.match(
    mvSrc,
    /this\.embedded[\s\S]{0,120}?setAttribute\("embedded"/,
    "an embedded media-viewer must pass embedded to its <video-player>",
  );
});
