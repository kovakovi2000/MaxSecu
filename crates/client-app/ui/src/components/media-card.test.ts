import { test } from "node:test";
import assert from "node:assert/strict";
import { cardHref, countsLabel } from "../core/card-view.ts";

// --- cardHref: routing per card kind ---------------------------------------

test("cardHref routes a bundle card to the bundle screen (never the viewer)", () => {
  assert.equal(cardHref("bundle", "ab12"), "#/bundle?id=ab12");
  // version is meaningless for a bundle link and must not leak into the hash.
  assert.equal(cardHref("bundle", "ab12", 3), "#/bundle?id=ab12");
});

test("cardHref routes a non-bundle card to the viewer", () => {
  assert.equal(cardHref("image", "ab12"), "#/viewer?id=ab12");
  assert.equal(cardHref("blog", "cd34"), "#/viewer?id=cd34");
  assert.equal(cardHref("generic", "ef56"), "#/viewer?id=ef56");
});

test("cardHref appends &v= only when a version is given", () => {
  assert.equal(cardHref("video", "ab12", 2), "#/viewer?id=ab12&v=2");
  assert.equal(cardHref("video", "ab12", 0), "#/viewer?id=ab12&v=0");
  assert.equal(cardHref("video", "ab12"), "#/viewer?id=ab12");
});

test("cardHref percent-encodes the id", () => {
  assert.equal(cardHref("bundle", "a b"), "#/bundle?id=a%20b");
  assert.equal(cardHref("image", "a b", 1), "#/viewer?id=a%20b&v=1");
});

// --- countsLabel: the bundle member tally strip ----------------------------

test("countsLabel omits zero categories", () => {
  assert.equal(countsLabel({ video: 1, image: 2, blog: 0, generic: 0 }), "VID 1 · IMG 2");
});

test("countsLabel renders every non-zero category in VID/IMG/TXT/FILE order", () => {
  assert.equal(
    countsLabel({ video: 1, image: 4, blog: 1, generic: 2 }),
    "VID 1 · IMG 4 · TXT 1 · FILE 2",
  );
});

test("countsLabel maps blog→TXT and generic→FILE", () => {
  assert.equal(countsLabel({ video: 0, image: 0, blog: 3, generic: 0 }), "TXT 3");
  assert.equal(countsLabel({ video: 0, image: 0, blog: 0, generic: 5 }), "FILE 5");
});

test("countsLabel is empty when every category is zero", () => {
  assert.equal(countsLabel({ video: 0, image: 0, blog: 0, generic: 0 }), "");
});
