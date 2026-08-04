import { test } from "node:test";
import assert from "node:assert/strict";
import {
  clampPage,
  offsetFor,
  pageCount,
  pageRange,
  pageWindow,
  shouldShowPager,
  showingLabel,
  type PageSlot,
} from "./paging.ts";

// Numbered-page arithmetic (F3). Pure functions, so these are REAL unit tests —
// no DOM, no Tauri, no source-regex lint.

// --- pageCount --------------------------------------------------------------

test("pageCount rounds up the last partial page", () => {
  assert.equal(pageCount(0, 50), 0);
  assert.equal(pageCount(1, 50), 1);
  assert.equal(pageCount(50, 50), 1);
  assert.equal(pageCount(51, 50), 2);
  assert.equal(pageCount(137, 50), 3);
  assert.equal(pageCount(200, 50), 4);
});

test("pageCount refuses nonsense inputs instead of returning Infinity", () => {
  assert.equal(pageCount(10, 0), 0);
  assert.equal(pageCount(10, -5), 0);
  assert.equal(pageCount(-1, 50), 0);
  assert.equal(pageCount(Number.NaN, 50), 0);
  assert.equal(pageCount(10, Number.NaN), 0);
});

// --- clampPage --------------------------------------------------------------

test("clampPage keeps a page index inside the listing", () => {
  assert.equal(clampPage(0, 3), 0);
  assert.equal(clampPage(2, 3), 2);
  assert.equal(clampPage(7, 3), 2, "past the end clamps to the last page");
  assert.equal(clampPage(-4, 3), 0, "before the start clamps to page 0");
  assert.equal(clampPage(5, 0), 0, "an empty listing has only page 0");
  assert.equal(clampPage(Number.NaN, 3), 0);
});

// --- offsetFor / pageRange / showingLabel -----------------------------------

test("offsetFor multiplies the 0-based page straight into the wire offset", () => {
  assert.equal(offsetFor(0, 50), 0);
  assert.equal(offsetFor(1, 50), 50);
  assert.equal(offsetFor(3, 50), 150);
  assert.equal(offsetFor(-1, 50), 0, "never negative");
  assert.equal(offsetFor(2, 0), 0);
});

test("pageRange gives the 1-based inclusive item span, clamped on the last page", () => {
  assert.deepEqual(pageRange(0, 50, 137), { from: 1, to: 50 });
  assert.deepEqual(pageRange(1, 50, 137), { from: 51, to: 100 });
  assert.deepEqual(pageRange(2, 50, 137), { from: 101, to: 137 });
  assert.equal(pageRange(3, 50, 137), null, "a page past the end shows nothing");
  assert.equal(pageRange(0, 50, 0), null);
});

test("showingLabel reports the honest total, not the page size", () => {
  assert.equal(showingLabel(0, 50, 137), "Showing 1-50 of 137.");
  assert.equal(showingLabel(2, 50, 137), "Showing 101-137 of 137.");
  // A single-page listing still names the true total (the old status line
  // reported the fetched window, which lied on #/mine).
  assert.equal(showingLabel(0, 50, 7), "Showing 1-7 of 7.");
  assert.equal(showingLabel(0, 50, 0), "No content yet.");
});

// --- pageWindow -------------------------------------------------------------

const nums = (w: PageSlot[]) => w.filter((s): s is number => typeof s === "number");

test("pageWindow shows every page when they fit", () => {
  assert.deepEqual(pageWindow(0, 1), [0]);
  assert.deepEqual(pageWindow(2, 5), [0, 1, 2, 3, 4]);
  assert.deepEqual(pageWindow(3, 7), [0, 1, 2, 3, 4, 5, 6]);
  assert.deepEqual(pageWindow(0, 0), [], "no pages ⇒ no slots");
});

test("pageWindow always keeps the first and last page reachable", () => {
  for (const page of [0, 1, 5, 20, 41]) {
    const w = pageWindow(page, 42);
    assert.equal(w[0], 0, `page ${page}: first page must stay reachable`);
    assert.equal(w[w.length - 1], 41, `page ${page}: last page must stay reachable`);
    assert.ok(nums(w).includes(clampPage(page, 42)), `page ${page}: current page must be shown`);
  }
});

test("pageWindow ellipsises the middle near the start", () => {
  assert.deepEqual(pageWindow(0, 42), [0, 1, 2, 3, 4, 5, "gap", 41]);
  assert.deepEqual(pageWindow(1, 42), [0, 1, 2, 3, 4, 5, "gap", 41]);
});

test("pageWindow ellipsises the middle near the end", () => {
  assert.deepEqual(pageWindow(41, 42), [0, "gap", 36, 37, 38, 39, 40, 41]);
});

test("pageWindow ellipsises both sides in the middle", () => {
  assert.deepEqual(pageWindow(20, 42), [0, "gap", 18, 19, 20, 21, 22, "gap", 41]);
});

test("pageWindow never hides a single page behind an ellipsis", () => {
  // count=8, cap=7: the naive window would render "0 1 2 3 4 5 … 7", where the
  // gap stands for exactly one page (6). Show the page instead.
  assert.deepEqual(pageWindow(0, 8), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(pageWindow(7, 8), [0, 1, 2, 3, 4, 5, 6, 7]);
  for (const w of [pageWindow(0, 8), pageWindow(7, 8), pageWindow(3, 9)]) {
    for (let i = 0; i < w.length; i++) {
      if (w[i] !== "gap") continue;
      const before = w[i - 1] as number;
      const after = w[i + 1] as number;
      assert.ok(after - before > 2, `a gap between ${before} and ${after} hides <2 pages`);
    }
  }
});

test("pageWindow respects a custom budget and a tiny one", () => {
  assert.deepEqual(pageWindow(10, 42, 5), [0, "gap", 9, 10, 11, "gap", 41]);
  // maxNumbers is floored at 3 so the control can never degenerate below
  // first/current/last.
  const w = pageWindow(10, 42, 1);
  assert.equal(w[0], 0);
  assert.equal(w[w.length - 1], 41);
  assert.ok(nums(w).includes(10));
});

test("pageWindow clamps an out-of-range current page", () => {
  assert.deepEqual(pageWindow(99, 42), pageWindow(41, 42));
  assert.deepEqual(pageWindow(-3, 42), pageWindow(0, 42));
});

// --- shouldShowPager: THE OLD-SERVER RULE -----------------------------------

test("shouldShowPager renders NO pager when the server reported no total", () => {
  // total === null is the un-upgraded-server signal: it ignored offset/cursor and
  // returned page 1. Rendering a pager there would send offset > 0 forever.
  assert.equal(shouldShowPager(null, 50), false);
  assert.equal(shouldShowPager(null, 1), false);
});

test("shouldShowPager hides the pager for a single-page listing", () => {
  assert.equal(shouldShowPager(0, 50), false);
  assert.equal(shouldShowPager(1, 50), false);
  assert.equal(shouldShowPager(50, 50), false);
  assert.equal(shouldShowPager(51, 50), true);
  assert.equal(shouldShowPager(137, 50), true);
});
