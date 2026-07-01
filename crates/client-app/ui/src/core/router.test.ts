import { test } from "node:test";
import assert from "node:assert/strict";
import { ROUTES, shouldBlockNav } from "./router.ts";

test("router knows the mine route", () => {
  assert.ok(ROUTES.includes("mine"), "#/mine is a known route");
  assert.ok(ROUTES.includes("feed"));
});

test("shouldBlockNav refuses navigation to a new hash while busy", () => {
  // Busy + a genuinely different destination → blocked.
  assert.equal(shouldBlockNav(true, "#/upload", "#/feed"), true);
  // Busy but the hash didn't actually change (e.g. our own restore) → allowed.
  assert.equal(shouldBlockNav(true, "#/upload", "#/upload"), false);
  // Idle → always allowed regardless of destination.
  assert.equal(shouldBlockNav(false, "#/upload", "#/feed"), false);
});
