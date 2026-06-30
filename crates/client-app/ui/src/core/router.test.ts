import { test } from "node:test";
import assert from "node:assert/strict";
import { ROUTES } from "./router.ts";

test("router knows the mine route", () => {
  assert.ok(ROUTES.includes("mine"), "#/mine is a known route");
  assert.ok(ROUTES.includes("feed"));
});
