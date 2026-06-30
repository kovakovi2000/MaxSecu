import { test } from "node:test";
import assert from "node:assert/strict";
import { decideCardOutcome, MAX_CARD_RETRIES } from "./card-retry.ts";
import { CancelledError } from "./serial.ts";

test("a cancellation on a still-connected card retries (the feed bug)", () => {
  assert.equal(decideCardOutcome(new CancelledError(), true, 0), "retry");
  assert.equal(decideCardOutcome(new CancelledError(), true, MAX_CARD_RETRIES - 1), "retry");
});

test("a cancellation on a disconnected card drops silently", () => {
  assert.equal(decideCardOutcome(new CancelledError(), false, 0), "drop");
});

test("a plain {message:'cancelled'} is still treated as a cancellation", () => {
  assert.equal(decideCardOutcome({ message: "cancelled" }, true, 0), "retry");
  assert.equal(decideCardOutcome({ message: "cancelled" }, false, 0), "drop");
});

test("a real backend error always fails (no retry)", () => {
  assert.equal(decideCardOutcome({ code: "verify_failed", message: "bad" }, true, 0), "fail");
  assert.equal(decideCardOutcome({ code: "fetch_failed", message: "x" }, false, 0), "fail");
});

test("retries are bounded so a pathological flush loop can't run away", () => {
  assert.equal(decideCardOutcome(new CancelledError(), true, MAX_CARD_RETRIES), "fail");
  assert.equal(decideCardOutcome(new CancelledError(), true, MAX_CARD_RETRIES + 3), "fail");
});
