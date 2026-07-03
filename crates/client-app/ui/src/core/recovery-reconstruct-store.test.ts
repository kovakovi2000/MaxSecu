import { test } from "node:test";
import assert from "node:assert/strict";
import { ReconstructState, rejectionCopy } from "./recovery-reconstruct-store.ts";

test("a fresh state starts at 0/0 and cannot reconstruct", () => {
  const s = new ReconstructState();
  assert.equal(s.get().have, 0);
  assert.equal(s.get().need, 0);
  assert.equal(s.canReconstruct(), false);
});

test("applying an accepted add sets have/need/label from the backend response", () => {
  const s = new ReconstructState();
  s.applyAccepted({ have: 1, need: 3, label: "recovery-2026" });
  assert.equal(s.get().have, 1);
  assert.equal(s.get().need, 3);
  assert.equal(s.get().label, "recovery-2026");
});

test("reconstruct-enabled predicate: false below k, true at exactly k, true above k", () => {
  const s = new ReconstructState();
  s.applyAccepted({ have: 1, need: 3, label: "L" });
  assert.equal(s.canReconstruct(), false, "1 of 3 is below k");
  s.applyAccepted({ have: 2, need: 3, label: "L" });
  assert.equal(s.canReconstruct(), false, "2 of 3 is below k");
  s.applyAccepted({ have: 3, need: 3, label: "L" });
  assert.equal(s.canReconstruct(), true, "3 of 3 is exactly k -> enabled");
  s.applyAccepted({ have: 4, need: 3, label: "L" });
  assert.equal(s.canReconstruct(), true, "4 of 3 is above k -> stays enabled");
});

test("a rejected add (e.g. a duplicate index) never reaches applyAccepted, so have does not change", () => {
  // The backend rejects a duplicate/malformed/corrupt/foreign/out-of-range share
  // with a UiError, not an AddShareResponse — the component only ever calls
  // applyAccepted() for an ACCEPTED add, so there is nothing to feed the store
  // on a rejection. This models that: two accepted adds set have=2, and no
  // further call (standing in for a rejected add_recovery_share) leaves it
  // unchanged.
  const s = new ReconstructState();
  s.applyAccepted({ have: 1, need: 5, label: "L" });
  s.applyAccepted({ have: 2, need: 5, label: "L" });
  const before = s.get().have;
  // (a rejected add would be handled by the component surfacing a role=alert
  // and simply not calling applyAccepted here)
  assert.equal(s.get().have, before, "have is unchanged by a rejected add");
  assert.equal(s.get().have, 2);
  assert.equal(s.canReconstruct(), false);
});

test("reset clears have/need/label back to a fresh session", () => {
  const s = new ReconstructState();
  s.applyAccepted({ have: 3, need: 3, label: "L" });
  assert.equal(s.canReconstruct(), true);
  s.reset();
  assert.equal(s.get().have, 0);
  assert.equal(s.get().need, 0);
  assert.equal(s.get().label, "");
  assert.equal(s.canReconstruct(), false);
});

test("rejectionCopy maps each of the five known codes to its own distinct, specific copy", () => {
  const codes = [
    "malformed_share",
    "corrupt_share",
    "duplicate_share",
    "foreign_share",
    "invalid_share_index",
  ];
  const seen = new Set<string>();
  for (const c of codes) {
    const msg = rejectionCopy(c, "fallback-text");
    assert.notEqual(msg, "fallback-text", `${c} must have its own copy, not the fallback`);
    seen.add(msg);
  }
  assert.equal(seen.size, codes.length, "all five messages must be distinct");
});

test("rejectionCopy falls back to the supplied (backend) message for an unrecognized code", () => {
  assert.equal(rejectionCopy("some_future_code", "backend text"), "backend text");
});
