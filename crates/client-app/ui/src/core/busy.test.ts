import { test } from "node:test";
import assert from "node:assert/strict";
import { setBusy, clearBusy, isBusy, busyReason, subscribeBusy } from "./busy.ts";

// Keep tests independent: the busy store is a module singleton.
function reset() {
  clearBusy();
}

test("isBusy/busyReason reflect setBusy + clearBusy", () => {
  reset();
  assert.equal(isBusy(), false);
  assert.equal(busyReason(), "");
  setBusy("Transcoding video");
  assert.equal(isBusy(), true);
  assert.equal(busyReason(), "Transcoding video");
  clearBusy();
  assert.equal(isBusy(), false);
  assert.equal(busyReason(), "");
});

test("subscribe fires immediately with current state, then on change", () => {
  reset();
  const seen: Array<[boolean, string]> = [];
  const off = subscribeBusy((b, r) => seen.push([b, r]));
  // Immediate call with the idle state.
  assert.deepEqual(seen[0], [false, ""]);
  setBusy("Uploading");
  clearBusy();
  off();
  setBusy("ignored after unsubscribe");
  clearBusy();
  assert.deepEqual(seen, [
    [false, ""],
    [true, "Uploading"],
    [false, ""],
  ]);
});

test("clearBusy is a no-op (no notify) when already idle", () => {
  reset();
  let calls = 0;
  const off = subscribeBusy(() => calls++);
  const baseline = calls; // the immediate call
  clearBusy(); // already idle → must not notify
  assert.equal(calls, baseline, "clearBusy while idle must not notify");
  off();
});

test("setBusy while busy updates the reason and notifies", () => {
  reset();
  const seen: string[] = [];
  const off = subscribeBusy((_b, r) => seen.push(r));
  setBusy("first");
  setBusy("second");
  off();
  clearBusy();
  assert.deepEqual(seen, ["", "first", "second"]);
});
