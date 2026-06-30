import { test } from "node:test";
import assert from "node:assert/strict";
import { serial, serialPriority, cancelPending } from "./serial.ts";

const tick = () => new Promise((r) => setTimeout(r, 5));

test("tasks run one at a time, in FIFO order", async () => {
  const order: number[] = [];
  const a = serial(async () => { await tick(); order.push(1); });
  const b = serial(async () => { order.push(2); });
  await Promise.all([a, b]);
  assert.deepEqual(order, [1, 2]);
});

test("a failing task does not stall the queue", async () => {
  const ran: number[] = [];
  const a = serial(async () => { throw new Error("boom"); }).catch(() => {});
  const b = serial(async () => { ran.push(2); });
  await Promise.all([a, b]);
  assert.deepEqual(ran, [2]);
});

test("priority task jumps ahead of queued tasks", async () => {
  const order: string[] = [];
  // Occupy the queue with a slow task, then enqueue normal + priority.
  const slow = serial(async () => { await tick(); order.push("slow"); });
  const normal = serial(async () => { order.push("normal"); });
  const prio = serialPriority(async () => { order.push("prio"); });
  await Promise.all([slow, normal, prio]);
  // slow runs first (already started); among the waiters, prio precedes normal.
  assert.equal(order[0], "slow");
  assert.ok(order.indexOf("prio") < order.indexOf("normal"));
});

test("cancelPending rejects queued (not-yet-started) tasks", async () => {
  let started = false;
  const slow = serial(async () => { await tick(); });
  const queued = serial(async () => { started = true; }).catch((e) => (e as Error).message);
  cancelPending();
  const res = await queued;
  await slow;
  assert.equal(started, false, "queued task never ran");
  assert.equal(res, "cancelled");
});
