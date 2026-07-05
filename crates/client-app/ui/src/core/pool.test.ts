import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { makePool, decodePool } from "./pool.ts";
import { isCancelled } from "./serial.ts";

test("pool runs at most N concurrently and drains", async () => {
  const pool = makePool(2);
  let active = 0,
    maxActive = 0;
  const mk = () =>
    pool.run(async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 10));
      active--;
      return "ok";
    });
  const results = await Promise.all([mk(), mk(), mk(), mk()]);
  assert.ok(maxActive <= 2, `maxActive=${maxActive}`);
  assert.deepEqual(results, ["ok", "ok", "ok", "ok"]);
});

test("runPriority bypasses the concurrency cap (starts even when saturated)", async () => {
  const pool = makePool(1);
  const order: string[] = [];
  let releaseNormal: () => void = () => {};

  // First normal task saturates the pool (size 1) and blocks.
  const n1 = pool.run(async () => {
    order.push("n1-start");
    await new Promise<void>((r) => {
      releaseNormal = r;
    });
    order.push("n1-end");
    return "n1";
  });

  // A second normal task must queue behind n1.
  const n2 = pool.run(async () => {
    order.push("n2-start");
    return "n2";
  });

  // A priority task must start immediately, bypassing the saturated cap —
  // it does NOT wait for n1 to finish.
  const p1 = await pool.runPriority(async () => {
    order.push("p1-run");
    return "p1";
  });
  assert.equal(p1, "p1");
  // Priority ran while n1 was still blocked and before the queued n2.
  assert.deepEqual(order, ["n1-start", "p1-run"]);

  // Now release the normal task and drain.
  releaseNormal();
  assert.deepEqual(await Promise.all([n1, n2]), ["n1", "n2"]);
});

test("cancelPending rejects queued normals, retains priorities, leaves running alone", async () => {
  const pool = makePool(1);
  const results: string[] = [];
  let releaseRunning: () => void = () => {};

  // Running task holds the only slot.
  const running = pool.run(async () => {
    await new Promise<void>((r) => {
      releaseRunning = r;
    });
    results.push("running-done");
    return "running";
  });

  // Queued normal task — should be cancelled.
  const queuedNormal = pool.run(async () => {
    results.push("normal-ran");
    return "normal";
  });

  // Queued priority task — should be retained and eventually run.
  const queuedPriority = pool.runPriority(async () => {
    results.push("priority-ran");
    return "priority";
  });

  pool.cancelPending();

  // The queued normal is rejected with CancelledError.
  await assert.rejects(queuedNormal, (err: unknown) => {
    assert.ok(isCancelled(err), "expected CancelledError");
    return true;
  });

  // Release the running task; it must complete normally.
  releaseRunning();
  assert.equal(await running, "running");

  // The retained priority task still resolves.
  assert.equal(await queuedPriority, "priority");
  assert.ok(results.includes("running-done"));
  assert.ok(results.includes("priority-ran"));
  assert.ok(!results.includes("normal-ran"));
});

test("a throwing task rejects only its own promise and releases its slot", async () => {
  const pool = makePool(1);
  const boom = pool.run(async () => {
    throw new Error("boom");
  });
  await assert.rejects(boom, /boom/);

  // Pool is not wedged: a subsequent task still runs.
  const after = await pool.run(async () => "after");
  assert.equal(after, "after");
});

test("a synchronously-throwing task releases its slot", async () => {
  const pool = makePool(1);
  const boom = pool.run((() => {
    throw new Error("sync-boom");
  }) as () => Promise<never>);
  await assert.rejects(boom, /sync-boom/);

  const after = await pool.run(async () => "after");
  assert.equal(after, "after");
});

test("setSize raises the cap and lets queued tasks start", async () => {
  const pool = makePool(1);
  let active = 0,
    maxActive = 0;
  // A single shared gate all tasks await, so releasing it drains every task
  // regardless of when each one started (avoids a per-task-releaser race).
  let openGate: () => void = () => {};
  const gate = new Promise<void>((r) => {
    openGate = r;
  });
  const mk = () =>
    pool.run(async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await gate;
      active--;
      return "ok";
    });

  const p = [mk(), mk(), mk(), mk()];
  // With size 1 only one is active.
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(maxActive, 1);

  // Raise the cap; more queued tasks should start immediately.
  pool.setSize(3);
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(maxActive, 3);

  openGate();
  assert.deepEqual(await Promise.all(p), ["ok", "ok", "ok", "ok"]);
});

// --- The shared feed-decode pool singleton (Task 7.2) -----------------------

test("decodePool is a shared pool exposing the full Pool interface", () => {
  for (const m of ["run", "runPriority", "cancelPending", "setSize"] as const) {
    assert.equal(typeof decodePool[m], "function", `decodePool.${m} missing`);
  }
});

test("a decodePool decode still resolves normally through the shared pool", async () => {
  assert.equal(await decodePool.run(async () => "decoded"), "decoded");
});

// Structural wiring: feed card decodes go through the pool's normal lane,
// viewer-open through the priority lane, and feed teardown flushes the pool —
// so card decodes run concurrently while a viewer-open never queues behind them,
// and `card-retry`'s isCancelled benign-flush handling still applies (the pool
// throws serial.ts's CancelledError).
test("media-card decodes cards through decodePool.run", () => {
  const src = readFileSync("src/components/media-card.ts", "utf8");
  assert.match(src, /decodePool\.run\(/, "media-card must route decrypt_card through decodePool.run");
});

test("media-viewer opens through decodePool.runPriority", () => {
  const src = readFileSync("src/components/media-viewer.ts", "utf8");
  assert.match(src, /decodePool\.runPriority\(/, "media-viewer must open via the priority lane");
});

test("feed-screen teardown flushes decodePool.cancelPending", () => {
  const src = readFileSync("src/components/feed-screen.ts", "utf8");
  assert.match(src, /decodePool\.cancelPending\(/, "feed-screen teardown must flush the decodePool");
});
