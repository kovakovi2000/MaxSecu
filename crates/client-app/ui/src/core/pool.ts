// A bounded-concurrency async runner. Generalizes the single-flight `serial`
// queue (concurrency 1) to N-at-a-time, so feed cards can decode in parallel up
// to the backend's cached authed-connection cap (`feed_concurrency`). Task 7.0
// added a backend connection pool; this is the frontend half — it caps how many
// decode calls are in flight so we don't outrun the backend's channel budget.
//
// Semantics mirror `serial.ts` so existing card-retry logic keeps working:
//   - reuses `CancelledError`/`isCancelled` (imported, not redefined),
//   - `runPriority` is for a viewer-open that must not wait behind card decodes:
//     it BYPASSES the concurrency cap and runs immediately (matching the intent
//     of `serialPriority`, taken further — a priority task never queues at all),
//   - `cancelPending` rejects QUEUED normal tasks with `CancelledError` and
//     RETAINS queued priority tasks (a viewer-open must survive a feed teardown),
//   - every task releases its slot on success AND throw (sync or async) so the
//     pool can never wedge.
//
// Pure module (no DOM/Tauri) so it is node-unit-testable.

import { CancelledError } from "./serial.ts";

export type Pool = {
  run<T>(task: () => Promise<T>): Promise<T>;
  runPriority<T>(task: () => Promise<T>): Promise<T>;
  cancelPending(): void;
  setSize(n: number): void;
};

type Job<T = unknown> = {
  task: () => Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
};

export function makePool(size: number): Pool {
  const queue: Job[] = [];
  let running = 0;
  let cap = Math.max(1, Math.floor(size));

  // Invoke a job with the same hardening as serial.ts: a SYNCHRONOUS throw (not
  // just a rejected promise) must still release the slot and reject the job.
  // `slotted` = whether this invocation holds a concurrency slot to release.
  function invoke(job: Job, slotted: boolean): void {
    let p: Promise<unknown>;
    try {
      p = Promise.resolve(job.task());
    } catch (e) {
      if (slotted) running--;
      job.reject(e);
      if (slotted) pump();
      return;
    }
    p.then(
      (v) => job.resolve(v),
      (e) => job.reject(e),
    ).finally(() => {
      if (slotted) {
        running--;
        pump();
      }
    });
  }

  // Start as many queued jobs as the current cap allows.
  function pump(): void {
    while (running < cap && queue.length) {
      const job = queue.shift()!;
      running++;
      invoke(job, true);
    }
  }

  function run<T>(task: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      queue.push({ task, resolve, reject } as Job);
      pump();
    });
  }

  // Priority lane: bypasses the cap entirely and runs immediately, so opening
  // the viewer never waits behind a backlog (or a saturated pool) of card
  // decodes. Does NOT occupy a concurrency slot, so it does not delay normals.
  function runPriority<T>(task: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      invoke({ task, resolve, reject } as Job, false);
    });
  }

  // Reject the QUEUED non-priority backlog (running tasks are untouched). There
  // are no queued priority jobs to retain — priorities bypass the queue and
  // start immediately — but we mirror serial's "retain priorities" contract for
  // safety: only non-priority jobs live in `queue`, so all queued jobs here are
  // normal and get cancelled.
  function cancelPending(): void {
    while (queue.length) {
      const job = queue.shift()!;
      job.reject(new CancelledError());
    }
  }

  function setSize(n: number): void {
    cap = Math.max(1, Math.floor(n));
    // Raising the cap should let more queued tasks start right away.
    pump();
  }

  return { run, runPriority, cancelPending, setSize };
}
