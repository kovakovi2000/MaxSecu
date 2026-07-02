// A single-flight async queue. The backend re-authenticates on a fresh channel
// and `try_lock`s ONE connect lock + borrows ONE non-Clone identity, so two
// authed commands cannot run at once — this queue serializes them. Hardened:
// every task releases the runner on success/error/cancel; a priority task jumps
// ahead of queued (not-yet-started) tasks (so opening the viewer is not stuck
// behind a backlog of card decrypts); `cancelPending` rejects everything still
// queued (used when leaving the feed) so a stalled backlog can't wedge the lock.

// The rejection `cancelPending` uses. A distinct type so callers (e.g. a feed
// card) can tell a benign queue-flush from a real backend failure and react
// differently — a still-on-screen card retries; a torn-down one drops silently.
// `.message` stays "cancelled" for back-compat with existing assertions/logs.
export class CancelledError extends Error {
  constructor() {
    super("cancelled");
    this.name = "CancelledError";
  }
}

/** True if `e` is a serial-queue cancellation (vs a real error). */
export function isCancelled(e: unknown): e is CancelledError {
  return (
    e instanceof CancelledError ||
    (typeof e === "object" && e !== null && (e as { message?: unknown }).message === "cancelled")
  );
}

type Job<T = unknown> = {
  task: () => Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
  priority: boolean;
};

const queue: Job[] = [];
let running = false;

function pump(): void {
  if (running) return;
  const job = queue.shift();
  if (!job) return;
  running = true;
  // Invoke inside try/catch so a SYNCHRONOUS throw (not just a rejected promise)
  // still releases the runner and rejects the job — the queue must never wedge.
  let p: Promise<unknown>;
  try {
    p = Promise.resolve(job.task());
  } catch (e) {
    running = false;
    job.reject(e);
    pump();
    return;
  }
  // Run, then ALWAYS release and pump the next — success or failure.
  p.then(
    (v) => job.resolve(v),
    (e) => job.reject(e),
  ).finally(() => {
    running = false;
    pump();
  });
}

function enqueue<T>(task: () => Promise<T>, priority: boolean): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const job: Job<T> = { task, resolve, reject, priority };
    if (priority) {
      // Insert ahead of the first non-priority job (after any queued priorities).
      let i = 0;
      while (i < queue.length && queue[i].priority) i++;
      queue.splice(i, 0, job as Job);
    } else {
      queue.push(job as Job);
    }
    // When the queue is idle this starts the task SYNCHRONOUSLY during the
    // serial()/serialPriority() call — deliberate; the priority ordering relies
    // on the running task not being preemptible once it has started.
    pump();
  });
}

export function serial<T>(task: () => Promise<T>): Promise<T> {
  return enqueue(task, false);
}

// High-priority: jumps ahead of queued normal tasks (e.g. viewer open over a
// backlog of card decrypts). Does NOT preempt the already-running task.
export function serialPriority<T>(task: () => Promise<T>): Promise<T> {
  return enqueue(task, true);
}

// Reject the queued NON-priority backlog (not the running task). Used when
// navigating away from the feed so a backlog of card decrypts cannot wedge the
// lock. PRIORITY jobs are RETAINED: they are user-initiated (a viewer open via
// `serialPriority`) and must survive a feed-teardown flush — otherwise navigating
// feed→viewer while cards are still decrypting cancels the open ("cancelled" /
// "Could not open this item"), a timing race that broke video (and any) playback.
export function cancelPending(): void {
  const kept: Job[] = [];
  while (queue.length) {
    const job = queue.shift()!;
    if (job.priority) kept.push(job);
    else job.reject(new CancelledError());
  }
  // Restore the retained priority jobs (order preserved) and resume the queue.
  queue.push(...kept);
  pump();
}
