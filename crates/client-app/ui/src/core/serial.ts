// A single-flight async queue. The backend re-authenticates on a fresh channel
// and `try_lock`s ONE connect lock + borrows ONE non-Clone identity, so two
// authed commands cannot run at once — this queue serializes them. Hardened:
// every task releases the runner on success/error/cancel; a priority task jumps
// ahead of queued (not-yet-started) tasks (so opening the viewer is not stuck
// behind a backlog of card decrypts); `cancelPending` rejects everything still
// queued (used when leaving the feed) so a stalled backlog can't wedge the lock.

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
  // Run, then ALWAYS release and pump the next — success or failure.
  job
    .task()
    .then(
      (v) => job.resolve(v),
      (e) => job.reject(e),
    )
    .finally(() => {
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

// Reject everything still queued (not the running task). Used when navigating
// away from the feed so a backlog of card decrypts cannot wedge the lock.
export function cancelPending(): void {
  while (queue.length) {
    const job = queue.shift()!;
    job.reject(new Error("cancelled"));
  }
}
