// A FIFO async serializer: runs tasks ONE AT A TIME via a promise chain. Used so
// the feed's per-card `decrypt_card` calls (and the viewer's `open_content`) do
// not fan out concurrently — each re-authenticates on a fresh channel and
// try_locks a single connect lock in the backend, so parallel calls would fail
// "busy". Serializing keeps the channel-bound auth flow correct and the UI honest.
let tail: Promise<unknown> = Promise.resolve();

export function serial<T>(task: () => Promise<T>): Promise<T> {
  // Chain after the previous task regardless of its outcome (success or failure),
  // so one card's error never stalls the rest of the queue.
  const run = tail.then(task, task);
  tail = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}
