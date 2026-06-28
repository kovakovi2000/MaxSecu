// Minimal observable store: typed state + subscribe. No framework.
export type Listener<T> = (s: T) => void;

export class Store<T> {
  private state: T;
  private listeners = new Set<Listener<T>>();
  constructor(initial: T) { this.state = initial; }
  get(): T { return this.state; }
  // Shallow merge: replaces top-level keys of state with those in `patch`;
  // always notifies all subscribers (no dirty-check). Listeners are snapshotted
  // before notifying, so subscribe/unsubscribe during a set() is safe.
  set(patch: Partial<T>): void {
    this.state = { ...this.state, ...patch };
    for (const l of [...this.listeners]) l(this.state);
  }
  subscribe(l: Listener<T>): () => void {
    this.listeners.add(l);
    l(this.state);
    return () => this.listeners.delete(l);
  }
}
