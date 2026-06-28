// Minimal observable store: typed state + subscribe. No framework.
export type Listener<T> = (s: T) => void;

export class Store<T> {
  private state: T;
  private listeners = new Set<Listener<T>>();
  constructor(initial: T) { this.state = initial; }
  get(): T { return this.state; }
  set(patch: Partial<T>): void {
    this.state = { ...this.state, ...patch };
    for (const l of this.listeners) l(this.state);
  }
  subscribe(l: Listener<T>): () => void {
    this.listeners.add(l);
    l(this.state);
    return () => this.listeners.delete(l);
  }
}
