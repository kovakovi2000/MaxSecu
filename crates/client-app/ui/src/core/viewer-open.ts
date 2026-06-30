// Orchestrates the viewer's "open one item" flow, factored OUT of the DOM
// component (<media-viewer>) so it is testable under node:test without a DOM or a
// Tauri mock. The component wires the real dependencies (subscribe = listen to the
// status events, open = serialPriority(call("open_content"))); this function owns
// only the control flow.

export interface ViewerOpenDeps<T> {
  /** Subscribe to the per-item status events; resolves to an unlisten fn. */
  subscribe: () => Promise<() => void>;
  /** Fetch + verify + decrypt the item (serialized backend call). */
  open: () => Promise<T>;
  /** Called with the opened content on success. */
  onResult: (c: T) => void;
  /** Called with a sanitized error on failure. */
  onError: (x: unknown) => void;
}

/** Returns a cleanup function the component calls from `disconnectedCallback`. */
export function runViewerOpen<T>(deps: ViewerOpenDeps<T>): () => void {
  // The status subscription is best-effort feedback ONLY — it must NEVER gate the
  // content open. Subscribing is fire-and-forget (matching every other screen);
  // `open()` is dispatched immediately and independently. If `subscribe()` never
  // settles (or rejects), the open still runs and the viewer still loads.
  let unlisten: (() => void) | null = null;
  let cleaned = false;
  deps
    .subscribe()
    .then((u) => {
      // If the component already disconnected before the listener landed, unlisten
      // straight away so the late subscription doesn't leak.
      if (cleaned) u();
      else unlisten = u;
    })
    .catch(() => {
      // A failed subscription only costs the live status line — not the open.
    });

  void (async () => {
    try {
      deps.onResult(await deps.open());
    } catch (x) {
      deps.onError(x);
    }
  })();

  return () => {
    cleaned = true;
    unlisten?.();
  };
}
