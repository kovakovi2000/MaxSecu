// A tiny app-wide "busy" flag. While busy — a video transcode/stage or an upload
// is in flight — the router refuses in-app navigation, the nav rail is disabled,
// and window.onbeforeunload warns before the tab/window is closed, so an
// in-flight transcode/upload cannot be silently abandoned. The Cancel button on
// the upload screen is the intended escape hatch. Deliberately minimal: a single
// flag + a human-readable reason + a subscribe for reactive UI.

type Listener = (busy: boolean, reason: string) => void;

let busy = false;
let reason = "";
const listeners = new Set<Listener>();

function notify(): void {
  for (const l of [...listeners]) l(busy, reason);
}

/** Mark the app busy with a human-readable reason (idempotent-ish: updates reason). */
export function setBusy(why: string): void {
  busy = true;
  reason = why;
  notify();
}

/** Clear the busy flag. No-op (no notify) when already idle. */
export function clearBusy(): void {
  if (!busy) return;
  busy = false;
  reason = "";
  notify();
}

/** True while a transcode/upload is in flight. */
export function isBusy(): boolean {
  return busy;
}

/** The current busy reason ("" when idle). */
export function busyReason(): string {
  return reason;
}

/** Subscribe to busy changes; called immediately with the current state. Returns an unsubscribe. */
export function subscribeBusy(l: Listener): () => void {
  listeners.add(l);
  l(busy, reason);
  return () => {
    listeners.delete(l);
  };
}
