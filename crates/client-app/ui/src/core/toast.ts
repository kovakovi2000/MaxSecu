// A tiny toast pub/sub (spec §5). Pure (no DOM/Tauri import) so it is unit-
// testable; <toast-host> subscribes and renders. Errors are assertive (announced
// immediately by screen readers); everything else is polite.
export type ToastKind = "success" | "info" | "error";
export interface ToastEvent { kind: ToastKind; message: string }

type ToastListener = (e: ToastEvent) => void;
const listeners = new Set<ToastListener>();

export function toast(kind: ToastKind, message: string): void {
  const e: ToastEvent = { kind, message };
  for (const l of [...listeners]) l(e);
}
export function subscribeToasts(l: ToastListener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}
