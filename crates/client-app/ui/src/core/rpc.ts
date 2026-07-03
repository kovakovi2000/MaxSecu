import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { guardCall } from "./trust-alarm.ts";

// Invokes a backend command. The returned promise REJECTS with the backend's
// sanitized UiError on failure; callers own rejection handling. Every call is
// funnelled through `guardCall`, the single central choke point: a
// `server_untrusted`-class rejection (trust alarms A/B/C) ALWAYS raises the shared
// <trust-alarm> modal and re-throws (fail closed — the action never proceeds, no
// fallback). Ordinary errors pass through unchanged for callers to handle.
export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return guardCall(invoke<T>(cmd, args));
}
// Subscribes to a backend event; resolves to an unlisten function. As with
// call(), the setup promise may reject and callers own rejection handling.
export function on<T>(event: string, cb: (payload: T) => void): Promise<() => void> {
  return listen<T>(event, (e) => cb(e.payload));
}
