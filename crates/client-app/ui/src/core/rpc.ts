import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// Invokes a backend command. The returned promise REJECTS with the backend's
// sanitized UiError on failure; callers own rejection handling.
export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);
}
// Subscribes to a backend event; resolves to an unlisten function. As with
// call(), the setup promise may reject and callers own rejection handling.
export function on<T>(event: string, cb: (payload: T) => void): Promise<() => void> {
  return listen<T>(event, (e) => cb(e.payload));
}
