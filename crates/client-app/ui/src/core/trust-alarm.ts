// Shared fail-closed trust alarm (spec §7 / §0-D2). The trusted core raises ONE
// distinct error code — `server_untrusted` — for every trust-anchor breach:
//   * alarm A: an upload's served recovery pubkey ≠ the embedded pin,
//   * alarm B: a TOFU-pinned OTHER user's directory key changed at share time,
//   * alarm C: a directory transparency inclusion/consistency check failed on
//     browse/open.
// All three funnel through here so a possibly-compromised server always produces
// the SAME prominent "stop" modal and NEVER a silent continue or fallback.
//
// This module is pure (no DOM, no Tauri import) so it is unit-testable; the
// <trust-alarm> component subscribes and renders the blocking modal. `guardCall`
// is the single choke point wired into core/rpc.ts's `call()`, so every command
// (upload / share / browse / open / login / recovery / register) is covered.

/// The one stable code the core returns for any A/B/C trust-anchor breach.
export const SERVER_UNTRUSTED = "server_untrusted";

export interface TrustAlarmEvent {
  /// Always `server_untrusted` today; kept explicit so the modal can key off it.
  code: string;
  /// The core's sanitized message (e.g. which user key changed). Rendered as
  /// secondary detail beneath the fixed "this server may be compromised" guidance.
  message: string;
}

type Listener = (e: TrustAlarmEvent) => void;
const listeners = new Set<Listener>();

/** True if `e` is the shared server_untrusted-class trust alarm (A/B/C). */
export function isServerUntrusted(e: unknown): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    (e as { code?: unknown }).code === SERVER_UNTRUSTED
  );
}

/** Notify the <trust-alarm> modal of a trust-anchor breach. */
export function raiseTrustAlarm(e: unknown): void {
  const code =
    typeof e === "object" && e !== null && typeof (e as { code?: unknown }).code === "string"
      ? String((e as { code: string }).code)
      : SERVER_UNTRUSTED;
  const message =
    typeof e === "object" && e !== null && typeof (e as { message?: unknown }).message === "string"
      ? String((e as { message: string }).message)
      : "";
  const ev: TrustAlarmEvent = { code, message };
  for (const l of [...listeners]) l(ev);
}

/** Subscribe to trust alarms; returns an unsubscribe fn. */
export function subscribeTrustAlarm(l: Listener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/**
 * Wrap a backend command promise so a `server_untrusted` rejection ALWAYS raises
 * the shared trust-alarm modal AND re-throws — the triggering action does not
 * proceed and there is no fallback. Ordinary errors and successes pass through
 * untouched. Wired into core/rpc.ts's `call()` so every command is covered.
 */
export async function guardCall<T>(p: Promise<T>): Promise<T> {
  try {
    return await p;
  } catch (e) {
    if (isServerUntrusted(e)) raiseTrustAlarm(e);
    throw e; // fail closed: re-throw so callers never see a "continue anyway" path
  }
}
