import { isCancelled } from "./serial.ts";

// Decide what a self-decrypting feed card should do when its decrypt settles with
// an error. This exists to fix a real bug: leaving the feed calls the GLOBAL
// `cancelPending()`, which flushes the one shared serial queue used by EVERY
// card. Under rapid feed → tab → feed navigation a card that is still on screen
// could have its queued decrypt rejected with a benign "cancelled" and then
// render that as a PERMANENT failure badge (the classic "the second image always
// switches to cancelled" report) — with no retry.
//
// The correct behavior:
//   - a cancellation on a card that is NO LONGER in the live DOM → drop silently
//     (it's being torn down; rendering anything is pointless),
//   - a cancellation on a card that is STILL connected → the flush was not meant
//     for this live card, so retry (bounded, so a pathological loop can't run away),
//   - any non-cancellation error → show the failed badge as before.
//
// Pure + dependency-light so it is unit-tested without a DOM.

export type CardOutcome = "retry" | "drop" | "fail";

export const MAX_CARD_RETRIES = 5;

export function decideCardOutcome(
  err: unknown,
  connected: boolean,
  attempts: number,
  maxRetries: number = MAX_CARD_RETRIES,
): CardOutcome {
  if (isCancelled(err)) {
    if (!connected) return "drop";
    return attempts < maxRetries ? "retry" : "fail";
  }
  return "fail";
}
