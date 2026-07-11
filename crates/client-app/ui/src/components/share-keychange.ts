import type { ReshareOutcome } from "../core/types.ts";

// A recipient outcome whose key changed since we last shared: warn + confirm.
export function isKeyChange(o: ReshareOutcome): boolean {
  return !o.ok && o.code === "key_changed";
}

// The human warning for a changed recipient key. Pure so it is unit-testable.
export function keyChangeMessage(o: ReshareOutcome): string {
  const oldFp = o.old_fingerprint ?? "unknown";
  const newFp = o.new_fingerprint ?? "unknown";
  return (
    `${o.username}'s security key has changed since you last shared with them. ` +
    `This can happen if they reinstalled the app — but it can also mean someone ` +
    `is impersonating them.\n\nPreviously: ${oldFp}\nNow: ${newFp}\n\n` +
    `Only continue if you trust this change.`
  );
}
