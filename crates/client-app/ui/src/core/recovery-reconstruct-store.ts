// Pure, Tauri-free state for the T6 `<recovery-reconstruct-screen>` (mirrors
// settings-store.ts). The BACKEND (`add_recovery_share`) is the sole source of
// truth for `have`/`need`/`label` — this store only ever advances by applying
// an ACCEPTED backend response via `applyAccepted`. A REJECTED add
// (malformed/corrupt/duplicate/foreign/out-of-range-index, spec §6 step 1)
// comes back as a `UiError`, not an `AddShareResponse` — the component's job is
// to render that rejection's `role=alert` copy and simply NOT call
// `applyAccepted`, so `have` can never be bumped by a rejected add (a duplicate
// index included). This file has no Tauri import, so it is unit-testable in
// plain `node:test` (see `recovery-reconstruct-store.test.ts`).

export interface ShareCount {
  have: number;
  need: number;
  label: string;
}

export class ReconstructState {
  private state: ShareCount;
  constructor(initial: ShareCount = { have: 0, need: 0, label: "" }) {
    this.state = initial;
  }
  get(): ShareCount {
    return this.state;
  }
  // Apply an ACCEPTED add_recovery_share (or reconstruct-time re-sync) response.
  // Never call this for a rejected add.
  applyAccepted(resp: ShareCount): void {
    this.state = resp;
  }
  // True once at least `need` shares have been accepted. Requires `need > 0`
  // (a threshold actually learned from a first accepted share) so a fresh 0/0
  // session is never reported as reconstructable.
  canReconstruct(): boolean {
    return this.state.need > 0 && this.state.have >= this.state.need;
  }
  reset(): void {
    this.state = { have: 0, need: 0, label: "" };
  }
}

// The five add_recovery_share rejection codes (spec §6 step 1 / §10), each
// with its own distinct, non-scary operator-facing copy — never a generic
// "something went wrong". Falls back to the caller-supplied text (the
// backend's own UiError.message) for any code not in this table, so a future
// backend code still surfaces something actionable rather than nothing.
const REJECTION_COPY: Record<string, string> = {
  malformed_share:
    "This doesn't look like a MaxSecu recovery share — check for a copy/paste error.",
  corrupt_share: "This share may be corrupted or mistyped — re-enter it.",
  duplicate_share: "You've already added that share.",
  foreign_share: "This share is from a different recovery key set.",
  invalid_share_index:
    "This share's number is out of range — check for a copy/paste error.",
};

export function rejectionCopy(code: string, fallback: string): string {
  return REJECTION_COPY[code] ?? fallback;
}
