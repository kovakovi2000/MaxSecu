// Bundle view-mode persistence (Task 3.3). The chosen way to view a bundle's
// members — "gallery" (a grid of cards) or "stacked" (a vertical per-member
// stack) — is a pure client UI preference. It is remembered across bundle opens
// in localStorage, defaulting to "gallery" on first-ever. This is intentionally
// NOT a backend Settings field: it holds no secret and never crosses the seam.
//
// The helpers are pure/guardable so they can be unit-tested without a DOM: the
// node test harness has neither localStorage nor the Tauri API, and localStorage
// can also throw at runtime (private mode / quota), so every access is guarded.

export type BundleViewMode = "gallery" | "stacked";

export const BUNDLE_VIEW_MODE_KEY = "bundleViewMode";

/** Coerce any stored/candidate value to a valid mode; default "gallery". */
export function normalizeBundleViewMode(v: string | null | undefined): BundleViewMode {
  return v === "stacked" ? "stacked" : "gallery";
}

/** Read the persisted mode, defaulting to "gallery" (first-ever / unavailable). */
export function readBundleViewMode(): BundleViewMode {
  try {
    const ls = (globalThis as { localStorage?: Storage }).localStorage;
    return normalizeBundleViewMode(ls?.getItem(BUNDLE_VIEW_MODE_KEY) ?? null);
  } catch {
    return "gallery";
  }
}

/** Persist the chosen mode; a failing/absent localStorage is swallowed. */
export function writeBundleViewMode(mode: BundleViewMode): void {
  try {
    const ls = (globalThis as { localStorage?: Storage }).localStorage;
    ls?.setItem(BUNDLE_VIEW_MODE_KEY, mode);
  } catch {
    // ignore — a UI preference that can't persist must never break the screen
  }
}
