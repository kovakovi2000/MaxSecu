// Bundle view-mode persistence. The chosen way to view a bundle's members —
// "gallery" (a grid of cards) or "stacked" (a vertical per-member stack) — is a
// non-secret client UI preference. It is remembered across bundle opens in the
// backend settings.json (settings.ui.bundle_view, via the shared settings store),
// NOT in browser localStorage, so nothing lands outside the portable folder.
//
// The helpers are pure/store-backed so they can be unit-tested without a DOM: the
// node test harness has no Tauri host, so writeBundleViewMode patches the store
// LOCALLY (synchronously) first and fires the backend persist fire-and-forget.
import { settingsStore } from "./settings-store-instance.ts";
import { updateSettings } from "./settings.ts";

export type BundleViewMode = "gallery" | "stacked";

/** Coerce any stored/candidate value to a valid mode; default "gallery". */
export function normalizeBundleViewMode(v: string | null | undefined): BundleViewMode {
  return v === "stacked" ? "stacked" : "gallery";
}

/** Read the persisted mode from the settings store (default "gallery"). */
export function readBundleViewMode(): BundleViewMode {
  return normalizeBundleViewMode(settingsStore.get().ui.bundle_view);
}

/** Persist the chosen mode to settings.json. Patches the store locally (sync) so the
 *  UI is responsive, then fires the backend persist fire-and-forget (never blocks the
 *  screen; a UI preference that can't persist must not break rendering). */
export function writeBundleViewMode(mode: BundleViewMode): void {
  settingsStore.patchLocal({ ui: { bundle_view: mode } });
  void updateSettings({ ui: { bundle_view: mode } }).catch(() => {});
}
