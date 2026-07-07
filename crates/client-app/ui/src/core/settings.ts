import { call } from "./rpc.ts";
import type { Settings } from "./types.ts";
import { decodePool } from "./pool.ts";
import { applyFrontend } from "./frontends.ts";

// The single shared settings store (spec §7). Settings screen, the header RAM
// gauge, and the shell theme all read/write THIS instance, so they always agree
// and apply live. The instance itself lives in the settings-store-instance.ts leaf
// module so frontends.ts can import it without an import cycle; re-exported here so
// existing `import { settingsStore } from "./settings.ts"` call sites keep working.
export { settingsStore } from "./settings-store-instance.ts";
import { settingsStore } from "./settings-store-instance.ts";

// Apply settings live: active frontend + a11y data-attrs (styles.css keys on
// them; reduced-motion ALSO respects the OS via a media query), and resize the
// shared feed-decode pool from `feed_concurrency`. The active frontend is UI-local
// (localStorage, via applyFrontend); the persisted backend appearance contract
// remains the existing dark setting.
export function applySettings(s: Settings): void {
  const root = document.documentElement;
  applyFrontend();
  root.toggleAttribute("data-reduced-motion", s.a11y.reduced_motion);
  root.toggleAttribute("data-high-contrast", s.a11y.high_contrast);
  root.setAttribute("data-text-size", s.a11y.text_size);
  decodePool.setSize(s.performance.feed_concurrency);
}

// Load persisted settings into the store and apply them. Safe on boot. Returns
// the loaded settings, or null on failure (defaults stay).
export async function loadAndApplySettings(): Promise<Settings | null> {
  try {
    const s = await call<Settings>("get_settings");
    settingsStore.set(s);
    applySettings(s);
    return s;
  } catch {
    return null;
  }
}

// Persist a patch: merge into the store, push to the backend, reflect any
// normalization (clamping) the backend returns, and apply live. Throws the
// sanitized UiError on failure (callers surface it).
export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  settingsStore.patchLocal(patch);
  const norm = await call<Settings>("set_settings", { settings: settingsStore.get() });
  settingsStore.set(norm);
  applySettings(norm);
  return norm;
}

// Subscribe the document theme/a11y attrs to every store change (call once on
// boot, after loadAndApplySettings, so live edits from any screen apply).
export function bindDocumentToSettings(): () => void {
  return settingsStore.subscribe((s) => applySettings(s));
}
