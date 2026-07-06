import { call } from "./rpc.ts";
import type { Settings } from "./types.ts";
import { SettingsStore } from "./settings-store.ts";
import { decodePool } from "./pool.ts";

const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { media_cache_cap_mb: 1024, thumb_cache_cap_mb: 256, feed_concurrency: 4, transcode_threads: 4, decode_threads: 4, cache_location: "Memory" },
  connection: { route_mode: "prefer-server" },
  appearance: { theme: "dark" },
};

export type ThemePreset = "tech" | "cheese" | "pottery";
const THEME_PRESET_KEY = "maxsecu.themePreset";

function normalizeThemePreset(value: unknown): ThemePreset {
  return value === "cheese" || value === "pottery" || value === "tech" ? value : "tech";
}

export function getThemePreset(): ThemePreset {
  try {
    return normalizeThemePreset(window.localStorage.getItem(THEME_PRESET_KEY));
  } catch {
    return "tech";
  }
}

export function setThemePreset(value: unknown): ThemePreset {
  const preset = normalizeThemePreset(value);
  try {
    window.localStorage.setItem(THEME_PRESET_KEY, preset);
  } catch {
    // Local storage can be unavailable in tests or locked-down webviews; the
    // visual preset still applies for this session through the DOM attribute.
  }
  applyThemePreset(preset);
  return preset;
}

export function applyThemePreset(value: unknown = getThemePreset()): ThemePreset {
  const preset = normalizeThemePreset(value);
  document.documentElement.setAttribute("data-theme", preset);
  return preset;
}

// The single shared settings store (spec §7). Settings screen, the header RAM
// gauge, and the shell theme all read/write THIS instance, so they always agree
// and apply live.
export const settingsStore = new SettingsStore(DEFAULTS);

// Apply settings live: visual theme preset + a11y data-attrs (styles.css keys on
// them; reduced-motion ALSO respects the OS via a media query), and resize the
// shared feed-decode pool from `feed_concurrency`. Theme presets are deliberately
// frontend-only placeholders; the persisted backend appearance contract remains
// the existing dark setting.
export function applySettings(s: Settings): void {
  const root = document.documentElement;
  applyThemePreset();
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
