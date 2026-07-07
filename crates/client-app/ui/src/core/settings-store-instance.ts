import { SettingsStore } from "./settings-store.ts";
import type { Settings } from "./types.ts";

// The single shared settings store instance lives in this tiny LEAF module so that
// both settings.ts (which owns updateSettings) and frontends.ts (which needs the
// store + updateSettings) can import it without forming an initialization cycle.
// settings.ts re-exports it so existing `import { settingsStore } from "./settings.ts"`
// call sites keep working.
const DEFAULTS: Settings = {
  a11y: { reduced_motion: false, high_contrast: false, text_size: "normal" },
  behavior: { confirm_destructive: false },
  performance: { media_cache_cap_mb: 1024, thumb_cache_cap_mb: 256, feed_concurrency: 4, transcode_threads: 4, decode_threads: 4, cache_location: "Memory" },
  connection: { route_mode: "prefer-server" },
  appearance: { theme: "dark", frontend: "default" },
  ui: { bundle_view: "gallery" },
  playback: { volume: 1.0, muted: false },
};

export const settingsStore = new SettingsStore(DEFAULTS);
