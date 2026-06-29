import { call } from "./rpc.ts";
import type { Settings } from "./types.ts";

// Apply accessibility settings by setting data-* attributes on <html>; styles.css
// keys on them. Reduced-motion ALSO respects the OS via a prefers-reduced-motion
// media query in styles.css.
export function applySettings(s: Settings): void {
  const root = document.documentElement;
  root.toggleAttribute("data-reduced-motion", s.a11y.reduced_motion);
  root.toggleAttribute("data-high-contrast", s.a11y.high_contrast);
  root.setAttribute("data-text-size", s.a11y.text_size);
}

// Load settings from the backend and apply them; safe to call on boot. Returns
// the loaded settings, or null if the backend call failed (defaults stay).
export async function loadAndApplySettings(): Promise<Settings | null> {
  try {
    const s = await call<Settings>("get_settings");
    applySettings(s);
    return s;
  } catch {
    return null;
  }
}
