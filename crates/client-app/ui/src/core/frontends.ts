// Frontend registry + runtime switcher. A "frontend" is a named visual skin: a
// complete stylesheet it owns (styles.<id>.css, swapped on the #frontend-css link)
// plus an optional decoration module that injects decorative DOM into data-deco-slot
// mount points. One shared component tree/backend serves all frontends. The choice is
// UI-local (localStorage), exactly like the retired theme presets. DOM/storage access
// is guarded so this module imports cleanly under node:test.
import { pizzaDeco } from "../frontends/pizza/deco.ts";

export type FrontendId = "default" | "pizza" | "slot3";

export interface DecoModule {
  // Called once on apply AND again after every route render — MUST be idempotent
  // (guard against injecting your decoration twice). Safe no-op if your slot is
  // absent on the current screen.
  mount(doc: Document): void;
  // Remove every node mount() injected. Called when switching away from this frontend.
  unmount(doc: Document): void;
}

export const FRONTENDS: ReadonlyArray<{ id: FrontendId; label: string }> = [
  { id: "default", label: "Default" },
  { id: "pizza", label: "Cheese Pizza" },
  { id: "slot3", label: "Custom (empty slot)" },
];

const FRONTEND_KEY = "maxsecu.frontend";

const STYLESHEETS: Record<FrontendId, string> = {
  default: "styles.css",
  pizza: "styles.pizza.css",
  slot3: "styles.slot3.css",
};

const DECO: Partial<Record<FrontendId, DecoModule>> = {
  pizza: pizzaDeco,
};

let activeDeco: DecoModule | null = null;

export function normalizeFrontend(value: unknown): FrontendId {
  return value === "pizza" || value === "slot3" || value === "default"
    ? value
    : "default";
}

export function frontendStylesheet(id: FrontendId): string {
  return STYLESHEETS[id];
}

export function getFrontend(): FrontendId {
  try {
    return normalizeFrontend(window.localStorage.getItem(FRONTEND_KEY));
  } catch {
    return "default";
  }
}

// Effect the frontend: swap stylesheet href + data-frontend attr, then unmount the
// previous deco and mount the new one (both wrapped so a broken deco never bricks the
// swap). Idempotent per id.
export function applyFrontend(value: unknown = getFrontend()): FrontendId {
  const id = normalizeFrontend(value);
  const link = document.getElementById("frontend-css");
  if (link) link.setAttribute("href", frontendStylesheet(id));
  document.documentElement.setAttribute("data-frontend", id);

  const next = DECO[id] ?? null;
  if (activeDeco && activeDeco !== next) {
    try { activeDeco.unmount(document); } catch { /* deco is non-critical */ }
  }
  activeDeco = next;
  if (activeDeco) {
    try { activeDeco.mount(document); } catch { /* deco is non-critical */ }
  }
  return id;
}

export function setFrontend(value: unknown): FrontendId {
  const id = normalizeFrontend(value);
  try {
    window.localStorage.setItem(FRONTEND_KEY, id);
  } catch {
    // Storage can be unavailable in tests / locked-down webviews; the frontend still
    // applies for this session via the DOM.
  }
  applyFrontend(id);
  return id;
}

// Re-run the active deco's idempotent mount (call after each route render so login-
// screen decoration appears once the screen is in the DOM).
export function refreshFrontendDeco(): void {
  if (activeDeco) {
    try { activeDeco.mount(document); } catch { /* deco is non-critical */ }
  }
}
