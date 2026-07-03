import { isBusy } from "./busy.ts";

export const ROUTES = [
  "connect", "feed", "mine", "bootstrap", "pending", "admin", "viewer", "upload", "settings",
  "recovery", "register",
] as const;
export type Route = (typeof ROUTES)[number];

// Pure guard (exported for tests): while the app is busy (a transcode/upload is
// in flight) an in-app route change to a DIFFERENT hash is refused, so the user
// can't navigate away mid-transcode. Same-hash "changes" (e.g. our own restore)
// are always allowed through.
export function shouldBlockNav(busy: boolean, current: string, next: string): boolean {
  return busy && next !== current;
}

export class Router {
  // Explicit field (not a `private` constructor parameter property): Node's
  // `--experimental-strip-types` test runner rejects parameter properties, and
  // router.ts is imported by router.test.ts. Runtime behavior is identical.
  private onChange: (r: Route) => void;
  // The hash we last accepted — used to restore the URL when a navigation is
  // refused while busy so the address bar doesn't drift out of sync.
  private current: string;
  constructor(onChange: (r: Route) => void) {
    this.onChange = onChange;
    this.current = location.hash;
    window.addEventListener("hashchange", () => {
      if (shouldBlockNav(isBusy(), this.current, location.hash)) {
        // Refuse: restore the previous hash. replaceState does NOT re-fire
        // hashchange, so this quietly reverts without re-entering the guard.
        history.replaceState(null, "", this.current || "#/");
        return;
      }
      this.emit();
    });
    this.emit();
  }
  private emit() {
    this.current = location.hash;
    const raw = location.hash.replace(/^#\//, "").split("?")[0];
    const r: Route = (ROUTES as readonly string[]).includes(raw) ? (raw as Route) : "connect";
    this.onChange(r);
  }
  go(r: Route) { location.hash = `#/${r}`; }
}
