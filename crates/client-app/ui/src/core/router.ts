export const ROUTES = [
  "connect", "feed", "mine", "bootstrap", "pending", "admin", "viewer", "upload", "settings",
] as const;
export type Route = (typeof ROUTES)[number];
export class Router {
  // Explicit field (not a `private` constructor parameter property): Node's
  // `--experimental-strip-types` test runner rejects parameter properties, and
  // router.ts is imported by router.test.ts. Runtime behavior is identical.
  private onChange: (r: Route) => void;
  constructor(onChange: (r: Route) => void) {
    this.onChange = onChange;
    window.addEventListener("hashchange", () => this.emit());
    this.emit();
  }
  private emit() {
    const raw = location.hash.replace(/^#\//, "").split("?")[0];
    const r: Route = (ROUTES as readonly string[]).includes(raw) ? (raw as Route) : "connect";
    this.onChange(r);
  }
  go(r: Route) { location.hash = `#/${r}`; }
}
