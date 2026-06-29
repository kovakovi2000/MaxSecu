const routes = ["connect", "feed", "bootstrap", "pending", "admin", "viewer", "upload"] as const;
export type Route = (typeof routes)[number];
export class Router {
  constructor(private onChange: (r: Route) => void) {
    window.addEventListener("hashchange", () => this.emit());
    this.emit();
  }
  private emit() {
    // Strip any `?query` (e.g. `#/viewer?id=x`) before matching: the route is
    // the path segment only; the component reads its own query from the hash.
    const raw = location.hash.replace(/^#\//, "").split("?")[0];
    const r: Route = (routes as readonly string[]).includes(raw) ? (raw as Route) : "connect";
    this.onChange(r);
  }
  go(r: Route) { location.hash = `#/${r}`; }
}
