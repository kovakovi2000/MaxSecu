const routes = ["connect", "feed"] as const;
export type Route = (typeof routes)[number];
export class Router {
  constructor(private onChange: (r: Route) => void) {
    window.addEventListener("hashchange", () => this.emit());
    this.emit();
  }
  private emit() {
    const raw = location.hash.replace(/^#\//, "");
    const r: Route = (routes as readonly string[]).includes(raw) ? (raw as Route) : "connect";
    this.onChange(r);
  }
  go(r: Route) { location.hash = `#/${r}`; }
}
