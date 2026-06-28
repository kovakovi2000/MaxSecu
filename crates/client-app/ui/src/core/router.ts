export type Route = "connect" | "feed";
export class Router {
  constructor(private onChange: (r: Route) => void) {
    window.addEventListener("hashchange", () => this.emit());
    this.emit();
  }
  private emit() {
    const r = (location.hash.replace("#/", "") || "connect") as Route;
    this.onChange(r);
  }
  go(r: Route) { location.hash = `#/${r}`; }
}
