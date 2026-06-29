// A progress meter with a textual percentage (non-color-only) and an ARIA
// progressbar. Set `value`/`max` (and optional `detail` text). 0/0 ⇒ indeterminate.
export class ProgressMeter extends HTMLElement {
  static get observedAttributes() { return ["value", "max", "detail"]; }
  attributeChangedCallback() { this.render(); }
  connectedCallback() { this.render(); }
  private render() {
    const value = Number(this.getAttribute("value") ?? "0");
    const max = Number(this.getAttribute("max") ?? "0");
    const detail = this.getAttribute("detail") ?? "";
    const pct = max > 0 ? Math.round((value / max) * 100) : null;
    this.setAttribute("role", "progressbar");
    if (pct !== null) {
      this.setAttribute("aria-valuenow", String(pct));
      this.setAttribute("aria-valuemin", "0");
      this.setAttribute("aria-valuemax", "100");
      this.textContent = `${pct}%${detail ? ` — ${detail}` : ""}`;
    } else {
      this.removeAttribute("aria-valuenow");
      this.textContent = detail || "Working…";
    }
  }
}
customElements.define("progress-meter", ProgressMeter);
