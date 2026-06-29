// A per-item status badge. Non-color-only (WCAG 1.4.1): a text label + a glyph,
// not color alone. `state` is one of the FetchMsg phases or a card state.
export class StateBadge extends HTMLElement {
  static get observedAttributes() { return ["state", "label"]; }
  attributeChangedCallback() { this.render(); }
  connectedCallback() { this.render(); }
  private render() {
    const state = this.getAttribute("state") ?? "idle";
    const label = this.getAttribute("label") ?? state;
    const glyph: Record<string, string> = {
      idle: "•", fetching: "⏳", verifying: "🔎", decrypting: "🔐",
      ready: "✓", failed: "⚠", verified: "✓",
    };
    this.setAttribute("role", "status");
    this.setAttribute("data-state", state);
    this.textContent = `${glyph[state] ?? "•"} ${label}`;
  }
}
customElements.define("state-badge", StateBadge);
