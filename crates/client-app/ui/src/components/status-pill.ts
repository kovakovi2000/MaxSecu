// Non-color-only status: every state renders an icon glyph AND its text label,
// inside an ARIA live region so assistive tech announces changes (WCAG 1.4.1).
const ICON: Record<string, string> = {
  connected: "●", reconnecting: "◐", disconnected: "○", degraded: "◑",
  resolving: "…", "tls-handshake": "…", "channel-binding": "…", idle: "○",
};
export class StatusPill extends HTMLElement {
  set state(s: string) {
    this.setAttribute("role", "status");
    this.setAttribute("aria-live", "polite");
    this.textContent = `${ICON[s] ?? "?"} ${s.replace(/-/g, " ")}`;
  }
}
customElements.define("status-pill", StatusPill);
