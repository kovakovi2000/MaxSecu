import { subscribeToasts, type ToastEvent } from "../core/toast.ts";

// Singleton toast surface mounted once in the shell. Two ARIA-live regions:
// assertive for errors, polite for success/info. Each toast is a node built via
// textContent (never innerHTML) and auto-dismisses; errors linger longer.
export class ToastHost extends HTMLElement {
  private off: (() => void) | null = null;

  connectedCallback() {
    this.innerHTML = `
      <div class="toast-stack">
        <div id="toast-assertive" role="alert" aria-live="assertive" aria-atomic="true"></div>
        <div id="toast-polite" role="status" aria-live="polite" aria-atomic="true"></div>
      </div>`;
    this.off = subscribeToasts((e) => this.show(e));
  }
  disconnectedCallback() {
    this.off?.();
  }
  private show(e: ToastEvent) {
    const region = this.querySelector(
      e.kind === "error" ? "#toast-assertive" : "#toast-polite",
    ) as HTMLElement;
    const item = document.createElement("div");
    item.className = `toast toast-${e.kind}`;
    item.textContent = e.message; // textContent: never HTML.
    region.appendChild(item);
    const ttl = e.kind === "error" ? 7000 : 4000;
    window.setTimeout(() => item.remove(), ttl);
  }
}
customElements.define("toast-host", ToastHost);
