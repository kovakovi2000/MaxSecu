import { subscribeTrustAlarm, type TrustAlarmEvent } from "../core/trust-alarm.ts";

// <trust-alarm> — the single shared, fail-closed trust-alarm modal (spec §7 / §0-D2).
// Mounted once in the shell, it subscribes to the trust-alarm bus and, on ANY
// `server_untrusted`-class breach (alarm A: upload recovery-pin mismatch; alarm B:
// a TOFU-pinned user key changed; alarm C: a transparency check failed), pops a
// blocking modal with the SAME plain-language "this server may be compromised —
// stop" guidance. The triggering action has ALREADY been blocked upstream
// (guardCall re-throws in core/rpc.ts), so this modal never offers a "continue
// anyway" — only Acknowledge, which dismisses the alert without resuming anything.
//
// Accessible: role="alertdialog" (assertive by nature), aria-modal, labelled by its
// heading and described by the guidance; Escape and a focus trap keep keyboard
// users inside it; focus returns to wherever it was when the alarm fired. All
// dynamic text is set via textContent (never innerHTML) — no XSS surface.
export class TrustAlarm extends HTMLElement {
  private off: (() => void) | null = null;
  private returnFocus: HTMLElement | null = null;
  private keydownHandler = (e: KeyboardEvent) => this.onKeydown(e);

  connectedCallback() {
    this.hidden = true;
    this.innerHTML = `
      <div class="trust-overlay">
        <div
          class="trust-panel"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="ta-h"
          aria-describedby="ta-guidance"
          tabindex="-1"
        >
          <div class="trust-head">
            <span class="trust-mark" aria-hidden="true">⚠</span>
            <h2 id="ta-h">This server may be compromised</h2>
          </div>
          <p id="ta-guidance">
            A security check that pins this server's identity just failed. This can
            mean the server has been tampered with or is impersonating someone.
            <strong>Stop and do not continue.</strong> Your action was blocked and
            no data was sent or shown. Do not retry until you have verified the
            server out of band with your operator.
          </p>
          <p id="ta-detail" class="trust-detail" role="status" aria-live="polite"></p>
          <div class="trust-actions">
            <button type="button" id="ta-ack" class="danger">I understand — stop</button>
          </div>
        </div>
      </div>`;

    (this.querySelector("#ta-ack") as HTMLButtonElement).addEventListener("click", () => this.close());
    // Clicking the backdrop dismisses (acknowledge) — there is deliberately no
    // "continue" affordance anywhere on this modal.
    const overlay = this.querySelector(".trust-overlay") as HTMLElement;
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) this.close();
    });

    this.off = subscribeTrustAlarm((e) => this.open(e));
  }

  disconnectedCallback() {
    this.off?.();
    document.removeEventListener("keydown", this.keydownHandler);
  }

  private open(e: TrustAlarmEvent) {
    // Re-entrancy guard: a second alarm firing while the modal is already open must
    // NOT clobber `returnFocus` with the modal's own Acknowledge button (which would
    // trap focus inside the modal after it closes). The modal is already blocking,
    // so the first alarm's guidance stands.
    if (!this.hidden) return;
    // Remember where focus was so it can be restored on acknowledge.
    this.returnFocus = (document.activeElement as HTMLElement) ?? null;
    const detail = this.querySelector("#ta-detail") as HTMLElement;
    // The core's sanitized message (e.g. which user key changed) as secondary
    // detail — textContent only, never HTML.
    detail.textContent = e.message ? `Details: ${e.message}` : "";
    this.hidden = false;
    // Guard against a double-open registering the handler twice.
    document.removeEventListener("keydown", this.keydownHandler);
    document.addEventListener("keydown", this.keydownHandler);
    (this.querySelector("#ta-ack") as HTMLButtonElement).focus();
  }

  private close() {
    this.hidden = true;
    document.removeEventListener("keydown", this.keydownHandler);
    this.returnFocus?.focus();
    this.returnFocus = null;
  }

  private onKeydown(e: KeyboardEvent) {
    if (this.hidden) return;
    if (e.key === "Escape") {
      e.preventDefault();
      this.close();
      return;
    }
    if (e.key === "Tab") this.trapTab(e);
  }

  private trapTab(e: KeyboardEvent) {
    // Only the Acknowledge button is focusable, so the trap simply keeps focus
    // pinned to it (Tab / Shift+Tab never escape the modal).
    const ack = this.querySelector("#ta-ack") as HTMLButtonElement;
    e.preventDefault();
    ack.focus();
  }
}
customElements.define("trust-alarm", TrustAlarm);
