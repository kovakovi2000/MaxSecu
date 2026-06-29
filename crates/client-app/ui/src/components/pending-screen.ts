import { call } from "../core/rpc.ts";
import type { AccountStateMsg } from "../core/types.ts";

// Status-only pending screen (D-G) with adaptive polling (D-I). The username is
// passed via the `username` attribute set by the shell after login.
export class PendingScreen extends HTMLElement {
  private timer: number | null = null;
  private epoch = 0;
  private readonly fast = 5000;
  private readonly slow = 30000;

  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="pd-h">
        <h1 id="pd-h" tabindex="-1">Awaiting approval</h1>
        <p>Your account has been created and is waiting for an administrator to
           approve it at the next signing ceremony.</p>
        <dl>
          <dt>Account</dt><dd><code id="pd-user"></code></dd>
        </dl>
        <p id="pd-status" role="status" aria-live="polite">Checking status…</p>
      </main>`;
    const user = this.getAttribute("username") ?? "";
    (this.querySelector("#pd-user") as HTMLElement).textContent = user;
    (this.querySelector("#pd-h") as HTMLElement).focus();
    document.addEventListener("visibilitychange", this.onVisibility);
    this.startPolling();
  }

  disconnectedCallback() {
    this.epoch++; // invalidate any in-flight chain
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    document.removeEventListener("visibilitychange", this.onVisibility);
  }

  // Re-poll promptly when the window regains focus (immediate-on-focus, D-I).
  // startPolling bumps the epoch, so any prior chain is cancelled — no doubling.
  private onVisibility = () => {
    if (!document.hidden) this.startPolling();
  };

  // Begins a fresh poll chain identified by a new epoch; cancels the previous.
  private startPolling() {
    this.epoch++;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    void this.poll(this.epoch);
  }

  private async poll(myEpoch: number) {
    const user = this.getAttribute("username") ?? "";
    // Empty username (e.g. a webview reload reset the in-memory session) — we
    // can't poll; send the user back to sign in rather than loop forever.
    if (!user) {
      location.hash = "#/connect";
      return;
    }
    let state: string | null = null;
    try {
      const res = await call<AccountStateMsg>("account_status", { req: { username: user } });
      state = res.state;
    } catch {
      /* network error: state stays null, handled below */
    }
    // Bail if a newer chain superseded us or the element was torn down while the
    // request was in flight — guarantees exactly one live chain.
    if (myEpoch !== this.epoch || !this.isConnected) return;
    const status = this.querySelector("#pd-status");
    if (!status) return;
    if (state === "active") {
      status.textContent = "Approved — opening the app…";
      location.hash = "#/feed";
      return; // stop polling; route away
    }
    status.textContent = state
      ? "Still pending. We'll keep checking."
      : "Couldn't reach the server; retrying…";
    const interval = document.hidden ? this.slow : this.fast;
    this.timer = window.setTimeout(() => void this.poll(myEpoch), interval);
  }
}

customElements.define("pending-screen", PendingScreen);
