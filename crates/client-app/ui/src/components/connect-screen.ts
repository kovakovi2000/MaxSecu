import { call } from "../core/rpc.ts";
import { setUsername } from "../core/session.ts";
import type { AccountStateMsg, Settings } from "../core/types.ts";

export class ConnectScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" class="connect-main" tabindex="-1" aria-labelledby="cn-h">
        <section class="connect-stage" aria-label="MaxSecu sign in">
          <div class="connect-hero">
            <div class="connect-visual" aria-hidden="true">
              <div class="scan-orb"><span>MX</span></div>
              <div class="orbit-ring ring-a"></div>
              <div class="orbit-ring ring-b"></div>
              <div class="signal-bars"><i></i><i></i><i></i><i></i></div>
            </div>
            <p class="eyebrow">zero-knowledge uplink</p>
            <h1 id="cn-h">Enter the secure media vault</h1>
            <p class="hero-copy">Encrypted posts, verified authors, local-first rendering. The UI only sees decrypted display data after the trusted core clears it.</p>
            <div class="hero-grid">
              <span>TCB locked</span>
              <span>serial queue</span>
              <span>no raw keys</span>
            </div>
            <div class="boot-console" aria-hidden="true">
              <span>kernel://ready</span>
              <span>identity://sealed</span>
              <span>render://sandboxed</span>
            </div>
          </div>
          <form id="f" class="connect-card" aria-describedby="cn-status err">
            <div class="form-head">
              <p class="eyebrow">session gate</p>
              <h2>Connect</h2>
              <p>Unlock your local keystore, then bind to a MaxSecu server.</p>
            </div>
            <div class="connect-core" aria-hidden="true">
              <span class="core-dot"></span>
              <span class="core-line"></span>
              <span class="core-dot"></span>
            </div>
            <label>Server <input name="server" required autocomplete="off" placeholder="localhost:8443"></label>
            <label>Username <input name="username" required autocomplete="username" placeholder="operator"></label>
            <label>Password <input name="password" type="password" required autocomplete="current-password" placeholder="••••••••"></label>
            <label class="tor-switch"><input type="checkbox" name="tor"> <span>Route through Tor</span></label>
            <button type="submit" class="connect-submit"><span class="submit-label">Connect securely</span><span class="submit-loader" aria-hidden="true"></span></button>
            <p id="cn-status" class="connect-status" role="status" aria-live="polite">Awaiting credentials.</p>
            <p id="err" role="alert"></p>
          </form>
        </section>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();
    const f = this.querySelector("#f") as HTMLFormElement;

    // Initialize the "Route through Tor" checkbox from the persisted route setting
    // (checked iff route_mode is "tor-only"). Ticking it at connect persists
    // TorOnly back to Settings — the login⇄setting coupling lives in the `connect`
    // command. Best-effort; on failure the box just starts unchecked.
    call<Settings>("get_settings")
      .then((s) => {
        const torBox = f.querySelector('input[name="tor"]') as HTMLInputElement | null;
        if (torBox) torBox.checked = s.connection.route_mode === "tor-only";
      })
      .catch(() => { /* keep default (unchecked) */ });
    const stage = this.querySelector(".connect-stage") as HTMLElement;
    const err = this.querySelector("#err") as HTMLElement;
    const status = this.querySelector("#cn-status") as HTMLElement;
    const submitLabel = this.querySelector(".submit-label") as HTMLElement;
    const controls = Array.from(f.querySelectorAll<HTMLInputElement | HTMLButtonElement>("input, button"));

    const setBusy = (busy: boolean, msg: string) => {
      f.toggleAttribute("aria-busy", busy);
      stage.classList.toggle("is-loading", busy);
      f.classList.toggle("is-loading", busy);
      status.textContent = msg;
      submitLabel.textContent = busy ? "Handshake running" : "Connect securely";
      controls.forEach((el) => { el.disabled = busy; });
    };

    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const d = new FormData(f);
      const uname = String(d.get("username"));
      err.textContent = "";
      setBusy(true, "Decrypting local keystore…");
      try {
        await call("unlock_keystore", { password: String(d.get("password")) });
        status.textContent = "Opening encrypted transport…";
        await call("connect", {
          req: {
            server: String(d.get("server")),
            username: uname,
            use_tor: !!d.get("tor"),
          },
        });
        status.textContent = "Checking account clearance…";
        // Stash the username so the pending screen can poll account_status for
        // the right user; UI-only convenience state, not a security boundary.
        setUsername(uname);
        // Route a not-yet-approved account to the status-only pending screen; an
        // active account goes straight to the app. account_status is a
        // request/response command (no event), so the connect handler decides.
        try {
          const acct = await call<AccountStateMsg>("account_status", { req: { username: uname } });
          status.textContent = acct.state === "active" ? "Access granted. Loading feed…" : "Account pending. Loading status…";
          location.hash = acct.state === "active" ? "#/feed" : "#/pending";
        } catch {
          // If the status check fails, fall back to the feed (which handles its
          // own errors); the connect itself already succeeded.
          status.textContent = "Connected. Loading feed…";
          location.hash = "#/feed";
        }
      } catch (x) {
        err.textContent =
          (x && typeof x === "object" && "message" in x
            ? String((x as { message: unknown }).message)
            : null) ?? "Sign-in failed.";
        setBusy(false, "Connection rejected. Check the details and try again.");
      }
    });
  }
}
customElements.define("connect-screen", ConnectScreen);
