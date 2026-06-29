import { call } from "../core/rpc.ts";
import { setUsername } from "../core/session.ts";
import type { AccountStateMsg } from "../core/types.ts";

export class ConnectScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1"><h1>Connect to a MaxSecu server</h1>
      <form id="f">
        <label>Server <input name="server" required autocomplete="off"></label>
        <label>Username <input name="username" required autocomplete="username"></label>
        <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
        <label><input type="checkbox" name="tor"> Use Tor</label>
        <button type="submit">Connect</button>
        <p id="err" role="alert"></p>
      </form></main>`;
    const f = this.querySelector("#f") as HTMLFormElement;
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const d = new FormData(f);
      const err = this.querySelector("#err")!;
      const uname = String(d.get("username"));
      try {
        await call("unlock_keystore", { password: String(d.get("password")) });
        await call("connect", {
          req: {
            server: String(d.get("server")),
            username: uname,
            use_tor: !!d.get("tor"),
          },
        });
        // Stash the username so the pending screen can poll account_status for
        // the right user; UI-only convenience state, not a security boundary.
        setUsername(uname);
        // Route a not-yet-approved account to the status-only pending screen; an
        // active account goes straight to the app. account_status is a
        // request/response command (no event), so the connect handler decides.
        try {
          const acct = await call<AccountStateMsg>("account_status", { req: { username: uname } });
          location.hash = acct.state === "active" ? "#/feed" : "#/pending";
        } catch {
          // If the status check fails, fall back to the feed (which handles its
          // own errors); the connect itself already succeeded.
          location.hash = "#/feed";
        }
      } catch (x) {
        err.textContent =
          (x && typeof x === "object" && "message" in x
            ? String((x as { message: unknown }).message)
            : null) ?? "Sign-in failed.";
      }
    });
  }
}
customElements.define("connect-screen", ConnectScreen);
