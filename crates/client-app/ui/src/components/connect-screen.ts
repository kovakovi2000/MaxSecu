import { call } from "../core/rpc.ts";

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
      try {
        await call("unlock_keystore", { password: String(d.get("password")) });
        await call("connect", {
          req: {
            server: String(d.get("server")),
            username: String(d.get("username")),
            use_tor: !!d.get("tor"),
          },
        });
        location.hash = "#/feed";
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
