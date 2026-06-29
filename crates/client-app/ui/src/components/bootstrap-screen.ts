import { call } from "../core/rpc.ts";
import type { GlassbreakResponse } from "../core/types.ts";

// Two-step first-run bootstrap (spec §4.2): ① generate the emergency glass-break
// account, ② create the first admin. Accessible: landmark, labelled controls,
// role="alert" errors, focus moved to the heading on step change.
export class BootstrapScreen extends HTMLElement {
  connectedCallback() {
    this.renderGlassbreak();
  }

  private renderGlassbreak() {
    this.innerHTML = `
      <main id="main" aria-labelledby="bs-h">
        <h1 id="bs-h" tabindex="-1">First-run setup — Step 1 of 2: Emergency account</h1>
        <p>This creates a one-time <strong>glass-break</strong> account. Record its
           credentials offline; it is your backstop if all admins are lost. It will
           <strong>not</strong> sign you in.</p>
        <form id="gb">
          <label>Bootstrap secret
            <input name="secret" required autocomplete="off" aria-describedby="gb-help" /></label>
          <p id="gb-help">Printed in the server console on first run.</p>
          <label><input type="checkbox" name="save" /> Also save an encrypted creds file</label>
          <label id="path-wrap" hidden>File path
            <input name="path" autocomplete="off" /></label>
          <button type="submit">Generate emergency account</button>
          <p id="gb-err" role="alert"></p>
        </form>
      </main>`;
    const form = this.querySelector("#gb") as HTMLFormElement;
    const saveBox = form.querySelector('input[name="save"]') as HTMLInputElement;
    const pathInput = form.querySelector('input[name="path"]') as HTMLInputElement;
    const pathWrap = this.querySelector("#path-wrap") as HTMLElement;
    saveBox.addEventListener("change", () => {
      pathWrap.hidden = !saveBox.checked;
      // Require a path only when the user opts into the backup file, so the
      // browser blocks an empty-path submit instead of silently discarding it.
      pathInput.required = saveBox.checked;
    });
    (this.querySelector("#bs-h") as HTMLElement).focus();
    form.addEventListener("submit", (e) => this.onGlassbreak(e, form));
  }

  private async onGlassbreak(e: Event, form: HTMLFormElement) {
    e.preventDefault();
    const err = this.querySelector("#gb-err")!;
    err.textContent = "";
    const d = new FormData(form);
    try {
      const res = await call<GlassbreakResponse>("register_glassbreak", {
        req: {
          bootstrap_secret: String(d.get("secret")),
          save_path: d.get("save") ? String(d.get("path") || "") || null : null,
        },
      });
      this.renderCredsThenAdmin(res);
    } catch (x) {
      err.textContent =
        (x && typeof x === "object" && "message" in x
          ? String((x as { message: unknown }).message)
          : null) ?? "Could not create the emergency account.";
    }
  }

  private renderCredsThenAdmin(creds: GlassbreakResponse) {
    this.innerHTML = `
      <main id="main" aria-labelledby="cr-h">
        <h1 id="cr-h" tabindex="-1">Save these emergency credentials now</h1>
        <p role="alert">Shown once. Store them offline and encrypted.</p>
        <dl>
          <dt>Username</dt><dd><code>${esc(creds.username)}</code></dd>
          <dt>Password</dt><dd><code>${esc(creds.password)}</code></dd>
        </dl>
        <button id="next">I have saved them — continue to create the first admin</button>
      </main>`;
    (this.querySelector("#cr-h") as HTMLElement).focus();
    (this.querySelector("#next") as HTMLButtonElement)
      .addEventListener("click", () => this.renderAdmin());
  }

  private renderAdmin() {
    this.innerHTML = `
      <main id="main" aria-labelledby="ad-h">
        <h1 id="ad-h" tabindex="-1">First-run setup — Step 2 of 2: First admin</h1>
        <form id="ad">
          <label>Username <input name="username" required autocomplete="username" /></label>
          <label>Password <input name="password" type="password" required autocomplete="new-password" /></label>
          <label>Bootstrap secret <input name="secret" required autocomplete="off" /></label>
          <button type="submit">Create first admin</button>
          <p id="ad-err" role="alert"></p>
        </form>
      </main>`;
    const form = this.querySelector("#ad") as HTMLFormElement;
    (this.querySelector("#ad-h") as HTMLElement).focus();
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = this.querySelector("#ad-err")!;
      err.textContent = "";
      const d = new FormData(form);
      try {
        await call<string>("create_first_admin", {
          req: {
            username: String(d.get("username")),
            password: String(d.get("password")),
            bootstrap_secret: String(d.get("secret")),
          },
        });
        location.hash = "#/connect"; // admin signs in normally after the ceremony
      } catch (x) {
        err.textContent =
          (x && typeof x === "object" && "message" in x
            ? String((x as { message: unknown }).message)
            : null) ?? "Could not create the first admin.";
      }
    });
  }
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

customElements.define("bootstrap-screen", BootstrapScreen);
