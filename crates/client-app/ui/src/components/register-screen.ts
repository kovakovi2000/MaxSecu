import { call } from "../core/rpc.ts";
import type { RegisteredDto } from "../core/types.ts";

// Registration-key enrollment (spec §5): startup mode #2. When a single-use
// `register.key` file is present beside the exe, the operator turns it into a real
// account. This screen collects a username + a keystore passphrase and calls
// `register_with_key`; the backend reads the local key file, generates a fresh
// identity ENTIRELY in Rust, enrols via the server, seals the identity into the
// keystore, and DELETES the consumed key file. The registration key value never
// reaches this screen. Startup-precedence routing to this screen is a later task.
//
// Accessible: focusable `#main` landmark focused on mount, labelled controls,
// role="status"/role="alert" live regions, dynamic text via textContent only.
export class RegisterScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" class="auth-main register-main" tabindex="-1" aria-labelledby="rg-h" aria-describedby="rg-status" data-deco-slot="login">
        <section class="auth-stage" aria-label="Registration gate">
          <div class="auth-copy">
            <p class="eyebrow">one-time enrollment</p>
            <h1 id="rg-h">Create your account</h1>
            <p>This device holds a single-use <strong>registration key</strong>. Choose a
              username and a strong passphrase to protect your local keystore.</p>
            <p class="auth-note">Your encryption keys are generated on this device and never leave it; the registration key is used once and then destroyed.</p>
          </div>
        <form id="rg-f" class="auth-card">
          <label>Server
            <input name="server" required autocomplete="off" placeholder="123.123.123.123:8443" /></label>
          <label>Username
            <input name="username" required autocomplete="username" /></label>
          <label>Keystore passphrase
            <input name="passphrase" type="password" required autocomplete="new-password" /></label>
          <button type="submit" id="rg-submit">Create account</button>
          <p id="rg-status" role="status" aria-live="polite">Enter a username and passphrase.</p>
          <p id="rg-err" role="alert"></p>
        </form>
        </section>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const form = this.querySelector("#rg-f") as HTMLFormElement;
    const submitBtn = this.querySelector("#rg-submit") as HTMLButtonElement;
    const status = this.querySelector("#rg-status") as HTMLElement;
    const err = this.querySelector("#rg-err") as HTMLElement;
    const serverInput = form.querySelector('input[name="server"]') as HTMLInputElement;
    const userInput = form.querySelector('input[name="username"]') as HTMLInputElement;
    const passInput = form.querySelector('input[name="passphrase"]') as HTMLInputElement;

    const message = (x: unknown): string =>
      (x && typeof x === "object" && "message" in x
        ? String((x as { message: unknown }).message)
        : null) ?? "Registration failed.";

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.textContent = "";
      submitBtn.disabled = true;
      status.textContent = "Generating your keys and enrolling…";
      try {
        const res = await call<RegisteredDto>("register_with_key", {
          req: {
            server: serverInput.value,
            username: userInput.value,
            passphrase: passInput.value,
          },
        });
        // The identity is sealed and the single-use key destroyed; the passphrase
        // is no longer needed on the (untrusted) UI side.
        passInput.value = "";
        passInput.disabled = true;
        userInput.disabled = true;
        serverInput.disabled = true;
        status.textContent =
          `Account "${res.username}" is ready. You can now sign in.`;
      } catch (x) {
        err.textContent = message(x);
        status.textContent = "Registration rejected. Check your details and retry.";
        submitBtn.disabled = false;
      }
    });
  }
}
customElements.define("register-screen", RegisterScreen);
