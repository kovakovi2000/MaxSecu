import { call } from "../core/rpc.ts";
import type { RecoveryChallengeDto, RecoveryLoginDto } from "../core/types.ts";

// Trusted-server recovery login (spec §6 / §5): a two-step, channel-bound
// challenge-response driven from the operator's COLD recovery key file. Step 1
// requests + unwraps a one-time challenge (the cold private key is unsealed and
// held entirely in Rust — it never reaches this screen); Step 2 answers it to
// establish an ADMIN session. This screen is deliberately minimal (passphrase +
// "Request Challenge" + status); startup-precedence routing to it is a later task.
//
// Accessible: focusable `#main` landmark focused on mount, labelled controls,
// role="status"/role="alert" live regions, dynamic text via textContent only.
export class RecoveryLoginScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="rl-h" aria-describedby="rl-status">
        <h1 id="rl-h">Recovery sign-in</h1>
        <p>Sign in with the cold <strong>recovery key</strong> to establish an
           admin server session. This grants admin actions only — it does
           <strong>not</strong> unlock content decryption.</p>
        <form id="rl-f">
          <label>Recovery key passphrase
            <input name="passphrase" type="password" required autocomplete="off" /></label>
          <button type="submit" id="rl-request">Request Challenge</button>
          <button type="button" id="rl-answer" hidden>Complete recovery sign-in</button>
          <p id="rl-status" role="status" aria-live="polite">Awaiting the recovery passphrase.</p>
          <p id="rl-err" role="alert"></p>
        </form>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const form = this.querySelector("#rl-f") as HTMLFormElement;
    const requestBtn = this.querySelector("#rl-request") as HTMLButtonElement;
    const answerBtn = this.querySelector("#rl-answer") as HTMLButtonElement;
    const status = this.querySelector("#rl-status") as HTMLElement;
    const err = this.querySelector("#rl-err") as HTMLElement;
    const passInput = form.querySelector('input[name="passphrase"]') as HTMLInputElement;

    const message = (x: unknown): string =>
      (x && typeof x === "object" && "message" in x
        ? String((x as { message: unknown }).message)
        : null) ?? "Recovery sign-in failed.";

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.textContent = "";
      requestBtn.disabled = true;
      status.textContent = "Unsealing recovery key and requesting a challenge…";
      try {
        const res = await call<RecoveryChallengeDto>("request_recovery_challenge", {
          passphrase: passInput.value,
        });
        // The cold private key is now held in Rust; the passphrase field is no
        // longer needed on the (untrusted) UI side.
        passInput.value = "";
        passInput.disabled = true;
        status.textContent = `Challenge ready for ${res.server_id}. Complete the sign-in.`;
        answerBtn.hidden = false;
        answerBtn.focus();
      } catch (x) {
        err.textContent = message(x);
        status.textContent = "Recovery sign-in rejected. Check the passphrase and retry.";
        requestBtn.disabled = false;
      }
    });

    answerBtn.addEventListener("click", async () => {
      err.textContent = "";
      answerBtn.disabled = true;
      status.textContent = "Answering the challenge…";
      try {
        const res = await call<RecoveryLoginDto>("answer_recovery_challenge");
        status.textContent = `Admin recovery session established on ${res.server_id}.`;
      } catch (x) {
        err.textContent = message(x);
        status.textContent = "Recovery sign-in rejected. Request a new challenge.";
        // The challenge is single-use; restart the flow.
        answerBtn.hidden = true;
        passInput.disabled = false;
        requestBtn.disabled = false;
      }
    });
  }
}
customElements.define("recovery-login-screen", RecoveryLoginScreen);
