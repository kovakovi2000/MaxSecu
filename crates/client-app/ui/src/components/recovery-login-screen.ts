import { call } from "../core/rpc.ts";
import { setRecoveryPrincipal } from "../core/session.ts";
import type { RecoveryChallengeDto, RecoveryLoginDto } from "../core/types.ts";

// Trusted-server recovery login (spec §6 / §5): a two-step, channel-bound
// challenge-response driven from the operator's COLD recovery key file. Step 1
// requests + unwraps a one-time challenge (the cold private key is unsealed and
// held entirely in Rust — it never reaches this screen); Step 2 answers it to
// establish the RECOVERY session, which then lands on the feed exactly like an
// ordinary sign-in does (the shell marks it with a persistent recovery banner).
//
// It also carries the ONLY control that can point a never-registered device at a
// server: `server_of` reads `config/connection.json`, whose only other writer is
// `persist_registered_server` (reachable solely from `register_with_key`), and
// `install-client.ps1` ships no such file. A fresh PC holding just a recovery
// keyblob would otherwise be unable to dial at all. All parsing/validation of the
// address or code lives in Rust (`set_server_from_code`) because it must be
// authenticated against the pinned `config/server_cert.der` on disk — this screen
// only renders states.
//
// The disaster this path exists for is "the operator kept the recovery blobs and
// the passphrase, and nothing else", so this screen must not quietly add a fourth
// thing to have kept. It does not: `pinned_server_hints` reads the server's own
// address back out of the certificate pinned in this folder (the server bakes it in
// as a SAN) and pre-fills the field with it. That is a CONVENIENCE only — the value
// still goes through the same Rust validation, and the dial still succeeds only
// against the pinned certificate. The PORT is not in the certificate and is not in
// any other file the handout ZIP ships, so it is left for the operator with the
// installer's default named in the help text rather than filled in silently.
//
// Accessible: focusable `#main` landmark focused on mount, labelled controls,
// role="status"/role="alert" live regions, dynamic text via textContent only.

// Mirror of Rust `commands::bootstrap::ServerHints`. Declared local to this screen
// on purpose: the recovery DTOs in core/types.ts are frozen two-field shapes, and
// the note there says anything else this screen needs gets its own command.
interface ServerHints {
  /** The address `connection.json` holds today, or "" when never pointed anywhere. */
  configured: string;
  /** Hosts the pinned certificate vouches for, best-guess first. */
  cert_hosts: string[];
  /** Always false today: X.509 carries no port. Never assume one. */
  port_known: boolean;
}

export class RecoveryLoginScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" class="auth-main recovery-main" tabindex="-1" aria-labelledby="rl-h" aria-describedby="rl-status" data-deco-slot="login">
        <section class="auth-stage" aria-label="Recovery gate">
          <div class="auth-copy">
            <p class="eyebrow">cold-key recovery</p>
            <h1 id="rl-h">Recovery sign-in</h1>
            <p>Sign in with the cold <strong>recovery key</strong> to establish an admin server session.</p>
            <p class="auth-note">This opens a session that can <strong>see and open everyone's content</strong>, and can invite users. You cannot post, delete or share from it.</p>
          </div>
        <div class="recovery-column">
          <details id="rl-srv" class="auth-card recovery-server">
            <summary id="rl-srv-sum">Server — set or change</summary>
            <p id="rl-srv-now">Checking which server this device is set to…</p>
            <label>Connection code — or just the server address
              <input id="rl-code" name="code" type="text" autocomplete="off" spellcheck="false"
                placeholder="123.123.123.123:8443" /></label>
            <p id="rl-srv-hint" class="hint"></p>
            <p id="rl-srv-warn" role="alert"></p>
            <button type="button" id="rl-srv-save">Use this server</button>
            <button type="button" id="rl-srv-cancel" hidden>Keep the current server</button>
            <p id="rl-srv-err" role="alert"></p>
            <p id="rl-srv-fp" class="hint"></p>
          </details>
          <form id="rl-f" class="auth-card">
            <label>Recovery key passphrase
              <input name="passphrase" type="password" required autocomplete="off" /></label>
            <button type="submit" id="rl-request">Request Challenge</button>
            <button type="button" id="rl-answer" hidden>Complete recovery sign-in</button>
            <p id="rl-status" role="status" aria-live="polite">Awaiting the recovery passphrase.</p>
            <p id="rl-err" role="alert"></p>
          </form>
        </div>
        </section>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const form = this.querySelector("#rl-f") as HTMLFormElement;
    const requestBtn = this.querySelector("#rl-request") as HTMLButtonElement;
    const answerBtn = this.querySelector("#rl-answer") as HTMLButtonElement;
    const status = this.querySelector("#rl-status") as HTMLElement;
    const err = this.querySelector("#rl-err") as HTMLElement;
    const passInput = form.querySelector('input[name="passphrase"]') as HTMLInputElement;
    const srv = this.querySelector("#rl-srv") as HTMLDetailsElement;
    const srvNow = this.querySelector("#rl-srv-now") as HTMLElement;
    const srvHint = this.querySelector("#rl-srv-hint") as HTMLElement;
    const srvWarn = this.querySelector("#rl-srv-warn") as HTMLElement;
    const srvErr = this.querySelector("#rl-srv-err") as HTMLElement;
    const srvFp = this.querySelector("#rl-srv-fp") as HTMLElement;
    const srvSave = this.querySelector("#rl-srv-save") as HTMLButtonElement;
    const srvCancel = this.querySelector("#rl-srv-cancel") as HTMLButtonElement;
    const codeInput = this.querySelector("#rl-code") as HTMLInputElement;
    const RESTING = "Awaiting the recovery passphrase.";

    const message = (x: unknown): string =>
      (x && typeof x === "object" && "message" in x
        ? String((x as { message: unknown }).message)
        : null) ?? "Recovery sign-in failed.";
    const codeOf = (x: unknown): string =>
      x && typeof x === "object" && "code" in x ? String((x as { code: unknown }).code) : "";

    // The address this device is pointed at RIGHT NOW, as last read from Rust —
    // never inferred from what was typed, because `set_server_from_code` normalizes
    // the port and drops the `#…` half of a connection code.
    let configured = "";
    // The exact field value the operator confirmed replacing `configured` with.
    // Empty = no confirmation outstanding. Editing the field clears it, so a
    // confirmation can never be spent on a different address than it was shown for.
    let armed = "";

    // Pre-filling is a convenience and must never win against the operator: the
    // hints arrive asynchronously, so a value typed in the meantime stands.
    const prefill = (value: string) => {
      if (!codeInput.value) codeInput.value = value;
    };

    const describeCurrent = () => {
      srvNow.textContent = configured
        ? `This device currently connects to: ${configured}`
        : "This device is not pointed at a server yet.";
    };

    const disarm = () => {
      armed = "";
      srvWarn.textContent = "";
      srvSave.textContent = "Use this server";
      srvCancel.hidden = true;
    };

    // Re-read rather than trust the input: Rust decides what actually landed in
    // connection.json.
    const refreshConfigured = async () => {
      try {
        configured = (await call<ServerHints>("pinned_server_hints")).configured;
      } catch {
        /* keep the last known value; the panel copy stays honest either way */
      }
      describeCurrent();
    };

    // Fill the field so an operator who remembers NOTHING can still proceed. The
    // host comes out of the certificate pinned in this folder — the same SAN list
    // `open_conn` verifies the dialled host against, so a pre-fill can only ever
    // name a server this folder's pin already vouches for. The port is a separate
    // matter: it is in no file here, so it is left to the operator and said so.
    const loadHints = async () => {
      let hints: ServerHints;
      try {
        hints = await call<ServerHints>("pinned_server_hints");
      } catch (x) {
        if (codeOf(x) === "not_pinned") {
          srvNow.textContent =
            "This folder has no pinned server certificate, so it cannot be pointed at a server. Use the client folder your admin gave you.";
        }
        return;
      }
      configured = hints.configured;
      describeCurrent();
      if (configured) {
        // Do NOT clobber a working address blind: show it, and make an edit an
        // explicit, confirmed replacement (see the save handler).
        prefill(configured);
        srvHint.textContent =
          "Changing this replaces the address above; you will be asked to confirm first.";
        return;
      }
      // Nothing saved: this is the step that has to happen before anything else, so
      // open the panel and announce it in the live region rather than stealing focus
      // from the landmark this screen just moved it to.
      srv.open = true;
      if (status.textContent === RESTING) {
        status.textContent = "This device is not pointed at a server yet — set the server first.";
      }
      const host = hints.cert_hosts[0] ?? "";
      if (!host) {
        srvHint.textContent =
          "Type the server address as host:port — for example 123.123.123.123:8443.";
        return;
      }
      prefill(hints.port_known ? host : `${host}:`);
      if (hints.port_known) {
        srvHint.textContent = "Filled in from the certificate pinned in this folder.";
        return;
      }
      const others = hints.cert_hosts.slice(1);
      srvHint.textContent =
        `The address was read from the certificate pinned in this folder. The port number is not stored anywhere in this folder, so add it after the colon — the installer's default is 8443, but your admin may have chosen another.` +
        (others.length ? ` The certificate also covers: ${others.join(", ")}.` : "");
    };

    // The optional out-of-band integrity check. It is worth doing when — and only
    // when — the operator has a copy of the connection code that did NOT travel
    // inside this folder: this value is derived from the folder's own pins, so
    // comparing it against something that came with the folder proves nothing,
    // while comparing it against what the admin says down the phone detects a
    // swapped pin. Not having a code is not a problem, and the copy says so.
    const loadFingerprint = async () => {
      let fp: string;
      try {
        fp = await call<string>("pinned_fingerprint");
      } catch {
        return; // no pinned cert ⇒ nothing to compare; loadHints already said so
      }
      srvFp.textContent =
        `Optional check — the pins in this folder produce the fingerprint ${fp}. If you still have the connection code and it reached you some other way (your admin read it out, or texted it), the part after the # should be exactly that; if it is not, stop and ask your admin, because the pins in this folder may have been swapped. If you have no code, or only the copy that came with this folder, skip the check — it would only be comparing this folder against itself, and the pinned certificate is what secures the connection either way.`;
    };

    const openServerSection = () => {
      srv.open = true;
      codeInput.focus();
    };

    const save = async () => {
      const code = codeInput.value.trim();
      srvErr.textContent = "";
      if (!code) {
        srvErr.textContent = "Enter the server address, or paste the connection code.";
        return;
      }
      // The pre-fill deliberately ends at the colon; catch it here with advice
      // instead of letting Rust answer the generic "that is not an address".
      if (code.endsWith(":")) {
        srvErr.textContent =
          "Add the port number after the colon — the installer's default is 8443, unless your admin chose another.";
        return;
      }
      // Anyone can reach #/recovery, so replacing a WORKING address is a confirmed
      // action, never a side effect of typing.
      if (configured && code !== configured && armed !== code) {
        armed = code;
        srvWarn.textContent =
          `This device already connects to ${configured}. Saving replaces that with ${code}, and recovery sign-in will then go to the new address. Choose "Replace server" to confirm.`;
        srvSave.textContent = "Replace server";
        srvCancel.hidden = false;
        return;
      }
      srvSave.disabled = true;
      try {
        await call("set_server_from_code", { code });
        disarm();
        await refreshConfigured();
        codeInput.value = configured;
        srvHint.textContent =
          "Changing this replaces the address above; you will be asked to confirm first.";
        srv.open = false;
        requestBtn.disabled = false;
        // Announced in the form's own live region, which stays visible: writing the
        // confirmation into the panel that is being collapsed means assistive tech
        // never gets to read it.
        status.textContent = configured
          ? `Server set to ${configured}. ${RESTING}`
          : `Server set for this device. ${RESTING}`;
        passInput.focus();
      } catch (x) {
        srvErr.textContent = codeOf(x) === "untrusted"
          ? "That connection code does not match the certificate pinned in this folder. The code may have been mistyped — or the pins in this folder are not the ones your admin issued. Check with them before continuing."
          : codeOf(x) === "not_pinned"
          ? "This folder has no pinned server certificate, so it cannot be pointed at a server. Use the client folder your admin gave you."
          : codeOf(x) === "bad_code"
          ? "That is not a server address or a connection code. An address looks like 123.123.123.123:8443."
          : codeOf(x) === "internal"
          ? "Could not save the server address."
          : message(x);
      } finally {
        srvSave.disabled = false;
      }
    };

    srvSave.addEventListener("click", () => {
      void save();
    });

    srvCancel.addEventListener("click", () => {
      codeInput.value = configured;
      disarm();
      srvErr.textContent = "";
      status.textContent = `Kept the current server: ${configured}`;
      codeInput.focus();
    });

    // The field is inside a <details>, not the form, so the browser's implicit
    // submit does nothing here: pressing Enter after typing the address used to be
    // silently ignored. Wire it explicitly. A pending replacement still needs the
    // second, deliberate press — Enter confirms exactly what the warning names.
    codeInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        void save();
      }
    });

    // An outstanding confirmation belongs to one exact value; editing revokes it.
    codeInput.addEventListener("input", () => {
      if (armed && armed !== codeInput.value.trim()) disarm();
    });

    void loadHints();
    void loadFingerprint();

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
        if (codeOf(x) === "no_server") {
          // Rust checks `server_of` before it touches the passphrase or the
          // network, so this is the authoritative "not pointed anywhere" signal.
          configured = "";
          describeCurrent();
          status.textContent = "This device is not pointed at a server yet — set the server first.";
          err.textContent = "";
          openServerSection();
        } else {
          err.textContent = message(x);
          status.textContent = "Recovery sign-in rejected. Check the passphrase and retry.";
        }
        requestBtn.disabled = false;
      }
    });

    answerBtn.addEventListener("click", async () => {
      err.textContent = "";
      answerBtn.disabled = true;
      status.textContent = "Answering the challenge…";
      try {
        const res = await call<RecoveryLoginDto>("answer_recovery_challenge");
        // Mirrors connect-screen: stash the principal so the shell can gate
        // session-only routes, then land on the feed. Without this the login
        // "succeeded" into a frozen screen.
        setRecoveryPrincipal();
        status.textContent = `Recovery session established on ${res.server_id}. Loading feed…`;
        location.hash = "#/feed";
      } catch (x) {
        err.textContent = message(x);
        status.textContent = "Recovery sign-in rejected. Request a new challenge.";
        // The challenge is single-use; restart the flow.
        answerBtn.hidden = true;
        answerBtn.disabled = false;
        passInput.disabled = false;
        requestBtn.disabled = false;
      }
    });
  }
}
customElements.define("recovery-login-screen", RecoveryLoginScreen);
