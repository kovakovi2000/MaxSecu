import { call } from "../core/rpc.ts";

// Admin operations (spec §5 Admin row). In the trusted-server recovery model the
// server is the enrollment authority and signs bindings itself — there is no
// offline ceremony, approval queue, or voucher flow. The only admin action is
// minting a single-use registration key to hand to a new user.
//
// The minted key is a capability token, so it is NEVER shown on screen or passed
// through the UI. Instead we open the native Save dialog, then ask the backend to
// mint the key and write it straight to the chosen file (inside the TCB); only the
// saved path comes back, for the confirmation line.
export class AdminScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" class="admin-main" tabindex="-1" aria-labelledby="ad-h">
        <h1 id="ad-h" tabindex="-1">Admin</h1>
        <section aria-labelledby="iv-h">
          <h2 id="iv-h">Invite a new user</h2>
          <p>Mint a single-use registration key and save it to a file to hand to the new user. The key is written straight to the file you choose — it is never shown on screen.</p>
          <button id="iv-btn" type="button">Mint registration key…</button>
          <p id="iv-out" role="status" aria-live="polite"></p>
        </section>
      </main>`;
    (this.querySelector("#ad-h") as HTMLElement).focus();
    (this.querySelector("#iv-btn") as HTMLButtonElement).addEventListener("click", () => void this.mint());
  }

  private async mint() {
    const out = this.querySelector("#iv-out");
    const btn = this.querySelector("#iv-btn") as HTMLButtonElement | null;
    if (!out) return;

    // 1) Choose the destination FIRST — nothing is minted if the admin cancels,
    //    so a cancelled save never burns a single-use key.
    let dest: string | null;
    try {
      dest = await call<string | null>("save_file", { defaultName: "register.key" });
    } catch (x) {
      out.textContent = errMessage(x, "Could not open the save dialog.");
      return;
    }
    if (!dest) {
      out.textContent = "Cancelled — no key was minted.";
      return;
    }

    // 2) Mint + write the key to that file inside the backend. The key itself
    //    never crosses back to the UI; only the saved path is returned.
    out.textContent = "Minting…";
    if (btn) btn.disabled = true;
    try {
      const saved = await call<string>("mint_registration_key", { destPath: dest });
      out.textContent = `Registration key saved to ${saved}. Hand this file to the new user — it works once.`;
    } catch (x) {
      out.textContent = errMessage(x, "Could not mint a registration key.");
    } finally {
      if (btn) btn.disabled = false;
    }
  }
}

// Strict-tsconfig-safe error narrowing (matches connect/enrollment screens).
function errMessage(x: unknown, fallback: string): string {
  return (x && typeof x === "object" && "message" in x
    ? String((x as { message: unknown }).message)
    : null) ?? fallback;
}

customElements.define("admin-screen", AdminScreen);
