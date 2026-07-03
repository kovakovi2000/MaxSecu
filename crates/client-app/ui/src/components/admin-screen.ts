import { call } from "../core/rpc.ts";
import type { MintedKeyResponse } from "../core/types.ts";

// Admin operations (spec §5 Admin row). In the trusted-server recovery model the
// server is the enrollment authority and signs bindings itself — there is no
// offline ceremony, approval queue, or voucher flow. The only admin action is
// minting a single-use registration key to hand to a new user.
export class AdminScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="ad-h">
        <h1 id="ad-h" tabindex="-1">Admin</h1>
        <section aria-labelledby="iv-h">
          <h2 id="iv-h">Invite a new user</h2>
          <button id="iv-btn" type="button">Mint registration key</button>
          <p id="iv-out" role="status" aria-live="polite"></p>
        </section>
      </main>`;
    (this.querySelector("#ad-h") as HTMLElement).focus();
    (this.querySelector("#iv-btn") as HTMLButtonElement).addEventListener("click", () => void this.mint());
  }

  private async mint() {
    const out = this.querySelector("#iv-out");
    if (!out) return;
    out.textContent = "Minting…";
    try {
      const res = await call<MintedKeyResponse>("mint_registration_key", {});
      out.textContent = `Registration key (hand to the new user in person): ${res.registration_key}`;
    } catch (x) {
      out.textContent = errMessage(x, "Could not mint a registration key.");
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
