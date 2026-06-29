import { call } from "../core/rpc.ts";
import type { PendingUserDto, IssueVoucherResponse } from "../core/types.ts";

// Admin operations (spec §5 Admin row): approval queue + voucher issuance.
// "Approve" is a ceremony-request (D-K), not an in-app grant.
export class AdminScreen extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="ad-h">
        <h1 id="ad-h" tabindex="-1">Admin</h1>
        <section aria-labelledby="iv-h">
          <h2 id="iv-h">Invite a new user</h2>
          <button id="iv-btn" type="button">Issue invite code</button>
          <p id="iv-out" role="status" aria-live="polite"></p>
        </section>
        <section aria-labelledby="pq-h">
          <h2 id="pq-h">Approval queue</h2>
          <p id="pq-status" role="status" aria-live="polite">Loading…</p>
          <ul id="pq-list"></ul>
        </section>
      </main>`;
    (this.querySelector("#ad-h") as HTMLElement).focus();
    (this.querySelector("#iv-btn") as HTMLButtonElement).addEventListener("click", () => void this.issue());
    void this.loadQueue();
  }

  private async issue() {
    const out = this.querySelector("#iv-out");
    if (!out) return;
    out.textContent = "Issuing…";
    try {
      const res = await call<IssueVoucherResponse>("issue_voucher", {});
      out.textContent = `Invite code (hand to the new user in person): ${res.code}`;
    } catch (x) {
      out.textContent = errMessage(x, "Could not issue an invite.");
    }
  }

  private async loadQueue() {
    const status = this.querySelector("#pq-status");
    const list = this.querySelector("#pq-list") as HTMLUListElement | null;
    if (!status || !list) return;
    try {
      const pending = await call<PendingUserDto[]>("list_pending", {});
      list.replaceChildren();
      if (pending.length === 0) {
        status.textContent = "No accounts awaiting approval.";
        return;
      }
      status.textContent = `${pending.length} awaiting approval.`;
      for (const u of pending) {
        const li = document.createElement("li");
        const name = document.createElement("span");
        // Server-controlled text rendered via textContent — never parsed as markup.
        name.textContent = `${u.username} `;
        li.appendChild(name);
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = "Prepare approval (ceremony)";
        btn.addEventListener("click", () => void this.requestApproval(u.user_id, li));
        li.appendChild(btn);
        list.appendChild(li);
      }
    } catch (x) {
      status.textContent = errMessage(x, "Could not load the queue.");
    }
  }

  private async requestApproval(userId: string, li: HTMLElement) {
    try {
      const item = await call<{ note: string }>("request_approval", { req: { user_id: userId } });
      const note = document.createElement("span");
      note.setAttribute("role", "status");
      note.textContent = ` — ${item.note}`;
      li.appendChild(note);
    } catch (x) {
      const note = document.createElement("span");
      note.setAttribute("role", "alert");
      note.textContent = ` — ${errMessage(x, "Could not prepare the ceremony request.")}`;
      li.appendChild(note);
    }
  }
}

// Strict-tsconfig-safe error narrowing (matches connect/bootstrap/pending screens).
function errMessage(x: unknown, fallback: string): string {
  return (x && typeof x === "object" && "message" in x
    ? String((x as { message: unknown }).message)
    : null) ?? fallback;
}

customElements.define("admin-screen", AdminScreen);
