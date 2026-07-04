import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { getUsername } from "../core/session.ts";
import { toast } from "../core/toast.ts";
import type { Contact, ResolvedRecipient, ReshareOutcome } from "../core/types.ts";
import "./state-badge.ts";

// <share-dialog> — the T4 multi-recipient sharing picker, now a tickable
// CHECKLIST of known contacts (people you've successfully shared with before,
// from list_contacts) PLUS the kept manual add-by-username input. Ticking a
// contact is free (no network); the share security path (reshare_file) still
// re-resolves + D5-verifies + TOFU-checks EVERY selected recipient at share
// time, so the checklist is only a faster way to feed usernames into that
// verified path. A contact who already has access is shown greyed + disabled.
//
// FAIL-CLOSED BY CONSTRUCTION is preserved: a manually-typed name still only
// becomes shareable once resolve_recipient RESOLVED it; a rejected resolve is
// rendered and dropped. Every authed/D5 call is routed through the shared
// serial() FIFO queue. No secrets cross this component — only usernames, hex
// ids, fingerprints, booleans, and sanitized codes.

type RowStatus =
  | "contact" // known contact, tickable, not yet verified this session
  | "pending"
  | "verified"
  | "rejected"
  | "sharing"
  | "shared"
  | "share-failed";

interface Row {
  key: string; // resolved user_id when known, else a synthetic per-attempt id
  username: string;
  status: RowStatus;
  selected: boolean; // checkbox state
  fingerprint?: string;
  alreadyShared?: boolean; // has access → checkbox disabled
  message?: string;
  code?: string | null;
}

export class ShareDialog extends HTMLElement {
  private fileId = "";
  private invoker: HTMLElement | null = null;
  private rows: Row[] = [];
  private alreadySharedIds = new Set<string>();
  private counter = 0;
  private keydownHandler = (e: KeyboardEvent) => this.onKeydown(e);

  connectedCallback() {
    this.hidden = true;
    this.innerHTML = `
      <div class="share-overlay">
        <div
          class="share-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby="sd-h"
          tabindex="-1"
        >
          <div class="share-head">
            <h2 id="sd-h">Share with people</h2>
            <button type="button" id="sd-close" class="secondary">Close</button>
          </div>
          <form id="sd-add-form">
            <label>
              Add someone by username
              <input type="text" id="sd-username" name="username" autocomplete="off" />
            </label>
            <button type="submit" id="sd-add-btn">Add</button>
          </form>
          <p id="sd-status" role="status" aria-live="polite"></p>
          <ul id="sd-rows" class="sd-roster" aria-label="People to share with" aria-live="polite"></ul>
          <div class="share-actions">
            <button type="button" id="sd-share-btn" disabled>Share</button>
          </div>
        </div>
      </div>`;

    const overlay = this.querySelector(".share-overlay") as HTMLElement;
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) this.close();
    });
    (this.querySelector("#sd-close") as HTMLButtonElement).addEventListener("click", () => this.close());
    (this.querySelector("#sd-add-form") as HTMLFormElement).addEventListener("submit", (e) => {
      e.preventDefault();
      const input = this.querySelector("#sd-username") as HTMLInputElement;
      const username = input.value.trim();
      if (!username) return;
      input.value = "";
      void this.addRecipient(username);
    });
    (this.querySelector("#sd-share-btn") as HTMLButtonElement).addEventListener("click", () => void this.share());
  }

  disconnectedCallback() {
    document.removeEventListener("keydown", this.keydownHandler);
  }

  /** Open the dialog for `fileId`; `invoker` regains focus when it closes. */
  openFor(fileId: string, invoker: HTMLElement) {
    this.fileId = fileId;
    this.invoker = invoker;
    this.rows = [];
    this.alreadySharedIds = new Set();
    this.renderRows();
    this.updateShareEnabled();
    (this.querySelector("#sd-status") as HTMLElement).textContent = "";
    this.hidden = false;
    document.removeEventListener("keydown", this.keydownHandler);
    document.addEventListener("keydown", this.keydownHandler);
    (this.querySelector("#sd-username") as HTMLInputElement).focus();

    // Load the contacts roster + already-access set, then seed the checklist.
    void this.loadRoster();
  }

  close() {
    this.hidden = true;
    document.removeEventListener("keydown", this.keydownHandler);
    this.invoker?.focus();
  }

  private onKeydown(e: KeyboardEvent) {
    if (this.hidden) return;
    if (e.key === "Escape") {
      e.preventDefault();
      this.close();
      return;
    }
    if (e.key === "Tab") this.trapTab(e);
  }

  private trapTab(e: KeyboardEvent) {
    const focusable = this.focusableElements();
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    if (e.shiftKey) {
      if (active === first || !focusable.includes(active as HTMLElement)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (active === last || !focusable.includes(active as HTMLElement)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  private focusableElements(): HTMLElement[] {
    const panel = this.querySelector(".share-panel") as HTMLElement;
    return Array.from(
      panel.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((el) => el.offsetParent !== null || el === document.activeElement);
  }

  /** Load contacts + the already-access set, then build the checklist. Fails
   * open: an empty roster / failed cross-check still leaves a working dialog. */
  private async loadRoster() {
    let contacts: Contact[] = [];
    try {
      contacts = await serial(() => call<Contact[]>("list_contacts", {}));
    } catch {
      contacts = []; // fail-open: manual input still works
    }
    try {
      const ids = await serial(() => call<string[]>("list_file_recipients", { fileId: this.fileId }));
      this.alreadySharedIds = new Set(ids);
    } catch {
      // fail-open: "unknown who has access" — no rows disabled.
    }
    // Seed contact rows, skipping any username already present (e.g. a manual add
    // that landed while this was loading). Self is never a contact, but guard anyway.
    const me = getUsername();
    for (const c of contacts) {
      if (me && c.username.toLowerCase() === me.toLowerCase()) continue;
      if (this.rows.some((r) => r.username.toLowerCase() === c.username.toLowerCase())) continue;
      const already = this.alreadySharedIds.has(c.user_id);
      this.rows.push({
        key: c.user_id,
        username: c.username,
        status: "contact",
        selected: false,
        fingerprint: c.fingerprint,
        alreadyShared: already,
      });
    }
    this.renderRows();
    this.updateShareEnabled();
  }

  private async addRecipient(username: string) {
    const status = this.querySelector("#sd-status") as HTMLElement;

    const me = getUsername();
    if (me && username.toLowerCase() === me.toLowerCase()) {
      this.rows.push({
        key: `rejected:${this.counter++}`,
        username,
        status: "rejected",
        selected: false,
        message: "You are already the owner.",
      });
      this.renderRows();
      return;
    }

    // If the username is already a row, just tick it (unless it already has access).
    const existingRow = this.rows.find(
      (r) => r.username.toLowerCase() === username.toLowerCase() && r.status !== "rejected",
    );
    if (existingRow) {
      if (!existingRow.alreadyShared) existingRow.selected = true;
      status.textContent = `${username} is already in the list.`;
      this.renderRows();
      this.updateShareEnabled();
      return;
    }

    const pendingKey = `pending:${this.counter++}`;
    this.rows.push({ key: pendingKey, username, status: "pending", selected: true });
    this.renderRows();

    try {
      const resolved = await serial(() =>
        call<ResolvedRecipient>("resolve_recipient", { req: { username } }),
      );
      const idx = this.rows.findIndex((r) => r.key === pendingKey);

      // Dedupe by resolved user_id: collapse onto an existing row for the same account.
      const dupe = this.rows.find((r) => r.key === resolved.user_id && r.status !== "rejected");
      if (dupe) {
        if (idx >= 0) this.rows.splice(idx, 1);
        if (!dupe.alreadyShared) dupe.selected = true;
        status.textContent = `${username} resolves to an account already in the list.`;
        this.renderRows();
        this.updateShareEnabled();
        return;
      }

      const already = resolved.already_shared || this.alreadySharedIds.has(resolved.user_id);
      const row: Row = {
        key: resolved.user_id,
        username: resolved.username,
        status: "verified",
        selected: !already,
        fingerprint: resolved.fingerprint,
        alreadyShared: already,
      };
      if (idx >= 0) this.rows[idx] = row;
      else this.rows.push(row);
      status.textContent = "";
    } catch (x) {
      const idx = this.rows.findIndex((r) => r.key === pendingKey);
      const msg = errMessage(x, "This user's identity could not be verified.");
      if (idx >= 0) {
        this.rows[idx] = { key: `rejected:${this.counter++}`, username, status: "rejected", selected: false, message: msg };
      }
    }
    this.renderRows();
    this.updateShareEnabled();
  }

  private toggleRow(key: string, checked: boolean) {
    const row = this.rows.find((r) => r.key === key);
    if (row && !row.alreadyShared) row.selected = checked;
    this.updateShareEnabled();
  }

  private updateShareEnabled() {
    const btn = this.querySelector("#sd-share-btn") as HTMLButtonElement;
    btn.disabled = !this.rows.some(
      (r) => r.selected && (r.status === "contact" || r.status === "verified"),
    );
  }

  private async share() {
    const selected = this.rows.filter(
      (r) => r.selected && (r.status === "contact" || r.status === "verified"),
    );
    const usernames = selected.map((r) => r.username);
    if (usernames.length === 0) return;
    const btn = this.querySelector("#sd-share-btn") as HTMLButtonElement;
    btn.disabled = true;
    for (const r of selected) r.status = "sharing";
    this.renderRows();

    try {
      const outcomes = await serial(() =>
        call<ReshareOutcome[]>("reshare_file", {
          req: { file_id: this.fileId, recipient_usernames: usernames },
        }),
      );
      this.applyOutcomes(outcomes);
    } catch (x) {
      const msg = errMessage(x, "Could not share this item right now.");
      for (const r of this.rows) {
        if (r.status === "sharing") {
          r.status = "share-failed";
          r.message = msg;
          r.code = null;
        }
      }
      toast("error", msg);
    }
    this.renderRows();
    this.updateShareEnabled();
  }

  private async retryRow(key: string) {
    const row = this.rows.find((r) => r.key === key);
    if (!row) return;
    row.status = "sharing";
    this.renderRows();
    try {
      const outcomes = await serial(() =>
        call<ReshareOutcome[]>("reshare_file", {
          req: { file_id: this.fileId, recipient_usernames: [row.username] },
        }),
      );
      this.applyOutcomes(outcomes);
    } catch (x) {
      row.status = "share-failed";
      row.message = errMessage(x, "Could not share this item right now.");
      row.code = null;
    }
    this.renderRows();
  }

  private applyOutcomes(outcomes: ReshareOutcome[]) {
    for (const o of outcomes) {
      const row = this.rows.find((r) => r.username === o.username && r.status === "sharing");
      if (!row) continue;
      if (o.ok) {
        row.status = "shared";
        row.selected = false;
        row.alreadyShared = true;
        row.message = undefined;
        row.code = null;
      } else {
        row.status = "share-failed";
        row.code = o.code ?? null;
        row.message = o.code ? `Failed: ${o.code}` : "Sharing failed.";
      }
    }
  }

  private renderRows() {
    const ul = this.querySelector("#sd-rows") as HTMLUListElement;

    const active = document.activeElement as HTMLElement | null;
    const actedRow = active && ul.contains(active) ? active.closest(".sd-row") : null;
    const actedRowKey = actedRow?.getAttribute("data-row") ?? null;

    ul.replaceChildren();
    for (const row of this.rows) {
      const li = document.createElement("li");
      li.className = "sd-row";
      li.setAttribute("data-row", row.key);

      // A checkbox is offered only for tickable rows (contact/verified). Rejected
      // and terminal (sharing/shared/share-failed) rows show status text instead.
      const tickable = row.status === "contact" || row.status === "verified";
      if (tickable) {
        const label = document.createElement("label");
        label.className = "sd-check";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = row.selected && !row.alreadyShared;
        cb.disabled = !!row.alreadyShared;
        cb.addEventListener("change", () => this.toggleRow(row.key, cb.checked));
        const name = document.createElement("span");
        name.className = "sd-username";
        name.textContent = row.username;
        label.appendChild(cb);
        label.appendChild(name);
        li.appendChild(label);
      } else {
        const name = document.createElement("span");
        name.className = "sd-username";
        name.textContent = row.username;
        li.appendChild(name);
      }

      if (row.fingerprint) {
        const fp = document.createElement("code");
        fp.className = "sd-fingerprint";
        fp.textContent = row.fingerprint;
        li.appendChild(fp);
      }

      const badge = document.createElement("state-badge");
      const { state, label: badgeLabel } = badgeFor(row);
      badge.setAttribute("state", state);
      badge.setAttribute("label", badgeLabel);
      li.appendChild(badge);

      if (row.alreadyShared && row.status !== "shared") {
        const note = document.createElement("span");
        note.className = "sd-note";
        note.textContent = "Already has access";
        li.appendChild(note);
      }

      if (row.status === "share-failed") {
        const retry = document.createElement("button");
        retry.type = "button";
        retry.className = "sd-retry";
        retry.textContent = "Retry";
        retry.addEventListener("click", () => void this.retryRow(row.key));
        li.appendChild(retry);
      }

      ul.appendChild(li);
    }

    if (actedRowKey !== null) {
      const rebuilt = Array.from(ul.children).find(
        (li) => (li as HTMLElement).getAttribute("data-row") === actedRowKey,
      ) as HTMLElement | undefined;
      const target =
        rebuilt?.querySelector<HTMLButtonElement | HTMLInputElement>("button, input") ??
        (this.querySelector("#sd-username") as HTMLInputElement);
      target.focus();
    }
  }
}

function badgeFor(row: Row): { state: string; label: string } {
  switch (row.status) {
    case "contact":
      return { state: "ready", label: "Contact" };
    case "pending":
      return { state: "verifying", label: "Verifying…" };
    case "verified":
      return { state: "verified", label: "Verified" };
    case "rejected":
      return { state: "failed", label: `Rejected: ${row.message ?? "unverifiable"}` };
    case "sharing":
      return { state: "fetching", label: "Sharing…" };
    case "shared":
      return { state: "ready", label: "Shared" };
    case "share-failed":
      return { state: "failed", label: row.message ?? "Failed" };
  }
}

function errMessage(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return fallback;
}

customElements.define("share-dialog", ShareDialog);
