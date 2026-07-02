import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { getUsername } from "../core/session.ts";
import { toast } from "../core/toast.ts";
import type { ResolvedRecipient, ReshareOutcome } from "../core/types.ts";
import "./state-badge.ts";

// <share-dialog> — the T4 post-upload multi-recipient sharing picker (spec §3/§5).
// A modal recipient picker: add-by-username → D5-verify via resolve_recipient →
// show a Verified/Rejected row (fingerprint + non-color-only <state-badge>) →
// "Share" wraps+POSTs to every Verified row via reshare_file, rendering a
// per-row outcome with a per-row Retry. FAIL-CLOSED BY CONSTRUCTION: a row only
// becomes eligible for Share once resolve_recipient has RESOLVED it — a rejected
// resolve is rendered and dropped, never fed to reshare_file. Every authed/D5
// call (resolve_recipient, list_file_recipients, reshare_file) is routed through
// the shared serial() FIFO queue (core/serial.ts) — the backend re-auths per
// call and cannot run those concurrently with any other in-flight command.
//
// No secrets ever pass through this component: only usernames, hex user_ids,
// fingerprints, booleans, and sanitized failure codes — the same DTOs the
// backend already restricts itself to (dto.rs's "no key material" rule).

type RowStatus = "pending" | "verified" | "rejected" | "sharing" | "shared" | "share-failed";

interface Row {
  key: string; // resolved user_id once known, else a synthetic per-attempt id
  username: string;
  status: RowStatus;
  fingerprint?: string;
  alreadyShared?: boolean;
  message?: string; // rejection reason (rejected) or sanitized code (share-failed)
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
            <h2 id="sd-h">Share with more people</h2>
            <button type="button" id="sd-close" class="secondary">Close</button>
          </div>
          <form id="sd-add-form">
            <label>
              Add a recipient by username
              <input type="text" id="sd-username" name="username" autocomplete="off" />
            </label>
            <button type="submit" id="sd-add-btn">Add</button>
          </form>
          <p id="sd-status" role="status" aria-live="polite"></p>
          <ul id="sd-rows" aria-label="Recipients" aria-live="polite"></ul>
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
    const status = this.querySelector("#sd-status") as HTMLElement;
    status.textContent = "";
    this.hidden = false;
    document.addEventListener("keydown", this.keydownHandler);

    const input = this.querySelector("#sd-username") as HTMLInputElement;
    input.focus();

    // Best-effort duplicate-awareness (§3 step 7): fails open to "unknown" —
    // never blocks the dialog, per list_file_recipients's own contract.
    void this.loadAlreadyShared();
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

  private async loadAlreadyShared() {
    try {
      const ids = await serial(() => call<string[]>("list_file_recipients", { fileId: this.fileId }));
      this.alreadySharedIds = new Set(ids);
      // Cross-check already-verified rows (resolved before this returned).
      for (const row of this.rows) {
        if (row.status === "verified" && this.alreadySharedIds.has(row.key)) row.alreadyShared = true;
      }
      this.renderRows();
    } catch {
      // Fail-open: "unknown" — the picker still works, just without the note.
    }
  }

  private async addRecipient(username: string) {
    const status = this.querySelector("#sd-status") as HTMLElement;

    // Reject self client-side (spec §3 step 4) — never call resolve_recipient.
    const me = getUsername();
    if (me && username.toLowerCase() === me.toLowerCase()) {
      this.rows.push({
        key: `rejected:${this.counter++}`,
        username,
        status: "rejected",
        message: "You are already the owner.",
      });
      this.renderRows();
      return;
    }

    // Don't re-request a username that's already pending/verified/rejected in
    // this session — the resolve is idempotent but pointless to repeat.
    if (this.rows.some((r) => r.username.toLowerCase() === username.toLowerCase() && r.status !== "rejected")) {
      status.textContent = `${username} is already in the list.`;
      return;
    }

    const pendingKey = `pending:${this.counter++}`;
    this.rows.push({ key: pendingKey, username, status: "pending" });
    this.renderRows();

    try {
      const resolved = await serial(() =>
        call<ResolvedRecipient>("resolve_recipient", { req: { username } }),
      );
      const idx = this.rows.findIndex((r) => r.key === pendingKey);

      // Dedupe by resolved user_id (spec §8) — two usernames resolving to the
      // same account collapse to one row.
      const existing = this.rows.find((r) => r.key === resolved.user_id && r.status !== "rejected");
      if (existing) {
        if (idx >= 0) this.rows.splice(idx, 1);
        status.textContent = `${username} resolves to an account already in the list.`;
        this.renderRows();
        return;
      }

      const row: Row = {
        key: resolved.user_id,
        username: resolved.username,
        status: "verified",
        fingerprint: resolved.fingerprint,
        alreadyShared: resolved.already_shared || this.alreadySharedIds.has(resolved.user_id),
      };
      if (idx >= 0) this.rows[idx] = row;
      else this.rows.push(row);
      status.textContent = "";
    } catch (x) {
      const idx = this.rows.findIndex((r) => r.key === pendingKey);
      const msg = errMessage(x, "This user's identity could not be verified.");
      if (idx >= 0) {
        this.rows[idx] = { key: `rejected:${this.counter++}`, username, status: "rejected", message: msg };
      }
    }
    this.renderRows();
    this.updateShareEnabled();
  }

  private removeRow(key: string) {
    this.rows = this.rows.filter((r) => r.key !== key);
    this.renderRows();
    this.updateShareEnabled();
  }

  private updateShareEnabled() {
    const btn = this.querySelector("#sd-share-btn") as HTMLButtonElement;
    btn.disabled = !this.rows.some((r) => r.status === "verified");
  }

  private async share() {
    const usernames = this.rows.filter((r) => r.status === "verified").map((r) => r.username);
    if (usernames.length === 0) return;
    const btn = this.querySelector("#sd-share-btn") as HTMLButtonElement;
    btn.disabled = true;
    for (const r of this.rows) if (r.status === "verified") r.status = "sharing";
    this.renderRows();

    try {
      const outcomes = await serial(() =>
        call<ReshareOutcome[]>("reshare_file", {
          req: { file_id: this.fileId, recipient_usernames: usernames },
        }),
      );
      this.applyOutcomes(outcomes);
    } catch (x) {
      // A whole-command failure (e.g. offline before any POST) — every row that
      // was attempted this round fails closed, individually retryable.
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
    ul.replaceChildren();
    for (const row of this.rows) {
      const li = document.createElement("li");
      li.className = "sd-row";
      li.setAttribute("data-row", row.key);

      const name = document.createElement("span");
      name.className = "sd-username";
      name.textContent = row.username;
      li.appendChild(name);

      if (row.fingerprint) {
        const fp = document.createElement("code");
        fp.className = "sd-fingerprint";
        fp.textContent = row.fingerprint;
        li.appendChild(fp);
      }

      const badge = document.createElement("state-badge");
      const { state, label } = badgeFor(row);
      badge.setAttribute("state", state);
      badge.setAttribute("label", label);
      li.appendChild(badge);

      if (row.alreadyShared && (row.status === "verified" || row.status === "sharing")) {
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

      if (row.status === "pending" || row.status === "verified" || row.status === "rejected") {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "sd-remove secondary";
        remove.textContent = "Remove";
        remove.setAttribute("aria-label", `Remove ${row.username}`);
        remove.addEventListener("click", () => this.removeRow(row.key));
        li.appendChild(remove);
      }

      ul.appendChild(li);
    }
  }
}

function badgeFor(row: Row): { state: string; label: string } {
  switch (row.status) {
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
