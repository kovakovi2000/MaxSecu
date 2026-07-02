import { on } from "../core/rpc.ts";
import type { SharePhase } from "../core/types.ts";
import "./state-badge.ts";

// Background reshare feedback tray (T4 Task 11, spec §6/§11) — mirrors
// <upload-tray>'s structure but for post-upload multi-recipient sharing.
// Subscribes to EVT_RESHARE and renders one <li> per file_id being (re)shared,
// with a per-recipient COUNT summary ("3 of 5 shared · 2 failed"). A reshare
// has no streaming payload, so this intentionally carries NO byte-rate/ETA
// math (unlike upload-tray) — progress is a running count built from the
// `recipient`/`done` events.
//
// It is a PASSIVE surface: it never calls reshare_file itself (that stays in
// <share-dialog>), it only reflects state — so background reshares keep
// surfacing progress even after the dialog that started them is dismissed.
//
// ARIA: the list is a labelled `aria-live="polite"` region. A row only gets
// `role="alert"` (assertive) once it reaches its terminal ALL-FAILED state
// (shared==0 && failed>0) — a fully or partially successful outcome stays
// polite. Each row's <state-badge> always carries a text label (WCAG 1.4.1,
// never color alone). A fully-successful row auto-clears after ~4s, like
// upload-tray; a failed/partial row persists with a Dismiss control.
//
// No secrets ever pass through here: only file_id/username/ok/code/counts —
// the same fields SharePhase/ReshareOutcomeDto already restrict themselves
// to. All dynamic text (including the user-controlled `username`) is set via
// textContent, never interpolated into innerHTML.

interface FileRow {
  fileId: string;
  usernames: Set<string>; // recipients seen this batch (first seen via "resolving")
  shared: number;
  failed: number;
  failures: Array<{ username: string; code: string | null }>;
  done: boolean;
}

export class ShareTray extends HTMLElement {
  private unlisten: (() => void) | null = null;
  private rows = new Map<string, FileRow>();

  async connectedCallback() {
    this.innerHTML = `
      <section class="share-tray" aria-label="Background sharing" hidden>
        <h2 class="st-title">Sharing</h2>
        <ul id="st-list" aria-live="polite"></ul>
      </section>`;

    const ul = await on<SharePhase>("maxsecu://reshare-state", (m) => this.onMsg(m));
    this.unlisten = ul;
  }

  disconnectedCallback() {
    this.unlisten?.();
    this.unlisten = null;
  }

  private rowFor(fileId: string): FileRow {
    let r = this.rows.get(fileId);
    if (!r) {
      r = { fileId, usernames: new Set(), shared: 0, failed: 0, failures: [], done: false };
      this.rows.set(fileId, r);
    }
    return r;
  }

  private li(fileId: string): HTMLLIElement {
    const list = this.querySelector("#st-list") as HTMLUListElement;
    let li = list.querySelector<HTMLLIElement>(`li[data-file="${cssEscape(fileId)}"]`);
    if (!li) {
      (this.querySelector(".share-tray") as HTMLElement | null)?.removeAttribute("hidden");
      li = document.createElement("li");
      li.setAttribute("data-file", fileId);

      const head = document.createElement("div");
      head.className = "st-head";
      const badge = document.createElement("state-badge");
      badge.className = "st-badge";
      const summary = document.createElement("span");
      summary.className = "st-summary";
      head.append(badge, summary);

      const failList = document.createElement("ul");
      failList.className = "st-failures";
      failList.setAttribute("aria-label", "Failed recipients");

      li.append(head, failList);
      list.appendChild(li);
    }
    return li;
  }

  private onMsg(m: SharePhase) {
    const row = this.rowFor(m.file_id);
    if (row.done) return; // a stray late event after finalize(); ignore.
    const li = this.li(m.file_id);
    const badge = li.querySelector(".st-badge") as HTMLElement;
    const summary = li.querySelector(".st-summary") as HTMLElement;

    switch (m.phase) {
      case "resolving":
        row.usernames.add(m.username);
        badge.setAttribute("state", "fetching");
        badge.setAttribute("label", "Resolving…");
        break;
      case "verifying":
        badge.setAttribute("state", "verifying");
        badge.setAttribute("label", "Verifying…");
        break;
      case "wrapping":
        badge.setAttribute("state", "decrypting");
        badge.setAttribute("label", "Wrapping…");
        break;
      case "recipient":
        if (m.ok) {
          row.shared += 1;
        } else {
          row.failed += 1;
          row.failures.push({ username: m.username, code: m.code });
        }
        this.renderFailures(li, row);
        break;
      case "done":
        // Authoritative: the backend's own tally overrides the running count.
        row.shared = m.shared;
        row.failed = m.failed;
        row.done = true;
        this.renderFailures(li, row);
        this.finalize(li, row);
        return;
    }

    // Running (non-terminal) count — no byte-rate/ETA math, just X of N.
    const total = Math.max(row.usernames.size, row.shared + row.failed);
    summary.textContent = total > 0
      ? `${row.shared} of ${total} shared${row.failed > 0 ? ` · ${row.failed} failed` : ""}`
      : "Sharing…";
  }

  private renderFailures(li: HTMLLIElement, row: FileRow) {
    const ul = li.querySelector(".st-failures") as HTMLUListElement;
    ul.replaceChildren();
    for (const f of row.failures) {
      const item = document.createElement("li");
      const name = document.createElement("span");
      name.className = "st-username";
      name.textContent = f.username; // textContent only — never raw innerHTML.
      const badge = document.createElement("state-badge");
      badge.setAttribute("state", "failed");
      badge.setAttribute("label", f.code ? `Failed: ${f.code}` : "Failed");
      item.append(name, badge);
      ul.appendChild(item);
    }
  }

  private finalize(li: HTMLLIElement, row: FileRow) {
    const badge = li.querySelector(".st-badge") as HTMLElement;
    const summary = li.querySelector(".st-summary") as HTMLElement;
    const total = row.shared + row.failed;
    const allFailed = row.shared === 0 && row.failed > 0;

    summary.textContent = total > 0
      ? `${row.shared} of ${total} shared${row.failed > 0 ? ` · ${row.failed} failed` : ""}`
      : "Nothing was shared.";

    if (allFailed) {
      // Terminal all-failed: the only case that escalates to assertive.
      li.setAttribute("role", "alert");
      badge.setAttribute("state", "failed");
      badge.setAttribute("label", "Sharing failed");
      this.addDismiss(li, row.fileId);
    } else if (row.failed > 0) {
      li.removeAttribute("role");
      badge.setAttribute("state", "failed");
      badge.setAttribute("label", "Partially shared");
      this.addDismiss(li, row.fileId);
    } else {
      li.removeAttribute("role");
      badge.setAttribute("state", "ready");
      badge.setAttribute("label", "Shared");
      this.clearRowLater(row.fileId);
    }
  }

  private addDismiss(li: HTMLLIElement, fileId: string) {
    if (li.querySelector("button.st-dismiss")) return;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "st-dismiss secondary";
    btn.textContent = "Dismiss";
    btn.setAttribute("aria-label", "Dismiss sharing result");
    btn.addEventListener("click", () => {
      this.rows.delete(fileId);
      li.remove();
      this.maybeHideTray();
    });
    li.appendChild(btn);
  }

  private clearRowLater(fileId: string) {
    window.setTimeout(() => {
      this.rows.delete(fileId);
      const list = this.querySelector("#st-list") as HTMLUListElement | null;
      list?.querySelector(`li[data-file="${cssEscape(fileId)}"]`)?.remove();
      this.maybeHideTray();
    }, 4000);
  }

  private maybeHideTray() {
    const list = this.querySelector("#st-list") as HTMLUListElement | null;
    if (!list || list.children.length === 0) {
      (this.querySelector(".share-tray") as HTMLElement | null)?.setAttribute("hidden", "");
    }
  }
}

function cssEscape(s: string): string {
  // file_id is server-side hex, but escape defensively for the attribute
  // selector (mirrors upload-tray's cssEscape).
  return s.replace(/["\\\]]/g, "\\$&");
}

customElements.define("share-tray", ShareTray);
