// Shared confirm-before-destructive helper (bundles Task 6.2). Two exports:
//
//  • `needsConfirm(confirmDestructive)` — the PURE decision (DOM-free, unit-
//    tested): honor the `confirm_destructive` behavior setting verbatim. When it
//    is on, a destructive action prompts first (the default-safe path — a
//    PERMANENT delete always asks); when off, the user has opted out of prompts.
//
//  • `confirmModal({...})` — an accessible confirm dialog returning
//    `Promise<boolean>` (true = the destructive action was confirmed). It is a
//    real modal: role="dialog"/aria-modal, Cancel focused on open (safe default),
//    Escape / backdrop / Cancel all resolve `false`, a focus trap keeps keyboard
//    users inside, and focus returns to the invoker on close. All dynamic text is
//    set via textContent (never innerHTML) — no XSS surface.
//
// The modal touches `document`, so it is exercised structurally (not mounted) in
// confirm.test.ts, matching the codebase convention for DOM/Tauri-bound UI.

// PURE: `confirm_destructive` is an opt-out — return it verbatim as the decision.
export function needsConfirm(confirmDestructive: boolean): boolean {
  return confirmDestructive;
}

export interface ConfirmOptions {
  title: string;
  message: string;
  /** Label for the destructive action button. Defaults to "Delete". */
  confirmLabel?: string;
}

// Build + show the modal; resolve true iff the user picks the destructive action.
export function confirmModal(opts: ConfirmOptions): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const returnFocus = (document.activeElement as HTMLElement) ?? null;

    const host = document.createElement("div");
    host.className = "confirm-host";
    // Static skeleton only — NO dynamic interpolation (a11y XSS lint). The
    // heading/message text is filled below via textContent.
    host.innerHTML = `
      <div class="confirm-overlay">
        <div
          class="confirm-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby="confirm-h"
          aria-describedby="confirm-msg"
          tabindex="-1"
        >
          <h2 id="confirm-h" class="confirm-h"></h2>
          <p id="confirm-msg" class="confirm-msg"></p>
          <div class="confirm-actions">
            <button type="button" id="confirm-cancel" class="secondary">Cancel</button>
            <button type="button" id="confirm-ok" class="danger">Delete</button>
          </div>
        </div>
      </div>`;

    const overlay = host.querySelector(".confirm-overlay") as HTMLElement;
    const heading = host.querySelector("#confirm-h") as HTMLElement;
    const msg = host.querySelector("#confirm-msg") as HTMLElement;
    const cancel = host.querySelector("#confirm-cancel") as HTMLButtonElement;
    const ok = host.querySelector("#confirm-ok") as HTMLButtonElement;

    // Dynamic text via textContent — never innerHTML.
    heading.textContent = opts.title;
    msg.textContent = opts.message;
    ok.textContent = opts.confirmLabel ?? "Delete";

    let settled = false;
    const finish = (result: boolean) => {
      if (settled) return;
      settled = true;
      document.removeEventListener("keydown", onKeydown, true);
      host.remove();
      returnFocus?.focus();
      resolve(result);
    };

    const onKeydown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        finish(false);
        return;
      }
      if (e.key === "Tab") {
        // Two-stop focus trap: Cancel ⇄ Delete never escape the modal.
        e.preventDefault();
        const active = document.activeElement;
        if (e.shiftKey) {
          (active === cancel ? ok : cancel).focus();
        } else {
          (active === ok ? cancel : ok).focus();
        }
      }
    };

    cancel.addEventListener("click", () => finish(false));
    ok.addEventListener("click", () => finish(true));
    // Backdrop click (outside the panel) cancels — the safe default.
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) finish(false);
    });
    document.addEventListener("keydown", onKeydown, true);

    document.body.appendChild(host);
    // Focus Cancel on open: the safe default target for a destructive prompt.
    cancel.focus();
  });
}
