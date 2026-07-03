import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import type { SplitRecoveryKeyResponse } from "../core/types.ts";

// <recovery-split-screen> — the T6 offline Shamir K-of-N split ceremony wizard
// (design spec §4 "the split ceremony UX" + §9 custody guidance + §10 a11y).
// Reachable from the shell's "Recovery custody" nav entry (mirrors "Admin").
//
// This screen exists to be run ONLY on the offline, air-gapped recovery
// device (spec §3) — the backend commands it calls (`split_recovery_key`,
// `record_split_ceremony`, `save_recovery_share`) perform zero network I/O by
// construction; nothing here dials out.
//
// Wizard steps (a small local state machine, `this.step`):
//   "setup" — load the sealed recovery-secret file + passphrase, choose a
//             non-secret label + k/n with live (non-blocking) guidance, then
//             Generate. The ONLY place `split_recovery_key` is called, wrapped
//             in `serial()` as a single-flight guard against a double-submit.
//   "share" — present exactly ONE of the n generated shares at a time (spec
//             §4.4 — never a "show all shares" list), with a persistent,
//             non-dismissable "shown once" banner, a copy-to-clipboard
//             primary action, and a "save to file" secondary action
//             (`save_recovery_share`). Advancing to the next share (or to the
//             completion summary once ALL n shares have been acknowledged)
//             moves focus to the new step's heading (wizard focus discipline,
//             spec §10) and DROPS the just-shown share reference.
//   "done"  — completion summary: ONLY non-secret metadata (label, k-of-n,
//             which custodian indices were issued) — never share/secret
//             bytes. Offers to write the non-secret ceremony log
//             (`record_split_ceremony`) on explicit operator action.
//
// Secret hygiene: the passphrase input is cleared the instant its value is
// captured for the Generate call (never lingers in the DOM); the in-memory
// `shares` array exists only for the span of the one-at-a-time reveal and is
// nulled out as soon as the last share has been acknowledged, and also on
// unmount — nothing here persists shares/passphrase beyond the wizard's own
// lifetime (spec §11 checklist).
type Step = "setup" | "share" | "done";

export class RecoverySplitScreen extends HTMLElement {
  private step: Step = "setup";

  // Live-collected shares for the one-at-a-time reveal (spec §4.4). Set once,
  // by Generate; drained to `null` the moment the last share is acknowledged
  // or the component is torn down — never held any longer than that.
  private shares: string[] | null = null;
  private shareIdx = 0; // index into `shares` currently on screen

  // Non-secret metadata carried from the split response into the "done" step,
  // kept AFTER `shares` is nulled (these fields carry no secret material).
  private doneLabel = "";
  private doneK = 0;
  private doneN = 0;

  private busy = false; // guards Generate against a double-submit

  connectedCallback() {
    this.renderShell();
  }

  disconnectedCallback() {
    // Leaving the screen mid-ceremony drops any still-unshown share text —
    // there is no "resume later" for a breakglass secret (mirrors the
    // backend's own CeremonySession discard-on-teardown discipline).
    this.shares = null;
  }

  // ---- shell ----

  private renderShell() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="rc-h">
        <h1 id="rc-h">Recovery custody — split ceremony</h1>
        <p class="hint">Run this only on the offline recovery device. This ceremony never
          makes a network call.</p>

        <section aria-labelledby="rc-g-h">
          <h2 id="rc-g-h">Custody guidance</h2>
          <ul id="rc-guidance-list">
            <li>Distribute shares to distinct trusted parties or locations. A share held by
              two people who fully trust each other, or stored in two copies of the same
              safe, is one custody point, not two.</li>
            <li>Never store <code>k</code> or more shares together. Storing enough shares
              together to reconstruct recreates the single point of theft this split exists
              to remove.</li>
            <li>Plan for loss. Any fewer than <code>k</code> shares can be lost and the key
              still reconstructs; losing more than that permanently breaks recoverability —
              there is no override, no backdoor.</li>
            <li>If a custodian's share is lost or suspected compromised, the only remedy is a
              full new split against a freshly rotated recovery key. Re-splitting THIS SAME
              key invalidates every share just issued but does not revoke the old,
              still-outstanding share's validity for the old key.</li>
            <li>Fewer than <code>k</code> shares reveal nothing about the secret to whoever
              holds them — an information-theoretic guarantee, not a computational one. A
              custodian holding one share can be told plainly: on its own, it is worthless
              to anyone who steals it.</li>
          </ul>
        </section>

        <div id="rc-step"></div>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();
    this.renderStep();
  }

  private stepEl(): HTMLElement {
    return this.querySelector("#rc-step") as HTMLElement;
  }

  /** Move to `step`, re-render its content, and move focus to its heading —
   * the wizard focus discipline (spec §10). Not used for the very first
   * render (the initial "setup" step keeps focus on #main, matching every
   * other routed screen's mount convention). */
  private goToStep(step: Step) {
    this.step = step;
    this.renderStep();
    (this.querySelector("#rc-step-h") as HTMLElement | null)?.focus();
  }

  private renderStep() {
    if (this.step === "setup") this.renderSetup();
    else if (this.step === "share") this.renderShare();
    else this.renderDone();
  }

  // ---- step: setup (load secret + choose k/n) ----

  private renderSetup() {
    this.stepEl().innerHTML = `
      <section aria-labelledby="rc-step-h">
        <h2 id="rc-step-h" tabindex="-1">Load the recovery secret and choose a threshold</h2>
        <p role="alert" id="rc-setup-err"></p>
        <form id="rc-setup-form">
          <label>Sealed recovery-secret file
            <input type="text" id="rc-path" name="path" autocomplete="off" /></label>
          <button type="button" id="rc-browse">Browse…</button>

          <label>Passphrase
            <input type="password" id="rc-pass" name="passphrase" autocomplete="off" /></label>

          <label>Label (non-secret, identifies this recovery-key generation)
            <input type="text" id="rc-label" name="label" autocomplete="off"
              value="MaxSecu recovery key" /></label>

          <label>Total shares (n)
            <input type="number" id="rc-n" name="n" min="1" max="255" value="5" /></label>
          <label>Threshold to reconstruct (k)
            <input type="number" id="rc-k" name="k" min="1" max="255" value="3" /></label>

          <p role="status" aria-live="polite" id="rc-guidance-live"></p>
          <p class="hint" id="rc-resplit-note">Re-splitting this (or any) key invalidates
            every share previously issued and must be paired with a full key rotation — see
            custody guidance above.</p>

          <button type="submit" id="rc-generate">Generate n shares</button>
        </form>
      </section>`;

    const pathInput = this.querySelector("#rc-path") as HTMLInputElement;
    (this.querySelector("#rc-browse") as HTMLButtonElement).addEventListener("click", () => {
      void this.browse(pathInput);
    });

    const kInput = this.querySelector("#rc-k") as HTMLInputElement;
    const nInput = this.querySelector("#rc-n") as HTMLInputElement;
    kInput.addEventListener("input", () => this.updateGuidance());
    nInput.addEventListener("input", () => this.updateGuidance());
    this.updateGuidance();

    (this.querySelector("#rc-setup-form") as HTMLFormElement).addEventListener("submit", (e) => {
      e.preventDefault();
      void this.generate();
    });
  }

  private async browse(pathInput: HTMLInputElement) {
    try {
      const picked = await call<string | null>("pick_file", { extensions: ["sealed"] });
      if (picked) pathInput.value = picked;
    } catch (x) {
      (this.querySelector("#rc-setup-err") as HTMLElement).textContent =
        errMessage(x, "Could not open the file dialog.");
    }
  }

  /** Read current k/n, validate (D-E: hard k>=1,n>=1,k<=n; advisory n>=3,
   * warn k=1/k=n), write live guidance text, and enable/disable Generate. */
  private updateGuidance(): { k: number; n: number; valid: boolean } {
    const kInput = this.querySelector("#rc-k") as HTMLInputElement;
    const nInput = this.querySelector("#rc-n") as HTMLInputElement;
    const live = this.querySelector("#rc-guidance-live") as HTMLElement;
    const generateBtn = this.querySelector("#rc-generate") as HTMLButtonElement;

    const k = Number(kInput.value);
    const n = Number(nInput.value);
    const valid = Number.isInteger(k) && Number.isInteger(n) && k >= 1 && n >= 1 && k <= n;

    const lines: string[] = [];
    if (!valid) {
      lines.push("Choose a threshold with 1 ≤ k ≤ n before generating.");
    } else {
      if (k === 1) {
        lines.push(
          "Warning: k = 1 means a SINGLE custodian's share alone fully reconstructs the " +
            "key — no different from keeping one whole cold copy.",
        );
      }
      if (k === n && n > 1) {
        lines.push(
          "Warning: k = n means losing any ONE custodian's share permanently loses the " +
            "ability to recover this key — there is no slack for loss.",
        );
      }
      if (n < 3) {
        lines.push(
          "Advisory: fewer than 3 custodians leaves little practical separation of trust. " +
            "Consider at least 3 if you can.",
        );
      }
      const majority = Math.floor(n / 2) + 1;
      if (k !== majority) {
        lines.push(`Suggestion: a common choice is a strict majority of n (e.g. ${majority} of ${n}).`);
      }
    }
    live.textContent = lines.join(" ");
    generateBtn.disabled = !valid;
    generateBtn.toggleAttribute("aria-disabled", !valid);
    return { k, n, valid };
  }

  private async generate() {
    if (this.busy) return;
    const err = this.querySelector("#rc-setup-err") as HTMLElement;
    err.textContent = "";

    const { k, n, valid } = this.updateGuidance();
    if (!valid) {
      err.textContent = "Choose a threshold with 1 ≤ k ≤ n before generating.";
      return;
    }

    const path = (this.querySelector("#rc-path") as HTMLInputElement).value.trim();
    const label = (this.querySelector("#rc-label") as HTMLInputElement).value.trim();
    const passInput = this.querySelector("#rc-pass") as HTMLInputElement;
    const passphrase = passInput.value;
    // Clear the passphrase from the DOM the instant it is captured — it must
    // never linger on screen or in the input's value past this point.
    passInput.value = "";

    if (!path) {
      err.textContent = "Choose the sealed recovery-secret file first.";
      return;
    }
    if (!label) {
      err.textContent = "Choose a label for this recovery-key generation.";
      return;
    }

    this.busy = true;
    const generateBtn = this.querySelector("#rc-generate") as HTMLButtonElement | null;
    if (generateBtn) generateBtn.disabled = true;

    try {
      const resp = await serial(() =>
        call<SplitRecoveryKeyResponse>("split_recovery_key", {
          req: { recovery_secret_path: path, passphrase, label, k, n },
        }),
      );
      this.shares = resp.shares;
      this.doneLabel = resp.label;
      this.doneK = resp.k;
      this.doneN = resp.n;
      this.shareIdx = 0;
      this.goToStep("share");
    } catch (x) {
      err.textContent = errMessage(x, "Could not split the recovery secret.");
      this.busy = false;
      if (generateBtn) generateBtn.disabled = false;
    }
  }

  // ---- step: share (one at a time, spec §4.4) ----

  private renderShare() {
    if (!this.shares || this.shareIdx >= this.shares.length) return;
    const total = this.shares.length;
    const num = this.shareIdx + 1;

    this.stepEl().innerHTML = `
      <section aria-labelledby="rc-step-h">
        <h2 id="rc-step-h" tabindex="-1"></h2>
        <p role="alert" id="rc-share-banner">This share is shown once. Write it down or
          export it now — store it separately from the other shares. Do not photograph or
          store it alongside another share.</p>
        <p class="hint" id="rc-share-hint"></p>

        <label id="rc-share-text-label"><span id="rc-share-text-label-text">Share text</span>
          <textarea id="rc-share-text" readonly rows="4"></textarea></label>

        <button type="button" id="rc-copy"></button>
        <p role="status" aria-live="polite" id="rc-copy-status"></p>

        <label>Save to path
          <input type="text" id="rc-save-path" autocomplete="off" /></label>
        <button type="button" id="rc-save"></button>
        <p role="status" aria-live="polite" id="rc-save-status"></p>

        <button type="button" id="rc-next">I have recorded this share — next</button>
      </section>`;

    const shareText = this.shares[this.shareIdx];
    (this.querySelector("#rc-step-h") as HTMLElement).textContent = `Share ${num} of ${total}`;
    (this.querySelector("#rc-share-hint") as HTMLElement).textContent =
      `Custodian index ${num} of ${total}. Give this share to one distinct, trusted ` +
      `custodian — never keep k or more shares together (see custody guidance above).`;
    (this.querySelector("#rc-share-text-label-text") as HTMLElement).textContent =
      `Share ${num} of ${total} text`;
    (this.querySelector("#rc-share-text") as HTMLTextAreaElement).value = shareText;
    (this.querySelector("#rc-copy") as HTMLButtonElement).textContent = `Copy share ${num} text`;
    (this.querySelector("#rc-save") as HTMLButtonElement).textContent = `Save share ${num} to file`;

    (this.querySelector("#rc-copy") as HTMLButtonElement).addEventListener("click", () => {
      void this.copyShare(shareText);
    });
    (this.querySelector("#rc-save") as HTMLButtonElement).addEventListener("click", () => {
      void this.saveShare(shareText);
    });
    (this.querySelector("#rc-next") as HTMLButtonElement).addEventListener("click", () => {
      this.nextShare();
    });
  }

  private async copyShare(text: string) {
    const status = this.querySelector("#rc-copy-status") as HTMLElement;
    try {
      await navigator.clipboard.writeText(text);
      status.textContent = "Copied to clipboard.";
    } catch {
      status.textContent = "Could not copy automatically — select the text above and copy it manually.";
    }
  }

  private async saveShare(text: string) {
    const status = this.querySelector("#rc-save-status") as HTMLElement;
    const path = (this.querySelector("#rc-save-path") as HTMLInputElement).value.trim();
    if (!path) {
      status.setAttribute("role", "alert");
      status.textContent = "Enter a path to save this share to.";
      return;
    }
    try {
      await call<void>("save_recovery_share", { path, shareText: text });
      status.setAttribute("role", "status");
      status.textContent = "Share saved to file.";
    } catch (x) {
      status.setAttribute("role", "alert");
      status.textContent = errMessage(x, "Could not save the share to that file.");
    }
  }

  private nextShare() {
    if (!this.shares) return;
    this.shareIdx += 1;
    if (this.shareIdx >= this.shares.length) {
      // Every share has now been acknowledged — drop the reference (spec §11:
      // nothing outlives the wizard's own lifetime) and move to the summary.
      this.shares = null;
      this.goToStep("done");
    } else {
      this.goToStep("share");
    }
  }

  // ---- step: done (non-secret summary + ceremony log) ----

  private renderDone() {
    const indices = Array.from({ length: this.doneN }, (_, i) => i + 1);

    this.stepEl().innerHTML = `
      <section aria-labelledby="rc-step-h">
        <h2 id="rc-step-h" tabindex="-1">Split complete</h2>
        <p role="status" aria-live="polite">Every share has been shown once. No share text
          remains available in this session — re-running Generate creates a NEW split that
          invalidates every share just issued and requires a full key rotation.</p>

        <dl id="rc-summary">
          <dt>Label</dt><dd id="rc-sum-label"></dd>
          <dt>Threshold</dt><dd id="rc-sum-kn"></dd>
          <dt>Custodian indices issued</dt><dd id="rc-sum-idx"></dd>
        </dl>

        <form id="rc-log-form">
          <label>Ceremony log file path
            <input type="text" id="rc-log-path" autocomplete="off" /></label>
          <label>Operator name (optional)
            <input type="text" id="rc-log-operator" autocomplete="off" /></label>
          <button type="submit" id="rc-log-submit">Write ceremony log</button>
        </form>
        <p role="status" aria-live="polite" id="rc-log-status"></p>

        <button type="button" id="rc-restart">Start another split</button>
      </section>`;

    (this.querySelector("#rc-sum-label") as HTMLElement).textContent = this.doneLabel;
    (this.querySelector("#rc-sum-kn") as HTMLElement).textContent = `${this.doneK} of ${this.doneN}`;
    (this.querySelector("#rc-sum-idx") as HTMLElement).textContent = indices.join(", ");

    (this.querySelector("#rc-log-form") as HTMLFormElement).addEventListener("submit", (e) => {
      e.preventDefault();
      void this.writeLog(indices);
    });
    (this.querySelector("#rc-restart") as HTMLButtonElement).addEventListener("click", () => {
      this.restart();
    });
  }

  private async writeLog(custodianIndices: number[]) {
    const status = this.querySelector("#rc-log-status") as HTMLElement;
    const logPath = (this.querySelector("#rc-log-path") as HTMLInputElement).value.trim();
    const operatorRaw = (this.querySelector("#rc-log-operator") as HTMLInputElement).value.trim();
    if (!logPath) {
      status.setAttribute("role", "alert");
      status.textContent = "Enter a path for the ceremony log first.";
      return;
    }
    try {
      await call<void>("record_split_ceremony", {
        req: {
          log_path: logPath,
          label: this.doneLabel,
          k: this.doneK,
          n: this.doneN,
          custodian_indices: custodianIndices,
          operator: operatorRaw ? operatorRaw : null,
        },
      });
      status.setAttribute("role", "status");
      status.textContent = "Ceremony log written.";
    } catch (x) {
      status.setAttribute("role", "alert");
      status.textContent = errMessage(x, "Could not write the ceremony log.");
    }
  }

  private restart() {
    this.shares = null;
    this.shareIdx = 0;
    this.doneLabel = "";
    this.doneK = 0;
    this.doneN = 0;
    this.busy = false;
    this.goToStep("setup");
  }
}

function errMessage(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return fallback;
}

customElements.define("recovery-split-screen", RecoverySplitScreen);
