import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { ReconstructState, rejectionCopy } from "../core/recovery-reconstruct-store.ts";
import type { AddShareResponse, ReconstructResponse, ProveResponse } from "../core/types.ts";
import "./state-badge.ts";

// <recovery-reconstruct-screen> — the T6 offline Shamir K-of-N RECONSTRUCT
// ceremony (design spec §6 "the reconstruct ceremony UX" + §10 a11y). The
// counterpart to Task 10's `<recovery-split-screen>`; run on the offline
// recovery device by a custodian who has collected `k` (or more) shares.
//
// Wizard steps (a small local state machine, `this.step`):
//   "add"   — add shares ONE AT A TIME (paste text, primary; "pick a file",
//             secondary) through `add_recovery_share`. The running list shows
//             COUNT ONLY ("3 of 5 needed") — a share's bytes are NEVER
//             redisplayed once accepted (spec §6 step 1). Each rejection
//             class (malformed/corrupt/duplicate/foreign/out-of-range-index)
//             gets its own distinct `role=alert` copy (`rejectionCopy`, the
//             pure `recovery-reconstruct-store.ts` module). "Reconstruct" is
//             `aria-disabled` (and truly disabled) until `have >= need` — no
//             below-threshold "try anyway".
//   "prove" — THE load-bearing gate (spec §6 step 4 / §2.2): reaching this
//             step via `reconstruct_recovery_key` does NOT mean success.
//             `reconstruct_recovery_key` only mints an opaque
//             `ceremony_handle` for a key that lives entirely inside the
//             backend's CeremonySession. Success is shown ONLY after the
//             operator supplies a REAL recovery wrap they have to hand
//             (file_id/version/dek_commit/the wrap itself) and
//             `prove_reconstructed_key` returns `verified: true`. A
//             `verified: false` is a valid, NON-success proof outcome — its
//             own distinct `role=alert`, never treated as an error and never
//             silently retried into a success.
//
// Secret hygiene: shares are held by the backend session, never redisplayed;
// the paste textarea is cleared after every accepted add; `discard_ceremony_session`
// is called both on an explicit "start over" and on `disconnectedCallback` (leaving
// the screen), zeroizing any collected shares / reconstructed key server-side —
// mirrors `<recovery-split-screen>`'s own teardown discipline.
type Step = "add" | "prove";

export class RecoveryReconstructScreen extends HTMLElement {
  private step: Step = "add";
  private counts = new ReconstructState();

  // Set once reconstruct_recovery_key succeeds; carries no secret (an opaque
  // handle + the non-secret label). Reset on "start over"/teardown.
  private ceremonyHandle = "";
  private proveVerified = false; // gates the green success state — see renderProve()

  private addBusy = false;
  private reconstructBusy = false;
  private proveBusy = false;

  connectedCallback() {
    this.renderShell();
  }

  disconnectedCallback() {
    // Leaving the screen ends the in-progress ceremony: the backend wipes any
    // collected share bodies and reconstructed key (spec §8/§11). Best-effort —
    // there is nothing useful to do with a failure here on teardown.
    void call<void>("discard_ceremony_session", {}).catch(() => {});
  }

  // ---- shell ----

  private renderShell() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="rr-h">
        <h1 id="rr-h">Recovery custody — reconstruct</h1>
        <p class="hint">Run this only on the offline recovery device, with shares gathered
          from distinct custodians. This ceremony never makes a network call.</p>
        <div id="rr-step"></div>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();
    this.renderStep();
  }

  private stepEl(): HTMLElement {
    return this.querySelector("#rr-step") as HTMLElement;
  }

  /** Move to `step`, re-render, and move focus to its heading (wizard focus
   * discipline, spec §10). Not used for the very first render (focus stays on
   * #main for the initial "add" step, matching every other routed screen). */
  private goToStep(step: Step) {
    this.step = step;
    this.renderStep();
    (this.querySelector("#rr-step-h") as HTMLElement | null)?.focus();
  }

  private renderStep() {
    if (this.step === "add") this.renderAdd();
    else this.renderProve();
  }

  // ---- step: add (one share at a time, spec §6 step 1) ----

  private renderAdd() {
    this.stepEl().innerHTML = `
      <section aria-labelledby="rr-step-h">
        <h2 id="rr-step-h" tabindex="-1">Add recovery shares</h2>

        <form id="rr-add-form">
          <label>Share text
            <textarea id="rr-share-text" rows="3" autocomplete="off"
              placeholder="MSHARE1:..."></textarea></label>
          <button type="submit" id="rr-add-btn">Add share</button>
          <button type="button" id="rr-pick-file">Pick a file…</button>
        </form>
        <p role="alert" id="rr-add-err"></p>

        <p role="status" aria-live="polite" id="rr-count"></p>
        <p role="status" aria-live="polite" id="rr-reconstruct-status"></p>

        <button type="button" id="rr-reconstruct" disabled aria-disabled="true">Reconstruct</button>
      </section>`;

    this.updateAddUI();

    (this.querySelector("#rr-add-form") as HTMLFormElement).addEventListener("submit", (e) => {
      e.preventDefault();
      void this.addShare();
    });
    (this.querySelector("#rr-pick-file") as HTMLButtonElement).addEventListener("click", () => {
      void this.pickShareFile();
    });
    (this.querySelector("#rr-reconstruct") as HTMLButtonElement).addEventListener("click", () => {
      void this.reconstruct();
    });
  }

  /** Reflect `this.counts` into the count/status live regions and the
   * Reconstruct button's disabled/aria-disabled state. Called after every
   * accepted add and on initial render. */
  private updateAddUI() {
    const { have, need } = this.counts.get();
    const countEl = this.querySelector("#rr-count") as HTMLElement | null;
    const statusEl = this.querySelector("#rr-reconstruct-status") as HTMLElement | null;
    const reconstructBtn = this.querySelector("#rr-reconstruct") as HTMLButtonElement | null;
    if (!countEl || !statusEl || !reconstructBtn) return;

    // Count only — the share text itself is never shown (spec §6 step 1).
    countEl.textContent = need > 0 ? `${have} of ${need} needed.` : "No shares added yet.";

    const canGo = this.counts.canReconstruct();
    if (need === 0) {
      statusEl.textContent = "Add at least one share to learn how many are needed.";
    } else if (!canGo) {
      const remaining = need - have;
      statusEl.textContent = `Add at least ${remaining} more share${remaining === 1 ? "" : "s"} to reconstruct.`;
    } else {
      statusEl.textContent = "Ready to reconstruct.";
    }

    const disabled = !canGo || this.reconstructBusy;
    reconstructBtn.disabled = disabled;
    reconstructBtn.toggleAttribute("aria-disabled", disabled);
  }

  private async pickShareFile() {
    const err = this.querySelector("#rr-add-err") as HTMLElement;
    err.textContent = "";
    try {
      const picked = await call<string | null>("pick_file", { extensions: ["mshare", "txt"] });
      if (!picked) return;
      const text = await call<string>("read_recovery_share_file", { path: picked });
      (this.querySelector("#rr-share-text") as HTMLTextAreaElement).value = text;
    } catch (x) {
      err.textContent = errMessage(x, "Could not read that file.");
    }
  }

  private async addShare() {
    if (this.addBusy) return;
    const err = this.querySelector("#rr-add-err") as HTMLElement;
    const textarea = this.querySelector("#rr-share-text") as HTMLTextAreaElement;
    const addBtn = this.querySelector("#rr-add-btn") as HTMLButtonElement | null;
    err.textContent = "";

    const shareText = textarea.value.trim();
    if (!shareText) {
      err.textContent = "Paste or load a share first.";
      return;
    }

    this.addBusy = true;
    if (addBtn) addBtn.disabled = true;
    try {
      const resp = await serial(() =>
        call<AddShareResponse>("add_recovery_share", { req: { share_text: shareText } }),
      );
      // Accepted: fold the backend's count/label into the pure store and clear
      // the input — a share, once accepted, is never redisplayed.
      this.counts.applyAccepted(resp);
      textarea.value = "";
      this.updateAddUI();
    } catch (x) {
      const code = errCode(x);
      err.textContent = rejectionCopy(code, errMessage(x, "Could not add that share."));
    } finally {
      this.addBusy = false;
      if (addBtn) addBtn.disabled = false;
    }
  }

  private async reconstruct() {
    if (this.reconstructBusy || !this.counts.canReconstruct()) return;
    const err = this.querySelector("#rr-add-err") as HTMLElement;
    err.textContent = "";

    this.reconstructBusy = true;
    this.updateAddUI();
    try {
      const resp = await serial(() => call<ReconstructResponse>("reconstruct_recovery_key", {}));
      // NB: reaching here is NOT success — reconstruct_recovery_key only mints
      // a handle into the backend session. The green state is gated entirely
      // behind prove_reconstructed_key returning verified:true (renderProve()).
      this.ceremonyHandle = resp.ceremony_handle;
      this.proveVerified = false;
      this.goToStep("prove");
    } catch (x) {
      err.textContent = errMessage(x, "Could not reconstruct the recovery key.");
    } finally {
      this.reconstructBusy = false;
      this.updateAddUI();
    }
  }

  // ---- step: prove (the load-bearing gate, spec §6 step 4) ----

  private renderProve() {
    const { label } = this.counts.get();

    this.stepEl().innerHTML = `
      <section aria-labelledby="rr-step-h">
        <h2 id="rr-step-h" tabindex="-1">Verify the reconstructed key</h2>
        <p class="hint">The shares combined without error, but that alone does not prove they
          were the right shares. Supply a real recovery wrap you already have — for a known
          file id, version, and key commitment — and this reconstructed key must actually open
          it before this ceremony is treated as a success.</p>
        <dl id="rr-prove-meta">
          <dt>Label</dt><dd id="rr-prove-label"></dd>
        </dl>

        <div id="rr-prove-success" hidden></div>
        <p role="alert" id="rr-prove-err"></p>

        <form id="rr-prove-form">
          <label>File id (hex)
            <input type="text" id="rr-file-id" autocomplete="off" /></label>
          <label>Version
            <input type="number" id="rr-version" min="0" step="1" autocomplete="off" /></label>
          <label>Key commitment (hex)
            <input type="text" id="rr-dek-commit" autocomplete="off" /></label>
          <label>Recovery wrap (base64)
            <textarea id="rr-wrap" rows="3" autocomplete="off"></textarea></label>
          <button type="submit" id="rr-verify-btn">Verify</button>
        </form>

        <button type="button" id="rr-restart">Start a new reconstruction</button>
      </section>`;

    (this.querySelector("#rr-prove-label") as HTMLElement).textContent = label;

    (this.querySelector("#rr-prove-form") as HTMLFormElement).addEventListener("submit", (e) => {
      e.preventDefault();
      void this.verify();
    });
    (this.querySelector("#rr-restart") as HTMLButtonElement).addEventListener("click", () => {
      void this.restart();
    });
  }

  private async verify() {
    if (this.proveBusy) return;
    const err = this.querySelector("#rr-prove-err") as HTMLElement;
    const success = this.querySelector("#rr-prove-success") as HTMLElement;
    const verifyBtn = this.querySelector("#rr-verify-btn") as HTMLButtonElement | null;
    err.textContent = "";

    const fileIdHex = (this.querySelector("#rr-file-id") as HTMLInputElement).value.trim();
    const versionRaw = (this.querySelector("#rr-version") as HTMLInputElement).value.trim();
    const dekCommitHex = (this.querySelector("#rr-dek-commit") as HTMLInputElement).value.trim();
    const wrapB64 = (this.querySelector("#rr-wrap") as HTMLTextAreaElement).value.trim();

    if (!fileIdHex || !versionRaw || !dekCommitHex || !wrapB64) {
      err.textContent = "Fill in the file id, version, key commitment, and recovery wrap.";
      return;
    }
    const version = Number(versionRaw);
    if (!Number.isInteger(version) || version < 0) {
      err.textContent = "Version must be a whole number.";
      return;
    }

    this.proveBusy = true;
    if (verifyBtn) verifyBtn.disabled = true;
    try {
      const resp = await serial(() =>
        call<ProveResponse>("prove_reconstructed_key", {
          req: {
            ceremony_handle: this.ceremonyHandle,
            file_id_hex: fileIdHex,
            version,
            dek_commit_hex: dekCommitHex,
            recovery_wrap_b64: wrapB64,
          },
        }),
      );
      if (resp.verified) {
        // ONLY path to the green success state — a real proof returned true.
        // <state-badge> renders a non-color-only (glyph + text) status; never
        // a bare color swatch (WCAG 1.4.1).
        this.proveVerified = true;
        success.replaceChildren();
        const badge = document.createElement("state-badge");
        badge.setAttribute("state", "verified");
        badge.setAttribute("label", "Recovery key reconstructed and verified");
        success.appendChild(badge);
        success.hidden = false;
        (this.querySelector("#rr-prove-form") as HTMLFormElement).hidden = true;
      } else {
        // A valid, SUCCESSFUL proof outcome that says "no" — not an error, and
        // never promoted to success. Stays on this step so the operator can
        // retry with a different wrap (e.g. from a different file/version).
        this.proveVerified = false;
        success.hidden = true;
        success.replaceChildren();
        err.textContent =
          "The reconstructed key did NOT open that wrap — the shares may be wrong or from a different key set.";
      }
    } catch (x) {
      this.proveVerified = false;
      success.hidden = true;
      success.replaceChildren();
      err.textContent = errMessage(x, "Could not run the verification.");
    } finally {
      this.proveBusy = false;
      if (verifyBtn) verifyBtn.disabled = false;
    }
  }

  private async restart() {
    // Explicit teardown of the whole ceremony (spec §8/§11): the backend wipes
    // every collected share and any reconstructed key, verified or not.
    try {
      await call<void>("discard_ceremony_session", {});
    } catch {
      // Best-effort — a failure here still resets local UI state below; the
      // component's disconnectedCallback (or the next screen visit) retries.
    }
    this.counts.reset();
    this.ceremonyHandle = "";
    this.proveVerified = false;
    this.addBusy = false;
    this.reconstructBusy = false;
    this.proveBusy = false;
    this.goToStep("add");
  }
}

// Strict-tsconfig-safe error narrowing (matches connect/bootstrap/pending/admin/
// recovery-split screens).
function errMessage(x: unknown, fallback: string): string {
  return (x && typeof x === "object" && "message" in x
    ? String((x as { message: unknown }).message)
    : null) ?? fallback;
}

// Extracts the backend's stable machine `code` off a rejected UiError (matches
// video-player.ts's `phaseCode` pattern). Falls back to an empty string, which
// `rejectionCopy` treats as "unknown" and falls through to `errMessage`.
function errCode(x: unknown): string {
  if (x && typeof x === "object" && "code" in x) {
    const c = (x as { code?: unknown }).code;
    if (typeof c === "string") return c;
  }
  return "";
}

customElements.define("recovery-reconstruct-screen", RecoveryReconstructScreen);
