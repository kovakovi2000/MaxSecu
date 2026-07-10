import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { toast } from "../core/toast.ts";
import { formatRate, pendingPromptText } from "../core/format.ts";
import type { ConnState, PendingUploadView, UploadMsg } from "../core/types.ts";
import "./progress-meter.ts";
import "./state-badge.ts";

// Active-uploads tray (spec §5/§6): subscribes to EVT_UPLOAD and shows per-job
// progress (meter + %), phase (non-color-only badge), and a Retry on failure.
// A done row auto-clears. Also shows resume prompts for interrupted uploads on
// each "connected" signal. ARIA: a labelled region with aria-live status.
export class UploadTray extends HTMLElement {
  private unlisteners: Array<() => void> = [];
  private starts = new Map<string, number>(); // job_id -> first-seen ms (for ETA)
  private pendingList: HTMLUListElement | null = null;

  async connectedCallback() {
    this.innerHTML = `
      <section class="upload-tray" aria-label="Active uploads" hidden>
        <h2 class="ut-title">Uploads</h2>
        <ul id="ut-pending" aria-live="polite" aria-label="Interrupted uploads"></ul>
        <ul id="ut-list" aria-live="polite"></ul>
      </section>`;
    this.pendingList = this.querySelector("#ut-pending") as HTMLUListElement;

    const ul = await on<UploadMsg>("maxsecu://upload-state", (m) => this.onMsg(m));
    this.unlisteners.push(ul);

    // Best-effort on mount (will fail if not yet authed — silently ignored).
    void this.checkPending();

    // Re-check on each "connected" signal to catch post-auth resumables.
    const cl = await on<ConnState>("maxsecu://connection-state", (s) => {
      if (s.state === "connected") void this.checkPending();
    });
    this.unlisteners.push(cl);
  }

  disconnectedCallback() {
    for (const ul of this.unlisteners) ul();
    this.unlisteners = [];
  }

  private row(jobId: string): HTMLLIElement {
    const list = this.querySelector("#ut-list") as HTMLUListElement;
    let li = list.querySelector<HTMLLIElement>(`li[data-job="${cssEscape(jobId)}"]`);
    if (!li) {
      (this.querySelector(".upload-tray") as HTMLElement | null)?.removeAttribute("hidden");
      li = document.createElement("li");
      li.setAttribute("data-job", jobId);
      const badge = document.createElement("state-badge");
      badge.className = "ut-badge";
      const meter = document.createElement("progress-meter");
      meter.className = "ut-meter";
      li.append(badge, meter);
      list.appendChild(li);
    }
    return li;
  }

  private onMsg(m: UploadMsg) {
    const li = this.row(m.job_id);
    const badge = li.querySelector("state-badge") as HTMLElement;
    const meter = li.querySelector("progress-meter") as HTMLElement;
    const phaseLabel: Record<string, string> = {
      encrypting: "Encrypting…", staging: "Starting…", uploading: "Uploading…",
      finalizing: "Finalizing…", done: "Uploaded", failed: "Failed",
    };
    badge.setAttribute("state", m.phase === "done" ? "ready" : m.phase === "failed" ? "failed" : "uploading");
    badge.setAttribute("label", phaseLabel[m.phase] ?? m.phase);

    if (m.phase === "uploading") {
      if (!this.starts.has(m.job_id)) this.starts.set(m.job_id, Date.now());
      meter.hidden = false;
      meter.setAttribute("value", String(m.done));
      meter.setAttribute("max", String(m.total));
      // Build detail: ETA + MB/s rate (rate omitted when bytes_per_s is 0).
      const eta = this.eta(m.job_id, m.done, m.total);
      const rate = formatRate(m.bytes_per_s);
      const detail = [eta, rate].filter(Boolean).join(" · ");
      meter.setAttribute("detail", detail);
    } else if (m.phase === "done") {
      meter.hidden = true;
      this.starts.delete(m.job_id);
      toast("success", "Upload complete.");
      this.clearRowLater(m.job_id);
    } else if (m.phase === "failed") {
      meter.hidden = true;
      this.starts.delete(m.job_id);
      badge.setAttribute("label", `Failed: ${m.code}`);
      this.addRetry(li, m.job_id);
      this.addDismiss(li);
    }
  }

  private eta(jobId: string, done: number, total: number): string {
    const started = this.starts.get(jobId);
    if (!started || done <= 0 || total <= 0) return "";
    const elapsed = (Date.now() - started) / 1000;
    const rate = done / Math.max(elapsed, 0.001); // chunks/sec
    const remaining = Math.max(total - done, 0);
    const secs = rate > 0 ? Math.round(remaining / rate) : 0;
    return secs > 0 ? `~${secs}s left` : "";
  }

  private addRetry(li: HTMLLIElement, jobId: string) {
    if (li.querySelector("button.ut-retry")) return;
    const btn = document.createElement("button");
    btn.className = "ut-retry";
    btn.textContent = "Retry";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        // `retry_confirm` routes to the right registry (single upload vs bundle);
        // the tray only knows the job_id, not which kind it is.
        await serial(() => call<string>("retry_confirm", { req: { job_id: jobId } }));
        btn.remove(); // success drives a fresh `done` event which clears the row
      } catch {
        btn.disabled = false; // a fresh `failed` event will refresh the label
      }
    });
    li.appendChild(btn);
  }

  private addDismiss(li: HTMLLIElement) {
    if (li.querySelector("button.ut-dismiss")) return;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ut-dismiss";
    btn.textContent = "Dismiss";
    // The `failed` event carries only job_id + code (no file_id_hex), so there
    // is no reliable id to reach the backend `dismiss_pending_upload` with — a
    // failed active job is not a retained "pending" upload. So Dismiss just
    // clears the stuck row locally so the user is never left with an
    // un-removable failure.
    btn.setAttribute("aria-label", "Dismiss failed upload");
    btn.addEventListener("click", () => {
      li.remove();
      this.maybeHideTray();
    });
    li.appendChild(btn);
  }

  private clearRowLater(jobId: string) {
    window.setTimeout(() => {
      const li = this.querySelector(`li[data-job="${cssEscape(jobId)}"]`);
      li?.remove();
      this.maybeHideTray();
    }, 4000);
  }

  // --- Pending (interrupted) upload resume prompts ---

  private async checkPending() {
    try {
      const pending = await call<PendingUploadView[]>("list_pending_uploads");
      for (const p of pending) this.renderPendingPrompt(p);
    } catch {
      // Best-effort: silently tolerate errors (e.g. not yet authed on first call).
    }
  }

  private renderPendingPrompt(p: PendingUploadView) {
    if (!this.pendingList) return;
    // Guard against duplicates if list_pending_uploads fires multiple times.
    if (this.pendingList.querySelector(`[data-pending-id="${cssEscape(p.file_id_hex)}"]`)) return;

    (this.querySelector(".upload-tray") as HTMLElement | null)?.removeAttribute("hidden");

    const li = document.createElement("li");
    li.className = "ut-pending-prompt";
    li.setAttribute("data-pending-id", p.file_id_hex);

    const text = document.createElement("span");
    text.textContent = pendingPromptText(p);

    const resumeBtn = document.createElement("button");
    resumeBtn.className = "ut-resume";
    resumeBtn.textContent = "Resume";
    resumeBtn.setAttribute("aria-label", `Resume upload of ${p.title}`);

    const discardBtn = document.createElement("button");
    discardBtn.className = "ut-discard";
    discardBtn.textContent = "Discard";
    discardBtn.setAttribute("aria-label", `Discard upload of ${p.title}`);

    resumeBtn.addEventListener("click", async () => {
      resumeBtn.disabled = true;
      discardBtn.disabled = true;
      try {
        // resume_upload re-runs the upload pipeline and emits normal upload-state
        // events; the active-uploads list takes over from here.
        await serial(() => call<void>("resume_upload", { fileIdHex: p.file_id_hex }));
        li.remove();
        this.maybeHideTray();
      } catch {
        resumeBtn.disabled = false;
        discardBtn.disabled = false;
      }
    });

    discardBtn.addEventListener("click", async () => {
      resumeBtn.disabled = true;
      discardBtn.disabled = true;
      try {
        await call<void>("dismiss_pending_upload", { fileIdHex: p.file_id_hex });
      } catch {
        // Best-effort: remove the prompt regardless so the user is not stuck.
      }
      li.remove();
      this.maybeHideTray();
    });

    li.append(text, resumeBtn, discardBtn);
    this.pendingList.appendChild(li);
  }

  private maybeHideTray() {
    const list = this.querySelector("#ut-list") as HTMLUListElement | null;
    if (
      (!list || list.children.length === 0) &&
      (!this.pendingList || this.pendingList.children.length === 0)
    ) {
      (this.querySelector(".upload-tray") as HTMLElement | null)?.setAttribute("hidden", "");
    }
  }
}

function cssEscape(s: string): string {
  // job_id / file_id_hex are server-side hex, but escape defensively for the
  // attribute selector.
  return s.replace(/["\\\]]/g, "\\$&");
}

customElements.define("upload-tray", UploadTray);
