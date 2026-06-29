import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import type { UploadMsg } from "../core/types.ts";
import "./progress-meter.ts";
import "./state-badge.ts";

// Active-uploads tray (spec §5/§6): subscribes to EVT_UPLOAD and shows per-job
// progress (meter + %), phase (non-color-only badge), and a Retry on failure.
// A done row auto-clears. ARIA: a labelled region with an aria-live status.
export class UploadTray extends HTMLElement {
  private unlisten: (() => void) | null = null;
  private starts = new Map<string, number>(); // job_id -> first-seen ms (for ETA)

  async connectedCallback() {
    this.innerHTML = `
      <section aria-label="Active uploads">
        <ul id="ut-list" aria-live="polite"></ul>
      </section>`;
    this.unlisten = await on<UploadMsg>("maxsecu://upload-state", (m) => this.onMsg(m));
  }

  disconnectedCallback() {
    this.unlisten?.();
  }

  private row(jobId: string): HTMLLIElement {
    const list = this.querySelector("#ut-list") as HTMLUListElement;
    let li = list.querySelector<HTMLLIElement>(`li[data-job="${cssEscape(jobId)}"]`);
    if (!li) {
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
      meter.setAttribute("detail", this.eta(m.job_id, m.done, m.total));
    } else if (m.phase === "done") {
      meter.hidden = true;
      this.starts.delete(m.job_id);
      this.clearRowLater(m.job_id);
    } else if (m.phase === "failed") {
      meter.hidden = true;
      this.starts.delete(m.job_id);
      badge.setAttribute("label", `Failed: ${m.code}`);
      this.addRetry(li, m.job_id);
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
        await serial(() => call<string>("confirm_upload", { req: { job_id: jobId } }));
        btn.remove(); // success drives a fresh `done` event which clears the row
      } catch {
        btn.disabled = false; // a fresh `failed` event will refresh the label
      }
    });
    li.appendChild(btn);
  }

  private clearRowLater(jobId: string) {
    window.setTimeout(() => {
      const li = this.querySelector(`li[data-job="${cssEscape(jobId)}"]`);
      li?.remove();
    }, 4000);
  }
}

function cssEscape(s: string): string {
  // job_id is server-side hex, but escape defensively for the attribute selector.
  return s.replace(/["\\\]]/g, "\\$&");
}

customElements.define("upload-tray", UploadTray);
