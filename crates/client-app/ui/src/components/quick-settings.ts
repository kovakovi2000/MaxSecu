import { call } from "../core/rpc.ts";
import { settingsStore, updateSettings } from "../core/settings.ts";
import type { Settings, RamLimits, MemoryStats } from "../core/types.ts";
import { ramGaugeModel } from "../core/gauge.ts";
import type { GaugeModel } from "../core/gauge.ts";

// ⚡ Quick-settings popover (spec §4): reduced to the two most-used controls —
// Theme toggle + RAM cache cap (slider bound to a number input, both clamped to
// the live `ram_limits`). Reads/writes the SHARED settings store so it stays in
// sync with the full Settings screen and applies live. Accessible: aria-expanded/
// -controls on the trigger, Esc-dismiss + focus return, all controls labelled.
//
// Left-edge rainbow gauge: a thin vertical bar pinned to the left edge of the
// popover that fills bottom→top proportional to process RSS / RAM budget. Polls
// the `memory_stats` backend command every 1500 ms (interval cleared on disconnect).
// `role="meter"` with aria-valuemin/max/now + aria-label (non-colour-only).
export class QuickSettings extends HTMLElement {
  private open = false;
  private limits: RamLimits | null = null;
  private _ramPollId: number | null = null;
  private _lastGauge: GaugeModel | null = null;

  connectedCallback() {
    this.innerHTML = `
      <div class="qs">
        <button id="qs-btn" aria-expanded="false" aria-controls="qs-pop" aria-haspopup="true" title="Quick settings">⚡</button>
        <div id="qs-pop" role="group" aria-label="Quick settings" hidden></div>
      </div>`;
    const btn = this.querySelector("#qs-btn") as HTMLButtonElement;
    btn.addEventListener("click", () => this.toggle());
    this.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Escape" && this.open) {
        this.close();
        btn.focus();
      }
    });
    // Start RAM gauge poll (immediately + every 1500 ms).
    void this._pollRam();
    this._ramPollId = window.setInterval(() => { void this._pollRam(); }, 1500);
  }

  disconnectedCallback() {
    if (this._ramPollId !== null) {
      clearInterval(this._ramPollId);
      this._ramPollId = null;
    }
  }

  private async _pollRam(): Promise<void> {
    try {
      const stats = await call<MemoryStats>("memory_stats");
      this._lastGauge = ramGaugeModel(stats.used_bytes, stats.budget_bytes);
    } catch {
      // fail-soft: keep the previous value (or null on first poll failure)
    }
    this._updateRamBar();
  }

  private _updateRamBar(): void {
    const bar = this.querySelector<HTMLElement>(".qs-ram-bar");
    if (!bar) return; // panel is closed, nothing to update
    const g = this._lastGauge;
    if (!g || g.hidden) {
      bar.hidden = true;
      return;
    }
    bar.hidden = false;
    bar.setAttribute("aria-valuenow", String(g.pct));
    bar.setAttribute("aria-label", g.label);
    const fill = bar.querySelector<HTMLElement>(".qs-ram-fill");
    if (fill) fill.style.height = `${g.fillFraction * 100}%`;
  }

  private async toggle() {
    if (this.open) { this.close(); return; }
    if (!this.limits) {
      try { this.limits = await call<RamLimits>("ram_limits"); } catch { this.limits = { default_mb: 256, min_mb: 64, max_mb: 4096 }; }
    }
    this.renderPopover();
    this.open = true;
    const pop = this.querySelector("#qs-pop") as HTMLElement;
    const btn = this.querySelector("#qs-btn") as HTMLButtonElement;
    pop.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    (pop.querySelector("input,select,button") as HTMLElement | null)?.focus();
  }
  private close() {
    this.open = false;
    (this.querySelector("#qs-pop") as HTMLElement).hidden = true;
    (this.querySelector("#qs-btn") as HTMLButtonElement).setAttribute("aria-expanded", "false");
  }

  private renderPopover() {
    const s = settingsStore.get();
    const limits = this.limits!;
    const pop = this.querySelector("#qs-pop") as HTMLElement;
    pop.replaceChildren();

    // --- Rainbow RAM gauge bar (position: absolute, left edge of panel) ---
    const g = this._lastGauge;
    const bar = document.createElement("div");
    bar.className = "qs-ram-bar";
    bar.setAttribute("role", "meter");
    bar.setAttribute("aria-valuemin", "0");
    bar.setAttribute("aria-valuemax", "100");
    if (g && !g.hidden) {
      bar.setAttribute("aria-valuenow", String(g.pct));
      bar.setAttribute("aria-label", g.label);
    } else {
      bar.setAttribute("aria-valuenow", "0");
      bar.setAttribute("aria-label", "RAM usage unavailable");
      bar.hidden = true;
    }
    const fill = document.createElement("div");
    fill.className = "qs-ram-fill";
    if (g && !g.hidden) fill.style.height = `${g.fillFraction * 100}%`;
    bar.appendChild(fill);
    pop.appendChild(bar);

    // Theme toggle.
    const themeLabel = document.createElement("label");
    themeLabel.textContent = "Theme ";
    const themeSel = document.createElement("select");
    for (const opt of ["dark", "light"] as const) {
      const o = document.createElement("option");
      o.value = opt; o.textContent = opt;
      if (s.appearance.theme === opt) o.selected = true;
      themeSel.appendChild(o);
    }
    themeSel.addEventListener("change", () => {
      const theme = themeSel.value === "light" ? "light" : "dark";
      void this.save({ appearance: { theme } });
    });
    themeLabel.appendChild(themeSel);
    pop.appendChild(themeLabel);

    // RAM cap: range + number, both clamped to [min,max].
    const ramLabel = document.createElement("label");
    ramLabel.textContent = "RAM cache cap (MB) ";
    const range = document.createElement("input");
    range.type = "range";
    range.min = String(limits.min_mb); range.max = String(limits.max_mb); range.step = "1";
    range.value = String(s.performance.ram_cache_cap_mb);
    range.setAttribute("aria-label", "RAM cache cap (MB)");
    const num = document.createElement("input");
    num.type = "number";
    num.min = String(limits.min_mb); num.max = String(limits.max_mb); num.step = "1";
    num.value = String(s.performance.ram_cache_cap_mb);
    num.setAttribute("aria-label", "RAM cache cap (MB), exact");
    const syncFrom = (v: number) => {
      const clamped = Math.min(Math.max(v, limits.min_mb), limits.max_mb);
      range.value = String(clamped); num.value = String(clamped);
      void this.save({ performance: { ram_cache_cap_mb: clamped } });
    };
    range.addEventListener("change", () => syncFrom(Number(range.value)));
    num.addEventListener("change", () => syncFrom(Number(num.value)));
    ramLabel.append(range, num);
    pop.appendChild(ramLabel);

    pop.appendChild(this.status());
  }

  private status(): HTMLParagraphElement {
    const p = document.createElement("p");
    p.id = "qs-status"; p.setAttribute("role", "status"); p.setAttribute("aria-live", "polite");
    return p;
  }

  private async save(patch: Partial<Settings>) {
    const status = this.querySelector("#qs-status");
    try {
      await updateSettings(patch);
      if (status) status.textContent = "Saved.";
    } catch (x) {
      if (status) status.textContent = errMsg(x, "Could not save.");
    }
  }
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("quick-settings", QuickSettings);
