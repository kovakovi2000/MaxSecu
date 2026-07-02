import { call } from "../core/rpc.ts";
import { settingsStore } from "../core/settings.ts";
import type { MemoryStats } from "../core/types.ts";
import { ramGaugeModel } from "../core/gauge.ts";
import type { GaugeModel } from "../core/gauge.ts";

// Standalone RAM-usage rainbow gauge for the shell header. A horizontal bar whose
// fill grows left→right proportional to process RSS ÷ the RAM cache cap the user set
// (the "RAM allocated for the app"). RSS is polled from the `memory_stats` backend
// command every 1500 ms; the denominator comes from the live settings store, so
// changing the cap on the Settings screen moves the bar immediately.
// `role="meter"` with aria-valuemin/max/now + aria-label (non-colour-only).
export class RamGauge extends HTMLElement {
  private _pollId: number | null = null;
  private _lastGauge: GaugeModel | null = null;
  private _lastUsed: number | null = null; // process RSS bytes from memory_stats
  private _unsubSettings: (() => void) | null = null;

  connectedCallback() {
    // Bar + a visible read-out: "<used> / <total> MB (<pct>%)". The bar is the
    // accessible meter (aria-*); the text is aria-hidden to avoid double SR output.
    this.innerHTML = `
      <div class="ram-gauge-wrap" hidden>
        <div class="ram-gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-label="RAM usage unavailable"><div class="ram-gauge-fill"></div></div>
        <span class="ram-gauge-text" aria-hidden="true"></span>
      </div>`;
    // Recompute whenever the cap changes (denominator is the cache cap).
    this._unsubSettings = settingsStore.subscribe(() => this._recompute());
    // Start polling (immediately + every 1500 ms).
    void this._poll();
    this._pollId = window.setInterval(() => { void this._poll(); }, 1500);
  }

  disconnectedCallback() {
    if (this._pollId !== null) {
      clearInterval(this._pollId);
      this._pollId = null;
    }
    if (this._unsubSettings) {
      this._unsubSettings();
      this._unsubSettings = null;
    }
  }

  private async _poll(): Promise<void> {
    try {
      const stats = await call<MemoryStats>("memory_stats");
      this._lastUsed = stats.used_bytes;
    } catch {
      // fail-soft: keep the previous value (or null on first poll failure)
    }
    this._recompute();
  }

  // Rebuild the gauge model from the last-seen RSS and the CURRENT cache cap, then
  // paint. Denominator = ram_cache_cap_mb (the RAM allocated for the app).
  private _recompute(): void {
    const capMb = settingsStore.get().performance.ram_cache_cap_mb;
    this._lastGauge = ramGaugeModel(this._lastUsed, capMb * 1024 * 1024);
    this._paint();
  }

  private _paint(): void {
    const wrap = this.querySelector<HTMLElement>(".ram-gauge-wrap");
    const bar = this.querySelector<HTMLElement>(".ram-gauge");
    if (!wrap || !bar) return;
    const g = this._lastGauge;
    if (!g || g.hidden) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    wrap.title = g.label;
    bar.setAttribute("aria-valuenow", String(g.pct));
    bar.setAttribute("aria-label", g.label);
    const fill = bar.querySelector<HTMLElement>(".ram-gauge-fill");
    if (fill) fill.style.width = `${g.fillFraction * 100}%`;
    const text = this.querySelector<HTMLElement>(".ram-gauge-text");
    if (text) text.textContent = g.label;
  }
}

customElements.define("ram-gauge", RamGauge);
