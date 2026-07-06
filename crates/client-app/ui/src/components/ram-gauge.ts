import { call } from "../core/rpc.ts";
import { settingsStore } from "../core/settings.ts";
import type { CacheStats } from "../core/types.ts";
import { ramGaugeModel } from "../core/gauge.ts";
import type { GaugeModel } from "../core/gauge.ts";

// Standalone RAM-cache rainbow gauge for the shell header. A horizontal bar whose
// fill grows left→right proportional to the in-RAM fragment cache's actual fill ÷
// the RAM cache cap the user set. The numerator is the live cache footprint polled
// from the `cache_stats` backend command every 1500 ms (0 when nothing is playing
// or the Disk backend is selected — the cache is per-play and LRU-evicts at the
// cap, so it visibly fills and drops during playback and can never exceed 100%);
// the denominator is the live settings cap, so changing the cap on the Settings
// screen moves the bar immediately.
// `role="meter"` with aria-valuemin/max/now + aria-label (non-colour-only).
export class RamGauge extends HTMLElement {
  private _pollId: number | null = null;
  private _lastGauge: GaugeModel | null = null;
  private _lastUsed: number | null = null; // in-RAM cache bytes from cache_stats
  private _unsubSettings: (() => void) | null = null;

  connectedCallback() {
    // Bar + a visible read-out: "<used> / <total> MB (<pct>%)". The bar is the
    // accessible meter (aria-*); the text is aria-hidden to avoid double SR output.
    this.innerHTML = `
      <div class="ram-gauge-wrap" hidden>
        <div class="ram-gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-label="RAM cache usage unavailable"><div class="ram-gauge-fill"></div></div>
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
      // Pass the CURRENT cap so the backend reconciles open caches to the same value
      // the gauge divides by (lowering the cap mid-playback then evicts down to it).
      const capBytes = settingsStore.get().performance.ram_cache_cap_mb * 1024 * 1024;
      const stats = await call<CacheStats>("cache_stats", { capBytes });
      this._lastUsed = stats.used_bytes;
    } catch {
      // fail-soft: keep the previous value (or null on first poll failure)
    }
    this._recompute();
  }

  // Rebuild the gauge model from the last-seen in-RAM cache fill and the CURRENT
  // cache cap, then paint. Denominator = ram_cache_cap_mb (the cache budget).
  private _recompute(): void {
    const capMb = settingsStore.get().performance.ram_cache_cap_mb;
    const g = ramGaugeModel(this._lastUsed, capMb * 1024 * 1024);
    // Prefix the read-out/label so it reads as the cache gauge, not whole-app RAM.
    this._lastGauge = g.hidden ? g : { ...g, label: `Cache ${g.label}` };
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
