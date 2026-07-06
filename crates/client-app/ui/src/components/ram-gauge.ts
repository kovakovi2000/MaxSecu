import { call } from "../core/rpc.ts";
import { settingsStore } from "../core/settings.ts";
import type { CacheStats } from "../core/types.ts";
import { ramGaugeModel } from "../core/gauge.ts";

// Standalone cache gauges for the shell header: TWO stacked rainbow bars — one for
// the app-global Media cache (video fragments + full content), one for the
// Thumbnails cache (feed-card meta). Each row = a caption + the accessible meter
// bar (aria-*) + a read-out + its own Clear button. The live footprint is polled
// from the `cache_stats` backend command every 1500 ms, passing BOTH caps.
//
// In Memory mode each bar's denominator is its configured cap (fill can never
// exceed 100%). In Disk mode the on-disk size is measured against the startup
// free-space estimate (the % may exceed 100 while the bar stays clamped; the
// caller appends a " (disk)" suffix). Changing a cap on the Settings screen moves
// the matching bar immediately (the store subscription recomputes).
//
// Each bar is `role="meter"` with aria-valuemin/max/now + aria-label
// (non-colour-only). Clearing a cache only forces a re-fetch — no user data is
// lost — so the Clear buttons are confirm-free.

interface RowSpec {
  key: "media" | "thumb";
  caption: string;
  clearCmd: string;
  clearAria: string;
}

const ROWS: RowSpec[] = [
  { key: "media", caption: "Media", clearCmd: "clear_media_cache", clearAria: "Clear media cache" },
  { key: "thumb", caption: "Thumbnails", clearCmd: "clear_thumb_cache", clearAria: "Clear thumbnails cache" },
];

export class RamGauge extends HTMLElement {
  private _pollId: number | null = null;
  private _stats: CacheStats | null = null;
  private _unsubSettings: (() => void) | null = null;

  connectedCallback() {
    this.innerHTML = `
      <div class="ram-gauge-rows">
        ${ROWS.map((r) => `
          <div class="ram-gauge-row" data-cache="${r.key}" hidden>
            <span class="ram-gauge-cap">${r.caption}</span>
            <div class="ram-gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-label="${r.caption} cache usage unavailable"><div class="ram-gauge-fill"></div></div>
            <span class="ram-gauge-text" aria-hidden="true"></span>
            <button type="button" class="cache-clear" data-clear="${r.key}" aria-label="${r.clearAria}">Clear</button>
          </div>`).join("")}
      </div>`;
    for (const r of ROWS) {
      const btn = this.querySelector<HTMLButtonElement>(`.cache-clear[data-clear="${r.key}"]`);
      btn?.addEventListener("click", () => { void this._clear(r.clearCmd); });
    }
    // Recompute whenever a cap changes (the caps are the Memory-mode denominators).
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
      // Pass BOTH current caps so the backend reconciles each open cache to the
      // same value the matching gauge divides by (Tauri maps the camelCase arg
      // names to `media_cap_bytes` / `thumb_cap_bytes`).
      const perf = settingsStore.get().performance;
      const mediaCapBytes = perf.media_cache_cap_mb * 1024 * 1024;
      const thumbCapBytes = perf.thumb_cache_cap_mb * 1024 * 1024;
      this._stats = await call<CacheStats>("cache_stats", { mediaCapBytes, thumbCapBytes });
    } catch {
      // fail-soft: keep the previous stats (or null on first poll failure)
    }
    this._recompute();
  }

  private async _clear(cmd: string): Promise<void> {
    try {
      await call<void>(cmd);
    } catch {
      // fail-soft: a clear failure just leaves the cache as-is
    }
    // Immediately re-poll so the just-cleared bar drops to 0.
    await this._poll();
  }

  private _recompute(): void {
    const perf = settingsStore.get().performance;
    const stats = this._stats;
    this._paintRow("media", stats ? stats.media_used : null, perf.media_cache_cap_mb, "Media", stats);
    this._paintRow("thumb", stats ? stats.thumb_used : null, perf.thumb_cache_cap_mb, "Thumbnails", stats);
  }

  private _paintRow(
    key: "media" | "thumb",
    used: number | null,
    capMb: number,
    caption: string,
    stats: CacheStats | null,
  ): void {
    const row = this.querySelector<HTMLElement>(`.ram-gauge-row[data-cache="${key}"]`);
    if (!row) return;
    const disk = !!stats && stats.disk_mode;
    let g = disk
      ? ramGaugeModel(used, stats!.disk_free_estimate, { disk: true })
      : ramGaugeModel(used, capMb * 1024 * 1024);
    if (disk && !g.hidden) g = { ...g, label: `${g.label} (disk)` };
    if (g.hidden) {
      row.hidden = true;
      return;
    }
    row.hidden = false;
    const full = `${caption} ${g.label}`;
    row.title = full;
    const bar = row.querySelector<HTMLElement>(".ram-gauge");
    if (bar) {
      // Keep aria-valuenow within [0,100] (the meter's declared range) via the
      // clamped fill, even when the Disk-mode label reports > 100%.
      bar.setAttribute("aria-valuenow", String(Math.round(g.fillFraction * 100)));
      bar.setAttribute("aria-label", full);
      const fill = bar.querySelector<HTMLElement>(".ram-gauge-fill");
      if (fill) fill.style.width = `${g.fillFraction * 100}%`;
    }
    const text = row.querySelector<HTMLElement>(".ram-gauge-text");
    if (text) text.textContent = g.label;
  }
}

customElements.define("ram-gauge", RamGauge);
