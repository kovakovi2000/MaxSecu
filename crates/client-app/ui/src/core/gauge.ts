// Pure model for the header cache-usage rainbow gauge.
// Keeps all math testable in plain Node (no DOM, no Tauri API).

export interface GaugeModel {
  pct: number;           // 0-100 in Memory mode; may exceed 100 in Disk mode (label only)
  fillFraction: number;  // 0.0-1.0, for bar fill width (always clamped — bar never overflows)
  label: string;         // "<usedMB> / <budgetMB> MB (<pct>%)" (or "<usedMB> MB" when free unknown)
  hidden: boolean;       // true when data is unavailable (or, in Memory mode, budget <= 0)
}

export interface GaugeOptions {
  // Disk mode: the on-disk cache size measured against the startup free-space
  // estimate (which may be exceeded → % uncapped). Default (omitted) = Memory
  // mode: the in-RAM fill measured against the configured cap (% never > 100).
  disk?: boolean;
}

/**
 * Derive the gauge display state from raw cache figures.
 *
 * Memory mode (default): fillFraction = clamp(used/budget, 0, 1),
 *   pct = round(fillFraction*100) — always ≤ 100. Hidden when used is null or
 *   budget <= 0. label = "<usedMB> / <budgetMB> MB (<pct>%)".
 *
 * Disk mode ({ disk: true }):
 *   - known free space (budget > 0): pct = round(used/budget*100) UNCAPPED (may
 *     exceed 100), but fillFraction = clamp(used/budget, 0, 1) so the bar never
 *     overflows its track. label = "<usedMB> / <freeMB> MB (<pct>%)".
 *   - unknown free space (budget <= 0, probe failed): raw size only, NOT hidden.
 *     label = "<usedMB> MB", pct = 0, fillFraction = 0.
 *
 * The "(disk)" suffix on the label is added by the caller, not here.
 */
export function ramGaugeModel(
  usedBytes: number | null,
  budgetBytes: number,
  opts: GaugeOptions = {}
): GaugeModel {
  if (usedBytes == null) {
    return { pct: 0, fillFraction: 0, label: "", hidden: true };
  }
  const usedMB = Math.round(usedBytes / (1024 * 1024));
  if (opts.disk) {
    if (budgetBytes <= 0) {
      // Free-space probe failed: fall back to showing the raw on-disk size.
      return { pct: 0, fillFraction: 0, label: `${usedMB} MB`, hidden: false };
    }
    const fillFraction = Math.min(Math.max(usedBytes / budgetBytes, 0), 1);
    const pct = Math.round((usedBytes / budgetBytes) * 100); // uncapped — may exceed 100
    const freeMB = Math.round(budgetBytes / (1024 * 1024));
    return { pct, fillFraction, label: `${usedMB} / ${freeMB} MB (${pct}%)`, hidden: false };
  }
  // Memory mode.
  if (budgetBytes <= 0) {
    return { pct: 0, fillFraction: 0, label: "", hidden: true };
  }
  const fillFraction = Math.min(Math.max(usedBytes / budgetBytes, 0), 1);
  const pct = Math.round(fillFraction * 100);
  const budgetMB = Math.round(budgetBytes / (1024 * 1024));
  const label = `${usedMB} / ${budgetMB} MB (${pct}%)`;
  return { pct, fillFraction, label, hidden: false };
}
