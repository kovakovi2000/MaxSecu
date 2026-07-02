// Pure model for the quick-settings RAM-usage rainbow gauge.
// Keeps all math testable in plain Node (no DOM, no Tauri API).

export interface GaugeModel {
  pct: number;           // 0-100, for aria-valuenow
  fillFraction: number;  // 0.0-1.0, for bar fill height
  label: string;         // "<usedMB> / <budgetMB> MB (<pct>%)"
  hidden: boolean;       // true when data is unavailable or budget <= 0
}

/**
 * Derive the gauge display state from raw memory figures.
 * - hidden when usedBytes is null OR budgetBytes <= 0
 * - fillFraction = clamp(usedBytes / budgetBytes, 0, 1)
 * - label = "<usedMB> / <budgetMB> MB (<pct>%)" (whole MB, rounded)
 */
export function ramGaugeModel(
  usedBytes: number | null,
  budgetBytes: number
): GaugeModel {
  if (usedBytes == null || budgetBytes <= 0) {
    return { pct: 0, fillFraction: 0, label: "", hidden: true };
  }
  const fillFraction = Math.min(Math.max(usedBytes / budgetBytes, 0), 1);
  const pct = Math.round(fillFraction * 100);
  const usedMB = Math.round(usedBytes / (1024 * 1024));
  const budgetMB = Math.round(budgetBytes / (1024 * 1024));
  const label = `${usedMB} / ${budgetMB} MB (${pct}%)`;
  return { pct, fillFraction, label, hidden: false };
}
