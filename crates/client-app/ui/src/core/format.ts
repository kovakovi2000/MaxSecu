import type { PendingUploadView } from "./types.ts";

const GiB = 1024 * 1024 * 1024;
const MiB = 1024 * 1024;
const KiB = 1024;

// Formats a rolling bytes-per-second rate for display in the upload tray.
// Returns "" for 0, negative, NaN, or Infinity (nothing to show yet / image/blog
// uploads that don't emit a rate). Otherwise returns e.g. "1.5 MB/s", "512 KB/s",
// "2.1 GB/s". Thresholds are binary (1024-based); labels use the common SI form.
export function formatRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return "";
  if (bytesPerSec >= GiB) {
    return `${(bytesPerSec / GiB).toFixed(1)} GB/s`;
  }
  if (bytesPerSec >= MiB) {
    return `${(bytesPerSec / MiB).toFixed(1)} MB/s`;
  }
  return `${Math.round(bytesPerSec / KiB)} KB/s`;
}

// Pure view-model helper: formats the resume-prompt text for a pending upload.
// Kept pure so it can be unit-tested without a DOM.
export function pendingPromptText(p: PendingUploadView): string {
  return `Resume upload of "${p.title}"? (${p.progress}/${p.total} chunks)`;
}
