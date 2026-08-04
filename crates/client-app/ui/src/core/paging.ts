// Numbered-page arithmetic for the "«  1 2 … 7 8 9 … 42  »" pagers (feed + bundle
// members). PURE — no DOM, no Tauri — so it unit-tests in plain Node
// (core/paging.test.ts). The components own only the rendering; every off-by-one
// lives here.
//
// Page indexes are 0-BASED throughout (they multiply straight into the wire
// `offset`); only the rendered label is 1-based. A "gap" is the ellipsis slot.

export type PageSlot = number | "gap";

// How many pages `total` items make at `limit` per page. 0 items ⇒ 0 pages.
export function pageCount(total: number, limit: number): number {
  if (!Number.isFinite(total) || total <= 0) return 0;
  if (!Number.isFinite(limit) || limit <= 0) return 0;
  return Math.ceil(total / limit);
}

// Force a page index into [0, count-1]. An empty listing clamps to page 0.
export function clampPage(page: number, count: number): number {
  if (!Number.isFinite(page) || page < 0) return 0;
  if (count <= 0) return 0;
  return Math.min(Math.floor(page), count - 1);
}

// The wire `offset` for a page. Never negative.
export function offsetFor(page: number, limit: number): number {
  if (!Number.isFinite(page) || page <= 0) return 0;
  if (!Number.isFinite(limit) || limit <= 0) return 0;
  return Math.floor(page) * Math.floor(limit);
}

// The 1-based inclusive item range shown on `page`, or null when there is
// nothing to show. `to` is clamped to `total` on the last (partial) page.
export function pageRange(
  page: number,
  limit: number,
  total: number,
): { from: number; to: number } | null {
  if (total <= 0 || limit <= 0) return null;
  const from = offsetFor(page, limit) + 1;
  if (from > total) return null;
  return { from, to: Math.min(total, from + Math.floor(limit) - 1) };
}

// The honest status line for a paginating server: "Showing 51-100 of 137."
// A single-page listing still reports the true total, so the count never lies.
export function showingLabel(page: number, limit: number, total: number): string {
  if (total <= 0) return "No content yet.";
  const r = pageRange(page, limit, total);
  if (!r) return `No items on this page (of ${total}).`;
  return `Showing ${r.from}-${r.to} of ${total}.`;
}

// The visible page-number window for the numbered control.
//
// * `count <= maxNumbers` ⇒ every page, no gaps.
// * otherwise ⇒ always the first and last page, a contiguous run around
//   `page`, and a "gap" wherever pages were skipped. A gap that would hide
//   exactly ONE page renders that page instead (an ellipsis standing for a
//   single number is just noise).
export function pageWindow(page: number, count: number, maxNumbers = 7): PageSlot[] {
  if (count <= 0) return [];
  const cur = clampPage(page, count);
  const cap = Math.max(3, Math.floor(maxNumbers));
  if (count <= cap) return Array.from({ length: count }, (_, i) => i);

  // First + last are always shown; the rest of the budget is a run around `cur`.
  const inner = cap - 2;
  let start = cur - Math.floor((inner - 1) / 2);
  let end = start + inner - 1;
  if (start < 1) {
    start = 1;
    end = start + inner - 1;
  }
  if (end > count - 2) {
    end = count - 2;
    start = Math.max(1, end - inner + 1);
  }

  const out: PageSlot[] = [0];
  if (start === 2) out.push(1); // a one-page gap is worse than the page itself
  else if (start > 2) out.push("gap");
  for (let i = start; i <= end; i++) out.push(i);
  if (end === count - 3) out.push(count - 2);
  else if (end < count - 3) out.push("gap");
  out.push(count - 1);
  return out;
}

// Whether a numbered pager is worth rendering at all. `total === null` is the
// old-server signal ("this server does not paginate") and MUST render nothing.
export function shouldShowPager(total: number | null, limit: number): boolean {
  if (total === null) return false;
  return pageCount(total, limit) > 1;
}
