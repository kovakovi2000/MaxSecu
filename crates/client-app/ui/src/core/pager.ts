import { pageWindow, type PageSlot } from "./paging.ts";

// The shared numbered-page control ("‹ Prev  1 2 … 7 8 9 … 42  Next ›") used by
// BOTH the feed and the bundle-member list, so the two can never drift apart in
// markup or accessibility semantics. The arithmetic lives in core/paging.ts
// (unit-tested); this module only turns it into DOM.
//
// The host <nav> is part of each component's STATIC innerHTML template (the a11y
// lint rejects `${}` interpolation into innerHTML); everything inside it is built
// with createElement/textContent and wired with addEventListener — never an
// inline handler.
//
// Accessibility: every control is a real <button type="button"> (keyboard- and
// AT-reachable by default), each carries an explicit aria-label ("Page 7", not a
// bare "7"), and the current page is marked aria-current="page". Prev/Next are
// disabled at the ends rather than silently no-op. After a re-render the focus
// hint restores focus to the equivalent control, so a keyboard user is never
// dumped back onto <body> by clicking through pages.

export type PagerFocus = "prev" | "next" | "current";

export interface PagerOptions {
  // 0-based current page.
  page: number;
  // Total page count. <= 1 hides the whole control.
  count: number;
  // Called with the 0-based target page and which control was used.
  onGo: (page: number, from: PagerFocus) => void;
  // Accessible name for the <nav> landmark (e.g. "Feed pages").
  label: string;
  // Which control to focus after this render (a re-render triggered by a click).
  focus?: PagerFocus;
}

export function renderPager(nav: HTMLElement, o: PagerOptions): void {
  nav.replaceChildren();
  nav.setAttribute("aria-label", o.label);
  if (o.count <= 1) {
    nav.hidden = true;
    return;
  }
  nav.hidden = false;

  const page = Math.min(Math.max(0, o.page), o.count - 1);
  let prevBtn: HTMLButtonElement | null = null;
  let nextBtn: HTMLButtonElement | null = null;
  let curBtn: HTMLButtonElement | null = null;

  const mk = (text: string, label: string, cls: string): HTMLButtonElement => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = cls;
    b.textContent = text;
    b.setAttribute("aria-label", label);
    return b;
  };

  prevBtn = mk("‹ Prev", "Previous page", "pager-btn pager-step");
  prevBtn.disabled = page === 0;
  prevBtn.addEventListener("click", () => o.onGo(page - 1, "prev"));
  nav.appendChild(prevBtn);

  for (const slot of pageWindow(page, o.count) as PageSlot[]) {
    if (slot === "gap") {
      const gap = document.createElement("span");
      gap.className = "pager-gap";
      gap.textContent = "…";
      gap.setAttribute("aria-hidden", "true");
      nav.appendChild(gap);
      continue;
    }
    const b = mk(String(slot + 1), `Page ${slot + 1}`, "pager-btn pager-num");
    if (slot === page) {
      b.setAttribute("aria-current", "page");
      b.classList.add("active");
      curBtn = b;
    }
    b.addEventListener("click", () => o.onGo(slot, "current"));
    nav.appendChild(b);
  }

  nextBtn = mk("Next ›", "Next page", "pager-btn pager-step");
  nextBtn.disabled = page === o.count - 1;
  nextBtn.addEventListener("click", () => o.onGo(page + 1, "next"));
  nav.appendChild(nextBtn);

  if (o.focus) {
    // Prefer the equivalent control; fall back to the current page button when
    // Prev/Next just became disabled at an end.
    const wanted =
      o.focus === "prev" && prevBtn && !prevBtn.disabled
        ? prevBtn
        : o.focus === "next" && nextBtn && !nextBtn.disabled
        ? nextBtn
        : curBtn;
    wanted?.focus();
  }
}
