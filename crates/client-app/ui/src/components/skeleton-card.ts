// A shimmer placeholder used while the feed/viewer load (spec §5/§6). Pure
// presentational; the shimmer is driven by motion tokens in styles.css and is
// stilled under reduced-motion. aria-hidden so screen readers ignore the
// placeholder (the live status region announces "Loading…").
export class SkeletonCard extends HTMLElement {
  connectedCallback() {
    this.setAttribute("aria-hidden", "true");
    this.innerHTML = `
      <div class="skeleton-card">
        <div class="sk sk-thumb"></div>
        <div class="sk sk-line sk-line-lg"></div>
        <div class="sk sk-line sk-line-sm"></div>
      </div>`;
  }
}
customElements.define("skeleton-card", SkeletonCard);
