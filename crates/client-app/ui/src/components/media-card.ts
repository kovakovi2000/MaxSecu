import { call } from "../core/rpc.ts";
import { decodePool } from "../core/pool.ts";
import { decideCardOutcome } from "../core/card-retry.ts";
import { cardHref, countsLabel } from "../core/card-view.ts";
import { downloadPost } from "../core/download.ts";
import type { Card } from "../core/types.ts";
import "./state-badge.ts";

// One feed item. Decrypts itself (title/tags/thumbnail) via decrypt_card — routed
// through the shared `decodePool` (core/pool.ts) so cards decode CONCURRENTLY, up
// to `feed_concurrency`. This reuses the backend authed-connection pool (Task 7.0),
// which is what makes concurrent decrypt_card safe (no per-call reauth once warm).
// The whole card gets one accessible transparent overlay link to the viewer; no
// separate "View" button or visible link chrome is needed.
export class MediaCard extends HTMLElement {
  // How many times this card's decrypt has been re-attempted after a benign
  // queue-flush cancellation (see core/card-retry.ts). Bounded so a pathological
  // flush loop can't spin.
  private attempts = 0;

  connectedCallback() {
    const id = this.getAttribute("file-id") ?? "";
    const versionAttr = this.getAttribute("version");
    const version = versionAttr !== null ? Number(versionAttr) : undefined;
    this.innerHTML = `
      <article aria-busy="true" class="media-card-shell">
        <state-badge state="decrypting" label="Decrypting…"></state-badge>
        <h3 class="title">…</h3>
      </article>`;
    void this.decrypt(id, version);
  }

  private async decrypt(id: string, version: number | undefined) {
    try {
      const card = await decodePool.run(() =>
        call<Card>("decrypt_card", { req: { file_id: id, version } }),
      );
      if (this.hasAttribute("mine-only") && !card.mine) {
        this.remove(); // filtered out by the "only my uploads" toggle
        return;
      }

      const isBundle = card.file_type === "bundle";
      const isGeneric = card.file_type === "generic";
      // A bundle links to the bundle screen; every other kind opens the viewer.
      const href = cardHref(card.file_type, id, version);

      const link = document.createElement("a");
      link.className = "media-card-link";
      link.href = href;
      link.setAttribute("aria-label", `Open ${card.title || "untitled post"}`);

      const article = document.createElement("article");
      article.className = "media-card-shell";
      article.setAttribute("aria-busy", "false");

      const top = document.createElement("div");
      top.className = "card-topline";
      const badge = document.createElement("state-badge");
      badge.setAttribute("state", "verified");
      badge.setAttribute("label", `Verified · ${card.author_fp}`);
      const type = document.createElement("span");
      type.className = "type-chip";
      type.textContent = card.file_type;
      top.append(badge, type);
      if (isBundle) {
        // A purple chip marking this card as a grouped post (routes to #/bundle).
        const bundleBadge = document.createElement("span");
        bundleBadge.className = "bundle-badge";
        bundleBadge.textContent = "◆ BUNDLE";
        top.appendChild(bundleBadge);
      }
      article.appendChild(top);

      const thumb = document.createElement("div");
      thumb.className = "thumb-frame";
      if (card.thumbnail_b64) {
        const img = document.createElement("img");
        img.src = `data:image/png;base64,${card.thumbnail_b64}`;
        img.alt = card.title ? `Thumbnail: ${card.title}` : "Thumbnail";
        img.loading = "lazy";
        thumb.appendChild(img);
      } else if (isGeneric) {
        // A downloadable file with no visual: show a document icon, not a media
        // placeholder, so it reads as a file at a glance.
        thumb.classList.add("thumb-generic");
        const icon = document.createElement("span");
        icon.className = "file-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = "📄";
        thumb.appendChild(icon);
      } else {
        const placeholder = document.createElement("span");
        placeholder.textContent = card.file_type === "blog" ? "TEXT" : card.file_type.toUpperCase();
        thumb.appendChild(placeholder);
      }
      article.appendChild(thumb);

      if (isBundle) {
        // The order-private member tally strip (omits zero categories). Skipped
        // when the bundle reports no members (empty label).
        const label = countsLabel(card.member_counts);
        if (label) {
          const counts = document.createElement("p");
          counts.className = "bundle-counts";
          counts.textContent = label;
          article.appendChild(counts);
        }
      }

      const h = document.createElement("h3");
      h.className = "title";
      // For a generic file the title IS the filename; fall back to "File".
      h.textContent = card.title || (isGeneric ? "File" : "(untitled)");
      article.appendChild(h);

      const footer = document.createElement("div");
      footer.className = "card-footer";
      if (card.tags.length) {
        const tags = document.createElement("p");
        tags.className = "tags";
        tags.textContent = card.tags.map((t) => `#${t}`).join(" ");
        footer.appendChild(tags);
      }
      if (!isGeneric) {
        const cue = document.createElement("span");
        cue.className = "open-cue";
        cue.setAttribute("aria-hidden", "true");
        cue.textContent = "Open node →";
        footer.appendChild(cue);
      }
      article.appendChild(footer);

      article.appendChild(link);

      if (isGeneric) {
        // A downloadable file surfaces a Download affordance: verify+decrypt+write
        // the plaintext via the shared per-post flow (save dialog → download_content).
        // Appended as a DIRECT CHILD of article.media-card-shell (a sibling of the
        // .media-card-link overlay) — NOT inside .card-footer, whose own z-index:1
        // stacking context would trap the button beneath the z-index:4 overlay. As a
        // direct child of the isolation:isolate article, its z-index:5 (styles.css)
        // competes directly with the overlay's z-index:4 and wins, so the button
        // receives the click; stopPropagation/preventDefault keep that click from
        // also navigating the card link.
        const dl = document.createElement("button");
        dl.type = "button";
        dl.className = "card-download";
        dl.textContent = "Download";
        dl.addEventListener("click", (e) => {
          e.stopPropagation();
          e.preventDefault();
          void downloadPost(id, card.file_type, card.title);
        });
        article.appendChild(dl);
      }

      this.replaceChildren(article);
    } catch (x) {
      // A "cancelled" rejection is the decodePool queue flush (decodePool
      // .cancelPending, called on feed teardown — the pool throws serial.ts's same
      // CancelledError), not a real failure. If this card is still on screen the
      // flush wasn't meant
      // for it — retry (bounded) so it can't get stuck on a permanent bogus
      // "cancelled" badge. If it's been torn down, drop silently.
      const outcome = decideCardOutcome(x, this.isConnected, this.attempts);
      if (outcome === "drop") return;
      if (outcome === "retry") {
        this.attempts++;
        void this.decrypt(id, version);
        return;
      }
      const article = document.createElement("article");
      article.className = "media-card-shell";
      article.setAttribute("aria-busy", "false");
      const badge = document.createElement("state-badge");
      badge.setAttribute("state", "failed");
      badge.setAttribute("label", cardErr(x));
      article.appendChild(badge);
      this.replaceChildren(article);
    }
  }
}

function cardErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "Could not decrypt this item.";
}

customElements.define("media-card", MediaCard);
