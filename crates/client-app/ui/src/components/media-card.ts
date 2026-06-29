import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import type { Card } from "../core/types.ts";
import "./state-badge.ts";

// One feed item. Decrypts itself (title/tags/thumbnail) via decrypt_card — routed
// through the shared serial queue so cards decode one-at-a-time (the backend
// re-auths per call and cannot run those concurrently). Shows a skeleton while
// decrypting, a sanitized error on failure, and links to the viewer.
export class MediaCard extends HTMLElement {
  connectedCallback() {
    const id = this.getAttribute("file-id") ?? "";
    this.innerHTML = `
      <article aria-busy="true">
        <state-badge state="decrypting" label="Decrypting…"></state-badge>
        <h3 class="title">…</h3>
      </article>`;
    void this.decrypt(id);
  }

  private async decrypt(id: string) {
    const article = this.querySelector("article")!;
    try {
      const card = await serial(() => call<Card>("decrypt_card", { req: { file_id: id } }));
      if (this.hasAttribute("mine-only") && !card.mine) {
        this.remove(); // filtered out by the "only my uploads" toggle
        return;
      }
      article.setAttribute("aria-busy", "false");
      article.replaceChildren();

      const badge = document.createElement("state-badge");
      badge.setAttribute("state", "verified");
      badge.setAttribute("label", `Verified · ${card.author_fp}`);
      article.appendChild(badge);

      if (card.thumbnail_b64) {
        const img = document.createElement("img");
        img.src = `data:image/png;base64,${card.thumbnail_b64}`;
        img.alt = card.title ? `Thumbnail: ${card.title}` : "Thumbnail";
        img.loading = "lazy";
        article.appendChild(img);
      }

      const h = document.createElement("h3");
      h.className = "title";
      h.textContent = card.title || "(untitled)";
      article.appendChild(h);

      if (card.tags.length) {
        const tags = document.createElement("p");
        tags.className = "tags";
        tags.textContent = card.tags.map((t) => `#${t}`).join(" ");
        article.appendChild(tags);
      }

      const open = document.createElement("a");
      open.href = `#/viewer?id=${encodeURIComponent(id)}`;
      open.textContent = "View";
      article.appendChild(open);
    } catch (x) {
      article.setAttribute("aria-busy", "false");
      article.replaceChildren();
      const badge = document.createElement("state-badge");
      badge.setAttribute("state", "failed");
      badge.setAttribute("label", cardErr(x));
      article.appendChild(badge);
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
