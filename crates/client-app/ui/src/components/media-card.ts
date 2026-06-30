import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { decideCardOutcome } from "../core/card-retry.ts";
import type { Card } from "../core/types.ts";
import "./state-badge.ts";

// One feed item. Decrypts itself (title/tags/thumbnail) via decrypt_card — routed
// through the shared serial queue so cards decode one-at-a-time (the backend
// re-auths per call and cannot run those concurrently). The whole card gets
// one accessible transparent overlay link to the viewer; no separate "View"
// button or visible link chrome is needed.
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
      const card = await serial(() =>
        call<Card>("decrypt_card", { req: { file_id: id, version } }),
      );
      if (this.hasAttribute("mine-only") && !card.mine) {
        this.remove(); // filtered out by the "only my uploads" toggle
        return;
      }

      const href = version !== undefined
        ? `#/viewer?id=${encodeURIComponent(id)}&v=${version}`
        : `#/viewer?id=${encodeURIComponent(id)}`;

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
      article.appendChild(top);

      const thumb = document.createElement("div");
      thumb.className = "thumb-frame";
      if (card.thumbnail_b64) {
        const img = document.createElement("img");
        img.src = `data:image/png;base64,${card.thumbnail_b64}`;
        img.alt = card.title ? `Thumbnail: ${card.title}` : "Thumbnail";
        img.loading = "lazy";
        thumb.appendChild(img);
      } else {
        const placeholder = document.createElement("span");
        placeholder.textContent = card.file_type === "blog" ? "TEXT" : card.file_type.toUpperCase();
        thumb.appendChild(placeholder);
      }
      article.appendChild(thumb);

      const h = document.createElement("h3");
      h.className = "title";
      h.textContent = card.title || "(untitled)";
      article.appendChild(h);

      const footer = document.createElement("div");
      footer.className = "card-footer";
      if (card.tags.length) {
        const tags = document.createElement("p");
        tags.className = "tags";
        tags.textContent = card.tags.map((t) => `#${t}`).join(" ");
        footer.appendChild(tags);
      }
      const cue = document.createElement("span");
      cue.className = "open-cue";
      cue.setAttribute("aria-hidden", "true");
      cue.textContent = "Open node →";
      footer.appendChild(cue);
      article.appendChild(footer);

      article.appendChild(link);
      this.replaceChildren(article);
    } catch (x) {
      // A "cancelled" rejection is the GLOBAL serial-queue flush (cancelPending),
      // not a real failure. If this card is still on screen the flush wasn't meant
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
