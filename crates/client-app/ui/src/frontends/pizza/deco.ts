import type { DecoModule } from "../../core/frontends.ts";

const DECORATION_ATTR = "data-pizza-deco";
const ORIGINAL_TEXT_ATTR = "data-pizza-original-text";

function hasDeco(host: Element, name: string): boolean {
  return host.querySelector(`[${DECORATION_ATTR}="${name}"]`) !== null;
}

function setText(doc: Document, selector: string, text: string): void {
  const el = doc.querySelector<HTMLElement>(selector);
  if (!el) return;
  if (!el.hasAttribute(ORIGINAL_TEXT_ATTR)) {
    el.setAttribute(ORIGINAL_TEXT_ATTR, el.textContent ?? "");
  }
  el.textContent = text;
}

function setIndexedText(doc: Document, selector: string, values: string[]): void {
  doc.querySelectorAll<HTMLElement>(selector).forEach((el, index) => {
    const value = values[index];
    if (value === undefined) return;
    if (!el.hasAttribute(ORIGINAL_TEXT_ATTR)) {
      el.setAttribute(ORIGINAL_TEXT_ATTR, el.textContent ?? "");
    }
    el.textContent = value;
  });
}

function restoreText(doc: Document): void {
  doc.querySelectorAll<HTMLElement>(`[${ORIGINAL_TEXT_ATTR}]`).forEach((el) => {
    el.textContent = el.getAttribute(ORIGINAL_TEXT_ATTR) ?? "";
    el.removeAttribute(ORIGINAL_TEXT_ATTR);
  });
}

function addLoginHero(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="login"]');
  if (!slot || hasDeco(slot, "login")) return;

  const host = slot.querySelector(".connect-hero, .auth-copy") ?? slot;
  const wrap = doc.createElement("div");
  wrap.className = "pizza-login-deco";
  wrap.setAttribute(DECORATION_ATTR, "login");
  wrap.setAttribute("aria-hidden", "true");

  const glow = doc.createElement("span");
  glow.className = "pizza-login-glow";

  const plate = doc.createElement("span");
  plate.className = "pizza-plate";

  const img = doc.createElement("img");
  img.src = "assets/pizza.png";
  img.alt = "";
  img.decoding = "async";
  img.loading = "eager";
  img.setAttribute("aria-hidden", "true");

  const dripA = doc.createElement("span");
  dripA.className = "pizza-drip pizza-drip-a";
  const dripB = doc.createElement("span");
  dripB.className = "pizza-drip pizza-drip-b";
  const dripC = doc.createElement("span");
  dripC.className = "pizza-drip pizza-drip-c";
  const steam = doc.createElement("span");
  steam.className = "pizza-steam";

  wrap.append(glow, plate, img, dripA, dripB, dripC, steam);
  host.prepend(wrap);
}

function addBackground(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="app-bg"]');
  if (!slot || hasDeco(slot, "app-bg")) return;

  const layer = doc.createElement("div");
  layer.className = "pizza-bg-layer";
  layer.setAttribute(DECORATION_ATTR, "app-bg");
  layer.setAttribute("aria-hidden", "true");

  for (const cls of ["cheese-sun", "tomato-orbit", "crust-ring", "basil-fleck", "pepperoni-fleck"]) {
    const span = doc.createElement("span");
    span.className = cls;
    layer.append(span);
  }
  slot.append(layer);
}

function rewriteLoginCopy(doc: Document): void {
  setText(doc, "#cn-h", "Melt into MaxSecu");
  setText(doc, ".connect-hero > .eyebrow", "wood-fired privacy gate");
  setText(
    doc,
    ".hero-copy",
    "Freshly baked encrypted posts, sealed local keys, and a crispy session layer. Your secrets stay in the oven; the UI only gets the finished slice.",
  );
  setIndexedText(doc, ".hero-grid span", ["melt-proof keys", "one-at-a-time oven", "secret sauce sealed"]);
  setIndexedText(doc, ".boot-console span", ["oven://preheated", "cheese://sealed", "slice://served-safe"]);
  setText(doc, ".form-head .eyebrow", "cheese-pull login");
  setText(doc, ".form-head h2", "Grab a slice");
  setText(
    doc,
    ".form-head p:not(.eyebrow)",
    "Unlock your local keystore, then serve this device a secure MaxSecu session.",
  );
  setText(doc, ".submit-label", "Start melting");
  setText(doc, "#cn-status", "Waiting for the secret sauce.");

  setText(doc, "#rg-h", "Bake your account");
  setText(doc, ".register-main .auth-copy .eyebrow", "fresh dough enrollment");
  setText(
    doc,
    ".register-main .auth-copy p:not(.eyebrow):not(.auth-note)",
    "This device has a one-use topping ticket. Pick a username and a strong passphrase to bake your local keystore.",
  );
  setText(
    doc,
    ".register-main .auth-note",
    "Keys are made on this device, sealed locally, and never tossed across the counter.",
  );
  setText(doc, "#rg-submit", "Bake account");
  setText(doc, "#rg-status", "Choose your name and secret sauce.");

  setText(doc, "#rl-h", "Recover the recipe");
  setText(doc, ".recovery-main .auth-copy .eyebrow", "cold-slice recovery");
  setText(
    doc,
    ".recovery-main .auth-copy p:not(.eyebrow):not(.auth-note)",
    "Use the cold recovery key to prove you own the master recipe and open an admin session.",
  );
  setText(
    doc,
    ".recovery-main .auth-note",
    "Admin recovery is for the oven controls only; it does not melt open content decryption.",
  );
  setText(doc, "#rl-request", "Warm up recovery");
  setText(doc, "#rl-status", "Waiting for the recovery sauce.");
}

export const pizzaDeco: DecoModule = {
  mount(doc: Document): void {
    addBackground(doc);
    addLoginHero(doc);
    rewriteLoginCopy(doc);
  },
  unmount(doc: Document): void {
    doc.querySelectorAll(`[${DECORATION_ATTR}]`).forEach((node) => node.remove());
    restoreText(doc);
  },
};
