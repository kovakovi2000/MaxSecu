import type { DecoModule } from "../../core/frontends.ts";

const DECO_ATTR = "data-map-deco";
const ORIGINAL_TEXT_ATTR = "data-map-original-text";

function hasDeco(host: Element, name: string): boolean {
  return host.querySelector(`[${DECO_ATTR}="${name}"]`) !== null;
}

function appendText(doc: Document, parent: Element, tag: string, className: string, text: string): HTMLElement {
  const el = doc.createElement(tag);
  el.className = className;
  el.textContent = text;
  parent.append(el);
  return el;
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
    const text = values[index];
    if (text === undefined) return;
    if (!el.hasAttribute(ORIGINAL_TEXT_ATTR)) {
      el.setAttribute(ORIGINAL_TEXT_ATTR, el.textContent ?? "");
    }
    el.textContent = text;
  });
}

function restoreText(doc: Document): void {
  doc.querySelectorAll<HTMLElement>(`[${ORIGINAL_TEXT_ATTR}]`).forEach((el) => {
    el.textContent = el.getAttribute(ORIGINAL_TEXT_ATTR) ?? "";
    el.removeAttribute(ORIGINAL_TEXT_ATTR);
  });
}

function addBackground(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="app-bg"]');
  if (!slot || hasDeco(slot, "app-bg")) return;

  const layer = doc.createElement("div");
  layer.className = "map-bg-layer";
  layer.setAttribute(DECO_ATTR, "app-bg");
  layer.setAttribute("aria-hidden", "true");

  const compass = doc.createElement("span");
  compass.className = "map-compass-bg";

  const route = doc.createElement("span");
  route.className = "map-route-line";

  const footprints = doc.createElement("div");
  footprints.className = "map-footprints";
  for (let trackIndex = 0; trackIndex < 3; trackIndex += 1) {
    const track = doc.createElement("span");
    track.className = "map-footprint-track";
    for (let i = 0; i < 8; i += 1) {
      appendText(doc, track, "span", "", "⋔");
    }
    footprints.append(track);
  }

  appendText(doc, layer, "span", "map-name-tag tag-a", "Moony");
  appendText(doc, layer, "span", "map-name-tag tag-b", "Padfoot");
  appendText(doc, layer, "span", "map-name-tag tag-c", "Prongs");
  layer.append(compass, route, footprints);
  slot.append(layer);
}

function addHeader(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="header"]');
  if (!slot || hasDeco(slot, "header")) return;

  const wrap = doc.createElement("span");
  wrap.className = "map-header-deco";
  wrap.setAttribute(DECO_ATTR, "header");
  wrap.setAttribute("aria-hidden", "true");

  appendText(doc, wrap, "span", "map-header-compass", "N");
  appendText(doc, wrap, "span", "", "Mischief Managed.");
  slot.append(wrap);
}

function addLoginSpell(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="login"]');
  if (!slot || hasDeco(slot, "login")) return;

  const host = slot.querySelector(".connect-hero, .auth-copy") ?? slot;
  const card = doc.createElement("div");
  card.className = "map-login-deco";
  card.setAttribute(DECO_ATTR, "login");
  card.setAttribute("aria-hidden", "true");

  appendText(doc, card, "p", "map-spell-kicker", "Reveal the parchment");
  appendText(doc, card, "strong", "map-spell-text", "I solemnly swear that I am up to no good.");
  appendText(doc, card, "p", "map-spell-sub", "Ink, corridors, and sealed secrets appear only after the trusted core opens the gate.");

  const prints = doc.createElement("span");
  prints.className = "map-login-prints";
  for (let i = 0; i < 5; i += 1) {
    appendText(doc, prints, "span", "", "⋔");
  }
  card.append(prints);
  host.prepend(card);
}

function rewriteLoginCopy(doc: Document): void {
  setText(doc, "#cn-h", "Open the enchanted media map");
  setText(doc, ".connect-hero > .eyebrow", "parchment-bound privacy gate");
  setText(
    doc,
    ".hero-copy",
    "A hand-inked route into encrypted posts, verified authors, and local-first viewing. The map shows only what the trusted core has safely revealed.",
  );
  setIndexedText(doc, ".hero-grid span", ["keys stay sealed", "one path at a time", "ink after trust"]);
  setIndexedText(doc, ".boot-console span", ["map://unfurling", "identity://sealed", "footprints://wandering"]);
  setText(doc, ".form-head .eyebrow", "keeper of the map");
  setText(doc, ".form-head h2", "Reveal access");
  setText(doc, ".form-head p:not(.eyebrow)", "Unlock the local keystore, then let the parchment draw the route to your MaxSecu server.");
  setText(doc, ".submit-label", "Reveal the map");
  setText(doc, "#cn-status", "The parchment is blank until credentials are offered.");

  setText(doc, "#rg-h", "Sign the parchment");
  setText(doc, ".register-main .auth-copy .eyebrow", "single-use enrollment charm");
  setText(
    doc,
    ".register-main .auth-copy p:not(.eyebrow):not(.auth-note)",
    "This device carries a one-use registration charm. Choose a name and passphrase to bind your local keystore.",
  );
  setText(
    doc,
    ".register-main .auth-note",
    "Your keys are conjured on this device, sealed locally, and never sent through the floo network.",
  );
  setText(doc, "#rg-submit", "Sign the map");
  setText(doc, "#rg-status", "Choose the name and passphrase that will reveal your route.");

  setText(doc, "#rl-h", "Recover the hidden passage");
  setText(doc, ".recovery-main .auth-copy .eyebrow", "cold-key recovery charm");
  setText(
    doc,
    ".recovery-main .auth-copy p:not(.eyebrow):not(.auth-note)",
    "Use the cold recovery key to prove ownership and reveal an admin passage through the map.",
  );
  setText(
    doc,
    ".recovery-main .auth-note",
    "Admin recovery opens the controls only; it does not reveal encrypted content by itself.",
  );
  setText(doc, "#rl-request", "Reveal challenge");
  setText(doc, "#rl-status", "The recovery passage is waiting for its passphrase.");
}

export const slot3Deco: DecoModule = {
  mount(doc: Document): void {
    addBackground(doc);
    addHeader(doc);
    addLoginSpell(doc);
    rewriteLoginCopy(doc);
  },
  unmount(doc: Document): void {
    doc.querySelectorAll(`[${DECO_ATTR}]`).forEach((node) => node.remove());
    restoreText(doc);
  },
};
