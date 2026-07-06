import type { DecoModule } from "../../core/frontends.ts";

const DECORATION_ATTR = "data-pizza-deco";

function hasDeco(host: Element, name: string): boolean {
  return host.querySelector(`[${DECORATION_ATTR}="${name}"]`) !== null;
}

function addLoginHero(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="login"]');
  if (!slot || hasDeco(slot, "login")) return;

  const wrap = doc.createElement("div");
  wrap.className = "pizza-login-deco";
  wrap.setAttribute(DECORATION_ATTR, "login");
  wrap.setAttribute("aria-hidden", "true");

  const glow = doc.createElement("span");
  glow.className = "pizza-login-glow";

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
  const steam = doc.createElement("span");
  steam.className = "pizza-steam";

  wrap.append(glow, img, dripA, dripB, steam);
  slot.prepend(wrap);
}

function addBackground(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="app-bg"]');
  if (!slot || hasDeco(slot, "app-bg")) return;

  const layer = doc.createElement("div");
  layer.className = "pizza-bg-layer";
  layer.setAttribute(DECORATION_ATTR, "app-bg");
  layer.setAttribute("aria-hidden", "true");

  for (const cls of ["cheese-sun", "tomato-orbit", "crust-ring", "cheese-drips"]) {
    const span = doc.createElement("span");
    span.className = cls;
    layer.append(span);
  }
  slot.append(layer);
}

function addHeaderAccent(doc: Document): void {
  const slot = doc.querySelector('[data-deco-slot="header"]');
  if (!slot || hasDeco(slot, "header")) return;

  const accent = doc.createElement("span");
  accent.className = "pizza-header-accent";
  accent.setAttribute(DECORATION_ATTR, "header");
  accent.setAttribute("aria-hidden", "true");
  slot.append(accent);
}

export const pizzaDeco: DecoModule = {
  mount(doc: Document): void {
    addBackground(doc);
    addHeaderAccent(doc);
    addLoginHero(doc);
  },
  unmount(doc: Document): void {
    doc.querySelectorAll(`[${DECORATION_ATTR}]`).forEach((node) => node.remove());
  },
};
