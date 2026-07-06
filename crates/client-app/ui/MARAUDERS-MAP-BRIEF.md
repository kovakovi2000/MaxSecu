# MaxSecu Client — Marauder's Map Frontend Brief (slot3)

> **Paste-ready task for an external frontend run.** The *rules* live in
> **`FRONTEND-GUIDE.md`** (same folder) — read it in full first. Its §3 (backend
> contract), §4 (serial queue), §5 (security & a11y), §6 (theming), and §11
> (multi-frontend architecture / drop-in contract) are **binding**.

## Mission

Author the **Marauder's Map** frontend (the `slot3` frontend): a Harry Potter,
Marauder's-Map-themed visual skin for the existing MaxSecu client. The Marauder's Map
is the enchanted parchment that reveals itself only when someone says the incantation
**"I solemnly swear that I am up to no good."** — and wipes clean with *"Mischief
Managed."*

## THIS IS A RESKIN, NOT A RECOLOR — read this twice

Do **not** just brown-tint the existing dark/tech look. A recolor (swapping accent hex
values, leaving the same glassy cards, neon glows, and sci-fi shapes) will be rejected.
Build a genuinely different **visual language** that reads as aged, hand-drawn
cartography and wizarding parchment:

- **Aged parchment** surfaces (warm cream/tan paper, foxing/stains, burnt/torn edges,
  subtle fold creases), **not** translucent dark glass. Replace the glassmorphism with
  paper.
- **Ink line-work**: hand-drawn double-rule borders, map roads/corridors, dotted paths,
  a **compass rose**, hatching/stippling, cartographic flourishes and banners.
- **Moving footprints**: the map's signature — little **dotted footprint trails** that
  animate/wander across surfaces (CSS keyframes), each near a wispy hand-lettered name
  tag. Purely decorative, `aria-hidden`.
- **Wizarding typography feel**: use system **serif** stacks (e.g. `"Georgia", "Iowan
  Old Style", "Palatino Linotype", serif`) plus small-caps / letter-spaced display
  treatment for headings to evoke old engraving. (No external/webfonts — see CSP.)
- **Ink palette**: sepia/umber/oxblood ink on parchment; candle-glow amber accents; the
  "revealed ink" effect for emphasis. Muted, warm, aged — not neon.
- **Reveal motif**: ink that **draws itself in** (stroke/opacity keyframes), parchment
  that **unfurls**, edges that scorch in. Evoke the map appearing as the spell is spoken.

Layout, spacing, component structure, and the backend contract stay **identical** — you
change the visual language, textures, ornament, decorative layers, and login copy, not
the DOM structure or the `--mx-*` spacing/radius/type tokens.

## The login page (REQUIRED)

The spell **"I solemnly swear that I am up to no good."** MUST appear prominently on the
login/connect screen — styled as the revealing incantation (e.g. hand-inked, drawing
itself in, glowing as if freshly conjured). Lean into the map reveal: the connect screen
should feel like the parchment blooming open when the spell is spoken. Nice-to-haves
(optional, your call): *"Messrs Moony, Wormtail, Padfoot & Prongs"* footer flavor;
*"Mischief Managed."* on the logout/lock affordance; a compass rose or "you are here"
marker; wandering footprints across the hero.

## Deliverables (exactly two files — see FRONTEND-GUIDE §11)

1. **`styles.slot3.css`** — a COMPLETE standalone stylesheet. Start from a copy of
   `styles.css` and re-skin it into the Marauder's Map language above. Keep every
   `--mx-*` spacing/radius/type token and the component selectors/structure; replace the
   colour/surface/border/texture treatment and add the parchment/ink/footprint styling
   (including styles for the decoration elements your `deco.ts` injects, and for the
   spell text). Do not alter layout or spacing.
2. **`src/frontends/slot3/deco.ts`** — implement `DecoModule` (`mount`/`unmount`,
   idempotent; see §11). Inject the spell text + map/parchment decoration into
   `[data-deco-slot="login"]`; ambient parchment + animated footprint layers into
   `[data-deco-slot="app-bg"]`; optional accent into `[data-deco-slot="header"]`. Guard
   injected nodes with a data-attr you own (e.g. `data-map-deco`) so `mount` is
   idempotent, and remove them all (and restore any rewritten copy) in `unmount()`. If
   you re-word login copy, follow the pizza deco's pattern: save originals in a
   `data-*-original-text` attribute and restore them on unmount.

## Constraints

- Preserve the backend contract, serial queue, and security/a11y invariants (§3–§5).
- **CSP-safe**: the app CSP is `default-src 'self'; img-src 'self' data:; style-src
  'self' 'unsafe-inline'; media-src ...` — **no external URLs, no web fonts, no remote
  images, no inline `<script>`**. Draw the map, parchment texture, compass, footprints,
  and ornament with **CSS gradients/filters + inline SVG `data:` URIs** only. System
  fonts only.
- No new dependencies. `npm run build`, `npm run typecheck`, `npm test`, and
  `npm run test:a11y` must all stay green.
- Colour/texture must never be the ONLY signal (a11y): keep text/icon cues; decorative
  layers stay `aria-hidden`; the `login` slot is the live `<main>` landmark, so
  `aria-hidden` the nodes you inject there (do not hide the landmark itself).

## How to preview

`npm install` then `npm run build`; serve `dist/` and select **"Marauder's Map"** in
Settings → Appearance → Frontend (or set `localStorage["maxsecu.frontend"]="slot3"`).
The scaffold already wires `slot3` → `styles.slot3.css` + `src/frontends/slot3/deco.ts`,
so your two files drop straight in.
