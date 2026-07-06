# MaxSecu Client — Cheese-Pizza Frontend Brief

> **Paste-ready task for an external frontend run.** The *rules* live in
> **`FRONTEND-GUIDE.md`** (same folder) — read it in full first. Its §3 (backend
> contract), §4 (serial queue), §5 (security & a11y), §6 (theming), and the new §9
> (multi-frontend architecture / drop-in contract) are **binding**.

## Mission

Author the **Cheese-Pizza** frontend: a full "melting / dripping cheese pizza" visual
skin for the existing MaxSecu client. You are **reskinning**, not rebuilding. The app,
its components, its layout, and the **spacing of every element must stay identical** —
you change only colour, texture, imagery, borders, shadows, gradients, and decoration.

## Deliverables (exactly two files — see FRONTEND-GUIDE §9)

1. **`styles.pizza.css`** — a COMPLETE standalone stylesheet. Start from a copy of
   `styles.css` and restyle it. Keep every `--mx-*` spacing/radius/type token and the
   component selectors/structure; retheme the colour/surface/border tokens and add
   pizza texture (golden crust, tomato-red accents, molten-cheese gradients, drip
   edges via pseudo-elements). Do not alter layout or spacing.
2. **`src/frontends/pizza/deco.ts`** — implement `DecoModule` (`mount`/`unmount`,
   idempotent; see §9). On the login screens, inject the supplied **`assets/pizza.png`**
   into `[data-deco-slot="login"]` as the hero image, plus optional cheese-drip layers
   into `[data-deco-slot="app-bg"]`. Remove all injected nodes in `unmount`.

## Login page (required)

The login/connect screen MUST prominently feature **`assets/pizza.png`** (the dripping
cheese-pizza slice). It is the centerpiece of the pizza frontend's sign-in.

## Constraints

- Preserve the backend contract, serial queue, and security/a11y invariants.
- No new dependencies. Framework-free, CSP-safe (no external URLs/fonts; inline or
  local assets only). `npm run build`, `npm run typecheck`, `npm test`, and
  `npm run test:a11y` must all stay green.
- Colour must never be the ONLY signal (a11y): keep text/icon cues.

## How to preview

`npm install` then `npm run build`; serve `dist/` and select "Cheese Pizza" in
Settings → Appearance → Frontend (or set `localStorage["maxsecu.frontend"]="pizza"`).
