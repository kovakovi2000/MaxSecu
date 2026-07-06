import type { DecoModule } from "../../core/frontends.ts";

// STUB — replaced wholesale by the external cheese-pizza design (see PIZZA-BRIEF.md).
// The real module injects assets/pizza.png into [data-deco-slot="login"] and cheese-
// drip layers into [data-deco-slot="app-bg"], and removes them in unmount().
export const pizzaDeco: DecoModule = {
  mount() { /* no-op stub */ },
  unmount() { /* no-op stub */ },
};
