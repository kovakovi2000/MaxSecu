import type { DecoModule } from "../../core/frontends.ts";

// STUB — replaced wholesale by the external Marauder's Map design (see
// MARAUDERS-MAP-BRIEF.md). The real module injects the map decoration + the spell
// "I solemnly swear that I am up to no good." into [data-deco-slot="login"], ambient
// parchment/footprint layers into [data-deco-slot="app-bg"], and removes them (plus
// restoring any rewritten copy) in unmount().
export const slot3Deco: DecoModule = {
  mount() { /* no-op stub */ },
  unmount() { /* no-op stub */ },
};
