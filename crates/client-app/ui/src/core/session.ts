// Module-level holder for the signed-in username. The UI is outside the TCB, so
// this is convenience state for routing/display only (it gates session-only
// routes in the app shell) — NOT a security boundary. Set by connect-screen on a
// successful sign-in; read by app-shell. esbuild bundles all UI modules
// together, so this singleton is shared across components.
let username = "";
export function setUsername(u: string): void { username = u; }
export function getUsername(): string { return username; }
