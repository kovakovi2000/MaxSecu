// Module-level holder for the signed-in username. The UI is outside the TCB, so
// this is convenience state for routing/display only (e.g. so the pending screen
// can poll account_status for the right user) — NOT a security boundary. Set by
// connect-screen on a successful sign-in; read by app-shell when it renders the
// pending screen. esbuild bundles all UI modules together, so this singleton is
// shared across components.
let username = "";
export function setUsername(u: string): void { username = u; }
export function getUsername(): string { return username; }
