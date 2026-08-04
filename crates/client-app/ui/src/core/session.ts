// Module-level holder for the signed-in PRINCIPAL. The UI is outside the TCB, so
// this is convenience state for routing/display only (it gates session-only
// routes in the app shell) — NOT a security boundary. Set by connect-screen on a
// successful sign-in (and by recovery-login-screen on a successful cold-key
// recovery sign-in); read by app-shell. esbuild bundles all UI modules
// together, so this singleton is shared across components.
//
// `kind` is deliberately SEPARATE from `username` rather than a reserved label
// stuffed into it. The recovery principal has NO username by construction (Rust
// `commands::auth::Principal::Recovery` carries none — the recovery account has
// no `users` row and no directory binding), so `username` stays "" for it. That
// is what keeps share-dialog's `if (me && …)` self-compares correct: a recovery
// session is nobody's username and can never false-match a real one.
export type PrincipalKind = "none" | "user" | "recovery";

let username = "";
let kind: PrincipalKind = "none";

export function setUsername(u: string): void {
  username = u;
  // Exactly the predicate app-shell used to compute inline from getUsername().
  kind = u.trim().length > 0 ? "user" : "none";
}
export function getUsername(): string { return username; }

// Mark this session as the cold-recovery principal. Leaves `username` empty —
// see the note above.
export function setRecoveryPrincipal(): void {
  username = "";
  kind = "recovery";
}

// Forget the principal (sign-out / "End recovery session").
export function clearPrincipal(): void {
  username = "";
  kind = "none";
}

export function getPrincipalKind(): PrincipalKind { return kind; }

// Whether ANY principal is signed in. For every value setUsername can receive
// this is identical to the old `getUsername().trim().length > 0`.
export function hasPrincipal(): boolean { return kind !== "none"; }
