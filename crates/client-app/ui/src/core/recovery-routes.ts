import type { Route } from "./router.ts";
import type { PrincipalKind } from "./session.ts";

// Routes a RECOVERY principal cannot use, so they are neither linked nor
// reachable by hash while one is signed in. Cosmetic honesty only — the real
// gate is the server (create_file/stage_version/finalize_version/put_chunk stay
// on `AuthedSession`, which hard-403s RECOVERY_ID) plus the Rust command-side
// refusals (`recovery_read_only`). "My Content" is always empty for a principal
// that authored nothing, and uploading is refused outright.
//
// `admin` is deliberately NOT in this set. The server's `AdminSession` extractor
// admits the reserved RECOVERY_ID (`crates/server/src/http.rs:2294`), and the
// ONLY two calls <admin-screen> makes are `save_file` (unauthenticated native
// dialog, `crates/client-app/src/commands/dialog.rs:89`) and
// `mint_registration_key` (`crates/client-app/src/commands/admin.rs:31`), which
// posts to `/v1/registration-keys` — a handler gated by `_admin: AdminSession`
// (`crates/server/src/http.rs:395`) and reached through the principal-aware
// `reauth` that has a `Principal::Recovery` arm
// (`crates/client-app/src/commands/connection.rs:264`). Inviting a new user from
// a recovery session genuinely works end to end, so hiding Admin would have been
// a lie told by the UI about a capability the backend grants.
//
// This lives in `core/` (not inline in app-shell) so the predicate is directly
// unit-testable: app-shell.ts imports Tauri via core/rpc.ts and cannot be loaded
// in plain Node.
export const RECOVERY_HIDDEN: ReadonlySet<Route> = new Set<Route>(["mine", "upload"]);

// Whether `route` must be unlinked and bounced to the feed for this principal.
// Only the recovery principal has hidden routes; every other kind sees them all.
export function isRouteHiddenFor(kind: PrincipalKind, route: Route): boolean {
  return kind === "recovery" && RECOVERY_HIDDEN.has(route);
}
