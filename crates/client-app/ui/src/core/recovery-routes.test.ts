import { test } from "node:test";
import assert from "node:assert/strict";
import { ROUTES, type Route } from "./router.ts";
import { RECOVERY_HIDDEN, isRouteHiddenFor } from "./recovery-routes.ts";

// core/recovery-routes.ts is DOM-free and Tauri-free, so the shell's route gate
// is exercised directly here (app-shell.ts itself imports Tauri via core/rpc.ts
// and can only be covered by the source-structural lint in src/a11y.test.ts).
//
// The load-bearing lock is "admin is reachable": the server's `AdminSession`
// extractor admits the reserved RECOVERY_ID (crates/server/src/http.rs:2294) and
// `POST /v1/registration-keys` is gated by `_admin: AdminSession`
// (crates/server/src/http.rs:395), so a recovery session genuinely CAN mint a
// registration key. Hiding or redirecting #/admin made the UI lie about a
// capability the backend grants.

test("a recovery principal keeps the admin route (inviting a user really works)", () => {
  assert.equal(isRouteHiddenFor("recovery", "admin"), false);
  assert.equal(RECOVERY_HIDDEN.has("admin"), false);
});

test("a recovery principal still loses My Content and Upload", () => {
  // It authored nothing (so "mine" is always empty) and `upload_*` is refused
  // client-side with `recovery_read_only`
  // (crates/client-app/src/commands/upload.rs:259).
  for (const r of ["mine", "upload"] as const) {
    assert.equal(isRouteHiddenFor("recovery", r), true, `${r} must stay hidden for recovery`);
  }
});

test("every other route stays reachable for a recovery principal", () => {
  const hidden = ROUTES.filter((r) => isRouteHiddenFor("recovery", r));
  assert.deepEqual([...hidden].sort(), ["mine", "upload"]);
});

test("a normal user and a signed-out visitor have no hidden routes", () => {
  for (const kind of ["user", "none"] as const) {
    for (const r of ROUTES) {
      assert.equal(
        isRouteHiddenFor(kind, r),
        false,
        `${kind} must not have ${r} hidden — only the recovery principal is gated`,
      );
    }
  }
});

test("every hidden route is a real route (no typo can silently gate nothing)", () => {
  for (const r of RECOVERY_HIDDEN) {
    assert.ok(
      (ROUTES as readonly string[]).includes(r),
      `${r} is not a declared route — the gate would be a no-op`,
    );
  }
});

test("the recovery gate never hides a route the shell would bounce to", () => {
  // applyRoute() redirects a hidden route to "feed"; if "feed" were ever added
  // to the set that redirect would be an infinite dead end.
  const fallback: Route = "feed";
  assert.equal(isRouteHiddenFor("recovery", fallback), false);
});
