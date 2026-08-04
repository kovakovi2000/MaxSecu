import { test } from "node:test";
import assert from "node:assert/strict";
import {
  clearPrincipal,
  getPrincipalKind,
  getUsername,
  hasPrincipal,
  setRecoveryPrincipal,
  setUsername,
} from "./session.ts";

// core/session.ts is DOM-free and Tauri-free, so it can be exercised directly
// (unlike the screen components, which are covered by source-structural lints).
//
// Two of these are load-bearing regression locks:
//  • "empty/whitespace username is not a principal" pins the equivalence that
//    lets app-shell use hasPrincipal() where it used to inline
//    `getUsername().trim().length > 0`.
//  • "recovery principal has no username" pins the property share-dialog relies
//    on: its self-compares are `if (me && …)`, so an empty `me` short-circuits
//    and a recovery session can never false-match a real user's name.

test("a non-empty username is a user principal", () => {
  clearPrincipal();
  setUsername("alice");
  assert.equal(hasPrincipal(), true);
  assert.equal(getPrincipalKind(), "user");
  assert.equal(getUsername(), "alice");
});

test("empty/whitespace username is not a principal (old app-shell predicate)", () => {
  for (const u of ["", "   ", "\t\n"]) {
    setUsername("alice");
    setUsername(u);
    assert.equal(
      hasPrincipal(),
      u.trim().length > 0,
      `hasPrincipal() must match the old getUsername().trim().length > 0 for ${JSON.stringify(u)}`,
    );
    assert.equal(getPrincipalKind(), "none");
    // getUsername() itself is byte-identical to what was set.
    assert.equal(getUsername(), u);
  }
});

test("recovery principal has no username", () => {
  clearPrincipal();
  setUsername("alice");
  setRecoveryPrincipal();
  assert.equal(hasPrincipal(), true);
  assert.equal(getPrincipalKind(), "recovery");
  assert.equal(
    getUsername(),
    "",
    "a recovery session is nobody's username — share-dialog's `if (me && …)` must short-circuit",
  );
});

test("clearPrincipal forgets both the kind and the username", () => {
  setUsername("alice");
  clearPrincipal();
  assert.equal(hasPrincipal(), false);
  assert.equal(getPrincipalKind(), "none");
  assert.equal(getUsername(), "");
});

test("signing in as a user after a recovery session restores the user principal", () => {
  setRecoveryPrincipal();
  setUsername("bob");
  assert.equal(getPrincipalKind(), "user");
  assert.equal(getUsername(), "bob");
});
