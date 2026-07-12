import { test } from "node:test";
import assert from "node:assert/strict";
import { connectionStatusText } from "./connection-status.ts";

// Unit tests for the pure ConnectionState -> text mapping. Written in the repo's
// native node:test style (the whole UI suite runs under `node --test`, not vitest);
// the assertions mirror the plan's vitest spec 1:1.

test("connectionStatusText gives the Tor bootstrap state an expectation-setting line", () => {
  assert.match(connectionStatusText("tor-bootstrapping"), /Tor/i);
});

test("connectionStatusText maps every known transport state to a non-empty message", () => {
  for (const s of ["resolving", "tor-bootstrapping", "tls-handshake", "channel-binding", "connected"]) {
    assert.ok(connectionStatusText(s).length > 0);
  }
});

test("connectionStatusText falls back to the generic transport message for unknown states", () => {
  assert.equal(connectionStatusText("idle"), "Opening encrypted transport…");
  assert.equal(connectionStatusText("whatever"), "Opening encrypted transport…");
});
