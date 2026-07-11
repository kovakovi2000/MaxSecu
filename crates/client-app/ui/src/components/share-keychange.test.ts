import { test } from "node:test";
import assert from "node:assert/strict";
import { keyChangeMessage, isKeyChange } from "./share-keychange.ts";

test("isKeyChange detects the key_changed code", () => {
  assert.equal(isKeyChange({ username: "a", ok: false, code: "key_changed" }), true);
  assert.equal(isKeyChange({ username: "a", ok: false, code: "share_failed" }), false);
  assert.equal(isKeyChange({ username: "a", ok: true, code: null }), false);
});

test("keyChangeMessage includes both fingerprints and the username", () => {
  const msg = keyChangeMessage({
    username: "flesman",
    ok: false,
    code: "key_changed",
    old_fingerprint: "A1B2 C3D4 E5F6 0718",
    new_fingerprint: "99AA BBCC DDEE FF00",
  });
  assert.match(msg, /flesman/);
  assert.match(msg, /A1B2 C3D4 E5F6 0718/);
  assert.match(msg, /99AA BBCC DDEE FF00/);
});
