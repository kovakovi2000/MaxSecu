import { test } from "node:test";
import assert from "node:assert/strict";
import {
  guardCall,
  isServerUntrusted,
  subscribeTrustAlarm,
  type TrustAlarmEvent,
} from "./trust-alarm.ts";

test("a server_untrusted error opens the trust alarm and the action does not proceed", async () => {
  const seen: TrustAlarmEvent[] = [];
  const off = subscribeTrustAlarm((e) => seen.push(e));
  let proceeded = false;
  await assert.rejects(
    guardCall(Promise.reject({ code: "server_untrusted", message: "pin mismatch" }))
      .then(() => {
        proceeded = true;
      }),
    "guardCall must re-reject a server_untrusted error (no fallback, no silent continue)",
  );
  off();
  // The shared <trust-alarm> modal subscribes to this bus, so a single emission is
  // the testable proxy for "the modal is shown".
  assert.equal(seen.length, 1, "the shared trust-alarm modal is raised exactly once");
  assert.equal(seen[0].code, "server_untrusted");
  assert.equal(proceeded, false, "the triggering action must not proceed");
});

test("an ordinary error passes through untouched and never trips the alarm", async () => {
  const seen: TrustAlarmEvent[] = [];
  const off = subscribeTrustAlarm((e) => seen.push(e));
  await assert.rejects(guardCall(Promise.reject({ code: "offline", message: "no net" })));
  off();
  assert.equal(seen.length, 0, "ordinary errors must not trip the trust alarm");
});

test("a successful call passes its value through untouched", async () => {
  const v = await guardCall(Promise.resolve(42));
  assert.equal(v, 42);
});

test("isServerUntrusted recognizes the shared code and rejects everything else", () => {
  assert.equal(isServerUntrusted({ code: "server_untrusted" }), true);
  assert.equal(isServerUntrusted({ code: "offline" }), false);
  assert.equal(isServerUntrusted(new Error("boom")), false);
  assert.equal(isServerUntrusted(null), false);
  assert.equal(isServerUntrusted("server_untrusted"), false);
});
