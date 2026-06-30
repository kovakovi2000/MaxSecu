import { test } from "node:test";
import assert from "node:assert/strict";
import { toast, subscribeToasts, type ToastEvent } from "./toast.ts";

test("toast() notifies subscribers with kind + message", () => {
  const seen: ToastEvent[] = [];
  const off = subscribeToasts((e) => seen.push(e));
  toast("success", "Uploaded");
  toast("error", "Nope");
  off();
  toast("info", "ignored after unsubscribe");
  assert.equal(seen.length, 2);
  assert.deepEqual(
    seen.map((e) => [e.kind, e.message]),
    [["success", "Uploaded"], ["error", "Nope"]],
  );
});
