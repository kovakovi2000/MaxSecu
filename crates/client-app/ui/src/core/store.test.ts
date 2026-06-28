import { test } from "node:test";
import assert from "node:assert";
import { Store } from "./store.ts";

test("set notifies subscribers with merged state", () => {
  const s = new Store({ a: 1, b: 2 });
  let seen: any = null;
  s.subscribe((v) => (seen = v));
  s.set({ b: 9 });
  assert.deepStrictEqual(seen, { a: 1, b: 9 });
});
