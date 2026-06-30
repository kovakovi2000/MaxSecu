import { test } from "node:test";
import assert from "node:assert/strict";
import { runViewerOpen } from "./viewer-open.ts";

const tick = () => new Promise((r) => setTimeout(r, 5));

// The bug this guards against: the viewer awaited the status-event subscription
// BEFORE calling open_content. When `listen()` never settled, the content open was
// never even dispatched and the viewer hung on "Loading…". The open must never be
// gated by the (best-effort, status-only) subscription.
test("content open runs even if the status subscription never resolves", async () => {
  let opened = false;
  let result: string | null = null;
  runViewerOpen<string>({
    subscribe: () => new Promise<() => void>(() => {}), // never resolves
    open: async () => {
      opened = true;
      return "CONTENT";
    },
    onResult: (c) => {
      result = c;
    },
    onError: () => {},
  });
  await tick();
  assert.equal(opened, true, "open() must run even if subscribe() never resolves");
  assert.equal(result, "CONTENT", "onResult receives the opened content");
});

test("a rejected subscription neither blocks nor fails the open", async () => {
  let result: string | null = null;
  let errored = false;
  runViewerOpen<string>({
    subscribe: () => Promise.reject(new Error("listen failed")),
    open: async () => "CONTENT",
    onResult: (c) => {
      result = c;
    },
    onError: () => {
      errored = true;
    },
  });
  await tick();
  assert.equal(result, "CONTENT");
  assert.equal(errored, false, "a subscribe rejection must not surface as a viewer error");
});

test("an open failure is routed to onError", async () => {
  let errored: unknown = null;
  runViewerOpen<string>({
    subscribe: () => Promise.resolve(() => {}),
    open: async () => {
      throw new Error("boom");
    },
    onResult: () => {},
    onError: (x) => {
      errored = x;
    },
  });
  await tick();
  assert.ok(errored instanceof Error, "open rejection reaches onError");
});

test("cleanup unlistens once the subscription has resolved", async () => {
  let unlistened = false;
  const cleanup = runViewerOpen<string>({
    subscribe: () => Promise.resolve(() => {
      unlistened = true;
    }),
    open: async () => "CONTENT",
    onResult: () => {},
    onError: () => {},
  });
  await tick();
  cleanup();
  assert.equal(unlistened, true);
});

test("cleanup before the subscription resolves still unlistens when it lands", async () => {
  let unlistened = false;
  let resolveSub!: (u: () => void) => void;
  const cleanup = runViewerOpen<string>({
    subscribe: () =>
      new Promise<() => void>((res) => {
        resolveSub = res;
      }),
    open: async () => "CONTENT",
    onResult: () => {},
    onError: () => {},
  });
  cleanup(); // disconnect before subscribe resolves
  resolveSub(() => {
    unlistened = true;
  }); // subscription lands late
  await tick();
  assert.equal(
    unlistened,
    true,
    "a late-resolving subscription is unlistened if already cleaned up",
  );
});
