import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeFrontend, frontendStylesheet, FRONTENDS } from "./frontends.ts";

test("normalizeFrontend accepts the three ids", () => {
  assert.equal(normalizeFrontend("default"), "default");
  assert.equal(normalizeFrontend("pizza"), "pizza");
  assert.equal(normalizeFrontend("slot3"), "slot3");
});

test("normalizeFrontend falls back to default for anything else", () => {
  assert.equal(normalizeFrontend("nope"), "default");
  assert.equal(normalizeFrontend(null), "default");
  assert.equal(normalizeFrontend(undefined), "default");
  assert.equal(normalizeFrontend(42), "default");
});

test("frontendStylesheet maps each id to its stylesheet file", () => {
  assert.equal(frontendStylesheet("default"), "styles.css");
  assert.equal(frontendStylesheet("pizza"), "styles.pizza.css");
  assert.equal(frontendStylesheet("slot3"), "styles.slot3.css");
});

test("FRONTENDS lists exactly the three ids in order", () => {
  assert.deepEqual(FRONTENDS.map((f) => f.id), ["default", "pizza", "slot3"]);
  for (const f of FRONTENDS) assert.ok(f.label.length > 0);
});

import { readFileSync } from "node:fs";

const html = readFileSync("index.html", "utf8");

test("index.html has a swappable #frontend-css stylesheet link defaulting to styles.css", () => {
  assert.match(html, /<link[^>]*id="frontend-css"[^>]*href="styles\.css"|<link[^>]*href="styles\.css"[^>]*id="frontend-css"/);
});

test("index.html defaults data-frontend and boots the persisted frontend pre-paint", () => {
  assert.match(html, /data-frontend="default"/);
  assert.match(html, /maxsecu\.frontend/);
  assert.doesNotMatch(html, /data-theme="tech"/);
});
