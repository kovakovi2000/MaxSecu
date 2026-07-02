import { test } from "node:test";
import assert from "node:assert/strict";
import { ramGaugeModel } from "./gauge.ts";

const GiB = 1024 * 1024 * 1024;
const MiB = 1024 * 1024;

test("hidden when usedBytes is null", () => {
  const m = ramGaugeModel(null, GiB);
  assert.equal(m.hidden, true);
});

test("hidden when budgetBytes is 0", () => {
  const m = ramGaugeModel(100, 0);
  assert.equal(m.hidden, true);
});

test("hidden when budgetBytes is negative", () => {
  const m = ramGaugeModel(100, -1);
  assert.equal(m.hidden, true);
});

test("fillFraction clamped at 0 when used is 0", () => {
  const m = ramGaugeModel(0, GiB);
  assert.equal(m.fillFraction, 0);
  assert.equal(m.pct, 0);
  assert.equal(m.hidden, false);
});

test("fillFraction clamped at 1 when used exceeds budget", () => {
  const m = ramGaugeModel(GiB * 2, GiB);
  assert.equal(m.fillFraction, 1);
  assert.equal(m.pct, 100);
  assert.equal(m.hidden, false);
});

test("label formatting: 512 MiB used, 1024 MiB budget → 50%", () => {
  const m = ramGaugeModel(512 * MiB, 1024 * MiB);
  assert.equal(m.label, "512 / 1024 MB (50%)");
  assert.equal(m.pct, 50);
  assert.equal(m.fillFraction, 0.5);
  assert.equal(m.hidden, false);
});

test("label formatting: full budget", () => {
  const m = ramGaugeModel(256 * MiB, 256 * MiB);
  assert.equal(m.label, "256 / 256 MB (100%)");
  assert.equal(m.pct, 100);
  assert.equal(m.fillFraction, 1);
});
