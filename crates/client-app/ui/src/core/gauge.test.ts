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

// --- Disk mode --------------------------------------------------------------

test("disk mode: used exceeds free → pct > 100 but fillFraction clamped to 1", () => {
  const m = ramGaugeModel(3 * GiB, 2 * GiB, { disk: true });
  assert.equal(m.hidden, false);
  assert.equal(m.pct, 150, "% is uncapped in disk mode");
  assert.ok(m.pct > 100);
  assert.equal(m.fillFraction, 1, "bar never overflows its track");
  assert.equal(m.label, "3072 / 2048 MB (150%)");
});

test("disk mode: normal fill under free space", () => {
  const m = ramGaugeModel(512 * MiB, 1024 * MiB, { disk: true });
  assert.equal(m.hidden, false);
  assert.equal(m.pct, 50);
  assert.equal(m.fillFraction, 0.5);
  assert.equal(m.label, "512 / 1024 MB (50%)");
});

test("disk mode: unknown free space (probe failed) → raw size, not hidden", () => {
  const m = ramGaugeModel(700 * MiB, 0, { disk: true });
  assert.equal(m.hidden, false, "raw-size fallback is shown, not hidden");
  assert.equal(m.label, "700 MB");
  assert.equal(m.pct, 0);
  assert.equal(m.fillFraction, 0);
});

test("disk mode: still hidden when used is null", () => {
  const m = ramGaugeModel(null, 0, { disk: true });
  assert.equal(m.hidden, true);
});
