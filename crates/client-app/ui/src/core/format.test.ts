import { test } from "node:test";
import assert from "node:assert/strict";
import { formatRate, pendingPromptText } from "./format.ts";
import type { PendingUploadView } from "./types.ts";

// --- formatRate ---

test("formatRate(0) returns empty string", () => {
  assert.equal(formatRate(0), "");
});

test("formatRate(negative) returns empty string", () => {
  assert.equal(formatRate(-1024), "");
});

test("formatRate(NaN) returns empty string", () => {
  assert.equal(formatRate(NaN), "");
});

test("formatRate(Infinity) returns empty string", () => {
  assert.equal(formatRate(Infinity), "");
});

test("formatRate(1572864) returns '1.5 MB/s' (1.5 MiB/s)", () => {
  // 1572864 = 1.5 * 1024 * 1024
  assert.equal(formatRate(1572864), "1.5 MB/s");
});

test("formatRate(1 MiB exactly) returns '1.0 MB/s'", () => {
  assert.equal(formatRate(1024 * 1024), "1.0 MB/s");
});

test("formatRate(512 KiB) returns KB/s", () => {
  const r = formatRate(512 * 1024);
  assert.equal(r, "512 KB/s");
});

test("formatRate(<1 MiB) shows KB/s, not MB/s", () => {
  const r = formatRate(1024 * 1024 - 1);
  assert.match(r, /KB\/s$/, `expected KB/s, got: ${r}`);
  assert.doesNotMatch(r, /MB\/s|GB\/s/);
});

test("formatRate(>=1 GiB) returns GB/s with one decimal", () => {
  const r = formatRate(2 * 1024 * 1024 * 1024);
  assert.equal(r, "2.0 GB/s");
});

test("formatRate(1 GiB exactly) returns '1.0 GB/s'", () => {
  assert.equal(formatRate(1024 * 1024 * 1024), "1.0 GB/s");
});

test("formatRate(10 MiB) returns MB/s", () => {
  const r = formatRate(10 * 1024 * 1024);
  assert.equal(r, "10.0 MB/s");
});

// --- pendingPromptText ---

test("pendingPromptText formats title and chunk counts", () => {
  const p: PendingUploadView = {
    file_id_hex: "aabbccdd",
    title: "My Video",
    progress: 42,
    total: 100,
  };
  assert.equal(pendingPromptText(p), `Resume upload of "My Video"? (42/100 chunks)`);
});

test("pendingPromptText includes the title in quotes", () => {
  const p: PendingUploadView = {
    file_id_hex: "11223344",
    title: "Holiday Clip",
    progress: 0,
    total: 50,
  };
  const text = pendingPromptText(p);
  assert.ok(text.includes('"Holiday Clip"'), `expected title in quotes: ${text}`);
  assert.ok(text.includes("0/50 chunks"), `expected chunk counts: ${text}`);
});
