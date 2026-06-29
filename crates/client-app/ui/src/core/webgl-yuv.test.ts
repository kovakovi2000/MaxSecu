import { test } from "node:test";
import assert from "node:assert";
import { planeSizes, buildProgramSources } from "./webgl-yuv.ts";

test("planeSizes computes luma w*h and half-res chroma (even dims)", () => {
  // 4x4: luma 16, chroma ceil(4/2)*ceil(4/2) = 2*2 = 4 each.
  assert.deepStrictEqual(planeSizes(4, 4), { y: 16, u: 4, v: 4 });
});

test("planeSizes rounds chroma up for odd dims", () => {
  // 5x5: luma 25, chroma ceil(5/2)*ceil(5/2) = 3*3 = 9 each.
  assert.deepStrictEqual(planeSizes(5, 5), { y: 25, u: 9, v: 9 });
  // 1x1: luma 1, chroma 1 each.
  assert.deepStrictEqual(planeSizes(1, 1), { y: 1, u: 1, v: 1 });
  // Mixed parity: 6x3 -> luma 18, chroma ceil(6/2)*ceil(3/2) = 3*2 = 6.
  assert.deepStrictEqual(planeSizes(6, 3), { y: 18, u: 6, v: 6 });
});

test("buildProgramSources returns vertex + fragment shader strings", () => {
  const { vertex, fragment } = buildProgramSources();
  assert.strictEqual(typeof vertex, "string");
  assert.strictEqual(typeof fragment, "string");
  assert.ok(vertex.length > 0);
  assert.ok(fragment.length > 0);
});

test("vertex shader sets gl_Position and passes a vTexCoord varying", () => {
  const { vertex } = buildProgramSources();
  assert.ok(vertex.includes("gl_Position"), "vertex sets gl_Position");
  assert.ok(vertex.includes("vTexCoord"), "vertex passes vTexCoord");
});

test("fragment shader references the 3 plane samplers", () => {
  const { fragment } = buildProgramSources();
  assert.ok(fragment.includes("yTex"), "references yTex sampler");
  assert.ok(fragment.includes("uTex"), "references uTex sampler");
  assert.ok(fragment.includes("vTex"), "references vTex sampler");
  assert.ok(fragment.includes("sampler2D"), "declares sampler2D uniforms");
});

test("fragment shader documents/uses BT.709 limited-range conversion", () => {
  const { fragment } = buildProgramSources();
  assert.ok(/BT\.?709/i.test(fragment), "documents BT.709");
  // BT.709 limited-range luma/chroma coefficients (R = 1.164*Y + 1.793*V, etc.).
  assert.ok(fragment.includes("1.164"), "uses limited-range luma scale 1.164");
  assert.ok(fragment.includes("1.793"), "uses BT.709 red-from-V coefficient 1.793");
  assert.ok(fragment.includes("2.112"), "uses BT.709 blue-from-U coefficient 2.112");
  // Limited-range offsets, normalized /255: Y-16/255 ~ 0.0627, chroma centered
  // at 128/255 ~ 0.50196.
  assert.ok(fragment.includes("0.0627"), "applies Y luma offset 16/255 = 0.0627");
  assert.ok(fragment.includes("0.50196"), "centers chroma at 128/255 = 0.50196");
});
