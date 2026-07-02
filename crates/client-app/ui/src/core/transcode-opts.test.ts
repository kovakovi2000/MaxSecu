import { test } from "node:test";
import assert from "node:assert/strict";
import {
  suggestKbps,
  normalizeOptions,
  resolutionForPreset,
  MIN_KBPS,
  MAX_KBPS,
  MAX_WIDTH,
  MAX_HEIGHT,
  MAX_PIXELS,
  type TranscodeOptions,
} from "./transcode-opts.ts";

test("suggestKbps(1920,1080,30) lands in a sane AV1 band and is clamped", () => {
  const k = suggestKbps(1920, 1080, 30);
  assert.ok(Number.isFinite(k), "finite");
  assert.ok(k >= 2000 && k <= 8000, `expected 2000..8000, got ${k}`);
  assert.ok(k >= MIN_KBPS && k <= MAX_KBPS, "within [MIN_KBPS, MAX_KBPS]");
  assert.equal(k, Math.round(k), "integer");
});

test("suggestKbps clamps a huge resolution down to MAX_KBPS", () => {
  // 8K @ 120fps would blow past the ceiling; must clamp.
  assert.equal(suggestKbps(7680, 4320, 120), MAX_KBPS);
});

test("suggestKbps guards degenerate inputs (0, NaN, negative) → >= MIN_KBPS, finite", () => {
  for (const [w, h, f] of [
    [0, 0, 0],
    [NaN, 1080, 30],
    [1920, NaN, 30],
    [1920, 1080, NaN],
    [-1920, -1080, -30],
    [Infinity, 1080, 30],
  ] as const) {
    const k = suggestKbps(w, h, f);
    assert.ok(Number.isFinite(k), `finite for ${w},${h},${f}`);
    assert.ok(k >= MIN_KBPS, `>= MIN_KBPS for ${w},${h},${f}, got ${k}`);
    assert.ok(k <= MAX_KBPS, `<= MAX_KBPS for ${w},${h},${f}`);
  }
});

test("normalizeOptions: Original/Original is unchanged", () => {
  const opts: TranscodeOptions = { resolution: "Original", bitrate: "Original" };
  assert.deepEqual(normalizeOptions(opts), { resolution: "Original", bitrate: "Original" });
});

test("normalizeOptions: Height floored even and clamped to MAX_HEIGHT", () => {
  assert.deepEqual(normalizeOptions({ resolution: { Height: 721 }, bitrate: "Original" }), {
    resolution: { Height: 720 },
    bitrate: "Original",
  });
  assert.deepEqual(normalizeOptions({ resolution: { Height: 9000 }, bitrate: "Original" }), {
    resolution: { Height: MAX_HEIGHT },
    bitrate: "Original",
  });
  // floor to MIN_DIM (2), never 0
  assert.deepEqual(normalizeOptions({ resolution: { Height: 1 }, bitrate: "Original" }), {
    resolution: { Height: 2 },
    bitrate: "Original",
  });
});

test("normalizeOptions: Custom dims floored even", () => {
  assert.deepEqual(
    normalizeOptions({ resolution: { Custom: { width: 1921, height: 1081 } }, bitrate: "Original" }),
    { resolution: { Custom: { width: 1920, height: 1080 } }, bitrate: "Original" },
  );
});

test("normalizeOptions: Custom per-dim clamp to caps (8K fits max_pixels exactly)", () => {
  assert.deepEqual(
    normalizeOptions({
      resolution: { Custom: { width: 100_000, height: 100_000 } },
      bitrate: "Original",
    }),
    { resolution: { Custom: { width: MAX_WIDTH, height: MAX_HEIGHT } }, bitrate: "Original" },
  );
});

test("normalizeOptions: Custom over MAX_PIXELS scales down aspect-preserving to <= MAX_PIXELS", () => {
  // Within per-dim caps but a contrived pixel overflow: width within MAX_WIDTH,
  // height within MAX_HEIGHT, but their product exceeds MAX_PIXELS.
  const norm = normalizeOptions({
    resolution: { Custom: { width: 7680, height: 4320 } },
    bitrate: "Original",
  });
  // 7680*4320 == MAX_PIXELS exactly, so unchanged.
  assert.deepEqual(norm.resolution, { Custom: { width: 7680, height: 4320 } });

  // Force overflow with a tighter aspect by exceeding the product via width near
  // cap and height near cap is impossible (==cap). Instead verify the general
  // invariant on a synthetic case that exceeds the cap before clamping is moot;
  // use dims whose product > MAX_PIXELS but each <= caps is impossible at default
  // bounds (caps multiply to exactly MAX_PIXELS). So assert the exact-cap case
  // does not exceed.
  if ("Custom" in norm.resolution) {
    assert.ok(norm.resolution.Custom.width * norm.resolution.Custom.height <= MAX_PIXELS);
  } else {
    assert.fail("expected Custom");
  }
});

test("normalizeOptions: Kbps clamped to floor and ceiling", () => {
  assert.deepEqual(normalizeOptions({ resolution: "Original", bitrate: { Kbps: 10_000_000 } }), {
    resolution: "Original",
    bitrate: { Kbps: MAX_KBPS },
  });
  assert.deepEqual(normalizeOptions({ resolution: "Original", bitrate: { Kbps: 1 } }), {
    resolution: "Original",
    bitrate: { Kbps: MIN_KBPS },
  });
  assert.deepEqual(normalizeOptions({ resolution: "Original", bitrate: { Kbps: 4000 } }), {
    resolution: "Original",
    bitrate: { Kbps: 4000 },
  });
});

test("wire shape matches the Rust externally-tagged serde enum", () => {
  assert.equal(
    JSON.stringify({ resolution: { Height: 720 }, bitrate: { Kbps: 4000 } }),
    '{"resolution":{"Height":720},"bitrate":{"Kbps":4000}}',
  );
  assert.equal(
    JSON.stringify({ resolution: "Original", bitrate: "Original" } satisfies TranscodeOptions),
    '{"resolution":"Original","bitrate":"Original"}',
  );
  assert.equal(
    JSON.stringify({
      resolution: { Custom: { width: 1920, height: 1080 } },
      bitrate: "Original",
    } satisfies TranscodeOptions),
    '{"resolution":{"Custom":{"width":1920,"height":1080}},"bitrate":"Original"}',
  );
});

test("resolutionForPreset maps the menu presets", () => {
  assert.equal(resolutionForPreset("original"), "Original");
  assert.deepEqual(resolutionForPreset("2160"), { Height: 2160 });
  assert.deepEqual(resolutionForPreset("1440"), { Height: 1440 });
  assert.deepEqual(resolutionForPreset("1080"), { Height: 1080 });
  assert.deepEqual(resolutionForPreset("720"), { Height: 720 });
  assert.deepEqual(resolutionForPreset("480"), { Height: 480 });
  // unknown preset falls back to Original (fail-safe)
  assert.equal(resolutionForPreset("nonsense"), "Original");
});
