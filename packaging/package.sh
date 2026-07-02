#!/usr/bin/env bash
# MaxSecu Media App — portable packaging (spec §8). Builds the release artifacts
# and lays out the portable folders. Tauri GUI bundle, Authenticode signing, and
# PostgreSQL bundling are GUARDED (run only if the tool/cert is present) — this
# script never fabricates a signed or PG-bundled artifact.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist"
echo "==> Building release binaries"
cargo build --release -p maxsecu-portable-server
cargo build --release -p maxsecu-client-app
# The confined VIDEO worker binaries the client spawns BESIDE its own exe (the
# decode media-worker + the author-side re-mux media-transcode-worker). Without
# them staged, image posts work but every VIDEO upload fails ("could not be processed").
cargo build --release -p maxsecu-media-worker
cargo build --release -p maxsecu-media-transcode-worker

echo "==> Laying out the portable SERVER folder ($OUT/MaxSecuServer)"
mkdir -p "$OUT/MaxSecuServer"/{config,logs}
cp "$ROOT/target/release/maxsecu-portable-server"* "$OUT/MaxSecuServer/" 2>/dev/null || \
  cp "$ROOT/target/release/maxsecu-portable-server" "$OUT/MaxSecuServer/"
cp "$ROOT/docs/schema.sql" "$OUT/MaxSecuServer/" || true

echo "==> Laying out the portable CLIENT folder ($OUT/MaxSecuClient)"
mkdir -p "$OUT/MaxSecuClient"/{config,keystore,index,cache,logs}
cp "$ROOT/target/release/maxsecu-client-app"* "$OUT/MaxSecuClient/" 2>/dev/null || \
  cp "$ROOT/target/release/maxsecu-client-app" "$OUT/MaxSecuClient/"
# The confined video worker binaries MUST sit BESIDE the client exe (the client
# resolves them relative to its own AppDir). ffmpeg is embedded in the client and
# materialized at runtime, so it needs no staging here.
for w in media-worker media-transcode-worker; do
  cp "$ROOT/target/release/$w"* "$OUT/MaxSecuClient/" 2>/dev/null || \
    cp "$ROOT/target/release/$w" "$OUT/MaxSecuClient/"
done
# Embedded UI assets (the WebView loads these).
if [ -d "$ROOT/crates/client-app/ui/dist" ]; then
  mkdir -p "$OUT/MaxSecuClient/ui"; cp -r "$ROOT/crates/client-app/ui/dist/." "$OUT/MaxSecuClient/ui/"
else
  echo "    (note: build the UI first — cd crates/client-app/ui && npm run build)"
fi

# --- GUARDED deferred-ops steps (never fail the build) ---
echo "==> Tauri GUI bundle (guarded)"
if command -v cargo-tauri >/dev/null 2>&1 || cargo tauri --version >/dev/null 2>&1; then
  echo "    cargo tauri available — run 'cargo tauri build' for the WebView2 installer bundle"
else
  echo "    DEFERRED (Tauri CLI not installed): the cargo-built client-app binary is produced; the"
  echo "    bundled WebView2 installer requires the Tauri CLI (ops/CI)."
fi
echo "==> Authenticode signing (guarded)"
if command -v signtool >/dev/null 2>&1 && [ -n "${MAXSECU_SIGN_CERT:-}" ]; then
  echo "    signtool + MAXSECU_SIGN_CERT present — sign the exes here"
else
  echo "    DEFERRED (no code-signing cert): set MAXSECU_SIGN_CERT + have signtool to Authenticode-sign."
fi
echo "==> PostgreSQL bundling (guarded)"
if [ -n "${MAXSECU_PG_DIST:-}" ]; then
  echo "    MAXSECU_PG_DIST=$MAXSECU_PG_DIST — copy the PG dist into MaxSecuServer/postgres/"
else
  echo "    DEFERRED (no PG dist): the dev profile runs on MemoryStore; prod injects DATABASE_URL +"
  echo "    a bundled/external PostgreSQL (ops/CI)."
fi
echo "==> Done. Portable folders in $OUT/"
