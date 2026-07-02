# MaxSecu Media App - portable packaging (spec #8). PowerShell twin of package.sh.
# Builds the release artifacts and lays out the portable folders. Tauri GUI bundle,
# Authenticode signing, and PostgreSQL bundling are GUARDED (run only if the
# tool/cert is present) - this script never fabricates a signed or PG-bundled
# artifact. The build steps abort on error; the guarded checks are wrapped in
# try/catch so a missing tool does not abort the script.
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..").Path
$Out  = Join-Path $Root "dist"

Write-Host "==> Building release binaries"
cargo build --release -p maxsecu-portable-server
if ($LASTEXITCODE -ne 0) { throw "cargo build (portable-server) failed" }
cargo build --release -p maxsecu-client-app
if ($LASTEXITCODE -ne 0) { throw "cargo build (client-app) failed" }
# The confined author-side re-mux worker binary. The client spawns this BESIDE its
# own exe (see client-app video::transcode_worker_path). Without it staged next to
# the client, image posts work (in-process) but every VIDEO upload fails with
# "That video could not be processed." (transcode worker not found). `media-worker`
# (the retired confined VIEW decoder) is no longer a shipped binary — native
# <video> is the viewer now; `media-worker` survives only as a dev-only
# decode-verification lib for media-transcode-worker's own tests.
cargo build --release -p maxsecu-media-transcode-worker
if ($LASTEXITCODE -ne 0) { throw "cargo build (media-transcode-worker) failed" }

Write-Host "==> Laying out the portable SERVER folder ($Out\MaxSecuServer)"
$Server = Join-Path $Out "MaxSecuServer"
foreach ($d in @("config", "logs")) { New-Item -ItemType Directory -Force -Path (Join-Path $Server $d) | Out-Null }
Copy-Item (Join-Path $Root "target\release\maxsecu-portable-server.exe") $Server -Force
$schema = Join-Path $Root "docs\schema.sql"
if (Test-Path $schema) { Copy-Item $schema $Server -Force }

Write-Host "==> Laying out the portable CLIENT folder ($Out\MaxSecuClient)"
$Client = Join-Path $Out "MaxSecuClient"
foreach ($d in @("config", "keystore", "index", "cache", "logs")) { New-Item -ItemType Directory -Force -Path (Join-Path $Client $d) | Out-Null }
Copy-Item (Join-Path $Root "target\release\maxsecu-client-app.exe") $Client -Force
# The confined transcode worker binary MUST sit BESIDE the client exe — the client
# resolves it relative to its own AppDir. (ffmpeg itself is embedded in the client
# via include_bytes! + materialized at runtime, so it needs no staging here.)
Copy-Item (Join-Path $Root "target\release\media-transcode-worker.exe") $Client -Force
# Embedded UI assets (the WebView loads these).
$UiDist = Join-Path $Root "crates\client-app\ui\dist"
if (Test-Path $UiDist) {
  $UiOut = Join-Path $Client "ui"
  New-Item -ItemType Directory -Force -Path $UiOut | Out-Null
  Copy-Item (Join-Path $UiDist "*") $UiOut -Recurse -Force
} else {
  Write-Host "    (note: build the UI first - cd crates\client-app\ui; npm run build)"
}

# --- GUARDED deferred-ops steps (never fail the build) ---
Write-Host "==> Tauri GUI bundle (guarded)"
try {
  $tauri = Get-Command cargo-tauri -ErrorAction SilentlyContinue
  if ($tauri) {
    Write-Host "    cargo tauri available - run 'cargo tauri build' for the WebView2 installer bundle"
  } else {
    Write-Host "    DEFERRED (Tauri CLI not installed): the cargo-built client-app binary is produced; the"
    Write-Host "    bundled WebView2 installer requires the Tauri CLI (ops/CI)."
  }
} catch {
  Write-Host "    DEFERRED (Tauri CLI not installed): the cargo-built client-app binary is produced; the"
  Write-Host "    bundled WebView2 installer requires the Tauri CLI (ops/CI)."
}

Write-Host "==> Authenticode signing (guarded)"
try {
  $signtool = Get-Command signtool -ErrorAction SilentlyContinue
  if ($signtool -and $env:MAXSECU_SIGN_CERT) {
    Write-Host "    signtool + MAXSECU_SIGN_CERT present - sign the exes here"
  } else {
    Write-Host "    DEFERRED (no code-signing cert): set MAXSECU_SIGN_CERT + have signtool to Authenticode-sign."
  }
} catch {
  Write-Host "    DEFERRED (no code-signing cert): set MAXSECU_SIGN_CERT + have signtool to Authenticode-sign."
}

Write-Host "==> PostgreSQL bundling (guarded)"
try {
  if ($env:MAXSECU_PG_DIST) {
    Write-Host "    MAXSECU_PG_DIST=$($env:MAXSECU_PG_DIST) - copy the PG dist into MaxSecuServer\postgres\"
  } else {
    Write-Host "    DEFERRED (no PG dist): the dev profile runs on MemoryStore; prod injects DATABASE_URL +"
    Write-Host "    a bundled/external PostgreSQL (ops/CI)."
  }
} catch {
  Write-Host "    DEFERRED (no PG dist): the dev profile runs on MemoryStore; prod injects DATABASE_URL +"
  Write-Host "    a bundled/external PostgreSQL (ops/CI)."
}

Write-Host "==> Done. Portable folders in $Out\"
