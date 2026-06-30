<#
.SYNOPSIS
    Fetch + SHA-256-verify the pinned static FFmpeg used by the universal-video-ingest
    feature (decision D-1). Stages it at vendor/ffmpeg/ffmpeg.exe for the client's
    `include_bytes!` embed.

.DESCRIPTION
    The binary is NOT committed (it is .gitignore'd); this script re-stages the EXACT
    pinned build on a fresh checkout. The pinned SHA-256 below is the source of truth
    (it must match $FFMPEG_SHA256 in crates/client-app/src/ffmpeg_bin.rs and the table
    in vendor/ffmpeg/README.md).

    Idempotent: if vendor/ffmpeg/ffmpeg.exe is already present AND matches the pinned
    hash, the download is skipped. On ANY hash mismatch the script FAILS LOUDLY (it
    never leaves an unpinned binary staged).

    NOTE: BtbN's `latest` tag is a ROLLING release; a future download may not match the
    pinned hash. That is intentional — a mismatch is a hard error, not a silent accept.
    If upstream rolled, obtain the matching build or deliberately re-pin (update the SHA
    here, in README.md, and in ffmpeg_bin.rs, and re-review).

.EXAMPLE
    pwsh scripts/fetch-ffmpeg.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Pinned build (keep in sync with vendor/ffmpeg/README.md + ffmpeg_bin.rs) ---------
$FFMPEG_URL    = 'https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip'
$FFMPEG_SHA256 = '6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e'
$INNER_PATH    = 'ffmpeg-master-latest-win64-gpl/bin/ffmpeg.exe'  # path inside the zip

# --- Paths ---------------------------------------------------------------------------
$repoRoot = Split-Path -Parent $PSScriptRoot
$destDir  = Join-Path $repoRoot 'vendor/ffmpeg'
$destExe  = Join-Path $destDir 'ffmpeg.exe'

function Get-Sha256Lower([string]$Path) {
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

# --- Fast path: already staged + correct ---------------------------------------------
if (Test-Path $destExe) {
    if ((Get-Sha256Lower $destExe) -eq $FFMPEG_SHA256) {
        Write-Host "ffmpeg.exe already staged and matches the pinned SHA-256 -- nothing to do."
        Write-Host "  $destExe"
        exit 0
    }
    Write-Warning "Existing $destExe does NOT match the pinned SHA-256; re-fetching."
}

New-Item -ItemType Directory -Force -Path $destDir | Out-Null

# --- Download to a temp file ---------------------------------------------------------
$tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("ffmpeg-static-{0}.zip" -f ([guid]::NewGuid()))
$tmpExt = Join-Path ([System.IO.Path]::GetTempPath()) ("ffmpeg-static-{0}"     -f ([guid]::NewGuid()))
try {
    Write-Host "Downloading $FFMPEG_URL ..."
    Invoke-WebRequest -Uri $FFMPEG_URL -OutFile $tmpZip

    Write-Host "Extracting ..."
    Expand-Archive -Path $tmpZip -DestinationPath $tmpExt -Force

    $innerExe = Join-Path $tmpExt $INNER_PATH
    if (-not (Test-Path $innerExe)) {
        throw "Expected '$INNER_PATH' inside the archive but it was not found. Upstream layout may have changed."
    }

    # Verify BEFORE staging -- never stage an unpinned binary.
    $got = Get-Sha256Lower $innerExe
    if ($got -ne $FFMPEG_SHA256) {
        throw @"
SHA-256 MISMATCH -- refusing to stage.
  expected: $FFMPEG_SHA256
  got:      $got
BtbN's 'latest' tag may have rolled to a newer build. Obtain the build matching the
pinned hash, or deliberately re-pin (update the SHA in scripts/fetch-ffmpeg.ps1,
vendor/ffmpeg/README.md, and crates/client-app/src/ffmpeg_bin.rs) and re-review.
"@
    }

    Copy-Item -Path $innerExe -Destination $destExe -Force
    Write-Host "Staged verified ffmpeg.exe -> $destExe"
    Write-Host "  SHA-256: $FFMPEG_SHA256"
}
finally {
    if (Test-Path $tmpZip) { Remove-Item -Force $tmpZip -ErrorAction SilentlyContinue }
    if (Test-Path $tmpExt) { Remove-Item -Recurse -Force $tmpExt -ErrorAction SilentlyContinue }
}
