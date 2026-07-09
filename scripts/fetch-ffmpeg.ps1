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

    NOTE: the URL below points at a DATED, IMMUTABLE BtbN autobuild release (not the
    rolling `latest` tag), so its asset is frozen and the pinned SHA-256 stays valid.
    BtbN does eventually prune very old autobuild releases; if the URL ever 404s,
    re-pin to a newer dated release (update the URL + SHA here, in README.md, and in
    ffmpeg_bin.rs, and re-review). A hash mismatch remains a hard error, never a silent
    accept.

.EXAMPLE
    pwsh scripts/fetch-ffmpeg.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Pinned build (keep in sync with vendor/ffmpeg/README.md + ffmpeg_bin.rs) ---------
$FFMPEG_URL    = 'https://github.com/BtbN/FFmpeg-Builds/releases/download/autobuild-2026-07-09-14-21/ffmpeg-n7.1.5-1-g7d0e842004-win64-gpl-7.1.zip'
$FFMPEG_SHA256 = '5899192cfbe74807e8e521e98b5e1dcb08ff7f188a7a3a527d2db7193b92c0f9'
$INNER_PATH    = 'ffmpeg-n7.1.5-1-g7d0e842004-win64-gpl-7.1/bin/ffmpeg.exe'  # path inside the zip

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
