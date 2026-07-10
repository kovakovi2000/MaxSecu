<#
.SYNOPSIS
    Rebuild the shareable end-user client ZIP for an ALREADY-SET-UP server.

.DESCRIPTION
    Produces a clean handout ZIP (default dist\MaxSecuClient-share.zip) — a fresh
    client (exe + ui + the pinned server certs + START-HERE.txt, and NOTHING else)
    that end users unzip and run. Use this when the server and your admin account
    already exist and you only need to (re)build the ZIP you hand out to users.

    SAFE BY DESIGN — it does NOT:
      * run maxsecu-setup or create/replace the recovery account,
      * touch recovery_key.blob / recovery_pin.bin / register.key,
      * touch your admin working client or its login/keystore (dist\MaxSecuClient).
    It reuses the recovery pin already embedded in the client crate
    (crates\client-app\recovery_pin.bin) from your original install-client run, so
    that file MUST already exist (run install-client.ps1 once first).

    The pins the client trusts are resolved in this order:
      1. -ConnectionCode  -> re-fetched from the server and trusted only if their
                             hash matches the fingerprint (authoritative),
      2. -Pins <dir>      -> reuse server_cert.der + directory_pub.der from <dir>,
      3. auto-detect      -> dist\MaxSecuClient\config from your admin build.

.PARAMETER ConnectionCode
    Optional "addr:port#fingerprint" — re-fetch + verify the pins from the server.
    Use this if you are not sure the local pins are current.

.PARAMETER Pins
    Optional folder containing server_cert.der + directory_pub.der to reuse
    (offline; no server round-trip).

.PARAMETER Out
    Output ZIP path. Default: dist\MaxSecuClient-share.zip.

.PARAMETER SkipBuild
    Reuse the already-compiled client binary + UI instead of rebuilding them
    (fast; use when the code hasn't changed since your last build).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\build-user-zip.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\build-user-zip.ps1 -ConnectionCode "1.2.3.4:8443#K7QF9M2ATBZ4C6XU..."
#>
[CmdletBinding()]
param(
    [string] $ConnectionCode = '',
    [string] $Pins = '',
    [string] $Out = '',
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'

function Write-Section { param([string] $Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Fail { param([string] $Text) Write-Host ''; Write-Host "ERROR: $Text" -ForegroundColor Red; exit 1 }

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host "Repo root: $Root"

# ---------------------------------------------------------------------------
# 0. Guard: this script must NEVER create a recovery account. Require the pin the
#    client build embeds (written by a prior install-client.ps1 run).
# ---------------------------------------------------------------------------
$EmbeddedPin = Join-Path $Root 'crates\client-app\recovery_pin.bin'
if (-not (Test-Path $EmbeddedPin)) {
    Fail @"
crates\client-app\recovery_pin.bin is missing.
Run scripts\install-client.ps1 once first — that creates the recovery account and
embeds the pin. This script only rebuilds the handout ZIP; it never creates a
recovery account, so it refuses to run without an existing embedded pin.
"@
}

# ---------------------------------------------------------------------------
# 1. Toolchains (skip the requirement entirely when -SkipBuild).
# ---------------------------------------------------------------------------
Write-Section 'Checking build toolchains'
if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
        Write-Host "cargo not on PATH; using rustup install at $cargoBin" -ForegroundColor DarkYellow
    }
}
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$node = Get-Command node -ErrorAction SilentlyContinue
$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $SkipBuild) {
    $missing = @()
    if ($null -eq $cargo) { $missing += 'cargo (Rust)' }
    if ($null -eq $node) { $missing += 'node' }
    if ($null -eq $npm) { $missing += 'npm' }
    if ($missing.Count -gt 0) {
        Fail "Missing required tools: $($missing -join ', '). Install them, or pass -SkipBuild to reuse the already-built client."
    }
}

# ---------------------------------------------------------------------------
# 2. Resolve the pins (server_cert.der + directory_pub.der) into a temp dir.
# ---------------------------------------------------------------------------
Write-Section 'Resolving the server pins'
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("maxsecu-userzip-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null
$CertOut = Join-Path $TmpDir 'server_cert.der'
$DirOut = Join-Path $TmpDir 'directory_pub.der'

if (-not [string]::IsNullOrWhiteSpace($ConnectionCode)) {
    # Parse addr:port#fingerprint (split the fingerprint on '#', the port on the
    # LAST ':' so IPv6/host:port forms parse correctly).
    $parts = $ConnectionCode -split '#', 2
    if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[1])) {
        Fail "Could not parse a fingerprint from -ConnectionCode '$ConnectionCode' (expected addr:port#fingerprint)."
    }
    $addr = $parts[0].Trim()
    $fp = $parts[1].Trim()
    $lastColon = $addr.LastIndexOf(':')
    if ($lastColon -lt 0) { Fail "Could not parse addr:port from -ConnectionCode '$ConnectionCode'." }
    $serverAddr = $addr.Substring(0, $lastColon)
    $portText = $addr.Substring($lastColon + 1)
    $port = 0
    if (-not [int]::TryParse($portText, [ref] $port)) {
        Fail "Could not parse a numeric port from -ConnectionCode '$ConnectionCode' (got '$portText')."
    }
    if ($null -eq $cargo) { Fail "cargo (Rust) is required to fetch pins with -ConnectionCode. Install Rust, or reuse local pins with -Pins <dir>." }
    Write-Host "Fetching + verifying pins from ${serverAddr}:${port} against the fingerprint ..."
    & cargo run --release --manifest-path (Join-Path $Root 'tools\maxsecu-setup\Cargo.toml') -- fetch-pins `
        --server "${serverAddr}:${port}" `
        --host "$serverAddr" `
        --fingerprint "$fp" `
        --cert-out "$CertOut" `
        --dir-out "$DirOut"
    if ($LASTEXITCODE -ne 0) {
        Fail "Fetching/verifying the pins failed (exit $LASTEXITCODE). Check that the server ${serverAddr}:${port} is reachable and the fingerprint matches the connection code."
    }
} else {
    # Reuse pins from -Pins, else auto-detect the admin build's config folder.
    $src = $Pins
    if ([string]::IsNullOrWhiteSpace($src)) { $src = Join-Path $Root 'dist\MaxSecuClient\config' }
    $srcCert = Join-Path $src 'server_cert.der'
    $srcDir = Join-Path $src 'directory_pub.der'
    if (-not (Test-Path $srcCert) -or -not (Test-Path $srcDir)) {
        Fail @"
No pins found to reuse (looked in '$src').
Pass -ConnectionCode "addr:port#fingerprint" to fetch + verify them from the server,
or -Pins <dir> pointing at a folder that has server_cert.der + directory_pub.der.
"@
    }
    Copy-Item -Path $srcCert -Destination $CertOut -Force
    Copy-Item -Path $srcDir -Destination $DirOut -Force
    Write-Host "Reusing pins from $src"
}

if (-not (Test-Path $CertOut) -or -not (Test-Path $DirOut)) {
    Fail "Pins were not resolved (server_cert.der / directory_pub.der missing)."
}

# ---------------------------------------------------------------------------
# 3. Build the UI + client (unless -SkipBuild reuses existing artifacts).
# ---------------------------------------------------------------------------
$ClientExe = Join-Path $Root 'crates\client-app\target\release\maxsecu-client-app.exe'
$UiDist = Join-Path $Root 'crates\client-app\ui\dist'

if ($SkipBuild) {
    Write-Section 'Reusing existing build artifacts (-SkipBuild)'
    if (-not (Test-Path $ClientExe)) { Fail "No prebuilt client at $ClientExe. Re-run without -SkipBuild to build it." }
    if (-not (Test-Path $UiDist)) { Fail "No prebuilt UI at $UiDist. Re-run without -SkipBuild to build it." }
} else {
    Write-Section 'Building the UI (npm ci + npm run build)'
    Push-Location (Join-Path $Root 'crates\client-app\ui')
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit $LASTEXITCODE)." }
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw "npm run build failed (exit $LASTEXITCODE)." }
    } finally {
        Pop-Location
    }

    Write-Section 'Building the client (cargo build --release)'
    # The client embeds a pinned static ffmpeg via include_bytes!; stage it first.
    $FfmpegExe = Join-Path $Root 'vendor\ffmpeg\ffmpeg.exe'
    if (-not (Test-Path $FfmpegExe)) {
        Write-Host 'vendor\ffmpeg\ffmpeg.exe missing — fetching the pinned build (scripts\fetch-ffmpeg.ps1) ...'
        & (Join-Path $Root 'scripts\fetch-ffmpeg.ps1')
        if (-not (Test-Path $FfmpegExe)) { Fail "vendor\ffmpeg\ffmpeg.exe is still missing after scripts\fetch-ffmpeg.ps1." }
    }
    & cargo build --release --manifest-path (Join-Path $Root 'crates\client-app\Cargo.toml') -p maxsecu-client-app
    if ($LASTEXITCODE -ne 0) { Fail "cargo build of the client failed (exit $LASTEXITCODE)." }
    if (-not (Test-Path $ClientExe)) { Fail "Client binary not found at $ClientExe after a successful build." }
    if (-not (Test-Path $UiDist)) { Fail "UI dist folder not found at $UiDist after the UI build." }
}

# ---------------------------------------------------------------------------
# 4. Stage the CLEAN handout: exe + ui\ + config\ pins + START-HERE.txt.
#    NO register.key, NO recovery blob, NO keystore/cache/logs (the app creates
#    its own runtime dirs on first launch).
# ---------------------------------------------------------------------------
Write-Section 'Staging the clean handout'
$DistDir = Join-Path $Root 'dist'
$StageRoot = Join-Path $DistDir '_userzip_stage'
$ShareClient = Join-Path $StageRoot 'MaxSecuClient'
if (Test-Path $StageRoot) { Remove-Item -Path $StageRoot -Recurse -Force }
New-Item -ItemType Directory -Path $ShareClient -Force | Out-Null

Copy-Item -Path $ClientExe -Destination $ShareClient -Force

$ShareUi = Join-Path $ShareClient 'ui'
New-Item -ItemType Directory -Path $ShareUi -Force | Out-Null
Copy-Item -Path (Join-Path $UiDist '*') -Destination $ShareUi -Recurse -Force

$ShareConfig = Join-Path $ShareClient 'config'
New-Item -ItemType Directory -Path $ShareConfig -Force | Out-Null
Copy-Item -Path $CertOut -Destination (Join-Path $ShareConfig 'server_cert.der') -Force
Copy-Item -Path $DirOut -Destination (Join-Path $ShareConfig 'directory_pub.der') -Force

# START-HERE.txt (plain language, CRLF line endings) — mirrors install-client.ps1.
$StartHereLines = @(
    'MaxSecu -- how to get started',
    '=============================',
    '',
    '1. Unzip this folder anywhere you like (for example your Desktop).',
    '',
    '2. Open the MaxSecuClient folder and double-click:',
    '       maxsecu-client-app.exe',
    '',
    '   Windows may warn that the publisher is unknown. That is expected for',
    '   this app (it is not signed). Click "More info", then "Run anyway".',
    '',
    '3. When the app opens, on the sign-up screen enter:',
    '     * The server address your admin gave you, for example:',
    '           123.123.123.123:8443',
    '     * The registration key your admin sent you (a one-time key).',
    '',
    '4. Choose a username and a strong passphrase. Keep your passphrase safe --',
    '   it protects your account and cannot be reset for you.',
    '',
    "That's it. You're in."
)
$StartHere = Join-Path $ShareClient 'START-HERE.txt'
$StartHereText = ($StartHereLines -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($StartHere, $StartHereText, (New-Object System.Text.UTF8Encoding($false)))

# ---------------------------------------------------------------------------
# 5. Zip only the clean staged MaxSecuClient folder.
# ---------------------------------------------------------------------------
Write-Section 'Building the ZIP'
if ([string]::IsNullOrWhiteSpace($Out)) { $Out = Join-Path $DistDir 'MaxSecuClient-share.zip' }
$OutDir = Split-Path $Out -Parent
if ($OutDir -and -not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
if (Test-Path $Out) { Remove-Item -Path $Out -Force }
Compress-Archive -Path $ShareClient -DestinationPath $Out -Force

Remove-Item -Path $StageRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 6. Summary.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '================ USER CLIENT ZIP READY ================' -ForegroundColor Green
Write-Host ''
Write-Host "  $Out"
Write-Host ''
Write-Host 'Give each new user, separately:' -ForegroundColor Cyan
Write-Host '  1. this ZIP, and'
Write-Host '  2. a one-time registration key (mint one per user in the admin app:'
Write-Host '     Admin screen -> mint a registration key).'
Write-Host ''
Write-Host 'The ZIP holds NO account data, NO recovery key, and NO registration key.' -ForegroundColor DarkGray
Write-Host 'Your recovery account, master key, and admin login were NOT touched.' -ForegroundColor DarkGray
Write-Host '======================================================' -ForegroundColor Green
