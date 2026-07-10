<#
.SYNOPSIS
    Build an UPGRADE ZIP for people who ALREADY use MaxSecu — updates the app in
    place with ZERO data loss (no re-enroll, no new registration key).

.DESCRIPTION
    Produces dist\MaxSecuClient-upgrade.zip: just the new client (exe + ui\) plus
    an UPGRADE-HERE.txt. Existing users copy those two items over their existing
    MaxSecuClient folder, replacing the old exe and ui\ folder. Everything that
    holds their account is left untouched — their keystore (login), their saved
    settings, and their pinned server certificate all live in the SAME folder and
    are preserved — so they just reopen the app and unlock with their usual
    passphrase. This is the client-side twin of scripts\upgrade-server.sh.

    Unlike build-user-zip.ps1 (a CLEAN handout for NEW users), this bundle
    deliberately ships NO config\ pins: an upgrade keeps the user's existing
    server pin in place. If your server ADDRESS or CERTIFICATE actually changed
    (e.g. you re-ran install-server.sh --public), hand out a fresh install ZIP
    from build-user-zip.ps1 instead — that is a re-pin, not an upgrade.

    SAFE BY DESIGN — like build-user-zip.ps1 it does NOT:
      * run maxsecu-setup or create/replace the recovery account,
      * touch recovery_key.blob / recovery_pin.bin / register.key,
      * touch your admin working client or its login/keystore (dist\MaxSecuClient).
    It reuses the recovery pin already embedded in the client crate
    (crates\client-app\recovery_pin.bin) from your original install-client run, so
    that file MUST already exist (run install-client.ps1 once first).

.PARAMETER Out
    Output ZIP path. Default: dist\MaxSecuClient-upgrade.zip.

.PARAMETER SkipBuild
    Reuse the already-compiled client binary + UI instead of rebuilding them
    (fast; use when the code hasn't changed since your last build).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\build-upgrade-zip.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\build-upgrade-zip.ps1 -SkipBuild
#>
[CmdletBinding()]
param(
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
embeds the pin. This script only builds an upgrade of the client; it never creates
a recovery account, so it refuses to run without an existing embedded pin.
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
# 2. Build the UI + client (unless -SkipBuild reuses existing artifacts).
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
# 3. Stage the UPGRADE payload: ONLY the two things that change on a code update
#    — the exe and ui\ — plus UPGRADE-HERE.txt. Deliberately NO config\ (keep the
#    user's existing server pin), NO keystore, NO account data of any kind.
# ---------------------------------------------------------------------------
Write-Section 'Staging the upgrade payload'
$DistDir = Join-Path $Root 'dist'
$StageRoot = Join-Path $DistDir '_upgradezip_stage'
$UpgradeClient = Join-Path $StageRoot 'MaxSecuClient-upgrade'
if (Test-Path $StageRoot) { Remove-Item -Path $StageRoot -Recurse -Force }
New-Item -ItemType Directory -Path $UpgradeClient -Force | Out-Null

Copy-Item -Path $ClientExe -Destination $UpgradeClient -Force

$UpgradeUi = Join-Path $UpgradeClient 'ui'
New-Item -ItemType Directory -Path $UpgradeUi -Force | Out-Null
Copy-Item -Path (Join-Path $UiDist '*') -Destination $UpgradeUi -Recurse -Force

# UPGRADE-HERE.txt (plain language, CRLF line endings) — the client twin of the
# server upgrade: update in place, keep your account.
$UpgradeHereLines = @(
    'MaxSecu -- how to upgrade',
    '=========================',
    '',
    'This is an UPGRADE for people who ALREADY use MaxSecu. It updates the app to',
    'the latest version WITHOUT touching your account: your login, your saved',
    'settings, and your server connection are all kept. You do NOT re-enroll and',
    'you do NOT need a new registration key.',
    '',
    '1. Close MaxSecu if it is open.',
    '',
    '2. Unzip this folder. Inside you will find just two things:',
    '       maxsecu-client-app.exe',
    '       ui\   (a folder)',
    '',
    '3. Copy BOTH of them into your EXISTING MaxSecuClient folder -- the same',
    '   folder you already run the app from -- and choose "Replace the files in',
    '   the destination" when Windows asks.',
    '',
    '   Do NOT delete your MaxSecuClient folder and do NOT start a new one: your',
    '   account lives inside it (the "keystore" and "config" folders) and must',
    '   stay exactly where it is. This upgrade only replaces the program itself.',
    '',
    '4. Open maxsecu-client-app.exe again and unlock with your usual passphrase.',
    '   Everything is right where you left it.',
    '',
    'That is it -- you are upgraded.'
)
$UpgradeHere = Join-Path $UpgradeClient 'UPGRADE-HERE.txt'
$UpgradeHereText = ($UpgradeHereLines -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($UpgradeHere, $UpgradeHereText, (New-Object System.Text.UTF8Encoding($false)))

# ---------------------------------------------------------------------------
# 4. Zip only the staged upgrade payload folder.
# ---------------------------------------------------------------------------
Write-Section 'Building the ZIP'
if ([string]::IsNullOrWhiteSpace($Out)) { $Out = Join-Path $DistDir 'MaxSecuClient-upgrade.zip' }
$OutDir = Split-Path $Out -Parent
if ($OutDir -and -not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
if (Test-Path $Out) { Remove-Item -Path $Out -Force }
Compress-Archive -Path $UpgradeClient -DestinationPath $Out -Force

Remove-Item -Path $StageRoot -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 5. Summary — phrased like the server upgrade: in place, no data loss.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '================ UPGRADE ZIP READY ================' -ForegroundColor Green
Write-Host ''
Write-Host "  $Out"
Write-Host ''
Write-Host 'Send it to your EXISTING users. They copy the exe + ui\ over their own' -ForegroundColor Cyan
Write-Host 'MaxSecuClient folder, replacing the old ones, and reopen the app.'
Write-Host ''
Write-Host 'Their account, saved settings and pinned server are all preserved --' -ForegroundColor DarkGray
Write-Host 'no re-enroll, no new registration key, no re-pin. This ZIP holds NO' -ForegroundColor DarkGray
Write-Host 'account data, recovery key, registration key, or server pins.' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Note: if your server ADDRESS or CERTIFICATE changed, send a fresh install' -ForegroundColor DarkGray
Write-Host 'ZIP from build-user-zip.ps1 instead -- that case is a re-pin, not an upgrade.' -ForegroundColor DarkGray
Write-Host '===================================================' -ForegroundColor Green
