<#
.SYNOPSIS
    Build the MaxSecu Windows client and produce the shareable handout ZIP.

.DESCRIPTION
    Run ONCE by the admin on a Windows PC after the Linux VPS server has finished
    its first run (so the pinned certs exist under maxsecu-server-data/client-pins).

    This script:
      * verifies the Rust (MSVC) + Node/npm toolchains are installed,
      * downloads the two pinned certs from the VPS over scp,
      * runs maxsecu-setup against the PUBLIC server to create the recovery
        account + the admin's first registration key,
      * builds the UI and the client binary,
      * lays out the admin working client (dist\MaxSecuClient),
      * produces the clean handout (dist\MaxSecuClient-share.zip).

.PARAMETER Vps
    SSH target of the server, e.g. root@123.123.123.123 (required).

.PARAMETER Port
    Server listen port. Default 8443.

.PARAMETER ServerAddr
    Public host/IP the client dials + the cert SAN. Default: the IP parsed from -Vps.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1 -Vps root@123.123.123.123
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Vps,

    [int] $Port = 8443,

    [string] $ServerAddr = '',

    # SSH port used ONLY for the scp cert fetch. Default 22; set this when the VPS
    # runs sshd on a non-standard port (a common hardening — e.g. -SshPort 14369).
    # It does not affect the app connection, which always uses -ServerAddr:$Port.
    [int] $SshPort = 22
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string] $Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Fail {
    param([string] $Text)
    Write-Host ''
    Write-Host "ERROR: $Text" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Resolve paths + default ServerAddr from -Vps
# ---------------------------------------------------------------------------
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host "Repo root: $Root"

# Parse the host portion out of user@host (host may itself be an IP or name).
$VpsHost = $Vps
if ($Vps -match '@') {
    $VpsHost = ($Vps -split '@', 2)[1]
}
if ([string]::IsNullOrWhiteSpace($VpsHost)) {
    Fail "Could not parse a host from -Vps '$Vps'. Expected the form user@host."
}

if ([string]::IsNullOrWhiteSpace($ServerAddr)) {
    $ServerAddr = $VpsHost
}
Write-Host "VPS ssh target : $Vps"
Write-Host "Server address : $ServerAddr"
Write-Host "Server port    : $Port"

# ---------------------------------------------------------------------------
# 2. Ensure toolchains (do NOT auto-install system-wide)
# ---------------------------------------------------------------------------
Write-Section 'Checking build toolchains'

# rustup installs cargo to %USERPROFILE%\.cargo\bin and normally adds it to the
# user PATH — but a terminal opened before install (or a customized PATH) won't
# see it, so `Get-Command cargo` reports Rust "missing" when it is in fact
# installed. Recover that common case: if cargo isn't on PATH but exists at the
# standard rustup location, prepend that dir to THIS session's PATH. This only
# makes an already-installed toolchain visible — it never installs anything.
if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
        Write-Host "cargo not on PATH; using rustup install at $cargoBin" -ForegroundColor DarkYellow
    }
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$node  = Get-Command node  -ErrorAction SilentlyContinue
$npm   = Get-Command npm   -ErrorAction SilentlyContinue

$missing = @()
if ($null -eq $cargo) { $missing += 'cargo (Rust)' }
if ($null -eq $node)  { $missing += 'node' }
if ($null -eq $npm)   { $missing += 'npm' }

if ($missing.Count -gt 0) {
    Write-Host ''
    Write-Host "Missing required tools: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Install them, then re-run this script:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Rust (with the MSVC toolchain):'
    Write-Host '    1. Install "Desktop development with C++" from the Visual Studio'
    Write-Host '       Build Tools (https://visualstudio.microsoft.com/downloads/).'
    Write-Host '    2. Install rustup from https://rustup.rs and choose the default'
    Write-Host '       host triple x86_64-pc-windows-msvc.'
    Write-Host ''
    Write-Host '  Node.js (LTS):'
    Write-Host '    Download and install the LTS build from https://nodejs.org'
    Write-Host ''
    Write-Host '  After installing, open a NEW terminal so PATH is refreshed.'
    Fail 'Required toolchains are missing. See instructions above.'
}

Write-Host "cargo : $($cargo.Source)"
Write-Host "node  : $($node.Source)"
Write-Host "npm   : $($npm.Source)"

# ---------------------------------------------------------------------------
# 3. Download the two pinned certs from the VPS via scp
# ---------------------------------------------------------------------------
Write-Section 'Downloading pinned certs from the VPS (scp)'

$scp = Get-Command scp -ErrorAction SilentlyContinue
if ($null -eq $scp) {
    Fail 'scp was not found. Enable the Windows OpenSSH Client (Settings > Apps > Optional features) and re-run.'
}

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("maxsecu-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$CertTmp = Join-Path $TmpDir 'server_cert.der'
$DirTmp  = Join-Path $TmpDir 'directory_pub.der'

Write-Host "Fetching server_cert.der ... (ssh port $SshPort)"
& scp -P $SshPort "${Vps}:maxsecu-server-data/client-pins/server_cert.der" $CertTmp
if ($LASTEXITCODE -ne 0) {
    Fail "scp of server_cert.der failed. Make sure the VPS is reachable on SSH port $SshPort (if sshd is not on 22, pass -SshPort <port>; if SSH is only reachable over a VPN, pass -Vps root@<vpn-ip> together with -ServerAddr <public-ip>), your SSH key/password works, and the server has completed its first run (the pins live at maxsecu-server-data/client-pins/ on the VPS)."
}

Write-Host "Fetching directory_pub.der ..."
& scp -P $SshPort "${Vps}:maxsecu-server-data/client-pins/directory_pub.der" $DirTmp
if ($LASTEXITCODE -ne 0) {
    Fail "scp of directory_pub.der failed. Same checks as above: server must have finished its first run so the pins exist."
}

if (-not (Test-Path $CertTmp)) { Fail "server_cert.der did not download to $CertTmp." }
if (-not (Test-Path $DirTmp))  { Fail "directory_pub.der did not download to $DirTmp." }
Write-Host "Pins downloaded to $TmpDir"

# ---------------------------------------------------------------------------
# 4. Create the recovery account + first key via maxsecu-setup
# ---------------------------------------------------------------------------
Write-Section 'Creating the recovery account (maxsecu-setup)'

$RecoveryBlob = Join-Path $Root 'recovery_key.blob'
$RecoveryPin  = Join-Path $Root 'recovery_pin.bin'
$RegisterKey  = Join-Path $Root 'register.key'

# Prompt for the recovery passphrase without echoing it; hand it to the child
# process only via the SETUP_RECOVERY_PW env var (never printed, never persisted).
Write-Host 'Choose a RECOVERY passphrase. Write it down and keep it offline with'
Write-Host 'recovery_key.blob -- together they are the ONLY way to recover the account.'
$SecurePw = Read-Host -AsSecureString 'Recovery passphrase'
$Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePw)
try {
    $PlainPw = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
}
if ([string]::IsNullOrEmpty($PlainPw)) {
    Fail 'Recovery passphrase cannot be empty.'
}

$SetupExit = 0
$env:SETUP_RECOVERY_PW = $PlainPw
try {
    & cargo run --release --manifest-path (Join-Path $Root 'tools\maxsecu-setup\Cargo.toml') -- `
        --server "${ServerAddr}:${Port}" `
        --host "$ServerAddr" `
        --cert "$CertTmp" `
        --out "$RecoveryBlob" `
        --pin-out "$RecoveryPin" `
        --first-key-out "$RegisterKey"
    $SetupExit = $LASTEXITCODE
} finally {
    # Scrub the passphrase from the environment and local variable.
    Remove-Item Env:\SETUP_RECOVERY_PW -ErrorAction SilentlyContinue
    $PlainPw = $null
}

if ($SetupExit -eq 3) {
    Write-Host ''
    Write-Host 'NOTE: the server already has a recovery account (exit code 3).' -ForegroundColor Yellow
    Write-Host '      Nothing was re-registered. Reusing the existing recovery_pin.bin if present.' -ForegroundColor Yellow
    if (-not (Test-Path $RecoveryPin)) {
        Fail "The server is already set up but no existing recovery_pin.bin was found at $RecoveryPin. You need the recovery_pin.bin from the original setup to build a working client."
    }
} elseif ($SetupExit -ne 0) {
    Fail "maxsecu-setup failed (exit code $SetupExit). Check the server address ${ServerAddr}:${Port} and that the cert matches the running server."
} else {
    Write-Host 'Recovery account created.'
}

# ---------------------------------------------------------------------------
# 5. Embed the recovery pin into the client crate
# ---------------------------------------------------------------------------
Write-Section 'Embedding recovery_pin.bin into the client crate'

$PinDest = Join-Path $Root 'crates\client-app\recovery_pin.bin'
if (-not (Test-Path $RecoveryPin)) {
    Fail "recovery_pin.bin not found at $RecoveryPin -- cannot embed it into the client."
}
Copy-Item -Path $RecoveryPin -Destination $PinDest -Force
Write-Host "Copied recovery_pin.bin -> $PinDest"

# ---------------------------------------------------------------------------
# 6. Build the UI
# ---------------------------------------------------------------------------
Write-Section 'Building the UI (npm ci + npm run build)'

Push-Location (Join-Path $Root 'crates\client-app\ui')
try {
    & npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit code $LASTEXITCODE)." }
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed (exit code $LASTEXITCODE)." }
} finally {
    Pop-Location
}
Write-Host 'UI built.'

# ---------------------------------------------------------------------------
# 7. Build the client binary
# ---------------------------------------------------------------------------
Write-Section 'Building the client (cargo build --release)'

& cargo build --release --manifest-path (Join-Path $Root 'crates\client-app\Cargo.toml') -p maxsecu-client-app
if ($LASTEXITCODE -ne 0) {
    Fail "cargo build of the client failed (exit code $LASTEXITCODE)."
}

$ClientExe = Join-Path $Root 'crates\client-app\target\release\maxsecu-client-app.exe'
if (-not (Test-Path $ClientExe)) {
    Fail "Client binary not found at $ClientExe after a successful build."
}
Write-Host "Client binary: $ClientExe"

$UiDist = Join-Path $Root 'crates\client-app\ui\dist'
if (-not (Test-Path $UiDist)) {
    Fail "UI dist folder not found at $UiDist after the UI build."
}

# ---------------------------------------------------------------------------
# 8. Lay out the admin working client (dist\MaxSecuClient)
# ---------------------------------------------------------------------------
Write-Section 'Laying out the admin working client (dist\MaxSecuClient)'

$DistDir  = Join-Path $Root 'dist'
$AdminDir = Join-Path $DistDir 'MaxSecuClient'
if (Test-Path $AdminDir) {
    Remove-Item -Path $AdminDir -Recurse -Force
}
New-Item -ItemType Directory -Path $AdminDir -Force | Out-Null

# exe
Copy-Item -Path $ClientExe -Destination $AdminDir -Force

# ui\ (contents of the built dist)
$AdminUi = Join-Path $AdminDir 'ui'
New-Item -ItemType Directory -Path $AdminUi -Force | Out-Null
Copy-Item -Path (Join-Path $UiDist '*') -Destination $AdminUi -Recurse -Force

# config\ pins
$AdminConfig = Join-Path $AdminDir 'config'
New-Item -ItemType Directory -Path $AdminConfig -Force | Out-Null
Copy-Item -Path $CertTmp -Destination (Join-Path $AdminConfig 'server_cert.der') -Force
Copy-Item -Path $DirTmp  -Destination (Join-Path $AdminConfig 'directory_pub.der') -Force

# register.key for the admin's own first enrollment (only when freshly minted)
if (Test-Path $RegisterKey) {
    Copy-Item -Path $RegisterKey -Destination (Join-Path $AdminDir 'register.key') -Force
    Write-Host 'Placed register.key in the admin working client (first enrollee becomes admin).'
} else {
    Write-Host 'No register.key present (server was already set up); admin folder built without one.' -ForegroundColor Yellow
}

# Empty runtime dirs the app expects (mirror packaging/package.sh layout).
foreach ($d in @('keystore', 'index', 'cache', 'logs')) {
    New-Item -ItemType Directory -Path (Join-Path $AdminDir $d) -Force | Out-Null
}
Write-Host "Admin working client ready: $AdminDir"

# ---------------------------------------------------------------------------
# 9. Build the CLEAN handout + ZIP
# ---------------------------------------------------------------------------
Write-Section 'Building the clean handout ZIP (dist\MaxSecuClient-share.zip)'

$StageRoot   = Join-Path $DistDir '_share_stage'
$ShareClient = Join-Path $StageRoot 'MaxSecuClient'
if (Test-Path $StageRoot) {
    Remove-Item -Path $StageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $ShareClient -Force | Out-Null

# exe only (NO register.key, NO recovery blob, NO keystore/cache/logs).
Copy-Item -Path $ClientExe -Destination $ShareClient -Force

# ui\
$ShareUi = Join-Path $ShareClient 'ui'
New-Item -ItemType Directory -Path $ShareUi -Force | Out-Null
Copy-Item -Path (Join-Path $UiDist '*') -Destination $ShareUi -Recurse -Force

# config\ pins
$ShareConfig = Join-Path $ShareClient 'config'
New-Item -ItemType Directory -Path $ShareConfig -Force | Out-Null
Copy-Item -Path $CertTmp -Destination (Join-Path $ShareConfig 'server_cert.der') -Force
Copy-Item -Path $DirTmp  -Destination (Join-Path $ShareConfig 'directory_pub.der') -Force

# ---------------------------------------------------------------------------
# 10. START-HERE.txt (plain language, CRLF line endings)
# ---------------------------------------------------------------------------
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

# Zip only the clean staged MaxSecuClient folder.
$ShareZip = Join-Path $DistDir 'MaxSecuClient-share.zip'
if (Test-Path $ShareZip) {
    Remove-Item -Path $ShareZip -Force
}
Compress-Archive -Path $ShareClient -DestinationPath $ShareZip -Force
Write-Host "Handout ZIP: $ShareZip"

# ---------------------------------------------------------------------------
# Cleanup temp
# ---------------------------------------------------------------------------
Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 11. Final summary for the admin
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '================ MAXSECU CLIENT BUILD COMPLETE ================' -ForegroundColor Green
Write-Host ''
Write-Host 'RECOVERY (do this now):' -ForegroundColor Yellow
Write-Host "  * Move this file to COLD / OFFLINE storage and never lose it:"
Write-Host "        $RecoveryBlob"
Write-Host '    Remember the recovery passphrase you just typed. Together they are'
Write-Host '    the ONLY way to recover the account -- there is no backup.'
Write-Host ''
Write-Host 'BECOME THE ADMIN:' -ForegroundColor Cyan
Write-Host "  * Run the admin client and enroll (the FIRST person to enroll becomes admin):"
Write-Host "        $AdminDir\maxsecu-client-app.exe"
Write-Host ''
Write-Host 'ADD MORE USERS:' -ForegroundColor Cyan
Write-Host '  * In the app (Admin screen) mint a single-use registration key, then send'
Write-Host '    the new user BOTH of these (separately):'
Write-Host "        1. the ZIP:  $ShareZip"
Write-Host '        2. the registration key you just minted'
Write-Host ''
Write-Host '==============================================================' -ForegroundColor Green
