<#
.SYNOPSIS
    Build the MaxSecu Windows client and produce the shareable handout ZIP.

.DESCRIPTION
    Run ONCE by the admin on a Windows PC after the Linux VPS server has finished
    its first run (so the pinned certs exist and the server printed a connection
    code).

    This script:
      * verifies the Rust (MSVC) + Node/npm toolchains are installed,
      * fetches the two pinned certs over the network from the server and verifies
        them against the connection-code fingerprint (no SSH required),
      * runs maxsecu-setup against the PUBLIC server to create the recovery
        account + the admin's first registration key,
      * builds the UI and the client binary,
      * lays out the admin working client (dist\MaxSecuClient),
      * produces the clean handout (dist\MaxSecuClient-share.zip).

.PARAMETER ConnectionCode
    The connection code the server printed, of the form addr:port#fingerprint
    (e.g. 123.123.123.123:8443#K7QF9M2ATBZ4C6XU...). This is the primary input:
    it is parsed into -ServerAddr, -Port and -Fingerprint for you.

.PARAMETER ServerAddr
    Public host/IP the client dials + the cert SAN. Manual alternative to
    -ConnectionCode (must be paired with -Fingerprint).

.PARAMETER Port
    Server listen port. Default 8443.

.PARAMETER Fingerprint
    The pin fingerprint (the part after '#' in the connection code). Manual
    alternative to -ConnectionCode (must be paired with -ServerAddr).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1 -ConnectionCode 123.123.123.123:8443#K7QF9M2ATBZ4C6XU...
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    # The connection code the server printed: "addr:port#fingerprint". Primary
    # input — it is split into $ServerAddr, $Port and $Fingerprint below. Provide
    # this OR the manual -ServerAddr/-Fingerprint pair.
    [Parameter(ParameterSetName = 'Install', Position = 0)]
    [string] $ConnectionCode = '',

    [Parameter(ParameterSetName = 'Install')]
    [string] $ServerAddr = '',

    [Parameter(ParameterSetName = 'Install')]
    [int] $Port = 8443,

    # The pin fingerprint (the text after '#' in the connection code). Load-bearing:
    # the fetched pins are trusted ONLY if their recomputed hash matches this.
    [Parameter(ParameterSetName = 'Install')]
    [string] $Fingerprint = '',

    # Unattended recovery passphrase. When supplied (or via $env:SETUP_RECOVERY_PW),
    # the interactive Read-Host prompt is skipped so the client can be installed
    # non-interactively (e.g. by scripts\test-full-install.ps1). Prefer the env var:
    # a -RecoveryPassphrase value is visible in shell history and process listings for
    # the life of the process, whereas the env var isn't captured in command-line args.
    # Leave both empty for the normal interactive install, which prompts without echoing.
    [Parameter(ParameterSetName = 'Install')]
    [string] $RecoveryPassphrase = '',

    # Tear the CLIENT down to zero and exit (no build): delete dist\ (both the admin
    # app and the handout ZIP), the recovery + registration secrets in the repo root
    # (recovery_key.blob / recovery_pin.bin / register.key), and the recovery pin
    # embedded into the client crate. Its own parameter set, so no other args are
    # required. Idempotent — absent files are simply reported and skipped.
    [Parameter(Mandatory = $true, ParameterSetName = 'Reset')]
    [switch] $Reset
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
# 1. Resolve paths (server address/port/fingerprint are parsed after the reset block)
# ---------------------------------------------------------------------------
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host "Repo root: $Root"

# ---------------------------------------------------------------------------
# 1b. Full reset (-Reset): delete this PC's built app + the security files it
#     created, so the next run starts from zero. Then exit — no build.
# ---------------------------------------------------------------------------
if ($Reset) {
    Write-Section 'Resetting the client (removing built app + security files)'

    # State this PC accumulated. NOT the git-tracked source, and NOT the build
    # caches (target\, node_modules\) — those are just caches; a rebuild refreshes
    # them and deleting them only costs you a slow recompile.
    $targets = @(
        (Join-Path $Root 'dist'),
        (Join-Path $Root 'recovery_key.blob'),
        (Join-Path $Root 'recovery_pin.bin'),
        (Join-Path $Root 'register.key'),
        (Join-Path $Root 'crates\client-app\recovery_pin.bin')
    )
    foreach ($t in $targets) {
        if (Test-Path $t) {
            Remove-Item -Path $t -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  removed  $t"
        } else {
            Write-Host "  absent   $t" -ForegroundColor DarkGray
        }
    }

    Write-Host ''
    Write-Host 'Client state removed. This PC is back to zero.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'NOTE: this erased recovery_key.blob and the embedded recovery pin -- the' -ForegroundColor Yellow
    Write-Host '      master key to the OLD server. Only do this to abandon that server.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'If you unzipped/copied the admin app elsewhere (e.g. your Desktop) and'
    Write-Host 'signed in there, delete that copy too -- it keeps its own login data.'
    Write-Host ''
    Write-Host 'For a completely clean rebuild you may ALSO delete the build caches:'
    Write-Host '  target\  crates\client-app\target\  crates\client-app\ui\node_modules\  crates\client-app\ui\dist\'
    Write-Host ''
    Write-Host 'To build again from scratch:' -ForegroundColor Cyan
    Write-Host '  .\scripts\install-client.ps1 -ConnectionCode <code-from-the-server>'
    exit 0
}

# Resolve the dial target + fingerprint from either -ConnectionCode or the manual
# -ServerAddr/-Fingerprint pair. The connection code is "addr:port#fingerprint";
# only the fingerprint is load-bearing (the address is untrusted transport info).
if (-not [string]::IsNullOrWhiteSpace($ConnectionCode)) {
    # Split off the fingerprint on '#', then split the address on the LAST ':' so
    # IPv6 / host:port forms parse correctly.
    $codeParts = $ConnectionCode -split '#', 2
    $addrPart  = $codeParts[0].Trim()
    if ($codeParts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($codeParts[1])) {
        Fail "Could not parse a fingerprint from -ConnectionCode '$ConnectionCode'. Expected the form addr:port#fingerprint."
    }
    $Fingerprint = $codeParts[1].Trim()

    $lastColon = $addrPart.LastIndexOf(':')
    if ($lastColon -lt 0) {
        Fail "Could not parse addr:port from -ConnectionCode '$ConnectionCode'. Expected the form addr:port#fingerprint."
    }
    $ServerAddr = $addrPart.Substring(0, $lastColon)
    $portText   = $addrPart.Substring($lastColon + 1)
    $parsedPort = 0
    if (-not [int]::TryParse($portText, [ref] $parsedPort)) {
        Fail "Could not parse a numeric port from -ConnectionCode '$ConnectionCode' (got '$portText')."
    }
    $Port = $parsedPort
}

# Require either a connection code (parsed above) OR the manual pair.
if ([string]::IsNullOrWhiteSpace($ServerAddr) -or [string]::IsNullOrWhiteSpace($Fingerprint)) {
    Fail "Provide -ConnectionCode ""addr:port#fingerprint"" (the code the server printed), or the manual pair -ServerAddr <host/IP> and -Fingerprint <code> (optionally -Port, default 8443)."
}

Write-Host "Server address : $ServerAddr"
Write-Host "Server port    : $Port"
Write-Host "Pin fingerprint: $Fingerprint"

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
# 3. Fetch + verify the two pinned certs over the network
# ---------------------------------------------------------------------------
Write-Section 'Fetching + verifying pins from the server'

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("maxsecu-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$CertTmp = Join-Path $TmpDir 'server_cert.der'
$DirTmp  = Join-Path $TmpDir 'directory_pub.der'

# maxsecu-setup fetch-pins dials the server, downloads the two public pins, and
# recomputes their fingerprint. It writes the .der files ONLY if that hash matches
# the connection-code fingerprint (integrity without SSH); on any mismatch,
# network, or parse error it writes NOTHING and exits non-zero.
if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
        Write-Host "cargo not on PATH; using rustup install at $cargoBin" -ForegroundColor DarkYellow
    }
}

Write-Host "Fetching pins from ${ServerAddr}:${Port} and verifying against the fingerprint ..."
& cargo run --release --manifest-path (Join-Path $Root 'tools\maxsecu-setup\Cargo.toml') -- fetch-pins `
    --server "${ServerAddr}:${Port}" `
    --host "$ServerAddr" `
    --fingerprint "$Fingerprint" `
    --cert-out "$CertTmp" `
    --dir-out "$DirTmp"
if ($LASTEXITCODE -ne 0) {
    Fail "Fetching/verifying the pins failed (exit code $LASTEXITCODE). Check that the server at ${ServerAddr}:${Port} is reachable and finished its first run, and that the fingerprint '$Fingerprint' exactly matches the connection code the server printed."
}

if (-not (Test-Path $CertTmp)) { Fail "server_cert.der is missing at $CertTmp." }
if (-not (Test-Path $DirTmp))  { Fail "directory_pub.der is missing at $DirTmp." }
Write-Host "Pins fetched + verified, ready in $TmpDir"

# ---------------------------------------------------------------------------
# 4. Create the recovery account + first key via maxsecu-setup
# ---------------------------------------------------------------------------
Write-Section 'Creating the recovery account (maxsecu-setup)'

$RecoveryBlob = Join-Path $Root 'recovery_key.blob'
$RecoveryPin  = Join-Path $Root 'recovery_pin.bin'
$RegisterKey  = Join-Path $Root 'register.key'

# RESUMABILITY: maxsecu-setup is once-only and produces three IRREPLACEABLE files
# (its preflight refuses to overwrite them, and the server 409s a second register).
# If a prior run already completed setup, those files are on disk — skip setup and
# resume the build rather than fail. This lets you re-run after fixing a later step
# (e.g. staging ffmpeg) without touching the recovery key / first registration key.
if ((Test-Path $RecoveryBlob) -and (Test-Path $RecoveryPin) -and (Test-Path $RegisterKey)) {
    Write-Host 'Recovery artifacts already present from a prior run — setup is complete; skipping maxsecu-setup.' -ForegroundColor Yellow
    Write-Host "  $RecoveryBlob"
    Write-Host "  $RecoveryPin"
    Write-Host "  $RegisterKey"
} else {
    # Prefer a non-interactively supplied passphrase (param or env var); fall back to
    # an interactive, non-echoed prompt. The plaintext is handed to the child process
    # ONLY via the SETUP_RECOVERY_PW env var below (never printed, never persisted).
    $PlainPw = $RecoveryPassphrase
    if ([string]::IsNullOrEmpty($PlainPw)) { $PlainPw = $env:SETUP_RECOVERY_PW }
    if ([string]::IsNullOrEmpty($PlainPw)) {
        Write-Host 'Choose a RECOVERY passphrase. Write it down and keep it offline with'
        Write-Host 'recovery_key.blob -- together they are the ONLY way to recover the account.'
        $SecurePw = Read-Host -AsSecureString 'Recovery passphrase'
        $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePw)
        try {
            $PlainPw = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        }
    } else {
        Write-Host 'Using a non-interactively supplied recovery passphrase.' -ForegroundColor DarkYellow
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
        $RecoveryPassphrase = $null
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

# The client embeds a pinned static ffmpeg.exe via include_bytes! (author-side
# video transcode). vendor\ffmpeg\ffmpeg.exe is gitignored, so a fresh checkout
# lacks it and the build fails with a cryptic include_bytes error. Stage it first
# with the pinned fetch script (idempotent: it skips the download if already staged
# and matching the pinned SHA-256).
$FfmpegExe = Join-Path $Root 'vendor\ffmpeg\ffmpeg.exe'
if (-not (Test-Path $FfmpegExe)) {
    Write-Host 'vendor\ffmpeg\ffmpeg.exe is missing — fetching the pinned build (scripts\fetch-ffmpeg.ps1) ...'
    try {
        & (Join-Path $Root 'scripts\fetch-ffmpeg.ps1')
    } catch {
        Write-Host "fetch-ffmpeg.ps1 failed: $_" -ForegroundColor Red
        Fail 'Could not fetch the pinned ffmpeg. Run scripts\fetch-ffmpeg.ps1 manually; if it reports a SHA-256 mismatch, BtbN latest has rolled -- obtain the matching build or re-pin the SHA (scripts\fetch-ffmpeg.ps1, vendor\ffmpeg\README.md, crates\client-app\src\ffmpeg_bin.rs), then re-run.'
    }
    if (-not (Test-Path $FfmpegExe)) {
        Fail "vendor\ffmpeg\ffmpeg.exe is still missing after scripts\fetch-ffmpeg.ps1."
    }
}

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
