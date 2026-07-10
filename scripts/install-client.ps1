<#
.SYNOPSIS
    Build the MaxSecu Windows client and produce the shareable handout ZIP.

.DESCRIPTION
    Run ONCE by the admin on a Windows PC after the Linux VPS server has finished
    its first run (so the pinned certs exist and the server printed a connection
    code).

    This script:
      * verifies the Rust (MSVC) + Node/npm toolchains are installed,
      * fetches the pinned server cert over the network and verifies it against
        the connection-code (CERT-only) fingerprint (no SSH required),
      * runs the offline-D5 ceremony inside maxsecu-setup: generates the directory
        root (D5) on THIS PC, uploads the delegation with the one-time -Token
        (which OPENS enrollment on the awaiting server), creates the recovery
        account + the admin's first registration key, and mints the FINAL
        user-facing connection code addr:port#fingerprint(server_cert, D5_pub),
      * builds the UI and the client binary,
      * lays out the admin working client (dist\MaxSecuClient),
      * produces the clean handout (dist\MaxSecuClient-share.zip).

.PARAMETER ConnectionCode
    The connection code install-server printed, of the form addr:port#fingerprint
    (e.g. 123.123.123.123:8443#K7QF9M2ATBZ4C6XU...). NOTE: for the offline-D5 flow
    this fingerprint is the SERVER-CERT-only fingerprint (used to pin TLS while the
    server still awaits delegation); it is NOT the final user-facing code. This
    script mints that final code after the ceremony. Parsed into -ServerAddr, -Port
    and -Fingerprint for you.

.PARAMETER Token
    The one-time delegation token install-server printed. Required for the offline-D5
    ceremony (it authorizes uploading the delegation that opens enrollment). May also
    be supplied via $env:SETUP_DELEGATION_TOKEN for an unattended run; otherwise you
    are prompted.

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
    # input -- it is split into $ServerAddr, $Port and $Fingerprint below. Provide
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

    # One-time offline-D5 delegation token (from install-server). Threads the
    # ceremony non-interactively when supplied (or via $env:SETUP_DELEGATION_TOKEN),
    # mirroring -RecoveryPassphrase; an interactive run prompts for it. It is handed
    # to the child maxsecu-setup ONLY via the SETUP_DELEGATION_TOKEN env var (never
    # printed, never persisted) and scrubbed afterwards.
    [Parameter(ParameterSetName = 'Install')]
    [string] $Token = '',

    # Tear the CLIENT down to zero and exit (no build): delete dist\ (both the admin
    # app and the handout ZIP), the recovery + registration secrets in the repo root
    # (recovery_key.blob / recovery_pin.bin / register.key), and the recovery pin
    # embedded into the client crate. Its own parameter set, so no other args are
    # required. Idempotent -- absent files are simply reported and skipped.
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
#     created, so the next run starts from zero. Then exit -- no build.
# ---------------------------------------------------------------------------
if ($Reset) {
    Write-Section 'Resetting the client (removing built app + security files)'

    # State this PC accumulated. NOT the git-tracked source, and NOT the build
    # caches (target\, node_modules\) -- those are just caches; a rebuild refreshes
    # them and deleting them only costs you a slow recompile.
    $targets = @(
        (Join-Path $Root 'dist'),
        (Join-Path $Root 'recovery_key.blob'),
        (Join-Path $Root 'recovery_pin.bin'),
        (Join-Path $Root 'register.key'),
        # Offline-D5 ceremony artifacts (directory root custody + minted code).
        (Join-Path $Root 'd5_key.blob'),
        (Join-Path $Root 'd5_recovery.blob'),
        (Join-Path $Root 'directory_pub.der'),
        (Join-Path $Root 'connection_code.txt'),
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
    Write-Host 'NOTE: this erased recovery_key.blob, the embedded recovery pin, AND the' -ForegroundColor Yellow
    Write-Host '      offline-D5 directory root (d5_key.blob / d5_recovery.blob) -- the' -ForegroundColor Yellow
    Write-Host '      master keys to the OLD server. Only do this to abandon that server.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'If you unzipped/copied the admin app elsewhere (e.g. your Desktop) and'
    Write-Host 'signed in there, delete that copy too -- it keeps its own login data.'
    Write-Host ''
    Write-Host 'For a completely clean rebuild you may ALSO delete the build caches:'
    Write-Host '  target\  crates\client-app\target\  crates\client-app\ui\node_modules\  crates\client-app\ui\dist\'
    Write-Host ''
    Write-Host 'To build again from scratch (re-run install-server first for a fresh token):' -ForegroundColor Cyan
    Write-Host '  .\scripts\install-client.ps1 -ConnectionCode <addr:port#cert-fp> -Token <token>'
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
# user PATH -- but a terminal opened before install (or a customized PATH) won't
# see it, so `Get-Command cargo` reports Rust "missing" when it is in fact
# installed. Recover that common case: if cargo isn't on PATH but exists at the
# standard rustup location, prepend that dir to THIS session's PATH. This only
# makes an already-installed toolchain visible -- it never installs anything.
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
# 3. Fetch + verify the pinned server cert over the network (CERT-ONLY)
# ---------------------------------------------------------------------------
Write-Section 'Fetching + verifying the server cert from the server'

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("maxsecu-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$CertTmp = Join-Path $TmpDir 'server_cert.der'

# Offline-D5 inversion: the server is AWAITING delegation and has NO directory_pub
# yet (the D5 root is generated on THIS PC by the ceremony below). So fetch-pins runs
# in CERT-ONLY mode (no --dir-out): it dials the server, downloads server_cert.der,
# and writes it ONLY if pin_fingerprint(cert, &[]) matches the connection-code
# (CERT-only) fingerprint. On any mismatch/network/parse error it writes NOTHING and
# exits non-zero. directory_pub.der is produced later by the ceremony, not here.
if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
        Write-Host "cargo not on PATH; using rustup install at $cargoBin" -ForegroundColor DarkYellow
    }
}

Write-Host "Fetching the server cert from ${ServerAddr}:${Port} and verifying against the fingerprint ..."
& cargo run --release --manifest-path (Join-Path $Root 'tools\maxsecu-setup\Cargo.toml') -- fetch-pins `
    --server "${ServerAddr}:${Port}" `
    --host "$ServerAddr" `
    --fingerprint "$Fingerprint" `
    --cert-out "$CertTmp"
if ($LASTEXITCODE -ne 0) {
    Fail "Fetching/verifying the server cert failed (exit code $LASTEXITCODE). Check that the server at ${ServerAddr}:${Port} is reachable and finished its first run, and that the CERT fingerprint '$Fingerprint' exactly matches the one install-server printed."
}

if (-not (Test-Path $CertTmp)) { Fail "server_cert.der is missing at $CertTmp." }
Write-Host "Server cert fetched + verified, ready in $TmpDir"

# ---------------------------------------------------------------------------
# 4. Offline-D5 ceremony: generate the directory root, install the delegation,
#    create the recovery account + first key, and mint the final connection code.
# ---------------------------------------------------------------------------
Write-Section 'Running the offline-D5 ceremony (maxsecu-setup)'

$RecoveryBlob = Join-Path $Root 'recovery_key.blob'
$RecoveryPin  = Join-Path $Root 'recovery_pin.bin'
$RegisterKey  = Join-Path $Root 'register.key'
# Ceremony artifacts. The directory root (D5) is generated + sealed on THIS PC; its
# public half is pinned into every client. d5_key.blob / d5_recovery.blob default
# alongside --out ($Root) inside maxsecu-setup; directory_pub.der is pinned to a
# stable path so a resumed run (and the dist layout below) can reuse it.
$DirPub       = Join-Path $Root 'directory_pub.der'
# The final user-facing connection code addr:port#fingerprint(server_cert, D5_pub),
# persisted so a resumed run can reprint it without re-running the (once-only) setup.
$ConnCodeFile = Join-Path $Root 'connection_code.txt'
# The public addr:port the minted connection code advertises (what users type). This
# is the parsed dial target, NOT a loopback/WSL address.
$ConnectAddr  = "${ServerAddr}:${Port}"
$FinalConnCode = ''

# RESUMABILITY: maxsecu-setup is once-only and produces IRREPLACEABLE files (its
# preflight refuses to overwrite them, and the server 409s a second register /
# already-delegated). If a prior run already completed the ceremony, those files are
# on disk -- skip setup and resume the build rather than fail. This lets you re-run
# after fixing a later step (e.g. staging ffmpeg) without touching the directory root
# / recovery key / first registration key.
if ((Test-Path $RecoveryBlob) -and (Test-Path $RecoveryPin) -and (Test-Path $RegisterKey) -and (Test-Path $DirPub)) {
    Write-Host 'Ceremony artifacts already present from a prior run -- setup is complete; skipping maxsecu-setup.' -ForegroundColor Yellow
    Write-Host "  $RecoveryBlob"
    Write-Host "  $RecoveryPin"
    Write-Host "  $RegisterKey"
    Write-Host "  $DirPub"
    if (Test-Path $ConnCodeFile) {
        $FinalConnCode = (Get-Content -Path $ConnCodeFile -Raw).Trim()
        Write-Host "  connection code (from $ConnCodeFile): $FinalConnCode"
    } else {
        Write-Host "  (no saved connection_code.txt -- see the final summary note below)" -ForegroundColor DarkYellow
    }
} else {
    # Resolve the one-time delegation token: -Token, else $env:SETUP_DELEGATION_TOKEN,
    # else an interactive prompt. Required -- it authorizes uploading the delegation
    # that opens enrollment. Handed to the child ONLY via SETUP_DELEGATION_TOKEN.
    $PlainToken = $Token
    if ([string]::IsNullOrEmpty($PlainToken)) { $PlainToken = $env:SETUP_DELEGATION_TOKEN }
    if ([string]::IsNullOrEmpty($PlainToken)) {
        Write-Host 'Paste the ONE-TIME delegation token that install-server printed.'
        $PlainToken = (Read-Host 'Delegation token').Trim()
    } else {
        Write-Host 'Using a non-interactively supplied delegation token.' -ForegroundColor DarkYellow
    }
    if ([string]::IsNullOrEmpty($PlainToken)) {
        Fail 'A delegation token is required (install-server printed it). Pass -Token <token> or set $env:SETUP_DELEGATION_TOKEN.'
    }

    # Prefer a non-interactively supplied passphrase (param or env var); fall back to
    # an interactive, non-echoed prompt. The plaintext is handed to the child process
    # ONLY via the SETUP_RECOVERY_PW env var below (never printed, never persisted).
    $PlainPw = $RecoveryPassphrase
    if ([string]::IsNullOrEmpty($PlainPw)) { $PlainPw = $env:SETUP_RECOVERY_PW }
    if ([string]::IsNullOrEmpty($PlainPw)) {
        Write-Host 'Choose a RECOVERY passphrase. Write it down and keep it offline with'
        Write-Host 'recovery_key.blob -- together they are the ONLY way to recover the account'
        Write-Host 'AND the directory root (it also seals the D5 recovery backup).'
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
    $SetupOut  = @()
    $env:SETUP_RECOVERY_PW      = $PlainPw
    $env:SETUP_DELEGATION_TOKEN = $PlainToken
    $env:SETUP_CONNECT_ADDR     = $ConnectAddr
    $env:SETUP_DIR_PUB_OUT      = $DirPub
    try {
        # Capture STDOUT so we can lift the machine-parseable "CONNECTION-CODE <code>"
        # line the ceremony prints; STDERR (progress) still streams to the console.
        $SetupOut = & cargo run --release --manifest-path (Join-Path $Root 'tools\maxsecu-setup\Cargo.toml') -- `
            --server "${ServerAddr}:${Port}" `
            --host "$ServerAddr" `
            --cert "$CertTmp" `
            --out "$RecoveryBlob" `
            --pin-out "$RecoveryPin" `
            --first-key-out "$RegisterKey"
        $SetupExit = $LASTEXITCODE
    } finally {
        # Scrub the secrets/params from the environment and local variables.
        Remove-Item Env:\SETUP_RECOVERY_PW -ErrorAction SilentlyContinue
        Remove-Item Env:\SETUP_DELEGATION_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:\SETUP_CONNECT_ADDR -ErrorAction SilentlyContinue
        Remove-Item Env:\SETUP_DIR_PUB_OUT -ErrorAction SilentlyContinue
        $PlainPw = $null
        $PlainToken = $null
        $RecoveryPassphrase = $null
        $Token = $null
    }

    # Echo the captured setup output so the operator still sees its banner/summary.
    if ($SetupOut) { $SetupOut | ForEach-Object { Write-Host $_ } }

    if ($SetupExit -eq 3) {
        Write-Host ''
        Write-Host 'NOTE: the server is already set up / already delegated (exit code 3).' -ForegroundColor Yellow
        Write-Host '      Nothing was re-registered. Reusing existing artifacts if present.' -ForegroundColor Yellow
        if (-not (Test-Path $RecoveryPin)) {
            Fail "The server is already set up but no existing recovery_pin.bin was found at $RecoveryPin. You need the recovery_pin.bin from the original setup to build a working client."
        }
        if (-not (Test-Path $DirPub)) {
            Fail "The server is already delegated but no existing directory_pub.der was found at $DirPub. You need the directory pin from the original ceremony (or restore the D5 backup with 'maxsecu-setup restore') to build a working client."
        }
        if (Test-Path $ConnCodeFile) {
            $FinalConnCode = (Get-Content -Path $ConnCodeFile -Raw).Trim()
        }
    } elseif ($SetupExit -ne 0) {
        Fail "maxsecu-setup / the D5 ceremony failed (exit code $SetupExit). Check the server address ${ServerAddr}:${Port}, that the cert matches the running server, and that the delegation token is valid and unused."
    } else {
        # Lift the minted connection code from the captured stdout and persist it.
        $ccMatch = $SetupOut | Select-String -Pattern '^\s*CONNECTION-CODE\s+(\S.*)$' | Select-Object -First 1
        if ($null -ne $ccMatch) {
            $FinalConnCode = $ccMatch.Matches[0].Groups[1].Value.Trim()
            [System.IO.File]::WriteAllText($ConnCodeFile, $FinalConnCode + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "Ceremony complete. Final connection code minted: $FinalConnCode" -ForegroundColor Green
        } else {
            Write-Host 'WARNING: setup succeeded but no CONNECTION-CODE line was found in its output.' -ForegroundColor Yellow
        }
        if (-not (Test-Path $DirPub)) {
            Fail "The ceremony reported success but directory_pub.der is missing at $DirPub. Cannot build a working client without the directory pin."
        }
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
    Write-Host 'vendor\ffmpeg\ffmpeg.exe is missing -- fetching the pinned build (scripts\fetch-ffmpeg.ps1) ...'
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
# directory_pub.der is the D5 pin produced by the ceremony above (NOT fetched from the
# server, which never holds the root) -- ship it so the client fails closed to trust it.
Copy-Item -Path $DirPub  -Destination (Join-Path $AdminConfig 'directory_pub.der') -Force

# ADMIN-ONLY: place the sealed directory root (d5_key.blob) beside the pins so the
# running admin client's on-login auto-renew + the renew_delegation command can find
# it. The client resolves it at <app_dir>/config/d5_key.blob (crate::commands::renew::
# d5_blob_path), i.e. dist\MaxSecuClient\config here. Its PRESENCE is what marks THIS
# PC as the directory authority; on any other device (no blob) auto-renew is a silent
# no-op. The ceremony wrote it to the repo root, sealed under the recovery passphrase.
#
# CRITICAL: this copy targets the ADMIN working client ONLY. The handout ZIP is built
# from a SEPARATE staging dir (dist\_share_stage below) whose config copies ONLY
# server_cert.der + directory_pub.der -- d5_key.blob (and d5_recovery.blob) are NEVER
# staged there, so the share ZIP can never leak the directory root. Do NOT add this
# copy to the share-stage block.
#
# Guarded: absent only on an odd resumed/restored run that recovered just the pins;
# renewal is a best-effort admin convenience, so a missing blob is a warning, not a
# failure (users still enroll + use the app fine; renewal just won't run from here).
$D5Blob = Join-Path $Root 'd5_key.blob'
if (Test-Path $D5Blob) {
    Copy-Item -Path $D5Blob -Destination (Join-Path $AdminConfig 'd5_key.blob') -Force
    Write-Host 'Placed d5_key.blob in the admin config (enables in-app delegation auto-renew).'
} else {
    Write-Host 'No d5_key.blob present (not this PC''s original ceremony); in-app auto-renew disabled here.' -ForegroundColor Yellow
}

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
# The ceremony-produced D5 directory pin (see the admin config note above).
Copy-Item -Path $DirPub  -Destination (Join-Path $ShareConfig 'directory_pub.der') -Force

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
Write-Host 'DELEGATION INSTALLED -- enrollment is now OPEN on the server.' -ForegroundColor Green
Write-Host 'The directory root (D5) was generated on THIS PC; the server holds only a'
Write-Host 'short-lived operational key it cannot renew without you.'
Write-Host ''
if (-not [string]::IsNullOrWhiteSpace($FinalConnCode)) {
    Write-Host 'CONNECTION CODE (the final, user-facing code -- this is what you hand out):' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "        $FinalConnCode" -ForegroundColor White
    Write-Host ''
    Write-Host "    Saved to: $ConnCodeFile"
    Write-Host '    Users only need the ADDRESS part (before the "#") plus their registration'
    Write-Host '    key; the pins in the ZIP already commit to this code.'
} else {
    Write-Host 'CONNECTION CODE: (not captured this run -- it was minted on the original run.' -ForegroundColor Yellow
    Write-Host "    See $ConnCodeFile, or re-derive it on the server with 'maxsecu-portable-server"
    Write-Host "    print-fingerprint', or 'maxsecu-setup restore' from the D5 backup.)" -ForegroundColor Yellow
}
Write-Host ''
Write-Host 'RECOVERY (do this now):' -ForegroundColor Yellow
Write-Host '  * Move these files to COLD / OFFLINE storage and never lose them:'
Write-Host "        $RecoveryBlob"
Write-Host "        $(Join-Path $Root 'd5_recovery.blob')   (the directory root backup)"
Write-Host '    Remember the recovery passphrase you just typed. Together they are the'
Write-Host '    ONLY way to recover the account AND the directory root -- there is no backup.'
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
