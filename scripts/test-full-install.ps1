<#
.SYNOPSIS
    Unattended full-install / reinstall E2E test for MaxSecu.
.DESCRIPTION
    Provisions a throwaway WSL Ubuntu-22.04 distro, installs the server via the real
    install-server.sh, builds the client via install-client.ps1, runs the headless
    live-smoke oracle against the live pair, then exercises the reset+reinstall path
    and re-runs the oracle, and finally tears everything down. Fail-fast with a
    try/finally that always unregisters the distro and resets the client.
.PARAMETER Port           Server listen port (default 8443).
.PARAMETER KeepOnFailure  Skip teardown on failure (for debugging).
.PARAMETER Iterations     Number of back-to-back clean passes (default 1).
#>
[CmdletBinding()]
param(
    [int]    $Port = 8443,
    [switch] $KeepOnFailure,
    [int]    $Iterations = 1
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1's progress stream can overflow the script call stack on
# large operations (notably Invoke-WebRequest); silence it globally.
$ProgressPreference = 'SilentlyContinue'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Stamp = Get-Date -Format 'yyyyMMddHHmmss'
$Distro = "maxsecu-test-$Stamp"
$WorkDir = Join-Path $env:TEMP "maxsecu-test-$Stamp"
$RootFsCache = Join-Path $env:LOCALAPPDATA 'maxsecu-test\ubuntu-22.04-rootfs.tar.gz'
$RecoveryPw = "livesmoke-recovery-$Stamp!"

function Phase($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Die($t)   { Write-Host "FAIL: $t" -ForegroundColor Red; throw $t }

# Run a command inside the distro as the default user; throws on non-zero exit.
# NB: the executable is invoked as `wsl.exe` (never bare `wsl`) throughout this
# script — PowerShell resolves functions before executables, so a function named
# `Wsl` + a bare `& wsl` would recurse into the function until the stack overflows.
function Invoke-WslCmd($cmd) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & wsl.exe -d $Distro -- bash -lc $cmd 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    foreach ($line in ($out -split "`r?`n")) { if ($line) { Write-Host "  [wsl] $line" } }
    if ($code -ne 0) { Die "wsl command failed ($code): $cmd" }
    return $out
}

function Provision-Wsl {
    Phase "Provision WSL distro $Distro"
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $installDir = Join-Path $WorkDir 'distro'
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    if (-not (Test-Path $RootFsCache)) {
        Write-Host "  Downloading Ubuntu 22.04 rootfs (one-time cache)..."
        New-Item -ItemType Directory -Path (Split-Path $RootFsCache) -Force | Out-Null
        $url = 'https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-ubuntu22.04lts.rootfs.tar.gz'
        $tmp = "$RootFsCache.partial"
        if (Test-Path $tmp) { Remove-Item -Force $tmp }
        # Use curl.exe (ships with Windows 10/11): it streams straight to disk with
        # no in-memory buffering and no PowerShell progress records, avoiding the
        # Invoke-WebRequest call-depth overflow on large downloads under PS 5.1.
        & curl.exe -fSL --retry 3 -o $tmp $url
        if ($LASTEXITCODE -ne 0) { Die "rootfs download failed (curl exit $LASTEXITCODE)" }
        if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -lt 1000000) {
            Die "rootfs download failed or is implausibly small"
        }
        Move-Item -Force $tmp $RootFsCache
    }

    & wsl.exe --import $Distro $installDir $RootFsCache --version 2
    if ($LASTEXITCODE -ne 0) { Die "wsl --import failed" }

    # Enable systemd (needed for the maxsecu-server systemd unit + postgresql).
    & wsl.exe -d $Distro -- bash -lc "printf '[boot]\nsystemd=true\n' | tee /etc/wsl.conf >/dev/null"
    & wsl.exe --terminate $Distro
    Start-Sleep -Seconds 2

    # Wait for systemd to reach running/degraded (degraded is fine — some units inactive).
    $ok = $false
    $state = ''
    for ($i = 0; $i -lt 60; $i++) {
        $state = (& wsl.exe -d $Distro -- bash -lc 'systemctl is-system-running 2>/dev/null')
        if ($state -match 'running|degraded') { $ok = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ok) { Die "systemd did not come up in the distro" }
    Write-Host "  distro up (systemd: $state)"
}

function Copy-Source {
    Phase "Copy source into the distro"
    $stage = Join-Path $WorkDir 'src'
    $exclude = @('target', 'node_modules', 'dist', '.git', 'webview', 'tmp')
    & robocopy $Root $stage /MIR /XD @exclude /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Die "robocopy of source failed ($LASTEXITCODE)" }
    $wslStage = (& wsl.exe -d $Distro -- wslpath -a ($stage -replace '\\','/'))
    if ($LASTEXITCODE -ne 0) { Die "wslpath translation failed" }
    Invoke-WslCmd "rm -rf ~/maxsecu && cp -r '$($wslStage.Trim())' ~/maxsecu && chmod +x ~/maxsecu/scripts/*.sh"
}

# mode: 'install' (returns the connection code) or 'reset' (returns $null).
function Install-Server([string]$mode) {
    Phase "Install server ($mode)"
    if ($mode -eq 'reset') {
        Invoke-WslCmd "cd ~/maxsecu && ./scripts/install-server.sh --reset --port $Port"
        return $null
    }
    $wslIp = (Invoke-WslCmd "hostname -I | awk '{print `$1}'").Trim()
    if (-not $wslIp) { Die "could not determine WSL IP" }
    Write-Host "  WSL IP: $wslIp"
    $log = Invoke-WslCmd "cd ~/maxsecu && ./scripts/install-server.sh --public $wslIp --port $Port --no-dropbox"
    $m = [regex]::Match($log, '(?m)^\s*([0-9.]+:[0-9]+#\S+)\s*$')
    if (-not $m.Success) { Die "could not parse the connection code from install-server output" }
    $code = $m.Groups[1].Value
    Write-Host "  connection code: $code"
    return $code
}

function Build-Client([string]$code) {
    Phase "Build client"
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') `
        -ConnectionCode $code -RecoveryPassphrase $RecoveryPw
    if ($LASTEXITCODE -ne 0) { Die "install-client.ps1 failed ($LASTEXITCODE)" }
}

function Run-Smoke([string]$code) {
    Phase "Run live-smoke oracle"
    $addr = ($code -split '#')[0]
    $ip = ($addr -split ':')[0]
    $clientDir = Join-Path $Root 'dist\MaxSecuClient'
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    & cargo run --release -p maxsecu-live-smoke --manifest-path (Join-Path $Root 'crates\client-app\Cargo.toml') -- `
        --server $addr --host $ip --client-dir $clientDir
    if ($LASTEXITCODE -ne 0) { Die "live-smoke failed ($LASTEXITCODE)" }
}

function Teardown {
    Phase "Teardown"
    try { & wsl.exe --terminate $Distro 2>$null } catch {}
    Start-Sleep -Seconds 1
    $unreg = $false
    for ($i = 0; $i -lt 5; $i++) {
        & wsl.exe --unregister $Distro 2>$null
        if ($LASTEXITCODE -eq 0) { $unreg = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $unreg) {
        Write-Host "  WARNING: could not unregister distro '$Distro' - remove it manually: wsl --unregister $Distro" -ForegroundColor Yellow
    }
    try {
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
    } catch { Write-Host "  client reset warning: $_" -ForegroundColor DarkYellow }
    if (Test-Path $WorkDir) {
        for ($i = 0; $i -lt 3; $i++) {
            Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
            if (-not (Test-Path $WorkDir)) { break }
            Start-Sleep -Seconds 2
        }
        if (Test-Path $WorkDir) {
            Write-Host "  WARNING: could not fully remove $WorkDir - delete it manually." -ForegroundColor Yellow
        }
    }
    Write-Host "  teardown complete"
}

$failed = $false
try {
    # Guarantee a clean client state regardless of what a prior run (or prior local
    # work) left in the repo root — otherwise install-client.ps1's resumability would
    # reuse a stale recovery_pin.bin/register.key and bind to the wrong server.
    Write-Host "==== Pre-clean client state ===="  -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null

    for ($iter = 1; $iter -le $Iterations; $iter++) {
        Phase "PASS $iter of $Iterations"
        Provision-Wsl
        Copy-Source
        $code = Install-Server 'install'
        Build-Client $code
        Run-Smoke $code

        Phase "Reset + reinstall path"
        Install-Server 'reset' | Out-Null
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
        $code2 = Install-Server 'install'
        Build-Client $code2
        Run-Smoke $code2

        Teardown
    }
    Write-Host "`nALL PASSES GREEN ($Iterations)" -ForegroundColor Green
}
catch {
    $failed = $true
    Write-Host "`nHARNESS FAILED: $_" -ForegroundColor Red
    Write-Host "  at: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkRed
    Write-Host "  stack: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    if ($KeepOnFailure) {
        Write-Host "-KeepOnFailure set: leaving distro '$Distro' and '$WorkDir' for debugging." -ForegroundColor Yellow
        Write-Host "  Server logs:  wsl -d $Distro -- journalctl -u maxsecu-server -e" -ForegroundColor Yellow
    } else {
        Teardown
    }
    exit 1
}
