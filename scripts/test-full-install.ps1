<#
.SYNOPSIS
    Unattended full-install / reinstall E2E test for MaxSecu.
.DESCRIPTION
    Provisions a throwaway WSL Ubuntu-22.04 distro, installs the server via the real
    install-server.sh, builds the client via install-client.ps1, runs the headless
    live-smoke oracle against the live pair, then exercises the reset+reinstall path
    and re-runs the oracle, and finally tears everything down. Fail-fast; on
    completion OR failure it tears down (unregisters the distro + resets the client)
    unless -KeepOnFailure is set, which leaves the distro up for debugging.
.PARAMETER Port           Server listen port (default 18443).
.PARAMETER KeepOnFailure  Skip teardown on failure (for debugging).
.PARAMETER Iterations     Number of back-to-back clean passes (default 1).
#>
[CmdletBinding()]
param(
    # Default off the common 8443 so the WSL server doesn't collide with a host
    # service on that port. Under WSL2 mirrored networking the distro shares the
    # host's stack, so a host listener on 8443 makes the server's 0.0.0.0:8443 bind
    # fail with EADDRINUSE. Override with -Port if 18443 is also taken.
    [int]    $Port = 18443,
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
$RecoveryPw = "livesmoke-recovery-$Stamp!"

# The WSL provision / install / build / smoke / teardown helpers live in a shared
# library so scripts/test-backup-rollback.ps1 reuses the exact same bodies. DOT-SOURCE
# it (a dot-sourced file's $script: scope IS ours -- never `& file.ps1`), then
# Initialize-WslHarness publishes the closed-over vars ($Root/$Distro/$WorkDir/$Port/
# $RecoveryPw/$RootFsCache/$KeepAlive) into this scope for the helpers to read.
. (Join-Path $PSScriptRoot 'lib\wsl-harness.ps1')
Initialize-WslHarness -RepoRoot $Root -DistroName $Distro -WorkingDir $WorkDir `
    -ServerPort $Port -RecoveryPassphrase $RecoveryPw

try {
    # Guarantee a clean client state regardless of what a prior run (or prior local
    # work) left in the repo root -- otherwise install-client.ps1's resumability would
    # reuse a stale recovery_pin.bin/register.key and bind to the wrong server.
    Write-Host "==== Pre-clean client state ===="  -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null

    for ($iter = 1; $iter -le $Iterations; $iter++) {
        Phase "PASS $iter of $Iterations"
        Provision-Wsl
        Copy-Source
        $srv = Install-Server 'install'
        Build-Client $srv
        Confirm-EnrollmentOpen
        Run-Smoke $srv

        Phase "Reset + reinstall path"
        Install-Server 'reset' | Out-Null
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
        $srv2 = Install-Server 'install'
        Build-Client $srv2
        Confirm-EnrollmentOpen
        Run-Smoke $srv2

        Teardown
    }
    Write-Host "`nALL PASSES GREEN ($Iterations)" -ForegroundColor Green
}
catch {
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
