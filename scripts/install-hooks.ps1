<#
.SYNOPSIS
    Installs the MaxSecu git hooks (one-time, idempotent).

.DESCRIPTION
    Points git at the repo's tracked hooks directory:

        git config core.hooksPath scripts/hooks

    That enables scripts/hooks/pre-push - the BACKWARD-COMPATIBILITY GATE:

        Every upgrade must keep existing users' access intact - account/login,
        keys, and already-uploaded data. No change may force a re-enroll,
        re-key, re-upload, re-share, or reset.

    Because the hooks live in the repo (not .git/hooks), everyone who runs this
    once gets every future hook automatically.

.EXAMPLE
    powershell -File scripts/install-hooks.ps1

.NOTES
    PowerShell 5.1 compatible: no '&&'/'||', no ternary, no null-coalescing.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Write-Rule {
    Write-Host '---------------------------------------------------------------------------'
}

$hooksPath = 'scripts/hooks'
$prePush = Join-Path $repoRoot 'scripts\hooks\pre-push'

Write-Rule
Write-Host 'MaxSecu git hooks'
Write-Rule

if (-not (Test-Path -LiteralPath $prePush)) {
    Write-Host "FAIL - $prePush not found. Are you in the repo root?" -ForegroundColor Red
    exit 1
}

$current = & git config --local core.hooksPath
if ($LASTEXITCODE -eq 0 -and $current -eq $hooksPath) {
    Write-Host "Already installed: core.hooksPath = $current"
} else {
    & git config --local core.hooksPath $hooksPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'FAIL - `git config core.hooksPath` returned non-zero.' -ForegroundColor Red
        exit 1
    }
    Write-Host "Installed: core.hooksPath = $hooksPath"
}

# Verify it took (never trust, verify).
$verify = & git config core.hooksPath
if ($LASTEXITCODE -ne 0 -or $verify -ne $hooksPath) {
    Write-Host "FAIL - verification failed: core.hooksPath is '$verify', expected '$hooksPath'." -ForegroundColor Red
    exit 1
}

Write-Host "Verified:  git config core.hooksPath -> $verify" -ForegroundColor Green
Write-Host ''
Write-Host 'Active hooks:'
Write-Host '  pre-push   the backward-compatibility gate. Blocks a push whose code can no'
Write-Host "             longer open bytes that an existing user's client already wrote."
Write-Host ''
Write-Rule
Write-Host 'Run the gate manually (do this before every push):'
Write-Host '  powershell -File scripts/compat-gate.ps1'
Write-Host ''
Write-Host 'Review a working diff against the rule before you even commit:'
Write-Host '  /compat-check      (Claude Code slash command)'
Write-Host ''
Write-Host 'Read the rules of engagement:'
Write-Host '  docs/compat/CHECKLIST.md    how to evolve a format without stranding a user'
Write-Host '  docs/compat/LEDGER.md       the append-only record of format changes'
Write-Host ''
Write-Host 'Emergency bypass (loud, and CI will still catch you):'
Write-Host '  SKIP_COMPAT_GATE=1 git push        (bash)'
Write-Host '  $env:SKIP_COMPAT_GATE=1; git push  (PowerShell)'
Write-Host ''
Write-Host 'Uninstall:'
Write-Host '  git config --unset core.hooksPath'
Write-Rule
exit 0
