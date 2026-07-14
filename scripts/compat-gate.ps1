<#
.SYNOPSIS
    Runs the MaxSecu BACKWARD-COMPATIBILITY GATE (both cargo workspaces).

.DESCRIPTION
    The rule this enforces:

        Every upgrade must keep existing users' access intact — account/login,
        keys, and already-uploaded data. No change may force a re-enroll,
        re-key, re-upload, re-share, or reset.

    This is the manual runner. The SAME gate runs automatically from
    scripts/hooks/pre-push (install once with scripts/install-hooks.ps1) and in
    the `compat` job of .github/workflows/ci.yml. Keep all three in sync.

    It is offline and deterministic: no Postgres, no network. The
    schema-equivalence test skips itself without DATABASE_URL and runs for real
    in the CI pg-gate job.

    A MISSING test target is a FAILURE, not a pass. A gate whose tests have
    vanished proves nothing, and a green run would be a lie.

.PARAMETER RootOnly
    Run only the root-workspace half (skip the heavy client-workspace build).
    Use while iterating; the full gate still runs on push.

.EXAMPLE
    powershell -File scripts/compat-gate.ps1

.NOTES
    PowerShell 5.1 compatible: no '&&'/'||', no ternary, no null-coalescing.
#>
[CmdletBinding()]
param(
    [switch]$RootOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$RULE = "Every upgrade must keep existing users' access intact - account/login, keys, and already-uploaded data. No change may force a re-enroll, re-key, re-upload, re-share, or reset."

# cargo is not on the default PATH in this environment.
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Write-Rule {
    Write-Host '---------------------------------------------------------------------------'
}

Write-Rule
Write-Host 'MaxSecu backward-compatibility gate'
Write-Rule
Write-Host $RULE
Write-Host ''

# ---------------------------------------------------------------------------
# Preflight: cargo, and the test targets that ARE the gate.
# ---------------------------------------------------------------------------
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargo) {
    Write-Rule
    Write-Host 'FAIL - cargo not found.' -ForegroundColor Red
    Write-Host 'Looked on PATH and in %USERPROFILE%\.cargo\bin. The gate cannot run, so it'
    Write-Host 'cannot pass.'
    Write-Rule
    exit 1
}

# Root workspace: crate `maxsecu-compat` (crates/compat).
$rootTargets = @(
    'crates/compat/tests/value_locks.rs',
    'crates/compat/tests/golden_open.rs',
    'crates/compat/tests/interop_matrix.rs',
    'crates/compat/tests/http_wire.rs',
    'crates/compat/tests/schema_equivalence.rs'
)
# Client workspace (excluded from the normal CI test job — this is the hole the
# gate closes: keyblob, recovery pin, settings.json, TOFU pins).
$clientTarget = 'crates/client-app/tests/compat.rs'

$expected = @()
$expected += $rootTargets
if (-not $RootOnly) { $expected += $clientTarget }

$missing = @()
foreach ($t in $expected) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $t))) { $missing += $t }
}

if ($missing.Count -gt 0) {
    Write-Rule
    Write-Host 'FAIL - compat gate INCOMPLETE: expected test target(s) missing.' -ForegroundColor Red
    Write-Rule
    foreach ($t in $missing) { Write-Host "    $t" }
    Write-Host ''
    Write-Host 'These targets ARE the gate. Missing is NOT passing: with them gone, nothing'
    Write-Host "proves that an existing user's keyblob, wraps or uploads still open."
    Write-Host 'Restore them - or, if a target was deliberately renamed, update'
    Write-Host 'scripts/compat-gate.ps1, scripts/hooks/pre-push and the `compat` job in'
    Write-Host '.github/workflows/ci.yml together.'
    Write-Rule
    exit 1
}

# ---------------------------------------------------------------------------
# The gate.
# ---------------------------------------------------------------------------
$results = @()
$failed = $false

Write-Host '==> [1/2] root workspace'
Write-Host '    cargo test -p maxsecu-compat --locked'
Write-Host ''
& cargo test -p maxsecu-compat --locked
if ($LASTEXITCODE -eq 0) {
    $results += [pscustomobject]@{ Workspace = 'root (maxsecu-compat)'; Status = 'PASS' }
} else {
    $results += [pscustomobject]@{ Workspace = 'root (maxsecu-compat)'; Status = 'FAIL' }
    $failed = $true
}

if ($RootOnly) {
    $results += [pscustomobject]@{ Workspace = 'client (client-app)'; Status = 'SKIPPED (-RootOnly)' }
} else {
    Write-Host ''
    Write-Host '==> [2/2] client workspace (the CI-excluded one)'
    Write-Host '    cargo test --manifest-path crates/client-app/Cargo.toml --locked --no-default-features --features unpinned-dev --test compat'
    Write-Host ''
    # --no-default-features: skip `embed-ffmpeg` (the vendored ffmpeg.exe is
    #   gitignored, so it is absent in CI and the gate must not depend on it).
    # --features unpinned-dev: build.rs fails CLOSED without a real
    #   recovery_pin.bin; the test pin is the documented test-only path.
    & cargo test --manifest-path crates/client-app/Cargo.toml --locked `
        --no-default-features --features unpinned-dev --test compat
    if ($LASTEXITCODE -eq 0) {
        $results += [pscustomobject]@{ Workspace = 'client (client-app)'; Status = 'PASS' }
    } else {
        $results += [pscustomobject]@{ Workspace = 'client (client-app)'; Status = 'FAIL' }
        $failed = $true
    }
}

Write-Host ''
Write-Rule
Write-Host 'compat gate summary'
Write-Rule
foreach ($r in $results) {
    Write-Host ("  {0,-24} {1}" -f $r.Workspace, $r.Status)
}
Write-Host ''

if ($failed) {
    Write-Host 'GATE FAILED.' -ForegroundColor Red
    Write-Host ''
    Write-Host 'A failing compat test does not mean a test is stale. It means bytes an'
    Write-Host "EXISTING USER'S CLIENT ALREADY WROTE - their keyblob, their DEK wraps, their"
    Write-Host 'uploaded chunks, their pins - can no longer be opened by this code. On a real'
    Write-Host 'deployment that is a permanent, unrecoverable loss of access.'
    Write-Host ''
    Write-Host 'Editing the fixture is NEVER the fix. Read docs/compat/CHECKLIST.md.'
    Write-Rule
    exit 1
}

Write-Host "GATE PASSED - yesterday's bytes still open today." -ForegroundColor Green
Write-Rule
exit 0
