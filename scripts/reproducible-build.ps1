# Reproducible-build check (Windows MSVC) — best-effort, NOT a hard gate.
#
# Builds a release binary twice in isolated target dirs with deterministic flags
# and compares SHA-256. Unlike the Linux path (scripts/reproducible-build.sh,
# the artifact-of-record), Windows PE output is only best-effort reproducible:
# the PE header carries a TimeDateStamp and the MSVC linker may embed a build
# GUID, so two builds can differ even when the code is identical. The linker
# flag /Brepro replaces the timestamp with a content hash; pass it via RUSTFLAGS
# (-C link-arg=/Brepro) below. Residual non-determinism on Windows is documented
# in docs/reproducible-builds.md and is why the LINUX musl build is the
# reproducible artifact of record (stack.md §5.1).
#
# Usage:  pwsh scripts/reproducible-build.ps1 [crate] [bin]
param(
    [string]$Crate = "maxsecu-media-worker",
    [string]$Bin   = "media-worker"
)
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $RepoRoot

$env:SOURCE_DATE_EPOCH = "1700000000"
$env:CARGO_INCREMENTAL = "0"
$commonRemap = "--remap-path-prefix=$RepoRoot=/src"

function Build-Into($outDir) {
    if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
    $env:CARGO_TARGET_DIR = $outDir
    # /Brepro: deterministic PE timestamp. Path remap maps each isolated target
    # dir to the same logical /target so the dir name can't leak into the bytes.
    $env:RUSTFLAGS = "$commonRemap --remap-path-prefix=$outDir=/target -C link-arg=/Brepro"
    cargo build --release --locked -p $Crate --bin $Bin
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $outDir" }
    return Join-Path $outDir "release\$Bin.exe"
}

Write-Output "Reproducible-build check (Windows, best-effort): $Crate :: $Bin"
$aBin = Build-Into "$RepoRoot\target-repro-a"
$bBin = Build-Into "$RepoRoot\target-repro-b"

$aSha = (Get-FileHash $aBin -Algorithm SHA256).Hash
$bSha = (Get-FileHash $bBin -Algorithm SHA256).Hash
Write-Output "build A: $aSha  ($aBin)"
Write-Output "build B: $bSha  ($bBin)"

if ($aSha -eq $bSha) {
    Write-Output "REPRODUCIBLE (Windows): identical SHA-256 ($aSha)"
    exit 0
} else {
    Write-Output "Windows PE differs (expected without full toolchain determinism) — see docs/reproducible-builds.md. The Linux musl build is the artifact of record."
    exit 0  # best-effort: a Windows PE difference is NOT a CI failure
}
