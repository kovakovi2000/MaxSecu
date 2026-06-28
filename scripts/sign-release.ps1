# Authenticode release signing (DESIGN §8 control 4 / D1; stack.md §1.5, §5.2).
#
# Signs a released Windows binary with the offline code-signing certificate and
# verifies the signature. The certificate is referenced ONLY by thumbprint (from
# the machine/offline cert store or an HSM/secret manager) — it is NEVER passed
# inline, embedded, or written to the repo/CI logs (§16.6: no secrets in source,
# bundles, env, or logs). Pair with docs/runbooks/release-signing.md (the full
# sign → manifest → transparency-log → client-verify flow).
#
# Usage:
#   pwsh scripts/sign-release.ps1 -File path\to\app.exe -Thumbprint <CERT_SHA1_THUMBPRINT> [-TimestampUrl <rfc3161-url>]
#
# Prerequisites: signtool.exe on PATH (Windows SDK), the signing cert present in
# the cert store addressed by -Thumbprint (a USB/HSM-backed key is recommended;
# the private key never leaves the token).
param(
    [Parameter(Mandatory = $true)][string]$File,
    [Parameter(Mandatory = $true)][string]$Thumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$Digest = "SHA256"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $File)) { throw "Artifact not found: $File" }

# Guardrail: a thumbprint is 40 hex chars. A value that looks like a path or a
# PFX/password is a refusal — we sign by store reference only, never inline cred.
$tp = $Thumbprint -replace '\s', ''
if ($tp -notmatch '^[0-9A-Fa-f]{40}$') {
    throw "Refusing to sign: -Thumbprint must be a 40-hex-char cert thumbprint (sign by store reference only; never pass a PFX/password/path)."
}

$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)
if ($null -eq $signtool) { throw "signtool.exe not found on PATH (install the Windows SDK)." }

Write-Output "Signing $File with cert $tp (timestamp: $TimestampUrl) ..."
& $signtool.Source sign /sha1 $tp /fd $Digest /tr $TimestampUrl /td $Digest $File
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE)." }

Write-Output "Verifying signature ..."
& $signtool.Source verify /pa /v $File
if ($LASTEXITCODE -ne 0) { throw "signtool verify failed (exit $LASTEXITCODE) — the artifact is NOT validly signed." }

$sha = (Get-FileHash $File -Algorithm SHA256).Hash
Write-Output "SIGNED + VERIFIED: $File"
Write-Output "artifact_sha256 = $sha"
Write-Output "Next: record this SHA-256 in the signed UpdateManifest and submit it to the transparency log (docs/runbooks/release-signing.md)."
