<#
.SYNOPSIS
  Flag any client write that lands OUTSIDE the portable <app_dir> folder.
.DESCRIPTION
  Parses a Process Monitor CSV export and reports successful write/create/registry
  operations by MaxSecu.exe and its msedgewebview2.exe children whose target path is
  not under -AppDir. Prints a PASS/FAIL summary and the annotated residual list.
.EXAMPLE
  ./Analyze-Capture.ps1 -Csv capture.csv -AppDir 'D:\MaxSecuClient'
#>
param(
  [Parameter(Mandatory)] [string]$Csv,
  [Parameter(Mandatory)] [string]$AppDir
)

$app = (Resolve-Path $AppDir).Path.TrimEnd('\').ToLowerInvariant()
$procNames = @('maxsecu.exe','msedgewebview2.exe')
$writeOps  = @(
  'WriteFile','SetRenameInformationFile','SetEndOfFileInformationFile',
  'SetAllocationInformationFile','RegSetValue','RegCreateKey'
)

$rows = Import-Csv -Path $Csv
$flagged = foreach ($r in $rows) {
  $proc = ($r.'Process Name').ToLowerInvariant()
  if ($procNames -notcontains $proc) { continue }
  if ($r.Result -ne 'SUCCESS') { continue }
  $op = $r.Operation
  # CreateFile counts only when it actually creates/writes (Detail names the disposition).
  $isWrite = ($writeOps -contains $op) -or
             ($op -eq 'CreateFile' -and $r.Detail -match 'Disposition:\s*(Create|Overwrite|Supersede|OpenIf|OverwriteIf)')
  if (-not $isWrite) { continue }
  $path = $r.Path
  if ([string]::IsNullOrEmpty($path)) { continue }
  $isRegistry = $path -like 'HK*'
  $lower = $path.ToLowerInvariant()
  if (-not $isRegistry -and $lower.StartsWith($app)) { continue }  # inside the folder: OK
  $kind = if ($isRegistry) {'REGISTRY'} else {'FILE'}
  [pscustomobject]@{ Kind = $kind; Process = $proc; Operation = $op; Path = $path }
}

$fileHits = @($flagged | Where-Object Kind -eq 'FILE')
$regHits  = @($flagged | Where-Object Kind -eq 'REGISTRY')

"== Out-of-folder FILE writes (must be zero for PASS) =="
if ($fileHits.Count -eq 0) { "  (none)" } else {
  $fileHits | Group-Object Path | Sort-Object Count -Descending |
    ForEach-Object { "  [{0,4}x] {1}" -f $_.Count, $_.Name }
}
""
"== Registry writes (review; shared-WebView2-runtime bookkeeping is expected) =="
if ($regHits.Count -eq 0) { "  (none)" } else {
  $regHits | Group-Object Path | Sort-Object Count -Descending |
    ForEach-Object { "  [{0,4}x] {1}" -f $_.Count, $_.Name }
}
""
if ($fileHits.Count -eq 0) {
  "RESULT: PASS — no client file write landed outside $AppDir."
  exit 0
} else {
  "RESULT: FAIL — $($fileHits.Count) file write(s) landed outside $AppDir (see above)."
  exit 1
}
