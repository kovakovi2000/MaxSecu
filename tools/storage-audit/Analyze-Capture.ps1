<#
.SYNOPSIS
  Flag any of OUR client's writes that land OUTSIDE the portable <app_dir> folder.
.DESCRIPTION
  Parses a Process Monitor CSV export and reports successful file writes by the
  client (maxsecu.exe) and its OWN WebView2 children whose target path is not under
  -AppDir. Key refinements learned from real captures:

    * Attribution by PID, not just image name. The WebView2 host image name
      (msedgewebview2.exe) is shared by every WebView2 app on the machine, so a
      bare name filter catches OTHER apps' hosts. We treat as "ours" only:
        - every maxsecu.exe PID, and
        - every msedgewebview2.exe PID that wrote at least once INTO <app_dir>
          (i.e. into our redirected <app_dir>\webview data folder).
      Writes by any other PID sharing the name are ignored.

    * NTFS pseudo-files are excluded. Writes to `X:\$LogFile`, `X:\$Mft`,
      `X:\$Extend\$Deleted\...`, `X:\$ConvertToNonresident`, or a bare volume root
      (`X:` / `X:\`) are the filesystem's own journal/metadata for our IN-folder
      writes — not out-of-folder data.

    * Genuine app-data leaks are separated from shared-runtime/driver bookkeeping.
      The WebView2/Edge runtime and the GPU driver write a fixed set of operational
      files outside any app folder (GPU shader cache, the Edge identity broker,
      runtime temp). These contain no app user data and are outside an app's control
      (the `data_directory` override does not cover them). They are reported, but do
      NOT fail the audit. PASS requires zero writes in the GENUINE bucket.

  Requires the CSV to include the default columns incl. `Process Name`, `PID`,
  `Operation`, `Path`, `Result`, `Detail`.
.EXAMPLE
  ./Analyze-Capture.ps1 -Csv capture1.csv -AppDir 'D:\scrs\programs\MaxSecu\.audit-run'
#>
param(
  [Parameter(Mandatory)] [string]$Csv,
  [Parameter(Mandatory)] [string]$AppDir,
  # Image names that MAY be ours. maxsecu.exe is always ours; a webview host counts
  # only if its PID also wrote into <app_dir> (see description).
  [string[]]$ProcessNames = @('maxsecu.exe','msedgewebview2.exe')
)

$app = (Resolve-Path $AppDir).Path.TrimEnd('\').ToLowerInvariant()
$procNames = $ProcessNames | ForEach-Object { $_.ToLowerInvariant() }
$writeOps  = @(
  'WriteFile','SetRenameInformationFile','SetEndOfFileInformationFile',
  'SetAllocationInformationFile','RegSetValue','RegCreateKey'
)

# Known shared-runtime / GPU-driver bookkeeping written OUTSIDE any app folder.
# Regexes matched against the lowercased path. These are expected and app-uncontrollable.
$benignPatterns = @(
  '\\nvidia\b',                                  # per-user NVIDIA GPU shader cache dirs
  'nvidia corporation',                          # %ProgramData% / driver NVIDIA profile store
  '\\d3dscache\\',                               # OS DirectX pipeline/shader cache (GPU process; compiled shader blobs, no user data)
  '\\explorer\\iconcache',                       # Windows shell icon cache — touched by the native file open/save dialog, global OS bookkeeping
  '\\microsoft\\oneauth\\',                      # Edge/WebView2 runtime identity broker
  '\\temp\\webview2downloads',                   # WebView2 runtime download temp
  '\\temp\\msedge_',                             # WebView2/Edge runtime temp
  '\\edgewebview\\application\\'                  # DLLs loaded from the shared runtime install
)

function Test-NtfsPseudo([string]$p) {
  return ($p -match '^[A-Za-z]:\\?$') -or ($p -match '^[A-Za-z]:\\\$')
}
function Test-Benign([string]$low) {
  foreach ($b in $benignPatterns) { if ($low -match $b) { return $true } }
  return $false
}
function Test-Write($row) {
  $op = $row.Operation
  if ($writeOps -contains $op) { return $true }
  return ($op -eq 'CreateFile' -and $row.Detail -match 'Disposition:\s*(Create|Overwrite|Supersede|OpenIf|OverwriteIf)')
}

# Pass 1 — establish OUR PID set: all maxsecu.exe PIDs, plus any webview-host PID
# that wrote into <app_dir>.
$ourPids = @{}
Import-Csv -Path $Csv | ForEach-Object {
  $pn = $_.'Process Name'; if (-not $pn) { return }
  $pn = $pn.ToLowerInvariant(); if ($procNames -notcontains $pn) { return }
  if ($pn -eq 'maxsecu.exe') { $ourPids[$_.PID] = 1; return }
  $p = $_.Path; if ($p -and $p.ToLowerInvariant().StartsWith($app)) { $ourPids[$_.PID] = 1 }
}

# Pass 2 — flag out-of-folder file writes by our PIDs, bucketed.
$leak = @{}; $benign = @{}; $temp = @{}
Import-Csv -Path $Csv | ForEach-Object {
  $pn = $_.'Process Name'; if (-not $pn) { return }
  $pn = $pn.ToLowerInvariant(); if ($procNames -notcontains $pn) { return }
  if (-not $ourPids[$_.PID]) { return }          # foreign PID sharing the image name
  if ($_.Result -ne 'SUCCESS') { return }
  if (-not (Test-Write $_)) { return }
  $p = $_.Path; if ([string]::IsNullOrEmpty($p)) { return }
  if ($p -like 'HK*') { return }                 # registry = runtime/OS bookkeeping, out of scope for data-at-rest
  $low = $p.ToLowerInvariant()
  if ($low.StartsWith($app)) { return }          # in-folder: OK
  if (Test-NtfsPseudo $p) { return }             # NTFS journal/metadata for in-folder writes
  if (Test-Benign $low) { $benign[$p] = 1 + $benign[$p] }
  elseif ($low -match '\\(appdata\\local|windows)\\temp\\') { $temp[$p] = 1 + $temp[$p] }  # runtime temp scratch
  else { $leak[$p] = 1 + $leak[$p] }
}

"Our PID set (maxsecu.exe + webview children that wrote in-folder): $((@($ourPids.Keys)) -join ', ')"
""
"== GENUINE out-of-folder app-data writes (must be zero for PASS): $($leak.Count) distinct =="
if ($leak.Count -eq 0) { "  (none)" } else {
  $leak.GetEnumerator() | Sort-Object Value -Descending |
    ForEach-Object { "  [{0,5}x] {1}" -f $_.Value, $_.Key }
}
""
"== Shared WebView2-runtime / GPU-driver bookkeeping (expected; no app user data): $($benign.Count) distinct =="
if ($benign.Count -eq 0) { "  (none)" } else {
  $benign.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 30 |
    ForEach-Object { "  [{0,5}x] {1}" -f $_.Value, $_.Key }
}
""
"== Runtime temp scratch (%TEMP%; review, does not fail): $($temp.Count) distinct =="
if ($temp.Count -eq 0) { "  (none)" } else {
  $temp.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 |
    ForEach-Object { "  [{0,5}x] {1}" -f $_.Value, $_.Key }
}
""
if ($leak.Count -eq 0) {
  "RESULT: PASS - no app-data write landed outside $AppDir (only shared-runtime/driver bookkeeping remains)."
  exit 0
} else {
  "RESULT: FAIL - $($leak.Count) app-data path(s) outside $AppDir (see GENUINE list above)."
  exit 1
}
