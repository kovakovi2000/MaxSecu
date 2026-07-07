<#
.SYNOPSIS
  Finish a Process Monitor capture and analyze it (phase 2 of 2).
.DESCRIPTION
  Terminates the running Procmon, WAITS for the process to fully exit (so the .pml
  backing file is flushed and unlocked — converting too early is what produced the
  "Unable to open .pml" / "no items to be saved" errors before), converts the .pml
  to CSV, then runs Analyze-Capture.ps1 against <AppDir>.

  Must run from the SAME elevated PowerShell context as Start-Capture.ps1.
.EXAMPLE
  .\Stop-Capture.ps1 -Name capture2
#>
param(
  [string]$Procmon = 'D:\scrs\programs\MaxSecu\ProcessMonitor\Procmon.exe',
  [string]$OutDir  = 'D:\scrs\programs\MaxSecu\.audit-run',
  [string]$Name    = 'capture2',
  [string]$AppDir  = 'D:\scrs\programs\MaxSecu\.audit-run'
)

$ErrorActionPreference = 'Stop'
$pml = Join-Path $OutDir "$Name.pml"
$csv = Join-Path $OutDir "$Name.csv"

Write-Host "Terminating Procmon..." -ForegroundColor Cyan
Start-Process -FilePath $Procmon -ArgumentList @('/Terminate') -Wait

# Wait until every Procmon process has actually exited AND the .pml is unlocked.
for ($i = 0; $i -lt 60; $i++) {
  $running = Get-Process Procmon, Procmon64 -ErrorAction SilentlyContinue
  $locked = $false
  if (-not $running -and (Test-Path $pml)) {
    try { $fs = [IO.File]::Open($pml, 'Open', 'Read', 'None'); $fs.Close() }
    catch { $locked = $true }
  } else { $locked = $true }
  if (-not $locked) { break }
  Start-Sleep -Milliseconds 500
}
if (-not (Test-Path $pml)) { throw "Backing file never appeared: $pml" }

Write-Host "Converting $pml -> $csv ..." -ForegroundColor Cyan
Start-Process -FilePath $Procmon -ArgumentList @(
  '/OpenLog', $pml, '/SaveAs', $csv
) -Wait
if (-not (Test-Path $csv)) { throw "Convert produced no CSV: $csv" }

$rows = (Get-Content $csv -ReadCount 0 | Measure-Object -Line).Lines
Write-Host ("CSV ready: {0} ({1:N0} lines)" -f $csv, $rows) -ForegroundColor Green
Write-Host ""

& (Join-Path $PSScriptRoot 'Analyze-Capture.ps1') -Csv $csv -AppDir $AppDir
