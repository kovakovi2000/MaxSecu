<#
.SYNOPSIS
  Begin a Process Monitor capture for the storage audit (phase 1 of 2).
.DESCRIPTION
  Clears any previous capture, then launches Procmon minimized, backing its live
  events to <OutDir>\<Name>.pml. Returns immediately — Procmon keeps recording in
  the background while you exercise the app. When finished, run Stop-Capture.ps1
  with the SAME -Name/-OutDir to terminate, convert, and analyze.

  Must run from an ELEVATED PowerShell (Procmon needs admin). If your execution
  policy blocks scripts, launch with:  powershell -ExecutionPolicy Bypass -File ...
.EXAMPLE
  .\Start-Capture.ps1 -Procmon 'D:\scrs\programs\MaxSecu\ProcessMonitor\Procmon.exe'
#>
param(
  [string]$Procmon = 'D:\scrs\programs\MaxSecu\ProcessMonitor\Procmon.exe',
  [string]$OutDir  = 'D:\scrs\programs\MaxSecu\.audit-run',
  [string]$Name    = 'capture2'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Procmon)) { throw "Procmon not found at $Procmon" }
if (-not (Test-Path $OutDir))  { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$pml = Join-Path $OutDir "$Name.pml"
$csv = Join-Path $OutDir "$Name.csv"

# Clean slate: any leftover Procmon from a prior run, plus stale output files.
Get-Process Procmon, Procmon64 -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
Remove-Item $pml, $csv -Force -ErrorAction SilentlyContinue

Write-Host "Starting Procmon -> $pml" -ForegroundColor Cyan
Start-Process -FilePath $Procmon -ArgumentList @(
  '/AcceptEula','/Quiet','/Minimized','/BackingFile', $pml
)

Write-Host ""
Write-Host "CAPTURING. Now exercise the client from its folder:" -ForegroundColor Green
Write-Host "  1. Launch .audit-run\MaxSecu.exe, unlock/login"
Write-Host "  2. Change theme; change skin; change bundle view (gallery <-> stacked)"
Write-Host "  3. Play a video, change volume + toggle mute"
Write-Host "  4. (if possible) upload a post that triggers a video transcode; download a file"
Write-Host "  5. Log out, then FULLY EXIT the app (so the exit-wipe runs)"
Write-Host ""
Write-Host "When done, run:  .\Stop-Capture.ps1 -Name $Name" -ForegroundColor Yellow
