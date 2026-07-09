# Storage audit — prove the client writes nothing outside its folder

Requires Sysinternals Process Monitor (`Procmon.exe`) and an **elevated** PowerShell.

## Quick path (two-phase driver, avoids the flush race)

From an admin PowerShell (add `-ExecutionPolicy Bypass` if scripts are blocked):

```
cd D:\scrs\programs\MaxSecu\tools\storage-audit
.\Start-Capture.ps1                 # launches Procmon, prints what to exercise
#  ... exercise EVERY flow below in .audit-run\MaxSecu.exe, then fully exit it ...
.\Stop-Capture.ps1                  # terminates, waits for flush, converts, analyzes
```

`Stop-Capture.ps1` waits for Procmon to fully exit before converting the `.pml`
(converting too early is what produced the earlier "Unable to open .pml" /
"no items to be saved" errors), then runs `Analyze-Capture.ps1` for you.

## Flows to exercise (persistence-relevant)
- Launch `MaxSecu.exe` from its portable folder, unlock/login
- change the theme; change the skin; change the bundle view (gallery ↔ stacked)
- play a video, change the volume + toggle mute
- upload a post that triggers a **video transcode** (exercises the confined ffmpeg
  path, whose per-job temp dir now lives in-folder); download a file
- log out, then **fully exit** the app (so the exit-wipe runs)

## Manual path (if you prefer raw commands)
```
Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile capture.pml
# ...exercise, then fully exit the app...
Procmon.exe /Terminate
Procmon.exe /OpenLog capture.pml /SaveAs capture.csv
.\Analyze-Capture.ps1 -Csv capture.csv -AppDir '<path-to-portable-folder>'
```

## Reading the result
PASS = no app-data FILE write outside the folder (GENUINE bucket = 0).

After the mitigations (temp redirect + `--disable-gpu-shader-disk-cache` +
implicit-SSO suppression) we additionally expect, versus the pre-mitigation
capture:
- **No `%TEMP%\msedge_*` / `WebView2Downloads` / `maxsecu-vjob-*`** outside the
  folder — that scratch now lands in `<app_dir>\webview\tmp` (in-folder, so it is
  filtered before the buckets and wiped on exit).
- **Fewer/zero GPU shader-cache writes** under `…\NVIDIA\…` (shader disk cache off).
- **Fewer/zero `…\Microsoft\OneAuth\…` touches** (implicit OS SSO suppressed).

Any residual OneAuth/NVIDIA/runtime entries land in the "benign shared-runtime"
bucket and do NOT fail the audit — review them, they carry no MaxSecu user data.
The REGISTRY section lists a few shared-WebView2-runtime HKCU keys (runtime
bookkeeping, not user data).
