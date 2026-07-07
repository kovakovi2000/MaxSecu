# Storage audit — prove the client writes nothing outside its folder

Requires Sysinternals Process Monitor (`Procmon.exe`) and admin rights.

## 1. Start the capture (admin PowerShell)
```
Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile capture.pml
```

## 2. Exercise EVERY persistence-relevant flow in the built client
Launch `MaxSecuClient.exe` from its portable folder, then:
- register / first-run (if applicable), unlock/login
- change the theme; change the skin; change the bundle view (gallery ↔ stacked)
- play a video and change the volume + toggle mute
- upload a post; download a file
- log out, then fully exit the app (so the exit-wipe runs)

## 3. Stop + export
```
Procmon.exe /Terminate
Procmon.exe /OpenLog capture.pml /SaveAs capture.csv
```

## 4. Analyze
```
./Analyze-Capture.ps1 -Csv capture.csv -AppDir '<path-to-portable-folder>'
```
PASS = no FILE write outside the folder. The REGISTRY section is expected to list a
few shared-WebView2-runtime keys under HKCU (runtime bookkeeping, not user data);
review that they are not app data.
