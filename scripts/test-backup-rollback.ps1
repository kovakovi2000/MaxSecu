<#
.SYNOPSIS
    Unattended backup / destroy / restore E2E for MaxSecu's server backup-rollback.
.DESCRIPTION
    Provisions a throwaway WSL Ubuntu-22.04 distro with an fs COLD TIER (a
    credential-free stand-in for Dropbox, kept OUTSIDE the data dir), installs the
    server, enrolls + uploads a blog AND an image via live-smoke `--phase seed`
    (the image forces a PINNED Thumbnail/Preview stream through the cold tier), seals
    a backup with backup-server.sh, exercises the three DRIVER-level cases the design
    assigns to this harness while the box is still alive (wrong passphrase, --dry-run,
    merge with a live DB ahead of the bundle), then DESTROYS the box to the ground --
    data dir, database, ROLE, /etc/maxsecu and the unit -- restores it from the bundle
    with restore-server.sh, and re-opens the SAME sealed client via live-smoke
    `--phase verify` (no re-enroll, no re-pin). That last step is the executable form
    of the CLAUDE.md rule: an existing user keeps account, keys and uploads intact.

    This shares its WSL plumbing (provision/install/build/teardown + the live-smoke
    build+invoke helpers) with test-full-install.ps1 via scripts/lib/wsl-harness.ps1.

    WARNING DESTRUCTIVE. Every mutation runs INSIDE a throwaway distro named
    `maxsecu-bkup-<stamp>`; a hard guard refuses the destroy phase if the distro name
    does not match that prefix, and Invoke-WslCmd refuses a `$null` distro (which
    would target the operator's DEFAULT distro).
.PARAMETER Port           Server listen port (default 18453, off test-full-install's 18443).
.PARAMETER KeepOnFailure  Skip teardown on failure (leave the distro up for debugging).
.PARAMETER IncludeGit     Copy .git into the distro so `--only code` (git checkout +
                          rebuild) is exercised for real; default OFF asserts the
                          fail-closed no-checkout path instead.
#>
[CmdletBinding()]
param(
    [int]    $Port = 18453,
    [switch] $KeepOnFailure,
    [switch] $IncludeGit
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Stamp = Get-Date -Format 'yyyyMMddHHmmss'
$Distro = "maxsecu-bkup-$Stamp"
$WorkDir = Join-Path $env:TEMP "maxsecu-bkup-$Stamp"
$RecoveryPw = "livesmoke-recovery-$Stamp!"
# The bundle passphrase (Argon2id). >=12 chars -- backup-server.sh (seal) refuses a
# shorter one. A test constant: it only ever guards a throwaway distro's bundle.
$BundlePw = "bkup-e2e-bundle-passphrase-$Stamp"

# Linux paths INSIDE the distro. The cold tier MUST live OUTSIDE the data dir -- the
# default is <data_dir>/cold, which the destroy step (rm -rf the data dir) would
# take the backup down with it. A guard below asserts the resolved paths disjoint.
$ColdDir = '/root/maxsecu-cold'
$DataDir = '/root/maxsecu-server-data'

# The state file (+ its sealed app-dir sibling) live on the WINDOWS side -- live-smoke
# runs on the host and its keystore is a host directory that must survive the WSL
# destroy untouched. verify re-opens exactly this sealed app-dir.
$StateDir = Join-Path $WorkDir 'state'
$StateFile = Join-Path $StateDir 'state.json'
$ClientDir = Join-Path $Root 'dist\MaxSecuClient'

# Shared WSL harness -- DOT-SOURCE (its $script: scope is ours), then publish the
# closed-over vars for the helpers.
. (Join-Path $PSScriptRoot 'lib\wsl-harness.ps1')
Initialize-WslHarness -RepoRoot $Root -DistroName $Distro -WorkingDir $WorkDir `
    -ServerPort $Port -RecoveryPassphrase $RecoveryPw

# Poll (from the host) until the port STOPS accepting connections -- the positive proof
# the destroy actually took the server down (a "passing" restore that was really a
# destroy-that-didn't is how this class of test rots into a tautology).
function Assert-PortDead([int]$port) {
    for ($i = 0; $i -lt 15; $i++) {
        $alive = $false
        $c = $null
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', $port)
            $alive = $true
        } catch { } finally {
            if ($c) { $c.Dispose() }
        }
        if (-not $alive) { return }
        Start-Sleep -Seconds 2
    }
    Die "server port $port is still accepting connections after the destroy step"
}

# Run a command inside the distro WITHOUT Invoke-WslCmd's throw-on-non-zero contract,
# returning @{ Code = <exit status>; Out = <combined output> }. The wrong-passphrase
# case below EXPECTS a failure and has to INSPECT it, which the throwing helper cannot
# express. It carries the same $Distro guard for the same reason: `wsl -d ''` would run
# the command against the operator's own DEFAULT distro.
function Invoke-WslCmdRaw($cmd) {
    if ([string]::IsNullOrWhiteSpace($Distro)) {
        Die "Invoke-WslCmdRaw: the distro name is not set -- refusing to target the DEFAULT distro."
    }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & wsl.exe -d $Distro -- bash -lc $cmd 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    foreach ($line in ($out -split "`r?`n")) { if ($line) { Write-Host "  [wsl] $line" } }
    return @{ Code = $code; Out = $out }
}

# systemd's monotonic timestamp of the unit's LAST transition into `active`. `is-active`
# alone cannot prove the driver left the service alone -- a stop followed by a start
# reports `active` again by the time we look -- but this number moves the instant the
# unit is restarted, so an unchanged value is positive proof the unit was never taken
# down. That is exactly the regression the wrong-passphrase and --dry-run cases guard.
function Get-UnitActiveStamp {
    $out = Invoke-WslCmd "systemctl show maxsecu-server --property=ActiveEnterTimestampMonotonic --value"
    $m = [regex]::Match($out, '(\d+)')
    if (-not $m.Success) { Die "could not read maxsecu-server's ActiveEnterTimestampMonotonic" }
    return $m.Groups[1].Value
}

# The live database's set of file_ids (lowercase hex), read as the postgres superuser so
# no password has to leave the unit. Lines are filtered to the exact 16-byte hex shape:
# psql notices arrive on stderr, which Invoke-WslCmd folds into the same string, and a
# stray line silently joining the set would weaken every comparison built on it.
#
# QUOTING (this cost a run): the command string handed to `wsl.exe -- bash -lc <arg>`
# must contain NO double quotes. PowerShell 5.1 wraps a native argument containing
# spaces in `"` but does NOT escape the quotes already inside it, so an inner `"..."`
# whose content has spaces gets its quoting redistributed -- bash then sees
# `encode(file_id,'hex')` unquoted and dies with "syntax error near unexpected token `('".
# (The harness's other inner-quoted commands survive only because what they quote --
# `$HOME/...` -- has no spaces.) So: single quotes only. That also rules out
# `encode(file_id,'hex')`, and it is not needed -- psql already renders BYTEA as
# `\x<hex>` under the default bytea_output=hex, which is the same 32 hex chars behind a
# two-character prefix the regex below strips.
function Get-LiveFileIds {
    $out = Invoke-WslCmd "sudo -u postgres psql -d maxsecu -tAc 'SELECT file_id FROM files ORDER BY 1'"
    $ids = @()
    foreach ($line in ($out -split "`r?`n")) {
        $t = $line.Trim()
        if ($t -match '^\\x([0-9a-f]{32})$') { $ids += $Matches[1] }
    }
    return , $ids
}

try {
    # Pre-clean host client state so install-client's resumability can't reuse a stale
    # recovery_pin.bin/register.key from a prior run. (Only here -- NEVER between seed
    # and verify, where a -Reset would delete the recovery_pin.bin verify depends on.)
    Write-Host "==== Pre-clean client state ===="  -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "install-client.ps1 -Reset failed ($LASTEXITCODE) -- refusing to run against leftover client state" }
    # Positively assert the reset actually removed the offline-D5 artifacts. If any
    # survive, install-client's resumability can reuse them against the BRAND-NEW
    # server in this run's distro: maxsecu-setup then reports "already delegated"
    # (exit 3), install-client happily reuses the stale directory_pub.der and exits
    # ZERO, and the failure surfaces several minutes later at Confirm-EnrollmentOpen
    # as "the server has no directory pin" -- pointing at the delegation ceremony
    # rather than at this line. Fail here, where the cause is legible.
    foreach ($stray in @('d5_key.blob', 'd5_recovery.blob', 'directory_pub.der',
                         'connection_code.txt', 'recovery_pin.bin', 'register.key',
                         'crates\client-app\recovery_pin.bin')) {
        $p = Join-Path $Root $stray
        if (Test-Path $p) { Die "pre-clean left '$stray' behind -- a stale D5/pin artifact would make install-client reuse the PREVIOUS server's delegation and the run would fail later at Confirm-EnrollmentOpen. Delete it and re-run." }
    }

    Provision-Wsl
    Copy-Source

    if ($IncludeGit) {
        # Copy-Source excludes .git (so ~/maxsecu is not a checkout). Add it back so
        # backup records a real git_sha and restore --only code can `git checkout`.
        Phase "Include .git (exercise --only code for real)"
        $stage = Join-Path $WorkDir 'src'
        & robocopy (Join-Path $Root '.git') (Join-Path $stage '.git') /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { Die "robocopy of .git failed ($LASTEXITCODE)" }
        $wslStage = (& wsl.exe -d $Distro -- wslpath -a ($stage -replace '\\', '/'))
        if ($LASTEXITCODE -ne 0) { Die "wslpath translation failed" }
        Invoke-WslCmd "rm -rf ~/maxsecu/.git && cp -r '$($wslStage.Trim())/.git' ~/maxsecu/.git"
    }

    # Install with the fs cold tier ON (and no Dropbox). --cold-tier-fs turns the
    # local-fs tier on AND points it at $ColdDir; --no-dropbox skips the creds prompt.
    $srv = Install-Server 'install' $ColdDir
    Build-Client $srv
    Confirm-EnrollmentOpen

    # Build the oracle ONCE; seed and verify run the SAME exe against dist\MaxSecuClient.
    $exe = Build-LiveSmoke
    $ip = ($srv.Addr -split ':')[0]

    # ---- SEED: enroll + upload (blog + image) into an app-dir beside the state file ----
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    Invoke-LiveSmokePhase -Exe $exe -SmokePhase 'seed' -Server $srv.Addr -SmokeHost $ip `
        -ClientDir $ClientDir -State $StateFile

    # ---- Guard: the cold dir must resolve OUTSIDE the data dir (else step 3 nukes the
    #      backup). Resolve both with `readlink -f` and compare on the HOST side so no
    #      brittle bash quoting is needed. ----
    Phase "Guard: cold tier is OUTSIDE the data dir"
    $coldReal = (Invoke-WslCmd "readlink -f '$ColdDir'").Trim()
    $dataReal = (Invoke-WslCmd "readlink -f '$DataDir'").Trim()
    if ($coldReal -eq $dataReal -or $coldReal.StartsWith("$dataReal/")) {
        Die "cold dir ($coldReal) is INSIDE the data dir ($dataReal) -- the destroy step would delete the backup"
    }
    Write-Host "  cold dir $coldReal is outside data dir $dataReal"

    # ---- BACKUP: passphrase on STDIN via printf (never argv); backup-server.sh passes
    #      it straight to the binary. ----
    Phase "Back up the server (backup-server.sh)"
    Invoke-WslCmd "cd ~/maxsecu && printf '%s' '$BundlePw' | bash scripts/backup-server.sh"
    # The sealed bundle's commit point is part 0 of the manifest container.
    Invoke-WslCmd "ls -d $ColdDir/_backup/*/manifest/0 >/dev/null 2>&1 && echo BUNDLE_OK || { echo NO_BUNDLE; exit 1; }"
    Write-Host "  backup bundle present under $ColdDir/_backup"

    # ---- The three cases the design's coverage table ("Where each case is tested")
    #      assigns to THIS harness. They belong HERE, between the seal and the destroy,
    #      because each one needs a live, healthy box: the Rust suites own the engine,
    #      but only a real systemd box can catch a DRIVER that takes the service down
    #      before it has earned the right to. ----

    # A wrong passphrase must fail while the box is still whole. The regression this
    # guards is a driver that stops the unit FIRST and only then discovers it cannot
    # unseal -- leaving a healthy server down over a typo, on a box whose operator is
    # by design a non-technical user with no escape hatch.
    Phase "Wrong passphrase fails cleanly (server stays UP, nothing half-applied)"
    $stampBefore = Get-UnitActiveStamp
    $bad = Invoke-WslCmdRaw "cd ~/maxsecu && printf '%s' 'definitely-not-the-bundle-passphrase' | bash scripts/restore-server.sh --from latest"
    if ($bad.Code -eq 0) { Die "restore-server.sh SUCCEEDED with a wrong passphrase" }
    # Non-vacuity: it has to have failed AT THE UNSEAL. A typo'd flag or a cold tier it
    # could not locate would also exit non-zero while proving nothing about ordering.
    if ($bad.Out -notmatch 'could not unseal the bundle') {
        Die "the wrong-passphrase run failed for the wrong reason (no unseal error in its output)"
    }
    Invoke-WslCmd "systemctl is-active --quiet maxsecu-server && echo STILL_UP || { echo SERVICE_DOWN; exit 1; }"
    if ((Get-UnitActiveStamp) -ne $stampBefore) {
        Die "the failed restore restarted maxsecu-server -- it stopped the unit before unsealing"
    }
    Wait-ServerReachable $Port
    Write-Host "  wrong passphrase refused; unit never left the state it was already in"

    # --dry-run must change nothing at all. The engine half is Rust's own dry-run test;
    # what only a live box can prove is that the DRIVER honors the flag BEFORE its
    # `systemctl stop`, so asking "what would this restore do?" never costs downtime.
    Phase "--dry-run changes nothing (and never stops the unit)"
    $stampBefore = Get-UnitActiveStamp
    $dry = Invoke-WslCmd "cd ~/maxsecu && printf '%s' '$BundlePw' | bash scripts/restore-server.sh --from latest --dry-run"
    if ($dry -notmatch 'Dry run complete') {
        Die "--dry-run did not reach its 'Dry run complete' exit -- it fell through to the apply path"
    }
    Invoke-WslCmd "systemctl is-active --quiet maxsecu-server && echo STILL_UP || { echo SERVICE_DOWN; exit 1; }"
    if ((Get-UnitActiveStamp) -ne $stampBefore) {
        Die "--dry-run restarted maxsecu-server -- the driver stopped the unit before honoring the flag"
    }
    Wait-ServerReachable $Port
    Write-Host "  dry run previewed the plan; unit untouched and still serving on $Port"

    # merge-with-live-ahead -- the rule this whole feature exists for. A user uploads
    # AFTER the bundle was sealed; rolling the database back must add whatever the live
    # DB is missing and remove NOTHING, so that upload has to still be there afterwards.
    # live-smoke has no "one more upload" phase, but `verify`'s final act IS a real
    # client upload through the real server: run against the still-live box it is
    # exactly the post-backup write this case needs (and a free health checkpoint on
    # the seeded identity before anything is destroyed).
    Phase "Merge with a live DB AHEAD of the bundle (a rollback must not strand a post-backup upload)"
    $idsAtBackup = Get-LiveFileIds
    Invoke-LiveSmokePhase -Exe $exe -SmokePhase 'verify' -Server $srv.Addr -SmokeHost $ip `
        -ClientDir $ClientDir -State $StateFile
    $idsAhead = Get-LiveFileIds
    $newIds = @($idsAhead | Where-Object { $idsAtBackup -notcontains $_ })
    # Without this the scenario is a tautology: if the live DB is not actually ahead of
    # the bundle, "the post-backup row survived" asserts nothing at all.
    if ($newIds.Count -lt 1) {
        Die "no post-backup file appeared in the live DB -- the merge case would assert nothing"
    }
    Write-Host "  live DB is ahead of the bundle by $($newIds.Count) file(s): $($newIds -join ', ')"

    $merge = Invoke-WslCmd "cd ~/maxsecu && printf '%s' '$BundlePw' | bash scripts/restore-server.sh --from latest --only db"
    # The other way this could pass while testing nothing: a restore that skipped the
    # database entirely (or quietly chose replace) would leave the assertions below
    # true without the dump->scratch->merge plumbing ever running. `merge` is also the
    # DEFAULT here precisely because a live DB exists -- no --db-mode is passed.
    if ($merge -notmatch 'Merging the backup into the live database') {
        Die "--only db did not take the MERGE path (db component skipped, or it chose replace)"
    }
    Wait-ServerReachable $Port
    $idsMerged = Get-LiveFileIds
    foreach ($fid in $newIds) {
        if ($idsMerged -notcontains $fid) {
            Die "the merge REMOVED post-backup file $fid -- a rollback stranded a user's upload"
        }
    }
    foreach ($fid in $idsAtBackup) {
        if ($idsMerged -notcontains $fid) { Die "the merge removed pre-backup file $fid" }
    }
    Write-Host "  merge kept all $($idsMerged.Count) file(s), including the $($newIds.Count) uploaded after the backup"

    # ---- DESTROY: to the ground. HARD name guard first (blast radius is a real rm -rf +
    #      DROP DATABASE/ROLE); every mutation runs INSIDE the throwaway distro. ----
    if ($Distro -notlike 'maxsecu-bkup-*') {
        Die "refusing to run destructive steps: distro '$Distro' does not match 'maxsecu-bkup-*'"
    }
    Phase "Destroy the server (data dir + database + ROLE + /etc/maxsecu + unit)"
    Invoke-WslCmd "systemctl stop maxsecu-server 2>/dev/null || true"
    Invoke-WslCmd "systemctl disable maxsecu-server 2>/dev/null || true"
    Invoke-WslCmd "rm -f /etc/systemd/system/maxsecu-server.service; rm -rf /etc/systemd/system/maxsecu-server.service.d; systemctl daemon-reload"
    Invoke-WslCmd "rm -rf '$DataDir'"
    Invoke-WslCmd "rm -rf /etc/maxsecu"
    # DROP DATABASE, then DROP ROLE (order per install-server.sh) -- dropping the role is
    # what forces the restore's dead-box CREATE ROLE + CREATE DATABASE path (its password
    # lives ONLY in the bundled unit); leaving it would ship that path untested.
    Invoke-WslCmd "sudo -u postgres psql -c 'DROP DATABASE IF EXISTS maxsecu WITH (FORCE);' 2>/dev/null || sudo -u postgres psql -c 'DROP DATABASE IF EXISTS maxsecu;'"
    Invoke-WslCmd "sudo -u postgres psql -c 'DROP ROLE IF EXISTS maxsecu;'"

    # ---- Assert the destruction actually happened (data gone, DB gone, role gone, port
    #      dead) -- otherwise a green verify might just be a destroy that no-op'd. ----
    Phase "Assert destruction"
    Invoke-WslCmd "test ! -e '$DataDir' && echo DATA_GONE || { echo DATA_PRESENT; exit 1; }"
    Invoke-WslCmd "test ! -e /etc/systemd/system/maxsecu-server.service && echo UNIT_GONE || { echo UNIT_PRESENT; exit 1; }"
    # Same no-double-quotes rule as Get-LiveFileIds (see the note there). Listing the
    # names and matching host-side avoids a WHERE clause needing a quoted literal, and
    # puts the full list in the log where it is useful when this assertion trips.
    $dbNames = (Invoke-WslCmd "sudo -u postgres psql -tAc 'SELECT datname FROM pg_database'") -split "`r?`n" | ForEach-Object { $_.Trim() }
    if ($dbNames -contains 'maxsecu') { Die "database 'maxsecu' still exists after destroy" }
    $roleNames = (Invoke-WslCmd "sudo -u postgres psql -tAc 'SELECT rolname FROM pg_roles'") -split "`r?`n" | ForEach-Object { $_.Trim() }
    if ($roleNames -contains 'maxsecu') { Die "role 'maxsecu' still exists after destroy" }
    Assert-PortDead $Port
    Write-Host "  destruction confirmed: data + DB + role gone, unit removed, port $Port dead"

    # ---- RESTORE: dead-box rebuild. --cold-tier-fs tells the binary where the bundle
    #      lives (no live unit to scrape it from); passphrase on STDIN; --force per spec. ----
    Phase "Restore the server (restore-server.sh --from latest --cold-tier-fs)"
    Invoke-WslCmd "cd ~/maxsecu && printf '%s' '$BundlePw' | bash scripts/restore-server.sh --from latest --cold-tier-fs '$ColdDir' --force"
    Wait-ServerReachable $Port

    # ---- VERIFY: the SAME dist\MaxSecuClient + the SAME oracle exe, no re-enroll, no
    #      re-pin. Reopens the sealed app-dir, asserts identity + directory binding +
    #      every recorded file's content survived, then that the WRITE path works. ----
    Invoke-LiveSmokePhase -Exe $exe -SmokePhase 'verify' -Server $srv.Addr -SmokeHost $ip `
        -ClientDir $ClientDir -State $StateFile

    Teardown
    Write-Host "`nBACKUP-ROLLBACK E2E GREEN" -ForegroundColor Green
}
catch {
    Write-Host "`nHARNESS FAILED: $_" -ForegroundColor Red
    Write-Host "  at: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkRed
    Write-Host "  stack: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    if ($KeepOnFailure) {
        Write-Host "-KeepOnFailure set: leaving distro '$Distro' and '$WorkDir' for debugging." -ForegroundColor Yellow
        Write-Host "  Server logs:  wsl -d $Distro -- journalctl -u maxsecu-server -e" -ForegroundColor Yellow
    } else {
        Teardown
    }
    exit 1
}
