<#
.SYNOPSIS
    Shared WSL E2E harness for MaxSecu's full-install and backup-rollback tests.
.DESCRIPTION
    A DOT-SOURCE-ONLY library of the throwaway-WSL helpers that both
    scripts/test-full-install.ps1 and scripts/test-backup-rollback.ps1 use to
    provision a disposable Ubuntu-22.04 distro, install the server, build the
    client, and tear everything down.

    CONTRACT -- DOT-SOURCE, never `& file.ps1`:

        . (Join-Path $PSScriptRoot 'lib\wsl-harness.ps1')
        Initialize-WslHarness -RepoRoot $Root -DistroName $Distro `
            -WorkingDir $WorkDir -ServerPort $Port -RecoveryPassphrase $RecoveryPw

    The helpers close over script-scope vars ($Root/$Distro/$WorkDir/$Port/
    $RecoveryPw/$RootFsCache/$script:KeepAlive). Because a dot-sourced file's
    `$script:` scope IS the caller's, Initialize-WslHarness publishes those values
    straight into the caller's script scope and every helper below then reads them.
    Invoking this file with `& ...` instead would put them in a child scope the
    caller cannot see, and the helpers would run against unset vars -- which for
    Invoke-WslCmd means `wsl.exe -d ''` = the DEFAULT distro. That is guarded below.
#>

# Publish the closed-over vars into the CALLER's script scope. DOT-SOURCED, so
# `$script:` here IS the caller's script scope (that is the whole contract). Call
# this ONCE, before any other harness function.
function Initialize-WslHarness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RepoRoot,
        [Parameter(Mandatory)][string] $DistroName,
        [Parameter(Mandatory)][string] $WorkingDir,
        [Parameter(Mandatory)][int]    $ServerPort,
        [Parameter(Mandatory)][string] $RecoveryPassphrase
    )
    $script:Root        = $RepoRoot
    $script:Distro      = $DistroName
    $script:WorkDir     = $WorkingDir
    $script:Port        = $ServerPort
    $script:RecoveryPw  = $RecoveryPassphrase
    $script:RootFsCache = Join-Path $env:LOCALAPPDATA 'maxsecu-test\ubuntu-22.04-rootfs.tar.gz'
    $script:KeepAlive   = $null
}

function Phase($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Die($t)   { Write-Host "FAIL: $t" -ForegroundColor Red; throw $t }

# Run a command inside the distro as the default user; throws on non-zero exit.
# NB: the executable is invoked as `wsl.exe` (never bare `wsl`) throughout this
# script -- PowerShell resolves functions before executables, so a function named
# `Wsl` + a bare `& wsl` would recurse into the function until the stack overflows.
function Invoke-WslCmd($cmd) {
    # SAFETY GUARD (shared with test-backup-rollback.ps1, whose blast radius is a
    # real `rm -rf`): `wsl.exe -d ''` targets the DEFAULT distro. A $null/unset
    # $Distro (harness not initialized, or a typo) would run the command against the
    # operator's own default distro. Refuse rather than risk it.
    if ([string]::IsNullOrWhiteSpace($Distro)) {
        throw "Invoke-WslCmd: `$Distro is not set (call Initialize-WslHarness first) -- refusing to target the DEFAULT distro (wsl -d '')."
    }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & wsl.exe -d $Distro -- bash -lc $cmd 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    foreach ($line in ($out -split "`r?`n")) { if ($line) { Write-Host "  [wsl] $line" } }
    if ($code -ne 0) { Die "wsl command failed ($code): $cmd" }
    return $out
}

function Provision-Wsl {
    Phase "Provision WSL distro $Distro"
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $installDir = Join-Path $WorkDir 'distro'
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    if (-not (Test-Path $RootFsCache)) {
        Write-Host "  Downloading Ubuntu 22.04 rootfs (one-time cache)..."
        New-Item -ItemType Directory -Path (Split-Path $RootFsCache) -Force | Out-Null
        $url = 'https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-ubuntu22.04lts.rootfs.tar.gz'
        $tmp = "$RootFsCache.partial"
        if (Test-Path $tmp) { Remove-Item -Force $tmp }
        # Use curl.exe (ships with Windows 10/11): it streams straight to disk with
        # no in-memory buffering and no PowerShell progress records, avoiding the
        # Invoke-WebRequest call-depth overflow on large downloads under PS 5.1.
        & curl.exe -fSL --retry 3 -o $tmp $url
        if ($LASTEXITCODE -ne 0) { Die "rootfs download failed (curl exit $LASTEXITCODE)" }
        if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -lt 1000000) {
            Die "rootfs download failed or is implausibly small"
        }
        Move-Item -Force $tmp $RootFsCache
    }

    # Defensively drop any leftover registration of this name (e.g. from a prior
    # iteration whose teardown could not unregister it) so --import can't fail on a
    # name clash with a confusing error.
    & wsl.exe --unregister $Distro 2>$null
    & wsl.exe --import $Distro $installDir $RootFsCache --version 2
    if ($LASTEXITCODE -ne 0) { Die "wsl --import failed" }

    # Enable systemd (needed for the maxsecu-server systemd unit + postgresql).
    & wsl.exe -d $Distro -- bash -lc "printf '[boot]\nsystemd=true\n' | tee /etc/wsl.conf >/dev/null"
    if ($LASTEXITCODE -ne 0) { Die "failed to write /etc/wsl.conf in the distro" }
    & wsl.exe --terminate $Distro
    Start-Sleep -Seconds 2

    # Wait for systemd to reach running/degraded (degraded is fine -- some units inactive).
    $ok = $false
    $state = ''
    for ($i = 0; $i -lt 60; $i++) {
        $state = (& wsl.exe -d $Distro -- bash -lc 'systemctl is-system-running 2>/dev/null')
        if ($state -match 'running|degraded') { $ok = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ok) { Die "systemd did not come up in the distro" }
    Write-Host "  distro up (systemd: $state)"

    # Keep the distro alive for the whole run. WSL2 idle-terminates a distro when no
    # wsl session is attached; during the multi-minute Windows-side client build there
    # are no wsl calls, so without this the distro (and the server) would be shut down
    # and the client's fetch-pins would get connection-refused.
    $script:KeepAlive = Start-Process -FilePath 'wsl.exe' `
        -ArgumentList @('-d', $Distro, '--', 'sleep', 'infinity') -WindowStyle Hidden -PassThru
}

function Copy-Source {
    Phase "Copy source into the distro"
    $stage = Join-Path $WorkDir 'src'
    $exclude = @('target', 'node_modules', 'dist', '.git', 'webview', 'tmp')
    & robocopy $Root $stage /MIR /XD @exclude /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Die "robocopy of source failed ($LASTEXITCODE)" }
    $wslStage = (& wsl.exe -d $Distro -- wslpath -a ($stage -replace '\\','/'))
    if ($LASTEXITCODE -ne 0) { Die "wslpath translation failed" }
    Invoke-WslCmd "rm -rf ~/maxsecu && cp -r '$($wslStage.Trim())' ~/maxsecu && chmod +x ~/maxsecu/scripts/*.sh"
}

# Wait until the server accepts a TCP connection from the host on 127.0.0.1:$port.
# Right after install the unit can briefly crash-loop on EADDRINUSE (install-server
# does `enable --now` then a redundant `systemctl restart`, racing the just-bound
# socket, which releases slowly under WSL mirrored networking) and may hit systemd's
# start-limit. Poll, and every ~10s clear any failed state and restart to guarantee
# recovery, so the client's fetch-pins never runs against a momentarily-down server.
function Wait-ServerReachable([int]$port) {
    # Require SUSTAINED reachability (3 consecutive connects ~2s apart): a single
    # momentary connect can succeed during a brief up-window mid-flap and then the
    # server cycles down again before the client's fetch-pins runs. Do NOT restart
    # repeatedly (that adds socket contention and prolongs the flap); nudge once,
    # late, only in case the unit gave up after hitting systemd's start-limit.
    $consecutive = 0
    $nudged = $false
    for ($i = 0; $i -lt 90; $i++) {
        $ok = $false
        $c = $null
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', $port)
            $ok = $true
        } catch { } finally {
            if ($c) { $c.Dispose() }
        }
        if ($ok) {
            $consecutive++
            if ($consecutive -ge 3) {
                Write-Host "  server reachable + stable on 127.0.0.1:$port"
                return
            }
        } else {
            $consecutive = 0
            # First unresponsive tick at/after ~60s: nudge a unit that gave up after
            # systemd's start-limit. Fire once, on elapsed time, not an exact index.
            if ($i -ge 30 -and -not $nudged) {
                $nudged = $true
                Invoke-WslCmd "systemctl reset-failed maxsecu-server 2>/dev/null; systemctl restart maxsecu-server 2>/dev/null; true" | Out-Null
            }
        }
        Start-Sleep -Seconds 2
    }
    Die "server did not become stably reachable on 127.0.0.1:$port within timeout"
}

# mode: 'install' (returns a hashtable of ceremony inputs) or 'reset' (returns $null).
#
# Offline-D5 change: install-server no longer prints a ready-to-run connection code
# (that final user-facing code is minted on the ADMIN PC by install-client's ceremony).
# A fresh install now comes up AWAITING DELEGATION with enrollment CLOSED and prints,
# under labeled headers, a SERVER-CERT FINGERPRINT and a ONE-TIME DELEGATION TOKEN,
# plus a ready-to-run install-client command line of the form:
#
#     powershell ... -File scripts\install-client.ps1 -ConnectionCode <addr:port#CERT_FP> -Token <token>
#
# We lift both the cert-only connection code (addr:port#CERT_FP) and the token from
# that emitted command line (a single authoritative line carrying both), and hand them
# to install-client so its ceremony can pin TLS, generate D5, and upload the delegation
# that OPENS enrollment. The returned hashtable has:
#   ConnCode - "addr:port#CERT_FP" for install-client -ConnectionCode
#   Token    - the one-time delegation token for install-client -Token
#   Addr     - "addr:port" (fingerprint stripped) for the live-smoke oracle's --server
#
# $ColdTierFsDir (OPTIONAL, additive): when set, appends `--cold-tier-fs <dir>` to the
# install so the server offloads to a local-fs cold tier (the backup E2E needs this;
# test-full-install passes nothing, so the command is byte-identical to before).
function Install-Server([string]$mode, [string]$ColdTierFsDir = '') {
    Phase "Install server ($mode)"
    if ($mode -eq 'reset') {
        Invoke-WslCmd "cd ~/maxsecu && ./scripts/install-server.sh --reset --port $Port"
        return $null
    }
    # Pin the cert SAN to 127.0.0.1 and dial 127.0.0.1 (not the distro's own
    # `hostname -I` address). Under WSL2 the Windows host reaches the distro's
    # service on 127.0.0.1 in BOTH networking modes (NAT localhost-forwarding and
    # mirrored hostAddressLoopback); in mirrored mode the distro's `hostname -I`
    # address is actually the host's mirrored LAN IP and loops back to the host,
    # so it is unreachable as a server address. The server still binds 0.0.0.0; only
    # the cert SAN + dial address are 127.0.0.1. Protocol path is otherwise identical.
    # $ColdTierFsDir empty (test-full-install) => byte-identical to the original
    # `--no-dropbox` command; set (backup E2E) => also turns the fs cold tier on.
    $coldFlag = if ($ColdTierFsDir) { " --cold-tier-fs $ColdTierFsDir" } else { '' }
    $log = Invoke-WslCmd "cd ~/maxsecu && ./scripts/install-server.sh --public 127.0.0.1 --port $Port --no-dropbox$coldFlag"

    # Primary: lift BOTH values from the single emitted install-client command line
    # (-ConnectionCode <addr:port#CERT_FP> -Token <token>). CERT_FP and the token are
    # single tokens (no whitespace), so `\S+` bounded by `-Token` splits them cleanly.
    $connCode = ''
    $token    = ''
    $m = [regex]::Match($log, '-ConnectionCode\s+(\S+)\s+-Token\s+(\S+)')
    if ($m.Success) {
        $connCode = $m.Groups[1].Value.Trim()
        $token    = $m.Groups[2].Value.Trim()
    } else {
        # Fallback: scrape the two labeled headers independently. Each prints its value
        # alone on the next non-empty (indented) line after the header line.
        $fp = [regex]::Match($log, '(?ms)SERVER-CERT FINGERPRINT[^\r\n]*\r?\n\s*\r?\n\s*(\S+)')
        $tk = [regex]::Match($log, '(?ms)ONE-TIME DELEGATION TOKEN[^\r\n]*\r?\n\s*\r?\n\s*(\S+)')
        if ($fp.Success -and $tk.Success) {
            $connCode = "127.0.0.1:$Port#" + $fp.Groups[1].Value.Trim()
            $token    = $tk.Groups[1].Value.Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($connCode) -or [string]::IsNullOrWhiteSpace($token)) {
        Die "could not parse the cert connection code + delegation token from install-server output (is the server AWAITING DELEGATION? a re-run of an already-delegated server prints no token)"
    }
    $addr = ($connCode -split '#')[0]
    Write-Host "  cert connection code: $connCode"
    Write-Host "  delegation token    : (scraped, $($token.Length) chars)"
    Wait-ServerReachable $Port
    return @{ ConnCode = $connCode; Token = $token; Addr = $addr }
}

# Assert the ceremony actually installed the delegation, so enrollment is now OPEN.
#
# THE ORACLE -- and why it is deliberately NOT `print-fingerprint`.
#
# `print-fingerprint` reads <data_dir>/client-pins/directory_pub.der. That file is an
# OPERATOR-CONVENIENCE EXPORT ("copy these into the client's config/"), and it is
# written ONLY by the server's STARTUP path -- run.rs `prepare()`/`run()`, both behind
# `if directory_pub.is_some()`, i.e. only for a delegation that was, in run.rs's own
# words, "loaded across a restart". The ceremony installs the delegation at RUNTIME
# (delegation_setup.rs writes config/d5_delegation.bin + config/directory_pub.der) and
# nothing re-exports it into client-pins/ until the next restart. So immediately after
# a SUCCESSFUL ceremony that file legitimately does not exist yet and print-fingerprint
# prints nothing.
#
# Asserting on it here was therefore a FALSE NEGATIVE against a server whose enrollment
# is genuinely open -- which is exactly why this step failed for every previous run of
# both E2Es. Proven on a live distro: after the ceremony the file is absent and
# print-fingerprint is empty; a single `systemctl restart` makes both appear, with no
# other change.
#
# Ask the RUNNING server instead. `GET /v1/bootstrap/delegation` is served straight off
# the live `st.auth.delegation()` context -- the SAME context that gates enrollment in
# server/src/http.rs -- so its answer is what "enrollment is open" actually means, with
# no restart timing in the way. Verified both directions against a real distro:
# awaiting => HTTP 404 (empty body), delegated => HTTP 200 + {directory_pub_b64,
# delegation_cert_b64}. That makes this check strictly STRONGER than the old one (it
# proves the running server's state, not just that a file exists) and non-vacuous.
function Confirm-EnrollmentOpen {
    Phase "Confirm enrollment OPENED (delegation installed)"
    # Retry briefly: the ceremony's HTTP response and the server's own state settle
    # within a beat of each other, so a momentary lag must not produce a false failure.
    $code = ''
    $body = ''
    for ($i = 0; $i -lt 10; $i++) {
        $probe = Invoke-WslCmd "curl -sk -m 10 -o /tmp/maxsecu-deleg.json -w 'http=%{http_code}\n' https://127.0.0.1:$Port/v1/bootstrap/delegation 2>/dev/null || echo 'http=curl-failed'"
        $m = [regex]::Match($probe, 'http=(\S+)')
        if ($m.Success) { $code = $m.Groups[1].Value }
        if ($code -eq '200') {
            $body = Invoke-WslCmd "cat /tmp/maxsecu-deleg.json 2>/dev/null || true"
            break
        }
        Start-Sleep -Seconds 1
    }
    # Non-vacuity: a 200 whose body carries no delegation cert would mean the route
    # answered but the server holds nothing -- treat it exactly like an awaiting server.
    if ($code -ne '200' -or $body -notmatch 'delegation_cert_b64') {
        # This assertion has failed before and told nobody why. Several very different
        # causes land on the same "not delegated" answer: (a) the delegation was
        # REJECTED -- historically clock skew, because the client anchors valid_from to
        # the WINDOWS clock and a drifted WSL2 VM then sees now < valid_from; (b) the
        # ceremony never reached this server at all (wrong port, a stale D5 artifact
        # making install-client reuse a PREVIOUS server's delegation); (c) the server
        # accepted it but did not persist it. Dump the evidence that separates them
        # BEFORE dying, so the next run is a diagnosis and not a repeat. Read-only.
        Write-Host "`n---- delegation diagnostics ----" -ForegroundColor Yellow
        Write-Host "  GET /v1/bootstrap/delegation -> http=$code  (404 = server is still AWAITING)"
        $hostSecs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $wslSecs = ''
        try { $wslSecs = (Invoke-WslCmd "date +%s").Trim() } catch { }
        Write-Host "  host unix : $hostSecs"
        Write-Host "  wsl unix  : $wslSecs"
        if ($wslSecs -match '^\d+$') {
            $skew = [int64]$wslSecs - [int64]$hostSecs
            Write-Host "  skew      : $skew s  (a large value is cause (a) -- run 'wsl.exe --shutdown' to re-sync the VM clock)"
        }
        # (c): did anything land in config/ (the RUNTIME-written, authoritative copy)?
        # client-pins/ is listed too, but remember it is only refreshed at STARTUP --
        # an absent directory_pub.der there is expected before the first restart and is
        # NOT itself evidence of failure.
        # Unquoted on purpose: a command string handed to `bash -lc` through
        # PowerShell 5.1 must contain no double quotes (see Get-LiveFileIds in
        # test-backup-rollback.ps1). These paths contain no spaces, so nothing needs them.
        try { Invoke-WslCmd "ls -la `$HOME/maxsecu-server-data/config/ 2>&1 || true" | Out-Null } catch { }
        try { Invoke-WslCmd "ls -la `$HOME/maxsecu-server-data/client-pins/ 2>&1 || true" | Out-Null } catch { }
        # The server names which check failed -- bad_window / op_key_mismatch /
        # bad_signature -- in its journal (delegation-bootstrap-400 hardening).
        try { Invoke-WslCmd "journalctl -u maxsecu-server -n 60 --no-pager 2>&1 | grep -iE 'delegation|bad_window|op_key_mismatch|bad_signature|400' || echo '(no delegation lines in the journal)'" | Out-Null } catch { }
        Write-Host "-------------------------------`n" -ForegroundColor Yellow
        Die "the running server does not serve a delegation (GET /v1/bootstrap/delegation -> $code) -- delegation was NOT installed / enrollment is still CLOSED (see the diagnostics above)"
    }
    # The delegation must also be PERSISTED, not just live in memory: the restore phase
    # of the backup E2E restarts (and rebuilds) this server, and enrollment has to stay
    # open across that. These are the two files delegation_setup.rs writes atomically.
    Invoke-WslCmd "test -s `$HOME/maxsecu-server-data/config/d5_delegation.bin && test -s `$HOME/maxsecu-server-data/config/directory_pub.der && echo DELEGATION_PERSISTED || { echo DELEGATION_NOT_PERSISTED; exit 1; }" | Out-Null
    Write-Host "  running server serves its delegation (http 200) and persisted it -- enrollment OPEN"
}

function Build-Client($srv) {
    Phase "Build client (offline-D5 ceremony)"
    # install-client runs the whole offline-D5 ceremony non-interactively here: it pins
    # the server cert against the CERT-only fingerprint in -ConnectionCode, generates the
    # directory root (D5) on THIS host, uploads the delegation with the one-time -Token
    # (which OPENS enrollment on the awaiting server), mints the final user-facing code,
    # and builds the admin app + share ZIP. -RecoveryPassphrase seals D5 + the recovery
    # account non-interactively. The token is also accepted via $env:SETUP_DELEGATION_TOKEN;
    # we pass it as -Token for a self-contained call.
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') `
        -ConnectionCode $srv.ConnCode -Token $srv.Token -RecoveryPassphrase $RecoveryPw
    if ($LASTEXITCODE -ne 0) { Die "install-client.ps1 (offline-D5 ceremony) failed ($LASTEXITCODE)" }
}

function Run-Smoke($srv) {
    Phase "Run live-smoke oracle"
    # Only the addr:port matters to the oracle -- it reads the pinned server_cert.der +
    # directory_pub.der from --client-dir/config, not from the connection-code fingerprint.
    $addr = $srv.Addr
    $ip = ($addr -split ':')[0]
    $clientDir = Join-Path $Root 'dist\MaxSecuClient'
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    & cargo run --release -p maxsecu-live-smoke --manifest-path (Join-Path $Root 'crates\client-app\Cargo.toml') -- `
        --server $addr --host $ip --client-dir $clientDir
    if ($LASTEXITCODE -ne 0) { Die "live-smoke failed ($LASTEXITCODE)" }
}

function Teardown {
    Phase "Teardown"
    if ($script:KeepAlive) {
        Stop-Process -Id $script:KeepAlive.Id -Force -ErrorAction SilentlyContinue
        $script:KeepAlive = $null
    }
    try { & wsl.exe --terminate $Distro 2>$null } catch {}
    Start-Sleep -Seconds 1
    $unreg = $false
    for ($i = 0; $i -lt 5; $i++) {
        & wsl.exe --unregister $Distro 2>$null
        if ($LASTEXITCODE -eq 0) { $unreg = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $unreg) {
        Write-Host "  WARNING: could not unregister distro '$Distro' - remove it manually: wsl --unregister $Distro" -ForegroundColor Yellow
    }
    try {
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
    } catch { Write-Host "  client reset warning: $_" -ForegroundColor DarkYellow }
    if (Test-Path $WorkDir) {
        for ($i = 0; $i -lt 3; $i++) {
            Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
            if (-not (Test-Path $WorkDir)) { break }
            Start-Sleep -Seconds 2
        }
        if (Test-Path $WorkDir) {
            Write-Host "  WARNING: could not fully remove $WorkDir - delete it manually." -ForegroundColor Yellow
        }
    }
    Write-Host "  teardown complete"
}

# --------------------------------------------------------------------------- #
# Backup-rollback additions (used ONLY by test-backup-rollback.ps1).
# --------------------------------------------------------------------------- #

# Build the live-smoke oracle ONCE so `seed` and `verify` run the SAME exe -- a
# rebuild between the two could pick up a different binary/pin and mask a real
# regression. Builds ONLY `-p maxsecu-live-smoke` (never a bare workspace build) so
# client-e2e's dev-only `unpinned-dev` never unifies in and defeats the real
# recovery-pin gate. Returns the absolute path to the built console exe.
function Build-LiveSmoke {
    Phase "Build live-smoke oracle (once)"
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    & cargo build --release -p maxsecu-live-smoke --manifest-path (Join-Path $Root 'crates\client-app\Cargo.toml')
    if ($LASTEXITCODE -ne 0) { Die "live-smoke build failed ($LASTEXITCODE)" }
    $exe = Join-Path $Root 'crates\client-app\target\release\maxsecu-live-smoke.exe'
    if (-not (Test-Path $exe)) { Die "live-smoke exe not found at $exe after build" }
    return $exe
}

# Run one live-smoke phase (seed|verify) against a PRE-BUILT exe, carrying the state
# file across the destroy/restore. live-smoke is a CONSOLE binary (NOT the
# GUI-subsystem client-app exe), so `& $Exe` waits, captures output, and sets
# $LASTEXITCODE correctly. `$SmokeHost` avoids clobbering PowerShell's automatic $Host.
function Invoke-LiveSmokePhase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Exe,
        [Parameter(Mandatory)][ValidateSet('seed', 'verify')][string] $SmokePhase,
        [Parameter(Mandatory)][string] $Server,
        [Parameter(Mandatory)][string] $SmokeHost,
        [Parameter(Mandatory)][string] $ClientDir,
        [Parameter(Mandatory)][string] $State
    )
    Phase "live-smoke --phase $SmokePhase"
    & $Exe --server $Server --host $SmokeHost --client-dir $ClientDir --phase $SmokePhase --state $State
    if ($LASTEXITCODE -ne 0) { Die "live-smoke --phase $SmokePhase failed ($LASTEXITCODE)" }
}
