<#
.SYNOPSIS
    Unattended full-install / reinstall E2E test for MaxSecu.
.DESCRIPTION
    Provisions a throwaway WSL Ubuntu-22.04 distro, installs the server via the real
    install-server.sh, builds the client via install-client.ps1, runs the headless
    live-smoke oracle against the live pair, then exercises the reset+reinstall path
    and re-runs the oracle, and finally tears everything down. Fail-fast; on
    completion OR failure it tears down (unregisters the distro + resets the client)
    unless -KeepOnFailure is set, which leaves the distro up for debugging.
.PARAMETER Port           Server listen port (default 18443).
.PARAMETER KeepOnFailure  Skip teardown on failure (for debugging).
.PARAMETER Iterations     Number of back-to-back clean passes (default 1).
#>
[CmdletBinding()]
param(
    # Default off the common 8443 so the WSL server doesn't collide with a host
    # service on that port. Under WSL2 mirrored networking the distro shares the
    # host's stack, so a host listener on 8443 makes the server's 0.0.0.0:8443 bind
    # fail with EADDRINUSE. Override with -Port if 18443 is also taken.
    [int]    $Port = 18443,
    [switch] $KeepOnFailure,
    [int]    $Iterations = 1
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1's progress stream can overflow the script call stack on
# large operations (notably Invoke-WebRequest); silence it globally.
$ProgressPreference = 'SilentlyContinue'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Stamp = Get-Date -Format 'yyyyMMddHHmmss'
$Distro = "maxsecu-test-$Stamp"
$WorkDir = Join-Path $env:TEMP "maxsecu-test-$Stamp"
$RootFsCache = Join-Path $env:LOCALAPPDATA 'maxsecu-test\ubuntu-22.04-rootfs.tar.gz'
$RecoveryPw = "livesmoke-recovery-$Stamp!"
# Holds an open `wsl` session so WSL2 doesn't idle-terminate the distro (which would
# kill the server) between our wsl calls during the long Windows-side client build.
$KeepAlive = $null

function Phase($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Die($t)   { Write-Host "FAIL: $t" -ForegroundColor Red; throw $t }

# Run a command inside the distro as the default user; throws on non-zero exit.
# NB: the executable is invoked as `wsl.exe` (never bare `wsl`) throughout this
# script — PowerShell resolves functions before executables, so a function named
# `Wsl` + a bare `& wsl` would recurse into the function until the stack overflows.
function Invoke-WslCmd($cmd) {
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

    # Wait for systemd to reach running/degraded (degraded is fine — some units inactive).
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
function Install-Server([string]$mode) {
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
    $log = Invoke-WslCmd "cd ~/maxsecu && ./scripts/install-server.sh --public 127.0.0.1 --port $Port --no-dropbox"

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
# Positive proof: on the server, `print-fingerprint` returns the full pin fingerprint
# ONLY once directory_pub.der has been pinned by the delegation (before that the server
# is awaiting and has no directory pin). `print-token` also flips to empty once the
# one-time token is burned. We assert the fingerprint is non-empty. Data dir + binary
# match install-server.sh's defaults for this layout: ~/maxsecu-server-data and the
# release binary under the copied source tree.
function Confirm-EnrollmentOpen {
    Phase "Confirm enrollment OPENED (delegation installed)"
    # print-fingerprint reads <data_dir>/client-pins/directory_pub.der (written when
    # the delegation is installed) off the filesystem -- no DATABASE_URL needed. Retry
    # a few times in case the server writes that pin a beat after acknowledging the
    # ceremony's delegation upload, so a momentary lag can't produce a false failure.
    $fp = ''
    for ($i = 0; $i -lt 10; $i++) {
        $fp = (Invoke-WslCmd "cd ~/maxsecu && MAXSECU_DATA_DIR=`"`$HOME/maxsecu-server-data`" ./target/release/maxsecu-portable-server print-fingerprint 2>/dev/null || true").Trim()
        if (-not [string]::IsNullOrWhiteSpace($fp)) { break }
        Start-Sleep -Seconds 1
    }
    if ([string]::IsNullOrWhiteSpace($fp)) {
        Die "server still reports no directory pin after the ceremony -- delegation was NOT installed / enrollment is still CLOSED"
    }
    Write-Host "  server now holds a directory delegation (fingerprint present) -- enrollment OPEN"
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

try {
    # Guarantee a clean client state regardless of what a prior run (or prior local
    # work) left in the repo root — otherwise install-client.ps1's resumability would
    # reuse a stale recovery_pin.bin/register.key and bind to the wrong server.
    Write-Host "==== Pre-clean client state ===="  -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null

    for ($iter = 1; $iter -le $Iterations; $iter++) {
        Phase "PASS $iter of $Iterations"
        Provision-Wsl
        Copy-Source
        $srv = Install-Server 'install'
        Build-Client $srv
        Confirm-EnrollmentOpen
        Run-Smoke $srv

        Phase "Reset + reinstall path"
        Install-Server 'reset' | Out-Null
        & powershell -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts\install-client.ps1') -Reset | Out-Null
        $srv2 = Install-Server 'install'
        Build-Client $srv2
        Confirm-EnrollmentOpen
        Run-Smoke $srv2

        Teardown
    }
    Write-Host "`nALL PASSES GREEN ($Iterations)" -ForegroundColor Green
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
