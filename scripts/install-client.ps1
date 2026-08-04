<#
.SYNOPSIS
    Build the MaxSecu Windows client and produce the shareable handout ZIP.

.DESCRIPTION
    Run ONCE by the admin on a Windows PC after the Linux VPS server has finished
    its first run (so the pinned certs exist and the server printed a connection
    code).

    This script:
      * verifies the Rust (MSVC) + Node/npm toolchains are installed,
      * fetches the pinned server cert over the network and verifies it against
        the connection-code (CERT-only) fingerprint (no SSH required),
      * runs the offline-D5 ceremony inside maxsecu-setup: generates the directory
        root (D5) on THIS PC, uploads the delegation with the one-time -Token
        (which OPENS enrollment on the awaiting server), creates the recovery
        account + the admin's first registration key, and mints the FINAL
        user-facing connection code addr:port#fingerprint(server_cert, D5_pub),
      * builds the UI and the client binary,
      * lays out the admin working client (dist\MaxSecuClient),
      * produces the clean handout (dist\MaxSecuClient-share.zip).

.PARAMETER ConnectionCode
    The connection code install-server printed, of the form addr:port#fingerprint
    (e.g. 123.123.123.123:8443#K7QF9M2ATBZ4C6XU...). NOTE: for the offline-D5 flow
    this fingerprint is the SERVER-CERT-only fingerprint (used to pin TLS while the
    server still awaits delegation); it is NOT the final user-facing code. This
    script mints that final code after the ceremony. Parsed into -ServerAddr, -Port
    and -Fingerprint for you.

.PARAMETER Token
    The one-time delegation token install-server printed. Required for the offline-D5
    ceremony (it authorizes uploading the delegation that opens enrollment). May also
    be supplied via $env:SETUP_DELEGATION_TOKEN for an unattended run; otherwise you
    are prompted.

.PARAMETER ServerAddr
    Public host/IP the client dials + the cert SAN. Manual alternative to
    -ConnectionCode (must be paired with -Fingerprint).

.PARAMETER Port
    Server listen port. Default 8443.

.PARAMETER Fingerprint
    The pin fingerprint (the part after '#' in the connection code). Manual
    alternative to -ConnectionCode (must be paired with -ServerAddr).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1 -ConnectionCode 123.123.123.123:8443#K7QF9M2ATBZ4C6XU...
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    # The connection code the server printed: "addr:port#fingerprint". Primary
    # input -- it is split into $ServerAddr, $Port and $Fingerprint below. Provide
    # this OR the manual -ServerAddr/-Fingerprint pair.
    [Parameter(ParameterSetName = 'Install', Position = 0)]
    [string] $ConnectionCode = '',

    [Parameter(ParameterSetName = 'Install')]
    [string] $ServerAddr = '',

    [Parameter(ParameterSetName = 'Install')]
    [int] $Port = 8443,

    # The pin fingerprint (the text after '#' in the connection code). Load-bearing:
    # the fetched pins are trusted ONLY if their recomputed hash matches this.
    [Parameter(ParameterSetName = 'Install')]
    [string] $Fingerprint = '',

    # Unattended recovery passphrase. When supplied (or via $env:SETUP_RECOVERY_PW),
    # the interactive Read-Host prompt is skipped so the client can be installed
    # non-interactively (e.g. by scripts\test-full-install.ps1). Prefer the env var:
    # a -RecoveryPassphrase value is visible in shell history and process listings for
    # the life of the process, whereas the env var isn't captured in command-line args.
    # Leave both empty for the normal interactive install, which prompts without echoing.
    [Parameter(ParameterSetName = 'Install')]
    [string] $RecoveryPassphrase = '',

    # One-time offline-D5 delegation token (from install-server). Threads the
    # ceremony non-interactively when supplied (or via $env:SETUP_DELEGATION_TOKEN),
    # mirroring -RecoveryPassphrase; an interactive run prompts for it. It is handed
    # to the child maxsecu-setup ONLY via the SETUP_DELEGATION_TOKEN env var (never
    # printed, never persisted) and scrubbed afterwards.
    [Parameter(ParameterSetName = 'Install')]
    [string] $Token = '',

    # Tear the CLIENT down to zero and exit (no build): delete dist\ (both the admin
    # app and the handout ZIP), the recovery + registration secrets in the repo root
    # (recovery_key.blob / recovery_pin.bin / register.key), and the recovery pin
    # embedded into the client crate. Its own parameter set, so no other args are
    # required. Idempotent -- absent files are simply reported and skipped.
    # It RESCUES dist\<client>\keystore\ to dist\_keystore-rescue-<stamp>\ first --
    # that folder holds the Argon2id-sealed private key of whoever signed in from
    # the admin app, and there is no server-side copy of it (see section 1b).
    [Parameter(Mandatory = $true, ParameterSetName = 'Reset')]
    [switch] $Reset,

    # Put the operator's COLD recovery keyblob where the client actually reads it,
    # then exit (no build, no ceremony, no network -- so it works on a fresh PC that
    # has only this checkout, a client folder and the cold blob).
    #
    # THE DEFECT THIS CLOSES: the ceremony writes the sealed blob to
    # <repo-root>\recovery_key.blob (section 4 below), but the client looks for it at
    # <client-folder>\recovery\recovery_key_blob -- a different folder AND a different
    # filename (crates\client-app\src\commands\recovery_login.rs:60
    # `dir.join("recovery").join("recovery_key_blob")`, probed on launch by
    # crates\client-app\src\commands\startup.rs:31). Without this switch nobody can
    # reach the recovery sign-in screen without reading the source.
    #
    # The bytes are copied VERBATIM (the Argon2id seal is never touched) and the
    # SHA-256 is re-checked afterwards; the copy is then ACL-locked to this Windows
    # account. The handout ZIP still never contains it -- that stays deliberate.
    [Parameter(Mandatory = $true, ParameterSetName = 'StageRecovery')]
    [string] $StageRecoveryKey,

    # Remove a previously staged recovery keyblob from a client folder (overwrite,
    # then delete) and exit. Run it the moment the recovery session is over: the
    # staged file is a full copy of the master key, and key + passphrase together
    # decrypt everything.
    [Parameter(Mandatory = $true, ParameterSetName = 'UnstageRecovery')]
    [switch] $UnstageRecoveryKey,

    # Which client folder to stage into / clean. Default: dist\MaxSecuClient (the
    # admin working client this script lays out). Point it at an unzipped handout
    # folder to run the recovery session from that copy instead.
    [Parameter(ParameterSetName = 'StageRecovery')]
    [Parameter(ParameterSetName = 'UnstageRecovery')]
    [string] $ClientDir = ''
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string] $Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Fail {
    param([string] $Text)
    Write-Host ''
    Write-Host "ERROR: $Text" -ForegroundColor Red
    exit 1
}

# Resolve the client folder the recovery keyblob is staged into / removed from.
# Defaults to the admin working client this script lays out (dist\MaxSecuClient).
# Fails closed unless the folder actually holds maxsecu-client-app.exe: the client
# resolves every portable path relative to the folder the EXE sits in
# (crates\client-app\src\main.rs:36-39 current_exe().parent()), so a keyblob dropped
# anywhere else is simply never read -- a silent no-op is the worst outcome here.
function Resolve-ClientDir {
    param([string] $Requested, [string] $RepoRoot)
    $dir = $Requested
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = Join-Path $RepoRoot 'dist\MaxSecuClient' }
    if (-not (Test-Path $dir)) {
        Fail "No client folder at '$dir'. Pass -ClientDir <folder> pointing at the folder that holds maxsecu-client-app.exe -- that is dist\MaxSecuClient after a normal install, or the MaxSecuClient folder a handout ZIP unzips to."
    }
    $dir = (Resolve-Path $dir).Path
    if (-not (Test-Path (Join-Path $dir 'maxsecu-client-app.exe'))) {
        Fail "'$dir' does not contain maxsecu-client-app.exe. The client reads its recovery keyblob from <folder-holding-the-exe>\recovery\recovery_key_blob, so a key placed here would never be found. Point -ClientDir at the folder the exe sits in."
    }
    return $dir
}

# Restrict a FOLDER to this Windows account: drop inherited permissions and grant
# inheritable FullControl to just you, SYSTEM and Administrators -- by SID, so it
# behaves the same on a non-English Windows. Returns $true only when icacls reported
# success. Best-effort by design: a filesystem that cannot carry an ACL (a FAT32 or
# exFAT USB stick) must never abort a recovery session, so the caller warns instead.
#
# FOLDER only, and never with /T: icacls cannot put (OI)(CI) inheritance flags on a
# FILE, and applying them down a tree leaves the file with an EMPTY DACL -- locking
# out its own owner. Harden the folder first, then let a freshly-copied file inherit.
function Set-OwnerOnlyAcl {
    param([string] $Path)
    $ok = $false
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $meSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        & icacls $Path /inheritance:r /grant:r "*${meSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C /Q | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
    } catch {
        $ok = $false
    } finally {
        $ErrorActionPreference = $prev
    }
    return $ok
}

# Undo Set-OwnerOnlyAcl: put the inherited permissions back on the folder and its
# contents. Used only when the hardened ACL turns out to exclude the running token.
function Reset-InheritedAcl {
    param([string] $Path)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & icacls $Path /reset /T /C /Q | Out-Null } catch { } finally { $ErrorActionPreference = $prev }
}

# Can this process actually open and read the file? A hardened ACL that excludes the
# running token would otherwise look like a successful stage and only surface later
# as "No recovery key file on this device" at the sign-in screen.
function Test-FileReadable {
    param([string] $Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try { [void]$fs.ReadByte() } finally { $fs.Dispose() }
        return $true
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# 1. Resolve paths (server address/port/fingerprint are parsed after the reset block)
# ---------------------------------------------------------------------------
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host "Repo root: $Root"

# ---------------------------------------------------------------------------
# 1b. Full reset (-Reset): delete this PC's built app + the security files it
#     created, so the next run starts from zero. Then exit -- no build.
# ---------------------------------------------------------------------------
if ($Reset) {
    Write-Section 'Resetting the client (removing built app + security files)'

    # SAFETY FIRST: dist\<client>\keystore\ holds the Argon2id-sealed PRIVATE KEY of
    # whoever signed in from that client. There is no server-side copy and no admin
    # escape hatch, so deleting dist\ wholesale destroys that account's identity for
    # good (this has already cost one real account). Rescue every non-empty keystore
    # to dist\_keystore-rescue-<stamp>\<client>\keystore\ BEFORE clearing dist\, then
    # delete everything else under dist\. The rescue stays inside the gitignored
    # dist\ tree at the same ACL, so nothing is newly exposed and nothing can be
    # committed. Deliberately NOT rescued: a staged recovery\recovery_key_blob (see
    # -StageRecoveryKey) -- that is a copy of the cold master key and must not
    # linger; the cold original is the authoritative one.
    $DistDir = Join-Path $Root 'dist'
    $RescueRoot = ''
    if (Test-Path $DistDir) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        foreach ($candidate in @(Get-ChildItem -Path $DistDir -Directory -ErrorAction SilentlyContinue)) {
            if ($candidate.Name -like '_keystore-rescue-*') { continue }
            $ks = Join-Path $candidate.FullName 'keystore'
            if (-not (Test-Path $ks)) { continue }
            if (@(Get-ChildItem -Path $ks -File -Recurse -Force -ErrorAction SilentlyContinue).Count -eq 0) { continue }
            if ([string]::IsNullOrEmpty($RescueRoot)) {
                $RescueRoot = Join-Path $DistDir ('_keystore-rescue-' + $stamp)
                New-Item -ItemType Directory -Path $RescueRoot -Force | Out-Null
            }
            $dest = Join-Path $RescueRoot $candidate.Name
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Copy-Item -Path $ks -Destination $dest -Recurse -Force
            Write-Host "  rescued  $ks -> $dest\keystore" -ForegroundColor Green
        }

        foreach ($child in @(Get-ChildItem -Path $DistDir -Force -ErrorAction SilentlyContinue)) {
            if ($child.Name -like '_keystore-rescue-*') { continue }
            Remove-Item -Path $child.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        # No rescue to keep -> remove dist\ entirely, exactly as before.
        if (@(Get-ChildItem -Path $DistDir -Force -ErrorAction SilentlyContinue).Count -eq 0) {
            Remove-Item -Path $DistDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  removed  $DistDir"
        } else {
            Write-Host "  cleared  $DistDir (kept only the keystore rescue)"
        }
    } else {
        Write-Host "  absent   $DistDir" -ForegroundColor DarkGray
    }

    # State this PC accumulated. NOT the git-tracked source, and NOT the build
    # caches (target\, node_modules\) -- those are just caches; a rebuild refreshes
    # them and deleting them only costs you a slow recompile.
    $targets = @(
        (Join-Path $Root 'recovery_key.blob'),
        (Join-Path $Root 'recovery_pin.bin'),
        (Join-Path $Root 'register.key'),
        # Offline-D5 ceremony artifacts (directory root custody + minted code).
        (Join-Path $Root 'd5_key.blob'),
        (Join-Path $Root 'd5_recovery.blob'),
        (Join-Path $Root 'directory_pub.der'),
        (Join-Path $Root 'connection_code.txt'),
        (Join-Path $Root 'crates\client-app\recovery_pin.bin')
    )
    foreach ($t in $targets) {
        if (Test-Path $t) {
            Remove-Item -Path $t -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  removed  $t"
        } else {
            Write-Host "  absent   $t" -ForegroundColor DarkGray
        }
    }

    Write-Host ''
    Write-Host 'Client state removed. This PC is back to zero.' -ForegroundColor Green
    Write-Host ''
    if (-not [string]::IsNullOrEmpty($RescueRoot)) {
        Write-Host 'KEYSTORE RESCUED -- your sealed sign-in key was NOT deleted:' -ForegroundColor Green
        Write-Host "      $RescueRoot"
        Write-Host '      That folder is the ONLY copy of that account''s private key. To keep'
        Write-Host '      signing in as the same user, copy its keystore\ back into the rebuilt'
        Write-Host '      client folder before you launch the app. Delete the rescue once you'
        Write-Host '      are sure you no longer need it -- it is still your sealed private key.'
        Write-Host ''
    }
    Write-Host 'NOTE: this erased recovery_key.blob, the embedded recovery pin, AND the' -ForegroundColor Yellow
    Write-Host '      offline-D5 directory root (d5_key.blob / d5_recovery.blob) -- the' -ForegroundColor Yellow
    Write-Host '      master keys to the OLD server. Only do this to abandon that server.' -ForegroundColor Yellow
    Write-Host '      Any recovery keyblob staged into a client folder was removed too;' -ForegroundColor Yellow
    Write-Host '      your COLD recovery_key.blob (the offline original) is untouched.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'If you unzipped/copied the admin app elsewhere (e.g. your Desktop) and'
    Write-Host 'signed in there, delete that copy too -- it keeps its own login data.'
    Write-Host ''
    Write-Host 'For a completely clean rebuild you may ALSO delete the build caches:'
    Write-Host '  target\  crates\client-app\target\  crates\client-app\ui\node_modules\  crates\client-app\ui\dist\'
    Write-Host ''
    Write-Host 'To build again from scratch (re-run install-server first for a fresh token):' -ForegroundColor Cyan
    Write-Host '  .\scripts\install-client.ps1 -ConnectionCode <addr:port#cert-fp> -Token <token>'
    exit 0
}

# ---------------------------------------------------------------------------
# 1c. Recovery-keyblob staging (-StageRecoveryKey / -UnstageRecoveryKey).
#
#     THE DELIVERY GAP THIS CLOSES. The ceremony (section 4) writes the sealed cold
#     recovery key to <repo-root>\recovery_key.blob, and the operator is told to move
#     that file to offline storage. But the CLIENT looks for it at
#         <folder-holding-the-exe>\recovery\recovery_key_blob
#     (crates\client-app\src\commands\recovery_login.rs:60 -- note the different
#     FOLDER and the different FILENAME: no dot, "blob" last). That path is what
#     crates\client-app\src\commands\startup.rs:31 probes to decide the app opens on
#     the recovery sign-in screen. Nothing in the install path, the handout ZIP or
#     the docs ever bridged the two, so an operator restoring on a fresh PC could not
#     reach recovery at all without reading Rust source.
#
#     Deliberately NOT done automatically at install time: the blob is the crown
#     jewel (key + passphrase = plaintext of every file, forever). It belongs in cold
#     storage, and lands in a live client folder only when the operator explicitly
#     asks for it, for the length of one session.
# ---------------------------------------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($StageRecoveryKey)) {
    Write-Section 'Staging the cold recovery keyblob into a client folder'

    if (-not (Test-Path $StageRecoveryKey)) {
        Fail "No file at '$StageRecoveryKey'. Pass the sealed recovery keyblob the ceremony wrote -- it is named recovery_key.blob and you moved it to cold/offline storage (a USB stick, typically)."
    }
    $SrcBlob = (Resolve-Path $StageRecoveryKey).Path
    if ((Get-Item -Path $SrcBlob) -is [System.IO.DirectoryInfo]) {
        Fail "'$SrcBlob' is a folder. Pass the recovery_key.blob FILE itself."
    }
    $SrcBytes = [System.IO.File]::ReadAllBytes($SrcBlob)

    # Fail closed on the wrong file rather than let the operator discover it as the
    # deliberately opaque "recovery_failed" at the sign-in screen. The recovery key is
    # a client-core keyblob: magic "MXKB", 157 bytes for a classical identity and 221
    # for a PQ (ML-KEM) one (crates\client-core\src\keyblob.rs -- MAGIC/BLOB_V1_LEN/
    # BLOB_V2_LEN). The two easy mistakes are the directory-root blobs, which sit in
    # the same folder and use a DISTINCT magic "MXD5" (crates\client-core\src\
    # seedblob.rs), and recovery_pin.bin, which is a bare public-key pin.
    $Magic = ''
    if ($SrcBytes.Length -ge 4) { $Magic = [System.Text.Encoding]::ASCII.GetString($SrcBytes, 0, 4) }
    if ($Magic -eq 'MXD5') {
        Fail "'$SrcBlob' is a DIRECTORY-ROOT blob (magic MXD5) -- that is d5_key.blob or d5_recovery.blob, not the recovery key. They live beside each other; stage recovery_key.blob instead. Nothing was staged."
    }
    if ($Magic -ne 'MXKB') {
        Fail "'$SrcBlob' is not a MaxSecu recovery keyblob (expected the magic MXKB, found '$Magic'). recovery_pin.bin and directory_pub.der are NOT the recovery key. Nothing was staged."
    }
    if ($SrcBytes.Length -ne 157 -and $SrcBytes.Length -ne 221) {
        Fail "'$SrcBlob' carries the MXKB magic but is $($SrcBytes.Length) bytes (expected 157 or 221) -- it looks truncated or corrupt. Use your cold backup copy. Nothing was staged."
    }

    $ClientPath   = Resolve-ClientDir -Requested $ClientDir -RepoRoot $Root
    $RecoveryDir  = Join-Path $ClientPath 'recovery'
    # EXACTLY the name the client reads -- recovery_key_blob, not recovery_key.blob.
    $RecoveryDest = Join-Path $RecoveryDir 'recovery_key_blob'

    # Restrict the FOLDER first, then drop a FRESH file into it so the copy inherits
    # the restricted ACL. Without this the copy inherits whatever dist\ grants, which
    # on a secondary or shared drive can include Users. (Removing any previous file
    # first is what makes the inherit happen -- overwriting in place keeps the old
    # ACL.) This never changes how the blob is sealed; it only narrows who can read
    # the bytes on this PC.
    New-Item -ItemType Directory -Path $RecoveryDir -Force | Out-Null
    $AclOk = Set-OwnerOnlyAcl -Path $RecoveryDir
    Remove-Item -Path $RecoveryDest -Force -ErrorAction SilentlyContinue
    Copy-Item -Path $SrcBlob -Destination $RecoveryDest -Force

    # The staged copy must be READABLE by this account. A hardened ACL that excluded
    # the running token would look like a successful stage and then fail at the
    # sign-in screen as "no recovery key file on this device", which is exactly the
    # dead end this whole switch exists to remove. If that happens, undo the
    # hardening, re-copy, and carry on with a warning -- never leave an unusable file.
    if (-not (Test-FileReadable -Path $RecoveryDest)) {
        Reset-InheritedAcl -Path $RecoveryDir
        $AclOk = $false
        Remove-Item -Path $RecoveryDest -Force -ErrorAction SilentlyContinue
        Copy-Item -Path $SrcBlob -Destination $RecoveryDest -Force
        if (-not (Test-FileReadable -Path $RecoveryDest)) {
            Remove-Item -Path $RecoveryDest -Force -ErrorAction SilentlyContinue
            Fail "Staged the keyblob to '$RecoveryDest' but this account cannot read it back, even after restoring the inherited permissions. The unreadable copy was deleted; nothing is staged. Check the folder's permissions, or stage into a client folder you own."
        }
    }

    # The seal must cross UNCHANGED: this is a byte copy, nothing re-wraps or re-keys
    # it, so the same passphrase opens it. Prove that rather than assert it.
    $SrcHash = (Get-FileHash -Path $SrcBlob -Algorithm SHA256).Hash.ToLowerInvariant()
    $DstHash = (Get-FileHash -Path $RecoveryDest -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($SrcHash -ne $DstHash) {
        Remove-Item -Path $RecoveryDest -Force -ErrorAction SilentlyContinue
        Fail "The staged copy does not match the source (sha256 $DstHash != $SrcHash). The bad copy was deleted; nothing is staged."
    }

    Write-Host ''
    Write-Host "Staged: $RecoveryDest" -ForegroundColor Green
    Write-Host "  sha256 $($SrcHash.Substring(0,12))... matches the source -- the Argon2id seal is byte-identical,"
    Write-Host '  so the SAME recovery passphrase opens it. Nothing was re-wrapped or re-keyed.'
    if ($AclOk) {
        Write-Host '  Access restricted to your Windows account (inherited permissions removed).'
    } else {
        Write-Host '  WARNING: could not restrict the file permissions -- the copy inherits the' -ForegroundColor Yellow
        Write-Host '           folder ACL. Do not leave it on a shared drive, and unstage as soon' -ForegroundColor Yellow
        Write-Host '           as the session is over.' -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host 'NEXT:' -ForegroundColor Cyan
    Write-Host ('  1. Run  ' + (Join-Path $ClientPath 'maxsecu-client-app.exe'))
    Write-Host '     It now opens on the RECOVERY sign-in screen (a recovery keyblob outranks'
    Write-Host '     a registration key on startup).'
    Write-Host '  2. On a PC that has never registered there is no saved server yet: open'
    Write-Host '     "Server -- set or change" on that screen and paste your connection code'
    Write-Host '     (addr:port#fingerprint) first, then enter the recovery passphrase.'
    Write-Host '  3. When you are finished, remove the staged copy:'
    Write-Host ('        .\scripts\install-client.ps1 -UnstageRecoveryKey -ClientDir "' + $ClientPath + '"')
    Write-Host ''
    Write-Host 'This staged file is a FULL copy of your master key. Whoever holds it AND the' -ForegroundColor Yellow
    Write-Host 'passphrase can read every file of every user. Your cold original is untouched --' -ForegroundColor Yellow
    Write-Host 'keep it offline, and never put this copy in anything you hand out.' -ForegroundColor Yellow
    exit 0
}

if ($UnstageRecoveryKey) {
    Write-Section 'Removing a staged recovery keyblob from a client folder'

    $ClientPath   = Resolve-ClientDir -Requested $ClientDir -RepoRoot $Root
    $RecoveryDir  = Join-Path $ClientPath 'recovery'
    $RecoveryDest = Join-Path $RecoveryDir 'recovery_key_blob'

    if (-not (Test-Path $RecoveryDest)) {
        Write-Host "No staged recovery keyblob at $RecoveryDest -- nothing to remove."
    } else {
        # Overwrite before unlinking so the sealed bytes are not left sitting in the
        # freed extent. BEST EFFORT ONLY: on an SSD (wear levelling) or a
        # copy-on-write/journalling filesystem the old extent can survive. The real
        # protection is, as always, the Argon2id seal plus your passphrase.
        try {
            $Len = (Get-Item -Path $RecoveryDest).Length
            $Buf = New-Object byte[] $Len
            $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $Rng.GetBytes($Buf) } finally { $Rng.Dispose() }
            [System.IO.File]::WriteAllBytes($RecoveryDest, $Buf)
        } catch {
            Write-Host 'Could not overwrite the staged copy first; deleting it anyway.' -ForegroundColor Yellow
        }
        Remove-Item -Path $RecoveryDest -Force
        Write-Host "Removed: $RecoveryDest" -ForegroundColor Green
    }

    if ((Test-Path $RecoveryDir) -and (@(Get-ChildItem -Path $RecoveryDir -Force -ErrorAction SilentlyContinue).Count -eq 0)) {
        Remove-Item -Path $RecoveryDir -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'That client opens on its normal sign-in screen again.'
    Write-Host 'Your COLD recovery_key.blob was never touched -- it stays your only master key.'
    exit 0
}

# Resolve the dial target + fingerprint from either -ConnectionCode or the manual
# -ServerAddr/-Fingerprint pair. The connection code is "addr:port#fingerprint";
# only the fingerprint is load-bearing (the address is untrusted transport info).
if (-not [string]::IsNullOrWhiteSpace($ConnectionCode)) {
    # Split off the fingerprint on '#', then split the address on the LAST ':' so
    # IPv6 / host:port forms parse correctly.
    $codeParts = $ConnectionCode -split '#', 2
    $addrPart  = $codeParts[0].Trim()
    if ($codeParts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($codeParts[1])) {
        Fail "Could not parse a fingerprint from -ConnectionCode '$ConnectionCode'. Expected the form addr:port#fingerprint."
    }
    $Fingerprint = $codeParts[1].Trim()

    $lastColon = $addrPart.LastIndexOf(':')
    if ($lastColon -lt 0) {
        Fail "Could not parse addr:port from -ConnectionCode '$ConnectionCode'. Expected the form addr:port#fingerprint."
    }
    $ServerAddr = $addrPart.Substring(0, $lastColon)
    $portText   = $addrPart.Substring($lastColon + 1)
    $parsedPort = 0
    if (-not [int]::TryParse($portText, [ref] $parsedPort)) {
        Fail "Could not parse a numeric port from -ConnectionCode '$ConnectionCode' (got '$portText')."
    }
    $Port = $parsedPort
}

# Require either a connection code (parsed above) OR the manual pair.
if ([string]::IsNullOrWhiteSpace($ServerAddr) -or [string]::IsNullOrWhiteSpace($Fingerprint)) {
    Fail "Provide -ConnectionCode ""addr:port#fingerprint"" (the code the server printed), or the manual pair -ServerAddr <host/IP> and -Fingerprint <code> (optionally -Port, default 8443)."
}

Write-Host "Server address : $ServerAddr"
Write-Host "Server port    : $Port"
Write-Host "Pin fingerprint: $Fingerprint"

# ---------------------------------------------------------------------------
# 2. Ensure toolchains (do NOT auto-install system-wide)
# ---------------------------------------------------------------------------
Write-Section 'Checking build toolchains'

# rustup installs cargo to %USERPROFILE%\.cargo\bin and normally adds it to the
# user PATH -- but a terminal opened before install (or a customized PATH) won't
# see it, so `Get-Command cargo` reports Rust "missing" when it is in fact
# installed. Recover that common case: if cargo isn't on PATH but exists at the
# standard rustup location, prepend that dir to THIS session's PATH. This only
# makes an already-installed toolchain visible -- it never installs anything.
if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
        Write-Host "cargo not on PATH; using rustup install at $cargoBin" -ForegroundColor DarkYellow
    }
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$node  = Get-Command node  -ErrorAction SilentlyContinue
$npm   = Get-Command npm   -ErrorAction SilentlyContinue

$missing = @()
if ($null -eq $cargo) { $missing += 'cargo (Rust)' }
if ($null -eq $node)  { $missing += 'node' }
if ($null -eq $npm)   { $missing += 'npm' }

if ($missing.Count -gt 0) {
    Write-Host ''
    Write-Host "Missing required tools: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Install them, then re-run this script:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Rust (with the MSVC toolchain):'
    Write-Host '    1. Install "Desktop development with C++" from the Visual Studio'
    Write-Host '       Build Tools (https://visualstudio.microsoft.com/downloads/).'
    Write-Host '    2. Install rustup from https://rustup.rs and choose the default'
    Write-Host '       host triple x86_64-pc-windows-msvc.'
    Write-Host ''
    Write-Host '  Node.js (LTS):'
    Write-Host '    Download and install the LTS build from https://nodejs.org'
    Write-Host ''
    Write-Host '  After installing, open a NEW terminal so PATH is refreshed.'
    Fail 'Required toolchains are missing. See instructions above.'
}

Write-Host "cargo : $($cargo.Source)"
Write-Host "node  : $($node.Source)"
Write-Host "npm   : $($npm.Source)"

# ---------------------------------------------------------------------------
# 3. Fetch + verify the pinned server cert over the network (CERT-ONLY)
# ---------------------------------------------------------------------------
Write-Section 'Fetching + verifying the server cert from the server'

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("maxsecu-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$CertTmp = Join-Path $TmpDir 'server_cert.der'

# Offline-D5 inversion: the server is AWAITING delegation and has NO directory_pub
# yet (the D5 root is generated on THIS PC by the ceremony below). So fetch-pins runs
# in CERT-ONLY mode (no --dir-out): it dials the server, downloads server_cert.der,
# and writes it ONLY if pin_fingerprint(cert, &[]) matches the connection-code
# (CERT-only) fingerprint. On any mismatch/network/parse error it writes NOTHING and
# exits non-zero. directory_pub.der is produced later by the ceremony, not here.
if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
        Write-Host "cargo not on PATH; using rustup install at $cargoBin" -ForegroundColor DarkYellow
    }
}

Write-Host "Fetching the server cert from ${ServerAddr}:${Port} and verifying against the fingerprint ..."
# NOTE: this step builds the maxsecu-setup TOOL, which pulls in a throwaway copy of
# the client-app compiled with a NON-SECURE test pin, so a cargo warning like
#   recovery_pin: NON-SECURE test pin (unpinned-dev) -- do not ship
# may scroll past below. It belongs to the SETUP TOOL's build, NOT to your shipped
# client. The client you distribute is built later and cryptographically VERIFIED at
# the end of this script (real recovery pin, no test pin).
Write-Host 'NOTE: a "recovery_pin: NON-SECURE test pin (unpinned-dev)" cargo warning may scroll' -ForegroundColor DarkGray
Write-Host '      past below -- it is from the setup TOOL''s throwaway build, NOT your shipped' -ForegroundColor DarkGray
Write-Host '      client. The shipped client is cryptographically verified at the end of this script.' -ForegroundColor DarkGray
& cargo run --release --manifest-path (Join-Path $Root 'tools\maxsecu-setup\Cargo.toml') -- fetch-pins `
    --server "${ServerAddr}:${Port}" `
    --host "$ServerAddr" `
    --fingerprint "$Fingerprint" `
    --cert-out "$CertTmp"
if ($LASTEXITCODE -ne 0) {
    Fail "Fetching/verifying the server cert failed (exit code $LASTEXITCODE). Check that the server at ${ServerAddr}:${Port} is reachable and finished its first run, and that the CERT fingerprint '$Fingerprint' exactly matches the one install-server printed."
}

if (-not (Test-Path $CertTmp)) { Fail "server_cert.der is missing at $CertTmp." }
Write-Host "Server cert fetched + verified, ready in $TmpDir"

# ---------------------------------------------------------------------------
# 4. Offline-D5 ceremony: generate the directory root, install the delegation,
#    create the recovery account + first key, and mint the final connection code.
# ---------------------------------------------------------------------------
Write-Section 'Running the offline-D5 ceremony (maxsecu-setup)'

$RecoveryBlob = Join-Path $Root 'recovery_key.blob'
$RecoveryPin  = Join-Path $Root 'recovery_pin.bin'
$RegisterKey  = Join-Path $Root 'register.key'
# Ceremony artifacts. The directory root (D5) is generated + sealed on THIS PC; its
# public half is pinned into every client. d5_key.blob / d5_recovery.blob default
# alongside --out ($Root) inside maxsecu-setup; directory_pub.der is pinned to a
# stable path so a resumed run (and the dist layout below) can reuse it.
$DirPub       = Join-Path $Root 'directory_pub.der'
# The final user-facing connection code addr:port#fingerprint(server_cert, D5_pub),
# persisted so a resumed run can reprint it without re-running the (once-only) setup.
$ConnCodeFile = Join-Path $Root 'connection_code.txt'
# The public addr:port the minted connection code advertises (what users type). This
# is the parsed dial target, NOT a loopback/WSL address.
$ConnectAddr  = "${ServerAddr}:${Port}"
$FinalConnCode = ''

# RESUMABILITY: maxsecu-setup is once-only and produces IRREPLACEABLE files (its
# preflight refuses to overwrite them, and the server 409s a second register /
# already-delegated). If a prior run already completed the ceremony, those files are
# on disk -- skip setup and resume the build rather than fail. This lets you re-run
# after fixing a later step (e.g. staging ffmpeg) without touching the directory root
# / recovery key / first registration key.
if ((Test-Path $RecoveryBlob) -and (Test-Path $RecoveryPin) -and (Test-Path $RegisterKey) -and (Test-Path $DirPub)) {
    Write-Host 'Ceremony artifacts already present from a prior run -- setup is complete; skipping maxsecu-setup.' -ForegroundColor Yellow
    Write-Host "  $RecoveryBlob"
    Write-Host "  $RecoveryPin"
    Write-Host "  $RegisterKey"
    Write-Host "  $DirPub"
    if (Test-Path $ConnCodeFile) {
        $FinalConnCode = (Get-Content -Path $ConnCodeFile -Raw).Trim()
        Write-Host "  connection code (from $ConnCodeFile): $FinalConnCode"
    } else {
        Write-Host "  (no saved connection_code.txt -- see the final summary note below)" -ForegroundColor DarkYellow
    }
} else {
    # Resolve the one-time delegation token: -Token, else $env:SETUP_DELEGATION_TOKEN,
    # else an interactive prompt. Required -- it authorizes uploading the delegation
    # that opens enrollment. Handed to the child ONLY via SETUP_DELEGATION_TOKEN.
    $PlainToken = $Token
    if ([string]::IsNullOrEmpty($PlainToken)) { $PlainToken = $env:SETUP_DELEGATION_TOKEN }
    if ([string]::IsNullOrEmpty($PlainToken)) {
        Write-Host 'Paste the ONE-TIME delegation token that install-server printed.'
        $PlainToken = (Read-Host 'Delegation token').Trim()
    } else {
        Write-Host 'Using a non-interactively supplied delegation token.' -ForegroundColor DarkYellow
    }
    if ([string]::IsNullOrEmpty($PlainToken)) {
        Fail 'A delegation token is required (install-server printed it). Pass -Token <token> or set $env:SETUP_DELEGATION_TOKEN.'
    }

    # Prefer a non-interactively supplied passphrase (param or env var); fall back to
    # an interactive, non-echoed prompt. The plaintext is handed to the child process
    # ONLY via the SETUP_RECOVERY_PW env var below (never printed, never persisted).
    $PlainPw = $RecoveryPassphrase
    if ([string]::IsNullOrEmpty($PlainPw)) { $PlainPw = $env:SETUP_RECOVERY_PW }
    if ([string]::IsNullOrEmpty($PlainPw)) {
        Write-Host 'Choose a RECOVERY passphrase. Write it down and keep it offline with'
        Write-Host 'recovery_key.blob -- together they are the ONLY way to recover the account'
        Write-Host 'AND the directory root (it also seals the D5 recovery backup).'
        $SecurePw = Read-Host -AsSecureString 'Recovery passphrase'
        $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePw)
        try {
            $PlainPw = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        }
    } else {
        Write-Host 'Using a non-interactively supplied recovery passphrase.' -ForegroundColor DarkYellow
    }
    if ([string]::IsNullOrEmpty($PlainPw)) {
        Fail 'Recovery passphrase cannot be empty.'
    }

    $SetupExit = 0
    $SetupOut  = @()
    $env:SETUP_RECOVERY_PW      = $PlainPw
    $env:SETUP_DELEGATION_TOKEN = $PlainToken
    $env:SETUP_CONNECT_ADDR     = $ConnectAddr
    $env:SETUP_DIR_PUB_OUT      = $DirPub
    try {
        # NOTE: like the fetch-pins step, this builds the maxsecu-setup TOOL, so a
        #   recovery_pin: NON-SECURE test pin (unpinned-dev) -- do not ship
        # cargo warning may scroll past. It belongs to the setup TOOL's throwaway build,
        # NOT to your shipped client, which is built later and cryptographically verified
        # at the end of this script.
        Write-Host 'NOTE: a "recovery_pin: NON-SECURE test pin (unpinned-dev)" cargo warning may scroll' -ForegroundColor DarkGray
        Write-Host '      past below -- it is from the setup TOOL''s throwaway build, NOT your shipped' -ForegroundColor DarkGray
        Write-Host '      client. The shipped client is cryptographically verified at the end of this script.' -ForegroundColor DarkGray
        # Capture STDOUT so we can lift the machine-parseable "CONNECTION-CODE <code>"
        # line the ceremony prints; STDERR (progress) still streams to the console.
        $SetupOut = & cargo run --release --manifest-path (Join-Path $Root 'tools\maxsecu-setup\Cargo.toml') -- `
            --server "${ServerAddr}:${Port}" `
            --host "$ServerAddr" `
            --cert "$CertTmp" `
            --out "$RecoveryBlob" `
            --pin-out "$RecoveryPin" `
            --first-key-out "$RegisterKey"
        $SetupExit = $LASTEXITCODE
    } finally {
        # Scrub the secrets/params from the environment and local variables.
        Remove-Item Env:\SETUP_RECOVERY_PW -ErrorAction SilentlyContinue
        Remove-Item Env:\SETUP_DELEGATION_TOKEN -ErrorAction SilentlyContinue
        Remove-Item Env:\SETUP_CONNECT_ADDR -ErrorAction SilentlyContinue
        Remove-Item Env:\SETUP_DIR_PUB_OUT -ErrorAction SilentlyContinue
        $PlainPw = $null
        $PlainToken = $null
        $RecoveryPassphrase = $null
        $Token = $null
    }

    # Echo the captured setup output so the operator still sees its banner/summary.
    if ($SetupOut) { $SetupOut | ForEach-Object { Write-Host $_ } }

    if ($SetupExit -eq 3) {
        Write-Host ''
        Write-Host 'NOTE: the server is already set up / already delegated (exit code 3).' -ForegroundColor Yellow
        Write-Host '      Nothing was re-registered. Reusing existing artifacts if present.' -ForegroundColor Yellow
        if (-not (Test-Path $RecoveryPin)) {
            Fail "The server is already set up but no existing recovery_pin.bin was found at $RecoveryPin. You need the recovery_pin.bin from the original setup to build a working client."
        }
        if (-not (Test-Path $DirPub)) {
            Fail "The server is already delegated but no existing directory_pub.der was found at $DirPub. You need the directory pin from the original ceremony (or restore the D5 backup with 'maxsecu-setup restore') to build a working client."
        }
        if (Test-Path $ConnCodeFile) {
            $FinalConnCode = (Get-Content -Path $ConnCodeFile -Raw).Trim()
        }
    } elseif ($SetupExit -ne 0) {
        Fail "maxsecu-setup / the D5 ceremony failed (exit code $SetupExit). Check the server address ${ServerAddr}:${Port}, that the cert matches the running server, and that the delegation token is valid and unused."
    } else {
        # Lift the minted connection code from the captured stdout and persist it.
        $ccMatch = $SetupOut | Select-String -Pattern '^\s*CONNECTION-CODE\s+(\S.*)$' | Select-Object -First 1
        if ($null -ne $ccMatch) {
            $FinalConnCode = $ccMatch.Matches[0].Groups[1].Value.Trim()
            [System.IO.File]::WriteAllText($ConnCodeFile, $FinalConnCode + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "Ceremony complete. Final connection code minted: $FinalConnCode" -ForegroundColor Green
        } else {
            Write-Host 'WARNING: setup succeeded but no CONNECTION-CODE line was found in its output.' -ForegroundColor Yellow
        }
        if (-not (Test-Path $DirPub)) {
            Fail "The ceremony reported success but directory_pub.der is missing at $DirPub. Cannot build a working client without the directory pin."
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Embed the recovery pin into the client crate
# ---------------------------------------------------------------------------
Write-Section 'Embedding recovery_pin.bin into the client crate'

$PinDest = Join-Path $Root 'crates\client-app\recovery_pin.bin'
if (-not (Test-Path $RecoveryPin)) {
    Fail "recovery_pin.bin not found at $RecoveryPin -- cannot embed it into the client."
}
Copy-Item -Path $RecoveryPin -Destination $PinDest -Force
Write-Host "Copied recovery_pin.bin -> $PinDest"

# ---------------------------------------------------------------------------
# 6. Build the UI
# ---------------------------------------------------------------------------
Write-Section 'Building the UI (npm ci + npm run build)'

Push-Location (Join-Path $Root 'crates\client-app\ui')
try {
    & npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit code $LASTEXITCODE)." }
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed (exit code $LASTEXITCODE)." }
} finally {
    Pop-Location
}
Write-Host 'UI built.'

# ---------------------------------------------------------------------------
# 7. Build the client binary
# ---------------------------------------------------------------------------
Write-Section 'Building the client (cargo build --release)'

# The client embeds a pinned static ffmpeg.exe via include_bytes! (author-side
# video transcode). vendor\ffmpeg\ffmpeg.exe is gitignored, so a fresh checkout
# lacks it and the build fails with a cryptic include_bytes error. Stage it first
# with the pinned fetch script (idempotent: it skips the download if already staged
# and matching the pinned SHA-256).
$FfmpegExe = Join-Path $Root 'vendor\ffmpeg\ffmpeg.exe'
if (-not (Test-Path $FfmpegExe)) {
    Write-Host 'vendor\ffmpeg\ffmpeg.exe is missing -- fetching the pinned build (scripts\fetch-ffmpeg.ps1) ...'
    try {
        & (Join-Path $Root 'scripts\fetch-ffmpeg.ps1')
    } catch {
        Write-Host "fetch-ffmpeg.ps1 failed: $_" -ForegroundColor Red
        Fail 'Could not fetch the pinned ffmpeg. Run scripts\fetch-ffmpeg.ps1 manually; if it reports a SHA-256 mismatch, BtbN latest has rolled -- obtain the matching build or re-pin the SHA (scripts\fetch-ffmpeg.ps1, vendor\ffmpeg\README.md, crates\client-app\src\ffmpeg_bin.rs), then re-run.'
    }
    if (-not (Test-Path $FfmpegExe)) {
        Fail "vendor\ffmpeg\ffmpeg.exe is still missing after scripts\fetch-ffmpeg.ps1."
    }
}

& cargo build --release --manifest-path (Join-Path $Root 'crates\client-app\Cargo.toml') -p maxsecu-client-app
if ($LASTEXITCODE -ne 0) {
    Fail "cargo build of the client failed (exit code $LASTEXITCODE)."
}

$ClientExe = Join-Path $Root 'crates\client-app\target\release\maxsecu-client-app.exe'
if (-not (Test-Path $ClientExe)) {
    Fail "Client binary not found at $ClientExe after a successful build."
}
Write-Host "Client binary: $ClientExe"

$UiDist = Join-Path $Root 'crates\client-app\ui\dist'
if (-not (Test-Path $UiDist)) {
    Fail "UI dist folder not found at $UiDist after the UI build."
}

# ---------------------------------------------------------------------------
# 7b. Verify the SHIPPED client embedded the real recovery pin (not the test pin)
# ---------------------------------------------------------------------------
# Prove the binary we just built embedded YOUR real recovery_pin.bin and not the
# NON-SECURE test pin. The client's headless --print-recovery-pin-fp subcommand
# prints sha256(embedded_pin) + whether it is the test pin, then exits; because the
# pin is include_bytes! of recovery_pin.bin, that hash equals the file's SHA-256.
Write-Section 'Verifying the shipped client embedded your real recovery pin'

# Capture the subcommand's stdout via Start-Process -Wait with a redirected output
# file, NOT the '&' call operator. The client is a GUI-subsystem (windowless)
# binary (main.rs: #![windows_subsystem = "windows"]); the verify subcommand exits
# before any window, but '&' does not reliably WAIT for a GUI-subsystem process, so
# capture can race and come back empty. Start-Process -Wait blocks on the process
# handle and -RedirectStandardOutput deterministically writes the two lines to a
# file. stdout/stderr go to SEPARATE files (PowerShell forbids the same path for both).
$FpOutFile = Join-Path $TmpDir 'recovery-pin-fp.out'
$FpErrFile = Join-Path $TmpDir 'recovery-pin-fp.err'
$FpProc = Start-Process -FilePath $ClientExe -ArgumentList '--print-recovery-pin-fp' `
    -Wait -PassThru -NoNewWindow `
    -RedirectStandardOutput $FpOutFile -RedirectStandardError $FpErrFile
if ($null -eq $FpProc -or $FpProc.ExitCode -ne 0) {
    $ec = if ($null -eq $FpProc) { '<not started>' } else { $FpProc.ExitCode }
    Fail "The shipped client failed to report its embedded recovery pin (--print-recovery-pin-fp exit code $ec). Do not distribute this build."
}

$FpText = if (Test-Path $FpOutFile) { Get-Content -Raw $FpOutFile } else { '' }
$shaMatch   = [regex]::Match($FpText, '(?im)^\s*recovery-pin-sha256:\s*([0-9a-f]{64})\s*$')
$isTestMatch = [regex]::Match($FpText, '(?im)^\s*recovery-pin-is-test:\s*(true|false)\s*$')
if (-not $shaMatch.Success -or -not $isTestMatch.Success) {
    Fail "Could not parse the recovery-pin fingerprint from the shipped client's output. Do not distribute this build.`nOutput was:`n$FpText"
}
$EmbeddedSha = $shaMatch.Groups[1].Value.ToLowerInvariant()
$IsTestPin   = $isTestMatch.Groups[1].Value.ToLowerInvariant()

if (-not (Test-Path $RecoveryPin)) {
    Fail "recovery_pin.bin not found at $RecoveryPin -- cannot verify the shipped client's embedded pin."
}
$ExpectedSha = (Get-FileHash -Path $RecoveryPin -Algorithm SHA256).Hash.ToLowerInvariant()

if ($IsTestPin -ne 'false') {
    Fail "The shipped client embedded the NON-SECURE test pin (recovery-pin-is-test: $IsTestPin). Do not distribute this build; re-run the ceremony so your real recovery_pin.bin is embedded."
}
if ($EmbeddedSha -ne $ExpectedSha) {
    Fail "The shipped client did NOT embed your real recovery pin (embedded sha256 $EmbeddedSha != recovery_pin.bin sha256 $ExpectedSha). Do not distribute this build."
}

Write-Host "  VERIFIED - real recovery pin embedded (sha256 $($EmbeddedSha.Substring(0,12))...); no test pin present." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 8. Lay out the admin working client (dist\MaxSecuClient)
# ---------------------------------------------------------------------------
Write-Section 'Laying out the admin working client (dist\MaxSecuClient)'

$DistDir  = Join-Path $Root 'dist'
$AdminDir = Join-Path $DistDir 'MaxSecuClient'
if (Test-Path $AdminDir) {
    Remove-Item -Path $AdminDir -Recurse -Force
}
New-Item -ItemType Directory -Path $AdminDir -Force | Out-Null

# exe
Copy-Item -Path $ClientExe -Destination $AdminDir -Force

# ui\ (contents of the built dist)
$AdminUi = Join-Path $AdminDir 'ui'
New-Item -ItemType Directory -Path $AdminUi -Force | Out-Null
Copy-Item -Path (Join-Path $UiDist '*') -Destination $AdminUi -Recurse -Force

# config\ pins
$AdminConfig = Join-Path $AdminDir 'config'
New-Item -ItemType Directory -Path $AdminConfig -Force | Out-Null
Copy-Item -Path $CertTmp -Destination (Join-Path $AdminConfig 'server_cert.der') -Force
# directory_pub.der is the D5 pin produced by the ceremony above (NOT fetched from the
# server, which never holds the root) -- ship it so the client fails closed to trust it.
Copy-Item -Path $DirPub  -Destination (Join-Path $AdminConfig 'directory_pub.der') -Force

# ADMIN-ONLY: place the sealed directory root (d5_key.blob) beside the pins so the
# running admin client's on-login auto-renew + the renew_delegation command can find
# it. The client resolves it at <app_dir>/config/d5_key.blob (crate::commands::renew::
# d5_blob_path), i.e. dist\MaxSecuClient\config here. Its PRESENCE is what marks THIS
# PC as the directory authority; on any other device (no blob) auto-renew is a silent
# no-op. The ceremony wrote it to the repo root, sealed under the recovery passphrase.
#
# CRITICAL: this copy targets the ADMIN working client ONLY. The handout ZIP is built
# from a SEPARATE staging dir (dist\_share_stage below) whose config copies ONLY
# server_cert.der + directory_pub.der -- d5_key.blob (and d5_recovery.blob) are NEVER
# staged there, so the share ZIP can never leak the directory root. Do NOT add this
# copy to the share-stage block.
#
# Guarded: absent only on an odd resumed/restored run that recovered just the pins;
# renewal is a best-effort admin convenience, so a missing blob is a warning, not a
# failure (users still enroll + use the app fine; renewal just won't run from here).
$D5Blob = Join-Path $Root 'd5_key.blob'
if (Test-Path $D5Blob) {
    Copy-Item -Path $D5Blob -Destination (Join-Path $AdminConfig 'd5_key.blob') -Force
    Write-Host 'Placed d5_key.blob in the admin config (enables in-app delegation auto-renew).'
} else {
    Write-Host 'No d5_key.blob present (not this PC''s original ceremony); in-app auto-renew disabled here.' -ForegroundColor Yellow
}

# register.key for the admin's own first enrollment (only when freshly minted)
if (Test-Path $RegisterKey) {
    Copy-Item -Path $RegisterKey -Destination (Join-Path $AdminDir 'register.key') -Force
    Write-Host 'Placed register.key in the admin working client (first enrollee becomes admin).'
} else {
    Write-Host 'No register.key present (server was already set up); admin folder built without one.' -ForegroundColor Yellow
}

# Empty runtime dirs the app expects (mirror packaging/package.sh layout).
foreach ($d in @('keystore', 'index', 'cache', 'logs')) {
    New-Item -ItemType Directory -Path (Join-Path $AdminDir $d) -Force | Out-Null
}
Write-Host "Admin working client ready: $AdminDir"

# ---------------------------------------------------------------------------
# 9. Build the CLEAN handout + ZIP
# ---------------------------------------------------------------------------
Write-Section 'Building the clean handout ZIP (dist\MaxSecuClient-share.zip)'

$StageRoot   = Join-Path $DistDir '_share_stage'
$ShareClient = Join-Path $StageRoot 'MaxSecuClient'
if (Test-Path $StageRoot) {
    Remove-Item -Path $StageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $ShareClient -Force | Out-Null

# exe only (NO register.key, NO recovery blob, NO keystore/cache/logs).
Copy-Item -Path $ClientExe -Destination $ShareClient -Force

# ui\
$ShareUi = Join-Path $ShareClient 'ui'
New-Item -ItemType Directory -Path $ShareUi -Force | Out-Null
Copy-Item -Path (Join-Path $UiDist '*') -Destination $ShareUi -Recurse -Force

# config\ pins
$ShareConfig = Join-Path $ShareClient 'config'
New-Item -ItemType Directory -Path $ShareConfig -Force | Out-Null
Copy-Item -Path $CertTmp -Destination (Join-Path $ShareConfig 'server_cert.der') -Force
# The ceremony-produced D5 directory pin (see the admin config note above).
Copy-Item -Path $DirPub  -Destination (Join-Path $ShareConfig 'directory_pub.der') -Force

# ---------------------------------------------------------------------------
# 10. START-HERE.txt (plain language, CRLF line endings)
# ---------------------------------------------------------------------------
$StartHereLines = @(
    'MaxSecu -- how to get started',
    '=============================',
    '',
    '1. Unzip this folder anywhere you like (for example your Desktop).',
    '',
    '2. Open the MaxSecuClient folder and double-click:',
    '       maxsecu-client-app.exe',
    '',
    '   Windows may warn that the publisher is unknown. That is expected for',
    '   this app (it is not signed). Click "More info", then "Run anyway".',
    '',
    '3. When the app opens, on the sign-up screen enter:',
    '     * The server address your admin gave you, for example:',
    '           123.123.123.123:8443',
    '     * The registration key your admin sent you (a one-time key).',
    '',
    '4. Choose a username and a strong passphrase. Keep your passphrase safe --',
    '   it protects your account and cannot be reset for you.',
    '',
    "That's it. You're in."
)
$StartHere = Join-Path $ShareClient 'START-HERE.txt'
$StartHereText = ($StartHereLines -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($StartHere, $StartHereText, (New-Object System.Text.UTF8Encoding($false)))

# FAIL CLOSED before zipping: the handout must never carry a secret. The copies
# above are explicit (exe + ui\ + the two pins), so this should never fire -- it is
# a standing assertion, added because dist\MaxSecuClient can now legitimately hold a
# staged recovery\recovery_key_blob (-StageRecoveryKey). If a future edit ever stages
# a client FOLDER wholesale instead of naming files, this stops the crown jewel, the
# directory root, a keystore or a registration key reaching every user.
$Leaks = @(Get-ChildItem -Path $ShareClient -Recurse -Force -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -eq 'recovery_key_blob' -or $_.Name -eq 'local_key_blob' -or
        $_.Name -eq 'register.key' -or $_.Name -eq 'recovery_pin.bin' -or
        $_.Extension -eq '.blob'
    })
if ($Leaks.Count -gt 0) {
    Fail ("Refusing to build the handout ZIP -- secret-shaped files are in the staged tree:`n  " + (($Leaks | ForEach-Object { $_.FullName }) -join "`n  "))
}

# Zip only the clean staged MaxSecuClient folder.
$ShareZip = Join-Path $DistDir 'MaxSecuClient-share.zip'
if (Test-Path $ShareZip) {
    Remove-Item -Path $ShareZip -Force
}
Compress-Archive -Path $ShareClient -DestinationPath $ShareZip -Force
Write-Host "Handout ZIP: $ShareZip"

# ---------------------------------------------------------------------------
# Cleanup temp
# ---------------------------------------------------------------------------
Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 11. Final summary for the admin
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '================ MAXSECU CLIENT BUILD COMPLETE ================' -ForegroundColor Green
Write-Host ''
Write-Host 'PROD-READY [OK] -- shipped client cryptographically verified: real recovery pin' -ForegroundColor Green
Write-Host '                embedded (no test pin), delegation installed / enrollment OPEN,' -ForegroundColor Green
Write-Host '                and the server + directory pins are committed into the connection code.' -ForegroundColor Green
Write-Host ''
Write-Host 'DELEGATION INSTALLED -- enrollment is now OPEN on the server.' -ForegroundColor Green
Write-Host 'The directory root (D5) was generated on THIS PC; the server holds only a'
Write-Host 'short-lived operational key it cannot renew without you.'
Write-Host ''
if (-not [string]::IsNullOrWhiteSpace($FinalConnCode)) {
    Write-Host 'CONNECTION CODE (the final, user-facing code -- this is what you hand out):' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "        $FinalConnCode" -ForegroundColor White
    Write-Host ''
    Write-Host "    Saved to: $ConnCodeFile"
    Write-Host '    Users only need the ADDRESS part (before the "#") plus their registration'
    Write-Host '    key; the pins in the ZIP already commit to this code.'
} else {
    Write-Host 'CONNECTION CODE: (not captured this run -- it was minted on the original run.' -ForegroundColor Yellow
    Write-Host "    See $ConnCodeFile, or re-derive it on the server with 'maxsecu-portable-server"
    Write-Host "    print-fingerprint', or 'maxsecu-setup restore' from the D5 backup.)" -ForegroundColor Yellow
}
Write-Host ''
Write-Host 'RECOVERY (do this now):' -ForegroundColor Yellow
Write-Host '  * Move these files to COLD / OFFLINE storage and never lose them:'
Write-Host "        $RecoveryBlob"
Write-Host "        $(Join-Path $Root 'd5_recovery.blob')   (the directory root backup)"
Write-Host '    Remember the recovery passphrase you just typed. Together they are the'
Write-Host '    ONLY way to recover the account AND the directory root -- there is no backup.'
Write-Host ''
Write-Host '  * TO USE IT LATER (breakglass sign-in, on this PC or a fresh one): the client'
Write-Host '    reads the recovery key from <client folder>\recovery\recovery_key_blob, which'
Write-Host '    is a DIFFERENT folder and a DIFFERENT filename from the recovery_key.blob'
Write-Host '    above. Do not copy it by hand -- run:'
Write-Host '        .\scripts\install-client.ps1 -StageRecoveryKey <path-to-recovery_key.blob>'
Write-Host '    (add -ClientDir <folder> to stage into an unzipped handout copy instead of'
Write-Host '    dist\MaxSecuClient). The app then opens on the recovery sign-in screen. When'
Write-Host '    the session is done, remove the copy again:'
Write-Host '        .\scripts\install-client.ps1 -UnstageRecoveryKey'
Write-Host '    The handout ZIP never contains the recovery key -- that is deliberate.'
Write-Host ''
Write-Host 'BECOME THE ADMIN:' -ForegroundColor Cyan
Write-Host "  * Run the admin client and enroll (the FIRST person to enroll becomes admin):"
Write-Host "        $AdminDir\maxsecu-client-app.exe"
Write-Host ''
Write-Host 'ADD MORE USERS:' -ForegroundColor Cyan
Write-Host '  * In the app (Admin screen) mint a single-use registration key, then send'
Write-Host '    the new user BOTH of these (separately):'
Write-Host "        1. the ZIP:  $ShareZip"
Write-Host '        2. the registration key you just minted'
Write-Host ''
Write-Host '==============================================================' -ForegroundColor Green
