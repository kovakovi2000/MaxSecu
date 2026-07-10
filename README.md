# MaxSecu — private, encrypted file storage

MaxSecu is a private place to store and share files. It runs on a small server
computer that you control. The important part: the server never sees your files
in a readable form. Everything is scrambled (encrypted) on your own device
before it is sent, and it stays scrambled on the server. This is called
"zero-knowledge" storage — even the server owner cannot read what is inside.

This guide walks you through setting it up from scratch. You do not need to be
technical. Most of it is copy-paste.

---

## What you'll need

- A **Windows PC** — this is where you (the admin) run the app.
- An **Ubuntu 22.04 VPS** — a rented Linux server on the internet. When you rent
  one, the provider gives you a **public IP address** (a string of numbers like
  `123.123.123.123`) and an **SSH login** for it (usually something like
  `root@123.123.123.123`). SSH is just the way you log in to that server.
- About **30 minutes**.
- Some patience the first time. MaxSecu is **built from its source code** rather
  than downloaded ready-made, so the very first setup compiles a lot of things
  and takes a while. This is a one-time cost — after that, everything is fast.

Throughout this guide, wherever you see **`YOUR_SERVER_IP`**, replace it with the
real public IP address of your VPS.

---

## How it fits together

There are three pieces:

- **The server** — runs on your Ubuntu VPS. People reach it at
  `YOUR_SERVER_IP:8443` (that `:8443` is just the "door number" the server
  listens on).
- **Your admin app** — runs on your Windows PC. You build it once. The first
  person to sign up becomes the admin (that's you).
- **A shareable app** — a single ZIP file you hand out to other people so they
  can use your server too.

You do Part 1 on the server, Part 2 on your Windows PC, and Part 3 whenever you
want to add a new person.

### Who's in charge — the trust model (short version)

The security of the whole system rests on a master signing key called the
**directory root**. Here's the important design choice: that key is created and
kept **on your Windows admin PC**, never on the internet-facing server.

The setup is automatic — you don't do anything special. When you run
`install-server.sh` (Part 1) it comes up **awaiting delegation** with **sign-up
closed**, and prints a one-time **delegation token**. When you then run
`install-client.ps1` (Part 2) and paste that token in, your PC quietly performs a
one-time **delegation ceremony**: it generates the directory root locally, hands
the server a short-lived *operational* key it can use day-to-day, and flips
sign-up **open**. The server can serve users with that operational key, but it can
never mint a new one or extend its own authority — only your admin PC can, because
only your PC holds the root. So even if the server were fully compromised, an
attacker could not silently become the directory authority for your users.

That short-lived key renews itself automatically: whenever you (the admin) sign in
on your admin PC with your recovery passphrase, the app quietly renews the
delegation in the background. On everyone else's PC this does nothing (they don't
hold the root), so there's nothing for your users to manage. Just keep signing in
periodically on the admin PC and the server stays delegated.

---

## Part 1 — Set up the server (do this once)

First, log in to your VPS from your Windows PC. Open **PowerShell** (search for
it in the Start menu) and type this, using the login your VPS provider gave you:

```
ssh root@YOUR_SERVER_IP
```

The first time you connect, it will ask something like "Are you sure you want to
continue connecting?" — type **`yes`** and press Enter. Then enter the password
(or it uses your SSH key automatically). You are now "inside" the server.

> If your VPS uses a non-standard SSH port (a common hardening step), add `-p`
> with that port, e.g. `ssh -p 14269 root@YOUR_SERVER_IP`. This only affects how
> you log in here; the client installer in Part 2 no longer uses SSH at all.

Now run these three lines, one after another:

```
git clone <YOUR_REPO_URL> maxsecu
cd maxsecu
./scripts/install-server.sh --public
```

**About `<YOUR_REPO_URL>`:** this is the one thing you must fill in yourself. It
is the web address where this MaxSecu code lives (the place you copied it from).
Everything else runs exactly as written.

That third line does all the heavy lifting: it installs everything the server
needs, builds MaxSecu, sets up its database, and turns the server on so it stays
running permanently — even after a reboot. Because `--public` is set, it may pause
to show the public IP address it detected and ask you to confirm it is correct;
just check it matches your VPS and continue.

When it finishes, the server is **awaiting delegation** (sign-up is closed until
you finish Part 2), and it prints a summary with three things you carry to your
Windows PC:

- your **public address** (like `YOUR_SERVER_IP:8443`),
- a **server-cert fingerprint** (a short code that lets your PC pin this exact
  server over the network — no SSH file copy needed), and
- a **one-time delegation token** (single-use; keep it secret until you use it).

To make this painless, the summary also prints a **ready-to-run command** for
Part 2 with all three already filled in — something like:

```
powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1 -ConnectionCode YOUR_SERVER_IP:8443#K7QF9M2ATBZ4C6XU... -Token 9F3K...
```

Copy that whole line; you'll paste it into Part 2. The server is now running on
its own — you can close the SSH window.

> Want a different port, or Dropbox storage offload? See
> [Optional settings (advanced)](#optional-settings-advanced) for the extra flags
> (`--port`, `--dropbox`).

---

## Part 2 — Build your app and the shareable app (on your Windows PC)

Now switch back to your own Windows PC. You will build two things: the admin app
for yourself, and the ZIP you hand out to everyone else.

Open **PowerShell** in the project folder (the MaxSecu code, downloaded on your
Windows PC) and paste the **ready-to-run command** the server printed at the end of
Part 1. It looks like this (your fingerprint and token will differ):

```
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -ConnectionCode "YOUR_SERVER_IP:8443#K7QF9M2ATBZ4C6XU..." -Token "9F3K..."
```

The `-ConnectionCode` carries the address plus the server-cert fingerprint; the
`-Token` is the one-time delegation token. Keep the quotes — they stop PowerShell
from choking on the `#`. (If you don't pass `-Token`, the script asks you to paste
the token before continuing.)

This is the step that performs the one-time **delegation ceremony** described in
[the trust model](#whos-in-charge--the-trust-model-short-version): your PC
generates the directory root here, uploads the delegation (which **opens sign-up**
on the server), and mints the final connection code for your users — all
automatically. You don't decide anything; you just supply the token.

> **Why `powershell -ExecutionPolicy Bypass -File`?** Windows blocks unsigned
> `.ps1` scripts by default, so running `.\scripts\install-client.ps1` directly
> fails with a "not digitally signed / cannot be loaded" security error. Launching
> it this way runs the script for that one command only, without changing your
> machine's execution policy. (The same applies to every `install-client.ps1`
> command below.)

> See [Optional settings (advanced)](#optional-settings-advanced) if you'd rather
> pass the address and fingerprint as separate flags.

This builds the Windows app, fetches the security files from your server over the
network (verifying them against the fingerprint), and runs the delegation ceremony.
Partway through, it asks you to **make up a recovery passphrase**
— a password you invent. **Write it down and keep it somewhere safe and offline.**
This passphrase protects your master recovery key **and** the directory root
created in the ceremony (more on that at the end). If you lose it, it cannot be
recovered for you.

When it finishes, you'll have two things in the `dist` folder:

- **`dist\MaxSecuClient\`** — your personal admin app.
- **`dist\MaxSecuClient-share.zip`** — the handout you give to other people.

Now start your admin app by running:

```
dist\MaxSecuClient\maxsecu-client-app.exe
```

On the screen, type your server address — `YOUR_SERVER_IP:8443` — and **sign up**.
**The first person to sign up becomes the admin.** Since that's you, you are now
in charge of the server.

---

## Part 3 — Add other people, and everyday use

### Adding a person

1. In the app, go to the **Admin** area and create a **registration key**. Make
   one key per person you want to invite (each key works once).
2. Send that person **two things, separately**:
   - the file **`dist\MaxSecuClient-share.zip`**, and
   - their own **registration key**.

   Sending them separately (for example, the ZIP by email and the key by text
   message) is safer.
3. They **unzip** the file anywhere, double-click **`maxsecu-client-app.exe`**,
   enter **your server address** (`YOUR_SERVER_IP:8443`) and **their registration
   key**, then pick a **username** and a **passphrase**. They're in.

### Everyday actions

The app is designed to be self-explanatory. In short:

- **Upload files** — drag them in or use the upload button.
- **Bundles** — group related files together so they're easy to browse and share
  as a set.
- **Share** — give another user on your server access to a file or bundle.
- **Download** — open any file you have access to and save it back to your PC.

---

## Keeping the server running

The server runs by itself in the background as a service called
`maxsecu-server`, and it restarts automatically whenever the VPS reboots. You
don't have to do anything to keep it on. If you ever want to check on it, SSH
back in and run:

```
sudo systemctl status maxsecu-server     # is it running?
journalctl -u maxsecu-server -f           # watch what it's doing live (Ctrl+C to stop)
```

---

## If something goes wrong

| What you see | What it usually means and what to do |
|---|---|
| "Secure connection failed" / the app can't connect | The server address is wrong — double-check `YOUR_SERVER_IP:8443`. Or the server was rebuilt with a new IP address, in which case the old app no longer trusts it — get a fresh ZIP from your admin. |
| Can't SSH into the server | Check the IP address is right and that your SSH key or password is correct. Ask your VPS provider if unsure. |
| `install-server.sh: Permission denied` | The download lost the "executable" mark. Either run it through bash — `bash scripts/install-server.sh --public` — or restore the mark once with `chmod +x scripts/*.sh`. |
| "recovery account already registered" (409) when building the client | The server still has state from an earlier setup. You must reset it, not just re-clone — see [Start over from scratch](#start-over-from-scratch-full-reset). |
| The Windows script says `cargo` or `npm` is missing | Your PC needs two free developer tools. Install **Rust** (from rustup.rs, choose the MSVC option) and **Node.js LTS** (from nodejs.org), then run the script again. |
| Windows warns "unknown publisher" when you open the app | This build isn't code-signed, which is normal for a self-built app. Click **More info**, then **Run anyway**. |
| The server won't start | SSH in and run `journalctl -u maxsecu-server -e` to see the error message. |
| "sign-up is closed" / users can't register | The delegation ceremony (Part 2) hasn't been completed yet, or it failed. Finish Part 2 on your admin PC — that opens sign-up. |
| The client installer says the token is invalid or already used | The delegation token is single-use. If you re-ran `install-server.sh`, it printed a **new** token — use that one. If the server is already delegated it won't print a token at all (sign-up is already open); you don't need one. |

---

## Recovery — the most important thing to protect

When you built your admin app, the ceremony created two files —
**`recovery_key.blob`** (your account's master key) and **`d5_recovery.blob`** (a
sealed backup of the **directory root**, the signing key that keeps your server
delegated) — both locked with the **recovery passphrase** you made up. Together
they are the master key that can recover the whole system. Keep **both files** and
the passphrase **offline** (for example on a USB stick in a drawer) and **never
share them with anyone**. The app ZIP you hand out to other people contains
**neither** — that is deliberate. If you lose them, there is no way to recover.

---

## Start over from scratch (full reset)

Sometimes you want to wipe everything and set up again from zero — moving to a new
server, or a half-finished attempt left things in a confusing state.

**The one thing people get wrong:** on the server, deleting the downloaded
`maxsecu` folder is **not** enough. The account database, the security
certificate, and (if you set it up) your Dropbox login all live **outside** that
folder. A fresh `git clone` reuses those leftovers, and you get errors like *"the
server already has a recovery account registered"*. The two commands below remove
everything for you.

### Reset the server (on the VPS)

SSH into the server and run:

```
cd ~/maxsecu
./scripts/install-server.sh --reset
```

That stops and removes the service, drops the database (every account, including
the recovery account) and its login role, deletes the data folder and TLS
certificate, removes the saved Dropbox login, and closes the firewall port —
everything except the source code itself. It's safe to run even on a server that
was only half–set-up, or never set up at all.

> **Rented a brand-new VPS instead?** Then skip this — a new VPS is already blank.
> Just start from [Part 1](#part-1--set-up-the-server-do-this-once).

> If you installed on a custom port, add the same `--port N` so the right firewall
> rule is removed, e.g. `./scripts/install-server.sh --reset --port 9443`.

When it's done, reinstall from [Part 1](#part-1--set-up-the-server-do-this-once).

### Reset the client (on your Windows PC)

In PowerShell, from the project folder, run:

```
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -Reset
```

That deletes the built apps (`dist\`), the recovery + registration files
(`recovery_key.blob`, `recovery_pin.bin`, `register.key`), and the recovery pin
embedded into the client. If you ever unzipped or copied the admin app somewhere
else (for example onto your Desktop) and signed in there, delete that copy too —
each copy keeps its own login data inside its own folder.

Then rebuild from [Part 2](#part-2--build-your-app-and-the-shareable-app-on-your-windows-pc).

> **This erases your recovery key.** `recovery_key.blob` and the recovery
> passphrase are the only master key to the *old* server. Only wipe them when you
> genuinely intend to abandon that server for good.

---

## Optional settings (advanced)

The two commands above work as-is for a standard setup. These extra options are
only needed if you want a non-default port, cold-tier storage, or to enter the
server address and fingerprint by hand. You can skip this section entirely if the
defaults worked for you.

### Server — `install-server.sh`

Run it in a terminal on the VPS. Flags can be combined.

| Option | What it does |
|---|---|
| `--public [IP]` | Make the server reachable from the internet. Binds `0.0.0.0` and bakes the public IP into the TLS certificate. If you omit the IP it is auto-detected and shown for you to confirm. Without `--public` the server is local-only (`127.0.0.1`), useful only for testing. |
| `--port N` | Listen port (default `8443`). If you change this, give users `YOUR_SERVER_IP:N` **and** pass the matching `-Port N` to the client installer below. |
| `--capacity-gb N` | Local disk cache size in GB before the cold tier starts offloading (default `200`). Interactively you're prompted; a non-interactive run silently uses `200`. Only matters with `--dropbox` on. |
| `--dropbox` | Turn on **Dropbox cold-tier offload** — idle/overflow files are moved to your Dropbox to save disk. Needs a real terminal: it asks for your Dropbox App key + secret, prints a URL for you to click **Allow** on, and you paste the one-time code back (paste it promptly — it expires within a minute or two). Safe to run again later to add Dropbox to an existing server. |
| `--no-dropbox` | Skip the Dropbox prompt entirely (also the behavior when there's no terminal). |
| `--reset` | Tear the server down to zero and exit (does **not** reinstall): stop + remove the service, drop the database + role, delete the data dir + TLS cert, remove the saved Dropbox login, close the firewall port. See [Start over from scratch](#start-over-from-scratch-full-reset). Combine with `--port N` if you installed on a custom port. |

Example — custom port with Dropbox offload:

```
./scripts/install-server.sh --public --port 9443 --dropbox
```

> Re-running with `--public` regenerates the server's TLS certificate. Any app
> you already handed out pinned the old certificate and will stop connecting, so
> rebuild and redistribute the client ZIP (Part 2) afterwards.

### Upgrade a running server — `upgrade-server.sh`

To apply a code update to a server that's already installed **without losing any
data and without making clients re-pin**, don't re-run the installer — use the
upgrade script. SSH into the server and run:

```
cd ~/maxsecu
./scripts/upgrade-server.sh
```

It pulls the latest code, rebuilds the server binary **while the old one keeps
serving** (so a build failure never takes production down), then restarts the
service — a one-second blip. Your database, blobs, TLS certificate, client pins,
and Dropbox login are all left exactly in place, and the server fingerprint is
unchanged, so existing clients keep working with no re-pin.

| Option | What it does |
|---|---|
| `--no-pull` | Rebuild the current checkout instead of `git pull`-ing first. |
| `--no-backup` | Skip the quick `pg_dump` safety backup taken before the restart. |
| `--capacity-gb N` | Also set the local cache capacity to N GB (via a systemd drop-in), without editing the unit by hand. |

> This never deletes data — only `install-server.sh --reset` does that. Do **not**
> use `--reset` to upgrade.

### Client — `install-client.ps1`

Run it in PowerShell on your Windows PC, always via
`powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 ...` —
Windows blocks unsigned `.ps1` scripts by default, so invoking the script
directly fails with a "not digitally signed / cannot be loaded" error.

| Option | What it does |
|---|---|
| `-ConnectionCode "addr:port#fp"` | **(primary)** The `-ConnectionCode` from the command the server printed. It carries the address, port, and the **server-cert fingerprint**; the installer splits it for you and trusts the fetched pins only if their hash matches. Provide this **or** the `-ServerAddr` + `-Fingerprint` pair below. |
| `-Token "token"` | The **one-time delegation token** the server printed. Required on a first (awaiting-delegation) install — it authorizes the ceremony that opens sign-up. Omit it and you're prompted to paste it. Also settable via the `SETUP_DELEGATION_TOKEN` env var. Not needed if the server is already delegated. |
| `-ServerAddr host/IP` | The public host/IP the app dials and the certificate is issued for. Manual alternative to `-ConnectionCode`; pair it with `-Fingerprint`. |
| `-Fingerprint code` | The server-cert fingerprint (the text after `#` in the connection code). Manual alternative to `-ConnectionCode`; pair it with `-ServerAddr`. |
| `-Port N` | Server port. Must match the server's `--port` (default `8443`). Only needed with the manual `-ServerAddr`/`-Fingerprint` pair — `-ConnectionCode` already carries the port. |
| `-RecoveryPassphrase "pw"` | Supply the recovery passphrase non-interactively (skips the prompt) so the install can run unattended. Prefer the `SETUP_RECOVERY_PW` env var — a flag value is visible in shell history and process listings. Omit both for the normal prompt (no echo). |
| `-Reset` | Tear the client down to zero and exit (no build): delete `dist\`, the recovery/registration files, **and the directory root** (`d5_key.blob` / `d5_recovery.blob`), so the next run starts fresh. No other arguments are required with it. See [Start over from scratch](#start-over-from-scratch-full-reset). |

Example — passing the address and fingerprint manually instead of a code:

```
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -ServerAddr 123.123.123.123 -Port 9443 -Fingerprint K7QF9M2ATBZ4C6XU...
```

### Rebuild only the users' ZIP — `build-user-zip.ps1`

Once the server and your admin account already exist and you just want to
(re)build the handout ZIP for users, use this instead of a full `install-client`:

```
powershell -ExecutionPolicy Bypass -File .\scripts\build-user-zip.ps1
```

It rebuilds the client and writes a clean `dist\MaxSecuClient-share.zip` (client +
UI + the pinned server certs + `START-HERE.txt`, and nothing else). It **never**
runs `maxsecu-setup`, never touches your recovery account / master key /
`register.key`, and never touches your admin login — so it is safe to run any time.

| Option | What it does |
|---|---|
| *(no arguments)* | Rebuilds, reusing the pins from your existing `dist\MaxSecuClient\config`. |
| `-ConnectionCode "addr:port#fp"` | Re-fetch + verify the pins from the server (use if the server cert changed). |
| `-Pins <dir>` | Reuse `server_cert.der` + `directory_pub.der` from a folder (offline). |
| `-SkipBuild` | Reuse the already-compiled client + UI (fast; skip if the code hasn't changed). |
| `-Out <path>` | Output ZIP path (default `dist\MaxSecuClient-share.zip`). |

Hand each new user the ZIP plus a one-time registration key you mint in the admin
app (Admin screen → mint a registration key).

Requires that you have run `install-client.ps1` at least once (that creates the
recovery account and embeds its pin, which this script reuses).

### Upgrade existing users' app — `build-upgrade-zip.ps1`

When you've updated the client code and want your **existing** users on the new
version **without losing their accounts**, build an upgrade ZIP — the client-side
twin of [`upgrade-server.sh`](#upgrade-a-running-server--upgrade-serversh):

```
powershell -ExecutionPolicy Bypass -File .\scripts\build-upgrade-zip.ps1
```

It writes `dist\MaxSecuClient-upgrade.zip` — just the new `maxsecu-client-app.exe`
+ `ui\` + an `UPGRADE-HERE.txt`. Each user copies those two items over their
existing `MaxSecuClient` folder, replacing the old ones, and reopens the app.
Their **keystore (login), saved settings, and pinned server all live in that same
folder and are kept** — no re-enroll, no new registration key, no re-pin. The ZIP
deliberately carries **no** account data and **no** server pins.

| Option | What it does |
|---|---|
| *(no arguments)* | Rebuild the client and write `dist\MaxSecuClient-upgrade.zip` (pulls first if this is a git checkout). |
| `-SkipBuild` | Reuse the already-compiled client + UI (fast; skip if the code hasn't changed). |
| `-NoPull` | Don't `git pull` first; build the files already in place. |
| `-Out <path>` | Output ZIP path (default `dist\MaxSecuClient-upgrade.zip`). |

> Only for a **code** update. If your server **address or certificate** changed,
> that's a re-pin, not an upgrade — hand out a fresh `build-user-zip.ps1` ZIP
> instead.

---

## Full-install E2E test harness

`scripts/test-full-install.ps1` provisions a throwaway WSL Ubuntu-22.04 server,
installs the server (`install-server.sh --public`), then drives the **real
offline-D5 ceremony** unattended: it scrapes the server-cert fingerprint and the
one-time delegation token from the install-server summary and runs
`install-client.ps1 -ConnectionCode <addr:port#cert-fp> -Token <token>
-RecoveryPassphrase <pw>`. It then asserts the delegation was installed — that the
server now reports a directory fingerprint, i.e. **sign-up has opened** — runs the
headless `maxsecu-live-smoke` oracle against the live pair, exercises the
reset+reinstall path, re-runs the oracle, then unregisters the distro and resets
the client.

    powershell -ExecutionPolicy Bypass -File scripts\test-full-install.ps1
    # options: -Port 8443  -KeepOnFailure  -Iterations 3

Requirements: WSL2 with virtualization enabled; the Rust MSVC + Node toolchains
(the same the normal client install needs). The Ubuntu rootfs is downloaded once
and cached under %LOCALAPPDATA%\maxsecu-test.

What the oracle asserts (the stock single-server surface): admin enroll -> blog
upload -> view-back -> admin mints a key -> second user enrolls (User role, not Admin)
-> the second user sees the admin's card in the feed -> the second user uploads and
views back its own blog. User-to-user `reshare` is intentionally NOT covered: it
requires an out-of-band sink server that the single-server install does not deploy.

### Non-interactive client install

`install-client.ps1` accepts `-RecoveryPassphrase <pw>` (or the `SETUP_RECOVERY_PW`
env var) and `-Token <token>` (or the `SETUP_DELEGATION_TOKEN` env var). When both
are supplied it runs the entire offline-D5 ceremony without a single prompt, so the
harness (or any automation) can install unattended. The normal interactive install
is unchanged -- omit them and it prompts (passphrase without echoing).

---

## For developers

Build, test, and internal design notes have moved to
[`docs/development.md`](docs/development.md).
