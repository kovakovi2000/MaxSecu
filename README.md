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

> Want a different port, or storage offload? See
> [Optional settings (advanced)](#optional-settings-advanced) for the extra flags
> (`--port`, `--dropbox`, `--cold-tier-fs`).
>
> **Decide storage offload now if you ever want a backup.** The sealed backup
> bundle lives on the same "cold tier" the offload uses, so a server without one
> **cannot be backed up at all**, and `upgrade-server.sh` then refuses to upgrade
> something it could not roll back. Once this box has been installed at all — a
> systemd service, a TLS certificate in the data folder, **or** any account in the
> database — you can no longer re-run this installer to add it (it refuses on any
> one of those three, so a failed first attempt already blocks a re-run). Add
> `--cold-tier-fs /srv/maxsecu-cold`
> (just a folder on the VPS — no account needed) or `--dropbox` to the command
> above. If you skip it now you can still add one later **without re-running the
> installer** — see [Change a setting on a running
> server](#change-a-setting-on-a-running-server) — doing it at install time is
> just simpler. See [Back up the server](#back-up-the-server--backup-serversh-and-restore-serversh).

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
`-Token` is the one-time delegation token. The quotes are harmless and keep
PowerShell from mis-reading the `#` if you retype the line by hand — the exact line
the server printed also works as-is. (If you don't pass `-Token`, the script asks
you to paste the token before continuing.)

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
| "recovery account already registered" (409) when building the client | **This is normal, and nothing was changed.** Every server that has already been set up answers this way — the setup step is one-shot, so it stopped and wrote nothing. Re-run the client build from the **same project folder the original ceremony ran in**: it still holds `recovery_pin.bin` and `directory_pub.der`, and the build reuses them to produce a working app. If that folder is gone, the two files are not equal: `directory_pub.der` **can** be rebuilt from your `d5_recovery.blob` backup and the recovery passphrase (`maxsecu-setup restore` — it is the same directory root, so no user has to re-pin), but `recovery_pin.bin` **cannot be rebuilt by any command** and the build needs it too — ask whoever ran the original ceremony for a copy (see [Recovery](#recovery--the-most-important-thing-to-protect)). Do **not** reach for a [reset](#start-over-from-scratch-full-reset): it erases every account and cannot be undone, and it is the answer only if you genuinely want to wipe this server and start over. |
| The Windows script says `cargo` or `npm` is missing | Your PC needs two free developer tools. Install **Rust** (from rustup.rs, choose the MSVC option) and **Node.js LTS** (from nodejs.org), then run the script again. |
| Windows warns "unknown publisher" when you open the app | This build isn't code-signed, which is normal for a self-built app. Click **More info**, then **Run anyway**. |
| The server won't start | SSH in and run `journalctl -u maxsecu-server -e` to see the error message. |
| "sign-up is closed" / users can't register | The delegation ceremony (Part 2) hasn't been completed yet, or it failed. Finish Part 2 on your admin PC — that opens sign-up. |
| The client installer says the token is invalid or already used | The token is single-use — a completed ceremony burns it. If the server is **already delegated** nobody needs a token: sign-up is already open, so your users just register in the app. To build another client ZIP yourself, re-run the client installer **from the project folder that already holds `recovery_key.blob`, `recovery_pin.bin`, `register.key` and `directory_pub.der`** — it skips the ceremony and never asks for a token. (Run from a folder missing any of those four and it *will* stop and ask, and pressing Enter aborts it.) If the ceremony never completed and you lost the printed line, the token is **still on the server** and you can simply read it back — no reset, nothing destroyed. SSH in and run `sudo systemctl restart maxsecu-server`, then `journalctl -u maxsecu-server -e`: while a server is awaiting delegation, every start prints a `one-time delegation token:` line. If that file was deleted, the restart writes a fresh token and prints that instead. Do **not** reach for a [reset](#start-over-from-scratch-full-reset). |
| `REFUSING: this box's account database could not be read` | The installer could not ask PostgreSQL how many accounts are on this box, and it will **not** assume "none" — that assumption is what installs straight over a live server and locks every app out for good. **Nothing that holds your data was changed.** (The one thing the check may have done is *start* PostgreSQL to ask — it says so when it did, and leaves it running; what starts at boot is untouched.) The message lists the three usual causes and the exact command to test with; fix PostgreSQL, then run the same command again. Do **not** reach for a [reset](#start-over-from-scratch-full-reset). |
| `REFUSING: this box has real accounts and a BROKEN TLS identity` | Half of the server's identity is on disk (`cert.der` without `key.der`, or the other way round). The server rebuilds **both** when either is missing, so its next start would mint a **new** identity and permanently lock out every app you handed out. **The unit, the data folder and the database are untouched** (the check may have started PostgreSQL and left it running; the message says so when it did). Put the original back from a backup — `printf '%s' 'my bundle passphrase' \| sudo bash scripts/restore-server.sh --from latest --only state` (the passphrase is piped in; without it the command sits there waiting for it) — see [Back up the server](#back-up-the-server--backup-serversh-and-restore-serversh). The message also spells out what to do if you have no backup. |
| `REFUSING: this box has real accounts but no TLS certificate here` | The database holds accounts but the installer found no certificate in the folder it resolved — so it is looking at the wrong folder, and continuing would mint a new identity and orphan every uploaded file. **The unit, the data folder and the database are untouched** (the check may have started PostgreSQL and left it running; the message says so when it did). Follow the three options the message prints; there is no flag that overrides this one. |

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

Keep a **third** thing beside them: a copy of **`dist\MaxSecuClient-share.zip`**,
and your **server address and port** written on paper. A recovery sign-in only
works from an app folder that already holds this server's pinned certificate, and
that ZIP is exactly such a folder — it carries no secrets, which is why it is safe
to store next to the keys. Without it there is nothing to unzip on a new PC, and a
fresh copy of the project code **cannot** rebuild one for a server that is already
set up.

### Using the recovery key (breakglass sign-in)

When you actually need it — a lost admin login, or rebuilding on a brand-new PC —
the app can sign in **with the recovery key itself**. That session can browse and
open every file, and mint registration keys. It cannot post, delete or share, so
it cannot hand a file back to a user who lost access — that still needs the
offline ceremony in `docs/runbooks/recovery-session.md`.

The catch is a naming one, and it is why this needs a command rather than drag and
drop: the ceremony wrote your key as **`recovery_key.blob`** in the project folder,
but the app looks for it inside the folder the `.exe` sits in, as
**`recovery\recovery_key_blob`** — a different folder *and* a different filename
(no dot, `blob` last). Don't copy it by hand. Run:

```
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -StageRecoveryKey E:\recovery_key.blob
```

That copies the file — byte for byte, still sealed with the same passphrase — into
`dist\MaxSecuClient\recovery\recovery_key_blob`, checks the copy matches, and
restricts it to your Windows account. It builds nothing and contacts no server. It
does need an **app folder to put the key into**, though: `dist\MaxSecuClient` from
an earlier build on this PC, or an unzipped copy of `MaxSecuClient-share.zip` (the
next command). If there is no such folder it stops and says so — it never guesses.

Staging into an unzipped app folder instead (e.g. the handout ZIP on a new PC):

```
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -StageRecoveryKey E:\recovery_key.blob -ClientDir C:\Users\you\Desktop\MaxSecuClient
```

Then open the app. It starts on the **recovery sign-in** screen. On a PC that has
never signed up there is no saved server yet, so open *"Server — set or change"* on
that screen. You do **not** need the connection code: the address is normally
already filled in for you, read out of the certificate in that folder, and a plain
`YOUR_SERVER_IP:8443` is enough on its own (paste the whole code if you still have
it). The **port** is the one part the app cannot work out — add it after the colon
yourself. Then enter the recovery passphrase.

**When you are done, take the copy back out** — passing the **same** `-ClientDir`
you staged into:

```
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -UnstageRecoveryKey -ClientDir C:\Users\you\Desktop\MaxSecuClient
```

Leave `-ClientDir` off and it looks in `dist\MaxSecuClient` instead: on a PC that
has one, it finds nothing to remove there, prints a cheerful success, and your
master key is still sitting in the folder you actually staged it into. Drop the
`-ClientDir` **only** when `dist\MaxSecuClient` is where you staged it.

> That staged file is a **full copy of your master key**. Anyone who gets it *and*
> the passphrase can read every file of every user. Leave it in place only for as
> long as the session lasts, and keep the offline original as the real one. It is
> never put into any ZIP you hand out.

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
everything except the source code itself. It reads the **real** data folder out of
the installed service file, so it wipes the box you actually have, not a guess.
It's safe to run on a server that was only half–set-up, or never set up at all.

**It asks first.** In a terminal it prints what is at stake — including how many
accounts are about to be destroyed — and waits for you to type **`DESTROY`**, in
capitals. Anything else aborts and nothing is touched.

**It can also refuse, and that is a good thing.** If PostgreSQL is installed here
but will not answer, it stops before deleting anything: removing the folder and
the service file while the database survives would leave accounts that nobody —
including you — could ever reach again. Fix PostgreSQL, then run the same command
again.

**Read the last lines it prints.** If it says this machine is **not** back to
zero, something survived and it names what. Do not install over that — clear the
cause and run `--reset` again first.

> **Rented a brand-new VPS instead?** Then skip this — a new VPS is already blank.
> Just start from [Part 1](#part-1--set-up-the-server-do-this-once).

> The firewall port is read from the installed service file, so you no longer need
> to repeat `--port N`. Pass it only if the service file is already gone and you
> installed on a custom port, e.g. `./scripts/install-server.sh --reset --port 9443`.

When it's done, reinstall from [Part 1](#part-1--set-up-the-server-do-this-once).

### Reset the client (on your Windows PC)

In PowerShell, from the project folder, run:

```
powershell -ExecutionPolicy Bypass -File .\scripts\install-client.ps1 -Reset
```

That deletes the built apps (`dist\`), the recovery + registration files
(`recovery_key.blob`, `recovery_pin.bin`, `register.key`), **the directory root and
its backup** (`d5_key.blob`, `d5_recovery.blob`), the pinned `directory_pub.der`
and `connection_code.txt`, and the recovery pin embedded into the client. If you
ever unzipped or copied the admin app somewhere else (for example onto your
Desktop) and signed in there, delete that copy too — each copy keeps its own login
data inside its own folder.

> **Your sign-in key is rescued, not destroyed.** The `keystore\` folder inside the
> admin app holds the sealed private key of whoever signed in there, and there is no
> server-side copy of it — deleting it loses that account for good. So `-Reset`
> copies it to `dist\_keystore-rescue-<date>\` first and prints where. To keep
> signing in as the same user afterwards, copy that `keystore\` folder back into the
> rebuilt app folder before you open it. Delete the rescue once you're sure you
> don't need it — it is still your sealed private key. (A recovery key you staged
> with `-StageRecoveryKey` is deliberately **not** rescued: it is only ever a copy,
> and your offline original is the real one.)

Then rebuild from [Part 2](#part-2--build-your-app-and-the-shareable-app-on-your-windows-pc).

> **This erases your recovery key and your directory-root backup.**
> `recovery_key.blob`, `d5_recovery.blob` and the recovery passphrase are the only
> master key to the *old* server. Only wipe them when you genuinely intend to
> abandon that server for good.
>
> It also erases **`recovery_pin.bin`**, and **no command in this project can
> recreate that file** — not the recovery passphrase, not `maxsecu-setup restore`,
> which rebuilds `directory_pub.der` but not the pin. (The pin is the *public* half
> of the recovery identity sealed inside `recovery_key.blob`, so it is not lost
> mathematically — but nothing shipped here derives it, so treat it as gone.)
> Without it you can never build an
> app that connects to the old server again. So if all you hit was *"recovery
> account already registered" (409)* in [If something goes
> wrong](#if-something-goes-wrong), do **not** run `-Reset`.

---

## Optional settings (advanced)

The two commands above work as-is for a standard setup. These extra options are
only needed if you want a non-default port, cold-tier storage, or to enter the
server address and fingerprint by hand. You can skip this section entirely if the
defaults worked for you.

### Server — `install-server.sh`

Run it in a terminal on the VPS. Flags can be combined.

> **This is a fresh-install tool — it is not a way to change a running server.**
> On a box that already has MaxSecu (a systemd service, a TLS certificate in the
> data folder, or any user account in the database) it **refuses to run** and
> prints what to use instead. That refusal is deliberate: re-running the installer
> rewrites the service file from whatever flags you type this time, and with
> `--rotate-tls-identity` it replaces the server's identity, which locks out every
> app you have already handed out — permanently, with no way for those users to
> repair it themselves. Pick the right tool:
>
> | You want to… | Use |
> |---|---|
> | apply a code update | `sudo bash scripts/upgrade-server.sh` |
> | change a setting (port, cold tier, cache size) | a systemd drop-in — see [Change a setting on a running server](#change-a-setting-on-a-running-server) |
> | back up / roll back data | [`scripts/backup-server.sh`, `scripts/restore-server.sh`](#back-up-the-server--backup-serversh-and-restore-serversh) |
> | wipe the box and start again | `./scripts/install-server.sh --reset`, then install |

| Option | What it does |
|---|---|
| `--public [IP]` | Make the server reachable from the internet. Binds `0.0.0.0` and bakes the public IP into the TLS certificate. If you omit the IP it is auto-detected and shown for you to confirm. Without `--public` the server is local-only (`127.0.0.1`), useful only for testing. **Going public afterwards is not a setting change:** the address is baked into the certificate, so a local-only box can only be reached from the internet by minting a new one — which permanently locks out every app already handed out. There **is** a later path, and it is not a reset: see the **"If your VPS's public IP changed"** note further down this section — it keeps the database, the recovery account and every upload, and only the handed-out ZIPs must be rebuilt. Reach for `--reset` only if you also want the accounts gone. Simplest of all: pass `--public` the first time. |
| `--port N` | Listen port (default `8443`). If you change this, give users `YOUR_SERVER_IP:N` **and** pass the matching `-Port N` to the client installer below. |
| `--capacity-gb N` | Local disk cache size in GB before the cold tier starts offloading (default `200`). Interactively you're prompted; a non-interactive run silently uses `200`. Only matters with a cold tier on. |
| `--dropbox` | Turn on **Dropbox cold-tier offload** — idle/overflow files are moved to your Dropbox to save disk. Needs a real terminal: it asks for your Dropbox App key + secret, prints a URL for you to click **Allow** on, and you paste the one-time code back (paste it promptly — it expires within a minute or two). Decide this **at install time**; adding it later is a drop-in, not a re-run. |
| `--no-dropbox` | Skip the Dropbox prompt entirely (also the behavior when there's no terminal). |
| `--cold-tier-fs DIR` | Use a local folder as the cold tier instead of Dropbox (no account needed). `DIR` must be an absolute path **outside** the data folder. Mutually exclusive with `--dropbox`. |
| `--reset` | Tear the server down to zero and exit (does **not** reinstall): stop + remove the service, drop the database + role, delete the data dir + TLS cert, remove the saved Dropbox login, close the firewall port. The data folder and the firewall port are read from the installed service file, not guessed. In a terminal it first shows what is at stake and makes you type **`DESTROY`**; with no terminal it just proceeds. It **refuses without destroying anything** if PostgreSQL cannot be reached on a box that has it, and it reports honestly what survived instead of always claiming success. See [Start over from scratch](#start-over-from-scratch-full-reset). |
| `--force-overwrite-existing-install` | Proceed even though an existing install was found. The service file is **rewritten from this run's flags**, so pass every flag the box was installed with. It does *not* delete the TLS certificate, does *not* drop the database, does *not* move the data folder, and reuses the database password from the existing service file whenever that password still works. If this run's data folder or run user disagrees with the installed service file — which happens when you re-run from a different account, e.g. a root shell entered with `su -` — the install is **refused outright** and naming this flag does not override that. **It cannot promise your users keep working, though:** "the certificate is not deleted" only helps if a certificate is actually **found** in the resolved data folder — if none is, the server mints a **new identity** and every installed app is locked out permanently. So a box whose database still holds accounts while no certificate is found there is **also refused outright**, with no override: that combination means the data folder was not located. When there is **no service file** (e.g. it was deleted) the data folder is a *guess* based on the account you are logged in as, so state it — `sudo env MAXSECU_DATA_DIR=/actual/path bash ./scripts/install-server.sh …`. |
| `--rotate-tls-identity` | Delete the TLS certificate + client pins so the server mints a **new identity**. Only for a server whose public IP genuinely changed. **Every existing app stops connecting permanently** and each user needs a freshly built ZIP. |
| `--assume-no-database` | **Last resort — it can destroy a working server.** Before installing, the script counts the accounts in the database, and that count is what stops it installing over a live box; if it cannot get an answer it stops (the `REFUSING: this box's account database could not be read` row in [If something goes wrong](#if-something-goes-wrong) — that is the only one this flag touches; the other two `REFUSING` rows fire on a count that *was* read, and no flag overrides them). This flag says *"I have checked, this machine holds no MaxSecu accounts — carry on."* It overwrites nothing by itself and it is **not** a substitute for `--force-overwrite-existing-install`, but it **gives up that protection**: if accounts really are here, every app you handed out is locked out permanently. Use it only when rebuilding a box whose database is genuinely gone. Otherwise repair PostgreSQL and re-run without it. |

Example — custom port with Dropbox offload:

```
./scripts/install-server.sh --public --port 9443 --dropbox
```

> **If your VPS's public IP changed** the certificate no longer matches the
> address, and the only fix is a new certificate — which every app you handed out
> will reject. Re-install with both opt-outs, then rebuild and redistribute the
> client ZIP (Part 2) to **every** user.
>
> **Read this before you run the command below.** It **permanently locks out every
> app you have already handed out**, and no user can repair that themselves — each
> one needs a freshly built ZIP from you, and anyone you cannot reach loses access
> to their files. Run it only when the public IP has genuinely changed. **If you
> are not sure — for example you only want a code update — run
> `sudo bash scripts/upgrade-server.sh` instead**: it keeps the certificate, so no
> app has to re-pin.
>
> ```
> ./scripts/install-server.sh --public NEW.IP.HERE --port 8443 \
>     --force-overwrite-existing-install --rotate-tls-identity
> ```
>
> Repeat **every** flag the box was installed with, on that one line. The service
> file is rewritten from this run's flags, so a `--cold-tier-fs DIR` you leave out
> is silently dropped — and the server then has nowhere to put a backup.

### Change a setting on a running server

Never re-run the installer for this. A **systemd drop-in** is applied after the
service file, so it overrides one value and touches nothing else — no data is
moved, no certificate changes, and no app has to re-pin. Example, turning on a
local-folder cold tier:

```
sudo mkdir -p /etc/systemd/system/maxsecu-server.service.d
sudo tee /etc/systemd/system/maxsecu-server.service.d/20-cold-tier.conf >/dev/null <<'EOF'
[Service]
Environment=MAXSECU_COLD_TIER=fs
Environment=MAXSECU_COLD_FS_DIR=/srv/maxsecu-cold
EOF
sudo install -d -o "$(sudo sed -n 's/^User=//p' /etc/systemd/system/maxsecu-server.service | tail -n1)" -m 0700 /srv/maxsecu-cold
sudo systemctl daemon-reload && sudo systemctl restart maxsecu-server
```

The same shape works for `MAXSECU_PORT`, `MAXSECU_BIND` and
`MAXSECU_CACHE_CAPACITY_BYTES`. A drop-in that holds a **secret** (`DATABASE_URL`,
a Dropbox token) must be `0600`, not the `0644` above.

**A port change needs two things the drop-in does not do for you.** Only the
installer ever opens the firewall, so after changing `MAXSECU_PORT` you must open
the new port yourself — `sudo ufw allow 9443/tcp` (and `sudo ufw delete allow
8443/tcp` once you're sure), on a box where ufw is active — or the server is simply
unreachable. And **every app you already handed out still dials the old port**: tell
each user the new `YOUR_SERVER_IP:9443` so they can change it on their sign-in
screen. Nobody has to re-pin — the certificate does not cover the port — but until
they retype the address they cannot connect.

The cold-tier folder must be **outside** the data folder — an `fs` cold tier that
points at, or inside, the server's blob directory **destroys ciphertext**, and
**nothing checks that for you** on any path (`--cold-tier-fs` verifies the
directory is an absolute path and writable, not that it is outside your data
folder). It must also be **owned by the user the service runs
as** — that is what the long `sed` above reads out of the service file. Do not
substitute your own username: if the owner is wrong the server simply cannot write
there, offload stops and backups fail. Details: `docs/runbooks/prod-upgrade.md`.

### Back up the server — `backup-server.sh` and `restore-server.sh`

A backup is one **passphrase-locked bundle** holding everything the box needs to
come back: the database, the service file (the only copy of the database
password), the saved Dropbox login, the server's TLS identity, and the delegation
files. It is written to the **cold tier** — the same Dropbox folder or local
folder the storage offload uses — so a server with **no cold tier cannot be backed
up**. Turn one on at install time (`--dropbox` or `--cold-tier-fs DIR`), or on a
running server with a drop-in as in [Change a setting on a running
server](#change-a-setting-on-a-running-server).

Take one. The passphrase is piped in rather than typed as an option, because
anything on a command line is readable by everyone on that machine:

```
printf '%s' 'my bundle passphrase' | sudo bash scripts/backup-server.sh
```

> **That passphrase is stored nowhere.** Without the exact text, nothing and
> nobody can ever open the bundle. Minimum 12 characters. Write it down and keep
> it with your recovery key.

Backing up only **reads** — it never stops the server and never changes the
database, so it is safe to run at any time. Run it before anything risky;
`upgrade-server.sh` runs it for you.

| Option | What it does |
|---|---|
| `--keep N` | Keep the newest N bundles and delete older ones (default `10`, minimum `1`). Your users' files are never pruned — only old bundles are. |

To see what you have, and to roll back:

```
sudo bash scripts/restore-server.sh --list
printf '%s' 'my bundle passphrase' | sudo bash scripts/restore-server.sh --from latest --dry-run
printf '%s' 'my bundle passphrase' | sudo bash scripts/restore-server.sh --from latest
```

`--list` needs no passphrase. Do the `--dry-run` first: it opens the bundle,
checks it, prints exactly what it would do, and changes nothing. A real restore
also opens the bundle **before** it stops the server, so a wrong passphrase costs
you nothing but a retry.

| Option | What it does |
|---|---|
| `--from latest` or `--from <stamp>` | Which bundle to use. Required unless you passed `--list`. |
| `--only db,state,code,blobs` | Restore only some parts (default `db,state,code`). `--only state` puts back just the service file, the TLS identity and the delegation files — that is the one to use when the server's identity is broken but its data is fine. |
| `--db-mode merge` / `replace` | `merge` (the default whenever the live database still exists) only **adds back** what is missing and never removes a live row, so it cannot cost anyone their account. `replace` overwrites the live database wholesale and therefore throws away everything created since the backup — it needs `--force` for exactly that reason. |
| `--dry-run` | Open, check and print the plan; change nothing, never stop the server. |
| `--force` | Authorize `--db-mode replace` over a live database. |
| `--cold-tier-fs <dir>` / `--dropbox-env <path>` | Only for rebuilding a **dead** box: there is no service file left to read the cold-tier location out of, so you have to say where the bundle is. |

Full detail, including rebuilding a dead VPS from scratch:
[`docs/runbooks/backup-restore.md`](docs/runbooks/backup-restore.md).

### Upgrade a running server — `upgrade-server.sh`

To apply a code update to a server that's already installed **without losing any
data and without making clients re-pin**, don't re-run the installer — use the
upgrade script. SSH into the server and run:

```
cd ~/maxsecu
./scripts/upgrade-server.sh
```

First it asks you for a **backup passphrase** and takes a sealed backup (see
[above](#back-up-the-server--backup-serversh-and-restore-serversh)) — if that
fails, the upgrade stops before changing anything. Then it pulls the latest code,
**stops the server**, rebuilds it, applies any database migrations, and starts it
again. **The server is down for the whole rebuild** — minutes, not seconds — so do
it when nobody needs it. If the build fails, the binary that was running is put
straight back and the server restarted, so a failed upgrade never leaves the box
down. Your database, blobs, TLS certificate, client pins, and Dropbox login are
all left exactly in place, and the server fingerprint is unchanged, so existing
clients keep working with no re-pin.

> **It needs a terminal, and it needs a cold tier.** You type the backup
> passphrase at a prompt, so run it over SSH rather than from a script — with no
> terminal it stops rather than upgrade with no way back. And if the server has no
> cold tier the backup has nowhere to go; the upgrade stops and prints how to add
> one without touching your data.
>
> **The very first upgrade onto this version needs `--no-backup`.** The server
> binary already installed on your box predates the backup feature and cannot take
> one, so run `sudo bash scripts/upgrade-server.sh --no-backup` that once. Every
> upgrade after it backs up normally. The script checks and tells you which case
> you are in — it will not guess.

| Option | What it does |
|---|---|
| `--no-pull` | Rebuild the current checkout instead of `git pull`-ing first. |
| `--no-backup` | Skip the sealed, rollback-able backup taken before anything changes (`scripts/backup-server.sh`). You then upgrade with **no rollback point** — only pass this if you know why. |
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
| `-StageRecoveryKey <path>` | Put your cold `recovery_key.blob` where the app actually reads it, then exit (no build, no server contact). It needs an app folder to stage **into**: `dist\MaxSecuClient` by default, or add `-ClientDir <folder>` pointing at an unzipped `MaxSecuClient-share.zip` — that is the fresh-PC case. If that folder holds no `maxsecu-client-app.exe` it stops rather than drop the key somewhere the app never looks. See [Using the recovery key](#using-the-recovery-key-breakglass-sign-in). |
| `-UnstageRecoveryKey` | Remove a recovery key staged by the flag above (overwrite, then delete) and exit. Run it as soon as the recovery session is over. Takes the same optional `-ClientDir <folder>`. |
| `-Reset` | Tear the client down to zero and exit (no build): delete `dist\`, the recovery/registration files, **and the directory root** (`d5_key.blob` / `d5_recovery.blob`), so the next run starts fresh. Your **sign-in keystore is rescued first** to `dist\_keystore-rescue-<date>\`. No other arguments are required with it. See [Start over from scratch](#start-over-from-scratch-full-reset). |

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
    # options: -Port 18443 (the default; change only if that port is taken)  -KeepOnFailure  -Iterations 3

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
