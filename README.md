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

When it finishes, it prints a summary that includes a **connection code** — the
address plus a short fingerprint, like `YOUR_SERVER_IP:8443#K7QF9M2ATBZ4C6XU...`.
Copy that whole code; you'll paste it into Part 2. It lets your Windows PC fetch
the server's security certificates over the network and confirm they're genuine,
so no SSH file copy is needed. The server is now running on its own — you can
close the SSH window.

> Want a different port, or Dropbox storage offload? See
> [Optional settings (advanced)](#optional-settings-advanced) for the extra flags
> (`--port`, `--dropbox`).

---

## Part 2 — Build your app and the shareable app (on your Windows PC)

Now switch back to your own Windows PC. You will build two things: the admin app
for yourself, and the ZIP you hand out to everyone else.

Open **PowerShell** in the project folder (the MaxSecu code, downloaded on your
Windows PC) and run:

```
./scripts/install-client.ps1 -ConnectionCode YOUR_CONNECTION_CODE
```

Replace `YOUR_CONNECTION_CODE` with the whole connection code the server printed
at the end of Part 1 (it looks like `YOUR_SERVER_IP:8443#K7QF9M2ATBZ4C6XU...`).
Wrap it in quotes if your shell dislikes the `#`.

> See [Optional settings (advanced)](#optional-settings-advanced) if you'd rather
> pass the address and fingerprint as separate flags.

This builds the Windows app and fetches the security files from your server over
the network, verifying them against the fingerprint in the connection code.
Partway through, it asks you to **make up a recovery passphrase**
— a password you invent. **Write it down and keep it somewhere safe and offline.**
This passphrase protects your master recovery key (more on that at the end). If
you lose it, it cannot be recovered for you.

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

---

## Recovery — the most important thing to protect

When you built your admin app, two things were created: a file named
**`recovery_key.blob`** and the **recovery passphrase** you made up. Together they
are the master key that can recover the whole system. Keep the file and the
passphrase **offline** (for example on a USB stick in a drawer) and **never share
them with anyone**. The app ZIP you hand out to other people does **not** contain
them — that is deliberate. If you lose both, there is no way to recover.

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
./scripts/install-client.ps1 -Reset
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

### Client — `install-client.ps1`

Run it in PowerShell on your Windows PC.

| Option | What it does |
|---|---|
| `-ConnectionCode "addr:port#fp"` | **(primary)** The connection code the server printed. It carries the address, port, and a fingerprint of the security certificates; the installer splits it for you and trusts the fetched pins only if their hash matches. Provide this **or** the `-ServerAddr` + `-Fingerprint` pair below. |
| `-ServerAddr host/IP` | The public host/IP the app dials and the certificate is issued for. Manual alternative to `-ConnectionCode`; pair it with `-Fingerprint`. |
| `-Fingerprint code` | The fingerprint part (the text after `#` in the connection code). Manual alternative to `-ConnectionCode`; pair it with `-ServerAddr`. |
| `-Port N` | Server port. Must match the server's `--port` (default `8443`). Only needed with the manual `-ServerAddr`/`-Fingerprint` pair — `-ConnectionCode` already carries the port. |
| `-Reset` | Tear the client down to zero and exit (no build): delete `dist\` and the recovery/registration files, so the next run starts fresh. No other arguments are required with it. See [Start over from scratch](#start-over-from-scratch-full-reset). |

Example — passing the address and fingerprint manually instead of a code:

```
./scripts/install-client.ps1 -ServerAddr 123.123.123.123 -Port 9443 -Fingerprint K7QF9M2ATBZ4C6XU...
```

---

## For developers

Build, test, and internal design notes have moved to
[`docs/development.md`](docs/development.md).
