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

When it finishes, it prints a summary with the **address to give people**
(`YOUR_SERVER_IP:8443`). Keep that handy — you'll need it in Part 2. The server
is now running on its own. You can close the SSH window.

---

## Part 2 — Build your app and the shareable app (on your Windows PC)

Now switch back to your own Windows PC. You will build two things: the admin app
for yourself, and the ZIP you hand out to everyone else.

Open **PowerShell** in the project folder (the MaxSecu code, downloaded on your
Windows PC) and run:

```
./scripts/install-client.ps1 -Vps root@YOUR_SERVER_IP
```

This builds the Windows app and connects to your server to collect the security
files it needs. Partway through, it asks you to **make up a recovery passphrase**
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

## For developers

Build, test, and internal design notes have moved to
[`docs/development.md`](docs/development.md).
