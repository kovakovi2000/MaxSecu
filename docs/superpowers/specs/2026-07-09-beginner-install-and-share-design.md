# Beginner install & client-sharing — design spec

**Date:** 2026-07-09
**Status:** approved, ready for implementation

## Goal

Make MaxSecu installable and usable by someone with near-zero technical
knowledge: a **Windows PC** runs the client, an **Ubuntu 22.04 Linux VPS** runs
the server. The install must be as close to copy-paste as the source-built
project allows. The admin builds once and hands out a **ready-to-run client ZIP**
plus a **single-use registration key** to each additional user; those users just
unzip, run the app, type the server's public IP, and enter their key.

## Chosen model (decisions locked)

- **Build model:** one-command install scripts (no prebuilt binaries in repo).
- **Transport:** the server is reachable directly on its **public IP** over the
  built-in **pinned self-signed TLS cert**. No SSH tunnel, no VPN, no launcher
  script for end users. Users type `PUBLIC_IP:8443` on the login/register screen.
- **Persistence:** PostgreSQL ("persistent-DEV" profile — `DATABASE_URL` set).
  This profile reuses the self-signed pinned cert + dev D5 key (run.rs already
  documents this); it does **not** require a CA cert or external audit sink.
- **Docs:** `README.md` becomes the friendly guide; existing dev notes move to
  `docs/development.md`.

## Why code changes are required (not just docs)

The client validates the pinned cert with rustls' standard verifier
(`transport.rs::pinned_client_config`, `with_no_client_auth`) and derives the TLS
`server_name` from the host the user types (`commands/connection.rs::open_conn`,
line ~114). Therefore:

1. The server currently binds `127.0.0.1` only (`run.rs`) — unreachable from the
   internet.
2. The self-signed cert has SAN `localhost` only (`pki.rs::ensure_dev_cert`) — so
   typing a bare public IP fails the TLS handshake (SNI/SAN mismatch).
3. The **register** command ignores the typed server: `register_with_key` reads
   the address from `server_of(dir)` (saved/default `connection.json`), unlike
   `login` which uses `req.server`. `RegisterWithKeyRequest` has no `server`
   field, and the register UI screen has no server input.

## Fixed contract (all deliverables MUST agree on these)

| Item | Value |
|---|---|
| systemd service name | `maxsecu-server.service` |
| Postgres role / db | `maxsecu` / `maxsecu` |
| Server data dir | `$HOME/maxsecu-server-data` (env `MAXSECU_DATA_DIR`) |
| Listen port | `8443` (env `MAXSECU_PORT`) |
| Bind address env | `MAXSECU_BIND` (default `127.0.0.1`; public → `0.0.0.0`) |
| Public-address env (cert SAN + server_name) | `MAXSECU_PUBLIC_ADDR` (host or IP; empty → localhost-only cert, today's behavior) |
| Client pins on server | `$MAXSECU_DATA_DIR/client-pins/{server_cert.der,directory_pub.der}` |
| Admin working client | `dist/MaxSecuClient/` |
| Handout ZIP | `dist/MaxSecuClient-share.zip` |
| Rust toolchain | pinned by `rust-toolchain.toml` (1.96.0) |

## Code changes

### C1 — configurable server bind address (crate: `portable-server`)

- `config.rs`: add `bind: String` to `LauncherConfig`, resolved from
  `MAXSECU_BIND` env, default `"127.0.0.1"`. Add unit tests (default; explicit
  `0.0.0.0`).
- `run.rs`: `TcpListener::bind((cfg.bind.as_str(), cfg.port))` instead of the
  hard-coded `"127.0.0.1"`. Keep the printed listen line accurate.

### C2 — public-IP/hostname in the generated cert SAN (crate: `portable-server`)

- `config.rs`: add `public_addr: Option<String>` from `MAXSECU_PUBLIC_ADDR`
  (host or IP; strip any `:port` if present — SAN is host-only). Test both.
- `pki.rs::ensure_dev_cert`: accept the extra SAN(s). Generate the cert with SAN
  list = `["localhost", "127.0.0.1"]` **plus** `public_addr` when set. An IPv4/IPv6
  literal must become an **IP SAN**, a hostname a **DNS SAN** (use
  `rcgen::CertificateParams` + `SanType::IpAddress`/`SanType::DnsName`, or
  `rcgen`'s address auto-detection — verify the emitted SAN type by test).
  Generation stays idempotent (skip if cert already exists); regenerating for a
  changed IP is an operator action (delete cert files) handled by the script.
- `run.rs`: thread `cfg.public_addr` into `ensure_dev_cert`.
- **Test:** generate a cert with a `1.2.3.4` public addr, then complete a rustls
  pinned handshake with `ServerName::IpAddress(1.2.3.4)` against it (proves the IP
  SAN validates through the same `pinned_client_config` the client uses). If the
  aws-lc-rs/webpki stack rejects IP-SAN validation, fall back to also emitting a
  DNS SAN and document that users may type a hostname; **flag this to the
  coordinator rather than silently changing the UX.**

### C3 — register uses the typed server (crate: `client-app`)

- `commands/register.rs`: add `server: String` to `RegisterWithKeyRequest`.
  `register_with_key` opens the connection with `req.server` (mirroring
  `login`), NOT `server_of(dir)`. On success, persist the entered server into
  `connection.json` (`ConnectionConfig { server, server_name, auto_connect:false }`
  via its existing `save`) so the user's subsequent logins default to it.
- Preserve all existing fail-safe ordering (local prechecks before the network
  call; key destroyed only after 201).
- Unit test: `RegisterWithKeyRequest` carries `server`; a stubbed/e2e-level check
  that the persisted `connection.json` holds the entered address.

### C4 — server-address field on the register screen (dir: `client-app/ui`)

- Add a server-address text input to the registration view, mirroring the login
  screen's field (same label/placeholder style, e.g. `123.123.123.123:8443`).
- Pass its value as `server` in the `register_with_key` invoke payload
  (**camelCase top-level scalar arg** per Tauri v2 JS convention: `{ server, username, passphrase }`).
- Match existing UI patterns/styles; keep CSP-safe (no inline JS). Build with
  `npm run build` in `crates/client-app/ui`.

## Scripts

### `scripts/install-server.sh` (Ubuntu 22.04)

Idempotent, `set -euo pipefail`, shellcheck-clean. Steps:

1. Parse flags: `--public [IP]` (optional; if IP omitted, auto-detect via
   `curl -s https://api.ipify.org` and confirm), `--port` (default 8443).
2. Install prereqs via apt: `build-essential pkg-config libssl-dev clang curl git postgresql`.
3. Install rustup non-interactively (`curl … | sh -s -- -y`), source cargo env;
   toolchain resolves from `rust-toolchain.toml`.
4. Build: `cargo build --release -p maxsecu-portable-server` from repo root.
5. PostgreSQL: create role `maxsecu` + db `maxsecu` (idempotent — check first);
   generate a random password; assemble
   `DATABASE_URL=postgres://maxsecu:PW@localhost/maxsecu`.
6. Apply schema: `psql "$DATABASE_URL" -f docs/schema.sql` (PgStore does NOT
   auto-apply). Idempotent-guard (skip if a known table already exists).
7. First cert generation: if `--public`, remove any stale
   `client-pins`/cert so C2 regenerates with the public IP SAN.
8. Write `maxsecu-server.service` (systemd, `WorkingDirectory` = repo root,
   `ExecStart` = built binary, `Environment=` lines for `DATABASE_URL`,
   `MAXSECU_BIND` (`0.0.0.0` if `--public` else `127.0.0.1`), `MAXSECU_PUBLIC_ADDR`,
   `MAXSECU_PORT`, `MAXSECU_DATA_DIR`, `Restart=always`, run as the invoking user).
   `systemctl daemon-reload && enable --now`.
9. If `--public`: `ufw allow $PORT/tcp` (guard if ufw present).
10. Wait for the pins to appear, then print a clear summary: the **public
    address to give users** (`IP:PORT`), the location of
    `client-pins/{server_cert.der,directory_pub.der}`, the reminder to run the
    Windows `install-client.ps1 -Vps user@IP` next, and `journalctl -u
    maxsecu-server -f` for logs. Never print the DB password beyond writing it
    into the service file (root-readable only).

### `scripts/install-client.ps1` (Windows, admin, run once)

Params: `-Vps <user@ip>` (required), `-Port <int>` (default 8443),
`-ServerAddr <ip>` (default = the IP from `-Vps`). Windows PowerShell 5.1
compatible (no `&&`, no ternary). Steps:

1. Ensure toolchains: check `cargo` (MSVC) and `node`/`npm`; if missing, print
   precise install instructions and stop (do not silently install system-wide).
2. `scp` the two pins from
   `${Vps}:maxsecu-server-data/client-pins/{server_cert.der,directory_pub.der}`
   into a temp dir.
3. Build + run `maxsecu-setup` against the public server:
   `cargo run --release --manifest-path tools/maxsecu-setup/Cargo.toml -- \
     --server $ServerAddr:$Port --host $ServerAddr --cert <downloaded server_cert.der> \
     --out recovery_key.blob --pin-out recovery_pin.bin --first-key-out register.key`
   (prompt for the recovery passphrase; pass via `SETUP_RECOVERY_PW` env to avoid
   echo). Handle exit code 3 = "already registered" gracefully.
4. Copy `recovery_pin.bin` → `crates/client-app/recovery_pin.bin`.
5. Build UI: `pushd crates/client-app/ui; npm ci; npm run build; popd`.
6. Build client:
   `cargo build --release --manifest-path crates/client-app/Cargo.toml -p maxsecu-client-app`.
7. Lay out admin working client `dist/MaxSecuClient/` (binary + `ui/` + `config/`
   pins + the `register.key` for the admin's own first enrollment = admin).
8. Build the **clean handout**: stage a fresh copy with ONLY the binary + `ui/` +
   `config/{server_cert.der,directory_pub.der}` + `START-HERE.txt`; explicitly
   **exclude** `keystore/`, `cache/`, `logs/`, any `register.key`, the recovery
   blob. Zip → `dist/MaxSecuClient-share.zip`.
9. Print next steps: move `recovery_key.blob` + passphrase to cold storage; run
   the admin client and enroll (first enrollee = admin); to add a user, mint a
   registration key in-app and send them the ZIP + that key.

`START-HERE.txt` content (plain language): unzip anywhere, double-click
`maxsecu-client-app.exe`, on the screen enter the server address your admin gave
you (`IP:8443`) and the registration key, pick a username + passphrase. That's it.

## Docs

- `README.md` — rewrite as the beginner guide. Sections: What this is · What you
  need · Part 1 Set up the server (SSH once, `git clone <YOUR_REPO_URL>`,
  `./scripts/install-server.sh --public`) · Part 2 Build your app + the shareable
  ZIP (`install-client.ps1 -Vps user@ip`) · Part 3 Add users & everyday use (mint
  key, send ZIP + key; upload/bundles/share/download in a sentence each) ·
  Keeping the server running (systemd, `journalctl`) · If something goes wrong
  (troubleshooting table: SSH auth, toolchain download, Postgres, firewall, cert
  mismatch/"secure connection failed" = wrong IP or stale cert) · Recovery (what
  `recovery_key.blob` is; keep it offline) · For developers → `docs/development.md`.
  One clearly-marked placeholder: `<YOUR_REPO_URL>`.
- `docs/development.md` — the current `README.md` content (build/test/clippy/deny,
  Phase-0 status, two-workspace note) verbatim, so nothing is lost.

## Verification

- Server crate: `cargo test -p maxsecu-portable-server` + `cargo clippy -p
  maxsecu-portable-server --all-targets -- -D warnings`, including the IP-SAN
  handshake test.
- Client crate: `cargo test --manifest-path crates/client-app/Cargo.toml`
  (register/server-address) + clippy; `npm run build` succeeds.
- Scripts: `shellcheck scripts/install-server.sh`; PowerShell parse check of
  `install-client.ps1` (`[ScriptBlock]::Create((Get-Content -Raw …))`).
- Do **not** run `cargo fmt --all` (pre-existing rustfmt drift). Format only
  changed files if needed.
- Live end-to-end (real VPS + clean Windows build) is the user's to confirm; the
  README troubleshooting section covers the expected snags.

## Out of scope (YAGNI)

Domain names / Let's Encrypt; the full production ceremony profile (offline D5,
CA cert, WORM sink); SSH-tunnel/Tailscale transports; auto-updating clients;
bundling the Rust/Node toolchains into an installer.
