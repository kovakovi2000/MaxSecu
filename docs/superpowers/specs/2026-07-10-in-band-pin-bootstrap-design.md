# In-band pin bootstrap via a fingerprint code

**Date:** 2026-07-10
**Status:** Approved (ready to implement)
**Scope:** Installer-only. Remove SSH from the client install entirely.

## Problem

`scripts/install-client.ps1` fetches the two trust-anchor pins
(`server_cert.der`, `directory_pub.der`) from the VPS over **scp**. SSH/scp is
the biggest failure point in the installer (Pageant vs OpenSSH key mismatch,
custom ports, host-key prompts). We want the client to fetch those pins **over
the network from the server itself**, authenticated so a man-in-the-middle on
that first fetch cannot substitute a fake cert.

## Trust model (why this is safe)

The two pins are **public** (a self-signed TLS cert + an Ed25519 directory key).
We need *integrity*, not secrecy. `install-server.sh` runs **on the box that
holds the pins**, so it can print a **connection code** that carries a hash
committing to the exact pin bytes. The admin copies that code by hand from their
own terminal into their own `install-client` invocation (a fully trusted path).
The client fetches the pins over the network, recomputes the hash, and trusts
them **only if it matches the code**. A network attacker cannot craft different
pins with the same hash (second-preimage resistance); a relaying attacker can
only pass the genuine pins through, after which the client pins the real cert and
the attacker is locked out. This is the SSH host-key-fingerprint model without
the SSH dependency. No secret is stored on the server.

## The connection code

```
193.39.15.51:8443#K7QF9M2ATBZ4C6XU...   (addr:port  #  fingerprint)
```

- `fingerprint = base32( SHA-256( DS ‖ len32(cert) ‖ cert ‖ len32(dir) ‖ dir )[..20] )`
  - `DS` = the ASCII bytes `MAXSECU-PINS-v1` (domain separation).
  - `len32(x)` = the byte length of `x` as a big-endian `u32`.
  - `cert` = raw bytes of `server_cert.der`; `dir` = raw bytes of `directory_pub.der`.
  - Truncate the SHA-256 digest to the first **20 bytes** (160 bits — ample
    preimage resistance), then base32-encode → exactly **32 chars**.
  - base32 = RFC 4648 alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`, uppercase, **no
    padding**. Implement inline (no new crate dependency).
- The **address half is untrusted** transport info (where to dial). Only the
  fingerprint is load-bearing.
- **Normalization on compare:** uppercase and strip every char not in
  `[A-Z2-7]` before comparing, so dashes/spaces introduced when copying don't
  break it.

## Components

### 1. Shared helper — `crates/crypto` (`maxsecu-crypto`)

Add a single source of truth used by BOTH the server (to print) and the client
(to verify), so they can never disagree:

```rust
/// base32(RFC4648, no pad) of SHA-256("MAXSECU-PINS-v1" ‖ len32(cert) ‖ cert
/// ‖ len32(dir) ‖ dir) truncated to 20 bytes. Uppercase, 32 chars.
pub fn pin_fingerprint(cert_der: &[u8], dir_der: &[u8]) -> String;
```

- Inline base32 encoder (no new dependency on the crypto crate).
- Unit tests: a known-answer vector; and "flipping any byte of cert or dir
  changes the output".

### 2. Server bootstrap endpoint — merged in the launcher (`crates/portable-server`)

**Do NOT touch the generic `server` crate or `AppState<S>`.** Add a small module
`crates/portable-server/src/bootstrap_pins.rs`:

```rust
/// A router exposing GET /v1/bootstrap/pins, closing over the pin bytes.
pub fn router(cert_der: Vec<u8>, dir_der: Vec<u8>) -> axum::Router;
```

- Handler returns `200 application/json`:
  `{ "server_cert_b64": "<base64 cert>", "directory_pub_b64": "<base64 dir>" }`.
- Unauthenticated by design (public data). Small, fixed-size response.
- In `run::prepare` (`crates/portable-server/src/run.rs`): export the pins to
  `client-pins/` **before** composing the bootstrap router (today the export
  happens in `run::run`; move/duplicate the two `export_client_pin*` calls so the
  files exist in `prepare`, or read the cert bytes from `layout.cert_der_path()`
  and the dir bytes from the exported `directory_pub.der`). Read both files, then
  `let app_router = app_router.merge(bootstrap_pins::router(cert_bytes, dir_bytes));`
  The served bytes MUST be byte-identical to the files `client-pins/*.der`.
- `portable-server` gains `base64` + `serde_json` deps if not already present
  (serde_json is; add base64).

### 3. Server fingerprint print — `crates/portable-server`

- **Subcommand** in `main.rs`: if `std::env::args().nth(1)` == `print-fingerprint`,
  read `<data_dir>/client-pins/{server_cert.der,directory_pub.der}` (data dir from
  `MAXSECU_DATA_DIR`, same default as `LauncherConfig`), print
  `maxsecu_crypto::pin_fingerprint(cert, dir)` to **stdout** and exit 0. On a
  missing pin file, exit non-zero with a stderr message. This is what
  `install-server.sh` calls — deterministic, not log-scraping.
- In `run::run`, also log a human line at startup:
  `connection code: <public_addr-or-127.0.0.1>:<port>#<fp>`.

### 4. Client fetch — `tools/maxsecu-setup` gains a `fetch-pins` mode

- In `main.rs`, if the first CLI arg is `fetch-pins`, dispatch to a new fetch
  path instead of the recovery-setup flow. Flags (reuse the existing
  `parse_flags`/`opt` helpers):
  - `--server ADDR:PORT` (dial target; required)
  - `--host ADDR` (SNI/Host; default = host part of `--server`)
  - `--fingerprint FP` (required)
  - `--cert-out PATH`, `--dir-out PATH` (required)
- New module `tools/maxsecu-setup/src/fetch.rs`:
  - Build an **unpinned** rustls `ClientConfig` with a clearly-named
    accept-any-cert verifier (`struct AcceptAnyServerCert;` implementing
    `ServerCertVerifier`, scoped to this file, loudly commented that it is safe
    ONLY because the payload is fingerprint-verified immediately after).
  - Connect TLS to `--server`, `GET /v1/bootstrap/pins`, parse the JSON, base64-
    decode both pins.
  - Recompute `maxsecu_crypto::pin_fingerprint(&cert, &dir)`; normalize both it
    and `--fingerprint` (uppercase, strip non-`[A-Z2-7]`); compare.
  - **On match:** write the two `.der` files (create-new semantics fine) and exit
    0. **On mismatch / network / parse error:** write **nothing**, print a clear
    `[fetch-pins] error: ...` to stderr, exit non-zero.
- The existing recovery-setup path (`real_main`) is unchanged and still consumes
  a `--cert` file.

### 5. `scripts/install-server.sh`

- After the pin-wait loop succeeds (the `$PIN_CERT` check), compute the
  fingerprint by invoking the freshly built server binary:
  `FP="$("$SERVER_BIN" print-fingerprint)"` with `MAXSECU_DATA_DIR="$DATA_DIR"`
  exported (so it reads the right data dir). Guard against an empty `FP`.
- In the friendly summary, print a clearly-labelled block:
  `Connection code (give this to install-client): <PUBLIC_ADDRESS>#<FP>` where
  `PUBLIC_ADDRESS` is the same `IP:PORT` already computed (or `127.0.0.1:PORT`
  for local-only). Explain it replaces the old "fetch pins over SSH" step.
- Update the printed `NEXT STEP` line to use `-ConnectionCode` (below) instead of
  `-Vps root@...`.

### 6. `scripts/install-client.ps1`

- **Remove** params `-Vps`, `-SshPort`, `-PinsDir` and the entire scp/`-PinsDir`
  download block and its help text. Keep the `-Reset` parameter set already added.
- **New params** (Install parameter set):
  - `-ConnectionCode "addr:port#fp"` — primary; parse into `$ServerAddr`,
    `$Port`, `$Fingerprint`.
  - `-ServerAddr`, `-Port` (default 8443), `-Fingerprint` — manual alternative.
  - Validation: require either `-ConnectionCode` OR (`-ServerAddr` and
    `-Fingerprint`); `Fail` with a clear message otherwise.
- **Replace** the "Downloading pinned certs from the VPS" section with a
  "Fetching + verifying pins" section that runs:
  `cargo run --release --manifest-path tools\maxsecu-setup\Cargo.toml -- fetch-pins --server "$ServerAddr`:$Port" --host "$ServerAddr" --fingerprint "$Fingerprint" --cert-out "$CertTmp" --dir-out "$DirTmp"`
  (prepend the cargo-PATH shim already in the script). On non-zero exit, `Fail`
  with a message pointing at the address/fingerprint.
- Everything after (recovery `maxsecu-setup` run using `$CertTmp`, embed pin, UI
  build, client build, admin/share layout, ZIP) is **unchanged**. The handout ZIP
  still bakes the pins into `config/` (end-user app unchanged).

## What is removed

The scp download, `-Vps`, `-SshPort`, `-PinsDir`, and all "key lives in Pageant"
fallback text. The admin no longer needs SSH to the VPS to build a client — only
the connection code.

## Testing / acceptance

- **Unit (`maxsecu-crypto`):** `pin_fingerprint` known-answer; byte-flip changes it.
- **Unit (server):** `bootstrap_pins::router` returns JSON whose base64 fields
  decode to the exact input bytes.
- **e2e (Rust, `maxsecu-setup` or `crates/client-e2e`):** start an in-process
  launcher (`run::prepare`), call the `fetch-pins` logic against it, assert the two
  written `.der` files are byte-identical to the server's `client-pins/*.der`.
  **Negative:** a mutated fingerprint makes fetch fail and write nothing.
- **Script smoke:** `bash -n scripts/install-server.sh`; `install-server.sh
  print-fingerprint` path reachable; `install-client.ps1` parses a
  `-ConnectionCode`, splits it correctly, and reaches the fetch step.
- **Build gates (all must pass):**
  - Root workspace: `cargo build --release -p maxsecu-portable-server` and
    `cargo test -p maxsecu-crypto`.
  - Client workspace (its own): build via
    `--manifest-path crates\client-app\Cargo.toml` and
    `--manifest-path tools\maxsecu-setup\Cargo.toml` (NOT `-p` from root).
  - Clippy where touched. **Never run `cargo fmt --all`** (pre-existing rustfmt
    drift). Format only touched files if needed.

## Build gotchas (from repo memory — respect these)

- cargo may not be on PATH: bash `export PATH="$HOME/.cargo/bin:$PATH";` /
  PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";`.
- `client-app` is its **own** cargo workspace (arti↔sqlx split); `maxsecu-setup`
  is built by `--manifest-path`, not `-p` from the root.
- Tauri v2 top-level scalar command args are camelCase in JS — N/A here (no UI
  changes), noted for completeness.
- Rebuild the dist server binary after server changes.

## Edge cases

- `--public` re-run regenerates the cert → new pins → new fingerprint → new code;
  old codes correctly fail verification (expected).
- Local-only server → code is `127.0.0.1:PORT#fp`.
- Malformed code, unreachable server, or hash mismatch → distinct non-zero exits
  with clear messages; no partial pin files written.
- The bootstrap endpoint is reachable before pinning because the client dials it
  with cert verification disabled and authenticates the *payload* via the
  fingerprint (not the transport).
