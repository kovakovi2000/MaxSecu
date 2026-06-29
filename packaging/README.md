# MaxSecu Media App — Packaging (Phase 6, §8)

Portable build scripts and run instructions for the MaxSecu Media App. The two
scripts are twins:

- `package.ps1` — **primary** (Windows host).
- `package.sh` — POSIX/bash twin.

Both run `cargo build --release` for the two binaries
(`maxsecu-portable-server`, `maxsecu-client-app`), lay out the two portable
folders under `dist/`, and then run three **GUARDED** deferred-ops steps that
activate only when the required tool/cert is present — they never fail the build
and never fabricate a signed exe or a bundled PostgreSQL.

```powershell
# Windows
.\packaging\package.ps1
```
```bash
# POSIX
bash packaging/package.sh
```

> Build the WebView UI first so the client folder ships its assets:
> `cd crates/client-app/ui && npm run build` (produces `ui/dist/`).

---

## 1. Portable layouts

### 1.1 Client (`dist/MaxSecuClient/`, spec §8.1)

```
MaxSecuClient/
  maxsecu-client-app(.exe)   # the Tauri app binary
  ui/                        # embedded WebView assets (index.html, main.js, styles.css)
  config/                    # pinned server_cert.der + directory_pub.der (copied from the server)
  keystore/                  # the client's local key material
  index/                     # local content index
  cache/                     # downloaded/decrypted media cache
  logs/
```

### 1.2 Server (`dist/MaxSecuServer/`, spec §8.2)

```
MaxSecuServer/
  maxsecu-portable-server(.exe)   # the launcher exe
  schema.sql                      # applied by the prod (Postgres) profile
  config/
  logs/
  postgres/   tls/   sink/        # PROD only (see Deferred Ops) — not produced in dev
```

The launcher generates its runtime data dir (`./maxsecu-server-data/` by
default) at first run; the `config/`/`logs/` placeholders above are the
packaging skeleton.

---

## 2. Running (dev)

1. **Start the server** from the packaged folder (or from source):
   ```bash
   cargo run --release -p maxsecu-portable-server
   # or: ./dist/MaxSecuServer/maxsecu-portable-server
   ```
   On first run it lays out `./maxsecu-server-data/` and prints **once**:
   - the **one-time bootstrap secret** (record it now — shown only on first run);
   - the **DEV-ONLY pinned D5** directory public key (hex);
   - the **client-pins** location: `./maxsecu-server-data/client-pins/`
     containing `server_cert.der` + `directory_pub.der`.

2. **Wire the client:** copy
   `maxsecu-server-data/client-pins/{server_cert.der,directory_pub.der}` into the
   client's `config/` folder. The client pins these to authenticate the server
   and the D5 directory key.

3. **Run the client** (`maxsecu-client-app`) and bootstrap the first admin using
   the printed bootstrap secret.

### Env knobs

| Var | Default | Meaning |
|-----|---------|---------|
| `MAXSECU_DATA_DIR` | `./maxsecu-server-data` | server data dir |
| `MAXSECU_PORT` | `8443` | listen port (HTTPS, 127.0.0.1) |
| `DATABASE_URL` | _(unset → dev)_ | when set, selects the **Prod** (Postgres) profile |

Setting `DATABASE_URL` switches the server to the Prod profile, which requires a
real Postgres + an injected (non-self-signed) cert + an external audit sink +
`schema.sql` applied (see Deferred Ops). With no `DATABASE_URL`, the dev profile
runs self-contained on `MemoryStore` + `FsBlobStore` + a self-signed pinned cert.

---

## 3. Deferred ops (environment-blocked — wiring hooks present)

These are intentionally not produced in this environment; each script step is
guarded and prints a `DEFERRED (...)` notice instead of failing or faking an
artifact. The wiring hook is in place so they activate when the tool/cert exists:

- **Real PostgreSQL bundling.** Set `MAXSECU_PG_DIST` (the scripts copy the PG
  dist into `MaxSecuServer/postgres/`) and run the server with
  `DATABASE_URL=postgres://…` (Prod profile) so it uses `PgStore` and applies
  `docs/schema.sql`. Dev runs on `MemoryStore`, so no PG is needed for local use.
- **Authenticode signing.** Provide `signtool` (Windows SDK) + a code-signing
  cert via `MAXSECU_SIGN_CERT`; the guarded step then signs the exes. Without a
  cert the unsigned cargo binaries are produced.
- **Tauri GUI bundle.** Install the Tauri CLI and run `cargo tauri build` to
  produce the WebView2 installer bundle. The scripts otherwise ship the plain
  cargo-built `maxsecu-client-app` binary + the `ui/dist` assets.
- **Reproducible-build flags + transparency-logged release.** Existing MaxSecu
  ops deferrals (see `docs/reproducible-builds.md`): pin the toolchain, set the
  reproducibility flags, and publish the release to the transparency log in CI.

---

## 4. Security note (READ)

The dev profile is **SECURITY-DEGRADED / dev-only**:

- The **dev D5 key** and **dev bootstrap secret** are generated at runtime into
  the data dir. The bootstrap secret is shown once on first run.
- `config/d5_secret.bin` in the data dir is a **cleartext private key** (the dev
  D5 seed). The dev data dir therefore **must not be shared or committed** — anyone
  with it can forge directory entries.
- The pinned D5 printed at boot is the DEV key, not a production ceremony key.

**Production** replaces all of the above: the D5 **public** key comes from the
offline ceremony (no private key on the server), the TLS cert is a real injected
cert (not self-signed), and the audit sink is a real external/WORM sink. Use the
Prod profile (`DATABASE_URL=…`) with those injected, never the dev artifacts.
