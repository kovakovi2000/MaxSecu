# Dropbox OAuth-refresh cold tier — design

**Date:** 2026-07-09
**Status:** Approved (brainstorm)
**Owner area:** `crates/server` (dropbox tier), `crates/portable-server` (config/wiring), `scripts/install-server.sh` (installer)

## Goal

The Dropbox cold tier (`crates/server/src/dropbox_tier.rs`) currently authenticates with a
single **static** OAuth access token from `MAXSECU_DROPBOX_TOKEN`. Dropbox scoped-app access
tokens are short-lived (~4 h), so the tier stops working once the token expires. This design
replaces the static token with an **OAuth refresh flow**: the server holds the long-lived
refresh token + app key/secret and mints fresh access tokens automatically, so offload and
rehydrate keep working with **no manual token maintenance** for as long as the app stays
authorized ("forever" modulo the operator revoking the app or Dropbox invalidating the
refresh token).

## Non-goals

- **No OAuth helper / browser flow.** The operator obtains the credential values out of band
  (Dropbox App Console + a one-time offline-access authorization) and pastes them.
- **No rotating-refresh-token handling.** Dropbox default refresh tokens are non-rotating; the
  server only *reads* the refresh token and never persists a new one. (Rotating-refresh-token
  support, if ever needed, is a follow-up.)
- **No legacy static-token mode.** The static-`MAXSECU_DROPBOX_TOKEN`-only path is **removed**.
  Dropbox mode requires the full refresh credential set or the cold tier stays **Off**.

## Current state (verified references)

`crates/server/src/dropbox_tier.rs`:
- `struct DropboxToken(String)` — redacts `Debug`, best-effort zeroize on drop; carried only in
  the `Authorization: Bearer …` header.
- `struct DropboxTier<H: DropboxHttp> { http: H, token: DropboxToken, root, … }`; an auth-header
  helper returns `("authorization", format!("Bearer {}", self.token.as_str()))`.
- `trait DropboxHttp { async fn execute(&self, DropboxRequest) -> Result<DropboxResponse, BlobError>; }`
  — the **sole** I/O seam. `DropboxRequest { method: DropboxMethod, url: String,
  headers: Vec<(String,String)> /* incl. Authorization */, body: Vec<u8> }`;
  `DropboxResponse { status: u16, body: Vec<u8>, … }`.
- Transports: `HyperDropboxHttp` (hyper + tokio-rustls/aws-lc-rs, verifies Dropbox's public
  WebPKI identity via `webpki-roots`); `MockDropboxHttp` (unit tests, records requests, returns
  canned responses).
- Constructors: `DropboxTier::<HyperDropboxHttp>::new(token, root)` (real);
  `with_http_and_hosts(http, token, api_host, content_host, root)` (generic).
- Hosts: `DEFAULT_API_HOST = "https://api.dropboxapi.com"`,
  `DEFAULT_CONTENT_HOST = "https://content.dropboxapi.com"`.
- `dropbox_live_round_trip` — `#[ignore]`d live test gated on `DROPBOX_TEST_TOKEN`.

`crates/portable-server/src/config.rs`:
- `enum ColdTierCfg { Off, Fs(PathBuf), Dropbox { token, root } }`.
- `from_parts(env)` parses `MAXSECU_COLD_TIER` = `off|fs|dropbox`; for `dropbox` reads
  `MAXSECU_DROPBOX_TOKEN` (+ `MAXSECU_DROPBOX_ROOT`, default `/maxsecu`), **fail-closed to Off**
  on a missing/empty token.

`crates/portable-server/src/run.rs::build_blobs`:
- `ColdTierCfg::Dropbox { token, root } => Arc::new(DropboxTier::new(token.clone(), root.clone())?)`
  then wrapped in `WriteBackTier` with a background idle-offload sweeper.

`scripts/install-server.sh`:
- Writes the systemd unit `/etc/systemd/system/maxsecu-server.service` (`root:root 0600`) with
  `Environment=` lines (holds `DATABASE_URL`, `MAXSECU_BIND`, `MAXSECU_PUBLIC_ADDR`,
  `MAXSECU_PORT`, `MAXSECU_DATA_DIR`).

## Design

### 1. Refreshing token source (`crates/server/src/dropbox_tier.rs`)

Replace the static `token` with a self-refreshing credential holder. Secrets redact `Debug`
and best-effort zeroize on drop, mirroring `DropboxToken`.

```
struct DropboxCreds {
    app_key: String,          // public-ish; used as HTTP Basic username on the token endpoint
    app_secret: Secret,       // redacted/zeroized
    refresh_token: Secret,    // redacted/zeroized
    cached: tokio::sync::Mutex<Option<CachedToken>>, // { access_token: DropboxToken, expires_at: Instant }
}
```

`DropboxTier<H>` holds `creds: DropboxCreds` instead of `token: DropboxToken`.

`async fn bearer(&self) -> Result<String, BlobError>`:
1. Lock `cached`; if a token exists and `Instant::now() + REFRESH_MARGIN < expires_at`, return
   `"Bearer <access_token>"`.
2. Otherwise **refresh under the lock** (single-flight: concurrent callers wait, then reuse the
   fresh token). Build a `DropboxRequest`:
   - `POST https://api.dropboxapi.com/oauth2/token`
   - header `Authorization: Basic base64(app_key ":" app_secret)`
   - header `Content-Type: application/x-www-form-urlencoded`
   - body `grant_type=refresh_token&refresh_token=<url-encoded refresh_token>`
   - execute via `self.http.execute(req)` (SAME seam ⇒ mockable).
3. On 2xx, parse JSON `{ "access_token": String, "expires_in": u64 }`; store
   `(access_token, Instant::now() + Duration::from_secs(expires_in))`; return.
   Non-2xx or malformed body → `BlobError` (server-side, sanitized).

`const REFRESH_MARGIN: Duration = Duration::from_secs(300);` (refresh 5 min before expiry).

**Reactive refresh on 401.** Route the content requests (`put_chunk`, `get_chunk`, the
delete/broker paths) through a shared helper that: obtains the bearer, sets it as the request's
`Authorization` header, `execute`s, and if the response status is **401**, invalidates `cached`,
refreshes once, and retries the request a single time. This absorbs early expiry / clock skew.

**Transport reuse.** The refresh request uses only the existing `DropboxRequest` fields
(arbitrary `headers` + `body`), so no struct/transport changes should be needed. During
implementation, confirm a Basic-auth + form-body request can be built and executed by both
`HyperDropboxHttp` and `MockDropboxHttp`; extend `DropboxRequest`/transports only if it cannot.

**Constructors.**
- `DropboxTier::<HyperDropboxHttp>::with_refresh(app_key, app_secret, refresh_token, access_token: Option<String>, root)`
  — real adapter. An `access_token: Some(_)` warm-starts `cached` with expiry `Instant::now()`
  (used immediately, refreshed on first `bearer()` if already stale — safe either way).
- A generic `with_refresh_http(http, app_key, app_secret, refresh_token, access_token, api_host, content_host, root)`
  for unit tests (mock transport / stub token endpoint).
- **Remove** the static `new(token, root)` / static-token construction path.

### 2. Config (`crates/portable-server/src/config.rs`)

```
enum ColdTierCfg {
    Off,
    Fs(PathBuf),
    Dropbox {
        app_key: String,
        app_secret: String,
        refresh_token: String,
        access_token: Option<String>,
        root: String,
    },
}
```

`from_parts` for `MAXSECU_COLD_TIER=dropbox`:
- Read `MAXSECU_DROPBOX_APP_KEY`, `MAXSECU_DROPBOX_APP_SECRET`, `MAXSECU_DROPBOX_REFRESH_TOKEN`.
  If **all three** present and non-empty → `Dropbox { …, access_token: env("MAXSECU_DROPBOX_ACCESS_TOKEN"),
  root: env("MAXSECU_DROPBOX_ROOT").unwrap_or("/maxsecu") }`.
- Otherwise → `Off` (fail closed).
- `MAXSECU_DROPBOX_TOKEN` is **no longer read** (removed with the static mode).

### 3. Wiring (`crates/portable-server/src/run.rs::build_blobs`)

```
ColdTierCfg::Dropbox { app_key, app_secret, refresh_token, access_token, root } => Arc::new(
    DropboxTier::with_refresh(
        app_key.clone(), app_secret.clone(), refresh_token.clone(),
        access_token.clone(), root.clone(),
    ).map_err(|e| std::io::Error::other(format!("dropbox tier init: {e}")))?,
),
```

### 4. Installer (`scripts/install-server.sh`)

New section after the main install:
- Prompt `Enable Dropbox cold-tier offload? [y/N]` — default **No**; auto-No when stdin is not a
  TTY (`[ -t 0 ]`) so non-interactive `--public` runs never hang. (A `--dropbox`/`--no-dropbox`
  flag may also force the choice.)
- On **yes**, read (secrets with `read -rs`, no echo): App key, App secret, Refresh token,
  Access token (optional), Dropbox root (default `/maxsecu`).
- Write `/etc/maxsecu/dropbox.env` as `root:root 0600` (via `install -o root -g root -m 0600`):
  ```
  MAXSECU_COLD_TIER=dropbox
  MAXSECU_DROPBOX_APP_KEY=…
  MAXSECU_DROPBOX_APP_SECRET=…
  MAXSECU_DROPBOX_REFRESH_TOKEN=…
  MAXSECU_DROPBOX_ACCESS_TOKEN=…      # written only if provided
  MAXSECU_DROPBOX_ROOT=/maxsecu
  ```
- The systemd unit ALWAYS includes `EnvironmentFile=-/etc/maxsecu/dropbox.env` (leading `-` ⇒
  optional: an absent file is ignored, so no-Dropbox installs are unaffected and re-runs never
  clobber existing creds).
- Never echo secrets; the `0600` file is the only at-rest copy.

### 5. Error handling & security

- All refresh/transport failures collapse to `BlobError` server-side (existing sanitized
  posture); nothing sensitive reaches a client. A failed refresh makes the cold-tier op fail
  loudly (offload/rehydrate errors) rather than silently degrading.
- `app_secret`, `refresh_token`, and the cached `access_token` redact from `Debug` and
  best-effort zeroize on drop.
- Zero-knowledge egress unchanged: only client-encrypted ciphertext goes to content endpoints;
  the refresh token appears ONLY in the token-endpoint request body over TLS, never logged.

## Testing

**Unit (CI, `MockDropboxHttp`, no network):**
- Refresh mints + caches an access token; a second `bearer()` before expiry does NOT hit the
  token endpoint (cache hit).
- Expiry (past `REFRESH_MARGIN`) triggers a refresh.
- A content request returning **401** → cache invalidated → refresh → single retry → success.
- Refresh non-2xx / malformed JSON → `BlobError`, no panic.
- (Optional) concurrent `bearer()` callers cause exactly one refresh (single-flight).
- Config parsing: full refresh set → `Dropbox`; any missing → `Off`; `root` default `/maxsecu`.

**Live (`#[ignore]`d, env-gated on real creds the operator provides):**
`dropbox_live_round_trip_refresh` — construct the real `DropboxTier::with_refresh` from the
`MAXSECU_DROPBOX_*` env, force a refresh, `put_chunk` a random ciphertext-shaped blob under a
fresh random test path, `get_chunk` it back (bytes match), delete it. Run:
```
MAXSECU_DROPBOX_APP_KEY=… MAXSECU_DROPBOX_APP_SECRET=… MAXSECU_DROPBOX_REFRESH_TOKEN=… \
  cargo test -p maxsecu-server --lib -- --ignored dropbox_live_round_trip_refresh
```

## Operator flow (for docs / install output)

1. Dropbox App Console → create a scoped app; add scopes `files.content.write`,
   `files.content.read`, `sharing.write`; note the **App key** + **App secret**.
2. One-time offline authorization to get a **refresh token** (authorization-code flow with
   `token_access_type=offline`): visit
   `https://www.dropbox.com/oauth2/authorize?client_id=<APP_KEY>&response_type=code&token_access_type=offline`,
   approve, then exchange the returned code at `https://api.dropboxapi.com/oauth2/token`
   (`grant_type=authorization_code`, Basic `app_key:app_secret`) for `refresh_token` (+ an
   initial `access_token`).
3. Run `install-server.sh`, answer **yes** to Dropbox, paste the values.

## Env var reference

| Variable | Required | Default |
|---|---|---|
| `MAXSECU_COLD_TIER=dropbox` | yes (to enable) | `off` |
| `MAXSECU_DROPBOX_APP_KEY` | yes | — |
| `MAXSECU_DROPBOX_APP_SECRET` | yes | — |
| `MAXSECU_DROPBOX_REFRESH_TOKEN` | yes | — |
| `MAXSECU_DROPBOX_ACCESS_TOKEN` | no (warm-start) | — |
| `MAXSECU_DROPBOX_ROOT` | no | `/maxsecu` |

## Acceptance criteria

- With the full refresh credential set in the environment, the server offloads to and rehydrates
  from Dropbox, and continues to work across access-token expiry with no manual intervention
  (the live round-trip passes and a forced-expiry unit test proves auto-refresh).
- Missing any of app key/secret/refresh token → cold tier stays `Off` (fail closed); no static
  fallback.
- Secrets never appear in logs, `Debug`, or the terminal; the on-disk copy is `0600` root-only.
- `cargo clippy --workspace --all-targets --locked` (with `RUSTFLAGS=-D warnings`) and
  `cargo fmt --all -- --check` stay clean; unit tests pass in CI.
