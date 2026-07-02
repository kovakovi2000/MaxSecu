# Plan — 3-way download-route setting + Dropbox direct-link + Tor transport

**Created:** 2026-07-02 · **Branch:** local `main` (no push).
**User decision:** build ALL THREE for real (route setting + coupling + Dropbox direct-link download + real Tor transport).

## The setting
A 3-way **download/transport route** in client Settings:
1. **TOR only** — route all traffic over Tor (fail-closed, no clearnet fallback); forces server-proxy (direct-Dropbox disabled under Tor).
2. **Prefer server** (default) — server proxies every blob (today's behavior).
3. **Prefer Dropbox offload** — when a blob is offloaded, download its ciphertext directly from Dropbox via a server-brokered short-lived URL (verify+decrypt client-side); fall back to server if unavailable.

**Login coupling:** ticking "Use Tor" on the connect screen auto-sets the mode to **TOR only** and persists it.

## Part A — route-mode setting + login coupling  [foundation; build first]
- `client-app/src/config.rs`: replace the `use_tor: bool` triple (`ConnectionSettings`, `ConnectionConfig`, and `ConnectRequest`) with a `RouteMode` enum (`TorOnly | PreferServer | PreferDropbox`, serde kebab, default `PreferServer`). Keep back-compat deserialization of the old `use_tor: bool` (`true`→`TorOnly`, `false`→`PreferServer`). Consolidate onto `SettingsConfig.connection.route_mode` as the persisted source of truth (T5 spec §8.6).
- `commands/settings.rs`: `get_settings`/`set_settings` round-trip `route_mode` (normalized).
- `commands/connection.rs`: `connect` reads `ConnectRequest` — if the Tor checkbox is ticked, persist `route_mode = TorOnly` to settings before/at connect (the coupling). `reauth` reads the persisted `route_mode`. Thread the mode into `open_conn` (drives Part C's dial + Part B's download choice). Replace the `if use_tor { not_implemented }` stub with a match on mode.
- UI `ui/src/components/settings-screen.ts`: replace the disabled `use_tor` checkbox with a 3-option control (radio group / select), labelled, WCAG-AA, wired via `onPrefChange` into `patch.connection.route_mode`. `core/settings.ts` applies it.
- UI `ui/src/components/connect-screen.ts`: the "Use Tor" checkbox initializes from the persisted mode (checked iff `TorOnly`) and, when ticked at connect, sets mode → TOR only (calls `set_settings` or passes it through connect). 
- Tests: config round-trip + back-compat; a11y structural lint for the new control.
- **Acceptance:** setting persists + drives `route_mode`; ticking Tor at login flips the setting; `prefer-server` behaves exactly as today; build 0 warnings; UI typecheck/test/a11y/build green.

## Part B — Dropbox direct-link download  [two-stage: security — external fetch]
- Server: turn on `direct_links_enabled` (config-gated in portable-server; the tier already implements `broker_direct_link` for offloaded chunks). Add/confirm the `GET .../direct-link` handler returns the brokered `DirectLink` for an offloaded chunk (or 404/none → client proxies).
- `client-core`: a direct-link fetch helper — download ciphertext from the brokered URL over TLS, then run it through the SAME per-chunk AEAD + manifest-digest verification the proxied path uses (a tampering/space link is caught; NO trust in the link source). Fail-closed → fall back to server proxy.
- `client-app`: when `route_mode == PreferDropbox` (and NOT Tor), the download path asks the server for a direct link per offloaded chunk, fetches+verifies via client-core, else proxies. Under `TorOnly`, NEVER direct (forces proxy).
- Tests: e2e over the real server+fs cold tier — offloaded chunk served via brokered link, verified; tampered link rejected; absent link → proxy fallback.
- **Security pass:** only ciphertext fetched; every byte AEAD/manifest-verified regardless of source; no key/plaintext to the link; fail-closed; never direct under Tor.

## Part C — real Tor transport  [two-stage: security — TCB transport / new deps]
- Ground in the T5 spec (`docs/superpowers/specs/2026-07-02-tor-transport-design.md`). Add `arti-client` (+ tokio rtcompat) to `client-app`; **deny.toml review** of the tree (no `ring`/`openssl` for the app TLS path; license + RUSTSEC pass; pin versions). If the tree fails review, fall back to a `tokio-socks` SOCKS5 connector (T5 §2 fallback) — report before committing a workaround.
- `transport.rs`: generalize `Transport::connect` to dial either a raw `TcpStream` (Direct) or an `arti_client::DataStream` (Tor) under the SAME `TlsConnector`/pinned root store/RFC5705 exporter — TLS + channel binding UNCHANGED (T5 §3). `pinned_client_config` untouched (review red-flag if it changes).
- `commands/connection.rs`/managed `TorState`: lazily bootstrap a shared `TorClient` on first Tor connect; `ConnectionState::TorBootstrapping`; sanitized `tor_unreachable`; fail-closed (never clearnet fallback under TorOnly).
- Tests: SOCKS5-stub e2e proving TLS + exporter survive the tunnel (T5 §9); fail-closed test; `#[ignore]` real-bootstrap smoke.
- **Security pass:** channel-binding/pinning survive the tunnel; no verifier bypass; fail-closed; deny/audit clean or justified.

## Part C — BLOCKED (2026-07-02) → DEFERRED pending user decision
`arti-client` **cannot resolve** in this workspace: `arti-client → tor-dirmgr → rusqlite → libsqlite3-sys ^0.34` collides with the workspace's `sqlx-sqlite → libsqlite3-sys ^0.30` under Cargo's `links = "sqlite3"` uniqueness rule — even though `sqlx`'s SQLite feature is never enabled, `sqlx-sqlite` is still a resolution candidate in the single shared `Cargo.lock` (confirmed: both are in the lockfile though never compiled). No code was written; worktree left clean.
**Options (need the user):** (1) bump the server's `sqlx` 0.8→0.9 (its SQLite range overlaps arti's → resolves; but a semver-major bump of the server DB adapter — verify first whether arti can drop its SQLite dir-store to avoid this entirely); (2) **DEFER Tor** (chosen default while user away): ship A+B, `TorOnly` stays fail-closed/selectable; (3) `tokio-socks` + external tor daemon (avoids the conflict, no server change, but needs a local tor + changes the trust surface — design preferred arti). `pinned_client_config` + the RFC5705 exporter remain UNCHANGED.

## Sequencing & review
A first (controller-built, defines the shared `RouteMode` contract + coupling). Then B and C in parallel (subagent-driven, each its own worktree), each two-stage reviewed (spec then security). Merge each; final workspace verification (build 0-warn, workspace lib, e2e, UI checks, cargo deny); then a holistic pass. Update memory.

## Notes / risks
- **arti-client is the biggest risk** (large tree, may fail deny; real Tor can't be CI-verified) — treated as a go/no-go per T5; `tokio-socks` is the documented fallback.
- Server-side write-back offload engine already merged (`b7281f0`) — Part B rides on its `broker_direct_link`.
- cargo NOT on PATH (prefix). NEVER `cargo fmt`. Tauri exe embeds `ui/dist` — rebuild+restage after UI changes. Trailers: Co-Authored-By: Claude Opus 4.8 + Claude-Session.
