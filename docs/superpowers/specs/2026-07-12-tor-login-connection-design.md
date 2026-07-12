# Test & Fix Tor Login to the Port-Forwarded Server — Design

**Date:** 2026-07-12
**Status:** Approved (pending spec review)
**Topic:** Make the MaxSecu client log in over Tor to a port-forwarded, self-hosted server, and fix the "stuck on the login page" symptom.

## Problem

A user port-forwarded TCP **8443** on their home router and wants the client to log in **over Tor** to the self-hosted MaxSecu server. A prior attempt "got stuck on the login page." We must test the Tor login path end-to-end and fix whatever makes it hang.

### Confirmed facts (from code investigation)

- The client's Tor mode is **clearnet-over-Tor**: `TorState::dial` calls `client.connect((host, port))` and dials the server's clearnet `host:port` **through a Tor exit relay** — it is *not* a `.onion` address (`crates/client-app/src/tor.rs:94-106`). Onion addressing is explicitly deferred.
- TLS is layered identically on the Tor and direct streams via `tls_over` (`crates/client-app/src/transport.rs:27-49`), pinning a single self-signed cert (`server_cert.der`) as the sole root, using rustls' default WebPKI verifier — **which still enforces SAN/hostname match and validity**.
- Login is two cheap calls on one pinned-TLS connection: `POST /v1/session/challenge` → `POST /v1/session/proof` (`crates/client-app/src/session.rs:83-146`). It is **NOT** gated by delegation or clock-skew (those gate only enrollment + the ceremony — `crates/server/src/http.rs:286-288`, `crates/server/src/delegation.rs`).
- The server binds **`127.0.0.1` by default**; only `install-server.sh --public` sets `MAXSECU_BIND=0.0.0.0` (`crates/portable-server/src/config.rs:69`, `scripts/install-server.sh:590-594`).
- The self-signed cert adds `localhost` + `127.0.0.1` SANs always, and the public address as an **IP-SAN only if `MAXSECU_PUBLIC_ADDR` is set** at generation time; generation is **idempotent** (skips if the cert exists), so a stale cert keeps old SANs (`crates/portable-server/src/pki.rs:20-45`).

### Root causes of "stuck on the login page"

1. **No timeout anywhere on the Tor path** — `TorClient::create_bootstrapped` (`tor.rs:83`), `client.connect` (`tor.rs:101`), and the `tls_over` handshake (`transport.rs:39`) are awaited with **no wrapping timeout**. The Tor design doc (`docs/superpowers/specs/2026-07-02-tor-transport-design.md` §5) *required* a ~60s bootstrap timeout that was never implemented. Any slow/blocked circuit hangs `connect()` **forever** → dead spinner. **This is the load-bearing defect.**
2. **The login screen never subscribes to `EVT_CONNECTION`** (`crates/client-app/ui/src/components/connect-screen.ts`). The backend emits progress states (`ConnectionState::TorBootstrapping`, etc. — `crates/client-app/src/state.rs:192-193`), but the UI shows a static "Opening encrypted transport…" string and holds a busy spinner until the promise settles. Even a *normal* cold Tor bootstrap (10–60s) looks stuck.

### Environmental preconditions (currently ALL unmet)

Probed on 2026-07-12: nothing listens on WSL:8443, no systemd unit, no Windows portproxy, no firewall rule for 8443. The router forward currently dead-ends. Public IP is **176.63.161.224** (real, not CGNAT; the earlier `193.39.15.51` was a now-disconnected VPN exit). Every link below must hold:

| Link | Action |
|---|---|
| Router `176.63.161.224:8443` → `192.168.0.10:8443` | user-configured; verify |
| Windows `:8443` → WSL `:8443` | portproxy **or** WSL mirrored-networking (needs admin/UAC) |
| Windows firewall inbound TCP 8443 | allow rule (needs admin/UAC) |
| Server bound `0.0.0.0:8443` | run portable-server with `MAXSECU_BIND=0.0.0.0` |
| Cert carries `176.63.161.224` as IP-SAN | set `MAXSECU_PUBLIC_ADDR=176.63.161.224`, delete stale cert to regenerate |
| Tor exit permits `:8443` | verify empirically (8443 is in Tor's reduced exit-policy allowlist + permitted by default policy — not a real blocker) |

Because Tor traffic exits to a **genuinely external** relay before returning to the WAN IP, this is a real external round-trip and sidesteps NAT-hairpin — the correct thing to test.

## Decisions (from brainstorming)

- **Architecture:** clearnet-over-Tor on **8443** (minimal, already set up). 8443 coexists with the VPS's Apache on 80/443. Onion service is a deferred follow-up.
- **Test target:** local WSL server on this PC via the home-router forward (a rehearsal for the VPS).
- **Test method:** headless Rust smoke first (fast, automatable), then one GUI confirmation.
- **Fix scope:** full hardening — timeout **and** UI progress **and** a regression test.

## Plan (phased)

### Phase 0 — Stand up the reachable server *(driver: me; needs UAC)*
- Detect WSL networking mode (mirrored vs NAT). If NAT, add `netsh interface portproxy` from Windows `:8443` to the WSL eth0 IP; if mirrored, none needed. Add a Windows firewall inbound allow for TCP 8443.
- Run `portable-server` bound `0.0.0.0:8443` with `MAXSECU_PUBLIC_ADDR=176.63.161.224`; delete any stale cert first so the IP-SAN is baked in.
- Enroll **one** test identity (via the normal direct client/setup path) and stash its keys + the pinned `server_cert.der` for the smoke to consume.

### Phase 0.5 — Reachability gate *(STOP-if-fail)*
- Prove the server responds locally (127.0.0.1:8443 and WSL:8443) and that Windows:8443 forwards to WSL (dial `192.168.0.10:8443` locally).
- Prove **external** reachability: the true external vantage is the Tor dial itself; optionally corroborate with an external port-check of `176.63.161.224:8443`. If external inbound fails (ISP block / forward misconfig), stop and fix the network — no code change helps.

### Phase 1 — Timeout fix (TDD) *(Track A — Rust transport)*
- Wrap Tor **bootstrap** (`tor.rs:83`), **dial** (`tor.rs:101`), and **TLS handshake** (`transport.rs:39`) in bounded timeouts. Proposed budgets (tunable): bootstrap ≤ 60s, dial ≤ 30s, handshake ≤ 15s — or a single overall connect deadline.
- On expiry, return a specific, sanitized error code (e.g. `tor_timeout` / reuse `offline`) so the UI shows a prompt, readable error instead of hanging.
- Tests: a unit/integration test asserting a blocked dial returns the timeout error within the budget (use a black-hole address / stub).

### Phase 2 — Headless Tor login smoke *(Track A — Rust transport)*
- New env-gated harness (extend `crates/client-e2e` `tor_route_e2e.rs` or `tools/live-smoke`): bootstrap a real arti `TorClient`, dial `176.63.161.224:8443` over a circuit, layer pinned TLS from the stashed cert, load the Phase-0 identity, run `challenge` → `proof`, assert a `session_token`.
- Gated behind an env var (e.g. `MAXSECU_TOR_LIVE=1` + the public IP) and `#[ignore]` so CI stays green.

### Phase 3 — Diagnose & fix *(driver: me; systematic-debugging)*
- Run the smoke; read the now-bounded error; fix the actual environmental cause (SAN mismatch / exit-policy / portproxy / ISP). Iterate until the smoke logs in over Tor.

### Phase 4 — UI progress *(Track B — Frontend; parallel with A)*
- Subscribe `connect-screen.ts` to `EVT_CONNECTION`; render live states ("Bootstrapping Tor…", "Handshaking…", "Authenticating…") and a visible failure state. Disjoint from Track A's files.

### Phase 5 — GUI confirmation *(driver: user)*
- User runs the real Tauri app, enters `176.63.161.224:8443`, checks "use Tor", logs in end-to-end.

### Phase 6 — Verify + CI gate *(driver: me)*
- Full local gate per project discipline: `cargo fmt --all -- --check`, `cargo clippy -D warnings`, `cargo test --locked` (client-app is its own workspace: `--manifest-path crates/client-app/Cargo.toml`). Live-Tor test stays `#[ignore]`/env-gated. `client-app`/`client-e2e` are excluded from CI, but must build+test locally.

## Multi-subagent orchestration

After Phase 0/0.5 (sequential, interactive, mine), two **disjoint code tracks run concurrently** on the same model/effort:
- **Track A (Rust transport):** timeout fix + headless smoke — `tor.rs`, `transport.rs`, `connection.rs`, `client-e2e`.
- **Track B (Frontend):** `connect-screen.ts` progress wiring — no file overlap with A.

Phase 3 (diagnosis) and Phase 6 (CI gate) are sequential and mine. Parallelism is real but bounded (~2 tracks + an optional diagnosis-fix agent) — not invented fan-out.

## Success criteria

1. The headless smoke completes a full `challenge → proof` login **over a Tor circuit** to `176.63.161.224:8443`, returning a session token.
2. A blocked/slow Tor path yields a **prompt, readable error** (within the timeout budget), never an infinite spinner.
3. The GUI login screen shows **live progress**, and the user can log in over Tor from the real app.
4. Full local CI gate is green.

## Risks

- **ISP/router doesn't deliver external inbound** → caught at Phase 0.5; network-side fix, not code.
- **netsh needs admin** → a UAC prompt will appear during Phase 0.
- **WSL eth0 IP changes across restarts** (NAT mode) → portproxy must target the current IP, or use mirrored networking.

## Out of scope

- Tor onion service (`.onion`) support — deferred follow-up.
- VPS deployment (Apache coexistence is already satisfied by using 8443).
- Moving the server to port 443 (unnecessary; 8443 is fine over Tor).
