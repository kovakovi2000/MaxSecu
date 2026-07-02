# Tor Transport — Design

**Status:** Draft design (spec-only task, 2026-07-02). No code in this change; ready for an implementation plan.
**Scope:** make the existing, currently-inert `use_tor` toggle (Phase-1 `ConnectRequest.use_tor`, Phase-5
`SettingsConfig.connection.use_tor`) actually route the client↔server connection through Tor, without
touching the crypto/auth path.
**Pre-existing decision this formalizes:** `DESIGN.md` D34 and `docs/stack.md` §1.8 already decided the shape
("optional, fail-closed, `arti-client`, forces server-proxy, optional onion service") before any Rust existed.
This document is the buildable version of that decision, grounded in the transport code that has since been
built (`crates/client-app/src/transport.rs`, `commands/connection.rs`) and the Phase-5 settings surface.

## 0. Where things stand today (read, not written, by this task)

- **Transport.** `crates/client-app/src/transport.rs::Transport::connect()` does exactly two things: dial a
  raw TCP socket (`tokio::net::TcpStream::connect(&self.addr)`), then run a TLS 1.3 handshake over it via
  `tokio_rustls::TlsConnector` built from `pinned_client_config()`. `pinned_client_config()` builds an
  `aws-lc-rs`-provider `ClientConfig` restricted to `TLS13` whose `RootCertStore` contains **only** the one
  pinned `server_cert.der` — no public CA roots. After the handshake, `Transport::connect()` calls
  `export_keying_material(&mut exporter, EXPORTER_LABEL, None)` where `EXPORTER_LABEL =
  b"EXPORTER-MaxSecu-channel-binding-v1"` (32 bytes), which is **byte-identical** to the server's
  `CHANNEL_BINDING_LABEL`/`CHANNEL_BINDING_LEN` in `crates/server/src/serve.rs` — a unit test in
  `transport.rs` (`exporter_params_are_pinned_to_server_contract`) guards the constants staying in sync.
- **Connect flow.** `crates/client-app/src/commands/connection.rs::open_conn(dir, server)` is the single seam
  that builds a `Transport`, runs `.connect()`, then layers `hyper::client::conn::http1::handshake` on top and
  returns `(SendRequest, host, exporter)`. Both `connect()` (fresh login) and `reauth()` (per-command
  channel-bound re-auth, used by every authenticated command) call `open_conn`. `connect()` **already has a
  fail-closed Tor stub**:
  ```
  if req.use_tor {
      return Err(UiError::new("not_implemented", "Tor support arrives in a later phase."));
  }
  ```
  This is the exact fail-closed shape D34 requires ("no clearnet fallback") — today it fails closed by
  refusing to connect *at all* rather than by falling back to clearnet. This design replaces that stub with a
  real Tor dial, keeping the fail-closed property.
- **Settings/config surface — three `use_tor` fields, only one wired.** `crates/client-app/src/dto.rs::
  ConnectRequest.use_tor` is the one actually read (by the stub above); it is populated by the connect
  screen's own checkbox (`crates/client-app/ui/src/components/connect-screen.ts`, `name="tor"`, always starts
  unchecked — it does not read settings). `crates/client-app/src/config.rs::ConnectionConfig.use_tor` (the
  persisted `connection.json`, `server_of()`'s struct) is loaded but its `use_tor` field is never read by any
  command. `SettingsConfig.connection: ConnectionSettings { use_tor: bool }` (persisted `settings.json`) is
  round-tripped by `get_settings`/`set_settings` (`commands/settings.rs`) and displayed in
  `settings-screen.ts` as `<input type="checkbox" name="use_tor" disabled />` — a disabled placeholder, per
  the Phase-5 sign-off (`docs/security-review-phase5-mediaapp.md`: "Real Tor transport — the toggle is a
  disabled placeholder"). **This three-way split is a pre-existing gap this design closes** — see §8.
- **Status UI convention.** `crates/client-app/src/state.rs::ConnectionState` (`Idle, Resolving,
  TlsHandshake, ChannelBinding, Connected, Reconnecting, Disconnected, Degraded`) is emitted over
  `EVT_CONNECTION` by `connect_inner`. `crates/client-app/ui/src/components/status-pill.ts` renders any such
  state as **icon + text**, never color-only (WCAG 1.4.1), inside a `role="status" aria-live="polite"`
  element, via a small `ICON: Record<string,string>` lookup.
- **Blob-tiering interaction (D31/D34).** `crates/server/src/http.rs::direct_link` brokers a short-lived
  scoped cold-tier (Dropbox) link, gated first by `AppState.direct_links_enabled` (an operator toggle, `403
  direct_disabled` when off) — `pub direct_links_enabled: … "A client also forces server-proxy under Tor
  (D34) by not calling it."` A repo-wide grep (`crates/client-app/src`) shows **no client-app caller of
  `direct-link` exists yet** — direct client↔Dropbox is not implemented client-side (per MEMORY: Dropbox
  wiring is a separate, possibly-deferred feature). The "Tor forces server-proxy" rule is therefore currently
  **vacuous** (nothing to force off yet) but must be honored the day direct-linking ships — noted as a
  cross-reference, not a new obligation of this design.
- **Rate limiting is already Tor-aware in spec.** `docs/parameters.md` §3: "Tor (D34) collapses source-IP
  signal (shared exits), so per-account limits are primary; per-IP is a secondary, best-effort global cap
  that is not relied upon under Tor." No server change needed — this is already how the server is specified
  to behave; flagged here so an implementer doesn't think Tor needs new server-side rate-limit code.

---

## 1. Goal & threat-model delta

**Goal.** When a user turns Tor on, every connection this client makes to the MaxSecu server routes over the
Tor network, so the server (and any network observer between the client and the Tor entry guard) cannot learn
the client's IP address / network location.

**What Tor adds** (mapped onto the existing `DESIGN.md` threat table, §"Threats & mitigations"):

- Hides the client's **source IP / network location** from the server operator and from network-level
  observers (ISP, Wi-Fi operator, local network) — the server sees a Tor exit-relay IP (or, in onion mode,
  no exit at all), not the user's real address.
- Resists **traffic-origin correlation** — an observer positioned only at the server side, or only at the
  client side, cannot link a connection to "this specific person at this specific network location" the way
  a direct TCP connection trivially allows.
- Adds a layer of protection against **coarse timing/volume correlation by network position** (though Tor is
  not perfect traffic-analysis resistance against a global passive adversary — out of scope for this app;
  `docs/stack.md` already flags large-media-over-Tor as slow, which is itself a timing signal, discussed in §5).

**What Tor does *not* add** — the app is already zero-knowledge on content **without** Tor:

- **Confidentiality of file content** is already handled by the existing E2E envelope encryption
  (`DESIGN.md` §4–§7): the server never has a decrypting key regardless of transport. Tor changes *nothing*
  about who can decrypt what.
- **Channel-binding / auth integrity** is unchanged (§3) — the RFC 5705 exporter and the pinned server cert
  are computed over the *same* TLS 1.3 session whether or not that session's TCP is carried over Tor.
- **The application-level sharing graph** — `docs/stack.md` §1.8 states this precisely: "Tor hides the
  client's IP / network location and coarse timing … It does **not** hide the application-level sharing
  graph or the server-visible `file_type`/sizes — you still authenticate as your account, so the server knows
  *who does what*, just not *from where*." The server still sees the authenticated username on every request
  (auth is unchanged), the files that account touches, and (per D35) the server-visible `file_type` +
  encrypted-value listing metadata.
- **Endpoint compromise.** Tor protects the network path, not the client device or the server. A compromised
  client leaks whatever the user does regardless of transport.

**Precise adversary this defends against:** a **network-position adversary** — an ISP, a local network
operator, a passive or active man-in-the-middle on the path to the server, or the server operator's own logs
— trying to learn *which network location* a given MaxSecu account connects from. It does **not** defend
against: a malicious/coerced server (that's the E2E crypto's job, unchanged), a compromised client, or an
adversary who can correlate traffic globally across both the Tor entry and exit (a stronger adversary class Tor
itself, not this app, is scoped against).

---

## 2. Routing mechanism

Two realistic ways to carry the client↔server TCP connection over Tor:

### (a) System/bundled Tor SOCKS5 proxy
The client dials the server through a local SOCKS5 endpoint (`127.0.0.1:9050` for the Tor Browser Bundle /
system `tor` daemon convention, or a MaxSecu-bundled `tor.exe` the app spawns and manages). A SOCKS5 client
library (e.g. `tokio-socks`) performs the SOCKS5 handshake and `CONNECT` to `host:port`, yielding a
`TcpStream`-like duplex byte stream; that stream replaces the raw TCP socket that
`transport::Transport::connect()` currently opens, and everything above it (TLS handshake, exporter, hyper)
is unchanged.

### (b) `arti-client` embedded in-process
[Arti](https://arti.torproject.org) is the Tor Project's own pure-Rust Tor client implementation, distributed
as the `arti-client` crate. Embedding it means the MaxSecu client process itself builds and holds Tor
circuits — no separate daemon, no local listening SOCKS port, no process to spawn/supervise/update. Its
`TorClient::connect((host, port))` API returns a `DataStream` that (like a SOCKS client's stream) implements
`AsyncRead + AsyncWrite` and can be substituted for the raw `TcpStream` at the exact same seam.

### Recommendation: (b), `arti-client`

This matches the decision already recorded in `docs/stack.md` §1.8 ("Implementation: `arti-client`… no
external `tor` daemon") and `DESIGN.md` D34's table row ("Optional client setting to route all connections
over Tor"), made before this transport code existed. Reaffirming it here, now that the concrete seam is known:

- **No local proxy to trust or spoof.** Option (a) introduces a new local attacker surface: *any* local
  process (malware, another user on a shared machine, a misconfigured VPN client) that can bind
  `127.0.0.1:9050` or answer the configured SOCKS address can intercept "Tor" traffic that never actually
  reaches Tor. Option (b) has no local listening socket at all — the circuit is built inside the same process
  that also holds the (locked/unlocked) identity, so there is one fewer inter-process trust boundary to get
  wrong. (§6 covers the residual: a compromised in-process dependency is a *different*, and arguably worse,
  risk class than a hostile local proxy — discussed there.)
- **Matches the project's supply-chain posture.** `deny.toml` is explicit that the crypto/encoding TCB is
  held to a "tight, audited set," pure-Rust where possible, and the client crate tree is already
  `aws-lc-rs`-only for TLS (no OpenSSL/ring). Requiring users to separately install/trust a C `tor` binary
  (option a's "system Tor" variant) reintroduces exactly the kind of unaudited native dependency the rest of
  this codebase avoids. `arti-client` is pure Rust.
- **No packaging/spawn/version-skew problem.** Bundling `tor.exe` (option a's "bundled" variant) means
  shipping, updating, and code-signing a third-party binary, and handling its process lifecycle (spawn, crash,
  respawn, port conflicts) — real work, and squarely the kind of "ship a vetted binary" ops burden `docs/
  stack.md` explicitly wants to avoid by choosing Arti. `arti-client` is a library dependency: `cargo build`
  produces one self-contained client binary, matching the existing "portable, no-install" client packaging
  goal (`docs/stack.md` §0 table, "Client packaging").
- **Same integration seam either way.** Nothing about this recommendation is fragile to reconsider later —
  §8's implementation sketch is written so that swapping in a `tokio-socks` stream instead of an
  `arti_client::DataStream` is a one-enum-variant change, not a redesign, in case Arti's dependency tree fails
  `cargo deny` review (§7) and a fallback is needed.

### How the wrap works (both options, mechanically)

`tokio_rustls::TlsConnector::connect<IO>(self, domain, stream: IO)` is already generic over any
`IO: AsyncRead + AsyncWrite + Unpin` — it does not require `IO` to be `tokio::net::TcpStream`. Today
`Transport::connect()` hands it a `TcpStream` (`tokio::net::TcpStream::connect(&self.addr)`). Under Tor mode
it hands the identical `connector.connect(self.server_name.clone(), <tor-stream>)` call a `DataStream`
(arti) or a SOCKS-tunneled stream (tokio-socks) instead — **the TLS handshake, the pinned root store, and the
RFC 5705 exporter call are all completely unaware of which one they got.** The TLS 1.3 session still
terminates at the real MaxSecu server on the far end; Tor (or the SOCKS proxy) only ever carries the opaque
TLS byte stream as a TCP transport. This is the crux of §3.

---

## 3. CRITICAL: channel binding + cert pinning survival

This is the part that must be gotten right, and the existing code already makes it structurally hard to get
wrong.

**Why routing the TCP through Tor/SOCKS does not break channel binding.** `Transport::connect()`'s exporter
call — `tls.get_ref().1.export_keying_material(&mut exporter, EXPORTER_LABEL, None)` — operates on the
**rustls `ConnectionCommon`**, i.e., the live TLS 1.3 session state (traffic secrets derived from the ECDHE
key exchange with the real server). That session is negotiated **end-to-end between this client's rustls
`ClientConfig` and the real server's rustls `ServerConfig`** (`crates/server/src/serve.rs::serve_connection`,
same `TlsAcceptor`/`export_channel_binding` on the server side). SOCKS (and Tor's own onion-routing layer) sit
**strictly below** this — they carry raw encrypted TLS bytes as an opaque TCP payload, with no visibility into
or participation in the TLS handshake. So:

- The **RFC 5705 exporter** is derived from secrets only the client and the real server ever compute (per TLS
  1.3's key schedule) — a proxy in the middle, honest or not, cannot compute it, and does not need to be
  trusted not to, because it never sees the plaintext exporter.
- The **pinned cert check** (`pinned_client_config`'s single-entry `RootCertStore`) is likewise evaluated by
  rustls against the leaf certificate the *real server* presents during the TLS handshake. A proxy cannot
  substitute a different cert without rustls's chain verification failing — there is no CA in the root store
  that would validate anything but the one pinned key.

**The one thing to get right:** the SOCKS/Tor hop must be a **plain TCP tunnel**, never a **TLS-terminating
proxy** (an HTTP `CONNECT`-style proxy that MITMs is a different animal — that's an HTTPS *interception*
proxy, not a SOCKS proxy; a corporate TLS-inspection box is the same failure mode). If something upstream of
`TlsConnector::connect()` terminated TLS itself (decrypting and re-encrypting under its own cert) before
handing bytes to rustls, the pinned-cert check would either fail closed (good — a hostile MITM re-encrypting
under an unrelated cert is rejected by the single-entry root store) or, if it fooled the client into trusting
a *different* pinned key, would silently defeat both pinning and channel binding.

**How this design guarantees it structurally, not by convention:**

- **SOCKS5 is inherently transport-layer only.** The SOCKS5 protocol (RFC 1928) has no concept of TLS; a
  conforming SOCKS5 `CONNECT` response is just "here is a raw byte-stream to `host:port`." A library like
  `tokio-socks` implements exactly the handshake+relay and returns the raw stream — there is no code path by
  which it could terminate TLS even if compromised, because it never parses or touches the bytes flowing over
  the tunnel after the SOCKS handshake completes.
- **`arti_client::DataStream` is Tor's anonymized-TCP-equivalent stream**, also below the TLS layer by
  construction — Arti's job ends at "deliver an authenticated, confidential *Tor circuit* to the exit/onion
  destination," which is then handed to our own `TlsConnector::connect()` exactly like a TCP stream would be.
  Arti never sees or needs to see anything about the HTTP/TLS running inside the stream it carries.
- **No new certificate trust is added anywhere in this design.** `pinned_client_config()` is not touched — the
  root store stays exactly the one pinned `server_cert.der`. Any future code path that tried to add a proxy's
  own CA to that store, or skip verification "for the proxy hop," would be the actual danger; this design
  explicitly does neither, and an implementer should treat any diff touching `pinned_client_config`'s root
  store as a red flag during review.
- **Concretely testable** (see §9): a test harness can prove the tunneled TCP is byte-opaque to the relay by
  running a real SOCKS5 stub between client and server and asserting the *same* `tls_channel_binding.rs`-style
  test still passes — the exporter values match and the relay-rejection assertion (a token from connection A
  rejected on connection B) still holds, because none of that logic is aware a proxy exists.

---

## 4. Onion-service option

`DESIGN.md` D34 already names this as "the strongest form (no exit node)" and `docs/stack.md` §1.8 repeats it:
"a server onion service (v3). No exit node, the server's location is also hidden, and the client talks to the
`.onion` directly."

**Two identity models, and how they interact with the existing pinning code:**

- **Clearnet server + Tor as pure transport (what §2/§3 describe).** The server keeps its current DNS
  name/IP and pinned leaf cert; Tor (via a normal exit relay) just carries the TCP to that IP:port. `open_conn`
  needs zero change to its `ServerName::try_from(host)` / pinned-cert logic — the destination is unchanged,
  only the path to it is anonymized. The residual: the **exit relay** sees "someone is opening a TLS
  connection to `<server IP>:<port>`" (destination visible, content opaque under TLS) — it does not see the
  server's *content*, but it does see that this server exists and is being contacted, and the server's own IP
  is not hidden from a sufficiently well-positioned observer near it.
- **Onion service (v3).** A v3 onion address is **self-authenticating**: the 56-character base32 address is
  itself derived from (a commitment to) the service's Ed25519 public key, so reaching `xyz…abc.onion` and
  completing the Tor rendezvous protocol *already* cryptographically proves you're talking to the holder of
  that key — no CA, no separate pinning needed for that guarantee. This removes exit relays from the picture
  entirely (Tor's onion-service rendezvous protocol never routes through an exit node), hiding the **server's**
  network location too, not just the client's.

**Does the existing pinned-TLS-cert scheme still make sense over an onion address?** Two sub-options:

1. **Keep pinned TLS *inside* the onion connection (recommended if onion ships at all).** `docs/stack.md`
   §1.8 already says this: "pinned-TLS (rustls) runs *inside* the tunnel, so server-identity verification is
   unchanged." Concretely: `ServerName::try_from("xyz…abc.onion")` — the `.onion` string is syntactically a
   valid DNS-style name (lowercase alphanumerics, single label, dot-separated), so `rustls`'s `ServerName`
   parser accepts it without any client-side special-casing. The pinned cert's SAN would then need to
   include that onion string (or the pinning check could stay keyed on the existing hostname-independent
   pinned-DER-bytes comparison, since `pinned_client_config` pins by raw cert bytes, not by SAN match against
   a CA — worth double-checking exactly which check does the identity binding when this is implemented).
   This is **defense-in-depth**: even if a bug or a malicious/compromised relay somewhere in Tor's own
   rendezvous machinery misdirected the circuit, the pinned TLS handshake still fails closed against anything
   but the real server's key — the app's existing zero-trust-in-transport posture is preserved rather than
   substituted.
2. **Trust the onion address alone, drop the pinned cert for onion connections.** Simpler (no SAN
   provisioning for `.onion`), and cryptographically sound on its own terms (self-authenticating name), but
   it means the onion-mode code path has a *different* trust root than the clearnet path — two authentication
   mechanisms to maintain and review instead of one, and it forecloses the option of moving the pinned key
   later (§ the pinned cert today is provisioned by the client's own bootstrap flow, not tied to DNS).

**Recommendation:** (1) — keep the pinned TLS handshake as the authentication mechanism in *all* modes
(direct, Tor-clearnet, Tor-onion); let Tor/onion routing be purely a reachability/anonymity layer underneath
it, exactly as designed for the SOCKS/Arti clearnet case in §2/§3. This means onion-service support, if and
when the server operator stands one up, is a **routing-only addition** on top of this design — no new client
auth code path — and is left as an explicit **open question for the user** (§10) on *whether* to build it now
or defer it; the clearnet-over-Tor case (§2/§3) is the one this design fully specifies and recommends
building first.

---

## 5. Failure & fallback UX

**Fail-closed is non-negotiable** (`DESIGN.md` D34: "the client fails closed (no clearnet fallback)… A silent
clearnet fallback would leak IP, so it MUST fail closed"). The existing stub already embodies this shape —
`commands/connection.rs::connect()`'s `if req.use_tor { return Err(not_implemented) }` never falls through to
the direct-TCP path below it. The real implementation preserves that structure: when Tor mode is on, the
**only** two outcomes are "connected via Tor" or a sanitized error — there is no code path that silently
retries over `tokio::net::TcpStream::connect` instead.

**New phases needed** (Tor circuit bootstrap happens *before* the existing `Resolving → TlsHandshake →
ChannelBinding → Connected` sequence, and can take anywhere from a couple of seconds to ~30s+ on a cold
start, per Tor's own bootstrap/consensus-fetch behavior):

- Extend `crates/client-app/src/state.rs::ConnectionState` with a **new** variant, e.g.
  `TorBootstrapping { pct: u8 }` (Arti's `TorClient::bootstrap()` exposes a progress/status stream this can
  be driven from), emitted before `Resolving` only when `use_tor` is set. The existing `Reconnecting`/
  `Degraded` variants are already reserved but currently unused by any emitter (grep confirms `state.rs` is
  the only definer) — `Degraded` is a reasonable fit for "Tor circuit built but noticeably slow," left as an
  implementation-time call rather than specified here.
- Extend `status-pill.ts`'s `ICON` map with an entry for the new kebab-case state (the pattern is
  self-documenting: `{ "tor-bootstrapping": "…" }` alongside the existing `resolving`/`tls-handshake`
  entries) — **no new component needed**, the existing non-color-only, `role="status" aria-live="polite"`
  convention (WCAG 1.4.1) covers it for free.
- On **Tor unreachable / bootstrap timeout / circuit-build failure**, emit `ConnectionState::Disconnected`
  (mirroring the existing `Err(e) => { emit_conn(ConnectionState::Disconnected); Err(e) }` catch-all in
  `connect()`) with a sanitized `UiError` (e.g. `code: "tor_unreachable"`, a human message like "Could not
  reach the Tor network. Check your connection and try again." — no raw Arti error internals leaked, matching
  the existing sanitized-error convention throughout `commands/connection.rs`, e.g. `UiError::new("offline",
  "Could not reach the server.")`). The connect screen's existing busy/status pattern
  (`connect-screen.ts`'s `setBusy`/`status.textContent` machinery) already has a place to surface this text —
  no new UI pattern required, just a new status string and (per WCAG) it already lands in the existing
  `role="status" aria-live="polite"` `#cn-status` element.
- **Bootstrap timeout policy:** pick a bounded timeout (e.g. 60s) after which the attempt fails with the
  sanitized error above rather than hanging indefinitely — matches the existing UX convention where every
  connect step already has an implicit bound (TCP connect timeout, TLS handshake timeout are effectively
  bounded by the OS/hyper defaults today; Arti bootstrap needs an explicit one since cold-start consensus
  fetch has no natural short timeout).

---

## 6. Security trade-offs

**Added trust/attack surface:**

- **`arti-client`'s dependency tree becomes part of the client-app attack surface.** It is a real Tor
  implementation (circuit building, the ntor/ntor3 handshake, guard selection, consensus/directory parsing) —
  meaningfully larger and more complex than `tokio-socks`'s few hundred lines. This is a genuine trade-off
  against option (a): a SOCKS client library is trivially small to audit; Arti is not. The mitigation is that
  Arti *is* the Tor Project's own reference pure-Rust implementation — the alternative (a C `tor` daemon) is
  not smaller, just external to the Rust dependency graph where `cargo deny`/`cargo audit` can't see it at
  all. Bringing it in-tree, in Rust, under the existing dependency-review discipline (deny.toml) is *more*
  visibility, not less, even though the raw line count is larger.
- **No local hostile-SOCKS-proxy risk** with Arti embedded (§2) — this is the concrete win over option (a):
  there's no local listening socket for another process on the machine to squat on or spoof.
- **A compromised/buggy Arti dependency** is a different risk shape than a hostile local proxy: it runs
  in-process, so a memory-safety bug there is a bug in the client-app process itself (though `unsafe_code =
  "forbid"` in `crates/client-app/Cargo.toml`'s `[lints.rust]` only forbids *this crate's own* unsafe code —
  it does not extend into `arti-client`'s dependency tree, which will contain unsafe code somewhere, same as
  `aws-lc-rs` already does today). The mitigating factor is unchanged from §3: even a fully compromised
  transport layer cannot forge the pinned TLS session or decrypt content, because that all happens above it
  and depends on secrets it never has.
- **Exit-node considerations: largely N/A.** For the recommended clearnet-over-Tor mode (§2), the exit relay
  sees only opaque TLS bytes to a fixed, already-public server address — it cannot read anything, only
  observe "this address exists and is being contacted right now" (already true of any clearnet observer
  without Tor). For the onion-service mode (§4), there is no exit relay at all. Neither mode exposes any
  *decryptable* traffic to an exit node — the E2E encryption (unaffected by transport) means an exit node's
  view is strictly worse than a passive clearnet observer's view of the same TLS-protected connection, not
  better.
- **Tor availability/latency is a new, real dependency.** Circuit bootstrap and per-request latency over Tor
  are materially worse than direct — `docs/stack.md` §1.8 already flags large-media transfer as slow under
  Tor; this is inherent to Tor, not something this design can mitigate beyond the fail-fast bootstrap-timeout
  UX in §5.

**Mitigations already covered above, summarized:** pinned-TLS-inside-the-tunnel (§3/§4) bounds the blast
radius of a compromised or malicious transport layer to *denial of service*, never *content or identity
compromise*; embedding Arti removes the local-proxy attack class entirely (§2); fail-closed (§5) prevents the
one truly catastrophic failure mode (silent IP leak).

---

## 7. What stays DEFERRED to ops

This design specifies the **code**: the connector seam, the toggle wiring, the status UX. It explicitly does
**not** include, and defers to a separate ops/security-review track:

- **Dependency-vetting `arti-client` (and its transitive tree) through `cargo deny`/`cargo audit`.** `deny.toml`
  today holds a curated, justified `advisories.ignore` list (RSA Marvin timing sidechannel on an unreached
  transitive dep, GTK3-Linux-only unmaintained crates, `paste` for the pure-Rust AV1 codecs) — each entry has
  a written why-this-is-safe note. Adding `arti-client` means walking its full dependency graph the same way:
  confirming it does not pull in `ring`/OpenSSL for *our* TLS path (Arti's own internal relay-TLS crypto
  choice is a separate question from the `aws-lc-rs`-based `tokio_rustls` this app already uses for the
  app-level TLS session — they do not need to match, since they protect different layers, but the license and
  RUSTSEC status of whatever Arti pulls in needs the same review), checking for `unsafe`/`unmaintained`/
  license flags, and pinning an exact version. This is real, non-trivial work — explicitly out of scope for
  this design doc, which only specifies *where* the dependency plugs in.
- **`tokio-socks` license/tree review** — smaller, but the same discipline applies if option (a) is ever
  adopted as a fallback (§2).
- **Bundling/shipping a real vetted `tor` binary** — not needed under the recommended Arti approach, but
  called out because the task framing considered it: if a future decision reverses course to "bundled system
  Tor" for some reason, packaging/signing/updating that binary is squarely an ops/`packaging/` (`package.sh`/
  `package.ps1`) concern, analogous to the existing deferred ffmpeg-binary and PostgreSQL-bundling steps in
  `docs/security-review-phase6-mediaapp.md` §4 — guarded, non-fabricating packaging steps, not core-crypto
  code.
- **Standing up a real server onion service** — an operator-side deployment decision (needs either Arti's own
  onion-service hosting support or a system `tor` hidden-service configuration fronting the existing app
  server), independent of and unblocked by this client-side design. Left as an open question in §10.
- **Keeping Arti's bundled Tor-directory fallback list current** — Arti ships a set of fallback directory
  authorities to bootstrap from; keeping that current across app updates is a supply-chain/release-cadence
  concern for whoever owns dependency updates, not a one-time design decision.

---

## 8. Implementation sketch

**No crypto/auth change anywhere in this sketch** — everything below is additive plumbing around the existing
`Transport`/`open_conn`/`ConnectRequest` seam; `pinned_client_config`, `EXPORTER_LABEL`, `session::
login_exchange`, and every server-side file are untouched.

1. **Generalize `Transport` to accept either dial strategy.**
   `crates/client-app/src/transport.rs::Transport::connect()` currently returns
   `tokio_rustls::client::TlsStream<tokio::net::TcpStream>`. New: a small enum (e.g. `RawStream`) with
   `Direct(tokio::net::TcpStream)` and `Tor(arti_client::DataStream)` variants, each delegating
   `AsyncRead`/`AsyncWrite` to the inner stream (a thin pin-projected wrapper, no new logic); `Transport::
   connect()`'s return type becomes `TlsStream<RawStream>`. The TLS handshake call site
   (`connector.connect(self.server_name.clone(), tcp)`) is unchanged apart from `tcp`'s new type — this is the
   whole point of rustls's `IO: AsyncRead + AsyncWrite + Unpin` bound already being generic.
2. **`Transport` gains a dial mode.** `Transport::new(tls, server_name, addr)` gains a `dial: DialMode`
   parameter (`Direct` or `Tor`, `#[derive(Clone, Copy)]`, no data needed beyond the variant itself since the
   Tor circuit-builder is looked up from shared state, not carried per-`Transport`). `connect()`'s internal
   match: `Direct` keeps today's `TcpStream::connect(&self.addr)`; `Tor` calls into a shared, lazily-
   bootstrapped Tor client (below) with the same `addr` (`host:port` string already parsed the same way).
3. **New managed Tauri state for the Tor client — mirrors the existing pattern exactly.** `crates/client-app/
   src/main.rs` currently registers `AppDir`, `Session`, `ConnectLock`, `UploadJobs`, `VideoJobs`,
   `VideoPrepareCancel`, `ContentCache` via `.manage(...)`. Add a `TorState(tokio::sync::Mutex<Option<Arc<
   arti_client::TorClient<…>>>>)` (new type in, e.g., a new `crates/client-app/src/tor.rs`), registered the
   same way. **Lazily bootstrap on first Tor-mode connect attempt** — never pay Arti's bootstrap cost when
   Tor is off — with a `get_or_bootstrap()` helper analogous in shape to `commands::connection::open_conn`
   (async, fallible, returns a sanitized `UiError` on bootstrap failure per §5).
4. **Wire `open_conn` and `reauth` to the toggle.** `crates/client-app/src/commands/connection.rs::open_conn`
   gains a `use_tor: bool` parameter (threaded from `ConnectRequest.use_tor` in `connect_inner`, and from the
   persisted config in `reauth` — see point 6 below for which source `reauth` reads, since `reauth` has no
   per-call `ConnectRequest` to read from today). Remove the `if req.use_tor { return Err(not_implemented) }`
   stub in `connect()`; replace with: emit `ConnectionState::TorBootstrapping` (if `use_tor`), resolve/reuse
   the shared `TorClient` from `TorState`, then proceed into the now-Tor-aware `open_conn` exactly as the
   direct path does today (the rest of `connect_inner` — `TlsHandshake`, `ChannelBinding`, the login exchange
   — is **completely unaware** anything changed, which is the point of §3).
5. **`server_of` stays as the address source.** `commands::connection::server_of` already resolves the
   connect address from `ConnectionConfig::load(dir).server`; nothing here changes what address is dialed,
   only how the TCP to it is obtained.
6. **Resolve the three-`use_tor`-fields gap (§0) as part of this work, not left dangling.** Recommended
   resolution: `SettingsConfig.connection.use_tor` (Phase-5, persisted) becomes the **default** the connect
   screen's checkbox initializes from — `connect-screen.ts` currently never calls `get_settings()`; add that
   call on mount and set the checkbox's initial `.checked` from `s.connection.use_tor`, exactly like
   `settings-screen.ts`'s own `writeControls` already does for its mirrored copy of the same field. The
   per-attempt `ConnectRequest.use_tor` remains the authoritative value for *that* connection (already true
   today, unchanged) — the user can still override the default per attempt, matching how every other
   Settings-vs-per-action field in this app already works (e.g. `behavior.confirm_destructive` is a default,
   not a hard rule). `reauth()` (no `ConnectRequest` available — it re-authenticates using only `dir`/
   `server`/`session`) reads the **persisted** `SettingsConfig.connection.use_tor` directly, since it has no
   per-attempt input to consult — this makes re-auth's Tor-ness consistent with the user's saved preference
   rather than silently direct. `ConnectionConfig.use_tor` (the currently-dead third field in
   `connection.json`) should be **removed** as redundant once this lands — it duplicates
   `SettingsConfig.connection.use_tor` and is not read anywhere today; flagged here rather than fixed, since
   it's a one-line cleanup better done in the implementation PR than speculated about here.
7. **Enable the settings-screen checkbox.** `settings-screen.ts`'s `<input type="checkbox" name="use_tor"
   disabled />` (line with `(arrives in a later phase)`) loses `disabled` and the caption; `onPrefChange`
   already has every other checkbox's wiring pattern to copy (`this.input("use_tor").checked` into the
   `patch.connection` object — currently `onPrefChange`'s `patch` object does not even include a `connection`
   key; add one).
8. **New dependency, flagged for `deny.toml` review (§7):** `arti-client` (pin exact version at
   implementation time) in `crates/client-app/Cargo.toml`, likely alongside `tor-rtcompat`'s tokio backend
   feature (Arti needs an async-runtime adapter; the app already runs on `tokio`). Must **not** pull in
   `ring`/OpenSSL for the app's own TLS path — verify via `cargo tree` the same way the RSA/`sqlx-postgres`
   exclusion is documented in `deny.toml` today. If Arti's tree fails review, `tokio-socks` (§2 option a) is
   the documented one-enum-variant fallback, not a redesign.
9. **State/UI additions**, per §5: `ConnectionState::TorBootstrapping { pct: u8 }` in `state.rs` +test update
   to its `serde` kebab-case guard test; a new `ICON` entry in `status-pill.ts`; a sanitized `tor_unreachable`
   `UiError` code.

---

## 9. Testing plan

Real Tor bootstrap is slow and network-dependent — unsuitable for CI or fast local iteration. The existing
test suite already has the right shape to test the *transport substitution* without needing real Tor:

- **Prove the seam is transparent with a local SOCKS5 stub, mirroring the existing e2e pattern.**
  `crates/server/tests/tls_channel_binding.rs` and `crates/client-app/tests/connect_login_e2e.rs` already
  spin up a real `MemoryStore`-backed `maxsecu_server::serve` over a loopback `TcpListener` with a
  `rcgen`-generated self-signed cert (`test_pki()`), and drive a **real** client `Transport`/`pinned_client_
  config`/RFC 5705 exporter against it. Add a **new e2e test** (e.g. `crates/client-app/tests/
  tor_transport_socks_stub_e2e.rs`) that inserts a minimal in-repo SOCKS5 relay (a small `tokio` `TcpListener`
  that speaks just enough of RFC 1928 to accept a `CONNECT` and then byte-copy in both directions to the real
  loopback server — a few dozen lines, no external crate needed for the *test-side* stub even before
  `tokio-socks` is chosen for the *client-side* implementation) between the client and the same test server.
  Assert:
  - The connect + login flow succeeds end-to-end exactly as `connect_login_e2e.rs` already asserts (proving
    TLS + the RFC 5705 exporter both work identically through the relay).
  - The exporter/channel-binding value obtained through the SOCKS stub is used correctly by the login proof
    (reuse `tls_channel_binding.rs`'s cross-connection relay-rejection assertion — a token minted on one
    connection is rejected on a different one — through the tunneled path too, to prove channel binding is
    still *meaningfully* per-connection and not somehow flattened by the relay).
  - A **negative test**: point the client's dial mode at a raw byte-mangling proxy stub (one that doesn't
    speak SOCKS5, or that tries to inject its own bytes) and assert the connection fails closed (TLS
    handshake or cert-pin failure), never succeeds with a wrong exporter/cert — this is the direct test of
    §3's "one thing to get right."
- **Fail-closed / no-fallback test.** Point `use_tor: true` at an address the SOCKS/Tor dial cannot reach
  (e.g. a closed port standing in for "Tor unreachable") and assert the client returns the sanitized
  `tor_unreachable`-style error and that **no** TCP connection was ever attempted directly to the real test
  server (assertable by pointing the "direct" address somewhere that would succeed if accidentally dialed,
  and asserting it wasn't).
- **Once `arti-client` is actually integrated**, a *separate*, explicitly-marked-slow/ignored-by-default test
  (`#[ignore]`, run manually or in a nightly job) can attempt a real bootstrap against the live Tor network to
  a `MemoryStore` test server exposed via a temporary onion service or a reachable clearnet test port, purely
  as a smoke check that Arti's own bootstrap still works with the pinned versions — not part of the fast
  suite, and not a gate for this design's core claim (which the SOCKS-stub e2e above already proves without
  needing real Tor).
- **Unit-level:** the `RawStream` enum's `AsyncRead`/`AsyncWrite` delegation is a thin pass-through — a small
  unit test with an in-memory duplex pipe (`tokio::io::duplex`) standing in for each variant is enough to
  catch a pin-projection mistake without needing any network at all.

---

## 10. Open questions / deferred (need the user)

- **Bundled/system `tor` (option a) vs. embedded `arti-client` (option b, recommended here).** This design
  recommends (b), consistent with the pre-existing `docs/stack.md` §1.8 decision — confirm that stands, or
  flag if the `deny.toml` review (§7/§9) later surfaces a blocker in Arti's dependency tree that would justify
  falling back to (a) as a fallback rather than the primary path. This is ultimately a judgment call on
  whether the arti-client dependency tree's size/maturity is an acceptable trade for this project's threat
  model, given it is a much larger addition than a SOCKS client — worth a deliberate go/no-go once §7's
  `cargo deny`/`cargo audit` pass is actually run.
- **Onion service: build now or defer?** §4 leaves this open. Standing up a real `.onion` for the MaxSecu
  server is an operator/ops decision independent of the client work in §8, and doubles the modes to test
  (§9). Recommend: ship clearnet-over-Tor (§2/§3) first, revisit onion as a follow-on once a server operator
  wants it.
- **Exact Arti version + feature set to pin**, and whether Arti's own onion-service *client* support (needed
  if the onion path is later built) should be pulled in now (bigger dependency surface) or added later
  (smaller now, a second `deny.toml` pass later).
- **`ConnectionConfig.use_tor` removal** (§8 point 6) — confirm the recommended consolidation onto
  `SettingsConfig.connection.use_tor` + per-attempt `ConnectRequest.use_tor` is the desired resolution of the
  three-field gap, rather than some other reconciliation.
- **Tor bootstrap timeout value** (§5) — this design suggests ~60s as a starting point; needs a real-world
  measurement once Arti is actually integrated to tune.
