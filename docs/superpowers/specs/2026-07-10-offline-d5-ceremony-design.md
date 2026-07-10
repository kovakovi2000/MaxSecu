# Offline-D5 directory delegation, integrated into install (workstream F)

- **Date:** 2026-07-10
- **Status:** Approved design; ready for implementation.
- **Scope:** Replace the SECURITY-DEGRADED dev-D5 directory key (whose private
  half lives on the internet-facing server) with an admin-PC-held D5 root that
  delegates a short-lived operational key to the server — folded into the
  existing `install-server.sh` + `install-client.ps1` flow. This is the
  previously-deferred "workstream F".

## 1. Problem / current state

The `maxsecu-portable-server` `Profile::Prod` (Postgres persistence) signs
identity enrollments with a **D5 directory key whose private half is generated
and stored on the server** (`portable-server/src/bootstrap.rs`, a 32-byte seed at
`<data_dir>/config/d5_secret.bin`). Clients pin its public half
(`directory_pub.der`). A server compromise therefore lets an attacker **forge
identity enrollments** that every client trusts. The startup banner
(`run.rs:196`) advertises this honestly:
`persistent-DEV / Postgres (SECURITY-DEGRADED dev cert+D5)` +
`pinned D5 (DEV ONLY — replace with the offline ceremony key in production)`.
There is no code path to supply a production D5; that is this spec.

## 2. Decisions (locked)

1. **D5 root lives on the admin's PC**, generated during `install-client.ps1`,
   sealed under the admin's login passphrase; never on the server.
2. **Server holds only a short-lived operational key**; D5 signs a delegation
   cert binding it, with a validity window.
3. **Auto-renew on admin login** (client re-delegates when the window is within
   the renew threshold); manual `renew-delegation` fallback.
4. **Default for real (Prod/Postgres) installs.** `Profile::Dev` (ephemeral
   MemoryStore) keeps the self-generated dev-D5 for tests/demos/E2E.
5. **D5 durability:** an encrypted copy is written into the same offline backup
   as `recovery_key.blob`, restorable with the recovery passphrase → same
   directory root, no client re-pin.
6. **Op-key window = 90 days; auto-renew when ≤ 21 days remain.**
7. **Breaking change** — no back-compat with dev-D5 enrollments (fresh install).

## 3. Trust chain

The pin is still the **D5 public key**; the connection-code/fingerprint model is
unchanged in shape. One hop is inserted:

```
pinned D5 pub  --verifies-->  delegation cert  --yields-->  operational_pub
operational_pub --verifies-->  enrollment binding
require: now ∈ [valid_from, valid_until]   (else fail closed)
```

- **Today:** enrollment binding signed directly by D5 (private key on server).
- **New:** enrollment binding signed by the server's **operational key**; the
  **delegation cert** (signed by D5, held offline) authorizes that op-key.

A client that cannot fetch/verify a currently-valid delegation **fails closed**
(refuses to trust enrollments), never falls open.

> **"enrollment binding" = the D5-signed directory binding** — the canonical
> `dirbinding` bytes + signature served at `GET /v1/directory/{username}` /
> `by-id/...` (`server/src/store.rs:70`, api.md §6.1). D5 signs these today; the
> operational key signs them after this change. The delegation hop must be
> applied wherever the client verifies a `directory_pub` (D5) signature — i.e.
> ALL directory-authority signatures, not just first-enrollment. (The
> append-only control-log head is a hash chain and per-file `genesis_sig` is an
> owner signature — neither is D5-signed, so both are unaffected.)

## 4. Delegation cert format (`maxsecu-crypto`)

New domain label: **`maxsecu/directory-delegation/v1`** (used with the existing
`sign_canonical`/`verify_canonical`). Canonical signed bytes (fixed layout, LE):

```
version:      u8   = 1
operational_pub: [u8; 32]   (Ed25519 public key the server signs enrollments with)
valid_from:   u64  (unix seconds)
valid_until:  u64  (unix seconds)
```

On-disk / wire serialization (raw, matching the repo's `*.der`/raw-bytes
convention): `version || operational_pub || valid_from || valid_until ||
signature[64]` (≈ 137 bytes), stored server-side as
`<data_dir>/config/d5_delegation.bin` and served to clients. The **issuer is
implicit**: the signature verifies against the pinned `directory_pub` (D5). No
issuer field is stored to avoid a second source of truth.

Provide in `maxsecu-crypto`: a `DirectoryDelegation` struct with
`sign(d5_secret, operational_pub, valid_from, valid_until) -> bytes`,
`verify(d5_pub, bytes, now) -> Result<operational_pub>` (checks signature +
window), and `parse`/`serialize`. Unit-tested for round-trip, expiry (before
`valid_from`, after `valid_until`), and tamper (flipped byte → verify fails).

## 5. Server side (`server` + `portable-server`)

- **Operational keypair:** generated on first Prod run, secret seed persisted at
  `<data_dir>/config/operational_secret.bin` (this key MAY live on the server —
  it is the delegated key, not the root). Public half derivable.
- **Directory pub:** in Prod, `directory_pub` is **received from the admin**
  (D5 public), not server-generated. Persisted at
  `<data_dir>/config/directory_pub.der` and served in the pins bundle.
- **Delegation storage/serving:** persist `d5_delegation.bin`; serve it in the
  pins/bootstrap bundle next to `server_cert.der` + `directory_pub.der`.
- **Enrollment signing:** sign bindings with the **operational key** (replaces
  the current dev-D5 signing in the Prod path).
- **States:**
  - **Awaiting delegation** (no valid `directory_pub`+delegation yet):
    enrollment is **closed** (fail closed); the server still serves existing
    content and its `operational_pub` + bootstrap endpoints.
  - **Delegated:** normal operation until `valid_until`; after expiry with no
    renewal, enrollment closes again (existing users unaffected).
- **Bootstrap endpoints (initial ceremony, one-time-token gated):**
  - `GET /bootstrap/operational-key` → returns `operational_pub` (public; the
    admin needs it to sign the delegation).
  - `POST /bootstrap/delegation` (token-gated) → body `{ directory_pub,
    delegation_cert }`; the server verifies the delegation verifies the given
    `directory_pub` over its own `operational_pub` and a sane window, then pins
    `directory_pub`, installs the delegation, **opens enrollment**, and **burns
    the one-time token** (TOFU, mirrors the existing "recovery registration open
    until first use" posture). The one-time token is printed by
    `install-server.sh` and shared operator-to-operator with `install-client`.
- **Renewal endpoint (post-bootstrap, admin-authenticated):**
  - `POST /admin/delegation` (admin auth) → accepts a fresh delegation cert for
    the current `operational_pub`; replaces the stored one. Used by auto-renew
    and the manual `renew-delegation` command. Op-key normally stays stable;
    supplying a delegation for a NEW op-key also rotates it (e.g. suspected
    server compromise).
- **Banner (`run.rs`):**
  - Awaiting: `directory: AWAITING DELEGATION (enrollment closed)`.
  - Delegated: `directory: delegated (valid until <date>)`.
  - Relabel `dev cert` → `pinned self-signed cert` (self-signed is the intended
    pinned-trust design; only the D5 degradation is being removed).
  - Remove the `SECURITY-DEGRADED dev+D5` / `DEV ONLY` lines in the Prod path.
- **Profile split:** `Profile::Dev` (MemoryStore) keeps the self-generated
  dev-D5 (no ceremony) so unit tests / demos / the E2E harness's server need no
  admin PC. `Profile::Prod` uses the delegation model.

## 6. Connection-code / fingerprint inversion (important)

Because `directory_pub` (D5) now originates on the **admin PC**, the
`pin_fingerprint(server_cert, directory_pub)` can only be computed once both are
known — i.e. **on the admin PC**, not by `install-server.sh`. Therefore:

- `install-server.sh` prints the **server-cert fingerprint** + **address** +
  the **one-time delegation token** (NOT the final connection code).
- During `install-client.ps1`, `maxsecu-setup` fetches `server_cert` (verified
  against that cert fingerprint / TOFU), generates D5, uploads the delegation,
  and then **computes and prints the user-facing connection code**
  `addr:port#fingerprint(server_cert, D5_pub)`.

This makes the **admin the authority that mints the connection code**, which is
consistent with the admin being the directory root.

## 7. Client side (`maxsecu-setup` + `client-app`)

- **Ceremony (in `maxsecu-setup`, unattended-capable):** generate D5; fetch the
  server `operational_pub`; sign the delegation (window = now .. now+90d); upload
  via `POST /bootstrap/delegation` with the one-time token; seal D5 under the
  admin login passphrase at rest; write an encrypted D5 copy into the recovery
  backup alongside `recovery_key.blob`. Then continue the existing setup
  (recovery account + first registration key). Must run non-interactively when
  `install-client.ps1 -RecoveryPassphrase` is used (for the E2E harness).
- **Verification chain:** wherever the client currently verifies an enrollment
  binding against `directory_pub`, insert the delegation hop — fetch/cache the
  server's delegation cert, verify it against the pinned D5, extract
  `operational_pub`, verify the binding against that, and enforce the window.
  Fail closed on any gap.
- **Auto-renew on login:** immediately after the admin unlocks (D5 available),
  if the current delegation's `valid_until` is ≤ 21 days away, sign a fresh
  90-day delegation for the server's current `operational_pub` and push it via
  the admin-authenticated `POST /admin/delegation`. Best-effort + logged; a
  failure never blocks login. Non-admin users skip this (no D5).
- **Manual fallback:** a `renew-delegation` command (client-app admin action or
  `maxsecu-setup` subcommand) does the same on demand.
- **Restore:** a `maxsecu-setup` path to restore D5 from the recovery backup
  (recovery passphrase) onto a new admin PC — same directory root, no re-pin.

## 8. Install-script integration

- **`install-server.sh`:** on a Prod install, start the server (it self-generates
  the op-key, enters awaiting-delegation), print the cert fingerprint + address +
  one-time delegation token, and instruct the operator to pass the token to
  `install-client`. No `--public` cert regen semantics change.
- **`install-client.ps1`:** accept the delegation token (param or prompt), run
  the ceremony inside `maxsecu-setup`, and print the final connection code +
  handout instructions. Unattended path threads the token like
  `-RecoveryPassphrase`.
- The `dist` client ZIP built by `build-user-zip.ps1` is unaffected (it ships
  `directory_pub` + `server_cert` pins as today; those now carry the real D5).

## 9. Security analysis

- **Improved:** the internet-facing server no longer holds the directory root.
  A full server compromise lets an attacker forge enrollments only with the
  operational key and only until `valid_until` (≤ 90 days), and they cannot
  renew (renewal needs D5 on the admin PC). Rotating the op-key via a fresh
  delegation cuts them off immediately.
- **Residual:** the admin PC is now the root — if it is compromised while the
  admin passphrase is entered, D5 is exposed. This is a deliberately smaller,
  operator-controlled surface than an always-on public server, and is the
  accepted trust boundary (the admin PC already holds the admin login and mints
  recovery). Not a fully air-gapped ceremony (that was the rejected higher-
  friction option).
- **Fail-closed everywhere:** missing/expired/invalid delegation ⇒ enrollment
  refused (server) and enrollment-trust refused (client). Never fail-open.
- **Token:** the bootstrap delegation token is single-use and TOFU, matching the
  existing recovery-registration bootstrap posture.

## 10. Testing

- **crypto:** delegation round-trip; window enforcement (pre/post); tamper.
- **server:** awaiting→delegated transition; enrollment closed while awaiting;
  sign-with-op-key; expired-delegation ⇒ closed; one-time token single-use;
  `/admin/delegation` requires admin auth; renewal replaces the stored cert.
- **client:** D5 seal/unseal under passphrase; recovery-backup write + restore;
  verify-chain (valid, expired, wrong-signer, tampered) fail-closed; auto-renew
  fires at threshold and no-ops otherwise.
- **E2E (`test-full-install.ps1`):** the real ceremony runs unattended
  (install-server prints token → install-client consumes it → delegation
  installed → enrollment opens → live-smoke enroll/upload/view passes), plus a
  reset+reinstall pass.

## 11. Migration

Breaking. Existing dev-D5 deployments must reinstall from 0 (which the operator
is doing). No conversion of dev-D5 enrollments. The `Profile::Dev` dev-D5 path is
retained unchanged.

## 12. Out of scope / deferred

- Fully air-gapped (separate-machine) ceremony.
- K-of-N / multi-admin D5 custody (single admin PC root for now).
- HSM / smartcard D5 storage.
- Automatic op-key rotation policy beyond "renew the window; rotate op-key on
  demand".
- External WORM/KT-witness/SIEM hardening (separate ops track).
