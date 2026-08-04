# MaxSecu — Client ↔ Server API Contract (v1)

**Status:** Spec (implement across Phases 1–5; auth/session is the Phase-1 gate).
**Scope:** the RPC surface between the native client and the secret-free app server (`DESIGN.md` §4.1). Covers auth/session, enrollment, directory, the revocation control-log, file record CRUD, chunked blob I/O, sharing, and the error/rate-limit model. **Out of scope:** the external append-only sink's own interface (`docs/sink-interface.md`), the on-disk SQL shape (`docs/schema.sql`), and the canonical bytes of signed records (`docs/encoding-spec.md`).
**Companion to:** `DESIGN.md`, `docs/parameters.md` (all numeric values live there — this doc references, never re-pins), `docs/encoding-spec.md`.

> **The server is untrusted for confidentiality and integrity (`DESIGN.md` §4.2/§10).** Every endpoint here enforces only **coarse** authorization; the client re-verifies every cryptographic fact (signatures, grants, manifests, tombstone completeness) regardless of what the server returns. Nothing in this contract is a security boundary on its own — it is the transport for records whose authenticity is established client-side.

---

## 1. Transport & framing

### 1.1 Transport
- **TLS 1.3 only**, client **pins the server identity** (`DESIGN.md` §9.2, rustls). Optionally tunneled over **Tor** (D34); in Tor mode the client makes **no clearnet connection** and **forces server-proxy** (§9 here).
- **HTTP/2**, and a **session runs over a single connection** (see §1.3). Multiple in-flight requests (e.g. parallel chunk transfers) multiplex as HTTP/2 streams on that one connection.
- Base path **`/v1`**. Breaking changes bump the path segment; additive fields are backward-compatible.

### 1.2 Two body formats
- **Control plane → JSON** (`application/json`). Small, language-neutral, debuggable.
- **Bulk data plane → raw bytes** (`application/octet-stream`). Stream ciphertext chunks (≈1 MiB each, `parameters.md` §1.2) are transferred raw, never base64.

### 1.3 Opaque signed records (**byte-exactness is mandatory**)
Every signed or hashed record (`dirbinding`, `manifest`, `grant`, `genesis`, `revocation`, `reinstatement`, `key_compromise`, …) is produced and signed **client-side** over its exact `canonical(...)` bytes (`encoding-spec.md`). In transit such a record is a **base64 (standard, padded) string** in a field suffixed **`_b64`**.

- The server **stores and returns these bytes verbatim** and **MUST NOT** decode, re-encode, reorder, or "normalize" them. A downloader verifies the signature over the base64-**decoded** bytes; any server reserialization would break verification (and is detected as a forgery).
- The server reads **only** the explicit control fields next to the blob (e.g. `file_id`, `version`, `file_type`, sizes) — never the record's interior — for routing/indexing. Those control fields are advisory; the authenticated copy is inside the signed bytes the client checks.

### 1.4 Identifiers
- `user_id`, `recipient_id` — **16-byte, server-assigned** at enrollment (§5). In paths/JSON as **lowercase hex** (32 chars).
- `file_id` — **16-byte, client-generated random** (`DESIGN.md` §12.2 step 2: the owner signs `genesis`/`manifest` over it before contacting the server, so it cannot be server-assigned). The server **enforces uniqueness** on create and rejects a collision (`409`, client regenerates — negligible at 2⁻¹²⁸). Hex in paths.
- `version` — u64, decimal in paths/JSON.

### 1.5 Channel binding (token is not a bare bearer)
The session is bound to the **TLS exporter** (RFC 5705) of the connection it was minted on (`DESIGN.md` §9.2). Because an exporter is **per-connection**, v1 **pins a session to its connection** (§2.3): the server re-derives the exporter from the live connection on every request and accepts the token only if it matches what it recorded at mint. A token replayed on any other connection (or lifted from the keystore onto another device) presents a different exporter and is rejected — **fail closed**.

---

## 2. Authentication & session lifecycle (`DESIGN.md` §9.2 — Phase 1)

### 2.1 `POST /v1/session/challenge`
Request a login challenge. **No user-existence oracle:** a well-formed challenge is returned for unknown usernames too (`DESIGN.md` §9.3).

```jsonc
// req
{ "username": "alice" }
// res 200
{ "nonce_b64": "…32 bytes…", "server_id": "maxsecu-prod-1", "expires_in_s": 60 }
```
- `nonce` is fresh, single-use, server-tracked, **60 s** TTL (`parameters.md` §2). Rate-limited per claimed username + source (§4).
- The client computes the proof over `auth_proof_context = {server_id, tls_exporter, nonce, timestamp}` (`encoding-spec.md` §4) using the **same connection's** exporter.
- `username` is bounded at **4096 raw request bytes** (`4 × MAX_TEXT`); longer ⇒ **`400`, empty body** (the §3 malformed-request shape), returned *before* any nonce is written. The bound is deliberately above every registerable name: `POST /v1/users` caps the **NFC** form at `MAX_TEXT` = 1024 and stores the raw bytes, which canonical composition can shrink by at most 3×, so no username that could exist exceeds 3072 bytes. Not an oracle — the answer depends only on length. It is also the *only* ceiling on this field: `auth_nonces_open_idx` is a **hash** index precisely so the storage layer imposes no second, lower limit that would turn an accepted name into a `500` (`migrations/0003_auth_nonce_lookup.sql`).

### 2.2 `POST /v1/session/proof`
```jsonc
// req
{ "username": "alice", "timestamp": 1719500000000, "proof_b64": "…Ed25519 sig…" }
// res 200
{ "session_token": "opaque", "expires_in_s": 3600 }
// res 401 — EMPTY BODY (sanitized: identical whether the username is unknown, the
//           proof is bad, the nonce is stale, or the channel does not match)
```
*(Corrected 2026-08-02: this example previously showed a body `{"error":{"code":"unauthorized"}}`. No such body is ever sent — `crates/server/src/http.rs:867` returns a bare `StatusCode::UNAUTHORIZED`, consistent with §3.)*
- Server verifies `proof` against the `sig_pub` on record (§9.2), checks nonce freshness/single-use, and checks the proof's `tls_exporter` equals the live connection's. Issues a token **bound to this connection's exporter**, TTL **60 min** (`parameters.md` §2), revocable.
- A single 401 shape for every failure cause — no oracle (§3).
- `username` carries the **same 4096-raw-byte bound as §2.1**, same constant, same **`400`, empty body**, checked before anything else. This route is equally unauthenticated and every attempt — including a failing one — inserts the claimed name as a key into the in-memory backoff limiter, which is never evicted. Same lockout argument: a name over the bound has no `sig_pub` on record, so its only possible outcome was the uniform `401` anyway.

### 2.3 Session pinning & reconnect
- The token is presented as **`Authorization: MaxSecu-Session <token>`** on every subsequent request, over the **same connection**.
- If the connection drops, the client **re-authenticates** (§2.1–2.2) to mint a fresh token on the new connection. Challenge-response is one round trip and the `sig_priv` is already unlocked in RAM, so reconnect cost is negligible. *(Alternative for a future multi-connection need: RFC 8471 token-binding keys; not in v1 — single-connection binding is simpler and strictly stronger.)*

### 2.4 `POST /v1/session/logout`
Revokes the presented token server-side (best-effort; tokens also expire). `204`. Callable by any authenticated principal, **including the recovery principal** — a recovery session must be able to end itself.

### 2.5 Self-login needs no directory verification
The server checks the user against the `sig_pub` it stored; if it swapped that key, the user's own genuine proof simply fails and login breaks — a detectable denial, not a silent compromise (`DESIGN.md` §9.2). An account whose binding is **not yet ceremony-signed** can still log in and manage its own files, but is not yet a valid recipient for others (§5).

---

## 3. Error model (`DESIGN.md` §16.2 — fail closed, sanitized)

Errors are conveyed by the **HTTP status code with an empty body** — the most-sanitized shape (impossible to leak), verified by `crates/server/tests/sanitized_errors.rs` (Phase 6, P6.7). The `code` column below names the **semantics** of each status, not a JSON field. **No** stack traces, DB text, paths, internal detail, or existence signals ever reach a client. Any exception on an auth/authz path ⇒ deny.

**The complete list of structured signals** (everything else stays bodiless). Each is a **constant** string that encodes no caller-specific fact, so none of them is an oracle:

| signal | route | added |
|---|---|---|
| `Retry-After` header on `429` | any rate-limited route (§4) | original |
| `403 {"code":"direct_disabled"}` | §9.4 direct-link opt-out | original |
| `403 {"code":"recovery_protected"}` | §10.2, targeting the recovery recipient | 2026-08-02 |
| `400 {"code":"bad_sort"}` · `bad_owner` · `bad_cursor` · `cursor_query_mismatch` | §8.6, on the four NEW query parameters only | 2026-08-02 |

The §8.6 codes are worth one sentence of justification: they attach to parameters **no shipped client sends**, so they cannot change any existing caller's outcome, and each one names a fact the caller already knows (*"the value you sent is not one I accept"*). Ordinary `403`s on §10.2 remain **bodiless**, so the recovery refusal is separable in logs from an ordinary ownership refusal without either of them leaking anything about the file.

| HTTP | semantics | Used for |
|---|---|---|
| 400 | `invalid_request` | malformed envelope, bad base64, bound-check failure (e.g. `chunk_size` out of range) |
| 401 | `unauthorized` | no/expired/channel-mismatched token; failed login (single shape, no oracle) |
| 403 | `forbidden` | authenticated but lacks the coarse capability (e.g. non-admin posting a tombstone) |
| 404 | `not_found` | absent **or** caller has no row for it — **same code**, so a `file_id` a caller can't access is indistinguishable from a missing one |
| 409 | `conflict` | `file_id` collision; stale/duplicate `version` commit (§12) |
| 413 | `payload_too_large` | chunk or record exceeds the bound-checked limit |
| 429 | `rate_limited` | per-account/source throttle (§4); carries `retry_after_s` |
| 5xx | `server_error` | generic; details only to server logs/sink |

---

## 4. Rate limiting & anti-automation (`DESIGN.md` §9.3, `parameters.md` §3 — decided: per-account, no hard lock)
- **Per-account is primary** (Tor collapses source-IP signal); per-source is a secondary advisory cap. **No hard account lockout** — exponential backoff + per-account challenge-issuance cap, **alert on spikes** instead of freezing accounts (so a third party cannot freeze a known username). `429` + `retry_after_s` on throttle.
- **Registration is voucher-gated, not public** (§5.1) — this is where "no public signup" (`parameters.md` §3) is enforced, since a brand-new client has no account to rate-limit against.

---

## 5. Enrollment & account (`DESIGN.md` §9.1, §12.1 — Phase 1/2)

### 5.1 `POST /v1/users` (voucher-gated, pre-auth)
Claims a username and publishes **public** key material. Creates an **unsigned** binding (`status=active`, `signed_at=null`) — usable for self-login, **not** yet a valid recipient until the in-person ceremony signs it (§7.2/§12.1).

```jsonc
// req
{ "username": "alice", "enc_pub_b64": "…32B X25519…", "sig_pub_b64": "…32B Ed25519…",
  "enrollment_voucher": "one-time code issued in person" }
// res 201
{ "user_id": "…hex16…" }
```
- The **voucher** is a one-time code handed out at in-person delivery; it operationalizes the "no public signup" policy and stops anonymous squatting/spam on this unauthenticated write. The cryptographic gate remains the **in-person fingerprint+username confirmation** at the offline ceremony (§12.1/D9/R32) — the voucher is only anti-spam, not a trust root.
- The server stores **no** salt, KDF params, or encrypted private key (D4) — those never leave the device.

### 5.2 `GET /v1/users/{user_id}/status`
Self-service enrollment status so the client knows when its binding is live. `{ "signed": false, "enrolled_at": …, "signed_at": null }`.

### 5.3 Offline-D5 directory delegation (ceremony + renewal, `docs/superpowers/specs/2026-07-10-offline-d5-ceremony-design.md`)

In the **Prod** (Postgres) profile the internet-facing server no longer holds the directory root. The admin-held **D5 root** (offline) signs a short-lived **delegation cert** authorizing the server's **operational key** to sign enrollment bindings within a validity window. `POST /v1/users` enrollment is **CLOSED (403)** unless a currently-valid delegation is installed (re-checked at request time against the live clock, so it auto-re-closes after `valid_until`). The **Dev** (MemoryStore) profile keeps the self-generated dev-D5 with a self-issued delegation and is always open (no ceremony).

**Delegation cert wire format** (`maxsecu-crypto`, spec §4; **113 bytes**, fixed little-endian):
```text
version:         u8        = 1
operational_pub: [u8; 32]  (Ed25519 key the server signs bindings with)
valid_from:      u64 LE    (unix seconds, inclusive)
valid_until:     u64 LE    (unix seconds, inclusive)
signature:       [u8; 64]  (Ed25519 by D5 over the 49-byte body under
                            the `maxsecu/directory-delegation/v1` label)
```
The **issuer is implicit** — the signature verifies against the pinned `directory_pub` (D5); there is no issuer field. Verification checks the signature FIRST, then the window inclusively. The server additionally enforces a **sane window** on install: `valid_until > now`, window length ≤ **366 days**, and `valid_from ≤ now + 24h` skew.

#### 5.3.1 `GET /v1/bootstrap/operational-key` (public)
Returns the server's operational public key so the admin PC can sign a delegation over it. Works while awaiting. `404` if the delegation model is not active (legacy path).
```jsonc
// res 200
{ "operational_pub_b64": "…32B Ed25519…" }
```

#### 5.3.2 `POST /v1/bootstrap/delegation` (one-time-token gated, TOFU)
The initial ceremony install. The server verifies the posted cert against the **posted** `directory_pub` (TOFU-pinned here), requires the extracted `operational_pub` to equal its own and a sane window, then **pins** the D5, installs the delegation, **opens enrollment**, and **burns the one-time token** (single-use). Any verification failure leaves the server **awaiting** (token NOT burned).
```jsonc
// req  (token printed by install-server.sh)
{ "token": "…hex…", "directory_pub_b64": "…32B D5 pub…", "delegation_cert_b64": "…113B cert…" }
// res 201 → { "status": "delegated", "valid_until": 1712345678 }
// 403 bad/absent token · 409 already delegated (token burned) · 400 malformed/invalid cert · 404 model inactive
```

#### 5.3.3 `GET /v1/bootstrap/delegation` (public)
Serves the currently-installed `{directory_pub, delegation_cert}` so a client can perform its verify-hop (pinned D5 → delegation → operational_pub → binding). `404` while awaiting.
```jsonc
// res 200
{ "directory_pub_b64": "…32B…", "delegation_cert_b64": "…113B…" }
```

#### 5.3.4 `POST /v1/admin/delegation` (AdminSession-gated — renewal)
Admin-authenticated renewal (auto-renew on login / manual `renew-delegation`). Verifies a fresh cert against the **already-pinned** D5, requires the extracted `operational_pub` to equal the current one (op-key rotation is out of scope → `400`), then **replaces** the stored delegation. Does **not** change the pinned D5. `AdminSession` supplies `401`/`403` for auth failures.
```jsonc
// req  (Authorization: MaxSecu-Session <hex>)
{ "delegation_cert_b64": "…113B cert…" }
// res 200 → { "status": "renewed", "valid_until": 1720000000 }
// 409 while awaiting (nothing to renew) · 400 invalid cert / op-key rotation · 404 model inactive
```

> **Enrollment-binding signer (invariant 2):** in Prod, enrollment bindings (`GET /v1/directory/{username}`) are signed by the **operational key**, so the `AdminSession` gate and the client verify bindings against `operational_pub` (extracted from the delegation), not directly against the pinned D5. In Dev the dev-D5 is both signer and root, so the two coincide byte-for-byte.

---

## 6. Directory (`DESIGN.md` §7 — Phase 2)

### 6.1 `GET /v1/directory/{username}`  ·  `GET /v1/directory/by-id/{user_id}`
Returns the **opaque** identity binding + its offline D5 signature; the client verifies against the **pinned** directory-signing key and runs the rollback/TOFU/role checks (§7.2). Never trust the server's framing — only the signed bytes.

```jsonc
// res 200
{ "binding_b64": "…canonical(dirbinding)…", "directory_signature_b64": "…Ed25519 by D5…" }
// res 404 if no signed binding exists (an unsigned/pending account is not a valid recipient)
```

### 6.2 `GET /v1/directory/recovery`
The recovery recipient's binding (the standing recipient, §6.3), verified identically — the server cannot substitute the recovery key either.

### 6.3 `POST /v1/directory/batch`
`{ "usernames": [...] }` → array of §6.1 results (or per-entry `not_found`), to verify a multi-recipient set in one round trip. Purely an optimization; each entry is verified independently client-side.

---

## 7. Revocation control-log (`DESIGN.md` §7.6, §11.5/§11.5a, §12.9b — Phase 5)

`revocation`, `reinstatement`, and `key_compromise` form **one** append-only hash chain (`encoding-spec.md` §4). The server serves the chain; the **authoritative head** is fetched and verified from the **external sink** (`docs/sink-interface.md`), and the client requires the served set to be **contiguous up to that anchored head**, failing closed on a gap (D22).

### 7.1 `GET /v1/revocations`
Serves the **whole** chain, in append order. **It takes no query parameters at all** — the handler is `State`-only (`server/http.rs:1016`, `get_revocations`) and calls `Store::control_records()` with no filter, no cursor and no limit.

> **Corrected 2026-08-02.** An earlier revision of this section documented `?scope=account`, `?file_id=<hex>`, `?since_epoch=<n>`, `?cursor=…` and `?limit=…`. **None of those has ever been accepted.** They were not silently rejected either — unknown query parameters are simply ignored — so a client that sent them received the *entire* chain and could easily have believed it received a filtered subset. That was a documentation lie, not a missing feature.

```jsonc
// res 200
{ "records": [ { "kind": "revocation", "record_b64": "…", "sig_b64": "…", "chain_head_b64": "…SHA-256 of this record…" }, … ],
  "next_cursor": null }
```
- `next_cursor` is a **permanent `null`** on this route (`server/http.rs:1008` `RevocationsRes`, hardcoded `next_cursor: None`). It is kept in the body only because it is in the frozen response shape; nothing populates it and nothing reads it.
- The client checks each `prev_head` links the previous record and that the final `chain_head` matches the **sink-anchored** head (out of band, per `sink-interface.md`). The server's own `chain_head` values are advisory; the sink is the authority.

**This endpoint is deliberately UNPAGINATED, and paginating it would be a security downgrade.** The client's reader takes only `records` and ignores `next_cursor` entirely (`client-app/src/revocations.rs:119-133`, `fetch_control_records`) — by design, because this is *authoritative revocation state*, not a UX nicety: a missing endpoint, a non-`200` or a malformed body **fails closed**, never a silently-empty (permissive) set. Introduce a cap or a cursor and that same reader would accept a **truncated chain** as the complete one, quietly under-enforcing revocations while still reporting success. The contiguity check (D22) would not save it: a prefix of the chain is contiguous. So any future paging here must be paired, in the same change, with a client that follows the cursor to exhaustion and fails closed on a partial walk — and it belongs in [`docs/compat/LEDGER.md`](compat/LEDGER.md), because "the server now returns fewer records for the same request" is a tightening of the worst kind.

### 7.2 `POST /v1/revocations`  ·  `POST /v1/reinstatements`  ·  `POST /v1/key-compromise`
Append a control-log record (admin-only; mass/`*` and all reinstatements require **dual control** — a second admin's co-signature in the record, §10.1/§11.5a). Body carries the opaque record + signature(s); the server verifies the **coarse** admin capability, appends to the chain, updates the head, and **publishes the appended record to the external sink** — which independently re-derives the new head `sha256(canonical(record))` (§16.5). `403` if the caller lacks the admin effective role.

```jsonc
// req (revocation)
{ "record_b64": "…canonical(revocation)…", "sig_b64": "…issuer Ed25519…", "co_sig_b64": "…second admin, if * / mass…" }
// res 201 { "chain_head_b64": "…new head…" }
```
> The server's acceptance is not the security event — the **anchoring to the sink** is. The issuer is not done until it **confirms** the sink reflects the new head (the sink-side re-derived `sha256(record)`); a server that appended but refused to publish is caught by that confirm (fail closed). A server that refuses to publish can only deny (clients fail closed on an unverifiable head), not forge or hide a revocation past one sink-head refresh.

---

## 8. Files — records (`DESIGN.md` §11.2/§11.7, §12.2/§12.5/§12.9 — Phases 3–5)

Upload is **two-phase** (stage → finalize) for atomicity and resumable chunking.

### 8.1 `POST /v1/files` — create file (version 1)
Stages the owner-signed record set. The file is **not visible** until finalize (§8.4).

```jsonc
// req
{ "file_id": "…hex16, client-generated…",
  "file_type": "video|image|blog",            // advisory mirror of the signed manifest's file_type (D35 listing)
  "genesis_b64": "…", "genesis_sig_b64": "…",
  "manifest_b64": "…", "manifest_sig_b64": "…",
  "streams": [ { "stream_type":"content", "chunk_count": 5120, "chunk_size": 1048576, "total_bytes": 5368709120 },
               { "stream_type":"metadata", "chunk_count": 1, "chunk_size": 65536, "total_bytes": 4096 },
               { "stream_type":"thumbnail", "chunk_count": 1, … }, { "stream_type":"preview", … } ],
  "wraps": [ { "recipient_id":"…|recovery", "recipient_type":"user|recovery",
               "wrapped_dek_b64":"…", "wrap_alg":"0x0001", "granted_by":"…", "grant_b64":"…", "grant_sig_b64":"…" }, … ],
  "listed": true,                              // OPTIONAL, default true; set once at v1. false = a bundle member hidden from the feed listing (Task 1.4)
  "bundle_id": "…hex16 owning bundle…" }       // OPTIONAL; the owning bundle's file_id for a member, else absent (Task 1.3)
// res 201
{ "upload_token": "opaque, scopes the chunk PUTs below", "version": 1 }
```
- Server **bound-checks** `chunk_size ∈ [4 KiB, 8 MiB]` and `chunk_count · chunk_size ≤ 256 GiB` (`parameters.md` §1.2) before accepting; `400`/`413` otherwise. It does **not** trust these for security (the signed manifest is authoritative) — they bound its own allocation.
- `wraps` MUST include a `recovery` entry (the client also asserts `recovery_present` in the signed manifest; the server only mirrors). Coarse check: caller `== genesis.owner_id`.
- **The recovery pair is a BICONDITIONAL — set both halves or neither** (tightened 2026-08-02, `server/files.rs:411-431`, mirrored in `MemoryStore::stage_version`, `server/store.rs:922-932`):

  > `recipient_type == "recovery"` **⇔** `recipient_id == "recovery"` (the reserved all-zero id `00000000000000000000000000000000`).

  Every wrap in the body is checked, and a **half-shape** — a `recovery`-typed wrap addressed to a real `user_id`, or a `user`-typed wrap claiming the sentinel id — is `400`. This is not a new rule: **Postgres has refused exactly this row since the baseline schema**, via `CHECK ( (recipient_type = 2) = (recipient_id = decode('00000000000000000000000000000000','hex')) )` (`migrations/0001_baseline.sql:253`, mirrored `docs/schema.sql:238`), and `maxsecu_encoding` refuses to *decode* the matching `Grant` at all (`DecodeError::RecoveryIdMismatch`, `crates/encoding/src/structs.rs:202-205`). What changed is only the answer: on Postgres the body used to surface as an opaque `500`, and a `MemoryStore`-backed server used to accept it with `201` — producing a file whose "recovery wrap" is addressed to a real user and which **the escrow key can never open**. The shipped client cannot emit a half-shape (it derives the id from the type, `client-app/src/commands/upload.rs:138-143`). See [`docs/compat/LEDGER.md`](compat/LEDGER.md), 2026-08-02.
- `listed`/`bundle_id` are **set once at v1** and ignored on rotations. `listed:false` marks a **bundle member** the feed listing (§8.6) hides; `bundle_id` points a member at its owning bundle (a malformed hex `bundle_id` is `400`).

### 8.2 `POST /v1/files/{file_id}/versions` — stage a new version (rotation/update)
Same body as §8.1 minus `genesis` (immutable, retained). `author_id` in the manifest must equal the owner (owner-only write, D29) — re-checked by **every downloader** (§8.5), the server only coarse-checks caller `== owner`. Returns `{ upload_token, version: N }` where the client proposes `N`; finalize enforces strict `+1` (§12).

### 8.3 Chunk upload — see §9.1.

### 8.4 `POST /v1/files/{file_id}/versions/{v}/finalize`
Atomically commits the staged version: the server verifies every stream received exactly `chunk_count` chunks of the declared sizes, then makes version `v` visible under the **serialize-on-`(file_id, version)`** rule (§12). On success the **prior version's chunks, wraps, and grants are deleted** (genesis + any durable records retained, §12.9). `200` / `409` on a lost race.

### 8.5 `GET /v1/files/{file_id}?version=<v|latest>`
Returns everything a downloader needs to verify and decrypt (`DESIGN.md` §12.5):

```jsonc
// res 200
{ "version": 7,
  "manifest_b64":"…", "manifest_sig_b64":"…", "genesis_b64":"…", "genesis_sig_b64":"…",
  "my_wrap": { "wrapped_dek_b64":"…", "grant_b64":"…", "grant_sig_b64":"…",
               "ancestor_grants": [ { "grant_b64":"…","grant_sig_b64":"…" }, … ] },   // re-share chain to author, if any
  "recovery_grant": { "grant_b64":"…", "grant_sig_b64":"…" },                          // grant only (presence check) — NOT the recovery wrap
  "streams": [ { "stream_type":"content","chunk_count":5120,"chunk_size":1048576,"blob_ref":"…" }, … ] }
// res 404 if no wrap row exists for the caller (indistinguishable from missing — no access oracle)
```
- The server returns **only the caller's** wrap — the row whose `recipient_id` equals the session principal — never another user's. The client then: verifies manifest + genesis, runs the **author-entitlement check** (`author_id == genesis.owner_id`), checks freshness/rollback + tombstone completeness, verifies its grant chain, and unwraps + checks `dek_commit` (§12.5). All server-independent.
- **Recovery carve-out (2026-08-01).** "Never the recovery *wrap*" holds for every ordinary caller, and the `recovery_grant` field above is still grant-only for them. It does **not** hold for the **recovery principal itself**: a session whose principal is the reserved recovery id is admitted on this route, and since the selection rule is `recipient_id == caller`, its `my_wrap.wrapped_dek_b64` **is** the recovery wrap. That is what makes the escrow readable online. Recovery is a standing recipient on every upload (§8.1: `wraps` MUST include a `recovery` entry), so it can open any file this way. **Admitted for it — the whole list, five routes:** §8.5 (this one), §8.6 (`GET /v1/files`), §9.2 (`GET …/chunks/{i}`), §9.3 (`GET …/chunks/{i}/status`) and §2.4 (`POST /v1/session/logout`). **Barred** for it on the file surface: `POST /v1/files`, `POST …/versions`, `PUT …/chunks/{i}`, `…/finalize` (§8.1–§8.4, §9.1), `DELETE /v1/files/{id}` (§8.7), **`POST …/wraps` (§10.1 — sharing)**, `DELETE …/wraps/{recipient}` (§10.2), `POST …/direct-link` (§9.4) and `GET …/recipients` (§8.5a) — all `403`. So a recovery session **reads everything and shares nothing**; §10.1 explains why sharing is shut. Cost stated in `DESIGN.md` §6.3 and the recovery spec §0 D6 / §9.

### 8.5a `GET /v1/files/{file_id}/recipients` — owner recipient set (rotation, §12.9)
The file **owner** reads the current version's **user** recipients + each one's grant chain, to drive **carry-forward** at rotation (§12.9 step 2) — necessary because a recipient may re-share onward (§12.4b) without the owner's knowledge, so the owner cannot track the set client-side. **Owner-only** (coarse caller `== genesis.owner_id`); `404` for a missing file **or** a non-owner caller — same code, **no oracle** (a non-owner cannot enumerate a file's readers). The recovery recipient is excluded (the owner always re-adds it). Wrapped DEKs are **not** returned — the owner re-wraps the fresh DEK to each recipient's directory-verified `enc_pub`.

```jsonc
// res 200
{ "recipients": [ { "recipient_id":"…", "granted_by":"…",
                    "grant_b64":"…", "grant_sig_b64":"…",
                    "ancestor_grants": [ { "grant_b64":"…","grant_sig_b64":"…" }, … ] }, … ] }
// res 404 if the file is absent or the caller is not the owner
```
The owner re-verifies each chain to the prior author (author/re-share edges only — possession-entailing) and drops any tombstoned or unverifiable recipient before re-wrapping `DEK'` (§12.9 step 2). The grant bytes are inert; the server cannot forge a recipient onto the carry-forward set.

### 8.6 `GET /v1/files` — listing (D35)
Returns the **authenticated `file_type`** + small-stream **structure/sizes** only — never values:

```jsonc
// GET /v1/files?type=video&limit=50&offset=100&sort=newest&owner=me
{ "files": [ { "file_id":"…","file_type":"video","version":7,"updated_at":…,
               "streams": { "title": {"size":118}, "thumbnail": {"size":18342}, "preview": {"size":221904} } }, … ],
  "next_cursor": "MXwxNTB8OWYzYzJhMWI0ZDVlNmY3MA",   // opaque; null on the last page
  "total": 137 }                                      // ADDED 2026-08-02 — see the old-server rule below
```
The client then fetches+decrypts the small `title`/`thumbnail` streams (§9) to render the browse view. The server can sort/filter **only** by `file_type`/size/time (§13). **Bundle members (`listed:false`) are excluded** from this listing (Task 1.4) — they are reached only through their bundle's member list, never the public feed.

**Query parameters.** All of them optional; **unknown parameters are ignored** (`ListQuery` has no `deny_unknown_fields` and every field is an `Option` — `server/http.rs:2045-2066`), so a pre-paging client that sends only `type`/`limit` gets exactly the pre-paging behaviour.

| param | values | default | notes |
|---|---|---|---|
| `type` | `video` \| `image` \| `blog` \| `bundle` \| … | absent = every type | An **unrecognised** type is NOT an error: it matches nothing and returns `{"files":[], "next_cursor":null, "total":0}` (`server/http.rs:2216-2224`). |
| `limit` | integer | **50** | **Capped at 200**: `q.limit.unwrap_or(50).min(200)` (`server/http.rs:2219`). Both numbers are a shipped contract — `tools/live-smoke` and the bundle e2e ask for `limit=200` and must keep getting 200. **Lowering either is a forbidden tightening.** |
| `offset` | u32 | **0** | 0-based **item** offset (not a page number). Ignored when a valid `cursor` is present. **NEW 2026-08-02.** |
| `cursor` | opaque string | absent | Exactly as returned in `next_cursor`. **SUPERSEDES `offset`** when present and valid; malformed ⇒ `400`. **NEW 2026-08-02.** |
| `sort` | `newest` \| `oldest` | `newest` | Anything else ⇒ `400 {"code":"bad_sort"}`. **NEW 2026-08-02.** |
| `owner` | `me` | absent | Restricts the listing to files the caller **owns** ("My Content"). Anything else ⇒ `400 {"code":"bad_owner"}`. **It is deliberately NOT an arbitrary `user_id`** — accepting one would turn this route into an enumeration oracle over other people's posts, which §13 exists to prevent. **NEW 2026-08-02.** |

**Response fields.** `files` is unchanged. Two changes, both additive:
- **`next_cursor` used to be `null` unconditionally; it is now populated.** Non-`null` **iff** `!files.is_empty() && offset + files.len() < total` (`server/http.rs:2269-2270`) — i.e. iff more items exist after this page under the same `(type, sort, owner)` triple. The `!files.is_empty()` half is an anti-livelock guard: with `limit=0` the page is empty while `total > 0`, and a cursor that does not advance would loop a paging client forever.
- **`total` is NEW** (`server/http.rs:2094`): the number of entries matching `(type, owner)` with `limit`/`offset` **ignored** — what a numbered pager divides by `limit`. It is sort-independent, and it is computed from the *same* `WHERE` clause as the page, inside one `REPEATABLE READ` transaction, so `total` can never describe a different set than `entries` (`server/pg.rs:970-1010`).

> **REQUIRED CLIENT BEHAVIOUR — the old-server rule.** A client **MUST** treat the **absence** of `total` in the response as *"this server does not paginate"*, render **no pager**, and **never request `offset > 0`**. This is not advisory. `total` is serialized **unconditionally** (no `skip_serializing_if`, `server/http.rs:2094`), so its absence is unambiguous — and an un-upgraded server (prod `41912da`) silently ignores `offset`/`cursor`/`sort`/`owner` and serves **page 1 forever**. A client that trusted its own `offset` against such a server would render "page 5" showing page 1's contents, with nothing to distinguish it from the truth. The shipped mitigation: `page_from_json` reports `total: None` for a body with no `total` key (`client-app/src/commands/feed.rs:120-140`), `FeedPageDto.total` carries it across the Tauri seam (`client-app/src/dto.rs:133`), and `shouldShowPager` returns `false` for `null` (`client-app/ui/src/core/paging.ts:92`). Note that the unknown-`type` empty page reports `total: 0`, **not** an absent `total`, precisely so it cannot be confused with an old server.

**The cursor token.** Server-defined and **opaque to clients** — do not parse it, do not construct one, do not persist one across a filter change. It is nevertheless deterministic and self-validating, and documented here so the contract is auditable:

```
                          (‖ = concatenation; the "|" between fields is a literal ASCII pipe)
cursor   = base64url-unpadded( "1" ‖ "|" ‖ <next_offset, decimal ASCII> ‖ "|" ‖ <query_fp> )
query_fp = first 16 hex chars of SHA-256( "type=" ‖ <type-or-empty>
                                        ‖ ";sort=" ‖ ("newest" or "oldest")
                                        ‖ ";owner=" ‖ <"me"-or-empty> )

example  = base64url-unpadded("1|150|9f3c2a1b4d5e6f70") = "MXwxNTB8OWYzYzJhMWI0ZDVlNmY3MA"
```

`<type>` is the **server's** canonical spelling (the `file_type_name` codepoint, `server/http.rs:1109-1118`), not the caller's raw string, so two spellings of the same filter cannot mint two fingerprints. `"1"` is the layout version; bumping it is how a future cursor stays distinguishable. Codec at `server/http.rs:2105-2158`. The fingerprint binds the **filter**, not the offset, and `next_offset` is parsed as `u32` — the same domain as the `offset` parameter — so a forged cursor cannot push an unbounded `OFFSET` into Postgres. Error codes (all `400`, all on parameters **no shipped client sends**, so none of them can reject an existing request):

| code | meaning |
|---|---|
| `bad_cursor` | undecodable, wrong version, or `next_offset` outside `u32` |
| `cursor_query_mismatch` | well-formed, but minted under a different `(type, sort, owner)` triple |
| `bad_sort` / `bad_owner` | an unrecognised value for that parameter |

Validation order (`server/http.rs:2186-2233`): `sort` and `owner` first (both feed the fingerprint), then the unknown-`type` early return, then the cursor. So `?type=bogus&cursor=…` returns the empty `total: 0` page rather than a cursor error — there is no canonical fingerprint for an unrecognised type, and an unknown type has always matched nothing rather than erroring the browse.

**Ordering, and what it does NOT guarantee.** `sort=newest` (the default, unchanged) is `ORDER BY updated_at DESC, file_id ASC`; `sort=oldest` is `ORDER BY updated_at ASC, file_id ASC` (`server/pg.rs:989-996`). The `file_id` tiebreak makes the order **total**, so no page can repeat or drop a row merely because two timestamps tie.

> **Offset paging over this order is NOT skip-free and NOT duplicate-free, and that is accepted.** `files.updated_at` is **mutable**: it is bumped by `finalize_version` (`server/pg.rs:822`, `UPDATE files SET current_version = $2, updated_at = now()`) **and by `add_wrap`** (`server/pg.rs:1205-1210`) — i.e. by **every re-share**. So a re-share landing while a user is paging can move an item across a page boundary, and that item is then **seen twice or missed**. Nothing detects it and nothing warns. It is reproduced, not assumed, by `crates/server/tests/pg_store.rs:1341` and `crates/server/tests/file_records.rs:502`.
>
> **A store divergence to know before you write a test against this** (pre-existing, not introduced by the paging work): `PgStore::finalize_version` stamps `files.updated_at = now()` from the **database** clock and **ignores** its `now_ms` argument (`server/pg.rs:822`), while `MemoryStore::finalize_version` uses `now_ms` (`server/store.rs:1015`). Harmless in production — both mean "now" — but a Postgres test cannot control the listing's sort key through that argument and must `UPDATE` the column itself. See the `seed_finalized` helper's comment at `crates/server/tests/pg_store.rs:1148-1155`.
>
> The two obvious "fixes" were both rejected, and should stay rejected. Sorting on the immutable `created_at` would stop a re-shared file ever surfacing in the recipient's feed — a product regression for existing users, which is the exact class of harm the compat rule protects. Adding a dedicated stable sort column touches frozen surface #9. A keyset cursor cannot help either, because the feed pager is **numbered** (`<< 1 2 3 4 >>`) and needs random access to page N plus a page count, neither of which keyset paging provides. Recorded in [`docs/compat/LEDGER.md`](compat/LEDGER.md), 2026-08-02.

**Who may call it.** Any authenticated principal, **including the recovery principal** (2026-08-01). The listing is **scoped to the caller**: an entry appears only if the caller holds a wrap for the file's current finalized version (their own self-wrap or a share) — same gate as the open path, no oracle. Because recovery is a standing recipient on every upload (§8.1), that scoping returns **every listed file** to it: the recovery session sees the whole feed. `listed:false` bundle members are still excluded from the listing for it too — they remain reachable by id via §8.5. `owner=me` composes with that scope rather than widening it: it is an additional `owner_id = caller` predicate, so it can only ever return a **subset** of what the caller could already see.

### 8.7 `DELETE /v1/files/{file_id}` — discard staged / owner-only permanent delete
Owner-only, no oracle. Two behaviors on one endpoint:
- **Staged (never finalized):** discards the staged version and frees its chunks — **idempotent** (an absent/already-discarded staged version is still `204`).
- **Finalized:** performs an **owner-only permanent delete** — this is the ONE path that removes committed content (server-side, via a transaction-local carve-out over the append-only triggers; the transparency/tamper-evidence logs stay fully immutable). It removes the file and all its versions/streams/wraps/genesis, **cascades to bundle members the same owner owns** (a member owned by anyone else is never touched), and **purges every blob, including the cold tier**. Deletion is local only — it never writes to the append-only sink.

`204` on success. `404` for an absent file **or** a non-owner (same code — no existence/ownership oracle). `400` on a malformed `file_id`; `500` on a backend fault. A non-owner of a finalized file is refused before the permanent-delete path is ever reached.

---

## 9. Streams & blob I/O (`DESIGN.md` §12.10, D31/D34 — Phases 3/4b)

Chunks are inert ciphertext; the client verifies each against the signed manifest's per-stream digest + per-chunk AEAD tag regardless of source (cache, Dropbox, or a tampering server) — so a bad byte from any tier is detected (§12.10).

### 9.1 `PUT /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}`
Upload one ciphertext chunk (raw `application/octet-stream`), scoped by the staging `upload_token`. **Idempotent by `index`** — re-PUT overwrites the same slot, so an interrupted upload simply re-sends missing indices (resumable). `413` if over the bound; `409` after finalize.

### 9.2 `GET /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}`
Download one ciphertext chunk (raw bytes). Supports HTTP range. **Server-proxy is the default** (D31): on a cache miss the server fetches from Dropbox and relays; progress is reported via §9.3.

**Who may call it.** The same §8.5 access gate: the file **owner**, or a recipient holding a wrap for that finalized version — otherwise `404` (missing-or-forbidden, no oracle). The **recovery principal is admitted** here and on the §9.3 status probe (2026-08-01), and holds a wrap on every finalized version, so it can fetch any chunk of any file. It is **not** admitted on §9.1 (`PUT`, upload) or §9.4 (`direct-link`) — both `403`. Note this read is not side-effect-free when a cold tier is configured: it rehydrates, and may offload capacity victims, exactly as for any other caller.

### 9.3 Cache-miss progress
For a proxied fetch that must pull from the cold tier, the server streams the body as it arrives (HTTP/2, chunked) so the client sees throughput; a `GET …/chunks/{index}/status` returns `{ "source":"cache|cold-fetching|cold-ready", "fetched_bytes":…, "total_bytes":… }` for UI progress (the "fetching from the cold tier" signal — a known popularity/recency side-channel, §15.3, accepted). The status carries the same §8.5 access gate as the chunk download — `404` for missing-or-forbidden, no oracle. *(Implementation: the tier is abstract (`server::tier::ColdTier`), so the source names generalize the original `dropbox-*` to `cold-*`; `fetched`/`total` bytes are filled by a streaming cold adapter and best-effort otherwise.)*

### 9.4 `POST /v1/files/{file_id}/versions/{v}/streams/{stream_type}/direct-link` (optional, opt-in)
Brokers a **short-lived, scoped, read-only** Dropbox link for a large blob so the client downloads it directly (bandwidth optimization). `{ "url":"…", "expires_in_s": 900 }` (`parameters.md` §8). The **master token is never given to the client**; the client still verifies every byte. **Disabled in Tor mode** (D34) and client-toggleable — `403 forbidden` with `code: "direct_disabled"` when off.

---

## 10. Sharing & soft-revoke (`DESIGN.md` §12.4b/§12.8 — Phase 4/5)

### 10.1 `POST /v1/files/{file_id}/wraps` — re-share read (online, D11)
A current recipient adds a **read** wrap for another directory-verified, non-tombstoned user. Body = one wrap row with its `granted_by` + `grant_sig` (the granter actually unwrapped+re-wrapped the DEK, so this is a *possession-entailing* grant eligible for carry-forward, §12.3a). Coarse checks: `granted_by` must equal the caller and the recipient must be a `user` (re-share never targets recovery) — else `400`; the caller must already hold a wrap for the file's current version — else `404` (indistinguishable from missing, no oracle). Idempotent by recipient (a re-share replaces an existing row). The edge is written to the external audit sink with `granted_by` (§16.5). The wrap added here is served to its recipient by §8.5 with the assembled `ancestor_grants` chain up to the author.

**The recovery principal is `403` here. Sharing from a recovery session is a CLOSED DECISION (owner, 2026-08-02) — not a pending item, not an oversight, and not a thing to "fix".** *(Corrected: an earlier revision of this note said the recovery principal was "an admitted caller here" and "a universal grant issuer by construction". That was written against a design that was reverted before it landed. This route runs on `AuthedSession`, which hard-`403`s the reserved recovery id; the browse/read allowlist covers §8.5, §8.6, §9.2, §9.3 and §2.4 only.)* Three reasons, each verified against the code:

- **(a) A recovery-issued grant is structurally unopenable by its recipient.** The downloader field-binds every ancestor grant *before* the chain walk and rejects any whose `recipient_type` is not `User` (`client-core/src/download.rs:448-450`). The server serves exactly the recovery wrap's grant as that ancestor, so the reject is unconditional.
- **(b) `granted_by = RECOVERY_ID` resolves to no CLIENT-TRUSTED signing key.** *(Be precise here — earlier revisions of this and several other documents said "no signing key exists". That is **wrong**.)* The recovery account **does** hold an Ed25519 `sig_pub` server-side (`server/src/store.rs:47-51`, `RecoveryAccount`). What does not exist is any **trusted path** to it: `GET /v1/recovery/pubkey` serves only `enc_pub_b64` and `mlkem_pub_b64` (`server/src/http.rs:667-686`), the embedded recovery pin omits `sig_pub` entirely, and every client open path passes no-op granter/admin resolvers — so the walk ends at `GrantChainBroken` regardless of what the server holds.
- **(c) It would DESTROY access that already works.** `add_wrap` is idempotent **by REPLACE** in both stores — `MemoryStore` drops any existing row for that `recipient_id` before inserting (`server/src/store.rs:1228`) and `PgStore` does it with `ON CONFLICT … DO UPDATE` (`server/src/pg.rs:1184-1203`). So a recovery re-share to somebody who **already had working access** swaps their good grant for one they cannot verify, silently and irreversibly. This is the reason the decision is **permanent** rather than a missing feature: it is not that sharing is unbuilt, it is that building it on this route destroys existing users' data access, which `CLAUDE.md` forbids outright.

Reasons (a) and (b) could in principle be lifted — by publishing a directory binding for `RECOVERY_ID` carrying a real Ed25519 signing key, or by adding `sig_pub` to the recovery pin (frozen surface #7) and terminating the chain at the `DESIGN.md` §12.7 admin key — and reason (c) would additionally need a server-side refusal of a REPLACE when `granted_by == RECOVERY_ID`. **The operator declined to take either on.** The route stays shut. Restoring a user's access to a file is done by the air-gapped §12.7 ceremony (`docs/runbooks/recovery-session.md`), which is what that ceremony is for.

The client refuses it too (`recovery_share_unsupported`, `client-app/src/commands/share.rs`) and hides the affordance, but a client-side refusal is not a security boundary — the bar is the extractor. `crates/server/tests/recovery_login_e2e.rs` posts a **well-formed** wrap body and asserts the `403`, so admitting the route breaks the build. See `DESIGN.md` §6.3, the recovery spec §0 D6 / §9, and `docs/security-review-trusted-server-recovery.md`.

```jsonc
{ "recipient_id":"…", "recipient_type":"user",
  "wrapped_dek_b64":"…", "wrap_alg":"0x0001", "granted_by":"…caller…", "grant_b64":"…", "grant_sig_b64":"…" }
// res 201
```
Re-sharing read **never** confers write (owner-only, D29) — there is no write-grant endpoint.

### 10.2 `DELETE /v1/files/{file_id}/wraps/{recipient_id}` — soft revoke
Server-side denial only (`DESIGN.md` §12.8): stops serving that recipient. **Not** a cryptographic boundary — for a guarantee against a malicious server, issue a **tombstone** (§7.2) and rotate. Coarse gate: the caller must be the file **owner** or the wrap's **`granted_by`** (the §14.5 "cut your own subtree" intuition) — else `403` (bodiless); `404` if no such file/wrap (no oracle); `204` on success.

**The recovery recipient may NOT be revoked, by anybody (added 2026-08-02).** Targeting `recipient_id = 00000000000000000000000000000000` (`RECOVERY_ID`), **or** a stored wrap whose `recipient_type = 2`, is:

```jsonc
// res 403
{ "code": "recovery_protected" }
```

for **every** caller — the file owner included. Enforced at three layers: the handler, *before* the `SoftRevoke` audit edge is written, so a refused request leaves no trace of a revoke that never happened (`server/http.rs:1890`, helper `recovery_protected()` at `:1927`); `MemoryStore` before the lock and again on the stored type (`server/store.rs:1244`, `:1266`); and `PgStore` **before `pool.begin()`** plus a stored-type check ahead of every write inside the transaction (`server/pg.rs:1232`, `:1286`).

**Why.** Stripping the recovery wrap is a **one-way blinding of the escrow**. `add_wrap` (§10.1) hard-rejects `recipient_id == RECOVERY_ID` in both stores (`server/store.rs:1205`, `server/pg.rs:1150-1151`), so nothing can put the wrap back at that version — not the owner, not the operator, not a re-upload of the same version. On Postgres the same request also writes an **append-only `wrap_revocations` tombstone** (`migrations/0002_delete_tombstones.sql:74,82-84`) that can never be removed, so even a backup restore honours the blinding (`docs/runbooks/backup-restore.md`). `DESIGN.md` §1.2/§6.3 state that the escrow can decrypt *100% of all files, past and present*; while this call succeeded, that statement was false for any file whose owner had made it so, silently and permanently.

**Why `403` and not `400` — the deliberate asymmetry with §10.1.** `add_wrap` answers `400` for the same recipient because there the **body** is invalid: a re-share may never target recovery at all. Here the request is well-formed and the caller **is** authorized for the route — just not for this target, which is exactly what `403` means, and `403` is already in this route's response set so no caller sees a new status class. Ordinary ownership `403`s on this route stay **bodiless**; only the recovery refusal carries a `code`, so the two are separable in logs.

**Compat note.** This is a **tightening** of a frozen surface (a call that used to return `204` now returns `403`) and is ledgered as one — see [`docs/compat/LEDGER.md`](compat/LEDGER.md), 2026-08-02. It is judged safe because no shipped client has ever issued it: `delete_req` has exactly two client call sites (`client-app/src/commands/delete_cmd.rs:54-59` and `client-app/src/commands/upload.rs:1782-1783`) and both target `/v1/files/{file_id}` (§8.7), never `…/wraps/…`.

---

## 11. Client audit reporting (`DESIGN.md` §16.5 — minimal)

`POST /v1/audit/client-event` mirrors client-detected anomalies (author-entitlement rejection, unauthorized reader-exclusion, missing recovery grant, plaintext export) to the server's local `auth_events`. **This mirror is forgeable by a malicious server** (§11.4) — the **authoritative** copy goes to the external sink (`sink-interface.md`); this endpoint is convenience/telemetry only. Body: `{ "type":…, "file_id"?:…, "version"?:…, "detail":"sanitized" }`. `202`.

---

## 12. Idempotency, concurrency & atomic version commit
- **Version commit is serialized on `(file_id, version)`** (§8.4). Finalize accepts `v` **iff** `v == current + 1`; a lost race or a stale proposal ⇒ `409`, and the client **rebases** onto the now-current version and re-derives (`DESIGN.md` §12.9). With owner-only write (D29) races are rare, but the gate is still enforced so `version` stays a strict `+1` chain (compatible with the §7.5/D23 rollback memory).
- **Chunk PUTs are idempotent by index** (§9.1); **create/stage** is idempotent by client-generated `file_id` (a duplicate stage of the same `file_id` returns the existing staging state, not a second file).
- **Mutations re-check session + coarse entitlement before any side effect; failures fail closed and are logged** (§10/§16.5).

---

## 13. Security properties this contract preserves (and what it doesn't)
- **Confidentiality/integrity do not rest here.** The server sees only inert ciphertext, public keys, signatures, wraps, and the D35 index fields; every guarantee is re-verified client-side (§1, §8.5). A fully malicious server can deny service but cannot read, forge a recipient/author, or pass off a stale version/binding (`DESIGN.md` §3.1).
- **No oracles:** uniform `401` for all login failures; `404` for both missing and forbidden files; well-formed challenges for unknown usernames.
- **Channel-bound sessions** (§1.5/§2.3) defeat lifted-token replay.
- **Coarse-only server authz** is defense-in-depth, never the boundary (§10/`DESIGN.md` §10).
- **Not covered here:** the sink head fetch/verify (`sink-interface.md`), SQL constraints enforcing the append-only/monotonic invariants (`schema.sql`), and the media sandbox (client-internal, `stack.md` §1.7). The **metadata residuals are unchanged** by this API — sizes, timing, cache hit/miss, sharing graph, and `file_type` remain server-visible by design (§13/§15.2).

---

## Cross-references
- Values (TTLs, sizes, cadences, rate limits): `docs/parameters.md`. Record bytes: `docs/encoding-spec.md`. Sink head: `docs/sink-interface.md`. DB shape: `docs/schema.sql`. Media isolation: `docs/media-sandbox.md`.
- Phase mapping: §2–§5 → Phase 1; §6–§7 → Phase 2/5; §8–§9 → Phase 3/4b; §10 → Phase 4/5.
