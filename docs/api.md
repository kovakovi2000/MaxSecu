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

### 2.2 `POST /v1/session/proof`
```jsonc
// req
{ "username": "alice", "timestamp": 1719500000000, "proof_b64": "…Ed25519 sig…" }
// res 200
{ "session_token": "opaque", "expires_in_s": 3600 }
// res 401 (sanitized — same shape whether username unknown, proof bad, nonce stale, or channel mismatch)
{ "error": { "code": "unauthorized" } }
```
- Server verifies `proof` against the `sig_pub` on record (§9.2), checks nonce freshness/single-use, and checks the proof's `tls_exporter` equals the live connection's. Issues a token **bound to this connection's exporter**, TTL **60 min** (`parameters.md` §2), revocable.
- A single 401 shape for every failure cause — no oracle (§3).

### 2.3 Session pinning & reconnect
- The token is presented as **`Authorization: MaxSecu-Session <token>`** on every subsequent request, over the **same connection**.
- If the connection drops, the client **re-authenticates** (§2.1–2.2) to mint a fresh token on the new connection. Challenge-response is one round trip and the `sig_priv` is already unlocked in RAM, so reconnect cost is negligible. *(Alternative for a future multi-connection need: RFC 8471 token-binding keys; not in v1 — single-connection binding is simpler and strictly stronger.)*

### 2.4 `POST /v1/session/logout`
Revokes the presented token server-side (best-effort; tokens also expire). `204`.

### 2.5 Self-login needs no directory verification
The server checks the user against the `sig_pub` it stored; if it swapped that key, the user's own genuine proof simply fails and login breaks — a detectable denial, not a silent compromise (`DESIGN.md` §9.2). An account whose binding is **not yet ceremony-signed** can still log in and manage its own files, but is not yet a valid recipient for others (§5).

---

## 3. Error model (`DESIGN.md` §16.2 — fail closed, sanitized)

Errors are conveyed by the **HTTP status code with an empty body** — the most-sanitized shape (impossible to leak), verified by `crates/server/tests/sanitized_errors.rs` (Phase 6, P6.7). The only structured signals are the sanctioned `429` `Retry-After` header and the constant `403 {"code":"direct_disabled"}` for the direct-link opt-out. The `code` column below names the **semantics** of each status, not a JSON field. **No** stack traces, DB text, paths, internal detail, or existence signals ever reach a client. Any exception on an auth/authz path ⇒ deny.

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
Query the chain. `?scope=account` (the `*` set) or `?file_id=<hex>`; `?since_epoch=<n>`; `?cursor=…&limit=…`.

```jsonc
// res 200
{ "records": [ { "kind": "revocation", "record_b64": "…", "sig_b64": "…", "chain_head_b64": "…SHA-256 of this record…" }, … ],
  "next_cursor": null }
```
- The client checks each `prev_head` links the previous record and that the final `chain_head` matches the **sink-anchored** head (out of band, per `sink-interface.md`). The server's own `chain_head` values are advisory; the sink is the authority.

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
               "wrapped_dek_b64":"…", "wrap_alg":"0x0001", "granted_by":"…", "grant_b64":"…", "grant_sig_b64":"…" }, … ] }
// res 201
{ "upload_token": "opaque, scopes the chunk PUTs below", "version": 1 }
```
- Server **bound-checks** `chunk_size ∈ [4 KiB, 8 MiB]` and `chunk_count · chunk_size ≤ 256 GiB` (`parameters.md` §1.2) before accepting; `400`/`413` otherwise. It does **not** trust these for security (the signed manifest is authoritative) — they bound its own allocation.
- `wraps` MUST include a `recovery` entry (the client also asserts `recovery_present` in the signed manifest; the server only mirrors). Coarse check: caller `== genesis.owner_id`.

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
- The server returns **only the caller's** wrap (never another user's, never the recovery *wrap*). The client then: verifies manifest + genesis, runs the **author-entitlement check** (`author_id == genesis.owner_id`), checks freshness/rollback + tombstone completeness, verifies its grant chain, and unwraps + checks `dek_commit` (§12.5). All server-independent.

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
`?type=video&cursor=…&limit=…`. Returns the **authenticated `file_type`** + small-stream **structure/sizes** only — never values:

```jsonc
{ "files": [ { "file_id":"…","file_type":"video","version":7,"updated_at":…,
               "streams": { "title": {"size":118}, "thumbnail": {"size":18342}, "preview": {"size":221904} } }, … ],
  "next_cursor": "…" }
```
The client then fetches+decrypts the small `title`/`thumbnail` streams (§9) to render the browse view. The server can sort/filter **only** by `file_type`/size/time (§13).

---

## 9. Streams & blob I/O (`DESIGN.md` §12.10, D31/D34 — Phases 3/4b)

Chunks are inert ciphertext; the client verifies each against the signed manifest's per-stream digest + per-chunk AEAD tag regardless of source (cache, Dropbox, or a tampering server) — so a bad byte from any tier is detected (§12.10).

### 9.1 `PUT /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}`
Upload one ciphertext chunk (raw `application/octet-stream`), scoped by the staging `upload_token`. **Idempotent by `index`** — re-PUT overwrites the same slot, so an interrupted upload simply re-sends missing indices (resumable). `413` if over the bound; `409` after finalize.

### 9.2 `GET /v1/files/{file_id}/versions/{v}/streams/{stream_type}/chunks/{index}`
Download one ciphertext chunk (raw bytes). Supports HTTP range. **Server-proxy is the default** (D31): on a cache miss the server fetches from Dropbox and relays; progress is reported via §9.3.

### 9.3 Cache-miss progress
For a proxied fetch that must pull from the cold tier, the server streams the body as it arrives (HTTP/2, chunked) so the client sees throughput; a `GET …/chunks/{index}/status` returns `{ "source":"cache|cold-fetching|cold-ready", "fetched_bytes":…, "total_bytes":… }` for UI progress (the "fetching from the cold tier" signal — a known popularity/recency side-channel, §15.3, accepted). The status carries the same §8.5 access gate as the chunk download — `404` for missing-or-forbidden, no oracle. *(Implementation: the tier is abstract (`server::tier::ColdTier`), so the source names generalize the original `dropbox-*` to `cold-*`; `fetched`/`total` bytes are filled by a streaming cold adapter and best-effort otherwise.)*

### 9.4 `POST /v1/files/{file_id}/versions/{v}/streams/{stream_type}/direct-link` (optional, opt-in)
Brokers a **short-lived, scoped, read-only** Dropbox link for a large blob so the client downloads it directly (bandwidth optimization). `{ "url":"…", "expires_in_s": 900 }` (`parameters.md` §8). The **master token is never given to the client**; the client still verifies every byte. **Disabled in Tor mode** (D34) and client-toggleable — `403 forbidden` with `code: "direct_disabled"` when off.

---

## 10. Sharing & soft-revoke (`DESIGN.md` §12.4b/§12.8 — Phase 4/5)

### 10.1 `POST /v1/files/{file_id}/wraps` — re-share read (online, D11)
A current recipient adds a **read** wrap for another directory-verified, non-tombstoned user. Body = one wrap row with its `granted_by` + `grant_sig` (the granter actually unwrapped+re-wrapped the DEK, so this is a *possession-entailing* grant eligible for carry-forward, §12.3a). Coarse checks: `granted_by` must equal the caller and the recipient must be a `user` (re-share never targets recovery) — else `400`; the caller must already hold a wrap for the file's current version — else `404` (indistinguishable from missing, no oracle). Idempotent by recipient (a re-share replaces an existing row). The edge is written to the external audit sink with `granted_by` (§16.5). The wrap added here is served to its recipient by §8.5 with the assembled `ancestor_grants` chain up to the author.

```jsonc
{ "recipient_id":"…", "recipient_type":"user",
  "wrapped_dek_b64":"…", "wrap_alg":"0x0001", "granted_by":"…caller…", "grant_b64":"…", "grant_sig_b64":"…" }
// res 201
```
Re-sharing read **never** confers write (owner-only, D29) — there is no write-grant endpoint.

### 10.2 `DELETE /v1/files/{file_id}/wraps/{recipient_id}` — soft revoke
Server-side denial only (`DESIGN.md` §12.8): stops serving that recipient. **Not** a cryptographic boundary — for a guarantee against a malicious server, issue a **tombstone** (§7.2) and rotate. Coarse gate: the caller must be the file **owner** or the wrap's **`granted_by`** (the §14.5 "cut your own subtree" intuition) — else `403`; `404` if no such file/wrap (no oracle); `204` on success.

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
