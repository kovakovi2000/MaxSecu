# MaxSecu — External Sink Interface (anchored control-log head)

**Status:** Spec (stand up before Phase 5; the sink itself is an operational prerequisite, stack.md §2.3/§4).
**Scope:** how a client fetches and verifies the **anchored head** of the control-log hash chain from the **external, append-only sink**, independent of the app server — the control that turns tombstone *withholding* from "detected" into "prevented within one refresh" (`DESIGN.md` §7.6/§16.5, D18/D22). Also defines the issuer-side anchoring step that closes write-time withholding.
**Companion to:** `DESIGN.md` §7.6/§11.4/§16.5, `docs/api.md` §7 (the server-served chain), `docs/parameters.md` §5 (refresh cadence), `docs/encoding-spec.md` §4 (the chained records).

> **Why a second system at all.** Every "detectable / bounded" claim in `DESIGN.md` rests on an audit trail the **untrusted app server cannot suppress or forge** (§11.4). The app server serves the tombstone *records* (api.md §7.1); the sink independently attests *what the current head is*, so a server that **withholds** a fresh tombstone is caught by a head mismatch and the client **fails closed**. The sink is therefore the one component besides the air-gapped trust root that must live **outside the app operator's unilateral control**.

---

## 1. What the sink is (and is not)

- **Is:** a genuinely independent, **append-only** store (WORM object store or an independent SIEM, stack.md §2.3) holding the control-log event stream and publishing a **digest-anchored head**. Separate infrastructure, separate credentials, separate failure domain from the app server.
- **Is not:** the Postgres `auth_events` mirror (forgeable by the app server, §11.4); not a signing authority (there is **no** online status signer — D13 removed); not a confidentiality boundary (it holds only the same inert signed records, never keys or plaintext).

The sink's integrity rests on two independent legs, either of which catches tampering:
1. **Independent custody + append-only semantics** — the operator cannot delete/reorder without breaking WORM.
2. **Digest anchoring** — the chain head is periodically **cross-published** to a medium the app operator does not control (e.g. a public transparency log / notary / a second org's store), so even a fully-compromised sink+server cannot rewrite history without the cross-published head diverging.

---

## 2. The object being anchored

The control-log is one hash chain over `revocation` / `reinstatement` / `key_compromise` records (`encoding-spec.md` §4; `schema.sql` `control_log`):

```
record_i.prev_head = SHA-256(canonical(record_{i-1}))      // record_0.prev_head = GENESIS_HEAD (00..00)
head_i             = SHA-256(canonical(record_i))
```

The **anchored head** is the tuple the sink attests:

```
AnchoredHead = { chain_seq : u64,        // count of records in the chain (global order)
                 head      : 32 bytes,    // head_{chain_seq}
                 anchored_at: timestamp,  // advisory only (never a freshness basis, §7.5)
                 anchor_proof }           // see §4
```

`chain_seq` + `head` together pin the chain to an exact length and content. A client that holds a trusted `AnchoredHead` can reject any server-served chain that is shorter (withholding → a gap), forked (different `head` at equal `chain_seq`), or rolled back (lower `chain_seq`).

---

## 3. Client read interface

The client talks to the sink over its **own pinned-TLS identity** (pinned in the build alongside the D5 key and the app-server identity, §7.3/§8) — a channel **independent of the app server**, so a malicious app server cannot interpose.

### 3.1 `GET {sink}/v1/control-log/head` → `AnchoredHead`
The current anchored head (§2). This is the **only** call required on the hot path; clients cache it per `parameters.md` §5 (relaxed 30 min; high-sensitivity-file operations bypass the cache for a fresh fetch).

### 3.2 `GET {sink}/v1/control-log/records?since_seq=<n>&limit=<m>` → `[ {chain_seq, record_bytes, sig, co_sig?} ]` (optional, recommended)
The sink's **own copy** of the records. Lets a client (or auditor) verify the app-server-served set against the sink directly, not merely against the head — strongest mode. If the sink serves records, the client need not trust the app server's chain at all; if it serves only the head (3.1), the client verifies the app server's records *up to* that head.

### 3.3 `GET {sink}/v1/control-log/anchor-log?since=<t>` → cross-publication receipts (audit/transparency)
The history of anchored heads + their `anchor_proof`s, for periodic auditor reconciliation against the independent cross-published medium (§4). Not on the client hot path.

---

## 4. `anchor_proof` — what makes the head trustworthy without a new online signer

`anchor_proof` is an abstraction with a small set of accepted concrete forms (the client ships an allowlist, like the `alg` registry); **at least one** must validate or the head is rejected (fail closed). In rough order of strength:

| Form | What the client checks | Notes |
|---|---|---|
| **Transparency-log inclusion** | a signed checkpoint + inclusion proof binding `head` into an append-only public log (e.g. a Merkle log / notary the app operator doesn't control) | strongest; ties into the Phase-7 key-transparency work (§7.4). Preferred target. |
| **Independent co-signature** | an Ed25519 signature over `{chain_seq, head}` by a key held by a **separate custodian** (not the app operator, not D5/D6), pinned in the build | a deliberately *different trust domain* from the app server — not the removed status signer (that was an app-side online key gating revocation freshness; this only attests an append-only head and never gates reads) |
| **WORM attestation** | the storage tier's own immutability receipt (e.g. object-lock retention metadata) over the head object | weakest alone (rests on the storage vendor); acceptable **combined** with cross-publication |

> **Not a reintroduced status signer.** The co-signature form may look like one, but it differs in every way that mattered: it signs only an *append-only head* (not per-user freshness), it is in a *separate custody domain*, it has *no expiry/fuse*, and a client that cannot reach it **fails closed only on sharing/rotation, never on reads** (§7.6). It is an availability dependency, not a fleet-wide liveness fuse (R9 stays designed out).

---

## 5. Client verification algorithm (fail-closed)

For any operation that requires revocation completeness — wrapping a new recipient, rotating, re-sharing, or the download-time completeness check (`api.md` §7/§8.5, `DESIGN.md` §12.4b/§12.5/§12.9):

1. **Obtain a trusted head.** Use the cached `AnchoredHead` if within the `parameters.md` §5 window (bypass cache for high-sensitivity files); else `GET …/head` (3.1) over the sink's pinned channel and **validate its `anchor_proof`** (§4). If neither succeeds → **fail closed** (block the operation; reads of already-verified content continue).
2. **Obtain the records.** Either from the sink (3.2, strongest) or from the app server (`api.md` §7.1).
3. **Verify the chain to the head.** Walk the records: each `prev_head` links the previous `head`; recompute every `head`; require the final record's `head == AnchoredHead.head` **and** record count `== AnchoredHead.chain_seq`. **Any gap, fork, short chain, or mismatch → fail closed** (D22). This is what defeats server withholding and rollback in one check.
4. **Verify each record's authority.** Check the issuer (and `co_signed_by` where dual control is required) Ed25519 signature against the issuer's **directory binding for the issuer's key_version at signing time** (historical binding, §11.7), and that the issuer's binding carries the `admin` effective role. Honor a `key_compromise` cutoff by the record's **sink position** (`chain_seq`), not its `effective_from` (D28).
5. **Apply revocation/role logic.** A user is under an active tombstone iff a `revocation` names them (`from_version ≤` the version in question) with **no** `reinstatement` whose `supersedes_epoch` references that revocation's `scope_epoch` — matched by explicit reference per `(scope, user)`, **never** by comparing the two independent epoch counters (R28/§11.5a). Effective roles = binding ceiling **minus** role-narrowing tombstones (§7.6).

Reads of already-verified content **never block** on the sink (§7.6); only operations that *extend or rotate* access require a fresh completeness proof.

---

## 6. Issuer-side anchoring (closes write-time withholding)

Detection at read time (§5) only helps if a freshly-issued tombstone actually **reaches** the sink — otherwise a malicious app server could simply never write it. So **anchoring is part of issuance**, not a background mirror (`api.md` §7.2 is the app-server convenience copy; this is the authoritative step):

1. An admin issues a control-log record (`api.md` §7.2) — the app server appends it to `control_log` and is *expected* to publish the new head to the sink.
2. The **issuing admin's client independently confirms** the new `head`/`chain_seq` is reflected at `GET {sink}/…/head` (and, where available, that the record appears via 3.2) **before treating the revocation as effective**. If the server failed to anchor, the admin writes to the sink directly (the issuer holds sink-write credentials for control-log records) or escalates — the revocation is not "done" until anchored.
3. Once anchored, every client enforces it within one refresh window (§5/parameters §5).

> This makes the app server unable to silently swallow a tombstone at write time: the human/admin path verifies anchoring, and the sink — not the app server — is the source of truth for the head.

### 6.1 Who may write to the sink
Append-only writes of control-log records are authorized by the **admin** credential set (separate from app-server service credentials). The sink enforces only **append-only ordering** (reject any non-appending write / head rewrite); it does **not** verify record signatures (clients do, §5 step 4). A compromised app server therefore cannot rewrite or reorder the sink, and cannot forge admin-signed records; the worst it can do is *fail to write*, which the issuer catches (§6 step 2) and which fails clients closed (§5 step 1).

---

## 7. Availability & operations
- **Cadence:** the sink re-publishes/anchors its head on each append, ceiling ≤ 60 s (`parameters.md` §5 (a)); clients refresh per §5 (b).
- **Outage semantics:** a sink outage blocks **new wraps / rotations / re-shares** (fail closed) and admin **issuance confirmation** (§6); it never blocks reads of already-verified content and is not a fleet-wide read fuse (§7.6, R9). Run it HA.
- **Independence is the whole point:** do not host the sink on the app server, share its credentials, or let the app operator alone hold the cross-publication key. The two-leg integrity (§1) only holds if the legs are genuinely separate.
- **Auditor reconciliation:** periodically compare the sink's `anchor-log` (3.3) against the independent cross-published medium; a divergence is a compromise alarm (emergency runbook territory, §16.4).

---

## 8. What this does not cover
- The **full audit event stream** (auth attempts, grants, exports, anomalies, §16.5) is also shipped to the sink for detection, but its query/retention interface is operational tooling, not a client hot path — out of scope here (this doc is specifically the **revocation-completeness head**).
- The **Phase-7 key-transparency log** for *directory* equivocation (§7.4) is a related but distinct append-only structure; the transparency-log `anchor_proof` form (§4) is the natural place the two converge later.

---

## Cross-references
`DESIGN.md` §7.6 (sink-anchored tombstones), §16.5 (external sink), §11.7/D28 (key-compromise cutoff by sink position), §11.5a/R28 (reinstatement predicate). `docs/api.md` §7 (server-served chain), `docs/parameters.md` §5 (cadence), `docs/encoding-spec.md` §4 (chained record bytes).
