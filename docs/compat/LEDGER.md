# Compat ledger

> **The rule:** *Every upgrade must keep existing users' access intact — account/login, keys, and already-uploaded data. No change may force a re-enroll, re-key, re-upload, re-share, or reset.*

The **append-only** record of every intentional change to a frozen surface (see [`CHECKLIST.md`](CHECKLIST.md) for the eleven of them).

**Append only.** Do not edit or delete an existing entry — including the ones that record mistakes. An entry that says "we broke this" is the reason it does not happen twice.

When you change a format, you write an entry here *and* you keep the old fixture *and* you keep a read path that still opens it. The pre-push hook warns when a frozen surface moves without a ledger entry; the corpus lock and the golden tests are the hard gate.

## Entry template

Copy this block, fill it in, append it to the bottom.

```markdown
## YYYY-MM-DD — <surface> — <one-line summary>

| | |
|---|---|
| **Commit** | `<sha>` |
| **Surface** | <which of the eleven frozen surfaces> |
| **What changed** | <the format delta, in bytes/fields> |
| **Why it is backward compatible** | <the argument, not the assertion> |
| **How OLD data is still read** | <the concrete read path: file:function> |
| **Fixture that proves it** | `compat/fixtures/<area>/<name>` (old) + `<name>` (new) |
| **Automatic on upgrade?** | <yes + how; or the migration id> |
```

---

## 2026-07-14 — client on-disk state (#11) — KNOWN WEAK SPOT: `staging/<file_id>/record.json` is unversioned

| | |
|---|---|
| **Commit** | *(none — recorded, not fixed; frozen as-is by the compat gate)* |
| **Surface** | #11, client on-disk state — `client-app/upload_staging.rs` |
| **What changed** | Nothing. This entry records a **liability**, so that the next person to touch it cannot claim they did not know. |
| **The problem** | A resumable upload's `staging/<file_id>/record.json` is **plain, unversioned, unsealed JSON**. It carries no magic bytes and no version tag, so there is no way for a future reader to tell which shape it is looking at, and no way to reject an unknown one. Every other access-critical format in the system fails closed on an unknown version; this one cannot even ask the question. |
| **Blast radius** | An in-flight resumable upload of a large file. A user who is mid-upload across an upgrade loses that upload's staged state — they must re-upload. That is a "re-upload", which is exactly what the rule forbids. |
| **Why it is frozen as-is** | The gate pins the CURRENT shape with a golden fixture, so today's records keep opening. Retro-versioning it is a change to the format, which is the very thing that needs the version tag first. |
| **What the next change to it MUST do** | Add a version tag **before** changing anything else. Concretely: accept the current tag-less shape as v0 forever (a compat-read path), write the new shape with an explicit version, fail closed on unknown versions, add a fixture for the new shape, and append an entry here. Do not "just add a field" — a tag-less format cannot safely gain a required one. |
| **Fixture** | `compat/fixtures/client-state/` (staging record — frozen at its current, unversioned shape) |

---

## 2026-07-11 — directory binding (#5/#10) — HISTORICAL BREAK (pre-gate): `2a626d6` forced a re-enroll

**This entry records a rule violation that already shipped.** It predates the gate. It is here so it is never repeated, and it is the reason the gate exists.

| | |
|---|---|
| **Commit** | `2a626d6` — "PQ-enrollment publish fix" |
| **Surface** | Directory binding / enrollment (`server/http.rs` `RegisterReq`, client `register.rs`) |
| **What changed** | User enrollment (`POST /v1/users`) never published the client's ML-KEM key into the signed directory binding: the client omitted `mlkem_pub_b64` and the server's `RegisterReq` had no such field, hard-coding `mlkem_pub: None`. Every binding was therefore classical while uploads had already moved to V2 hybrid wraps. The fix added the field on both sides. |
| **Why it was NOT backward compatible** | **It was not retroactive.** New enrollments got a hybrid binding; the bindings of everyone who had *already* enrolled were never republished and stayed classical. Every V2 reshare to them failed with `pq_key_missing`. |
| **Cost to users** | **Every already-enrolled recipient had to RE-ENROLL.** A forced re-enroll is a forbidden outcome under the rule. |
| **What should have happened** | Either (a) republish existing bindings automatically as part of the upgrade — a migration, not a manual step — or (b) keep a working reshare path to a classical binding so that old recipients kept receiving shares while their bindings caught up. Either would have satisfied the rule. Both were skipped because nothing was watching. |
| **Why nothing caught it** | Every test round-tripped: it sealed and opened with the same code, so both sides drifted together and the suite stayed green. There was no test that took an OLD binding and asked whether TODAY's code could still reshare to it. |
| **What now catches it** | The interop matrix (`crates/compat/tests/interop_matrix.rs`): every frozen `Suite` (V1 classical, V2 hybrid) × every frozen keyblob version (v1 classical, v2 PQ) must still unwrap, verify and **reshare**. It reproduces the break as its real symptom — *an old classical binding can no longer participate in a reshare* — not as a missing JSON field. |
| **Status** | Not retro-fixed; the affected recipients have already re-enrolled. Out of scope by decision (design spec §8). Recorded permanently. |
