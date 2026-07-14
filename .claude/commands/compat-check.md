---
description: Review the working diff against the backward-compatibility rule before pushing — which frozen surfaces it touches, whether it can strand an existing user, and run the compat gate.
---

# /compat-check — would this change lock an existing user out?

You are reviewing the **current working diff** against the one rule MaxSecu cannot break:

> **Every upgrade must keep existing users' access intact — account/login, keys, and already-uploaded data. No change may force a re-enroll, re-key, re-upload, re-share, or reset.**

MaxSecu ships to non-technical users on a real VPS with real data, and there is **no admin escape hatch by design**. If an upgrade makes a user's keyblob, DEK wrap or directory binding unreadable, that user's data is gone permanently — nobody can recover it. This review is the cheapest place to catch that.

Do this now, in order. Do not skip to the verdict.

## 1. Get the diff

```
git status --short
git diff --stat HEAD
git diff HEAD
```

If the branch has unpushed commits, include them (`git diff origin/main...HEAD`) — the hook will review the whole pushed range, so you should too.

## 2. Which frozen surfaces does it touch?

Map the changed paths against the frozen list (full table with blast radius: `docs/compat/CHECKLIST.md`):

| Path | Surface |
|---|---|
| `crates/encoding/**` | canonical encoding: 13 `type_id`s + 13 `labels::*` — **every signature ever made** |
| `crates/crypto/**` | HKDF labels, chunk AEAD/AAD, DEK wrap V1/V2, delegation cert, `pin_fp` |
| `crates/client-core/src/keyblob.rs` | `MXKB` v1/v2 — the user's login |
| `crates/client-core/src/seedblob.rs` | `MXD5` seedblob / `recovery_key.blob` — recovery |
| `crates/server/src/http.rs` | the `/v1` JSON wire, both directions |
| `crates/server/src/blob.rs` | `blob_ref` = `hex(file_id)/version/stream_type` |
| `docs/schema.sql`, `migrations/**` | DB schema — existing servers strand |
| `compat/**` | the frozen corpus itself |
| `crates/client-app/src/{config,tofu,contacts,index,recovery_pin,upload_staging,layout,keystore}.rs` | client on-disk state; TOFU reset is a **security** downgrade |

State plainly which of these the diff touches. If it touches **none**, say so and go to step 5 (still run the gate — a change elsewhere can still move a shared constant).

## 3. Ask the access-breaking questions

For each touched surface, answer with evidence from the diff — not with "should be fine":

- **Login:** can a user who enrolled on the *previous* version still unlock their keyblob and log in?
- **Data:** can this code still **open** a file uploaded by the previous version — chunk AEAD, AAD framing, DEK unwrap, all of it?
- **Sharing:** can an *existing* recipient, whose directory binding was published by the previous version, still be shared with?
- **Additive or required?** A new optional field is safe. A field that is now *required* — and that old data does not have — is a break.
- **Repurposed?** Was any `type_id`, label, version byte, magic, tag or field given a new meaning? The old meaning is still out there on disk, signed.
- **Tightened?** Does any check now *reject* data the previous version **wrote**? That is a break **even when it is more secure**. Prefer widening over tightening.
- **Automatic?** Does an existing deployment reach the new state on upgrade with **no user action** — no re-enroll, re-key, re-upload, re-share, reset, or "run this once"? Schema changes: is there a migration, is it idempotent, is it crash-safe, is a new column nullable/defaulted?
- **Retroactive?** If the change makes *newly written* records better, what happens to the records that already exist? (This is exactly what `2a626d6` got wrong: it published ML-KEM keys into new bindings but never republished existing ones, and **every already-enrolled recipient had to re-enroll**.)

## 4. Corpus discipline

- Does the diff **edit or delete** any file under `compat/fixtures/`? If so: **stop.** The corpus is add-only. Editing a fixture to match new code does not make the code compatible — it deletes the evidence that it isn't. Say this bluntly; it is never the fix.
- Does it **add** a fixture? Then it must also extend that area's `corpus.lock`.
- Is this an intentional format change? Then it needs all three: an old-format read path, a NEW fixture, and an entry appended to `docs/compat/LEDGER.md`. Check whether the ledger entry is there; if not, draft it.

## 5. Run the gate

```
powershell -File scripts/compat-gate.ps1
```

Report the real output. A **missing test target is a FAILURE**, not a pass — the gate proves nothing if its tests are gone.

If a test fails, do not propose editing the fixture, relaxing the assertion, or `#[ignore]`. Diagnose which frozen surface moved, and say what an existing user would lose.

## 6. Verdict

Give one, explicitly:

- **SAFE TO PUSH** — no frozen surface touched, or the change is provably additive; gate green. Name the evidence.
- **NEEDS A LEDGER ENTRY** — intentional, compatible format change; the old read path and the new fixture exist, but `docs/compat/LEDGER.md` is not updated. Draft the entry.
- **BREAKS EXISTING USERS — DO NOT PUSH** — name precisely what a user loses (login? files? the ability to be shared with?), and what the compatible version of this change looks like: keep the old path, add the new one alongside it.

If you cannot answer *"a user who enrolled, uploaded and shared on the previous version still works after this upgrade, with no action on their part"* with evidence, the verdict is **DO NOT PUSH**.
