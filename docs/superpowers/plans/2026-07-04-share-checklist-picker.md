# Share Checklist Picker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the type-one-name-at-a-time `<share-dialog>` with a scrollable, tickable checklist of known contacts (people you've shared with before), while keeping the manual username input as a complement.

**Architecture:** A new identity-sealed `ContactStore` (`username → user_id + fingerprint`) is written on each successful share and read to populate the checklist. The share security path (`reshare_file`) is unchanged — it still re-resolves + D5-verifies + TOFU-checks every recipient at share time. The checklist is purely a faster way to feed usernames into that verified path.

**Tech Stack:** Rust (Tauri commands, `crates/client-app`), TypeScript (vanilla web components, `crates/client-app/ui`). Sealed-at-rest stores use HKDF-from-identity AEAD (mirrors `tofu.rs` / `index.rs`).

**Reference spec:** `docs/superpowers/specs/2026-07-04-share-checklist-picker-design.md`

**Environment note:** `cargo` is not on PATH — prefix Rust commands with `export PATH="$HOME/.cargo/bin:$PATH";`. All Rust commands run from `crates/client-app` (its own cargo workspace). All UI commands run from `crates/client-app/ui`. **Never** run `cargo fmt --all` (pre-existing rustfmt drift is out of scope).

---

## File Structure

- **Create** `crates/client-app/src/contacts.rs` — the `ContactStore` sealed address book (one responsibility: persist + enumerate `username → {user_id, fingerprint}`).
- **Modify** `crates/client-app/src/lib.rs` — register `pub mod contacts;`.
- **Modify** `crates/client-app/src/dto.rs` — add `ContactDto`.
- **Modify** `crates/client-app/src/commands/share.rs` — add `list_contacts` command; thread `&mut ContactStore` through `reshare_inner` / `run_reshare_batch`; upsert on success.
- **Modify** `crates/client-app/src/main.rs` — register the `list_contacts` command.
- **Modify** `crates/client-app/ui/src/core/types.ts` — add the `Contact` interface.
- **Modify** `crates/client-app/ui/src/components/share-dialog.ts` — checklist rework, manual input kept.
- **Modify** `crates/client-app/ui/styles.css` — scrollable checklist styles.
- **Modify** `crates/client-app/ui/src/a11y.test.ts` — checklist a11y assertions.

---

## Task 1: `ContactStore` sealed address book

**Files:**
- Create: `crates/client-app/src/contacts.rs`
- Modify: `crates/client-app/src/lib.rs` (add `pub mod contacts;` after `pub mod content_cache;`)

- [ ] **Step 1: Register the module**

In `crates/client-app/src/lib.rs`, add the line (keep the list alphabetical-ish, place after `pub mod content_cache;`):

```rust
pub mod contacts;
```

- [ ] **Step 2: Write `contacts.rs` with the store + failing tests**

Create `crates/client-app/src/contacts.rs`:

```rust
//! A local, identity-sealed CONTACTS address book — the roster source for the
//! share checklist (`<share-dialog>`). Distinct from the security-critical TOFU
//! pin store ([`crate::tofu`]): this is a UX convenience that maps a username to
//! its `user_id` (so the picker can grey out contacts who already have access)
//! and a display fingerprint. A contact is recorded ONLY when a share to them
//! actually succeeds (see `commands::share::run_reshare_batch`).
//!
//! # At-rest confidentiality + integrity
//! Sealed on disk at `<dir>/contacts/contacts.bin` with an AEAD key derived
//! (HKDF-SHA256) from the unlocked identity — the SAME identity-derived sealing
//! the TOFU store and local search index use. Confidential + integrity-protected
//! at rest and unreadable by any other identity. Fails closed on a decrypt/parse
//! error (the read command degrades that to an empty roster — never blocks
//! sharing).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use maxsecu_client_core::Identity;

use crate::error::UiError;

/// Domain-separation label for the contacts-store sealing key + AEAD aad.
/// Distinct from the TOFU and index labels so all three sealed stores use
/// unrelated keys.
const CONTACTS_LABEL: &[u8] = b"MaxSecu-contacts-v1";

/// One enumerated contact (roster row). `fingerprint` is the full 32-byte key
/// fingerprint; the read command truncates it for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub username: String,
    pub user_id: [u8; 16],
    pub fingerprint: [u8; 32],
}

/// On-disk (pre-seal) shape: username → hex-encoded record, for a stable,
/// debuggable serialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ContactsMap {
    /// username → {user_id hex16, fingerprint hex32}.
    contacts: BTreeMap<String, ContactRecordDisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContactRecordDisk {
    user_id: String,    // 32 lowercase-hex chars (16 bytes)
    fingerprint: String, // 64 lowercase-hex chars (32 bytes)
}

/// The identity-sealed local contacts store. Holds ONLY the derived sealing key
/// and the in-RAM map — never the `Identity`, and nothing crosses the Tauri seam.
pub struct ContactStore {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    map: BTreeMap<String, (/*user_id*/ [u8; 16], /*fingerprint*/ [u8; 32])>,
}

impl ContactStore {
    /// Open (load + decrypt) the sealed store under `<dir>/contacts/contacts.bin`,
    /// or an empty store if absent. Fails closed (`untrusted`) on a decrypt/parse
    /// error (corrupt / foreign identity) — never silently discards contacts.
    pub fn open(dir: &Path, identity: &Identity) -> Result<Self, UiError> {
        let key = seal_key(identity);
        let path = dir.join("contacts").join("contacts.bin");
        let map = match std::fs::read(&path) {
            Ok(sealed) => decrypt_map(&key, &sealed)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => {
                return Err(UiError::new(
                    "untrusted",
                    "The contacts store could not be read.",
                ))
            }
        };
        Ok(ContactStore { path, key, map })
    }

    /// Every contact, sorted by username (the `BTreeMap` iteration order).
    pub fn list(&self) -> Vec<Contact> {
        self.map
            .iter()
            .map(|(username, (user_id, fingerprint))| Contact {
                username: username.clone(),
                user_id: *user_id,
                fingerprint: *fingerprint,
            })
            .collect()
    }

    /// Insert or replace the contact for `username` and persist atomically.
    /// Idempotent: re-sharing to the same user simply refreshes the record.
    pub fn upsert(
        &mut self,
        username: &str,
        user_id: [u8; 16],
        fingerprint: [u8; 32],
    ) -> Result<(), UiError> {
        // Persist a CANDIDATE map first; only commit to `self.map` after the atomic
        // on-disk write succeeds (mirrors `tofu.rs` — never an in-RAM entry that was
        // never written to disk).
        let mut candidate = self.map.clone();
        candidate.insert(username.to_owned(), (user_id, fingerprint));
        self.persist(&candidate)?;
        self.map = candidate;
        Ok(())
    }

    /// Encrypt + persist `map` atomically (seal → temp → `sync_all` → rename), so a
    /// crash mid-write leaves the OLD sealed blob intact rather than a torn file
    /// that would fail-closed on the next `open`.
    fn persist(
        &self,
        map: &BTreeMap<String, ([u8; 16], [u8; 32])>,
    ) -> Result<(), UiError> {
        let dir = self.path.parent().ok_or_else(untrusted_write)?;
        std::fs::create_dir_all(dir).map_err(|_| untrusted_write())?;
        let on_disk = ContactsMap {
            contacts: map
                .iter()
                .map(|(u, (id, fp))| {
                    (
                        u.clone(),
                        ContactRecordDisk {
                            user_id: hex(id),
                            fingerprint: hex(fp),
                        },
                    )
                })
                .collect(),
        };
        let plain = serde_json::to_vec(&on_disk).map_err(|_| untrusted_write())?;
        let nonce = maxsecu_crypto::random_array::<12>();
        let ct = maxsecu_crypto::seal(&self.key, &nonce, CONTACTS_LABEL, &plain);
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        let tmp = self.path.with_extension("bin.tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(|_| untrusted_write())?;
            std::io::Write::write_all(&mut f, &out).map_err(|_| untrusted_write())?;
            f.sync_all().map_err(|_| untrusted_write())?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|_| untrusted_write())
    }
}

/// Derive the 32-byte sealing key from the unlocked identity (a stable TCB
/// secret), domain-separated so it is unrelated to any wrap, TOFU, or index key.
fn seal_key(identity: &Identity) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(maxsecu_crypto::hkdf_sha256_32(
        &identity.enc_secret().expose_bytes(),
        CONTACTS_LABEL,
    ))
}

/// Decrypt + decode a sealed `nonce ‖ ct` blob into the in-RAM map.
fn decrypt_map(
    key: &[u8; 32],
    sealed: &[u8],
) -> Result<BTreeMap<String, ([u8; 16], [u8; 32])>, UiError> {
    let untrusted = || UiError::new("untrusted", "The contacts store is corrupt.");
    if sealed.len() < 12 {
        return Err(untrusted());
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| untrusted())?;
    let plain =
        maxsecu_crypto::open(key, &nonce, CONTACTS_LABEL, ct).map_err(|_| untrusted())?;
    let on_disk: ContactsMap = serde_json::from_slice(&plain).map_err(|_| untrusted())?;
    let mut map = BTreeMap::new();
    for (u, rec) in on_disk.contacts {
        let id = unhex::<16>(&rec.user_id).ok_or_else(untrusted)?;
        let fp = unhex::<32>(&rec.fingerprint).ok_or_else(untrusted)?;
        map.insert(u, (id, fp));
    }
    Ok(map)
}

fn untrusted_write() -> UiError {
    UiError::new("untrusted", "The contacts store could not be written.")
}

/// Lowercase hex of a byte slice.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse `2*N` lowercase-hex chars into `[u8; N]` (`None` if malformed).
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxcontacts_{}_{}",
            std::process::id(),
            maxsecu_crypto::random_array::<8>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    const ID_A: [u8; 16] = [0x0A; 16];
    const FP_A: [u8; 32] = [0xF1; 32];
    const ID_B: [u8; 16] = [0x0B; 16];
    const FP_B: [u8; 32] = [0xF2; 32];

    #[test]
    fn upsert_then_list_is_sorted_and_roundtrips() {
        let dir = tmp_dir();
        let id = Identity::generate();
        let mut store = ContactStore::open(&dir, &id).unwrap();

        store.upsert("bob", ID_B, FP_B).unwrap();
        store.upsert("alice", ID_A, FP_A).unwrap();

        let list = store.list();
        assert_eq!(list.len(), 2);
        // BTreeMap ⇒ username-sorted: alice before bob.
        assert_eq!(list[0].username, "alice");
        assert_eq!(list[0].user_id, ID_A);
        assert_eq!(list[0].fingerprint, FP_A);
        assert_eq!(list[1].username, "bob");

        // Upsert replaces (idempotent), never duplicates.
        store.upsert("alice", ID_B, FP_B).unwrap();
        let list = store.list();
        assert_eq!(list.len(), 2, "upsert replaces, not appends");
        assert_eq!(list[0].user_id, ID_B, "alice's record was replaced");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persists_sealed_across_reopen_and_username_not_plaintext() {
        let dir = tmp_dir();
        let id = Identity::generate();
        {
            let mut store = ContactStore::open(&dir, &id).unwrap();
            store.upsert("carol", ID_A, FP_A).unwrap();
        }
        // On-disk bytes must not contain the plaintext username.
        let raw = std::fs::read(dir.join("contacts").join("contacts.bin")).unwrap();
        assert!(
            !raw.windows(5).any(|w| w == b"carol"),
            "username must be sealed"
        );

        // Reopen with the SAME identity sees the contact.
        let reopened = ContactStore::open(&dir, &id).unwrap();
        let list = reopened.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].username, "carol");

        // A DIFFERENT identity cannot read the sealed store (fails closed).
        let other = Identity::generate();
        assert!(ContactStore::open(&dir, &other).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_or_short_store_fails_closed_on_open() {
        let dir = tmp_dir();
        let id = Identity::generate();
        let cdir = dir.join("contacts");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(cdir.join("contacts.bin"), b"not-a-sealed-blob").unwrap();
        assert_eq!(
            ContactStore::open(&dir, &id).err().unwrap().code,
            "untrusted"
        );
        std::fs::write(cdir.join("contacts.bin"), b"short").unwrap();
        assert_eq!(
            ContactStore::open(&dir, &id).err().unwrap().code,
            "untrusted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [ ] **Step 3: Run the tests — verify they pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test contacts:: 2>&1 | tail -20`
Expected: `test result: ok.` — the three `contacts::tests::*` pass (compilation confirms the `maxsecu_crypto::{seal,open,hkdf_sha256_32,random_array}` and `Identity::{enc_secret}` APIs match, as used identically in `tofu.rs`).

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/src/contacts.rs crates/client-app/src/lib.rs
git commit -m "feat(share): identity-sealed ContactStore address book

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `ContactDto` + `list_contacts` command

**Files:**
- Modify: `crates/client-app/src/dto.rs` (add `ContactDto` after `ResolvedRecipientDto`, ~line 257)
- Modify: `crates/client-app/src/commands/share.rs` (add `list_contacts` near `list_file_recipients`, end of file before tests)
- Modify: `crates/client-app/src/main.rs` (register command after line 72)

- [ ] **Step 1: Add `ContactDto` to `dto.rs`**

In `crates/client-app/src/dto.rs`, after the `ResolvedRecipientDto` struct (ends ~line 257), add:

```rust
/// A known contact (roster row) for the share checklist — display-only, no key
/// material. `already_shared` is filled in by the dialog (cross-checked against
/// `list_file_recipients`), NOT by the store; the command always returns `false`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ContactDto {
    pub username: String,
    pub user_id: String,     // hex16, opaque to the UI
    pub fingerprint: String, // first 8 bytes hex, display-only
}
```

- [ ] **Step 2: Add a serialization test for the DTO**

In `crates/client-app/src/dto.rs`, inside the existing `reshare_dto_tests` module (near the other DTO tests, ~line 313), add:

```rust
#[test]
fn contact_dto_serializes_all_fields() {
    let dto = ContactDto {
        username: "bob".into(),
        user_id: "ab".repeat(8),
        fingerprint: "deadbeefcafebabe".into(),
    };
    let v: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&dto).unwrap()).unwrap();
    assert_eq!(v["username"], "bob");
    assert_eq!(v["user_id"], "ab".repeat(8));
    assert_eq!(v["fingerprint"], "deadbeefcafebabe");
}
```

- [ ] **Step 3: Add the `list_contacts` command to `share.rs`**

In `crates/client-app/src/commands/share.rs`, first extend the `crate::dto` import (currently imports `ReshareOutcomeDto, ReshareRequest, ResolveRecipientRequest, ResolvedRecipientDto`) to also import `ContactDto`:

```rust
use crate::dto::{
    ContactDto, ReshareOutcomeDto, ReshareRequest, ResolveRecipientRequest,
    ResolvedRecipientDto,
};
```

Then add this command just BEFORE the `#[cfg(test)]` line at the end of the file:

```rust
// ---------------------------------------------------------------------------
// list_contacts — the roster source for the share checklist
// ---------------------------------------------------------------------------

/// `list_contacts` — the local address book (people you've successfully shared
/// with), the roster for the share checklist. Reads the identity-sealed
/// [`crate::contacts::ContactStore`].
///
/// FAILS OPEN to an empty roster: a not-yet-signed-in identity, an absent store,
/// or any store-open error all degrade to `Ok(vec![])` so the dialog is NEVER
/// blocked (manual username input remains fully available). `fingerprint` is the
/// first 8 bytes hex (matching `resolved_recipient_dto`). `already_shared` is not
/// part of this DTO — the dialog computes access itself via `list_file_recipients`.
#[tauri::command]
pub async fn list_contacts(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
) -> Result<Vec<ContactDto>, UiError> {
    let guard = session.0.lock().await;
    let Some(identity) = guard.identity.as_ref() else {
        return Ok(Vec::new()); // not signed in → empty roster, fail-open
    };
    let store = match crate::contacts::ContactStore::open(&dir.0, identity) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()), // corrupt/unreadable → empty, never block
    };
    Ok(store
        .list()
        .into_iter()
        .map(|c| ContactDto {
            username: c.username,
            user_id: hex(&c.user_id),
            fingerprint: hex(&c.fingerprint[..8]),
        })
        .collect())
}
```

- [ ] **Step 4: Register the command in `main.rs`**

In `crates/client-app/src/main.rs`, after line 72 (`...share::list_file_recipients,`), add:

```rust
            maxsecu_client_app::commands::share::list_contacts,
```

- [ ] **Step 5: Run tests — verify they pass and it compiles**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test contact_dto_serializes 2>&1 | tail -20 && cargo build 2>&1 | tail -5`
Expected: the DTO test passes; `cargo build` finishes without errors (confirms the command + registration compile).

- [ ] **Step 6: Commit**

```bash
git add crates/client-app/src/dto.rs crates/client-app/src/commands/share.rs crates/client-app/src/main.rs
git commit -m "feat(share): list_contacts command + ContactDto (fail-open roster)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Record contacts on a successful share

**Files:**
- Modify: `crates/client-app/src/commands/share.rs` (`reshare_inner`, `run_reshare_batch`, and the three in-module test call sites)

- [ ] **Step 1: Open the `ContactStore` in `reshare_inner`'s identity block**

In `crates/client-app/src/commands/share.rs`, find the Step 3 block in `reshare_inner` that currently returns `(dek, tofu)`:

```rust
    let (dek, mut tofu) = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        let dek = recover_own_dek(&view, file_id, identity, my_id)?;
        let tofu = TofuStore::open(&dir.0, identity)?;
        (dek, tofu)
    }; // guard drops here — identity no longer borrowed
```

Replace it with (also open the contacts store under the same borrow):

```rust
    let (dek, mut tofu, mut contacts) = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        let dek = recover_own_dek(&view, file_id, identity, my_id)?;
        let tofu = TofuStore::open(&dir.0, identity)?;
        let contacts = crate::contacts::ContactStore::open(&dir.0, identity)?;
        (dek, tofu, contacts)
    }; // guard drops here — identity no longer borrowed
```

- [ ] **Step 2: Pass `&mut contacts` into `run_reshare_batch`**

In the same function, the `run_reshare_batch(...)` call currently passes `&mut tofu,` before `&req.recipient_usernames,`. Add `&mut contacts,` immediately after `&mut tofu,`:

```rust
        &mut tofu,
        &mut contacts,
        &req.recipient_usernames,
```

- [ ] **Step 3: Add the `contacts` parameter to `run_reshare_batch`**

In the `run_reshare_batch` signature, add the parameter right after the `tofu: &mut TofuStore,` line:

```rust
    tofu: &mut TofuStore,
    contacts: &mut crate::contacts::ContactStore,
    recipients: &[String],
```

- [ ] **Step 4: Upsert on the successful-POST branch**

In `run_reshare_batch`, find the successful POST arm (currently):

```rust
            Ok((st, _)) if st == hyper::StatusCode::CREATED => {
                push_outcome(&mut outcomes, emit, file_id_hex, uname, true, None);
            }
```

Replace it with (record the contact best-effort BEFORE recording the outcome; `author` is in scope from the resolve step above):

```rust
            Ok((st, _)) if st == hyper::StatusCode::CREATED => {
                // Best-effort: remember this recipient as a contact (roster for the
                // share checklist). A store-write failure must NEVER turn a
                // successful share into a failure — swallow it (mirrors the
                // best-effort index write in `feed.rs`).
                let fp = crate::tofu::key_fingerprint(&author.enc_pub, &author.sig_pub);
                let _ = contacts.upsert(uname, author.user_id, fp);
                push_outcome(&mut outcomes, emit, file_id_hex, uname, true, None);
            }
```

- [ ] **Step 5: Update the three in-module test call sites**

In the `#[cfg(test)]` module of `share.rs` there are three `run_reshare_batch(...)` calls (in `mixed_batch_is_per_recipient_isolated_never_drops_a_row`, `post_failure_is_isolated_from_a_succeeding_recipient_in_one_batch`, and `changed_pinned_key_blocks_the_share_but_first_sighting_proceeds`). Each currently passes `&mut empty_tofu(),` or `&mut tofu,` followed by `&recipients,`. Insert `&mut empty_contacts(),` between the tofu argument and `&recipients,` in **all three**. For example the first becomes:

```rust
            &mut empty_tofu(),
            &mut empty_contacts(),
            &recipients,
```

And in `changed_pinned_key_blocks_the_share_but_first_sighting_proceeds` (which uses a named `&mut tofu,`):

```rust
            &mut tofu,
            &mut empty_contacts(),
            &recipients,
```

- [ ] **Step 6: Add the `empty_contacts` test helper**

In the `#[cfg(test)]` module of `share.rs`, next to the existing `empty_tofu()` helper, add:

```rust
    /// A fresh, empty ContactStore in a unique temp dir (so a batch test starts
    /// with no contacts). Left in OS temp space; these are ephemeral test runs.
    fn empty_contacts() -> crate::contacts::ContactStore {
        let dir = std::env::temp_dir().join(format!(
            "mxcontacts_share_{}_{}",
            std::process::id(),
            maxsecu_crypto::random_array::<8>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        crate::contacts::ContactStore::open(&dir, &Identity::generate()).unwrap()
    }
```

- [ ] **Step 7: Add a test that success records a contact and failure does not**

In the same test module, add a new test. It drives `run_reshare_batch` with one resolvable recipient (`alice`, whose `/wraps` POST returns 201) and one unresolvable (`ghost`), against a shared `ContactStore`, then asserts only `alice` was recorded:

```rust
    /// A successful share RECORDS the recipient as a contact; an unresolvable /
    /// failed recipient records NOTHING. Uses the same `spawn_router` stub as the
    /// isolation test (alice → 201 wrap; ghost → default 404 resolve).
    #[tokio::test]
    async fn successful_share_records_a_contact_failed_does_not() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();

        let (_alice_sk, alice_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let tombstones = empty_tombstones();
        let session = session_with_identity();

        let file_id_hex: String = FILE_ID.iter().map(|b| format!("{b:02x}")).collect();

        let mut routes = HashMap::new();
        routes.insert(
            "/v1/directory/alice".to_owned(),
            (hyper::StatusCode::OK, alice_binding(&d5, alice_pk.to_bytes())),
        );
        routes.insert(
            format!("/v1/files/{file_id_hex}/wraps"),
            (hyper::StatusCode::CREATED, "{}".to_owned()),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;

        let mut contacts = empty_contacts();
        let recipients = vec!["ghost".to_owned(), "alice".to_owned()];
        let outcomes = run_reshare_batch(
            &mut sender,
            "localhost",
            "tok",
            &file_id_hex,
            FILE_ID,
            1,
            dek.commit(),
            Suite::V1,
            GRANTER_ID,
            &dek,
            &tombstones,
            &session,
            &mut empty_tofu(),
            &mut contacts,
            &recipients,
            &verifier,
            &mut trust,
            NOW,
            &|_| {},
        )
        .await;

        assert_eq!(outcomes.len(), 2);
        assert!(!outcomes[0].ok, "ghost fails");
        assert!(outcomes[1].ok, "alice succeeds");

        // Only the successful recipient (alice) was recorded — ghost never resolved.
        let list = contacts.list();
        assert_eq!(list.len(), 1, "only the successful share is a contact");
        assert_eq!(list[0].username, "alice");
        // alice's binding uses user_id [0x0A; 16] (see `alice_binding`).
        assert_eq!(list[0].user_id, [0x0A; 16]);
    }
```

- [ ] **Step 8: Run the share tests — verify all pass**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test --lib commands::share:: 2>&1 | tail -25`
Expected: all share tests pass, including the new `successful_share_records_a_contact_failed_does_not` and the three updated batch-isolation tests.

- [ ] **Step 9: Commit**

```bash
git add crates/client-app/src/commands/share.rs
git commit -m "feat(share): record a contact on each successful share (best-effort)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: UI types + checklist dialog rework

**Files:**
- Modify: `crates/client-app/ui/src/core/types.ts` (add `Contact` interface after `ResolvedRecipient`, ~line 64)
- Modify: `crates/client-app/ui/src/components/share-dialog.ts` (rework)

- [ ] **Step 1: Add the `Contact` interface to `types.ts`**

In `crates/client-app/ui/src/core/types.ts`, after the `ResolvedRecipient` interface (~line 64), add:

```typescript
// A known contact (roster row) for the share checklist — mirrors ContactDto.
export interface Contact {
  username: string;
  user_id: string; // hex16, opaque to the UI
  fingerprint: string; // first 8 bytes hex, display-only
}
```

- [ ] **Step 2: Rework `share-dialog.ts`**

Rewrite `crates/client-app/ui/src/components/share-dialog.ts`. Key changes from the current file:
1. Add `Contact` to the `../core/types.ts` import.
2. Extend the `Row` interface with `selected: boolean` and a new `"contact"` status, plus a `disabled` flag.
3. Replace the `<form>`-only body with: a **manual add form** (kept) ABOVE a **scrollable checklist** `<ul id="sd-rows" class="sd-roster">`.
4. On `openFor`, load contacts + already-shared in parallel and seed the checklist.
5. Render each row as a `<label>` wrapping a `<input type="checkbox">` + username (+ short fingerprint + badge). Already-shared rows: checkbox `disabled`, unchecked-by-intent, greyed with the "Already has access" note.
6. `share()` collects usernames of all CHECKED rows (statuses `contact` or `verified`).

Replace the ENTIRE file contents with:

```typescript
import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { getUsername } from "../core/session.ts";
import { toast } from "../core/toast.ts";
import type { Contact, ResolvedRecipient, ReshareOutcome } from "../core/types.ts";
import "./state-badge.ts";

// <share-dialog> — the T4 multi-recipient sharing picker, now a tickable
// CHECKLIST of known contacts (people you've successfully shared with before,
// from list_contacts) PLUS the kept manual add-by-username input. Ticking a
// contact is free (no network); the share security path (reshare_file) still
// re-resolves + D5-verifies + TOFU-checks EVERY selected recipient at share
// time, so the checklist is only a faster way to feed usernames into that
// verified path. A contact who already has access is shown greyed + disabled.
//
// FAIL-CLOSED BY CONSTRUCTION is preserved: a manually-typed name still only
// becomes shareable once resolve_recipient RESOLVED it; a rejected resolve is
// rendered and dropped. Every authed/D5 call is routed through the shared
// serial() FIFO queue. No secrets cross this component — only usernames, hex
// ids, fingerprints, booleans, and sanitized codes.

type RowStatus =
  | "contact" // known contact, tickable, not yet verified this session
  | "pending"
  | "verified"
  | "rejected"
  | "sharing"
  | "shared"
  | "share-failed";

interface Row {
  key: string; // resolved user_id when known, else a synthetic per-attempt id
  username: string;
  status: RowStatus;
  selected: boolean; // checkbox state
  fingerprint?: string;
  alreadyShared?: boolean; // has access → checkbox disabled
  message?: string;
  code?: string | null;
}

export class ShareDialog extends HTMLElement {
  private fileId = "";
  private invoker: HTMLElement | null = null;
  private rows: Row[] = [];
  private alreadySharedIds = new Set<string>();
  private counter = 0;
  private keydownHandler = (e: KeyboardEvent) => this.onKeydown(e);

  connectedCallback() {
    this.hidden = true;
    this.innerHTML = `
      <div class="share-overlay">
        <div
          class="share-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby="sd-h"
          tabindex="-1"
        >
          <div class="share-head">
            <h2 id="sd-h">Share with people</h2>
            <button type="button" id="sd-close" class="secondary">Close</button>
          </div>
          <form id="sd-add-form">
            <label>
              Add someone by username
              <input type="text" id="sd-username" name="username" autocomplete="off" />
            </label>
            <button type="submit" id="sd-add-btn">Add</button>
          </form>
          <p id="sd-status" role="status" aria-live="polite"></p>
          <ul id="sd-rows" class="sd-roster" aria-label="People to share with" aria-live="polite"></ul>
          <div class="share-actions">
            <button type="button" id="sd-share-btn" disabled>Share</button>
          </div>
        </div>
      </div>`;

    const overlay = this.querySelector(".share-overlay") as HTMLElement;
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) this.close();
    });
    (this.querySelector("#sd-close") as HTMLButtonElement).addEventListener("click", () => this.close());
    (this.querySelector("#sd-add-form") as HTMLFormElement).addEventListener("submit", (e) => {
      e.preventDefault();
      const input = this.querySelector("#sd-username") as HTMLInputElement;
      const username = input.value.trim();
      if (!username) return;
      input.value = "";
      void this.addRecipient(username);
    });
    (this.querySelector("#sd-share-btn") as HTMLButtonElement).addEventListener("click", () => void this.share());
  }

  disconnectedCallback() {
    document.removeEventListener("keydown", this.keydownHandler);
  }

  /** Open the dialog for `fileId`; `invoker` regains focus when it closes. */
  openFor(fileId: string, invoker: HTMLElement) {
    this.fileId = fileId;
    this.invoker = invoker;
    this.rows = [];
    this.alreadySharedIds = new Set();
    this.renderRows();
    this.updateShareEnabled();
    (this.querySelector("#sd-status") as HTMLElement).textContent = "";
    this.hidden = false;
    document.removeEventListener("keydown", this.keydownHandler);
    document.addEventListener("keydown", this.keydownHandler);
    (this.querySelector("#sd-username") as HTMLInputElement).focus();

    // Load the contacts roster + already-access set, then seed the checklist.
    void this.loadRoster();
  }

  close() {
    this.hidden = true;
    document.removeEventListener("keydown", this.keydownHandler);
    this.invoker?.focus();
  }

  private onKeydown(e: KeyboardEvent) {
    if (this.hidden) return;
    if (e.key === "Escape") {
      e.preventDefault();
      this.close();
      return;
    }
    if (e.key === "Tab") this.trapTab(e);
  }

  private trapTab(e: KeyboardEvent) {
    const focusable = this.focusableElements();
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    if (e.shiftKey) {
      if (active === first || !focusable.includes(active as HTMLElement)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (active === last || !focusable.includes(active as HTMLElement)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  private focusableElements(): HTMLElement[] {
    const panel = this.querySelector(".share-panel") as HTMLElement;
    return Array.from(
      panel.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((el) => el.offsetParent !== null || el === document.activeElement);
  }

  /** Load contacts + the already-access set, then build the checklist. Fails
   * open: an empty roster / failed cross-check still leaves a working dialog. */
  private async loadRoster() {
    let contacts: Contact[] = [];
    try {
      contacts = await serial(() => call<Contact[]>("list_contacts", {}));
    } catch {
      contacts = []; // fail-open: manual input still works
    }
    try {
      const ids = await serial(() => call<string[]>("list_file_recipients", { fileId: this.fileId }));
      this.alreadySharedIds = new Set(ids);
    } catch {
      // fail-open: "unknown who has access" — no rows disabled.
    }
    // Seed contact rows, skipping any username already present (e.g. a manual add
    // that landed while this was loading). Self is never a contact, but guard anyway.
    const me = getUsername();
    for (const c of contacts) {
      if (me && c.username.toLowerCase() === me.toLowerCase()) continue;
      if (this.rows.some((r) => r.username.toLowerCase() === c.username.toLowerCase())) continue;
      const already = this.alreadySharedIds.has(c.user_id);
      this.rows.push({
        key: c.user_id,
        username: c.username,
        status: "contact",
        selected: false,
        fingerprint: c.fingerprint,
        alreadyShared: already,
      });
    }
    this.renderRows();
    this.updateShareEnabled();
  }

  private async addRecipient(username: string) {
    const status = this.querySelector("#sd-status") as HTMLElement;

    const me = getUsername();
    if (me && username.toLowerCase() === me.toLowerCase()) {
      this.rows.push({
        key: `rejected:${this.counter++}`,
        username,
        status: "rejected",
        selected: false,
        message: "You are already the owner.",
      });
      this.renderRows();
      return;
    }

    // If the username is already a row, just tick it (unless it already has access).
    const existingRow = this.rows.find(
      (r) => r.username.toLowerCase() === username.toLowerCase() && r.status !== "rejected",
    );
    if (existingRow) {
      if (!existingRow.alreadyShared) existingRow.selected = true;
      status.textContent = `${username} is already in the list.`;
      this.renderRows();
      this.updateShareEnabled();
      return;
    }

    const pendingKey = `pending:${this.counter++}`;
    this.rows.push({ key: pendingKey, username, status: "pending", selected: true });
    this.renderRows();

    try {
      const resolved = await serial(() =>
        call<ResolvedRecipient>("resolve_recipient", { req: { username } }),
      );
      const idx = this.rows.findIndex((r) => r.key === pendingKey);

      // Dedupe by resolved user_id: collapse onto an existing row for the same account.
      const dupe = this.rows.find((r) => r.key === resolved.user_id && r.status !== "rejected");
      if (dupe) {
        if (idx >= 0) this.rows.splice(idx, 1);
        if (!dupe.alreadyShared) dupe.selected = true;
        status.textContent = `${username} resolves to an account already in the list.`;
        this.renderRows();
        this.updateShareEnabled();
        return;
      }

      const already = resolved.already_shared || this.alreadySharedIds.has(resolved.user_id);
      const row: Row = {
        key: resolved.user_id,
        username: resolved.username,
        status: "verified",
        selected: !already,
        fingerprint: resolved.fingerprint,
        alreadyShared: already,
      };
      if (idx >= 0) this.rows[idx] = row;
      else this.rows.push(row);
      status.textContent = "";
    } catch (x) {
      const idx = this.rows.findIndex((r) => r.key === pendingKey);
      const msg = errMessage(x, "This user's identity could not be verified.");
      if (idx >= 0) {
        this.rows[idx] = { key: `rejected:${this.counter++}`, username, status: "rejected", selected: false, message: msg };
      }
    }
    this.renderRows();
    this.updateShareEnabled();
  }

  private toggleRow(key: string, checked: boolean) {
    const row = this.rows.find((r) => r.key === key);
    if (row && !row.alreadyShared) row.selected = checked;
    this.updateShareEnabled();
  }

  private updateShareEnabled() {
    const btn = this.querySelector("#sd-share-btn") as HTMLButtonElement;
    btn.disabled = !this.rows.some(
      (r) => r.selected && (r.status === "contact" || r.status === "verified"),
    );
  }

  private async share() {
    const selected = this.rows.filter(
      (r) => r.selected && (r.status === "contact" || r.status === "verified"),
    );
    const usernames = selected.map((r) => r.username);
    if (usernames.length === 0) return;
    const btn = this.querySelector("#sd-share-btn") as HTMLButtonElement;
    btn.disabled = true;
    for (const r of selected) r.status = "sharing";
    this.renderRows();

    try {
      const outcomes = await serial(() =>
        call<ReshareOutcome[]>("reshare_file", {
          req: { file_id: this.fileId, recipient_usernames: usernames },
        }),
      );
      this.applyOutcomes(outcomes);
    } catch (x) {
      const msg = errMessage(x, "Could not share this item right now.");
      for (const r of this.rows) {
        if (r.status === "sharing") {
          r.status = "share-failed";
          r.message = msg;
          r.code = null;
        }
      }
      toast("error", msg);
    }
    this.renderRows();
    this.updateShareEnabled();
  }

  private async retryRow(key: string) {
    const row = this.rows.find((r) => r.key === key);
    if (!row) return;
    row.status = "sharing";
    this.renderRows();
    try {
      const outcomes = await serial(() =>
        call<ReshareOutcome[]>("reshare_file", {
          req: { file_id: this.fileId, recipient_usernames: [row.username] },
        }),
      );
      this.applyOutcomes(outcomes);
    } catch (x) {
      row.status = "share-failed";
      row.message = errMessage(x, "Could not share this item right now.");
      row.code = null;
    }
    this.renderRows();
  }

  private applyOutcomes(outcomes: ReshareOutcome[]) {
    for (const o of outcomes) {
      const row = this.rows.find((r) => r.username === o.username && r.status === "sharing");
      if (!row) continue;
      if (o.ok) {
        row.status = "shared";
        row.selected = false;
        row.alreadyShared = true;
        row.message = undefined;
        row.code = null;
      } else {
        row.status = "share-failed";
        row.code = o.code ?? null;
        row.message = o.code ? `Failed: ${o.code}` : "Sharing failed.";
      }
    }
  }

  private renderRows() {
    const ul = this.querySelector("#sd-rows") as HTMLUListElement;

    const active = document.activeElement as HTMLElement | null;
    const actedRow = active && ul.contains(active) ? active.closest(".sd-row") : null;
    const actedRowKey = actedRow?.getAttribute("data-row") ?? null;

    ul.replaceChildren();
    for (const row of this.rows) {
      const li = document.createElement("li");
      li.className = "sd-row";
      li.setAttribute("data-row", row.key);

      // A checkbox is offered only for tickable rows (contact/verified). Rejected
      // and terminal (sharing/shared/share-failed) rows show status text instead.
      const tickable = row.status === "contact" || row.status === "verified";
      if (tickable) {
        const label = document.createElement("label");
        label.className = "sd-check";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = row.selected && !row.alreadyShared;
        cb.disabled = !!row.alreadyShared;
        cb.addEventListener("change", () => this.toggleRow(row.key, cb.checked));
        const name = document.createElement("span");
        name.className = "sd-username";
        name.textContent = row.username;
        label.appendChild(cb);
        label.appendChild(name);
        li.appendChild(label);
      } else {
        const name = document.createElement("span");
        name.className = "sd-username";
        name.textContent = row.username;
        li.appendChild(name);
      }

      if (row.fingerprint) {
        const fp = document.createElement("code");
        fp.className = "sd-fingerprint";
        fp.textContent = row.fingerprint;
        li.appendChild(fp);
      }

      const badge = document.createElement("state-badge");
      const { state, label: badgeLabel } = badgeFor(row);
      badge.setAttribute("state", state);
      badge.setAttribute("label", badgeLabel);
      li.appendChild(badge);

      if (row.alreadyShared && row.status !== "shared") {
        const note = document.createElement("span");
        note.className = "sd-note";
        note.textContent = "Already has access";
        li.appendChild(note);
      }

      if (row.status === "share-failed") {
        const retry = document.createElement("button");
        retry.type = "button";
        retry.className = "sd-retry";
        retry.textContent = "Retry";
        retry.addEventListener("click", () => void this.retryRow(row.key));
        li.appendChild(retry);
      }

      ul.appendChild(li);
    }

    if (actedRowKey !== null) {
      const rebuilt = Array.from(ul.children).find(
        (li) => (li as HTMLElement).getAttribute("data-row") === actedRowKey,
      ) as HTMLElement | undefined;
      const target =
        rebuilt?.querySelector<HTMLButtonElement | HTMLInputElement>("button, input") ??
        (this.querySelector("#sd-username") as HTMLInputElement);
      target.focus();
    }
  }
}

function badgeFor(row: Row): { state: string; label: string } {
  switch (row.status) {
    case "contact":
      return { state: "ready", label: "Contact" };
    case "pending":
      return { state: "verifying", label: "Verifying…" };
    case "verified":
      return { state: "verified", label: "Verified" };
    case "rejected":
      return { state: "failed", label: `Rejected: ${row.message ?? "unverifiable"}` };
    case "sharing":
      return { state: "fetching", label: "Sharing…" };
    case "shared":
      return { state: "ready", label: "Shared" };
    case "share-failed":
      return { state: "failed", label: row.message ?? "Failed" };
  }
}

function errMessage(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return fallback;
}

customElements.define("share-dialog", ShareDialog);
```

- [ ] **Step 3: Typecheck the UI**

Run: `cd crates/client-app/ui && npm run typecheck 2>&1 | tail -20`
Expected: no type errors (exit 0). Confirms the `Contact` import, the extended `Row` shape, and all handlers type-check.

- [ ] **Step 4: Build the UI bundle**

Run: `cd crates/client-app/ui && npm run build 2>&1 | tail -5`
Expected: esbuild completes, `dist/main.js` written, no errors.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/types.ts crates/client-app/ui/src/components/share-dialog.ts
git commit -m "feat(share): tickable contacts checklist in <share-dialog>, manual input kept

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Scrollable checklist styles

**Files:**
- Modify: `crates/client-app/ui/styles.css` (extend the existing `.sd-*` share-dialog rules)

- [ ] **Step 1: Inspect the existing share-dialog styles**

Run: `grep -n "sd-row\|sd-roster\|sd-username\|share-panel\|sd-check\|sd-note" crates/client-app/ui/styles.css`
Expected: shows the existing `.sd-row`, `.sd-username`, `.sd-note`, `.share-panel` rules (so the new rules match their conventions; `.sd-roster` and `.sd-check` will be absent — those are new).

- [ ] **Step 2: Add the scrollable-checklist rules**

Append to `crates/client-app/ui/styles.css` (adjust nearby if the file already sets `#sd-rows` height — the new `.sd-roster` selector is more specific and intended to own the scroll):

```css
/* Share checklist: a bounded, scrollable list of tickable contacts. */
.sd-roster {
  max-height: 15rem;
  overflow-y: auto;
  margin: 0.5rem 0;
  padding: 0;
  list-style: none;
  border: 1px solid var(--border, #444);
  border-radius: 6px;
}
.sd-roster:empty {
  display: none; /* no chrome when the roster is empty (manual-only) */
}
.sd-roster .sd-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 0.6rem;
  border-bottom: 1px solid var(--border-faint, #333);
}
.sd-roster .sd-row:last-child {
  border-bottom: none;
}
/* The checkbox+username label is the row's primary hit target. */
.sd-check {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}
.sd-check input[type="checkbox"]:disabled {
  cursor: not-allowed;
}
/* An already-has-access row is visibly de-emphasised. */
.sd-row:has(input[type="checkbox"]:disabled) {
  opacity: 0.6;
}
```

- [ ] **Step 3: Rebuild the UI to copy `styles.css` into `dist/`**

Run: `cd crates/client-app/ui && npm run build 2>&1 | tail -5`
Expected: build succeeds; `dist/styles.css` refreshed.

- [ ] **Step 4: Commit**

```bash
git add crates/client-app/ui/styles.css
git commit -m "style(share): scrollable checklist + greyed already-shared rows

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: a11y assertions + full verification

**Files:**
- Modify: `crates/client-app/ui/src/a11y.test.ts` (extend the existing share-dialog block, ~line 207–275)

- [ ] **Step 1: Add checklist a11y assertions**

In `crates/client-app/ui/src/a11y.test.ts`, inside the existing share-dialog test block (after the Escape-handling assertion, before the `no unescaped innerHTML` test around line 267), add two assertions to the relevant `test(...)` (or add a new `test`) using the already-loaded `sd` source string:

```typescript
  test("share-dialog: checklist is a labelled, scrollable roster", () => {
    // The roster <ul> carries an accessible label and the scroll class…
    assert.match(sd, /class="sd-roster"/, "share-dialog needs the sd-roster checklist container");
    assert.match(sd, /aria-label="People to share with"/, "the roster needs an accessible label");
    // …and each tickable row is a real <input type="checkbox"> inside a <label>
    // (never a click handler on a non-interactive element).
    assert.match(sd, /type = "checkbox"|type="checkbox"/, "tickable rows use a real checkbox input");
    assert.match(sd, /cb\.disabled = /, "already-shared rows disable the checkbox");
  });
```

- [ ] **Step 2: Run the a11y test**

Run: `cd crates/client-app/ui && npm run test:a11y 2>&1 | tail -25`
Expected: all a11y tests pass, including the new checklist assertions and the retained share-dialog dialog/trap/escape/XSS checks.

- [ ] **Step 3: Run the full UI test + typecheck suite**

Run: `cd crates/client-app/ui && npm test 2>&1 | tail -15 && npm run typecheck 2>&1 | tail -5`
Expected: existing core tests pass; typecheck clean. (No new core unit test is required — the dialog logic is DOM-bound and covered structurally by a11y + the Rust command tests.)

- [ ] **Step 4: Run the full client-app Rust test suite**

Run: `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test 2>&1 | tail -25`
Expected: the whole client-app workspace test suite passes (contacts store, share batch incl. the new contact-recording test, DTO test, and all pre-existing tests).

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/a11y.test.ts
git commit -m "test(share): a11y assertions for the contacts checklist

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification checklist

After all tasks, confirm from the repo root:

- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo test 2>&1 | tail -20` — all Rust tests green.
- [ ] `export PATH="$HOME/.cargo/bin:$PATH"; cd crates/client-app && cargo build 2>&1 | tail -5` — compiles clean.
- [ ] `cd crates/client-app/ui && npm run typecheck && npm test && npm run test:a11y` — all green.
- [ ] Manual/`/run` smoke (optional, if a demo server is available): open a viewer → Share → the checklist lists prior recipients, an already-shared contact is greyed, ticking + Share fans out, a typed username still resolves + shares.

---

## Notes for the implementer

- **Never** run `cargo fmt --all` — the crate carries intentional pre-existing rustfmt drift. Match in-file style for new lines.
- The security model is unchanged: `reshare_file` re-verifies every recipient at share time (resolve + D5 + TOFU alarm-B + fail-isolation). The checklist only chooses which usernames to submit.
- `list_contacts` and `list_file_recipients` both FAIL OPEN — a read error must never block the dialog; the user can always fall back to manual input.
- Contact recording is best-effort inside `run_reshare_batch`: a store-write error must never downgrade a successful share to a failure.
