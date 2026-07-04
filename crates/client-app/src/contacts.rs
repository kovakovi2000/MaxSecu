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
