//! Trust-on-first-use (TOFU) pinning of OTHER users' directory keys — trust-alarm
//! layer B (spec §0-B/§7).
//!
//! The recovery account is pinned at COMPILE time ([`crate::recovery_pin`], alarm-A).
//! Every OTHER user's key is instead pinned the first time this client resolves +
//! D5-verifies it (TOFU): the pin is recorded locally, and any LATER differing key
//! for the same username raises a fail-closed trust alarm
//! ([`crate::recovery_pin::TrustAlarm::UserKeyChanged`], alarm-B) that BLOCKS the
//! in-flight action (e.g. a share) rather than silently wrapping to a
//! server-substituted key. A first sighting is NORMAL and never blocks — only a
//! CHANGE blocks.
//!
//! # Pinned representation
//! The pin is the identity fingerprint `SHA-256(canonical(enc_pub ‖ sig_pub))`
//! ([`maxsecu_crypto::fingerprint`], DESIGN §7.1) — the SAME value the D5 verify
//! ladder already computes for a binding. Because it covers BOTH the encryption and
//! signing pubkeys, a change in EITHER half yields a different fingerprint ⇒ a
//! `Changed` outcome. Storing the 32-byte fingerprint (not the raw keys) is enough
//! for both change-detection and the short human-comparable display form.
//!
//! # At-rest confidentiality + integrity
//! The map is sealed on disk at `<dir>/tofu/pins.tofu` with an AEAD key derived
//! (HKDF-SHA256) from the unlocked identity — the SAME identity-derived sealing the
//! local search index uses ([`crate::index`]). So the pin store is confidential and
//! integrity-protected at rest, and unreadable by any other identity.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use maxsecu_client_core::Identity;

use crate::error::UiError;
use crate::recovery_pin::TrustAlarm;

/// Domain-separation label for the TOFU-store sealing key + AEAD aad. Distinct from
/// the search-index label so the two sealed stores use unrelated keys.
const TOFU_LABEL: &[u8] = b"MaxSecu-tofu-pins-v1";

/// The result of checking a resolved user key against the local TOFU pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuOutcome {
    /// First sighting of this username — the key was just pinned (persisted).
    /// NORMAL trust-on-first-use; the caller proceeds.
    Pinned,
    /// The same key as the stored pin — verified, the caller proceeds.
    Match,
    /// A DIFFERENT key than the stored pin for this username — alarm-B. The caller
    /// MUST block the in-flight action (the pin is NOT overwritten).
    Changed,
}

/// The fingerprint that identifies a user's key material: `SHA-256(canonical(enc ‖
/// sig))`. A change in EITHER pubkey changes this value.
pub fn key_fingerprint(enc_pub: &[u8; 32], sig_pub: &[u8; 32]) -> [u8; 32] {
    maxsecu_crypto::fingerprint(enc_pub, sig_pub)
}

/// A SHORT, stable, human-comparable rendering of a 32-byte fingerprint: the first
/// 8 bytes as uppercase hex, grouped in 4s (e.g. `A1B2 C3D4 E5F6 0718`), for
/// optional out-of-band comparison. Deterministic for a given fingerprint.
pub fn short_fingerprint(fp: &[u8; 32]) -> String {
    fp[..8]
        .chunks(2)
        .map(|c| format!("{:02X}{:02X}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// On-disk (pre-seal) shape: username → fingerprint, hex-encoded for a stable,
/// debuggable serialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TofuMap {
    /// username → fingerprint (lowercase hex of the 32-byte fingerprint).
    pins: BTreeMap<String, String>,
}

/// The identity-sealed local TOFU pin store. Holds ONLY the derived sealing key and
/// the in-RAM map — never the `Identity` itself, and nothing crosses the Tauri seam.
pub struct TofuStore {
    path: PathBuf,
    /// The identity-derived AEAD sealing key (zeroized on drop).
    key: Zeroizing<[u8; 32]>,
    /// username → pinned fingerprint.
    map: BTreeMap<String, [u8; 32]>,
}

impl TofuStore {
    /// Open (load + decrypt) the sealed TOFU store under `<dir>/tofu/pins.tofu`, or
    /// an empty store if absent. Fails closed (`untrusted`) on a decrypt/parse error
    /// (corrupt / written by a foreign identity) — never silently discards pins.
    pub fn open(dir: &Path, identity: &Identity) -> Result<Self, UiError> {
        let key = seal_key(identity);
        let path = dir.join("tofu").join("pins.tofu");
        let map = match std::fs::read(&path) {
            Ok(sealed) => decrypt_map(&key, &sealed)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => {
                return Err(UiError::new(
                    "untrusted",
                    "The trust store could not be read.",
                ))
            }
        };
        Ok(TofuStore { path, key, map })
    }

    /// Check a resolved+verified user key against the local pin, pinning it on a
    /// first sighting (and persisting). Returns:
    /// * [`TofuOutcome::Pinned`] the FIRST time `username` is seen (pin persisted),
    /// * [`TofuOutcome::Match`] when the SAME key is seen again,
    /// * [`TofuOutcome::Changed`] when a DIFFERENT key is presented (pin unchanged).
    ///
    /// A `Changed` result NEVER overwrites the stored pin — the old, trusted pin is
    /// retained so a subsequent re-check still trips the alarm.
    pub fn check_or_pin(
        &mut self,
        username: &str,
        enc_pub: &[u8; 32],
        sig_pub: &[u8; 32],
    ) -> Result<TofuOutcome, UiError> {
        let fp = key_fingerprint(enc_pub, sig_pub);
        match self.map.get(username) {
            None => {
                self.map.insert(username.to_owned(), fp);
                self.persist()?;
                Ok(TofuOutcome::Pinned)
            }
            Some(pinned) if *pinned == fp => Ok(TofuOutcome::Match),
            Some(_) => Ok(TofuOutcome::Changed),
        }
    }

    /// The pinned fingerprint for `username`, if any (for the display form).
    pub fn pinned_fingerprint(&self, username: &str) -> Option<[u8; 32]> {
        self.map.get(username).copied()
    }

    /// Encrypt + persist the map to `<dir>/tofu/pins.tofu` (creates `tofu/`).
    fn persist(&self) -> Result<(), UiError> {
        let dir = self.path.parent().ok_or_else(untrusted_write)?;
        std::fs::create_dir_all(dir).map_err(|_| untrusted_write())?;
        let on_disk = TofuMap {
            pins: self
                .map
                .iter()
                .map(|(u, fp)| (u.clone(), hex32(fp)))
                .collect(),
        };
        let plain = serde_json::to_vec(&on_disk).map_err(|_| untrusted_write())?;
        let nonce = maxsecu_crypto::random_array::<12>();
        let ct = maxsecu_crypto::seal(&self.key, &nonce, TOFU_LABEL, &plain);
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        std::fs::write(&self.path, out).map_err(|_| untrusted_write())
    }
}

/// Map a [`TofuOutcome`] to a [`TrustAlarm`] for the blocking path: `Changed` ⇒
/// alarm-B carrying the username; `Pinned`/`Match` are non-blocking (`None`).
pub fn outcome_to_alarm(outcome: TofuOutcome, username: &str) -> Option<TrustAlarm> {
    match outcome {
        TofuOutcome::Changed => Some(TrustAlarm::UserKeyChanged {
            username: username.to_owned(),
        }),
        TofuOutcome::Pinned | TofuOutcome::Match => None,
    }
}

/// Derive the 32-byte TOFU-store sealing key from the unlocked identity (a stable
/// TCB secret), domain-separated so it is unrelated to any wrap or index key.
fn seal_key(identity: &Identity) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(maxsecu_crypto::hkdf_sha256_32(
        &identity.enc_secret().expose_bytes(),
        TOFU_LABEL,
    ))
}

/// Decrypt + decode a sealed `nonce ‖ ct` blob into the in-RAM fingerprint map.
fn decrypt_map(
    key: &[u8; 32],
    sealed: &[u8],
) -> Result<BTreeMap<String, [u8; 32]>, UiError> {
    let untrusted = || UiError::new("untrusted", "The trust store is corrupt.");
    if sealed.len() < 12 {
        return Err(untrusted());
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| untrusted())?;
    let plain =
        maxsecu_crypto::open(key, &nonce, TOFU_LABEL, ct).map_err(|_| untrusted())?;
    let on_disk: TofuMap = serde_json::from_slice(&plain).map_err(|_| untrusted())?;
    let mut map = BTreeMap::new();
    for (u, hex) in on_disk.pins {
        map.insert(u, unhex32(&hex).ok_or_else(untrusted)?);
    }
    Ok(map)
}

fn untrusted_write() -> UiError {
    UiError::new("untrusted", "The trust store could not be written.")
}

/// Lowercase hex of a 32-byte fingerprint (on-disk form).
fn hex32(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse 64 lowercase-hex chars back into a 32-byte fingerprint (`None` if malformed).
fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp dir per test (mirrors `index.rs`'s test tmp-dir helper).
    fn tmp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxtofu_{}_{}",
            std::process::id(),
            maxsecu_crypto::random_array::<8>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    const ENC_A: [u8; 32] = [0xE1; 32];
    const SIG_A: [u8; 32] = [0x51; 32];
    const ENC_B: [u8; 32] = [0xE2; 32];
    const SIG_B: [u8; 32] = [0x52; 32];

    #[test]
    fn first_use_pins_then_matches_then_changed() {
        let dir = tmp_dir();
        let id = Identity::generate();
        let mut store = TofuStore::open(&dir, &id).unwrap();

        // First sighting → Pinned (and persisted, NOT blocking).
        assert_eq!(
            store.check_or_pin("alice", &ENC_A, &SIG_A).unwrap(),
            TofuOutcome::Pinned
        );
        // Same key again → Match.
        assert_eq!(
            store.check_or_pin("alice", &ENC_A, &SIG_A).unwrap(),
            TofuOutcome::Match
        );
        // A DIFFERENT enc key → Changed (either half changing must trip it).
        assert_eq!(
            store.check_or_pin("alice", &ENC_B, &SIG_A).unwrap(),
            TofuOutcome::Changed
        );
        // A DIFFERENT sig key (enc unchanged) → Changed too.
        assert_eq!(
            store.check_or_pin("alice", &ENC_A, &SIG_B).unwrap(),
            TofuOutcome::Changed
        );
        // A Changed result did NOT overwrite the pin: the original key still Matches.
        assert_eq!(
            store.check_or_pin("alice", &ENC_A, &SIG_A).unwrap(),
            TofuOutcome::Match
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_stable_and_display_is_short() {
        let a = key_fingerprint(&ENC_A, &SIG_A);
        let b = key_fingerprint(&ENC_A, &SIG_A);
        assert_eq!(a, b, "fingerprint is stable for the same key");
        assert_ne!(a, key_fingerprint(&ENC_B, &SIG_A), "enc change → new fp");
        assert_ne!(a, key_fingerprint(&ENC_A, &SIG_B), "sig change → new fp");

        let disp = short_fingerprint(&a);
        assert_eq!(short_fingerprint(&a), disp, "display is stable");
        // 4 groups of 4 hex chars + 3 spaces = 19 chars — short + human-comparable.
        assert_eq!(disp.len(), 19);
        assert_eq!(disp.matches(' ').count(), 3);
        assert!(disp.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }

    #[test]
    fn pin_persists_across_reopen_and_is_sealed() {
        let dir = tmp_dir();
        let id = Identity::generate();
        {
            let mut store = TofuStore::open(&dir, &id).unwrap();
            assert_eq!(
                store.check_or_pin("bob", &ENC_A, &SIG_A).unwrap(),
                TofuOutcome::Pinned
            );
        }
        // On-disk bytes must not contain the plaintext username.
        let raw = std::fs::read(dir.join("tofu").join("pins.tofu")).unwrap();
        assert!(!raw.windows(3).any(|w| w == b"bob"), "username is sealed");

        // Reopening with the SAME identity sees the pin (Match, not a re-pin).
        let mut reopened = TofuStore::open(&dir, &id).unwrap();
        assert_eq!(
            reopened.check_or_pin("bob", &ENC_A, &SIG_A).unwrap(),
            TofuOutcome::Match
        );

        // A DIFFERENT identity cannot read the sealed store (fails closed).
        let other = Identity::generate();
        assert!(TofuStore::open(&dir, &other).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_maps_to_alarm_others_do_not() {
        assert_eq!(
            outcome_to_alarm(TofuOutcome::Changed, "alice"),
            Some(TrustAlarm::UserKeyChanged {
                username: "alice".to_owned()
            })
        );
        assert_eq!(outcome_to_alarm(TofuOutcome::Pinned, "alice"), None);
        assert_eq!(outcome_to_alarm(TofuOutcome::Match, "alice"), None);
    }
}
