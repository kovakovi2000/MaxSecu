//! `MXBU` — the sealed **server-backup bundle** format (backup design, "MXBU v1").
//!
//! A backup bundle is the one thing in this system that is *not* client-encrypted
//! before it leaves the box: it carries the TLS private key, the operational
//! signing seed, the Dropbox refresh token itself, and a `pg_dump` holding every
//! user's directory binding and DEK wraps. It egresses to the same cold tier as
//! the blobs — where `dropbox_tier.rs`'s module doc promises that nothing but
//! client ciphertext ever passes — so it has to arrive there already sealed. A
//! plaintext bundle in Dropbox hands the entire server to whoever holds the
//! Dropbox account.
//!
//! `MXD5` (`client-core/src/seedblob.rs`) is the model, but cannot be reused:
//! `unseal_seed` hard-rejects anything that is not exactly 93 bytes because it
//! exists to carry one 32-byte seed, and a bundle is unbounded. `maxsecu-crypto`
//! has both halves this needs — `derive_key` (Argon2id, with the below-floor
//! guard) and `seal`/`open` (AES-256-GCM).
//!
//! ```text
//! magic "MXBU" (4) | version u8 = 1 | argon m_kib u32 | t u32 | p u32
//!   | salt[16] | nonce_base[12]           <-- 45-byte header, also the AEAD AAD
//!
//! part_aad   = header ‖ part_index u32 BE ‖ is_last u8
//! part_ct    = AES-256-GCM(key, nonce_for(nonce_base, part_index), part_aad, part)
//! part blob  = header ‖ part_ct                            (ciphertext ‖ tag[16])
//! ```
//!
//! **A part at a time, never a bundle at a time.** A `pg_dump` is unbounded, and
//! parts also sidestep Dropbox's 150 MB single-shot cliff without the
//! upload-session API this repo does not have. That is why [`MxbuSealer`] and
//! [`MxbuOpener`] are sessions rather than whole-bundle functions: Argon2id runs
//! exactly once per bundle, and there is deliberately no entry point that would
//! require a caller to materialize the whole dump to use it.
//!
//! `part_index` and `is_last` in the AAD defeat reorder and truncation — the same
//! property `ChunkAad` gives blobs. `ChunkAad` itself is not reusable: it is
//! hard-wired to `file_id`/`version`/`StreamType` and sits on frozen surfaces #1
//! and #5. Note the two are not equally defended: `part_index` is bound twice,
//! into the nonce *and* the AAD, and mutating either alone still rejects a swap —
//! whereas `is_last` is bound in the AAD only, and is the sole thing standing
//! between a truncated download and a bundle that restores silently short.
//!
//! Every part blob repeats the 45-byte header. It costs 45 bytes per part and
//! buys self-description: a part fetched off an untrusted tier states its own
//! `(m,t,p)`, salt and `nonce_base`, so the key can be derived from whichever
//! part came back first, and a part belonging to a *different* bundle is caught
//! by a header compare instead of only by the AEAD refusing it.
//!
//! Sealing and opening are **separate types on purpose**. The passphrase minimum
//! gates writing only (see [`MIN_PASSPHRASE_CHARS`]), so there must be no way to
//! reach `seal_part` from a session that was opened rather than created — which a
//! single type with two constructors would quietly provide.

use core::fmt;
use maxsecu_crypto::{self as crypto, random_array, Argon2Params, CryptoError};
use zeroize::Zeroizing;

/// Distinct from the keyblob's `MXKB` and the seedblob's `MXD5`, and bound into
/// every part's AEAD AAD — so no blob of one family can ever open as another.
const MAGIC: &[u8; 4] = b"MXBU";
const VERSION_V1: u8 = 1;
const TAG_LEN: usize = 16;

/// Ceilings on the Argon2id `(m,t,p)` a stored part may name. `derive_key` guards
/// the floor; these guard the other end — see [`parse_header`] for why the KDF
/// cannot be handed unbounded values off an untrusted tier.
const MAX_ARGON_M_KIB: u32 = 4 * 1024 * 1024; // 4 GiB — 16x the desktop target
const MAX_ARGON_T: u32 = 64;
const MAX_ARGON_P: u32 = 16;

/// `magic(4) ‖ version(1) ‖ m_kib(4) ‖ t(4) ‖ p(4) ‖ salt(16) ‖ nonce_base(12)`.
/// Prefixed to every stored part and used verbatim as the head of its AEAD AAD.
pub const MXBU_HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + 16 + 12; // 45

/// `header(45) ‖ part_index u32 BE ‖ is_last u8`.
const PART_AAD_LEN: usize = MXBU_HEADER_LEN + 4 + 1; // 50

/// The shortest passphrase [`MxbuSealer::new`] will write a bundle under,
/// counted in characters.
///
/// A bundle sitting in Dropbox faces unlimited offline attack and one Argon2id
/// derivation is all that stands in front of it, so refusing to *write* a weak
/// one is worth the friction. It is a floor, not a guarantee.
///
/// It gates writing **only**. [`MxbuOpener`] must never check it: raising this
/// number later would otherwise retroactively brick every bundle already written
/// under a shorter passphrase — "a stricter check that rejects data the previous
/// version wrote is a break even when it is more secure" (`docs/compat/CHECKLIST.md`).
/// Neither keyblob nor seedblob enforces any minimum, so there is no precedent to
/// copy here and none to break.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Why an `MXBU` part was refused. Fail-closed: there is no best-effort parse and
/// no partial part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MxbuError {
    /// [`MxbuSealer::new`] refused to write under a passphrase shorter than
    /// [`MIN_PASSPHRASE_CHARS`]. Never returned when opening.
    PassphraseTooShort { chars: usize, min: usize },
    /// Not an `MXBU` part: shorter than a header plus a tag, the wrong magic
    /// (e.g. an `MXD5`/`MXKB` blob), a header disagreeing with the bundle's, or
    /// Argon2id parameters so absurd no writer could have produced them.
    CorruptPart,
    /// The header's version byte is not one this build writes or reads. An
    /// unknown version is an explicit error, never a best-effort parse — but
    /// every version that has ever existed must keep opening, forever.
    UnsupportedVersion(u8),
    /// The header's Argon2id `(m,t,p)` are under the mandatory floor, refused
    /// before any work (inherited from `derive_key`).
    BelowArgonFloor,
    /// Argon2id itself failed. Distinct from [`MxbuError::BelowArgonFloor`] so a
    /// real KDF fault is not reported as an operator-fixable parameter problem.
    KeyDerivation,
    /// The AEAD did not authenticate. Deliberately **one** shape for a wrong
    /// passphrase, tampered bytes, a reordered part and a truncated bundle: AES-GCM
    /// cannot tell them apart, and inventing a distinction would be a fiction —
    /// and, for the passphrase, an oracle.
    Unauthentic,
}

impl fmt::Display for MxbuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MxbuError::PassphraseTooShort { chars, min } => {
                write!(f, "passphrase is {chars} characters, minimum {min}")
            }
            MxbuError::CorruptPart => write!(f, "not an MXBU backup part"),
            MxbuError::UnsupportedVersion(v) => write!(f, "unsupported MXBU version {v}"),
            MxbuError::BelowArgonFloor => write!(f, "Argon2id parameters below the floor"),
            MxbuError::KeyDerivation => write!(f, "Argon2id key derivation failed"),
            MxbuError::Unauthentic => {
                write!(
                    f,
                    "part did not authenticate (passphrase, tamper, or order)"
                )
            }
        }
    }
}

impl std::error::Error for MxbuError {}

fn from_crypto(e: CryptoError) -> MxbuError {
    match e {
        CryptoError::BelowArgonFloor => MxbuError::BelowArgonFloor,
        _ => MxbuError::KeyDerivation,
    }
}

fn build_header(
    params: Argon2Params,
    salt: &[u8; 16],
    nonce_base: &[u8; 12],
) -> [u8; MXBU_HEADER_LEN] {
    let mut h = [0u8; MXBU_HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = VERSION_V1;
    h[5..9].copy_from_slice(&params.m_kib.to_be_bytes());
    h[9..13].copy_from_slice(&params.t.to_be_bytes());
    h[13..17].copy_from_slice(&params.p.to_be_bytes());
    h[17..33].copy_from_slice(salt);
    h[33..45].copy_from_slice(nonce_base);
    h
}

/// Split a stored part into its header and the `(m,t,p)` the key must be
/// re-derived under.
///
/// The length gate necessarily precedes the magic gate — the slices below would
/// panic otherwise — but it is a *minimum*, not `seedblob`'s exact-93 equality,
/// so a foreign blob still reaches the magic check and is rejected by it. That
/// distinction is what keeps this module's domain-separation test from being the
/// vacuous length-gate pass its `unseal_seed` counterpart is.
fn parse_header(part: &[u8]) -> Result<([u8; MXBU_HEADER_LEN], Argon2Params), MxbuError> {
    if part.len() < MXBU_HEADER_LEN + TAG_LEN {
        return Err(MxbuError::CorruptPart);
    }
    if &part[0..4] != MAGIC {
        return Err(MxbuError::CorruptPart);
    }
    let version = part[4];
    if version != VERSION_V1 {
        return Err(MxbuError::UnsupportedVersion(version));
    }
    let params = Argon2Params {
        m_kib: u32::from_be_bytes(part[5..9].try_into().unwrap()),
        t: u32::from_be_bytes(part[9..13].try_into().unwrap()),
        p: u32::from_be_bytes(part[13..17].try_into().unwrap()),
    };
    // Twelve bytes of cost parameters, straight off a tier nobody trusts, on their
    // way into a KDF whose only guard is the FLOOR. `argon2` allocates `m_kib` KiB
    // with an infallible `vec![Block; …]`, so a corrupt or hostile `m_kib` near
    // `u32::MAX` asks for ~4 TiB and ABORTS the process — mid-rollback, with no
    // `MxbuError` for the restorer to report and the shell trap left to restart the
    // server around it. `t` needs the same treatment for a different reason: it is
    // pure time, and `u32::MAX` passes is an unbounded hang rather than an error.
    // This is not the tightening `docs/compat/CHECKLIST.md` forbids — a bundle is
    // only ever sealed at `ARGON2_DESKTOP_TARGET` (256 MiB, t=3, p=1) or, in the
    // compat corpus, at `ARGON2_FLOOR` (19 MiB, t=2, p=1), so these bounds sit far
    // above every set of parameters that has ever been written and well clear of
    // any retune that would still finish in the ~1 s the target is calibrated to.
    if params.m_kib > MAX_ARGON_M_KIB || params.t > MAX_ARGON_T || params.p > MAX_ARGON_P {
        return Err(MxbuError::CorruptPart);
    }
    let mut header = [0u8; MXBU_HEADER_LEN];
    header.copy_from_slice(&part[..MXBU_HEADER_LEN]);
    Ok((header, params))
}

fn nonce_base(header: &[u8; MXBU_HEADER_LEN]) -> [u8; 12] {
    let mut b = [0u8; 12];
    b.copy_from_slice(&header[33..45]);
    b
}

/// The part's 96-bit AES-GCM nonce: the bundle's random `nonce_base` with the
/// big-endian `part_index` XORed into its trailing four bytes — the TLS 1.3
/// record-nonce construction.
///
/// Written fresh rather than reused. The repo's only `nonce_for`
/// (`crypto/src/aead.rs`) is private, takes a single `chunk_index`, and has no
/// `nonce_base` concept; it must also not be widened under that name, where a
/// `pub` twin would collide.
///
/// This departs from every other single-shot `seal` call site here (keyblob,
/// seedblob, contacts, tofu, index), each of which stores a fresh random nonce
/// beside its ciphertext. Deliberate: a per-part random nonce would have to be
/// stored per part, whereas `base ⊕ index` binds ordering into the nonce as well
/// as into the AAD. Uniqueness holds because `salt` is fresh per bundle — so the
/// key is unique per bundle — and XOR by a constant is injective, so each
/// `part_index` maps to exactly one nonce under that key.
fn nonce_for(nonce_base: &[u8; 12], part_index: u32) -> [u8; 12] {
    let mut n = *nonce_base;
    for (b, x) in n[8..].iter_mut().zip(part_index.to_be_bytes()) {
        *b ^= x;
    }
    n
}

fn part_aad(header: &[u8; MXBU_HEADER_LEN], part_index: u32, is_last: bool) -> [u8; PART_AAD_LEN] {
    let mut a = [0u8; PART_AAD_LEN];
    a[..MXBU_HEADER_LEN].copy_from_slice(header);
    a[MXBU_HEADER_LEN..MXBU_HEADER_LEN + 4].copy_from_slice(&part_index.to_be_bytes());
    a[PART_AAD_LEN - 1] = u8::from(is_last);
    a
}

/// Writes one bundle: a fresh salt and `nonce_base`, one Argon2id derivation, and
/// then any number of parts sealed under it.
pub struct MxbuSealer {
    header: [u8; MXBU_HEADER_LEN],
    key: Zeroizing<[u8; 32]>,
}

/// Reads one bundle. There is deliberately no path from here to [`MxbuSealer`] —
/// see [`MIN_PASSPHRASE_CHARS`].
pub struct MxbuOpener {
    header: [u8; MXBU_HEADER_LEN],
    key: Zeroizing<[u8; 32]>,
}

// Hand-written so a `#[derive(Debug)]` anywhere upstream cannot print the derived
// key: `Zeroizing<[u8; 32]>` is itself Debug, so a derive here would leak it.
impl fmt::Debug for MxbuSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MxbuSealer").finish_non_exhaustive()
    }
}

impl fmt::Debug for MxbuOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MxbuOpener").finish_non_exhaustive()
    }
}

impl MxbuSealer {
    /// Begin a bundle under `passphrase`. Pure CPU (one Argon2id); no I/O.
    ///
    /// `params` is caller-supplied rather than pinned to `ARGON2_DESKTOP_TARGET`
    /// so the compat gate can mint fixtures at the floor without a 256 MiB stall
    /// per test. It lands in the header, so a future retune leaves today's
    /// bundles openable.
    pub fn new(passphrase: &str, params: Argon2Params) -> Result<MxbuSealer, MxbuError> {
        // Characters, not bytes: `passphrase.len()` would pass a four-emoji
        // passphrase as sixteen.
        let chars = passphrase.chars().count();
        if chars < MIN_PASSPHRASE_CHARS {
            return Err(MxbuError::PassphraseTooShort {
                chars,
                min: MIN_PASSPHRASE_CHARS,
            });
        }
        let salt: [u8; 16] = random_array();
        let nonce_base: [u8; 12] = random_array();
        let key = crypto::derive_key(passphrase.as_bytes(), &salt, params).map_err(from_crypto)?;
        Ok(MxbuSealer {
            header: build_header(params, &salt, &nonce_base),
            key,
        })
    }

    /// The bundle's 45-byte header — the prefix of every part this sealer writes.
    pub fn header(&self) -> &[u8; MXBU_HEADER_LEN] {
        &self.header
    }

    /// Seal one part, returning the complete stored blob (`header ‖ ct ‖ tag`).
    ///
    /// `part_index` must be the part's position in the bundle and `is_last` set on
    /// exactly the final one; both are bound into the AAD, so getting either wrong
    /// produces a bundle that cannot be opened. Infallible, like `crypto::seal`.
    ///
    /// `plaintext` stays the caller's to manage — it is one frame of a `pg_dump`
    /// or a config file, and zeroizing a copy here would not reach theirs.
    pub fn seal_part(&self, part_index: u32, is_last: bool, plaintext: &[u8]) -> Vec<u8> {
        let nonce = nonce_for(&nonce_base(&self.header), part_index);
        let aad = part_aad(&self.header, part_index, is_last);
        let ct = crypto::seal(&self.key, &nonce, &aad, plaintext);
        let mut out = Vec::with_capacity(MXBU_HEADER_LEN + ct.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&ct);
        out
    }
}

impl MxbuOpener {
    /// Re-derive a bundle's key from **any one** of its parts — every part
    /// carries the header, so the first one back off the tier will do.
    ///
    /// The `(m,t,p)` come from that header and are passed straight through. There
    /// is deliberately no check that they equal today's `ARGON2_DESKTOP_TARGET`:
    /// such a check would reject the floor-sealed compat fixture, and would brick
    /// every bundle already written the day the target is retuned.
    ///
    /// Below-floor params are still refused, before any work, by `derive_key`, and
    /// absurd ones by `parse_header`'s ceiling. Succeeding here means only that the
    /// header parsed — a wrong passphrase is indistinguishable until a part fails
    /// to open.
    pub fn from_part(passphrase: &str, part: &[u8]) -> Result<MxbuOpener, MxbuError> {
        let (header, params) = parse_header(part)?;
        // No MIN_PASSPHRASE_CHARS gate here, and there must never be one.
        let key = crypto::derive_key(passphrase.as_bytes(), &salt_of(&header), params)
            .map_err(from_crypto)?;
        Ok(MxbuOpener { header, key })
    }

    /// Open one part at its position in the bundle.
    ///
    /// The caller supplies `part_index` and `is_last` from the bundle's own
    /// [`BackupIndex`](maxsecu_encoding::structs::BackupIndex) — walking
    /// `0..parts.len()` with `is_last` on the final one. That is what makes
    /// truncation and reorder detectable: a dropped final part leaves its
    /// predecessor being opened as `is_last`, which it was not sealed as.
    pub fn open_part(
        &self,
        part_index: u32,
        is_last: bool,
        part: &[u8],
    ) -> Result<Vec<u8>, MxbuError> {
        if part.len() < MXBU_HEADER_LEN + TAG_LEN || part[..MXBU_HEADER_LEN] != self.header[..] {
            return Err(MxbuError::CorruptPart);
        }
        let nonce = nonce_for(&nonce_base(&self.header), part_index);
        let aad = part_aad(&self.header, part_index, is_last);
        crypto::open(&self.key, &nonce, &aad, &part[MXBU_HEADER_LEN..])
            .map_err(|_| MxbuError::Unauthentic)
    }
}

fn salt_of(header: &[u8; MXBU_HEADER_LEN]) -> [u8; 16] {
    let mut s = [0u8; 16];
    s.copy_from_slice(&header[17..33]);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::{Argon2Params, ARGON2_FLOOR};

    /// Every test seals at the floor: the desktop target is 256 MiB and ~1 s per
    /// derive, and this module derives a key dozens of times.
    fn params() -> Argon2Params {
        ARGON2_FLOOR
    }

    const PW: &str = "a-long-enough-backup-passphrase";

    /// Seal `parts` in order, `is_last` on the final one.
    fn seal_all(sealer: &MxbuSealer, parts: &[&[u8]]) -> Vec<Vec<u8>> {
        parts
            .iter()
            .enumerate()
            .map(|(i, pt)| sealer.seal_part(i as u32, i == parts.len() - 1, pt))
            .collect()
    }

    /// Open each part at the position it occupies — exactly what a restorer
    /// walking `BackupIndex::parts` does.
    fn open_all(opener: &MxbuOpener, parts: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, MxbuError> {
        parts
            .iter()
            .enumerate()
            .map(|(i, ct)| opener.open_part(i as u32, i == parts.len() - 1, ct))
            .collect()
    }

    /// Build a part **from the documented byte layout**, not by calling
    /// [`MxbuSealer`]. It is the only way to mint bytes `seal` deliberately
    /// refuses to write (a short passphrase), and it is the same independent-writer
    /// trick the compat corpus uses (`golden_open.rs`'s `build_keyblob`): the
    /// reader is then proved against *foreign* bytes rather than round-tripping
    /// our own writer, which would let both sides drift together.
    fn build_part(
        pw: &str,
        params: Argon2Params,
        salt: &[u8; 16],
        nonce_base: &[u8; 12],
        part_index: u32,
        is_last: bool,
        pt: &[u8],
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(MXBU_HEADER_LEN);
        header.extend_from_slice(b"MXBU");
        header.push(1);
        header.extend_from_slice(&params.m_kib.to_be_bytes());
        header.extend_from_slice(&params.t.to_be_bytes());
        header.extend_from_slice(&params.p.to_be_bytes());
        header.extend_from_slice(salt);
        header.extend_from_slice(nonce_base);
        assert_eq!(header.len(), MXBU_HEADER_LEN);

        let mut aad = header.clone();
        aad.extend_from_slice(&part_index.to_be_bytes());
        aad.push(u8::from(is_last));

        let key = maxsecu_crypto::derive_key(pw.as_bytes(), salt, params).expect("floor params");
        let mut nonce = *nonce_base;
        for (b, x) in nonce[8..].iter_mut().zip(part_index.to_be_bytes()) {
            *b ^= x;
        }
        let ct = maxsecu_crypto::seal(&key, &nonce, &aad, pt);

        let mut out = header;
        out.extend_from_slice(&ct);
        out
    }

    #[test]
    fn seal_open_round_trips_a_multi_part_bundle() {
        let parts: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 1000]).collect();
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let sealed = seal_all(&sealer, &refs);
        assert_eq!(&sealed[0][0..4], b"MXBU");
        // The key is derived from whichever part came back first — every part
        // repeats the header, so a restorer need not fetch a specific one.
        let opener = MxbuOpener::from_part(PW, &sealed[0]).unwrap();
        assert_eq!(open_all(&opener, &sealed).unwrap(), parts);
    }

    #[test]
    fn a_part_is_ciphertext_not_the_plaintext() {
        let pt: Vec<u8> = (0..=255u8).collect();
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let part = sealer.seal_part(0, true, &pt);
        assert!(
            !part.windows(pt.len()).any(|w| w == pt),
            "the plaintext leaked into the sealed part"
        );
    }

    #[test]
    fn a_wrong_passphrase_is_rejected() {
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let part = sealer.seal_part(0, true, b"the dropbox refresh token");
        // Deriving succeeds — the header parses under any passphrase. A wrong one
        // is only discoverable by failing to open a part, which is the AEAD's
        // answer and deliberately the only one.
        let opener = MxbuOpener::from_part("a-different-backup-passphrase", &part).unwrap();
        assert_eq!(
            opener.open_part(0, true, &part).map(|_| ()),
            Err(MxbuError::Unauthentic)
        );
    }

    #[test]
    fn a_tampered_part_is_rejected() {
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let mut part = sealer.seal_part(0, true, b"tamper me");
        let last = part.len() - 1;
        part[last] ^= 0x01;
        let opener = MxbuOpener::from_part(PW, &part).unwrap();
        assert_eq!(
            opener.open_part(0, true, &part).map(|_| ()),
            Err(MxbuError::Unauthentic)
        );
    }

    #[test]
    fn a_foreign_blob_is_not_an_mxbu_part() {
        // MXD5 (93 B) and MXKB v2 (221 B) share MXBU's 45-byte header shape and
        // its KDF; only the magic keeps them apart. A crossover would hand one
        // family's reader another family's key material.
        let mut mxd5 = vec![0u8; 93];
        mxd5[0..4].copy_from_slice(b"MXD5");
        mxd5[4] = 1;
        assert_eq!(
            MxbuOpener::from_part(PW, &mxd5).map(|_| ()),
            Err(MxbuError::CorruptPart)
        );

        let mut mxkb = vec![0u8; 221];
        mxkb[0..4].copy_from_slice(b"MXKB");
        mxkb[4] = 2;
        assert_eq!(
            MxbuOpener::from_part(PW, &mxkb).map(|_| ()),
            Err(MxbuError::CorruptPart)
        );

        // Non-vacuity — the assertions above would pass just as well off the
        // length gate, having never read a byte of the magic. That is exactly the
        // false pass `unseal_seed`'s counterpart test gives: its exact-93-byte
        // gate fires first, so it proves nothing about the magic it names. Here
        // the length gate is a *minimum* both probes clear; swapping in the MXBU
        // magic and changing nothing else proves the magic is what rejected them,
        // because the rejection moves off CorruptPart onto whatever the rest of
        // the header now says.
        for (probe, expected) in [
            (&mxd5, MxbuError::BelowArgonFloor), // version 1, but (m,t,p) all zero
            (&mxkb, MxbuError::UnsupportedVersion(2)),
        ] {
            let mut as_mxbu = probe.clone();
            as_mxbu[0..4].copy_from_slice(MAGIC);
            assert_eq!(
                MxbuOpener::from_part(PW, &as_mxbu).map(|_| ()),
                Err(expected)
            );
        }
    }

    #[test]
    fn corrupt_shapes_are_rejected() {
        // Shorter than a header + tag can never be a part.
        assert_eq!(
            MxbuOpener::from_part(PW, &[0u8; 10]).map(|_| ()),
            Err(MxbuError::CorruptPart)
        );
        assert_eq!(
            MxbuOpener::from_part(PW, &[]).map(|_| ()),
            Err(MxbuError::CorruptPart)
        );
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let mut part = sealer.seal_part(0, true, b"x");
        part[4] = 99;
        assert_eq!(
            MxbuOpener::from_part(PW, &part).map(|_| ()),
            Err(MxbuError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn below_floor_params_are_refused_on_unseal() {
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let mut part = sealer.seal_part(0, true, b"x");
        // m_kib (bytes 5..9) to 1 MiB, far under the 19 MiB floor.
        part[5..9].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(
            MxbuOpener::from_part(PW, &part).map(|_| ()),
            Err(MxbuError::BelowArgonFloor)
        );
    }

    #[test]
    fn absurd_argon_params_are_refused_before_the_kdf() {
        // The mirror of `below_floor_params_are_refused_on_unseal`. A part's
        // `(m,t,p)` are read verbatim off the tier and handed to `derive_key`,
        // which only checks the floor — so an `m_kib` near `u32::MAX` reaches
        // argon2's infallible `vec![Block; …]`, asks the allocator for ~4 TiB, and
        // takes the whole restore process down with an abort instead of returning
        // an `MxbuError`. `t` at `u32::MAX` is the same defect wearing a different
        // coat: billions of passes over the floor's 19 MiB is an unbounded hang.
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let base = sealer.seal_part(0, true, b"x");

        for (field, bytes) in [(5usize, 9usize), (9, 13), (13, 17)] {
            let mut part = base.clone();
            part[field..bytes].copy_from_slice(&u32::MAX.to_be_bytes());
            assert_eq!(
                MxbuOpener::from_part(PW, &part).map(|_| ()),
                Err(MxbuError::CorruptPart),
                "header bytes {field}..{bytes} at u32::MAX reached the KDF"
            );
        }

        // Widening, not tightening (`docs/compat/CHECKLIST.md`): the ceiling has to
        // sit far above every parameter set a writer has ever produced, or it
        // bricks bundles already sitting in Dropbox.
        for p in [ARGON2_FLOOR, maxsecu_crypto::ARGON2_DESKTOP_TARGET] {
            assert!(p.m_kib <= MAX_ARGON_M_KIB / 4);
            assert!(p.t <= MAX_ARGON_T / 4 && p.p <= MAX_ARGON_P / 4);
        }
        let sealer = MxbuSealer::new(PW, ARGON2_FLOOR).unwrap();
        let part = sealer.seal_part(0, true, b"under the ceiling");
        let opener = MxbuOpener::from_part(PW, &part).unwrap();
        assert_eq!(
            opener.open_part(0, true, &part).unwrap(),
            b"under the ceiling"
        );
    }

    #[test]
    fn dropping_the_last_part_is_rejected() {
        // What `is_last` in the part AAD is for: after a truncation the new final
        // part gets opened with is_last = true, but it was sealed with false.
        let parts: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 64]).collect();
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let sealed = seal_all(&sealer, &refs);
        let opener = MxbuOpener::from_part(PW, &sealed[0]).unwrap();
        let truncated = &sealed[..sealed.len() - 1];
        assert_eq!(
            open_all(&opener, truncated).map(|_| ()),
            Err(MxbuError::Unauthentic)
        );
    }

    #[test]
    fn reordering_parts_is_rejected() {
        // Parts 0 and 1 are both is_last = false, so swapping them isolates the
        // index binding from the truncation one.
        //
        // `part_index` is bound *twice* — into the nonce (base ⊕ index) and into
        // the AAD — and mutation-testing each in turn shows either one alone
        // still rejects this swap. Truncation has no such redundancy: `is_last`
        // is bound in the AAD only, which is what `dropping_the_last_part_is_rejected`
        // actually pins.
        let parts: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 64]).collect();
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let sealer = MxbuSealer::new(PW, params()).unwrap();
        let mut sealed = seal_all(&sealer, &refs);
        sealed.swap(0, 1);
        let opener = MxbuOpener::from_part(PW, &sealed[0]).unwrap();
        assert_eq!(
            open_all(&opener, &sealed).map(|_| ()),
            Err(MxbuError::Unauthentic)
        );
    }

    #[test]
    fn a_part_from_another_bundle_is_rejected() {
        // `db` and `state` are sealed as independent bundles. A foreign part is
        // refused on the header compare — its bundle's key could not open it
        // either, but the sharper error is worth having. This also pins that the
        // salt and nonce_base are fresh per bundle: identical headers here would
        // mean two bundles sharing a key and a nonce space.
        let a = MxbuSealer::new(PW, params()).unwrap();
        let b = MxbuSealer::new(PW, params()).unwrap();
        let part_a = a.seal_part(0, true, b"bundle a");
        let part_b = b.seal_part(0, true, b"bundle b");
        assert_ne!(part_a[..MXBU_HEADER_LEN], part_b[..MXBU_HEADER_LEN]);
        let opener = MxbuOpener::from_part(PW, &part_a).unwrap();
        assert_eq!(
            opener.open_part(0, true, &part_b).map(|_| ()),
            Err(MxbuError::CorruptPart)
        );
    }

    #[test]
    fn a_floor_sealed_bundle_still_opens() {
        // `unseal` reads (m,t,p) out of the header and passes them through.
        // Pinning ARGON2_DESKTOP_TARGET would reject this bundle — and would
        // brick every bundle already in Dropbox the day the target is retuned.
        // "Prefer widening over tightening" (docs/compat/CHECKLIST.md).
        assert_ne!(ARGON2_FLOOR, maxsecu_crypto::ARGON2_DESKTOP_TARGET);
        let sealer = MxbuSealer::new(PW, ARGON2_FLOOR).unwrap();
        let part = sealer.seal_part(0, true, b"floor-sealed");
        let opener = MxbuOpener::from_part(PW, &part).unwrap();
        assert_eq!(opener.open_part(0, true, &part).unwrap(), b"floor-sealed");
    }

    #[test]
    fn seal_refuses_a_short_passphrase() {
        assert_eq!(
            MxbuSealer::new("short-11-ch", params()).map(|_| ()),
            Err(MxbuError::PassphraseTooShort {
                chars: 11,
                min: MIN_PASSPHRASE_CHARS
            })
        );
        assert!(MxbuSealer::new("exactly12chr", params()).is_ok());
        // Counted in characters, not bytes: four 4-byte emoji are 16 bytes but
        // only four choices, and a byte-length gate would wave them through.
        assert_eq!(
            MxbuSealer::new("🔒🔒🔒🔒", params()).map(|_| ()),
            Err(MxbuError::PassphraseTooShort {
                chars: 4,
                min: MIN_PASSPHRASE_CHARS
            })
        );
    }

    #[test]
    fn a_bundle_written_under_a_short_passphrase_still_opens() {
        // The minimum gates the WRITER only. Were `unseal` to enforce it too, the
        // day the minimum is raised every bundle already sitting in Dropbox under
        // a shorter passphrase becomes unopenable — a stricter check rejecting
        // data the previous version wrote, which CLAUDE.md calls a break even
        // when it is more secure.
        let short = "hunter2";
        assert!(MxbuSealer::new(short, params()).is_err());
        let part = build_part(
            short,
            params(),
            &[0x5A; 16],
            &[0x6B; 12],
            0,
            true,
            b"old bundle",
        );
        let opener = MxbuOpener::from_part(short, &part).unwrap();
        assert_eq!(opener.open_part(0, true, &part).unwrap(), b"old bundle");
    }

    #[test]
    fn the_reader_opens_independently_written_bytes() {
        // build_part is a second implementation of the documented layout. If the
        // two ever disagree — header field order, the AAD framing, the nonce
        // derivation — this fails, where a seal/open round-trip would not: both
        // halves would drift together. That is the `2a626d6` failure mode.
        let salt = [0x11; 16];
        let nonce_base = [0x22; 12];
        let parts: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 100]).collect();
        let sealed: Vec<Vec<u8>> = parts
            .iter()
            .enumerate()
            .map(|(i, pt)| build_part(PW, params(), &salt, &nonce_base, i as u32, i == 2, pt))
            .collect();
        let opener = MxbuOpener::from_part(PW, &sealed[0]).unwrap();
        assert_eq!(open_all(&opener, &sealed).unwrap(), parts);
    }
}
