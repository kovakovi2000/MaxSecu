//! Point this install at its server — from the operator's **connection code**
//! (`ADDR:PORT#FINGERPRINT`) or, in a disaster, from the bare `ADDR:PORT` alone —
//! without any registration.
//!
//! `server_of` (`commands::connection`) reads the dial address out of
//! `config/connection.json`, and the ONLY production writer of that file is
//! `persist_registered_server`, reachable only from `register_with_key`. A device
//! that holds a recovery keyblob but has never registered therefore has no address
//! to dial and cannot even reach the recovery-login endpoints.
//!
//! **Why a bare address is enough.** What authenticates the channel is the pinned
//! certificate already sitting in this folder: `open_conn` builds a `RootCertStore`
//! containing EXACTLY `config/server_cert.der` and nothing else, TLS 1.3 only
//! (`transport::pinned_client_config`). Dial the wrong box and the handshake fails —
//! no code required, and no code could have helped, because the address is not in
//! the fingerprint's preimage in the first place.
//!
//! **What the code check is, precisely** — the two halves of this are both true and
//! were previously written as if they contradicted each other. (a) The comparison
//! this file performs teaches the PROGRAM nothing: `#FINGERPRINT` is a pure function
//! of two PUBLIC files the folder already holds (`server_cert.der` +
//! `directory_pub.der`), so re-deriving it from those same bytes can only ever agree
//! with itself. (b) The check is nonetheless genuinely worth doing, because its value
//! accrues to the OPERATOR and only when the code travelled a channel this folder did
//! not: an admin reading the code down the phone is asserting which pins they issued,
//! so a disagreement means the pins in THIS folder were swapped in transit. That is
//! why a supplied code is still verified and still fails closed on mismatch — and
//! equally why its ABSENCE cannot be fatal: it is not a check the folder could ever
//! perform for itself. The screen's copy says exactly this: do it when you have an
//! independent copy of the code, skip it when you do not.
//!
//! Requiring the full code was a break-glass trap. The shipped cold-storage
//! instruction (`scripts/install-client.ps1`, `README.md`) tells the operator to
//! keep the recovery blobs and the passphrase — not the code — and recovery sign-in
//! is the only disaster path there is. Meanwhile the ordinary connect screen and the
//! register screen have always accepted a bare `host:port`. The one flow that runs
//! when everything else is on fire was the strictest, which is exactly backwards.
//!
//! **The address the operator no longer has to remember.** The premise of this path
//! is that the operator kept the blobs and the passphrase and *nothing else*, so
//! making them recall `1.2.3.4:8443` from memory only moves the trap one step. They
//! do not have to: the server bakes its public address into its OWN certificate as a
//! SAN (`portable-server::pki::ensure_dev_cert`, driven by `install-server.sh
//! --public`), and that certificate is `config/server_cert.der` — already sitting in
//! this folder. `pinned_server_hints` reads it back out so the screen can pre-fill
//! the field. This is also why the SAN is the RIGHT source rather than a guess:
//! `open_conn` verifies the dialled host against that very SAN list, so a host read
//! out of the cert is by construction one the pinned handshake can accept.
//!
//! The PORT is genuinely NOT recoverable, and is reported as such rather than
//! guessed. X.509 carries no port; the handout ZIP `install-client.ps1` builds stages
//! exactly `server_cert.der` + `directory_pub.der` (no `connection.json`), and its
//! `START-HERE.txt` prints only an EXAMPLE address. So a hint is a host, flagged
//! `port_known: false`, and the screen leaves the port to the operator — naming the
//! installer's default in help text, never silently filling it in.
//!
//! None of this is trusted input. A pre-filled host is a suggestion the operator can
//! overwrite; it goes through the same `resolve_dial_target` as anything typed, and
//! the dial still succeeds only against the pinned cert. See
//! `a_prefilled_host_is_still_only_a_suggestion_the_pin_decides`.

use std::path::Path;

use tauri::State;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};

use crate::config::ConnectionConfig;
use crate::error::UiError;
use crate::transport;

use super::auth::AppDir;

/// `set_server_from_code` — record where to dial, from either a full connection
/// code or a bare `HOST:PORT`.
///
/// With a `#`, both fingerprint modes `maxsecu-setup` can mint are accepted,
/// mirroring exactly what `fetch_and_verify` supports: the 2-pin form (`cert` +
/// `directory_pub`) and the cert-only form (the offline-D5 ceremony, where the
/// directory key originates on the admin PC and the server serves none). A
/// mismatch writes nothing.
#[tauri::command]
pub async fn set_server_from_code(code: String, dir: State<'_, AppDir>) -> Result<(), UiError> {
    set_server_inner(&dir.0, &code)
}

/// `pinned_fingerprint` — the connection-code fingerprint THIS folder derives from
/// its own pins.
///
/// Two audiences on the recovery screen. An operator who still holds a code can
/// eyeball-compare the half after the `#`, which is the one thing a code genuinely
/// proves (see the module docs: an independent channel disagreeing with the folder
/// means the pins were swapped). An operator who does not hold one is *informed*
/// rather than blocked, and has a value to read back to the admin.
///
/// Nothing secret crosses the seam: both inputs are PUBLIC files that already live
/// in this folder, and the result is the same string `maxsecu-setup` printed at
/// install time.
///
/// One value, not two: the 2-pin form is what `install-client.ps1` mints as the
/// final user-facing code, and when `directory_pub.der` is absent — the mid-install
/// window before the offline-D5 ceremony writes it — `dir_pub` is empty and this
/// collapses to exactly the cert-only form that stage issues. So the printed value
/// always matches the code this folder's install stage handed out.
#[tauri::command]
pub fn pinned_fingerprint(dir: State<'_, AppDir>) -> Result<String, UiError> {
    pinned_fingerprint_inner(&dir.0)
}

/// The command body, minus the Tauri seam — same split as `set_server_inner`, and
/// for the same reason: `tauri::State` has no public constructor, so a test that
/// wants to exercise the REAL body (rather than re-implement it and pass forever)
/// has to be handed the `&Path` directly. Everything above this line is one
/// `dir.0`.
fn pinned_fingerprint_inner(dir: &Path) -> Result<String, UiError> {
    let cert = read_pinned_cert(dir)?;
    Ok(maxsecu_crypto::pin_fingerprint(
        &cert,
        &read_directory_pub(dir),
    ))
}

/// What the recovery screen needs to fill its one field HONESTLY: where this device
/// points today, and what the pinned certificate says the server is called.
///
/// Every field is derived from PUBLIC bytes already in this folder (the pinned cert
/// and the app's own config), so it discloses nothing across the seam that the
/// folder did not already hold.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct ServerHints {
    /// The dial address currently in `config/connection.json`, or `""` when this
    /// device has never been pointed anywhere. Shown so the operator can SEE what a
    /// save would replace, instead of discovering it after the fact.
    pub configured: String,
    /// Host names / IP literals the pinned certificate vouches for, best guess
    /// first (see [`dialable_hosts`]). Every entry is one `open_conn` could dial.
    pub cert_hosts: Vec<String>,
    /// **Always `false`.** A reported field rather than an assumption hard-coded in
    /// the screen: X.509 has nowhere to put a port, and no other file in the handout
    /// carries one either (see the module docs). Should a future handout ever ship
    /// the port — a stamped `connection.json`, say — this flips to `true` and the
    /// screen's "add the port yourself" copy switches off with it, without the two
    /// sides having to be re-reasoned about.
    pub port_known: bool,
}

/// `pinned_server_hints` — read-side companion to `set_server_from_code`.
///
/// The disaster premise is an operator holding the recovery blobs, the passphrase
/// and nothing else. This is what stops "and the address, which you also had to
/// remember" from being a fourth requirement: the address is in the pinned cert's
/// SAN, and the cert is in the folder.
///
/// Fails with `not_pinned` on a folder with no usable certificate — the same
/// precondition `set_server_from_code` applies, surfaced BEFORE the operator types
/// anything rather than after.
#[tauri::command]
pub fn pinned_server_hints(dir: State<'_, AppDir>) -> Result<ServerHints, UiError> {
    pinned_server_hints_inner(&dir.0)
}

/// The command body, minus the Tauri seam (see [`pinned_fingerprint_inner`]).
fn pinned_server_hints_inner(dir: &Path) -> Result<ServerHints, UiError> {
    let cert = read_pinned_cert(dir)?;
    Ok(ServerHints {
        configured: ConnectionConfig::load(dir).server,
        cert_hosts: dialable_hosts(&cert),
        port_known: false,
    })
}

/// The command body, minus the Tauri seam, so the whole decision — including "and
/// nothing was written" — is unit-testable rather than reasoned about.
fn set_server_inner(dir: &Path, input: &str) -> Result<(), UiError> {
    let addr = resolve_dial_target(dir, input)?;
    persist_code_server(dir, addr)
        .map_err(|_| UiError::new("internal", "Could not save the server address."))
}

/// Decide what to dial, or fail with a code the screen can turn into an actionable
/// sentence. Three distinct failures that used to collapse into one `untrusted`:
///
/// * `not_pinned` — this folder has no usable `server_cert.der`. Nothing about the
///   pasted string is worth saying; the folder itself is the problem.
/// * `bad_code` — the string is neither a connection code nor a dial address (a
///   typo, a truncated paste).
/// * `untrusted` — a real fingerprint mismatch. The pins were swapped.
///
/// Splitting them leaks nothing: both pins are PUBLIC files, the comparison is
/// entirely local, and there is no remote party to learn anything from the answer.
fn resolve_dial_target(dir: &Path, input: &str) -> Result<String, UiError> {
    let input = input.trim();

    // Gate BOTH branches on the pin, and read it first. It is the actual
    // authenticator, so a folder without one cannot be pointed anywhere — and no
    // message about the pasted string would be honest while that is true.
    let cert = read_pinned_cert(dir)?;

    let bad_code = || {
        UiError::new(
            "bad_code",
            "That is not a connection code or a server address.",
        )
    };

    if !input.contains('#') {
        // Bare address: the pinned cert above is the whole trust decision.
        return parse_dial_address(input).ok_or_else(bad_code);
    }

    // With a `#` the check is unchanged and still fails closed. Note the address is
    // deliberately NOT re-validated on this branch: `parse_connection_code` is a
    // frozen surface (#7) and has always persisted whatever address the code
    // carried, so imposing a shape here could reject a code an earlier build minted.
    let (addr, fp) = maxsecu_crypto::parse_connection_code(input).ok_or_else(bad_code)?;
    let dir_pub = read_directory_pub(dir);
    if fp != maxsecu_crypto::pin_fingerprint(&cert, &dir_pub)
        && fp != maxsecu_crypto::pin_fingerprint(&cert, &[])
    {
        return Err(UiError::new(
            "untrusted",
            "That connection code does not match this app's pinned server.",
        ));
    }
    Ok(addr)
}

/// Read `config/server_cert.der` AND prove it is something this app could actually
/// pin, by building the very same single-root TLS config `open_conn` builds. Using
/// that exact constructor (rather than a hand-rolled "looks like DER" test) is what
/// stops the two from drifting: if it succeeds here, the dial's TLS setup succeeds.
///
/// The parse is a precondition the earlier code did not apply (it compared against
/// whatever bytes were in the file), and a stricter check normally has to justify
/// itself against the compat rule. This one costs nobody access: `open_conn` runs
/// the IDENTICAL `pinned_client_config` on the very next step, so a folder that
/// fails here could never have completed a connection anyway. Refusing now — with a
/// message naming the real problem — beats persisting an address and failing later
/// with "Invalid pinned certificate" on a screen that cannot act on it.
fn read_pinned_cert(dir: &Path) -> Result<Vec<u8>, UiError> {
    let not_pinned = || {
        UiError::new(
            "not_pinned",
            "This folder has no pinned server certificate, so it cannot be pointed at a server.",
        )
    };
    let bytes =
        std::fs::read(dir.join("config").join("server_cert.der")).map_err(|_| not_pinned())?;
    transport::pinned_client_config(CertificateDer::from(bytes.clone()))
        .map_err(|_| not_pinned())?;
    Ok(bytes)
}

/// The pinned directory key, or empty when it is not on disk yet. Absent is a real
/// state (the offline-D5 ceremony writes it after the cert), and it is exactly what
/// makes the 2-pin fingerprint collapse to the cert-only one — so absence must be a
/// value here, never an error.
fn read_directory_pub(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("config").join("directory_pub.der")).unwrap_or_default()
}

/// Accept a bare `HOST:PORT`, and only the shapes `open_conn` can actually dial, so
/// a typo is caught on the screen that can still fix it instead of resurfacing later
/// as a mystery TLS error on a screen that cannot.
///
/// Deliberately the same parse `open_conn` performs: split on the LAST `:` (there is
/// no IPv6 bracket form — `ServerName` rejects it, as does `open_conn`), a non-zero
/// `u16` port, and a host `rustls` will accept as an SNI / cert-SAN target. That last
/// check is what rejects a pasted `https://…` URL. The port is reformatted from the
/// parsed number so what lands in `connection.json` is byte-for-byte what `open_conn`
/// will re-split.
fn parse_dial_address(input: &str) -> Option<String> {
    let (host, port) = input.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    ServerName::try_from(host.to_owned()).ok()?;
    Some(format!("{host}:{port}"))
}

// ---------------------------------------------------------------------------
// Reading the server's own name back out of the pinned certificate.
//
// This is a deliberately tiny, read-only DER walk rather than a new dependency:
// the client workspace has no X.509 parser of its own (`rustls` exposes none, and
// `x509-parser`/`der-parser` are not in this graph), and pulling one in for a
// convenience pre-fill would add an audited crate to a key-holding binary to save
// ~60 lines. It is bounded on every axis — no recursion without a depth cap, no
// length it does not first check against the remaining slice, no allocation
// proportional to a length field — and NOTHING it returns is trusted: the result
// is a suggestion typed into a text box that then goes through the ordinary
// `resolve_dial_target` + pinned-TLS path. A malformed certificate yields an empty
// hint list, never a panic and never a different trust decision.
// ---------------------------------------------------------------------------

/// `id-ce-subjectAltName` = 2.5.29.17, DER-encoded OID body.
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
/// `id-at-commonName` = 2.5.4.3, DER-encoded OID body.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// Deepest nesting either search below needs (subject: RDNSequence → SET → ATV),
/// plus headroom. A cap, not a target — it is what makes the walk non-recursive in
/// effect on hostile input.
const MAX_DER_DEPTH: u8 = 4;

/// The host names this folder's pinned certificate vouches for, in the order the
/// recovery screen should offer them, filtered to the ones that could actually be
/// dialled.
///
/// **Order matters and is not the certificate's.** `ensure_dev_cert` mints the SANs
/// as `localhost`, `127.0.0.1`, then the public address — so the entry an operator
/// on any other machine needs is LAST in the file. A naive "first SAN" pre-fill
/// would hand a stranded operator `localhost`, which is worse than nothing. The
/// loopback entries are kept (they are the correct answer for a local install), just
/// demoted.
///
/// **Every entry is dialable.** Each candidate is run through the same
/// `ServerName::try_from` that `parse_dial_address` and `open_conn` use, so a
/// wildcard SAN (`*.example.com`), an e-mail/URI SAN or a junk DNS name can never be
/// offered as a pre-fill the operator would then have to debug.
fn dialable_hosts(cert_der: &[u8]) -> Vec<String> {
    let (subject, extensions) = tbs_parts(cert_der).unwrap_or((&[], &[]));
    let mut hosts = san_hosts(extensions);
    // Only when there is no SAN at all. A PROD deployment may inject a real CA cert
    // (`pki.rs`: "PROD injects a real cert"), and older/simpler ones carry the host
    // only in the subject CN. Modern verifiers ignore CN, so this is a hint source
    // of last resort — never a trust input.
    if hosts.is_empty() {
        hosts.extend(subject_common_name(subject));
    }
    hosts.retain(|h| ServerName::try_from(h.clone()).is_ok());
    // Stable sort ⇒ certificate order is preserved WITHIN each group.
    hosts.sort_by_key(|h| is_loopback_host(h));
    let mut seen: Vec<String> = Vec::new();
    hosts.retain(|h| {
        let fresh = !seen.contains(h);
        if fresh {
            seen.push(h.clone());
        }
        fresh
    });
    hosts
}

/// `localhost` / `127.0.0.1` / `::1` — correct for a local install, useless to a
/// stranded operator, so these sort last.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// One DER TLV: `(tag, content, rest)`. `None` on anything this app's certificates
/// cannot contain — a truncated element, a BER indefinite length, a multi-byte tag
/// number, or a length no `usize` here should hold. Refusing beats guessing: the
/// caller's fallback is "no hint", which costs the operator one typed host.
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, r) = b.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // high-tag-number form: never in an X.509 certificate.
    }
    let (&first_len, r) = r.split_first()?;
    let (len, r) = if first_len < 0x80 {
        (usize::from(first_len), r)
    } else {
        // 0x80 exactly = indefinite length (BER only, forbidden in DER); >4 length
        // octets would be a >4 GiB object. Neither can appear in a pinned cert.
        let n = usize::from(first_len & 0x7f);
        if n == 0 || n > 4 || r.len() < n {
            return None;
        }
        let (len_bytes, r) = r.split_at(n);
        (
            len_bytes
                .iter()
                .fold(0usize, |a, &x| (a << 8) | usize::from(x)),
            r,
        )
    };
    if r.len() < len {
        return None;
    }
    Some((tag, &r[..len], &r[len..]))
}

/// Split a `Certificate` into the two TBS fields this module reads: the **subject**
/// `Name` and the `[3] extensions` block.
///
/// Positional, not a search. The alternative — scanning the whole certificate for an
/// OID — would find the ISSUER's common name first on a CA-issued cert (giving the
/// CA's name as a "server address"), and could in principle match bytes inside an
/// unrelated field. Walking the actual structure costs a dozen lines and removes
/// both failure modes.
fn tbs_parts(cert_der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (0x30, certificate, _) = der_tlv(cert_der)? else {
        return None;
    };
    let (0x30, tbs, _) = der_tlv(certificate)? else {
        return None;
    };
    let mut fields: Vec<(u8, &[u8])> = Vec::new();
    let mut cur = tbs;
    while let Some((tag, content, rest)) = der_tlv(cur) {
        fields.push((tag, content));
        cur = rest;
    }
    // `[0] EXPLICIT version` is the only OPTIONAL field ahead of `subject`; drop it
    // so the fixed positions below hold for a v1 and a v3 certificate alike.
    let body = match fields.first() {
        Some((0xA0, _)) => &fields[1..],
        _ => &fields[..],
    };
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, …
    let subject = body
        .get(4)
        .filter(|(tag, _)| *tag == 0x30)
        .map_or(&[][..], |(_, c)| *c);
    // `[3] EXPLICIT extensions` is found by TAG, not position: the two deprecated
    // OPTIONAL unique-ID fields may precede it. It wraps `SEQUENCE OF Extension`.
    let extensions = body
        .iter()
        .find(|(tag, _)| *tag == 0xA3)
        .and_then(|(_, c)| der_tlv(c))
        .filter(|(tag, _, _)| *tag == 0x30)
        .map_or(&[][..], |(_, c, _)| c);
    Some((subject, extensions))
}

/// The `dNSName` / `iPAddress` entries of the SAN extension, in certificate order.
///
/// IPv6 `iPAddress` SANs are deliberately SKIPPED. `open_conn` splits `server` on
/// the LAST colon and rejects the bracket form, so there is no `host:port` string an
/// operator could build from an IPv6 literal that the dial would reliably re-split —
/// offering one would be handing them an address that cannot work.
fn san_hosts(extensions: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(extn_value) = extension_value(extensions, OID_SUBJECT_ALT_NAME) else {
        return out;
    };
    // extnValue's OCTET STRING wraps `GeneralNames ::= SEQUENCE OF GeneralName`.
    let Some((0x30, names, _)) = der_tlv(extn_value) else {
        return out;
    };
    let mut cur = names;
    while let Some((tag, content, rest)) = der_tlv(cur) {
        cur = rest;
        match tag {
            // [2] dNSName, IMPLICIT IA5String (ASCII by definition).
            0x82 => {
                if let Ok(s) = std::str::from_utf8(content) {
                    if s.is_ascii() && !s.is_empty() {
                        out.push(s.to_owned());
                    }
                }
            }
            // [7] iPAddress, IMPLICIT OCTET STRING; 4 octets = IPv4.
            0x87 if content.len() == 4 => {
                out.push(
                    std::net::Ipv4Addr::new(content[0], content[1], content[2], content[3])
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    out
}

/// The `extnValue` OCTET STRING contents of the first extension carrying `oid`.
fn extension_value<'a>(extensions: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    //                          extnValue OCTET STRING }
    let mut rest_of_extension = find_by_leading_oid(extensions, oid, MAX_DER_DEPTH)?;
    while let Some((tag, content, rest)) = der_tlv(rest_of_extension) {
        if tag == 0x04 {
            return Some(content);
        }
        rest_of_extension = rest; // skip the optional `critical` BOOLEAN
    }
    None
}

/// The subject's `CN`, when it is one of the string types a host name is issued in.
fn subject_common_name(subject: &[u8]) -> Option<String> {
    let value = find_by_leading_oid(subject, OID_COMMON_NAME, MAX_DER_DEPTH)?;
    let (tag, content, _) = der_tlv(value)?;
    // UTF8String / PrintableString / IA5String: the DirectoryString forms a CA
    // actually puts a host name in.
    if !matches!(tag, 0x0c | 0x13 | 0x16) {
        return None;
    }
    let s = std::str::from_utf8(content).ok()?;
    (s.is_ascii() && !s.is_empty()).then(|| s.to_owned())
}

/// Depth-bounded search for the first CONSTRUCTED element whose first child is
/// exactly `oid`; returns everything after that OID (the element's remaining
/// fields). Primitive elements are never descended into, so a signature or a public
/// key that happens to contain the OID's bytes cannot match.
fn find_by_leading_oid<'a>(der: &'a [u8], oid: &[u8], depth: u8) -> Option<&'a [u8]> {
    if depth == 0 {
        return None;
    }
    let mut cur = der;
    while let Some((tag, content, rest)) = der_tlv(cur) {
        cur = rest;
        if tag & 0x20 == 0 {
            continue; // primitive: no children to inspect
        }
        if let Some((0x06, id, after_oid)) = der_tlv(content) {
            if id == oid {
                return Some(after_oid);
            }
        }
        if let Some(hit) = find_by_leading_oid(content, oid, depth - 1) {
            return Some(hit);
        }
    }
    None
}

/// Write the dial address carried by an ALREADY-AUTHENTICATED connection code into
/// `<dir>/config/connection.json`. Load-then-patch (the shape
/// `register::persist_registered_server` uses) so every existing preference on the
/// file survives: `server` is the only field this command has any opinion about.
///
/// In particular `auto_connect` is left ALONE. Its sibling
/// `persist_registered_server` deliberately forces it off — enrollment is a
/// first-run ceremony that must land the user on the connect screen, and that is
/// pinned by `register.rs`'s `persist_registered_server_preserves_prior_prefs_and_forces_manual`
/// test — but re-pointing an existing install at its server is not enrollment, and
/// silently un-setting a preference the user chose in Settings is a regression, not
/// a safety measure. (The default is already `false`, so a first-run install still
/// gets manual connect without touching the field.)
fn persist_code_server(dir: &Path, addr: String) -> std::io::Result<()> {
    let mut cfg = ConnectionConfig::load(dir);
    cfg.server = addr;
    cfg.save(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private scratch dir per test. The counter (not just the clock) is what makes
    /// it unique: these tests run on parallel threads and the Windows system clock is
    /// far too coarse to separate them on its own.
    fn tempdir() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "mxboot-ut-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A scratch dir pinned exactly the way `install-client.ps1` leaves one: a REAL
    /// self-signed cert (so `pinned_client_config` genuinely accepts it) plus the
    /// pinned directory key. Returns the dir and the DER bytes the fingerprint is
    /// derived from.
    fn pinned_dir() -> (std::path::PathBuf, Vec<u8>, Vec<u8>) {
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("config")).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let dir_pub = vec![0x5Au8; 32];
        std::fs::write(dir.join("config").join("server_cert.der"), &cert_der).unwrap();
        std::fs::write(dir.join("config").join("directory_pub.der"), &dir_pub).unwrap();
        (dir, cert_der, dir_pub)
    }

    fn saved_server(dir: &Path) -> String {
        ConnectionConfig::load(dir).server
    }

    #[test]
    fn a_bare_address_points_a_pinned_folder_at_its_server() {
        // THE disaster-recovery case: the operator kept the recovery blobs and the
        // passphrase (what the shipped cold-storage instruction tells them to keep)
        // and no longer has the connection code. The pinned cert in the folder is
        // the real authenticator, so the bare address is enough.
        let (dir, _, _) = pinned_dir();
        set_server_inner(&dir, "123.123.123.123:8443").unwrap();
        assert_eq!(saved_server(&dir), "123.123.123.123:8443");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bare_address_is_normalized_and_tolerates_a_pasted_newline() {
        // Copy-paste from a text file drags whitespace along; and what lands in
        // connection.json must be exactly what `open_conn` re-splits.
        let (dir, _, _) = pinned_dir();
        set_server_inner(&dir, "  vault.example.com:08443\n").unwrap();
        assert_eq!(saved_server(&dir), "vault.example.com:8443");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bare_address_needs_a_genuinely_pinned_folder() {
        // Not pinned at all → its own code, because "check your connection code" is
        // the wrong advice when the folder is the problem.
        let dir = tempdir();
        assert_eq!(
            set_server_inner(&dir, "123.123.123.123:8443")
                .unwrap_err()
                .code,
            "not_pinned"
        );
        // Present but not a certificate → same answer (`pinned_client_config`, the
        // constructor the dial itself uses, refuses it).
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::fs::write(dir.join("config").join("server_cert.der"), b"not a cert").unwrap();
        assert_eq!(
            set_server_inner(&dir, "123.123.123.123:8443")
                .unwrap_err()
                .code,
            "not_pinned"
        );
        assert!(
            !dir.join("config").join("connection.json").exists(),
            "a rejected input must write nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unparseable_input_is_bad_code_not_untrusted() {
        // The third failure that used to hide behind `untrusted`: a typo. Distinct
        // from a pin mismatch, which is a security event.
        let (dir, _, _) = pinned_dir();
        for junk in [
            "",
            "not-an-address",
            "vault.example.com",              // no port
            "vault.example.com:notaport",     // port not a number
            "vault.example.com:0",            // port 0 cannot be dialled
            "vault.example.com:99999",        // out of u16 range
            "https://vault.example.com:8443", // a pasted URL: rustls rejects the host
            "[::1]:8443",                     // no IPv6 bracket form (open_conn agrees)
        ] {
            assert_eq!(
                set_server_inner(&dir, junk).unwrap_err().code,
                "bad_code",
                "input {junk:?} must be reported as a malformed input"
            );
        }
        assert!(
            !dir.join("config").join("connection.json").exists(),
            "a rejected input must write nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_code_whose_fingerprint_mismatches_still_fails_closed() {
        // The one genuine benefit of the code is preserved: a code that arrived over
        // an independent channel and disagrees with the folder's pins is a pin swap.
        // It must still be refused, and must still write nothing.
        let (dir, cert, _) = pinned_dir();
        // A fingerprint over the RIGHT cert but the WRONG directory key — the exact
        // shape a swapped directory pin produces.
        let wrong = maxsecu_crypto::pin_fingerprint(&cert, &[0xEEu8; 32]);
        let err = set_server_inner(&dir, &format!("123.123.123.123:8443#{wrong}")).unwrap_err();
        assert_eq!(err.code, "untrusted");
        assert!(
            !dir.join("config").join("connection.json").exists(),
            "a mismatched code must write nothing"
        );
        // …and a truncated/garbled fingerprint is a typo, not a pin swap.
        assert_eq!(
            set_server_inner(&dir, "123.123.123.123:8443#ABCD")
                .unwrap_err()
                .code,
            "bad_code"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn both_minted_code_forms_are_still_accepted() {
        // Unchanged behaviour: the 2-pin code `install-client.ps1` hands users, and
        // the cert-only code the offline-D5 stage issues.
        let (dir, cert, dir_pub) = pinned_dir();
        let two_pin = maxsecu_crypto::pin_fingerprint(&cert, &dir_pub);
        set_server_inner(&dir, &format!("1.2.3.4:8443#{two_pin}")).unwrap();
        assert_eq!(saved_server(&dir), "1.2.3.4:8443");

        let cert_only = maxsecu_crypto::pin_fingerprint(&cert, &[]);
        set_server_inner(&dir, &format!("5.6.7.8:9443#{cert_only}")).unwrap();
        assert_eq!(saved_server(&dir), "5.6.7.8:9443");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_derived_fingerprint_is_the_one_the_code_carries() {
        // What the screen shows must be comparable, character for character, against
        // the half after the `#` of the code the install minted.
        //
        // This calls the COMMAND's own body (`pinned_fingerprint_inner`, which
        // `pinned_fingerprint` is a one-line `dir.0` over) rather than re-deriving
        // the value inline. An earlier version of this test did the latter and was
        // therefore incapable of failing when the command changed — it only ever
        // asserted that `pin_fingerprint` equals `pin_fingerprint`.
        let (dir, cert, dir_pub) = pinned_dir();
        let shown = pinned_fingerprint_inner(&dir).unwrap();
        assert_eq!(shown, maxsecu_crypto::pin_fingerprint(&cert, &dir_pub));
        assert_eq!(shown.len(), 32);
        // With no directory key pinned yet it collapses to the cert-only form — the
        // code that stage of the install actually issues.
        std::fs::remove_file(dir.join("config").join("directory_pub.der")).unwrap();
        assert_eq!(
            pinned_fingerprint_inner(&dir).unwrap(),
            maxsecu_crypto::pin_fingerprint(&cert, &[])
        );
        // And the same precondition the rest of the module applies: an unpinnable
        // folder has no fingerprint to show, with the code that says so.
        let bare = tempdir();
        assert_eq!(
            pinned_fingerprint_inner(&bare).unwrap_err().code,
            "not_pinned"
        );
        let _ = std::fs::remove_dir_all(&bare);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A certificate minted exactly the way the server mints its own
    /// (`portable-server::pki::ensure_dev_cert`): `localhost`, then `127.0.0.1`,
    /// then — only with `install-server.sh --public` — the address users dial. The
    /// ORDER is the point: the one entry that matters to a stranded operator is last.
    fn cert_with_sans(sans: Vec<rcgen::SanType>) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn dns(name: &str) -> rcgen::SanType {
        rcgen::SanType::DnsName(rcgen::Ia5String::try_from(name.to_owned()).unwrap())
    }

    fn ip(addr: &str) -> rcgen::SanType {
        rcgen::SanType::IpAddress(addr.parse().unwrap())
    }

    /// The server's own SAN set for a `--public 203.0.113.7` install.
    fn public_install_sans() -> Vec<rcgen::SanType> {
        vec![dns("localhost"), ip("127.0.0.1"), ip("203.0.113.7")]
    }

    /// Pin a scratch folder to a caller-supplied certificate.
    fn pinned_to(cert_der: &[u8]) -> std::path::PathBuf {
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::fs::write(dir.join("config").join("server_cert.der"), cert_der).unwrap();
        dir
    }

    #[test]
    fn the_public_address_is_read_out_of_the_pinned_cert_ahead_of_loopback() {
        // THE gap this closes: the operator kept the blobs and the passphrase and
        // does not remember the address — but the server baked it into the very
        // certificate sitting in this folder.
        //
        // The ordering assertion is the whole test. `ensure_dev_cert` appends the
        // public address LAST, so a "first SAN" pre-fill would hand a stranded
        // operator `localhost`. Loopback is kept (it is right for a local install),
        // just demoted.
        let dir = pinned_to(&cert_with_sans(public_install_sans()));
        let hints = pinned_server_hints_inner(&dir).unwrap();
        assert_eq!(
            hints.cert_hosts,
            vec!["203.0.113.7", "localhost", "127.0.0.1"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_hostname_public_address_is_read_from_the_dns_san() {
        // `install-server.sh --public vault.example.com` → a DNS SAN, not an IP one
        // (`pki::san_for` classifies), and it must lead just the same.
        let dir = pinned_to(&cert_with_sans(vec![
            dns("localhost"),
            ip("127.0.0.1"),
            dns("vault.example.com"),
        ]));
        let hints = pinned_server_hints_inner(&dir).unwrap();
        assert_eq!(hints.cert_hosts.first().unwrap(), "vault.example.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_local_only_cert_still_hints_loopback() {
        // No `--public`: the SANs are loopback-only, and loopback IS the answer for
        // that install. "Everything is loopback" must not collapse to "no hint".
        let dir = pinned_to(&cert_with_sans(vec![dns("localhost"), ip("127.0.0.1")]));
        let hints = pinned_server_hints_inner(&dir).unwrap();
        assert_eq!(hints.cert_hosts, vec!["localhost", "127.0.0.1"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_port_is_reported_as_unknown_and_never_invented() {
        // X.509 carries no port and the handout ZIP ships no file that does, so the
        // hint is a HOST. The screen must be told this rather than assume it: a hint
        // that silently carried a made-up `:8443` would send an operator whose admin
        // chose another port into a dead dial with no clue why.
        let dir = pinned_to(&cert_with_sans(public_install_sans()));
        let hints = pinned_server_hints_inner(&dir).unwrap();
        assert!(
            !hints.port_known,
            "no port is recoverable from a certificate"
        );
        for h in &hints.cert_hosts {
            assert!(
                !h.contains(':'),
                "hint {h:?} must be a bare host, never host:port"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_currently_configured_address_is_reported_so_it_cannot_be_clobbered_blind() {
        // The screen shows what a save would replace. Empty on a device that has
        // never been pointed anywhere — which is also how the screen knows to open
        // the server panel on arrival instead of waiting for a failed challenge.
        let dir = pinned_to(&cert_with_sans(public_install_sans()));
        assert_eq!(pinned_server_hints_inner(&dir).unwrap().configured, "");

        ConnectionConfig {
            server: "old.example.com:9443".into(),
            use_tor: false,
            auto_connect: false,
        }
        .save(&dir)
        .unwrap();
        assert_eq!(
            pinned_server_hints_inner(&dir).unwrap().configured,
            "old.example.com:9443"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hints_need_a_genuinely_pinned_folder_and_write_nothing() {
        // Same precondition as `set_server_from_code`, surfaced BEFORE the operator
        // types rather than after — and reading hints is a read: it must never
        // create `connection.json` (which is exactly what `server_of` treats as "this
        // device is pointed somewhere").
        let bare = tempdir();
        assert_eq!(
            pinned_server_hints_inner(&bare).unwrap_err().code,
            "not_pinned"
        );
        std::fs::create_dir_all(bare.join("config")).unwrap();
        std::fs::write(bare.join("config").join("server_cert.der"), b"not a cert").unwrap();
        assert_eq!(
            pinned_server_hints_inner(&bare).unwrap_err().code,
            "not_pinned"
        );
        let _ = std::fs::remove_dir_all(&bare);

        let dir = pinned_to(&cert_with_sans(public_install_sans()));
        pinned_server_hints_inner(&dir).unwrap();
        assert!(
            !dir.join("config").join("connection.json").exists(),
            "reading hints must not point the device anywhere"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_hosts_the_dial_could_actually_accept_are_offered() {
        // A wildcard SAN, an e-mail SAN and a URI SAN are all legal X.509 and none is
        // a dialable host. Offering one as a pre-fill would hand the operator a
        // string that fails later with a TLS error on a screen that cannot act on it.
        // The filter is the SAME `ServerName::try_from` the dial itself applies.
        let dir = pinned_to(&cert_with_sans(vec![
            dns("*.example.com"),
            rcgen::SanType::Rfc822Name(
                rcgen::Ia5String::try_from("ops@example.com".to_owned()).unwrap(),
            ),
            rcgen::SanType::URI(
                rcgen::Ia5String::try_from("https://vault.example.com".to_owned()).unwrap(),
            ),
            dns("vault.example.com"),
        ]));
        assert_eq!(
            pinned_server_hints_inner(&dir).unwrap().cert_hosts,
            vec!["vault.example.com"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_certificate_with_no_san_falls_back_to_the_subject_common_name() {
        // PROD may inject a real CA-issued cert (`pki.rs`); older ones carry the host
        // only in the subject CN. Last resort, and a hint only — the dial still
        // verifies against whatever the cert actually vouches for.
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "vault.example.com");
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();

        let dir = pinned_to(&der);
        assert_eq!(
            pinned_server_hints_inner(&dir).unwrap().cert_hosts,
            vec!["vault.example.com"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_issuers_common_name_is_never_offered_as_the_server_address() {
        // Why `tbs_parts` walks the structure by position instead of scanning the
        // whole certificate for the CN OID: on a CA-issued cert the ISSUER's Name
        // comes FIRST, so a scan would pre-fill the operator's field with the name of
        // the certificate authority.
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example Issuing CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let mut leaf = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, "vault.example.com");
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let der = leaf
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap()
            .der()
            .to_vec();

        assert_eq!(dialable_hosts(&der), vec!["vault.example.com"]);
        let _ = der;
    }

    #[test]
    fn a_malformed_certificate_yields_no_hint_rather_than_a_panic() {
        // The parse runs over a file on disk that could be anything. Every truncation
        // of a real certificate — the cheap systematic way to hit a length field that
        // over-runs its slice — must come back as "no hint", never a panic. (The
        // pinned-cert precondition already refuses these folders; this is the belt
        // for the braces.)
        let cert = cert_with_sans(public_install_sans());
        for n in 0..cert.len() {
            assert!(
                dialable_hosts(&cert[..n]).len() <= 3,
                "a truncated certificate must not invent hints"
            );
        }
        for junk in [
            &b""[..],
            &b"not a cert"[..],
            // A SEQUENCE claiming 0xFFFF bytes of content it does not have.
            &[0x30, 0x82, 0xFF, 0xFF, 0x00][..],
            // High-tag-number form, which this parser refuses outright.
            &[0x3F, 0x81, 0x01, 0x00][..],
        ] {
            assert!(dialable_hosts(junk).is_empty());
        }
    }

    #[test]
    fn a_prefilled_host_is_still_only_a_suggestion_the_pin_decides() {
        // The fail-closed claim in the module docs, at the level this layer can
        // prove: pre-filling grants no bypass and cannot introduce a foreign address.
        let ours = cert_with_sans(public_install_sans());
        let theirs = cert_with_sans(vec![dns("evil.example.com"), ip("198.51.100.9")]);

        // 1. Hints come ONLY from the certificate THIS folder pinned. A second
        //    server's SANs are not reachable from here, so no pre-fill can point the
        //    operator at a box their own pin does not already vouch for.
        let dir = pinned_to(&ours);
        let hints = pinned_server_hints_inner(&dir).unwrap();
        for foreign in dialable_hosts(&theirs) {
            assert!(!hints.cert_hosts.contains(&foreign));
        }

        // 2. A hinted host is fed back through the SAME `resolve_dial_target` as
        //    anything typed by hand: it is not pre-authorized, and a connection code
        //    that disagrees with this folder's pins still fails closed on it.
        let host = hints.cert_hosts.first().unwrap();
        let wrong = maxsecu_crypto::pin_fingerprint(&theirs, &[]);
        assert_eq!(
            set_server_inner(&dir, &format!("{host}:8443#{wrong}"))
                .unwrap_err()
                .code,
            "untrusted"
        );
        assert!(!dir.join("config").join("connection.json").exists());

        // 3. …and the hint is not itself an address: without a port it is refused
        //    exactly like any other malformed input, which is what keeps "the screen
        //    left the port to you" honest instead of quietly dialling a default.
        assert_eq!(set_server_inner(&dir, host).unwrap_err().code, "bad_code");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_code_server_preserves_every_other_preference() {
        // Re-pointing an install at its server must set `server` and NOTHING else:
        // both `use_tor` and `auto_connect` are the user's choices and survive.
        let dir = tempdir();
        ConnectionConfig {
            server: "old:1".into(),
            use_tor: true,
            auto_connect: true,
        }
        .save(&dir)
        .unwrap();
        persist_code_server(&dir, "new-host:8443".into()).unwrap();
        let cfg = ConnectionConfig::load(&dir);
        assert_eq!(cfg.server, "new-host:8443");
        assert!(cfg.use_tor, "prior use_tor preference preserved");
        assert!(cfg.auto_connect, "prior auto_connect preference preserved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_code_server_on_a_fresh_install_leaves_auto_connect_off() {
        // No pre-existing file ⇒ the defaults apply, so a first-run install still
        // lands on the connect screen without the command forcing anything.
        let dir = tempdir();
        persist_code_server(&dir, "123.123.123.123:8443".into()).unwrap();
        let cfg = ConnectionConfig::load(&dir);
        assert_eq!(cfg.server, "123.123.123.123:8443");
        assert!(!cfg.auto_connect, "the default is already manual connect");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
