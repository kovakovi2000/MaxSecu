//! Server-side decode of a posted control-log record (DESIGN §11.5/§11.5a/§11.7,
//! api.md §7.2). The server stores the **opaque** signed bytes and serves them
//! verbatim; it decodes only to derive the chain link (`prev_head`/`head`) it
//! must enforce and the **advisory** projection columns it indexes on (schema
//! `control_log`). The authenticated copy is always the bytes the client checks.

use maxsecu_crypto::sha256;
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::{KeyCompromise, Reinstatement, Revocation};
use maxsecu_encoding::types::{FileScope, Role};

/// The chain link plus the advisory projections extracted from one record.
pub(crate) struct DecodedControl {
    pub kind: i16, // 6=revocation 7=reinstatement 8=key_compromise
    pub prev_head: [u8; 32],
    pub head: [u8; 32], // SHA-256(canonical(record))
    pub subject_user_id: [u8; 16],
    pub is_account_wide: bool,
    pub scope_file_id: Option<[u8; 16]>,
    pub revoked_capability: Option<i16>,
    pub from_version: Option<i64>,
    pub scope_epoch: Option<i64>,
    pub supersedes_epoch: Option<i64>,
    pub compromised_key_version: Option<i64>,
    pub effective_from_ms: Option<u64>,
    pub issued_by: [u8; 16],
    pub co_signed_by: Option<[u8; 16]>,
}

fn scope_file(s: FileScope) -> Option<[u8; 16]> {
    match s {
        FileScope::Specific(id) => Some(id.0),
        FileScope::AccountWide => None,
    }
}

/// Decode by peeking the canonical `type_id` (encoding-spec §5); `decode` also
/// enforces canonicality, so a non-canonical record is rejected. `None` ⇒ the
/// bytes are not a canonical revocation/reinstatement/key-compromise record.
pub(crate) fn decode_control(bytes: &[u8]) -> Option<DecodedControl> {
    let id = match bytes {
        [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
        _ => return None,
    };
    let head = sha256(bytes);
    match id {
        0x0006 => {
            let r: Revocation = decode(bytes).ok()?;
            Some(DecodedControl {
                kind: 6,
                prev_head: r.prev_head.0,
                head,
                subject_user_id: r.revoked_user_id.0,
                is_account_wide: matches!(r.scope, FileScope::AccountWide),
                scope_file_id: scope_file(r.scope),
                revoked_capability: r.revoked_capability.map(|c| c as i16),
                from_version: Some(r.from_version as i64),
                scope_epoch: Some(r.revocation_epoch as i64),
                supersedes_epoch: None,
                compromised_key_version: None,
                effective_from_ms: None,
                issued_by: r.issued_by.0,
                co_signed_by: r.co_signed_by.map(|i| i.0),
            })
        }
        0x0007 => {
            let r: Reinstatement = decode(bytes).ok()?;
            Some(DecodedControl {
                kind: 7,
                prev_head: r.prev_head.0,
                head,
                subject_user_id: r.reinstated_user_id.0,
                is_account_wide: matches!(r.scope, FileScope::AccountWide),
                scope_file_id: scope_file(r.scope),
                revoked_capability: None,
                from_version: None,
                scope_epoch: Some(r.reinstatement_epoch as i64),
                supersedes_epoch: Some(r.supersedes_epoch as i64),
                compromised_key_version: None,
                effective_from_ms: None,
                issued_by: r.issued_by.0,
                co_signed_by: Some(r.co_signed_by.0),
            })
        }
        0x0008 => {
            let r: KeyCompromise = decode(bytes).ok()?;
            Some(DecodedControl {
                kind: 8,
                prev_head: r.prev_head.0,
                head,
                subject_user_id: r.user_id.0,
                is_account_wide: false,
                scope_file_id: None,
                revoked_capability: None,
                from_version: None,
                scope_epoch: None,
                supersedes_epoch: None,
                compromised_key_version: Some(r.key_version as i64),
                effective_from_ms: Some(r.effective_from.0),
                issued_by: r.issued_by.0,
                co_signed_by: Some(r.co_signed_by.0),
            })
        }
        _ => None,
    }
}

/// The lowercase role text in the advisory `users.roles` / `directory_bindings.roles`
/// TEXT[] projections.
pub(crate) fn role_text(r: &Role) -> String {
    match r {
        Role::User => "user".to_owned(),
        Role::Admin => "admin".to_owned(),
    }
}

/// Parse a role from its projection text (unknown text is ignored by the caller).
pub(crate) fn role_from_text(s: &str) -> Option<Role> {
    match s {
        "user" => Some(Role::User),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}
