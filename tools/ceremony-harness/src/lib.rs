//! TEST-ONLY scripted offline ceremony (spec §4.5). Wraps the air-gapped
//! `admin-core` D5 key so a test can D5-sign + revoke without a real air-gap.
//! NEVER a production path — the real ceremony runs the CLIs offline.

#![forbid(unsafe_code)]

use maxsecu_admin_core::{
    CoSign, ControlChain, DirectorySigner, RevokeParams, SignedControlRecord,
};
use maxsecu_crypto::{fingerprint, SigningKey};
use maxsecu_encoding::encode;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::types::{Bytes32, FileScope, Id, Role, RoleSet, Text, Timestamp};

/// Far-future validity bound for test bindings (year 2100).
pub const FAR_FUTURE_MS: u64 = 4_102_444_800_000;

/// The scripted ceremony: holds the D5 key (and dual-control admin keys for
/// account-wide revokes) the way the offline ceremony would.
pub struct Ceremony {
    d5: DirectorySigner,
}

/// What the publish endpoint consumes: the canonical binding bytes + D5 signature.
pub struct PublishedBinding {
    pub binding_bytes: Vec<u8>,
    pub signature: [u8; 64],
}

impl Ceremony {
    /// Generate a fresh D5 key (key-generation ceremony).
    pub fn generate() -> Ceremony {
        Ceremony {
            d5: DirectorySigner::generate(),
        }
    }

    /// The pinned D5 public key clients + the server are configured with.
    pub fn directory_pub(&self) -> [u8; 32] {
        self.d5.public_key()
    }

    /// Sign an identity binding with the given roles, modeling the in-person
    /// fingerprint-confirmation step. `user_id`/`enc_pub`/`sig_pub` are the values
    /// the server returned at registration.
    pub fn sign_binding(
        &self,
        username: &str,
        user_id: [u8; 16],
        enc_pub: [u8; 32],
        sig_pub: [u8; 32],
        roles: &[Role],
        key_version: u64,
    ) -> PublishedBinding {
        let binding = DirBinding {
            username: Text::new(username).expect("valid username"),
            user_id: Id(user_id),
            enc_pub: Bytes32(enc_pub),
            sig_pub: Bytes32(sig_pub),
            key_version,
            roles: RoleSet::new(roles.iter().copied()),
            not_before: Timestamp(0),
            not_after: Timestamp(FAR_FUTURE_MS),
            mlkem_pub: None,
        };
        let confirmed = fingerprint(&enc_pub, &sig_pub); // the admin confirms this in person
        let signed = self
            .d5
            .sign_enrollment(&binding, &confirmed)
            .expect("fingerprint matches (scripted)");
        PublishedBinding {
            binding_bytes: encode(&signed.binding),
            signature: signed.signature,
        }
    }

    /// A dual-controlled account-wide revocation tombstone (for de-admin/revoke
    /// flows). The caller supplies both admins' signing keys + ids so it owns the
    /// keys needed to verify the returned record. Returns the signed record + the
    /// new anchored head.
    pub fn account_revoke(
        &self,
        issuer: &SigningKey,
        issuer_id: [u8; 16],
        co: &SigningKey,
        co_id: [u8; 16],
        revoked: [u8; 16],
        at_ms: u64,
    ) -> (SignedControlRecord, [u8; 32]) {
        let mut chain = ControlChain::new();
        let rec = chain
            .revoke(
                issuer,
                RevokeParams {
                    scope: FileScope::AccountWide,
                    revoked_user_id: Id(revoked),
                    revoked_capability: None,
                    from_version: 1,
                    issued_by: Id(issuer_id),
                    created_at: Timestamp(at_ms),
                },
                Some(CoSign {
                    admin_id: Id(co_id),
                    key: co,
                }),
            )
            .expect("account-wide revoke is dual-controlled");
        let head = chain.head();
        (rec, head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::VerifyingKey;
    use maxsecu_encoding::decode;
    use maxsecu_encoding::labels::DIRBINDING;

    #[test]
    fn signed_binding_verifies_under_the_pinned_d5() {
        let cer = Ceremony::generate();
        let pb = cer.sign_binding(
            "alice",
            [0x0A; 16],
            [0xE1; 32],
            [0x51; 32],
            &[Role::User],
            1,
        );
        let binding: DirBinding = decode(&pb.binding_bytes).unwrap();
        VerifyingKey::from_bytes(&cer.directory_pub())
            .unwrap()
            .verify_canonical(DIRBINDING, &binding, &pb.signature)
            .expect("a scripted-ceremony binding verifies under the pinned D5");
        assert_eq!(binding.roles.roles(), &[Role::User]);
    }

    #[test]
    fn account_revoke_record_verifies_under_the_issuer_and_cosigner() {
        use maxsecu_encoding::GENESIS_HEAD;
        let cer = Ceremony::generate();
        let issuer = SigningKey::generate();
        let co = SigningKey::generate();
        let (rec, head) = cer.account_revoke(
            &issuer,
            [0xAD; 16],
            &co,
            [0xC0; 16],
            [0x0F; 16],
            1_719_500_000_000,
        );
        rec.verify(&issuer.verifying_key().to_bytes())
            .expect("issuer signature verifies");
        rec.verify_co_sign(&co.verifying_key().to_bytes())
            .expect("co-signer signature verifies");
        assert_eq!(head, rec.head);
        assert_ne!(head, GENESIS_HEAD.0, "the chain head advanced past genesis");
    }
}
