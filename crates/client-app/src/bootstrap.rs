//! Glass-break emergency-credential generation (spec §4.1/§4.2). Random local
//! creds, sealed like any portable keystore; never auto-logged-in.

use maxsecu_client_core::Identity;
use maxsecu_crypto::random_array;

use crate::error::UiError;

/// A freshly generated emergency credential set. The password is high-entropy and
/// shown once; the identity is sealed by the caller into the keystore.
pub struct GlassbreakCreds {
    pub username: String,
    pub password: String,
    pub identity: Identity,
}

/// Generate a random username (`gb-<hex>`) + a high-entropy password + a fresh
/// identity. Pure/local — no network, no login.
pub fn generate_glassbreak() -> GlassbreakCreds {
    let uname_suffix: [u8; 6] = random_array();
    let pw_bytes: [u8; 24] = random_array();
    GlassbreakCreds {
        username: format!("gb-{}", hex_lower(&uname_suffix)),
        password: base64_url(&pw_bytes),
        identity: Identity::generate(),
    }
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// URL-safe base64 without padding — a copy-pasteable password alphabet.
fn base64_url(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(b)
}

/// Validate that a generated password meets the length floor.
pub fn ensure_strong(password: &str) -> Result<(), UiError> {
    if password.len() < 16 {
        return Err(UiError::new(
            "weak_password",
            "Generated password too short.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glassbreak_creds_are_random_and_well_formed() {
        let a = generate_glassbreak();
        let b = generate_glassbreak();
        assert!(a.username.starts_with("gb-"));
        assert_ne!(a.username, b.username, "usernames are random");
        assert_ne!(a.password, b.password, "passwords are random");
        ensure_strong(&a.password).unwrap();
        assert_ne!(a.identity.sig_pub_bytes(), b.identity.sig_pub_bytes());
    }
}
