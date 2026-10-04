//! Isolated ZK-108 feasibility probe. No application routes, credentials or vaults.
#![forbid(unsafe_code)]
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

// Obvious synthetic fixture; never accepts real passwords.
const PASSWORD: &[u8] = b"ZK-108-dummy-password-only";

pub fn hash(memory_kib: u32, iterations: u32) -> Result<String, String> {
    let params = Params::new(memory_kib, iterations, 1, Some(32))
        .map_err(|_| "invalid probe parameters".to_owned())?;
    let salt = SaltString::generate(&mut OsRng);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(PASSWORD, &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "probe hashing failed".to_owned())
}

pub fn verify(encoded: &str, correct: bool) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(
            if correct {
                PASSWORD
            } else {
                b"wrong-dummy-password"
            },
            &parsed,
        )
        .is_ok()
}

#[wasm_bindgen]
pub fn hash_probe(memory_kib: u32, iterations: u32) -> Result<String, JsValue> {
    hash(memory_kib, iterations).map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn verify_probe(encoded: &str, correct: bool) -> bool {
    verify(encoded, correct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_parameters_and_verification() {
        let first = hash(19456, 2).expect("synthetic probe hashes");
        let second = hash(19456, 2).expect("synthetic probe hashes");
        assert!(first.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert_ne!(first, second, "CSPRNG salts must differ");
        assert!(verify(&first, true));
        assert!(!verify(&first, false));
        assert!(!verify("malformed-verifier", true));
    }
}
