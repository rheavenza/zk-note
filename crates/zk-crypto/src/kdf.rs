//! Argon2id key derivation functions and parameter configurations.

use crate::error::CryptoError;
use crate::keys::{KeyEncryptionKey, KEY_LEN};
use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64, Encoding};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Canonical algorithm identifier for Argon2id.
pub const ARGON2ID_ALGORITHM: &str = "argon2id";

/// Recommended salt size in bytes (128 bits).
pub const SALT_LEN: usize = 16;

/// Production Argon2id parameters per MASTER_SPEC.md §5.3.
pub const PROD_MEMORY_KIB: u32 = 65536; // 64 MiB
pub const PROD_ITERATIONS: u32 = 3;
pub const PROD_PARALLELISM: u32 = 1;

/// Fast test parameters strictly isolated for test execution.
pub const TEST_MEMORY_KIB: u32 = 1024; // 1 MiB
pub const TEST_ITERATIONS: u32 = 1;
pub const TEST_PARALLELISM: u32 = 1;

/// Argon2id KDF parameter configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Algorithm identifier, must be "argon2id".
    pub algorithm: String,
    /// Random salt encoded as Standard Base64.
    pub salt: String,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost / number of iterations.
    pub iterations: u32,
    /// Degree of parallelism / lanes.
    pub parallelism: u32,
}

impl KdfParams {
    /// Creates a new `KdfParams` with production defaults and a freshly generated 16-byte random salt.
    #[must_use]
    pub fn new_production() -> Self {
        Self::new_production_with_rng(&mut rand_core::OsRng)
    }

    /// Creates a new `KdfParams` with production defaults using the provided CSPRNG.
    pub fn new_production_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut salt_bytes = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt_bytes);
        Self {
            algorithm: ARGON2ID_ALGORITHM.to_string(),
            salt: Base64::encode_string(&salt_bytes),
            memory_kib: PROD_MEMORY_KIB,
            iterations: PROD_ITERATIONS,
            parallelism: PROD_PARALLELISM,
        }
    }

    /// Creates a new `KdfParams` with fast test parameters and a freshly generated 16-byte random salt.
    ///
    /// # Safety and Security
    /// This constructor is strictly intended for tests. Do NOT use test parameters in production.
    #[must_use]
    pub fn new_test() -> Self {
        Self::new_test_with_rng(&mut rand_core::OsRng)
    }

    /// Creates a new `KdfParams` with fast test parameters using the provided CSPRNG.
    pub fn new_test_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut salt_bytes = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt_bytes);
        Self {
            algorithm: ARGON2ID_ALGORITHM.to_string(),
            salt: Base64::encode_string(&salt_bytes),
            memory_kib: TEST_MEMORY_KIB,
            iterations: TEST_ITERATIONS,
            parallelism: TEST_PARALLELISM,
        }
    }

    /// Creates a custom `KdfParams` configuration with an explicit salt byte slice.
    pub fn custom(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: &[u8],
    ) -> Result<Self, CryptoError> {
        if salt.len() < 8 {
            return Err(CryptoError::InvalidKeyLength {
                expected: SALT_LEN,
                actual: salt.len(),
            });
        }
        Ok(Self {
            algorithm: ARGON2ID_ALGORITHM.to_string(),
            salt: Base64::encode_string(salt),
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Decodes the Base64 salt into raw bytes.
    pub fn raw_salt(&self) -> Result<Vec<u8>, CryptoError> {
        Base64::decode_vec(&self.salt)
            .map_err(|e| CryptoError::InvalidEncoding(format!("invalid base64 salt: {e}")))
    }

    /// Derives a [`KeyEncryptionKey`] (KEK) from the provided passphrase and stored parameters.
    ///
    /// The caller's passphrase is not stored or retained in memory by this method.
    pub fn derive_kek(&self, passphrase: &[u8]) -> Result<KeyEncryptionKey, CryptoError> {
        derive_kek(passphrase, self)
    }
}

impl From<zk_protocol::vault::KdfParams> for KdfParams {
    fn from(p: zk_protocol::vault::KdfParams) -> Self {
        Self {
            algorithm: p.algorithm,
            salt: p.salt,
            memory_kib: p.memory_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
        }
    }
}

impl From<KdfParams> for zk_protocol::vault::KdfParams {
    fn from(p: KdfParams) -> Self {
        Self {
            algorithm: p.algorithm,
            salt: p.salt,
            memory_kib: p.memory_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
        }
    }
}

/// Derives a 256-bit [`KeyEncryptionKey`] from a user passphrase and [`KdfParams`] using Argon2id.
///
/// Implements RFC 9106 Argon2id key derivation.
/// The caller's passphrase is not stored or retained in memory by this function.
pub fn derive_kek(passphrase: &[u8], params: &KdfParams) -> Result<KeyEncryptionKey, CryptoError> {
    if params.algorithm != ARGON2ID_ALGORITHM {
        return Err(CryptoError::UnsupportedAlgorithm(params.algorithm.clone()));
    }

    let salt_bytes = params.raw_salt()?;
    if salt_bytes.len() < 8 {
        return Err(CryptoError::InvalidKeyLength {
            expected: SALT_LEN,
            actual: salt_bytes.len(),
        });
    }

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::KdfFailure(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut kek_bytes = [0u8; KEY_LEN];

    argon2
        .hash_password_into(passphrase, &salt_bytes, &mut kek_bytes)
        .map_err(|e| CryptoError::KdfFailure(e.to_string()))?;

    let kek = KeyEncryptionKey::from_bytes(kek_bytes);
    Ok(kek)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_params_serialization_round_trip() {
        let params = KdfParams::new_test();
        let json = serde_json::to_string(&params).expect("serialize kdf params");
        let parsed: KdfParams = serde_json::from_str(&json).expect("deserialize kdf params");
        assert_eq!(params, parsed);
    }

    #[test]
    fn test_protocol_kdf_params_conversion() {
        let params = KdfParams::new_production();
        let proto: zk_protocol::vault::KdfParams = params.clone().into();
        let round_trip: KdfParams = proto.into();
        assert_eq!(params, round_trip);
    }

    #[test]
    fn test_production_vs_test_params_separation() {
        let prod = KdfParams::new_production();
        let test = KdfParams::new_test();

        assert_eq!(prod.memory_kib, PROD_MEMORY_KIB);
        assert_eq!(prod.iterations, PROD_ITERATIONS);
        assert_eq!(prod.parallelism, PROD_PARALLELISM);

        assert_eq!(test.memory_kib, TEST_MEMORY_KIB);
        assert_eq!(test.iterations, TEST_ITERATIONS);
        assert_eq!(test.parallelism, TEST_PARALLELISM);

        assert_ne!(prod.memory_kib, test.memory_kib);
        assert_ne!(prod.iterations, test.iterations);
    }

    #[test]
    fn test_derive_kek_consistency() {
        let passphrase = b"correct horse battery staple";
        let params = KdfParams::new_test();

        let kek1 = params.derive_kek(passphrase).expect("derive 1");
        let kek2 = params.derive_kek(passphrase).expect("derive 2");

        assert_eq!(kek1, kek2);

        // Different passphrase produces different KEK
        let kek_different_pass = params
            .derive_kek(b"different password")
            .expect("derive diff");
        assert_ne!(kek1, kek_different_pass);

        // Different salt produces different KEK
        let params_other_salt = KdfParams::new_test();
        let kek_diff_salt = params_other_salt
            .derive_kek(passphrase)
            .expect("derive diff salt");
        assert_ne!(kek1, kek_diff_salt);
    }

    #[test]
    fn test_unsupported_algorithm_rejected() {
        let mut params = KdfParams::new_test();
        params.algorithm = "argon2d".to_string();

        let res = params.derive_kek(b"passphrase");
        assert_eq!(
            res,
            Err(CryptoError::UnsupportedAlgorithm("argon2d".to_string()))
        );
    }

    #[test]
    fn test_known_deterministic_test_vector() {
        // Deterministic test vector using RFC 9106 Argon2id:
        // Passphrase: b"password"
        // Salt: 16 bytes [0x01, 0x02, ..., 0x10]
        // Memory: 1024 KiB, Iterations: 2, Parallelism: 1
        let salt = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let params = KdfParams::custom(1024, 2, 1, &salt).expect("valid custom params");
        let kek = params.derive_kek(b"password").expect("derive kek");

        // The derived key is deterministically verified against this exact 32-byte output:
        let expected_bytes = kek.to_bytes();
        let expected_hex = expected_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        // Re-run derivation from scratch to confirm exact deterministic match:
        let kek_recomputed = params.derive_kek(b"password").expect("re-derive kek");
        assert_eq!(kek.as_bytes(), kek_recomputed.as_bytes());

        // Lock in the known 32-byte vector:
        assert_eq!(
            expected_hex, "007f6b258779db1c07dda5ff432b9025b66d7ec395ed9acba7939210b3ed97b8",
            "Argon2id deterministic test vector mismatch"
        );
    }
}
