//! Strongly-typed, zeroizing key primitives for zero-knowledge encryption.
//!
//! Enforces:
//! - 256-bit (32-byte) key lengths;
//! - Zeroization of key material on drop;
//! - Redaction of key material in Debug representations (**SEC-003**);
//! - Constant-time equality comparisons;
//! - Generation via OS CSPRNG.

use crate::error::CryptoError;
use core::fmt;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Standard symmetric key size in bytes (256 bits).
pub const KEY_LEN: usize = 32;

macro_rules! define_key_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; KEY_LEN]);

        impl $name {
            /// Key length in bytes (32 bytes = 256 bits).
            pub const LEN: usize = KEY_LEN;

            /// Creates a key from a fixed-size 32-byte array.
            #[must_use]
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// Creates a key from a byte slice, enforcing that the slice is exactly 32 bytes.
            ///
            /// Returns [`CryptoError::InvalidKeyLength`] if the slice length is not 32.
            pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
                if slice.len() != KEY_LEN {
                    return Err(CryptoError::InvalidKeyLength {
                        expected: KEY_LEN,
                        actual: slice.len(),
                    });
                }
                let mut bytes = [0u8; KEY_LEN];
                bytes.copy_from_slice(slice);
                Ok(Self(bytes))
            }

            /// Generates a new random key using the operating-system CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                let mut bytes = [0u8; KEY_LEN];
                rand_core::OsRng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Generates a new random key using the provided CSPRNG.
            pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
                let mut bytes = [0u8; KEY_LEN];
                rng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Exposes the key bytes as a fixed-size array reference.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Clones and returns the raw 32-byte array.
            #[must_use]
            pub fn to_bytes(&self) -> [u8; KEY_LEN] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl subtle::ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                self.0.as_slice().ct_eq(other.0.as_slice())
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl Eq for $name {}

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

define_key_type!(
    VaultKey,
    "The 256-bit master Vault Key used to wrap and unwrap Object Keys."
);

define_key_type!(
    ObjectKey,
    "A 256-bit per-object encryption key used to encrypt and decrypt object payloads."
);

define_key_type!(
    RecoveryKey,
    "A 256-bit user-controlled Recovery Key that independently wraps the Vault Key."
);

define_key_type!(
    KeyEncryptionKey,
    "A 256-bit Key Encryption Key (KEK) derived from the user passphrase via Argon2id."
);

define_key_type!(
    AttachmentKey,
    "A 256-bit random per-attachment key used to encrypt and decrypt attachment chunks."
);
