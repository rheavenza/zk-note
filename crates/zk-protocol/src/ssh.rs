//! Version 1 native SSH authentication. Contains no vault or content secrets.
use crate::auth::AuthToken;
use base64ct::{Base64Unpadded, Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Domain separator for the canonical signed authentication message.
pub const SSH_AUTH_DOMAIN: &str = "zk-note-ssh-auth-v1";
/// SSH authentication protocol version.
pub const SSH_AUTH_VERSION: u32 = 1;

/// Begin a proof, without disclosing whether a fingerprint is registered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshStartRequest {
    pub version: u32,
    pub fingerprint: String,
    pub audience: String,
    pub account_id: Option<Uuid>,
    pub device_id: Uuid,
}

/// All fields are bound by the signature; the server persists this exact challenge.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshChallenge {
    pub request: SshStartRequest,
    pub challenge_id: Uuid,
    /// Base64url without padding, encoding 32 CSPRNG bytes.
    pub nonce: String,
    /// Unix seconds, authoritative server expiry (120 seconds after issuance).
    pub expires_at: u64,
}
impl std::fmt::Debug for SshChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshChallenge")
            .field("challenge_id", &self.challenge_id)
            .field("proof", &"[REDACTED]")
            .finish()
    }
}
/// Invalid canonical authentication fields. Never includes input material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSshChallenge;
impl std::fmt::Display for InvalidSshChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid SSH authentication challenge")
    }
}
impl std::error::Error for InvalidSshChallenge {}
impl SshChallenge {
    /// Binary v1 framing: u32-BE length + UTF-8 domain, u32-BE version,
    /// length-prefixed audience and fingerprint, optional account (one-byte tag
    /// followed by 16 UUID bytes if present), 16-byte device and challenge UUIDs,
    /// 32 raw nonce bytes, and u64-BE Unix expiration. No JSON is signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, InvalidSshChallenge> {
        let r = &self.request;
        if r.fingerprint.len() != 50 || self.nonce.len() != 43 {
            return Err(InvalidSshChallenge);
        }
        let fingerprint = r
            .fingerprint
            .strip_prefix("SHA256:")
            .ok_or(InvalidSshChallenge)?;
        let digest = Base64Unpadded::decode_vec(fingerprint).map_err(|_| InvalidSshChallenge)?;
        let nonce = Base64UrlUnpadded::decode_vec(&self.nonce).map_err(|_| InvalidSshChallenge)?;
        if r.version != SSH_AUTH_VERSION
            || r.device_id.is_nil()
            || self.challenge_id.is_nil()
            || r.account_id.is_some_and(|id| id.is_nil())
            || self.expires_at == 0
            || nonce.len() != 32
            || digest.len() != 32
            || Base64Unpadded::encode_string(&digest) != fingerprint
            || Base64UrlUnpadded::encode_string(&nonce) != self.nonce
            || r.audience.len() > 2048
            || !r.audience.is_ascii()
            || r.audience
                .bytes()
                .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
            || !(r.audience.starts_with("https://") || r.audience.starts_with("http://"))
        {
            return Err(InvalidSshChallenge);
        }
        let mut bytes = Vec::with_capacity(256);
        append_string(&mut bytes, SSH_AUTH_DOMAIN);
        bytes.extend_from_slice(&r.version.to_be_bytes());
        append_string(&mut bytes, &r.audience);
        append_string(&mut bytes, &r.fingerprint);
        match r.account_id {
            Some(id) => {
                bytes.push(1);
                bytes.extend_from_slice(id.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(r.device_id.as_bytes());
        bytes.extend_from_slice(self.challenge_id.as_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(bytes)
    }
}
fn append_string(bytes: &mut Vec<u8>, value: &str) {
    // All strings above are bounded by protocol constants/validation.
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Complete a proof using an SSH wire-format signature encoded as base64url.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshFinishRequest {
    pub challenge: SshChallenge,
    /// Redacted during formatting; explicitly exposed only to serialization/verifier.
    pub signature: AuthToken,
}

/// Only public OpenSSH keys are accepted. Private key and unknown fields are rejected.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddSshKeyRequest {
    pub public_key: String,
    pub label: Option<String>,
}
/// Public metadata for managing machine credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshCredential {
    pub credential_id: Uuid,
    pub fingerprint: String,
    pub label: Option<String>,
    pub device_id: Option<Uuid>,
    pub revoked: bool,
}

impl std::fmt::Debug for AddSshKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddSshKeyRequest")
            .field("public_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn fixture() -> SshChallenge {
        SshChallenge {
            request: SshStartRequest {
                version: 1,
                audience: "https://notes.example".into(),
                fingerprint: format!("SHA256:{}", Base64Unpadded::encode_string(&[2; 32])),
                account_id: Some(Uuid::from_bytes([3; 16])),
                device_id: Uuid::from_bytes([4; 16]),
            },
            challenge_id: Uuid::from_bytes([5; 16]),
            nonce: Base64UrlUnpadded::encode_string(&[6; 32]),
            expires_at: 123,
        }
    }
    #[test]
    fn golden_canonical_binary_vector() {
        let bytes = fixture().signing_bytes().unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "000000137a6b2d6e6f74652d7373682d617574682d7631000000010000001568747470733a2f2f6e6f7465732e6578616d706c65000000325348413235363a41674943416749434167494341674943416749434167494341674943416749434167494341674943416749010303030303030303030303030303030304040404040404040404040404040404050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606000000000000007b");
    }
    #[test]
    fn every_binding_changes_signed_bytes_and_malformed_fields_fail() {
        let original = fixture();
        let bytes = original.signing_bytes().unwrap();
        for field in 0..7 {
            let mut c = original.clone();
            match field {
                0 => c.request.audience = "https://other.example".into(),
                1 => c.request.device_id = Uuid::from_bytes([8; 16]),
                2 => c.challenge_id = Uuid::from_bytes([8; 16]),
                3 => {
                    c.request.fingerprint =
                        format!("SHA256:{}", Base64Unpadded::encode_string(&[8; 32]))
                }
                4 => c.request.account_id = None,
                5 => c.nonce = Base64UrlUnpadded::encode_string(&[8; 32]),
                _ => c.expires_at += 1,
            }
            assert_ne!(c.signing_bytes().unwrap(), bytes);
        }
        for field in 0..8 {
            let mut c = original.clone();
            match field {
                0 => c.request.version = 2,
                1 => c.request.device_id = Uuid::nil(),
                2 => c.challenge_id = Uuid::nil(),
                3 => c.request.fingerprint = "SHA256:bad".into(),
                4 => c.request.account_id = Some(Uuid::nil()),
                5 => c.nonce = "bad".into(),
                6 => c.request.audience = "https://example\n".into(),
                _ => c.expires_at = 0,
            }
            assert!(c.signing_bytes().is_err());
        }
    }
    #[test]
    fn serialization_and_secret_redaction() {
        let request = SshFinishRequest {
            challenge: fixture(),
            signature: AuthToken::new("proof_secret"),
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: SshFinishRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.challenge, request.challenge);
        assert!(!format!("{request:?}").contains("proof_secret"));
        assert!(!format!("{request:?}").contains(&request.challenge.nonce));
        let add = AddSshKeyRequest {
            public_key: "private-input-sentinel".into(),
            label: None,
        };
        assert!(!format!("{add:?}").contains("private-input-sentinel"));
        for field in ["private_key", "passphrase", "vault_key", "plaintext"] {
            let mut value = serde_json::to_value(&request).unwrap();
            value[field] = "secret".into();
            assert!(serde_json::from_value::<SshFinishRequest>(value).is_err());
            let value = serde_json::json!({"public_key":"ssh-ed25519 ...",field:"secret"});
            assert!(serde_json::from_value::<AddSshKeyRequest>(value).is_err());
        }
    }
}
