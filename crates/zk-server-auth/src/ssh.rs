//! Server-only OpenSSH Ed25519 credential parsing and SSH signature verification.
use base64ct::{Base64UrlUnpadded, Encoding};
use signature::Verifier;
use ssh_key::{Algorithm, HashAlg, PublicKey, Signature};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshVerificationFailed;
impl std::fmt::Display for SshVerificationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SSH authentication failed")
    }
}
impl std::error::Error for SshVerificationFailed {}
/// Parse a public Ed25519 key and discard comments; never accept private keys/certificates.
pub fn parse_public_key(input: &str) -> Result<(PublicKey, String, String), SshVerificationFailed> {
    if input.len() > 4096 {
        return Err(SshVerificationFailed);
    }
    let input = input.trim();
    if input.chars().any(char::is_control) {
        return Err(SshVerificationFailed);
    }
    let mut key = PublicKey::from_openssh(input).map_err(|_| SshVerificationFailed)?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(SshVerificationFailed);
    }
    key.set_comment("");
    let canonical = key.to_openssh().map_err(|_| SshVerificationFailed)?;
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    Ok((key, canonical, fingerprint))
}
/// Verify a bounded SSH signature using the registered, server-stored public key.
pub fn verify_signature(
    public_key: &str,
    message: &[u8],
    encoded_signature: &str,
) -> Result<(), SshVerificationFailed> {
    let (key, _, _) = parse_public_key(public_key)?;
    if encoded_signature.len() > 1024 {
        return Err(SshVerificationFailed);
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(encoded_signature).map_err(|_| SshVerificationFailed)?;
    let signature = Signature::try_from(bytes.as_slice()).map_err(|_| SshVerificationFailed)?;
    if signature.algorithm() != Algorithm::Ed25519 {
        return Err(SshVerificationFailed);
    }
    Verifier::verify(&key, message, &signature).map_err(|_| SshVerificationFailed)
}

/// Bounded public .pub input for local operator provisioning. No private-key parser.
pub fn read_public_key_file(path: &std::path::Path) -> Result<String, SshVerificationFailed> {
    use std::io::Read;
    if path.extension().and_then(|s| s.to_str()) != Some("pub") {
        return Err(SshVerificationFailed);
    }
    let file = std::fs::File::open(path).map_err(|_| SshVerificationFailed)?;
    let mut input = String::new();
    file.take(4097)
        .read_to_string(&mut input)
        .map_err(|_| SshVerificationFailed)?;
    let (_, canonical, _) = parse_public_key(&input)?;
    Ok(canonical)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use signature::Signer;
    #[test]
    fn stored_ed25519_key_verifies_only_original_message_and_wire_signature() {
        let key = ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .unwrap();
        let other = ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .unwrap();
        let public = key.public_key().to_openssh().unwrap();
        let message = b"zk-note-ssh-auth-v1 test message";
        let signature: Signature = key.try_sign(message).unwrap();
        let bytes: Vec<u8> = signature.try_into().unwrap();
        let encoded = Base64UrlUnpadded::encode_string(&bytes);
        verify_signature(&public, message, &encoded).unwrap();
        assert!(
            verify_signature(&other.public_key().to_openssh().unwrap(), message, &encoded).is_err()
        );
        assert!(verify_signature(&public, b"mutated", &encoded).is_err());
        for bad in ["bad", "", "c2VjcmV0LXNpZ25hdHVyZQ"] {
            let error = verify_signature(&public, message, bad).unwrap_err();
            assert_eq!(format!("{error:?}"), "SshVerificationFailed");
            assert_eq!(error.to_string(), "SSH authentication failed");
        }
        assert!(parse_public_key(&format!("{public}\nprivate-sentinel")).is_err());
    }
}
