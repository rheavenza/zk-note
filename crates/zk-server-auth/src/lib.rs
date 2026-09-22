//! Server-only WebAuthn ES256 verification, shared by native and Worker adapters.
//! No content encryption keys or client note models enter this crate.
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zk_protocol::webauthn::{WebAuthnLoginFinishRequest, WebAuthnRegisterFinishRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationFailed;
impl std::fmt::Display for VerificationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebAuthn verification failed")
    }
}
impl std::error::Error for VerificationFailed {}
type Result<T> = std::result::Result<T, VerificationFailed>;

pub fn decode(input: &str) -> Result<Vec<u8>> {
    if input.len() > 32768 {
        return Err(VerificationFailed);
    }
    Base64UrlUnpadded::decode_vec(input).map_err(|_| VerificationFailed)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}
fn client_data(
    encoded: Option<&str>,
    challenge: &[u8],
    origin: &str,
    kind: &str,
) -> Result<Vec<u8>> {
    let bytes = decode(encoded.ok_or(VerificationFailed)?)?;
    let data: ClientData = serde_json::from_slice(&bytes).map_err(|_| VerificationFailed)?;
    if data.kind != kind
        || data.origin != origin
        || data.cross_origin
        || decode(&data.challenge)? != challenge
    {
        return Err(VerificationFailed);
    }
    Ok(bytes)
}
fn auth_data(bytes: &[u8], rp: &str, registration: bool) -> Result<u32> {
    if bytes.len() < 37 || bytes[..32] != Sha256::digest(rp.as_bytes())[..] {
        return Err(VerificationFailed);
    }
    let flags = bytes[32];
    // Require user presence and verification; reject invalid backup flags and reserved bits.
    if flags & 5 != 5
        || flags & 0x22 != 0
        || (flags & 0x10 != 0 && flags & 8 == 0)
        || (flags & 0x40 != 0) != registration
    {
        return Err(VerificationFailed);
    }
    Ok(u32::from_be_bytes(
        bytes[33..37].try_into().map_err(|_| VerificationFailed)?,
    ))
}
fn field<'a>(value: &'a Value, key: &Value) -> Result<&'a Value> {
    let map = value.as_map().ok_or(VerificationFailed)?;
    let mut matches = map.iter().filter(|(k, _)| k == key);
    let result = &matches.next().ok_or(VerificationFailed)?.1;
    if matches.next().is_some() {
        return Err(VerificationFailed);
    }
    Ok(result)
}
fn number(n: i64) -> Value {
    Value::Integer(n.into())
}
fn parse_cbor(bytes: &[u8]) -> Result<Value> {
    let mut reader = std::io::Cursor::new(bytes);
    let value = ciborium::de::from_reader(&mut reader).map_err(|_| VerificationFailed)?;
    if reader.position() != bytes.len() as u64 {
        return Err(VerificationFailed);
    }
    Ok(value)
}
fn extensions(bytes: &[u8], flags: u8) -> Result<()> {
    if flags & 0x80 != 0 {
        if parse_cbor(bytes)?.as_map().is_none() {
            return Err(VerificationFailed);
        }
    } else if !bytes.is_empty() {
        return Err(VerificationFailed);
    }
    Ok(())
}

/// Accept only privacy-preserving `none` attestation and ES256 credentials.
/// Returns a canonical SEC1 public key derived from attested credential data;
/// the untrusted legacy `public_key` request field is never used as authority.
pub fn register(
    req: &WebAuthnRegisterFinishRequest,
    challenge: &[u8],
    rp: &str,
    origin: &str,
) -> Result<Vec<u8>> {
    client_data(
        req.client_data_json.as_deref(),
        challenge,
        origin,
        "webauthn.create",
    )?;
    let attestation = parse_cbor(&decode(
        req.attestation_object
            .as_deref()
            .ok_or(VerificationFailed)?,
    )?)?;
    if field(&attestation, &Value::Text("fmt".into()))?.as_text() != Some("none")
        || !field(&attestation, &Value::Text("attStmt".into()))?
            .as_map()
            .ok_or(VerificationFailed)?
            .is_empty()
    {
        return Err(VerificationFailed);
    }
    let data = field(&attestation, &Value::Text("authData".into()))?
        .as_bytes()
        .ok_or(VerificationFailed)?;
    auth_data(data, rp, true)?;
    if data.len() < 55 {
        return Err(VerificationFailed);
    }
    let len = u16::from_be_bytes([data[53], data[54]]) as usize;
    if len == 0
        || len > 1023
        || data.get(55..55 + len).ok_or(VerificationFailed)? != decode(&req.credential_id)?
    {
        return Err(VerificationFailed);
    }
    let remaining = data.get(55 + len..).ok_or(VerificationFailed)?;
    let mut reader = std::io::Cursor::new(remaining);
    let key: Value = ciborium::de::from_reader(&mut reader).map_err(|_| VerificationFailed)?;
    extensions(&remaining[reader.position() as usize..], data[32])?;
    if field(&key, &number(1))? != &number(2)
        || field(&key, &number(3))? != &number(-7)
        || field(&key, &number(-1))? != &number(1)
    {
        return Err(VerificationFailed);
    }
    let x = field(&key, &number(-2))?
        .as_bytes()
        .ok_or(VerificationFailed)?;
    let y = field(&key, &number(-3))?
        .as_bytes()
        .ok_or(VerificationFailed)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(VerificationFailed);
    }
    let mut sec1 = vec![4];
    sec1.extend(x);
    sec1.extend(y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| VerificationFailed)?;
    Ok(sec1)
}

/// Verify challenge, origin, RP binding, UP/UV flags, signature and counter.
pub fn login(
    req: &WebAuthnLoginFinishRequest,
    challenge: &[u8],
    rp: &str,
    origin: &str,
    key: &[u8],
    old_count: u64,
) -> Result<u32> {
    let client = client_data(
        req.client_data_json.as_deref(),
        challenge,
        origin,
        "webauthn.get",
    )?;
    let data = decode(
        req.authenticator_data
            .as_deref()
            .ok_or(VerificationFailed)?,
    )?;
    let count = auth_data(&data, rp, false)?;
    extensions(&data[37..], data[32])?;
    if (count != 0 || old_count != 0) && u64::from(count) <= old_count {
        return Err(VerificationFailed);
    }
    let mut message = data;
    message.extend(Sha256::digest(client));
    let signature =
        Signature::from_der(&decode(&req.signature)?).map_err(|_| VerificationFailed)?;
    VerifyingKey::from_sec1_bytes(key)
        .map_err(|_| VerificationFailed)?
        .verify(&message, &signature)
        .map_err(|_| VerificationFailed)?;
    Ok(count)
}
