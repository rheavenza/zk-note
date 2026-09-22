# ADR-0006: Verified server authentication across native and Workers

Status: Accepted (user authorized authentication compatibility changes).

Account UUIDs are identifiers, never bearer credentials. Device enrollment and
adding passkeys to an existing account require a valid account session. Anonymous
passkey registration allocates an unpredictable account ID on the server and binds
it to the single-use expiring registration challenge. CLI account-only login now
requires an existing session token, entered without echo; token login remains
available. There is no public administration or token-provisioning bypass.

`zk-server-auth` contains only server-side WebAuthn validation and depends on
`zk-protocol`, RustCrypto P-256/ECDSA and SHA-256, and ciborium CBOR decoding. It
has no client content cryptography or plaintext models. These dependencies avoid
OpenSSL/native-only linking and permit the same verifier in wasm32 Workers.
Cryptographic primitives are provided by libraries, not implemented here.

The initial supported profile is ES256, user presence and user verification
required, discoverable credentials, and privacy-preserving `none` attestation.
Registration derives the key from the attested credential data rather than trusting
the legacy public_key field. Login verifies the signature over authenticator data
and SHA-256(clientDataJSON), the exact configured origin, RP ID hash, challenge,
ceremony type, flags, and signature counter. Nonzero counters advance by CAS;
zero counters are allowed for synced passkeys. Challenge consumption is atomic
and failed ceremonies cannot reuse a challenge. Devices associated with a revoked
credential cannot be bypassed by supplying a different device ID during login.

RP ID and origin come from deployment configuration, never Host/Origin headers.
Native defaults are localhost and http://localhost:5173. Production operators
must set ZK_WEBAUTHN_RP_ID and ZK_WEBAUTHN_ORIGIN to the browser deployment.

Compatibility: /v1 routes and zk-protocol JSON shapes remain intact. Previously
optional proof fields are now required by validation. Invalid mock proofs and UUID
tokens are intentionally rejected. The browser sends the existing proof fields and
no longer fabricates credentials when WebAuthn is unavailable. Previously stored
unverified keys are not trusted by the new SEC1 key verifier; installations must
re-enroll through an authorized session or an operator-controlled recovery process.
No envelope, sync mutation, tombstone, or cursor format changes are involved.

Reference: [W3C WebAuthn Level 2 registration and assertion verification](https://www.w3.org/TR/webauthn-2/).
This is a deliberately limited WebAuthn profile, not authenticator certification or
a claim of hardware attestation. Additional algorithms/attestation formats require
explicit validation and tests.
