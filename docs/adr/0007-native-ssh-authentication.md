# ADR-0007: Agent-first Ed25519 authentication for the native client

Status: Accepted for ZK-109.

Authentication remains independent of vault encryption (MASTER_SPEC §4). Native
clients prove possession of an operator-provisioned `ssh-ed25519` public key over
HTTPS, then use the existing `SessionResponse`, bearer middleware, and device
revocation APIs. No SSH daemon or sync transport is added. The native deployment
supports these endpoints; Workers support is outside ZK-109.

## Dependencies and proof format

RustCrypto `ssh-key` 0.6.7 parses OpenSSH public keys, computes SHA256 fingerprints,
parses SSH signatures, and verifies Ed25519 using its library implementation.
`ssh-agent-client-rs` 1.1.3 handles the agent protocol. Versions are locked in
Cargo.lock. The agent library enables additional parser algorithms transitively;
application selection, provisioning, and verification accept only plain Ed25519
keys and signatures. RSA, certificates, security-key variants and direct private
key files are unsupported. Native HTTPS uses reqwest's Rustls backend with
platform certificate verification; authentication redirects are disabled.

The canonical message is binary, implemented only in `zk-protocol::ssh`:

```text
u32be(len(domain)) || UTF8("zk-note-ssh-auth-v1") || u32be(1)
|| u32be(len(audience)) || UTF8(audience)
|| u32be(len(fingerprint)) || UTF8(OpenSSH SHA256 fingerprint)
|| account_tag:u8 || [account_uuid:16 if tag=1; no bytes if tag=0]
|| device_uuid:16 || challenge_uuid:16 || random_nonce:32
|| expiration_unix_seconds:u64be
```

UUID bytes use RFC UUID order (`Uuid::as_bytes`); lengths count UTF-8 bytes.
Wire JSON carries the nonce as canonical unpadded base64url, but the signed
message includes the decoded 32 bytes. Fingerprints use `SHA256:` plus canonical
unpadded standard base64 of the 32-byte digest. Nil UUIDs, invalid version,
malformed nonce/fingerprint, zero expiry and unbounded fields are rejected.
The optional account UUID binds an explicit client constraint; the credential
fingerprint and stored account ownership always determine the actual account.
A literal hex golden vector and per-field mutation tests lock this format.

This is an application authentication signature in SSH signature wire format,
not an SSH connection signature or an OpenSSH SSHSIG document. The agent signs
only locally reconstructed, validated challenge bytes. The client checks the
returned request against its own request, the UUID, 32-byte nonce, and expiry
(allowing up to 60 seconds of clock skew beyond the server's 120-second TTL).
The server reconstructs bytes from its persisted challenge, requires the exact
returned fields, checks configured audience and expiry, and consumes each proof
atomically before validation, including unsuccessful proofs.

## Storage and revocation

Append-only migration 010 adds public credentials, login-v1 challenges, and an
optional credential association on sessions. Fingerprints and canonical public
keys are globally unique even after revocation. Comments are discarded. Account
creation plus initial key insertion is transactional and available only through
the local operator command. Authenticated key management is account scoped.

A key binds to its first device ID. Further login must use that device; a revoked
device cannot bypass revocation by supplying another ID. Use one key per machine.
Challenge start looks up an active registered credential and stores its reference.
Unknown/revoked keys get indistinguishable dummy challenges with no credential
reference; finish always fails generically. Registration after a dummy start
cannot turn it into a usable challenge. This avoids account enumeration.

Proof verification, credential/device checks, first-device association and session
insertion run in a database transaction. Session secrets are 32 CSPRNG bytes; only
BLAKE2s digests are persisted. SSH sessions expire after one hour, and no refresh
mechanism is introduced. Re-authenticate through the agent after expiry. Logout
revokes the session without revoking the key. Key revocation atomically revokes
its pinned device and all sessions for that device, including sessions issued by
other authentication methods. Sessions derived from the key are also revoked.
Other machine keys/devices remain usable; existing device/session revocation is
authoritative. A derived device's independent key can still authenticate if its
own credential/device has not been revoked.

## Client behavior and limits

The agent retains private material; production code never reads private key files
or exports a key from the agent. Unix agent I/O has 15-second read/write timeouts
and runs on blocking worker threads. `SSH_AUTH_SOCK` selects the local agent;
Windows support follows the agent library's named-pipe connection implementation
and is not verified by the Unix integration fixture.

Agent Ed25519 identities are sorted lexically by SHA256 fingerprint. One key is
selected automatically. Multiple keys require an explicit `--identity SHA256:...`
(`--fingerprint` alias) for noninteractive CLI login, or a numbered prompt in a
terminal. The TUI Account modal discovers identities through its SSH Agent
button, displays type/fingerprint/sanitized comment and cycles with Left/Right;
Enter signs using the selected key. `r` reloads agent identities. Token input and
authorization remain available. Agent discovery never signs a challenge.
SSH-issued devices use the fixed label `SSH native client`; `--device-name` remains
applicable to token device authorization. Auth sessions are atomically replaced
using restricted temporary files; failed proofs/discovery never overwrite the
previous session. Cancel scrubs token input and clears pending modal work.

Vault linking/restoration remains a separate task. SSH authentication neither
uploads nor unlocks a vault. No content format, sync architecture, cursor,
mutation, merge or tombstone behavior changes.

## Verification

`cargo test -p zk-server --test server_ssh_auth_tests` exercises HTTP login/key
management, bindings, expiry, replay, revocation, ownership, secret rejection and
redaction. `cargo test -p zk-cli ssh::tests` starts an isolated OpenSSH agent,
loads generated keys in memory, and exercises selection plus full native HTTP
login/session/status/logout. This test requires `ssh-agent` on Unix and local
socket permissions. `scripts/server-contract.mjs` independently checks existing
passkey and ciphertext API compatibility.

References: [ssh-key](https://docs.rs/ssh-key/0.6.7/ssh_key/),
[ssh-agent-client-rs](https://docs.rs/ssh-agent-client-rs/1.1.3/ssh_agent_client_rs/).

## Audience trust

`ZK_SSH_AUTH_ORIGIN` is an operator-configured canonical origin, defaulting to
`http://127.0.0.1:8080`. It is never derived from Host/forwarding/browser headers.
The configured string must equal `url::Url::origin().ascii_serialization()`:
lowercase ASCII/IDNA hostname, canonical IPv6 brackets, no explicit default port,
no trailing slash, credentials, path, query or fragment. Remote HTTPS is required;
HTTP is allowed only for localhost and loopback IPs. Custom bind ports require
explicit audience configuration. The client applies its existing URL validation
and compares the challenge audience with its intended normalized server origin
before requesting any signature. Redirects are disabled for auth traffic.
