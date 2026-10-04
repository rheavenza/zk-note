# ZK-107 — Redacted network evidence

This document records the shape of every server-bound request the web client
produces across the complete ZK-107 journey (register → link/bootstrap upload →
first sync → conflict → tombstone delete). It exists to show that **only
ciphertext and permitted sync metadata** leave the browser (SEC-001/SEC-002).

It is produced by `apps/web/e2e/zero-knowledge-evidence.spec.ts`, which drives
two real browser contexts against a local `zk-server` and the production bundle
while recording every `/v1` request body, then asserts:

1. no note title, note body, edit text, tag, passphrase, recovery key, or raw key
   material appears in any request body;
2. no forbidden wire key name (`title`, `body`, `tags`, `passphrase`, `plaintext`,
   `vault_key`, `note_key`, `recovery_key`, `search_terms`, …) appears anywhere,
   at any nesting depth;
3. `/v1/sync/push` bodies use only the protocol keys below, and the opaque
   envelope carries only AEAD metadata (`nonce`/`ciphertext`);
4. locking and unlocking the vault performs **no** network I/O at all.

The assertions are the gate; this file is the human-readable summary. Placeholders
stand for values whose real content is opaque or variable-length:
`<uuid>` = opaque identifier, `<b64url>` = base64url ciphertext/signature,
`<int>` = integer, `<bool>` = boolean.

## Endpoint payload shapes

### `POST /v1/auth/webauthn/register/start`

```json
{ "display_name": "<string>", "username": "<string>" }
```

Account metadata only. Allowed by SEC-001 ("Authentication traffic is separate").

### `POST /v1/auth/webauthn/register/finish`

```json
{
  "attestation_object": "<b64url>",
  "challenge_id": "<uuid>",
  "client_data_json": "<b64url>",
  "credential_id": "<b64url>",
  "display_name": "<string>",
  "public_key": "<b64url>"
}
```

### `POST /v1/auth/webauthn/login/start` → `{}`
### `POST /v1/auth/webauthn/login/finish`

```json
{
  "authenticator_data": "<b64url>",
  "challenge_id": "<uuid>",
  "client_data_json": "<b64url>",
  "credential_id": "<b64url>",
  "signature": "<b64url>"
}
```

### `GET /v1/vault/bootstrap` — no request body.

### `POST /v1/vault/bootstrap`

```json
{
  "crypto_version": "<int>",
  "kdf": {
    "algorithm": "<string>",
    "iterations": "<int>",
    "memory_kib": "<int>",
    "parallelism": "<int>",
    "salt": "<b64url>"
  },
  "recovery_wrapped_vault_key": {
    "cipher_suite": "<string>",
    "ciphertext": "<b64url>",
    "nonce": "<b64url>"
  },
  "wrapped_vault_key": {
    "cipher_suite": "<string>",
    "ciphertext": "<b64url>",
    "nonce": "<b64url>"
  }
}
```

The vault key is present only as an AEAD-wrapped ciphertext. The passphrase and
recovery key are never transmitted; the KDF salt is public derivation metadata.

### `GET /v1/sync/pull?after=<seq>&limit=<n>` — no request body; the bearer token
travels in the `Authorization` header only.

### `POST /v1/sync/push`

```json
{
  "mutation_id": "<uuid>",
  "object_id": "<uuid>",
  "expected_revision": "<int>",
  "object_kind": "<int>",
  "is_deleted": "<bool>",
  "envelope": {
    "envelope_version": "<int>",
    "object_id": "<uuid>",
    "object_kind": "<int>",
    "wrapped_key": { "nonce": "<b64url>", "ciphertext": "<b64url>" },
    "payload": { "nonce": "<b64url>", "ciphertext": "<b64url>" }
  }
}
```

The note's title, body, and tags live only inside `payload.ciphertext`. The
delete/tombstone path reuses the same shape with `is_deleted = true`.

## Not observed, by design

- No plaintext search terms, titles, bodies, tags, or attachment filenames are
  ever sent — the server exposes no endpoint that would accept them.
- No `passphrase`, `vault_key`, `note_key`, or `recovery_key` field exists on the
  wire; the client-side zero-knowledge validator (`validateNoPlaintextSecrets`)
  fails closed before any request is dispatched.
