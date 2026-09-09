# zk-core

Core note domain model, validation rules, vault lifecycle orchestration, and cryptographic envelope bridging for the zero-knowledge note system.

## Plaintext Note Model (`PlaintextNote`)

The plaintext note domain model (`zk_core::note::PlaintextNote`, aliased as `zk_core::Note`) encapsulates the user's decrypted note content and client metadata.

### Schema (`NOTE_SCHEMA_VERSION_V1 = 1`)

```json
{
  "schema_version": 1,
  "title": "Meeting Notes",
  "body": "# Architecture Review\n\nAll security invariants hold.",
  "tags": [
    "architecture",
    "security"
  ],
  "created_at": "2026-09-09T05:00:00.000Z",
  "updated_at": "2026-09-09T05:30:00.000Z",
  "attachments": []
}
```

### Canonicalization & Deterministic Serialization

Before a note is serialized and passed to the encryption envelope:
1. **UTF-8 BOM Stripping**: Leading Byte Order Marks (`\u{feff}`) in title and body are stripped.
2. **Newline Normalization**: All newlines in the Markdown body are normalized to Unix newlines (`\n`).
3. **Tag Canonicalization**: Tags are trimmed of whitespace, converted to lowercase, filtered of empty strings, deduplicated, and sorted in ascending lexicographical order.
4. **Deterministic JSON**: Serialized with a fixed struct field order (`schema_version`, `title`, `body`, `tags`, `created_at`, `updated_at`, `attachments`), ensuring identical semantic state produces byte-identical canonical JSON.

### Validation Limits

| Constant | Value | Description |
|---|---|---|
| `NOTE_SCHEMA_VERSION_V1` | `1` | Only schema version 1 is supported. |
| `MAX_TITLE_LEN` | `1024` bytes | Maximum note title length in bytes. |
| `MAX_BODY_LEN` | `10 * 1024 * 1024` bytes (10 MiB) | Maximum note body size in bytes. |
| `MAX_TAGS_COUNT` | `100` | Maximum number of tags per note. |
| `MAX_TAG_LEN` | `128` bytes | Maximum length of an individual tag. |
| `MAX_ATTACHMENTS_COUNT` | `100` | Maximum number of attachment identifiers per note. |
| `MAX_ATTACHMENT_ID_LEN` | `128` bytes | Maximum length of an attachment identifier. |

RFC 3339 timestamps are strictly validated for month ranges, leap years, day-of-month bounds, and timezone offsets.

### Cryptographic Integration

`PlaintextNote` integrates directly with `zk-crypto`:
- `note.encrypt(&vault_key, object_id)`: Canonicalizes, validates, and encrypts into a `zk_protocol::envelope::EncryptedEnvelope` (kind = `OBJECT_KIND_NOTE`).
- `PlaintextNote::decrypt(&envelope, &vault_key)`: Validates envelope version, decrypts payload, parses JSON, and validates domain rules.
