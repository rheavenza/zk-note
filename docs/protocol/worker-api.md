# Web Worker Cryptographic Message API Specification

Version: 1.0  
Status: Active  
Milestone: M6 (ZK-062)  
Applies to: `apps/web`

---

## 1. Purpose & Security Boundaries

This document specifies the message-passing protocol between the browser UI thread (React components) and the dedicated Web Worker hosting the Rust WebAssembly cryptographic core (`zk-wasm`).

### 1.1 Invariants Enforced

- **SEC-001 / SEC-002 — Plaintext and Keys Never Exposed to React State**:
  The raw 32-byte `VaultKey`, derived Key Encryption Keys (KEK), and `WasmVaultSession` instance live **strictly** within WebAssembly linear memory inside the isolated Web Worker thread. React component state, dev tools, and global browser variables never receive or hold raw key bytes.
- **SEC-003 — No Secrets in Logs**:
  Messages across the boundary contain note identifiers, envelope JSON payloads, or sanitized error codes. Unencrypted passphrases sent during unlock/init are consumed immediately and scrubbed.
- **SEC-009 — Ephemeral Plaintext Only**:
  Plaintext notes exist in UI memory only while unlocked and active. When the vault is locked (`LOCK_VAULT`), the worker zeroes all session key material using `zeroize`, flushes in-memory search indexes, and broadcasts `VAULT_LOCKED` to clear UI note state.
- **SEC-010 — Fail-Closed Cryptography**:
  All invalid envelopes, tampered ciphertexts, wrong passphrases, and unauthorized actions reject with typed error codes.

---

## 2. Message Architecture

Communication uses asynchronous RPC message passing with correlation identifiers:

```text
┌──────────────────────────────────────────────┐
│                  Main Thread                 │
│              (React / UI Layer)              │
│                                              │
│   ┌──────────────────────────────────────┐   │
│   │          VaultWorkerClient           │   │
│   └──────────────────────────────────────┘   │
└──────────────┬────────────────▲──────────────┘
               │                │
 WorkerRequest │                │ WorkerResponse / BroadcastEvent
               ▼                │
┌───────────────────────────────┴──────────────┐
│                  Web Worker                  │
│             (Dedicated Thread)               │
│                                              │
│   ┌──────────────────────────────────────┐   │
│   │             VaultHandler             │   │
│   └──────────────────┬───────────────────┘   │
│                      │                       │
│                      ▼                       │
│   ┌──────────────────────────────────────┐   │
│   │         WasmVaultSession             │   │
│   │       (WASM Linear Memory)           │   │
│   │  - VaultKey (32 bytes)               │   │
│   │  - InMemorySearchIndex               │   │
│   └──────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

---

## 3. Envelope Definitions

### 3.1 Request Envelope (`WorkerRequest`)

```typescript
export interface WorkerRequest<T extends WorkerRequestType> {
  id: string; // Unique correlation ID (e.g. "req-1-1725945600000")
  type: T;    // Message type
  payload: RequestPayloadMap[T];
}
```

### 3.2 Response Envelope (`WorkerResponse`)

Success response:
```typescript
export interface WorkerResponseSuccess<T extends WorkerRequestType> {
  id: string;
  ok: true;
  data: ResponseDataMap[T];
}
```

Failure response:
```typescript
export interface WorkerResponseError {
  id: string;
  ok: false;
  error: {
    code: WorkerErrorCode;
    message: string;
  };
}
```

### 3.3 Broadcast Events (`WorkerBroadcastEvent`)

Unsolicited events initiated by the worker:
```typescript
export interface WorkerBroadcastEvent {
  event: "VAULT_LOCKED";
}
```

---

## 4. Error Codes (`WorkerErrorCode`)

| Error Code | Meaning |
| :--- | :--- |
| `VAULT_LOCKED` | Operation requires unlocked vault, but session is locked or uninitialized. |
| `DECRYPTION_FAILED` | Passphrase incorrect, auth tag mismatch, or ciphertext tampered. |
| `ENCRYPTION_FAILED` | Note or attachment encryption failed. |
| `INVALID_RECOVERY_KEY` | Recovery phrase invalid format or checksum mismatch. |
| `INVALID_PAYLOAD` | Malformed JSON envelope, schema violation, or unsupported version. |
| `INTERNAL_ERROR` | Unexpected worker or runtime exception. |

---

## 5. Operations Catalog

### 5.1 `GET_STATUS`
Checks whether the vault is currently unlocked and holds an active key session.

- **Payload**: `void`
- **Response**:
  ```json
  {
    "isUnlocked": true
  }
  ```

---

### 5.2 `INIT_VAULT`
Generates a fresh 256-bit Vault Key and Recovery Key, wraps them under an Argon2id KEK, stores the active session in worker memory, and returns bootstrap metadata for server storage.

- **Payload**:
  ```typescript
  {
    passphrase: string;
    kdfParamsJson?: string; // Optional custom/test KDF parameters
  }
  ```
- **Response**:
  ```typescript
  {
    wrappedVaultKey: string;      // WrappedVaultKey JSON
    kdfParamsJson: string;        // KdfParams JSON
    wrappedRecoveryKey: string;   // Recovery-wrapped VaultKey JSON
    recoveryPhrase: string;       // Formatted 24-word recovery phrase
  }
  ```

---

### 5.3 `UNLOCK_VAULT`
Derives KEK from passphrase using Argon2id, unwraps the Vault Key, and initializes the active session in worker memory.

- **Payload**:
  ```typescript
  {
    passphrase: string;
    wrappedVaultKeyJson: string;
    kdfParamsJson: string;
  }
  ```
- **Response**: `{ "success": true }`
- **Failures**: `DECRYPTION_FAILED` on wrong passphrase or tampered envelope.

---

### 5.4 `UNLOCK_WITH_RECOVERY_KEY`
Parses recovery phrase, validates checksum, unwraps recovery-wrapped Vault Key, and initializes the active session.

- **Payload**:
  ```typescript
  {
    recoveryPhrase: string;
    wrappedRecoveryKeyJson: string;
  }
  ```
- **Response**: `{ "success": true }`
- **Failures**: `INVALID_RECOVERY_KEY` on checksum error; `DECRYPTION_FAILED` on key mismatch.

---

### 5.5 `LOCK_VAULT`
Explicitly locks the vault. Calls `WasmVaultSession::lock()`, scrubbing all key bytes and search indexes via `Zeroize`. Broadcasts `VAULT_LOCKED`.

- **Payload**: `void`
- **Response**: `{ "success": true }`

---

### 5.6 `REWRAP_PASSPHRASE`
Derives a new KEK from a new passphrase and re-wraps the active Vault Key without re-encrypting any stored notes.

- **Payload**:
  ```typescript
  {
    newPassphrase: string;
    kdfParamsJson?: string;
  }
  ```
- **Response**:
  ```typescript
  {
    newWrappedVaultKey: string;
    newKdfParamsJson: string;
  }
  ```
- **Failures**: `VAULT_LOCKED` if called while locked.

---

### 5.7 `ENCRYPT_NOTE`
Constructs canonical note JSON and encrypts it into an `EncryptedEnvelope` (XChaCha20-Poly1305) using the active session key.

- **Payload**:
  ```typescript
  {
    noteId: string;
    title: string;
    body: string;
    tags: string[];
  }
  ```
- **Response**:
  ```typescript
  {
    envelopeJson: string;
  }
  ```
- **Failures**: `VAULT_LOCKED` if locked.

---

### 5.8 `DECRYPT_NOTE`
Decrypts an `EncryptedEnvelope` using the active session key and validates domain constraints.

- **Payload**:
  ```typescript
  {
    envelopeJson: string;
  }
  ```
- **Response**:
  ```typescript
  {
    id: string;
    title: string;
    body: string;
    tags: string[];
    createdAt: string;
    updatedAt: string;
  }
  ```
- **Failures**: `VAULT_LOCKED` if locked; `DECRYPTION_FAILED` if tampered.

---

### 5.9 `DECRYPT_NOTES_BATCH`
Bulk decrypts multiple envelopes in a single worker turn. Partial decryption failures are captured in the `failed` array without terminating the batch.

- **Payload**:
  ```typescript
  {
    envelopes: Array<{ id: string; envelopeJson: string }>;
  }
  ```
- **Response**:
  ```typescript
  {
    notes: PlaintextNoteDto[];
    failed: Array<{ id: string; error: string }>;
  }
  ```

---

### 5.10 `INDEX_NOTE`
Inserts note title, tags, and body content into the worker's in-memory BM25-style search index.

- **Payload**:
  ```typescript
  {
    noteId: string;
    title: string;
    body: string;
    tags: string[];
    updatedAt: string;
  }
  ```
- **Response**: `{ "success": true }`

---

### 5.11 `REMOVE_FROM_INDEX`
Removes a note's terms from the search index (e.g. upon note deletion or tombstoning).

- **Payload**:
  ```typescript
  {
    noteId: string;
  }
  ```
- **Response**: `{ "success": true }`

---

### 5.12 `SEARCH`
Executes an in-memory full-text search across indexed note content, returning scored matches with context snippets.

- **Payload**:
  ```typescript
  {
    query: string;
  }
  ```
- **Response**:
  ```typescript
  Array<{
    noteId: string;
    score: number;
    matchedTitle: string;
    snippet: string;
  }>
  ```

---

## 6. Client Architecture & React Usage

React components interact with the worker solely via `VaultWorkerClient`:

```typescript
import { VaultWorkerClient } from "@zk-notes/web";

const worker = new Worker(new URL("./worker/worker.js", import.meta.url), { type: "module" });
const client = new VaultWorkerClient(worker);

// Hooking lock event to clear visible UI state:
client.onLock(() => {
  setPlaintextNotes([]);
  setIsUnlocked(false);
});

// Decrypting note for editor view:
const noteDto = await client.decryptNote(encryptedEnvelopeJson);
```
