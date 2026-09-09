# ADR-0003: Cryptographic Primitives, Key Hierarchy, and Dependency Shortlist

## Status

Accepted

## Context

The core value proposition of Zero-Knowledge Notes is end-to-end client-side confidentiality: the server persists only unreadable ciphertext and cannot decrypt user notes under any circumstances (**SEC-001**, **SEC-002**).

To uphold the absolute security rules defined in `AGENTS.md` and `MASTER_SPEC.md` §5:
1. All application content must use modern, authenticated encryption only (**SEC-004**).
2. Nonce reuse must be mathematically impossible under concurrent, offline multi-device operation (**SEC-005**).
3. Secret material must be protected in memory, redacted from diagnostics, and zeroized upon drop (**SEC-003**).
4. Operations must execute consistently across both native platforms (Linux, macOS, Windows) and WebAssembly (browser).
5. Cryptographic choices must rely on vetted, actively maintained, pure-Rust libraries rather than custom implementations or unmaintained C bindings (**AGENTS.md §4, §10**).

## Decision

### 1. Cryptographic Algorithms

We select the following suite:

| Purpose | Algorithm | Key Size | Nonce / Salt Size | Specification |
| :--- | :--- | :--- | :--- | :--- |
| **Password KDF** | Argon2id | 256 bits | 128-bit (16 bytes) salt | RFC 9106 |
| **Content AEAD** | XChaCha20-Poly1305 | 256 bits | 192-bit (24 bytes) nonce | draft-irtf-cfrg-xchacha |
| **Key Wrapping** | XChaCha20-Poly1305 | 256 bits | 192-bit (24 bytes) nonce | Authenticated Key Wrap |
| **RNG** | OS CSPRNG | N/A | N/A | OS system call / Web Crypto API |

#### Rationale: Argon2id
- Winner of the Password Hashing Competition; standard in RFC 9106.
- Provides superior defense against side-channel cache-timing attacks (Argon2i mode) and GPU/ASIC hardware brute-force attacks (Argon2d memory-hardness).
- Production default parameters:
  - Memory: 64 MiB (65,536 KiB)
  - Iterations (Time cost): 3
  - Parallelism: 1 (optimal for single-threaded WASM and cross-platform consistency)
- Parameter calibration is stored in the vault metadata so older vaults remain decryptable if parameters are bumped (**MASTER_SPEC.md §5.3**).
- Tests must use fast, isolated test parameters (e.g. 1 MiB, 1 iteration) strictly confined to test configurations.

#### Rationale: XChaCha20-Poly1305
- **Extended Nonce (192 bits)**: Standard ChaCha20-Poly1305 uses a 96-bit nonce, which risks nonce collision when generated randomly across decentralized offline devices. XChaCha20 extends the nonce to 192 bits using HChaCha20 subkey derivation. At 192 bits, random nonce selection from a CSPRNG has negligible collision probability ($< 2^{-32}$ after $2^{64}$ encryptions), eliminating the need for synchronized nonce counters across devices (**SEC-005**).
- **Constant-Time Execution**: ChaCha20 relies on simple ARX (Add-Rotate-Xor) operations that execute in constant time across all CPU architectures and WebAssembly runtimes without requiring dedicated hardware instructions (like AES-NI) or risking cache-timing side channels.
- **Poly1305 MAC**: Guarantees authenticity and integrity. Any tampering with ciphertext or Associated Authenticated Data (AAD) fails closed (**SEC-010**).

### 2. Key Hierarchy and Wrapping Architecture

```text
               Vault Passphrase
                      │
                      ▼
                   Argon2id (Salt + Params)
                      │
                      ▼
            Key Encryption Key (KEK)
                    (256-bit)
                      │
                      ├───────── AEAD Wrap / Unwrap ─────────┐
                      ▼                                      ▼
           Wrapped Vault Key Envelope              Vault Key (Plaintext in RAM)
           (Stored on Server & Disk)                         (256-bit)
                                                             │
                     ┌───────────────────────────────────────┤
                     ▼                                       ▼
             Object Key A (256-bit)                  Object Key B (256-bit)
                     │                                       │
                     ▼                                       ▼
            Encrypted Payload A                     Encrypted Payload B
```

1. **Vault Key**: A cryptographically random 256-bit master key generated on the client. It never leaves the client in plaintext.
2. **Key Encryption Key (KEK)**: Derived ephemerally from the vault passphrase + salt using Argon2id. Used solely to wrap/unwrap the Vault Key.
3. **Recovery Key**: A high-entropy 256-bit random key generated during vault setup that independently wraps the same Vault Key. Allows recovery if the passphrase is lost.
4. **Passphrase Rotation**: Changing the vault passphrase derives a new KEK and re-wraps the Vault Key. Crucially, **all object ciphertexts remain unchanged**, avoiding costly bulk re-encryption (**MASTER_SPEC.md §5.4**).
5. **Per-Object Keys**: Every object (note, notebook, settings) receives a fresh, random 256-bit Object Key. The Object Key is wrapped with the Vault Key using authenticated encryption.
6. **Associated Data (AAD)**: Key wrapping and payload encryption authenticate protocol metadata (envelope version, account ID, object ID, and object kind) in the AEAD AAD to prevent ciphertext splicing and transposition attacks.

### 3. Memory Protection and Secret Handling

- **Zeroization**: All sensitive keys (`VaultKey`, `KeyEncryptionKey`, `ObjectKey`, `RecoveryKey`) must wrap raw byte buffers with `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` to scrub memory when dropped.
- **Diagnostics Redaction**: `Debug` and `Display` implementations for keys, plaintext envelopes, and passphrases must print `[REDACTED]` or only display non-sensitive length/fingerprint markers (**SEC-003**).
- **Constant-Time Comparison**: Key comparisons or cryptographic token validations must use constant-time primitives (`subtle::ConstantTimeEq`).

### 4. Dependency Shortlist

We evaluate and shortlist the following production-grade Rust crates for Milestone M1 implementation:

| Crate | Purpose | Version Track | Justification |
| :--- | :--- | :--- | :--- |
| `chacha20poly1305` | XChaCha20-Poly1305 AEAD | `0.10` | RustCrypto tier-1 crate; pure Rust; audited; `Aead` trait; constant-time via `subtle`; native + WASM. |
| `argon2` | Argon2id KDF | `0.5` | RustCrypto implementation of RFC 9106; pure Rust; no C compiler required; works in native and WASM. |
| `zeroize` | Memory scrubbing | `1.8` | Industry standard in Rust for clearing sensitive stack/heap memory; derives `ZeroizeOnDrop`. |
| `subtle` | Constant-time ops | `2.6` | Standard constant-time comparison library; audited; prevents timing side-channels. |
| `getrandom` | OS entropy / CSPRNG | `0.2` or `0.3` | Backed by Linux `getrandom(2)`, macOS `getentropy`, Windows `BCryptGenRandom`, and browser `Crypto.getRandomValues()`. |
| `rand_core` | CSPRNG traits | `0.6` | Standard Rust RNG abstraction (`CryptoRng`, `RngCore`, `OsRng`). |

*Note: Per ZK-005 acceptance criteria, application cryptographic code is NOT implemented in this task. Crate dependencies will be introduced in Milestone M1 (ZK-010+).*

## Consequences

- Cryptographic design is locked to industry-standard algorithms (Argon2id + XChaCha20-Poly1305) with 256-bit symmetric security.
- Extended nonces (192-bit) prevent nonce reuse risks in distributed offline synchronization.
- Pure Rust dependency selection guarantees clean cross-compilation to both native targets and WebAssembly without C FFI toolchain hurdles.
- Passphrase changes are fast ($O(1)$) and do not require re-encrypting existing notes.
