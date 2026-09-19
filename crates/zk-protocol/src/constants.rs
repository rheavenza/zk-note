//! Protocol V1 constants for zero-knowledge synchronization,
//! envelope formatting, revisions, sequences, and error codes.

/// Active wire protocol version.
pub const PROTOCOL_VERSION_V1: u32 = 1;

/// Active encrypted envelope format version.
pub const ENVELOPE_VERSION_V1: u32 = 1;

/// Active encrypted attachment chunk format version.
pub const ATTACHMENT_CHUNK_VERSION_V1: u32 = 1;

/// Target chunk size for large attachments: 4 MiB (4,194,304 bytes).
pub const DEFAULT_ATTACHMENT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum allowed single attachment size: 100 MiB (104,857,600 bytes).
pub const MAX_ATTACHMENT_SIZE: u64 = 100 * 1024 * 1024;

/// Initial expected revision value for creating a new object.
pub const INITIAL_EXPECTED_REVISION: u64 = 0;

/// Revision assigned to a newly created object upon first commit.
pub const INITIAL_OBJECT_REVISION: u64 = 1;

/// Initial server sequence value before any accepted mutations.
pub const INITIAL_SERVER_SEQ: u64 = 0;

/// Initial sync cursor for a client that has not yet synchronized.
pub const INITIAL_SYNC_CURSOR: u64 = 0;

// Object kind numeric discriminants (protocol constants).
/// Object kind: Note.
pub const OBJECT_KIND_NOTE: u16 = 1;
/// Object kind: Notebook.
pub const OBJECT_KIND_NOTEBOOK: u16 = 2;
/// Object kind: User Settings.
pub const OBJECT_KIND_USER_SETTINGS: u16 = 3;
/// Object kind: Attachment Manifest.
pub const OBJECT_KIND_ATTACHMENT_MANIFEST: u16 = 4;
/// Object kind: Reserved for future extensions.
pub const OBJECT_KIND_RESERVED: u16 = 5;

// Canonical error codes defined in MASTER_SPEC.md §20.
/// Authentication is required to access the requested resource.
pub const ERROR_AUTH_REQUIRED: &str = "AUTH_REQUIRED";
/// Caller is not authorized to access this resource or account.
pub const ERROR_AUTH_FORBIDDEN: &str = "AUTH_FORBIDDEN";
/// Provided authentication token has expired.
pub const ERROR_AUTH_EXPIRED: &str = "AUTH_EXPIRED";
/// Provided authentication token or session has been revoked.
pub const ERROR_AUTH_REVOKED: &str = "AUTH_REVOKED";
/// Originating device has been revoked and cannot authenticate.
pub const ERROR_DEVICE_REVOKED: &str = "DEVICE_REVOKED";
/// Local operation rejected because the vault is locked.
pub const ERROR_VAULT_LOCKED: &str = "VAULT_LOCKED";
/// Cryptographic envelope or parameter version is unsupported.
pub const ERROR_CRYPTO_UNSUPPORTED_VERSION: &str = "CRYPTO_UNSUPPORTED_VERSION";
/// Decryption or authentication tag verification failed.
pub const ERROR_CRYPTO_AUTH_FAILED: &str = "CRYPTO_AUTH_FAILED";
/// Encrypted envelope structure is malformed or corrupted.
pub const ERROR_INVALID_ENVELOPE: &str = "INVALID_ENVELOPE";
/// Compare-and-swap failed due to revision mismatch.
pub const ERROR_REVISION_CONFLICT: &str = "REVISION_CONFLICT";
/// Mutation ID was previously processed with different parameters.
pub const ERROR_MUTATION_REPLAY_MISMATCH: &str = "MUTATION_REPLAY_MISMATCH";
/// Requested object does not exist.
pub const ERROR_OBJECT_NOT_FOUND: &str = "OBJECT_NOT_FOUND";
/// Requested object has been deleted (tombstone).
pub const ERROR_OBJECT_DELETED: &str = "OBJECT_DELETED";
/// Provided sync cursor is invalid or out of range.
pub const ERROR_SYNC_CURSOR_INVALID: &str = "SYNC_CURSOR_INVALID";
/// Request rate limit or quota exceeded.
pub const ERROR_RATE_LIMITED: &str = "RATE_LIMITED";
/// Network is unavailable or unreachable.
pub const ERROR_NETWORK_UNAVAILABLE: &str = "NETWORK_UNAVAILABLE";
/// Local database or persistent cache operation failed.
pub const ERROR_LOCAL_STORAGE_FAILURE: &str = "LOCAL_STORAGE_FAILURE";
/// Internal server error.
pub const ERROR_SERVER_FAILURE: &str = "SERVER_FAILURE";
/// WebAuthn challenge has expired.
pub const ERROR_WEBAUTHN_CHALLENGE_EXPIRED: &str = "WEBAUTHN_CHALLENGE_EXPIRED";
/// WebAuthn challenge was not found or has already been used.
pub const ERROR_WEBAUTHN_CHALLENGE_NOT_FOUND: &str = "WEBAUTHN_CHALLENGE_NOT_FOUND";
/// WebAuthn signature or attestation verification failed.
pub const ERROR_WEBAUTHN_VERIFICATION_FAILED: &str = "WEBAUTHN_VERIFICATION_FAILED";
/// WebAuthn credential was not found for the requested identity.
pub const ERROR_WEBAUTHN_CREDENTIAL_NOT_FOUND: &str = "WEBAUTHN_CREDENTIAL_NOT_FOUND";
/// WebAuthn credential ID already registered.
pub const ERROR_WEBAUTHN_CREDENTIAL_EXISTS: &str = "WEBAUTHN_CREDENTIAL_EXISTS";
/// Account aggregate storage quota exceeded (ZK-082).
pub const ERROR_QUOTA_EXCEEDED: &str = "QUOTA_EXCEEDED";
/// Payload exceeds maximum single object/blob limit (ZK-082).
pub const ERROR_PAYLOAD_TOO_LARGE: &str = "PAYLOAD_TOO_LARGE";
/// Requested ciphertext blob was not found (ZK-082).
pub const ERROR_BLOB_NOT_FOUND: &str = "BLOB_NOT_FOUND";
