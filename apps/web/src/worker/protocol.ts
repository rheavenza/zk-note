/**
 * Web Worker Message Protocol Definitions (ZK-062).
 *
 * Defines the typed RPC message protocol between the UI/React layer and
 * the dedicated cryptographic Web Worker.
 *
 * In accordance with MASTER_SPEC.md § 18, SEC-001, SEC-002, and SEC-009:
 * - The raw Vault Key NEVER crosses this boundary.
 * - Heavy crypto (Argon2id KDF, bulk note decryption, search indexing/querying)
 *   is isolated in the Web Worker.
 * - React components only receive decrypted PlaintextNoteDto objects when requested
 *   and do not own persistent key material.
 */

export enum WorkerErrorCode {
  VAULT_LOCKED = "VAULT_LOCKED",
  VAULT_ALREADY_UNLOCKED = "VAULT_ALREADY_UNLOCKED",
  DECRYPTION_FAILED = "DECRYPTION_FAILED",
  ENCRYPTION_FAILED = "ENCRYPTION_FAILED",
  INVALID_PAYLOAD = "INVALID_PAYLOAD",
  INVALID_RECOVERY_KEY = "INVALID_RECOVERY_KEY",
  INTERNAL_ERROR = "INTERNAL_ERROR",
}

export interface PlaintextNoteDto {
  id: string;
  title: string;
  body: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

export interface SearchResultDto {
  noteId: string;
  score: number;
  matchedTitle: string;
  snippet: string;
}

export interface VaultInitResultDto {
  wrappedVaultKey: string;
  kdfParamsJson: string;
  wrappedRecoveryKey: string;
  recoveryPhrase: string;
}

export interface VaultRewrapResultDto {
  newWrappedVaultKey: string;
  newKdfParamsJson: string;
}

export interface VaultStatusDto {
  isUnlocked: boolean;
}

export interface DecryptBatchItem {
  id: string;
  envelopeJson: string;
}

export interface DecryptBatchResultDto {
  notes: PlaintextNoteDto[];
  failed: Array<{ id: string; error: string }>;
}

// ----------------------------------------------------------------------------
// Request Types & Payloads
// ----------------------------------------------------------------------------

export interface InitVaultPayload {
  passphrase: string;
  kdfParamsJson?: string;
}

export interface UnlockVaultPayload {
  passphrase: string;
  wrappedVaultKeyJson: string;
  kdfParamsJson: string;
}

export interface UnlockWithRecoveryKeyPayload {
  recoveryPhrase: string;
  wrappedRecoveryKeyJson: string;
}

export interface RewrapPassphrasePayload {
  newPassphrase: string;
  kdfParamsJson?: string;
}

export interface EncryptNotePayload {
  noteId: string;
  title: string;
  body: string;
  tags: string[];
}

export interface DecryptNotePayload {
  envelopeJson: string;
}

export interface DecryptNotesBatchPayload {
  envelopes: DecryptBatchItem[];
}

export interface IndexNotePayload {
  noteId: string;
  title: string;
  body: string;
  tags: string[];
  updatedAt: string;
}

export interface RemoveFromIndexPayload {
  noteId: string;
}

export interface SearchPayload {
  query: string;
}

export interface RequestPayloadMap {
  INIT_VAULT: InitVaultPayload;
  UNLOCK_VAULT: UnlockVaultPayload;
  UNLOCK_WITH_RECOVERY_KEY: UnlockWithRecoveryKeyPayload;
  LOCK_VAULT: void;
  GET_STATUS: void;
  REWRAP_PASSPHRASE: RewrapPassphrasePayload;
  ENCRYPT_NOTE: EncryptNotePayload;
  DECRYPT_NOTE: DecryptNotePayload;
  DECRYPT_NOTES_BATCH: DecryptNotesBatchPayload;
  INDEX_NOTE: IndexNotePayload;
  REMOVE_FROM_INDEX: RemoveFromIndexPayload;
  SEARCH: SearchPayload;
}

export interface ResponseDataMap {
  INIT_VAULT: VaultInitResultDto;
  UNLOCK_VAULT: { success: true };
  UNLOCK_WITH_RECOVERY_KEY: { success: true };
  LOCK_VAULT: { success: true };
  GET_STATUS: VaultStatusDto;
  REWRAP_PASSPHRASE: VaultRewrapResultDto;
  ENCRYPT_NOTE: { envelopeJson: string };
  DECRYPT_NOTE: PlaintextNoteDto;
  DECRYPT_NOTES_BATCH: DecryptBatchResultDto;
  INDEX_NOTE: { success: true };
  REMOVE_FROM_INDEX: { success: true };
  SEARCH: SearchResultDto[];
}

export type WorkerRequestType = keyof RequestPayloadMap;

export type WorkerRequest = {
  [K in WorkerRequestType]: {
    id: string;
    type: K;
    payload: RequestPayloadMap[K];
  };
}[WorkerRequestType];

export type WorkerTypedRequest<T extends WorkerRequestType> = {
  id: string;
  type: T;
  payload: RequestPayloadMap[T];
};

export interface WorkerResponseSuccess<T extends WorkerRequestType = WorkerRequestType> {
  id: string;
  ok: true;
  data: ResponseDataMap[T];
}

export interface WorkerResponseError {
  id: string;
  ok: false;
  error: {
    code: WorkerErrorCode;
    message: string;
  };
}

export type WorkerResponse<T extends WorkerRequestType = WorkerRequestType> =
  | WorkerResponseSuccess<T>
  | WorkerResponseError;

export interface WorkerBroadcastEvent {
  event: "VAULT_LOCKED";
}

export type WorkerOutgoingMessage = WorkerResponse | WorkerBroadcastEvent;

export function isWorkerBroadcastEvent(msg: unknown): msg is WorkerBroadcastEvent {
  return typeof msg === "object" && msg !== null && "event" in msg;
}
