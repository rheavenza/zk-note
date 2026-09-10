/**
 * Storage Models and Types for Web IndexedDB Adapter (ZK-063).
 *
 * Provides exact structural and semantic parity with the Rust `zk-storage` crate.
 */

export interface EncryptedEnvelopeDto {
  envelope_version: number;
  object_id: string;
  object_kind: number;
  wrapped_key: {
    nonce: string;
    ciphertext: string;
  };
  payload: {
    nonce: string;
    ciphertext: string;
  };
}

export interface StoredEncryptedObject {
  object_id: string;
  object_kind: number;
  revision: number;
  server_seq: number;
  is_deleted: boolean;
  envelope: EncryptedEnvelopeDto;
  updated_at: string;
}

export interface ObjectFilter {
  kind?: number;
  include_deleted?: boolean;
}

export enum MutationType {
  Upsert = "Upsert",
  Delete = "Delete",
}

export enum MutationStatus {
  Pending = "Pending",
  InFlight = "InFlight",
  Failed = "Failed",
}

export interface PendingMutation {
  mutation_id: string;
  object_id: string;
  expected_revision: number;
  object_kind: number;
  mutation_type: MutationType;
  envelope: EncryptedEnvelopeDto;
  created_at: string;
  retry_count: number;
  status: MutationStatus;
}

export interface BaseVersion {
  object_id: string;
  revision: number;
  envelope: EncryptedEnvelopeDto;
}

export interface SyncState {
  sync_cursor: number;
  last_sync_at: string | null;
  device_id: string | null;
}

export interface ConflictRecord {
  conflict_id: string;
  object_id: string;
  object_kind: number;
  base_revision: number;
  remote_revision: number;
  base_envelope: EncryptedEnvelopeDto | null;
  local_envelope: EncryptedEnvelopeDto;
  remote_envelope: EncryptedEnvelopeDto;
  candidate_envelope: EncryptedEnvelopeDto | null;
  resolved: boolean;
  remote_is_deleted?: boolean;
  local_is_deleted?: boolean;
  created_at: string;
  resolved_at: string | null;
}
