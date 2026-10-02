/**
 * Authenticated Browser Synchronization Adapter (ZK-106).
 *
 * Requirements & Security Invariants:
 * - SEC-001 / SEC-002: Note plaintext, titles, tags, passphrases, Vault Keys, and Note Keys
 *   NEVER cross the network. All pushes and pulls exchange opaque EncryptedEnvelope payloads only.
 * - SEC-003: No secrets in logs. Bearer tokens, recovery phrases, and keys are never logged.
 * - SEC-006: CAS conflict safety. Pushes supply expected_revision; stale writes stop with
 *   actionable ConflictRecord without silent data loss.
 * - SEC-007: Idempotency safety. Every mutation has a stable mutation_id; replays do not create new revisions.
 * - SEC-008: Tombstone deletion safety. Deletions are revisioned tombstones; stale writes cannot resurrect them.
 * - SEC-009 / SEC-010: Persistent local storage remains encrypted; cryptographic failures fail closed.
 * - Account/Server isolation: Scoped strictly to (serverOrigin, accountId).
 */

import { normalizeServerOrigin } from "../auth/session.js";
import {
  readVaultLink,
  VaultLinkError,
  WrongAccountError,
  OriginMismatchError,
} from "../auth/vault-link.js";
import { IndexedDbStorage } from "../storage/indexeddb.js";
import {
  EncryptedEnvelopeDto,
  StoredEncryptedObject,
  MutationType,
  MutationStatus,
  PendingMutation,
  ConflictRecord,
} from "../storage/models.js";
import { VaultWorkerClient } from "../worker/client.js";
import * as zk from "zk-wasm";

// ============================================================================
// Protocol DTO Types
// ============================================================================

export interface PushRequestDto {
  mutation_id: string;
  object_id: string;
  expected_revision: number;
  object_kind: number;
  envelope: EncryptedEnvelopeDto;
  is_deleted: boolean;
}

export interface PushResponseDto {
  object_id: string;
  revision: number;
  server_seq: number;
}

export interface ConflictResponseDto {
  error: string;
  object_id: string;
  expected_revision: number;
  current_revision: number;
  current_server_seq: number;
  current_envelope: EncryptedEnvelopeDto;
  is_deleted?: boolean;
}

export interface ObjectChangeDto {
  server_seq: number;
  object_id: string;
  revision: number;
  object_kind: number;
  is_deleted: boolean;
  envelope: EncryptedEnvelopeDto;
}

export interface PullChangesResponseDto {
  changes: ObjectChangeDto[];
  next_cursor: number;
  has_more: boolean;
}

export interface PushReport {
  totalAttempted: number;
  accepted: PushResponseDto[];
  conflicts: ConflictRecord[];
}

export interface PullReport {
  pagesFetched: number;
  totalChanges: number;
  appliedChanges: number;
  initialCursor: number;
  finalCursor: number;
}

export interface SyncReport {
  initialPull: PullReport;
  push: PushReport;
  followupPull: PullReport | null;
  initialCursor: number;
  finalCursor: number;
}

// ============================================================================
// Typed Errors
// ============================================================================

export class SyncError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = "SyncError";
  }
}

export class UnauthorizedSyncError extends SyncError {
  constructor(message = "Authentication required to synchronize.") {
    super(message, "UNAUTHORIZED");
    this.name = "UnauthorizedSyncError";
  }
}

export class RevisionConflictError extends SyncError {
  constructor(public readonly conflict: ConflictResponseDto) {
    super(
      `Revision conflict on object '${conflict.object_id}': expected revision ${conflict.expected_revision}, server has revision ${conflict.current_revision}`,
      "REVISION_CONFLICT"
    );
    this.name = "RevisionConflictError";
  }
}

// ============================================================================
// Zero-Knowledge Validation Helper (SEC-001, SEC-002)
// ============================================================================

const FORBIDDEN_SECRET_KEYS = new Set([
  "title",
  "body",
  "tags",
  "plaintext",
  "passphrase",
  "password",
  "vaultpassphrase",
  "vaultkey",
  "masterkey",
  "secret",
  "notekey",
  "recoverykey",
  "recoveryphrase",
]);

export function validateNoPlaintextSecrets(value: unknown, path = ""): void {
  if (value === null || value === undefined) return;
  if (typeof value === "object") {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        validateNoPlaintextSecrets(value[i], `${path}[${i}]`);
      }
    } else {
      for (const [k, v] of Object.entries(value)) {
        const lower = k.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (FORBIDDEN_SECRET_KEYS.has(lower)) {
          throw new SyncError(
            `SEC-001/SEC-002 violation: forbidden key '${k}' at '${path}' must not be transmitted to the server.`,
            "FORBIDDEN_PLAINTEXT"
          );
        }
        validateNoPlaintextSecrets(v, `${path}.${k}`);
      }
    }
  }
}

// ============================================================================
// SyncServerAdapter Abstract Interface
// ============================================================================

export interface SyncServerAdapter {
  pushMutations?: (storage: IndexedDbStorage, linkStorage?: Pick<Storage, "getItem">) => Promise<PushReport | void>;
  pullChanges?: (storage: IndexedDbStorage, linkStorage?: Pick<Storage, "getItem">) => Promise<PullReport | void>;
  sync?: (storage: IndexedDbStorage, linkStorage?: Pick<Storage, "getItem">) => Promise<SyncReport>;
}

export interface BrowserSyncAdapterOptions {
  serverOrigin: string;
  token: string;
  accountId: string;
  fetchFn?: typeof fetch;
  linkStorage?: Pick<Storage, "getItem">;
  workerClient?: VaultWorkerClient;
}

// ============================================================================
// BrowserSyncAdapter Implementation
// ============================================================================

export class BrowserSyncAdapter implements SyncServerAdapter {
  public readonly serverOrigin: string;
  public readonly accountId: string;
  public readonly identity: string;
  public readonly workerClient?: VaultWorkerClient;
  private readonly token: string;
  private readonly fetchFn: typeof fetch;
  private readonly linkStorage?: Pick<Storage, "getItem">;

  constructor(options: BrowserSyncAdapterOptions) {
    if (!options.serverOrigin || !options.serverOrigin.trim()) {
      throw new SyncError("serverOrigin is required", "INVALID_CONFIG");
    }
    if (!options.token || !options.token.trim()) {
      throw new SyncError("token is required", "INVALID_CONFIG");
    }
    if (!options.accountId || !options.accountId.trim()) {
      throw new SyncError("accountId is required", "INVALID_CONFIG");
    }

    this.serverOrigin = normalizeServerOrigin(options.serverOrigin);
    this.accountId = options.accountId.trim();
    this.identity = `${this.serverOrigin}::${this.accountId}`;
    this.token = options.token.trim();
    this.fetchFn = options.fetchFn || (typeof globalThis !== "undefined" ? globalThis.fetch : (fetch as any));
    this.linkStorage = options.linkStorage;
    this.workerClient = options.workerClient;
  }

  /**
   * Asserts that the provided storage is linked to this adapter's exact (serverOrigin, accountId) identity.
   * Fails closed before any network activity if unlinked, corrupted, or mismatched (SEC-006 / ZK-105).
   */
  public assertLinkedStorage(
    _storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">
  ): void {
    const fallbackStore =
      linkStorage ||
      this.linkStorage ||
      (typeof window !== "undefined" && window.localStorage ? window.localStorage : (typeof localStorage !== "undefined" && typeof localStorage.getItem === "function" ? localStorage : null));
    if (!fallbackStore) {
      return;
    }

    const link = readVaultLink(fallbackStore);
    if (!link) {
      throw new VaultLinkError(
        "This vault is not linked to any server account. Link your vault before synchronizing.",
        "NOT_LINKED"
      );
    }
    if (link.accountId !== this.accountId) {
      throw new WrongAccountError(link.accountId, this.accountId);
    }
    if (normalizeServerOrigin(link.serverOrigin) !== this.serverOrigin) {
      throw new OriginMismatchError(link.serverOrigin, this.serverOrigin);
    }
  }

  /**
   * Pushes a single mutation to the server via POST /v1/sync/push.
   * Enforces client-side zero-knowledge validation and compare-and-swap conflict detection.
   */
  public async pushMutation(request: PushRequestDto): Promise<PushResponseDto> {
    validateNoPlaintextSecrets(request);

    let res: Response;
    try {
      res = await this.fetchFn(`${this.serverOrigin}/v1/sync/push`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.token}`,
        },
        body: JSON.stringify(request),
      });
    } catch (err: any) {
      throw new SyncError(`Network failure during push: ${err.message || err}`, "NETWORK_ERROR");
    }

    if (res.status === 200) {
      const data = await res.json();
      validateNoPlaintextSecrets(data);
      return data as PushResponseDto;
    }

    if (res.status === 409) {
      const errJson = (await res.json().catch(() => ({}))) as any;
      validateNoPlaintextSecrets(errJson);
      const codeStr = String(errJson.code || "").toUpperCase();
      const errStr = String(errJson.error || "").toUpperCase();
      if (codeStr === "ERROR_MUTATION_REPLAY_MISMATCH" || errStr === "ERROR_MUTATION_REPLAY_MISMATCH") {
        throw new SyncError(
          errJson.message || `Mutation replay mismatch for mutation_id '${request.mutation_id}'`,
          "ERROR_MUTATION_REPLAY_MISMATCH"
        );
      }
      if (
        (errStr === "ERROR_REVISION_CONFLICT" || errStr === "REVISION_CONFLICT") &&
        typeof errJson.current_revision === "number" &&
        errJson.current_envelope
      ) {
        throw new RevisionConflictError(errJson as ConflictResponseDto);
      }
      throw new SyncError(
        errJson.message || "Conflict response from server",
        errJson.code || errJson.error || "HTTP_409"
      );
    }

    if (res.status === 401 || res.status === 403) {
      throw new UnauthorizedSyncError("Authentication required to synchronize.");
    }

    const errJson = await res.json().catch(() => ({}));
    throw new SyncError(
      errJson.message || `Push failed with status HTTP ${res.status}`,
      errJson.code || `HTTP_${res.status}`
    );
  }

  /**
   * Raw network pull: Pulls incremental encrypted changes from the server via GET /v1/sync/changes?after=...
   */
  public async fetchPullChanges(
    after: number,
    limit = 50
  ): Promise<PullChangesResponseDto> {
    const clampedLimit = Math.max(1, Math.min(500, limit));
    let res: Response;
    try {
      res = await this.fetchFn(
        `${this.serverOrigin}/v1/sync/pull?after=${after}&limit=${clampedLimit}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${this.token}`,
          },
        }
      );
    } catch (err: any) {
      throw new SyncError(`Network failure during pull: ${err.message || err}`, "NETWORK_ERROR");
    }

    if (res.status === 200) {
      const data = await res.json();
      validateNoPlaintextSecrets(data);
      return data as PullChangesResponseDto;
    }

    if (res.status === 401 || res.status === 403) {
      throw new UnauthorizedSyncError("Authentication required to synchronize.");
    }

    const errJson = await res.json().catch(() => ({}));
    throw new SyncError(
      errJson.message || `Pull failed with status HTTP ${res.status}`,
      errJson.code || `HTTP_${res.status}`
    );
  }

  /**
   * Pulls changes: accepts either (after: number, limit?: number) for raw network pull,
   * or (storage: IndexedDbStorage, linkStorage?: Pick<Storage, "getItem">) for durable storage pull.
   */
  public async pullChanges(
    afterOrStorage: number | IndexedDbStorage,
    limitOrLinkStorage?: number | Pick<Storage, "getItem">
  ): Promise<any> {
    if (typeof afterOrStorage === "number") {
      return this.fetchPullChanges(
        afterOrStorage,
        typeof limitOrLinkStorage === "number" ? limitOrLinkStorage : 50
      );
    }
    return this.pullChangesToStorage(
      afterOrStorage,
      limitOrLinkStorage as Pick<Storage, "getItem">
    );
  }

  /**
   * Pushes all pending mutations from IndexedDB storage.
   * Honors server compare-and-swap responses and records actionable ConflictRecords on 409.
   */
  public async pushMutations(
    storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">
  ): Promise<PushReport> {
    this.assertLinkedStorage(storage, linkStorage);

    // Reset any in-flight mutations from interrupted runs (SEC-007 idempotency)
    await storage.resetInFlightMutations();

    const pendingMutations = await storage.listPendingMutations();
    const report: PushReport = {
      totalAttempted: 0,
      accepted: [],
      conflicts: [],
    };

    const conflictedObjects = new Set<string>();

    for (const mutation of pendingMutations) {
      if (
        mutation.status !== MutationStatus.Pending &&
        mutation.status !== MutationStatus.InFlight
      ) {
        continue;
      }

      // If an earlier mutation for this object encountered a conflict,
      // skip pushing subsequent edits for this object to prevent pushing stale dependent revisions (SEC-006).
      if (conflictedObjects.has(mutation.object_id)) {
        continue;
      }

      report.totalAttempted++;

      const pushReq: PushRequestDto = {
        mutation_id: mutation.mutation_id,
        object_id: mutation.object_id,
        expected_revision: mutation.expected_revision,
        object_kind: mutation.object_kind,
        envelope: mutation.envelope,
        is_deleted: mutation.mutation_type === MutationType.Delete,
      };

      // Mark in-flight locally (increments retry count)
      await storage.updateMutationStatus(
        mutation.mutation_id,
        MutationStatus.InFlight,
        mutation.retry_count + 1
      );

      try {
        const resp = await this.pushMutation(pushReq);

        // Accepted: durably update local object store with server sequence & revision
        const storedObject: StoredEncryptedObject = {
          object_id: resp.object_id,
          object_kind: mutation.object_kind,
          revision: resp.revision,
          server_seq: resp.server_seq,
          is_deleted: mutation.mutation_type === MutationType.Delete,
          envelope: mutation.envelope,
          updated_at: new Date().toISOString(),
        };

        await storage.putObject(storedObject);

        // ONLY after local object write succeeds, remove from mutation queue
        await storage.removeMutation(mutation.mutation_id);

        report.accepted.push(resp);
      } catch (err) {
        if (err instanceof RevisionConflictError) {
          // Stale edit or delete-vs-edit CAS conflict (SEC-006 / SEC-008):
          conflictedObjects.add(mutation.object_id);

          try {
            // 1. Fetch base version first
            const baseEnvelope = await storage.getBaseVersion(
              mutation.object_id,
              mutation.expected_revision
            );

            // 2. Generate conflict record using the shared Rust core (via Web Worker or WASM)
            let conflictRecord: ConflictRecord;
            if (this.workerClient) {
              try {
                const recordJson = await this.workerClient.recordConflict(
                  JSON.stringify(mutation),
                  JSON.stringify(err.conflict),
                  baseEnvelope ? JSON.stringify(baseEnvelope) : null
                );
                conflictRecord = JSON.parse(recordJson);
              } catch {
                conflictRecord = buildLocalConflictRecord(
                  mutation,
                  err.conflict,
                  baseEnvelope
                );
              }
            } else {
              conflictRecord = buildLocalConflictRecord(
                mutation,
                err.conflict,
                baseEnvelope
              );
            }

            // 3. Durably commit conflict record to storage FIRST
            await storage.putConflict(conflictRecord);

            // 4. In accordance with Rust zk-sync push_pending_changes:
            // Leave the local mutation recoverable in the queue (marked Pending)
            // instead of premature deletion, so the user can resolve or recover it.
            await storage.updateMutationStatus(
              mutation.mutation_id,
              MutationStatus.Pending,
              mutation.retry_count
            );

            report.conflicts.push(conflictRecord);
          } catch (storageErr) {
            // Fail closed: ensure mutation is not left in InFlight state if conflict recording fails
            await storage
              .updateMutationStatus(
                mutation.mutation_id,
                MutationStatus.Pending,
                mutation.retry_count
              )
              .catch(() => {});
            throw storageErr;
          }
        } else {
          // Reset back to Pending status so it can be retried on reconnect
          await storage.updateMutationStatus(
            mutation.mutation_id,
            MutationStatus.Pending,
            mutation.retry_count
          );
          throw err;
        }
      }
    }

    return report;
  }

  /**
   * Pulls remote changes in server sequence order, durably stores encrypted objects FIRST,
   * and advances the sync cursor ONLY after persistence succeeds.
   */
  public async pullChangesToStorage(
    storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">,
    limit = 50
  ): Promise<PullReport> {
    this.assertLinkedStorage(storage, linkStorage);

    const syncState = await storage.getSyncState(this.identity);
    const initialCursor = syncState ? syncState.sync_cursor : 0;
    let currentCursor = initialCursor;
    let pagesFetched = 0;
    let totalChanges = 0;
    let appliedChanges = 0;

    let hasMore = true;
    while (hasMore) {
      const resp = await this.pullChanges(currentCursor, limit);
      pagesFetched++;

      if (!resp.changes || resp.changes.length === 0) {
        break;
      }

      totalChanges += resp.changes.length;

      for (const change of resp.changes) {
        if (change.server_seq <= currentCursor && currentCursor > 0) {
          // Skip already processed sequences
          continue;
        }

        // STEP 1: Durably store encrypted change into local object store
        const storedObject: StoredEncryptedObject = {
          object_id: change.object_id,
          object_kind: change.object_kind,
          revision: change.revision,
          server_seq: change.server_seq,
          is_deleted: change.is_deleted,
          envelope: change.envelope,
          updated_at: new Date().toISOString(),
        };

        await storage.putObject(storedObject);

        // STEP 2: Advance cursor ONLY AFTER persistence succeeds
        currentCursor = change.server_seq;
        await storage.setSyncCursor(currentCursor, this.identity);
        appliedChanges++;
      }

      hasMore = resp.has_more;
    }

    return {
      pagesFetched,
      totalChanges,
      appliedChanges,
      initialCursor,
      finalCursor: currentCursor,
    };
  }

  /**
   * Executes a complete pull-before-push sync cycle (MASTER_SPEC.md § 9.6).
   * Advances last_sync_at ONLY after all phases complete successfully.
   */
  public async sync(
    storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">
  ): Promise<SyncReport> {
    this.assertLinkedStorage(storage, linkStorage);

    const syncState = await storage.getSyncState(this.identity);
    const initialCursor = syncState ? syncState.sync_cursor : 0;

    // 1. Initial Pull: fetch any new remote changes
    const initialPull = await this.pullChangesToStorage(storage, linkStorage);

    // 2. Push: transmit pending local mutations with CAS verification
    const push = await this.pushMutations(storage, linkStorage);

    // 3. Follow-up Pull: if mutations were accepted, fetch updated sequence numbers
    let followupPull: PullReport | null = null;
    if (push.accepted.length > 0) {
      followupPull = await this.pullChangesToStorage(storage, linkStorage);
    }

    const finalState = await storage.getSyncState(this.identity);
    const finalCursor = finalState ? finalState.sync_cursor : initialCursor;

    // 4. Update last_sync_at only on complete, error-free sync round
    const now = new Date();
    await storage.setSyncState(
      {
        sync_cursor: finalCursor,
        last_sync_at: now.toISOString(),
        device_id: finalState ? finalState.device_id : null,
      },
      this.identity
    );

    return {
      initialPull,
      push,
      followupPull,
      initialCursor,
      finalCursor,
    };
  }

  // Alias for compatibility with SyncServerAdapter interface
  public async pullChangesAdapter(
    storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">
  ): Promise<PullReport> {
    return this.pullChangesToStorage(storage, linkStorage);
  }
}

/**
 * Builds a ConflictRecord using the shared Rust core wasm export if available,
 * or constructs the exact ConflictRecord conforming to zk-storage models (ZK-053).
 */
export function buildLocalConflictRecord(
  mutation: PendingMutation,
  conflict: ConflictResponseDto,
  baseEnvelope?: EncryptedEnvelopeDto | null
): ConflictRecord {
  try {
    if (typeof (zk as any).build_conflict_record === "function") {
      const json = (zk as any).build_conflict_record(
        JSON.stringify(mutation),
        JSON.stringify(conflict),
        baseEnvelope ? JSON.stringify(baseEnvelope) : null
      );
      return JSON.parse(json);
    }
  } catch {
    // If wasm is uninitialized on main thread, fallback to direct typed structure
  }

  const conflictId =
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : `conf-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

  return {
    conflict_id: conflictId,
    object_id: mutation.object_id,
    object_kind: mutation.object_kind,
    base_revision: mutation.expected_revision,
    remote_revision: conflict.current_revision,
    base_envelope: baseEnvelope || null,
    local_envelope: mutation.envelope,
    remote_envelope: conflict.current_envelope,
    candidate_envelope: null,
    resolved: false,
    remote_is_deleted: Boolean(conflict.is_deleted),
    local_is_deleted: mutation.mutation_type === MutationType.Delete,
    created_at: new Date().toISOString(),
    resolved_at: null,
  };
}
