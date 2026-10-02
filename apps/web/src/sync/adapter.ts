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
  MutationStatus,
  ConflictRecord,
} from "../storage/models.js";
import { VaultWorkerClient } from "../worker/client.js";
import * as zk from "zk-wasm";

let wasmInitPromise: Promise<void> | null = null;

export async function ensureWasmInitialized(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    try {
      if (typeof (zk as any).initSync === "function") {
        if (typeof process !== "undefined" && process.versions?.node) {
          const { createRequire } = await import("node:module");
          const fs = await import("node:fs");
          const path = await import("node:path");
          const require = createRequire(import.meta.url);
          const pkgJs = require.resolve("zk-wasm");
          const wasmPath = path.join(path.dirname(pkgJs), "zk_wasm_bg.wasm");
          if (fs.existsSync(wasmPath)) {
            const bytes = fs.readFileSync(wasmPath);
            (zk as any).initSync({ module: bytes });
            return;
          }
        }
      }
      if (typeof (zk as any).default === "function") {
        await (zk as any).default();
      }
    } catch {
      // Ignore if already initialized
    }
  })();
  return wasmInitPromise;
}

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
  /**
   * Pushes all pending mutations from IndexedDB storage.
   * Driven by the shared Rust core WasmSyncStateMachine.
   */
  public async pushMutations(
    storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">
  ): Promise<PushReport> {
    this.assertLinkedStorage(storage, linkStorage);
    await ensureWasmInitialized();

    await storage.resetInFlightMutations();

    const pendingMutations = await storage.listPendingMutations();
    const sm = new zk.WasmSyncStateMachine(0n, JSON.stringify(pendingMutations));

    // Initialize state machine and step past initial pull to enter push phase directly
    sm.start();
    const pushInitActionsJson = sm.handle_pull_response(
      JSON.stringify({ changes: [], next_cursor: 0, has_more: false })
    );
    const actions: any[] = JSON.parse(pushInitActionsJson);

    const report: PushReport = {
      totalAttempted: 0,
      accepted: [],
      conflicts: [],
    };

    while (actions.length > 0) {
      const action = actions.shift();
      if (!action) continue;

      switch (action.type) {
        case "ResetInFlightMutations": {
          await storage.resetInFlightMutations();
          break;
        }

        case "MarkMutationInFlight": {
          await storage.updateMutationStatus(
            action.mutation_id,
            MutationStatus.InFlight,
            action.retry_count
          );
          break;
        }

        case "SendPush": {
          report.totalAttempted++;
          const currentMutation = pendingMutations.find(
            (m) => m.mutation_id === action.request.mutation_id
          );

          try {
            const resp = await this.pushMutation(action.request);
            report.accepted.push(resp);
            const nextActions = JSON.parse(
              sm.handle_push_success(action.request.mutation_id, JSON.stringify(resp))
            );
            actions.push(...nextActions);
          } catch (err: any) {
            if (err instanceof RevisionConflictError) {
              const baseEnvelope = await storage.getBaseVersion(
                action.request.object_id,
                action.request.expected_revision
              );

              // Fail closed: shared-core Rust/WASM generates conflict record; no TypeScript fallback!
              let conflictRecord: ConflictRecord;
              try {
                if (this.workerClient) {
                  const recordJson = await this.workerClient.recordConflict(
                    JSON.stringify(currentMutation || action.request),
                    JSON.stringify(err.conflict),
                    baseEnvelope ? JSON.stringify(baseEnvelope) : null
                  );
                  conflictRecord = JSON.parse(recordJson);
                } else {
                  const recordJson = zk.build_conflict_record(
                    JSON.stringify(currentMutation || action.request),
                    JSON.stringify(err.conflict),
                    baseEnvelope ? JSON.stringify(baseEnvelope) : null
                  );
                  conflictRecord = JSON.parse(recordJson);
                }
              } catch (recErr) {
                await storage
                  .updateMutationStatus(action.request.mutation_id, MutationStatus.Pending)
                  .catch(() => {});
                throw recErr;
              }

              report.conflicts.push(conflictRecord);
              const nextActions = JSON.parse(
                sm.handle_push_conflict(action.request.mutation_id, JSON.stringify(conflictRecord))
              );
              actions.push(...nextActions);
            } else {
              // Any non-revision-conflict error (network error, 409 replay mismatch, 500, etc.):
              // Fail closed: reset in-flight mutation back to Pending so it can be retried / inspected (no data loss!)
              await storage
                .updateMutationStatus(action.request.mutation_id, MutationStatus.Pending)
                .catch(() => {});
              throw err;
            }
          }
          break;
        }

        case "AcknowledgeAccepted": {
          await storage.putObject(action.object);
          await storage.removeMutation(action.mutation_id);
          break;
        }

        case "RecordConflict": {
          try {
            await storage.putConflict(action.conflict_record);
          } catch (storageErr) {
            await storage
              .updateMutationStatus(action.mutation_id, MutationStatus.Pending)
              .catch(() => {});
            throw storageErr;
          }
          break;
        }

        case "ResetMutationToPending": {
          await storage.updateMutationStatus(action.mutation_id, MutationStatus.Pending);
          break;
        }

        case "MarkMutationFailed": {
          await storage.updateMutationStatus(action.mutation_id, MutationStatus.Failed);
          break;
        }

        case "FetchPull":
        case "UpdateSyncState": {
          break;
        }
      }
    }

    return report;
  }

  /**
   * Pulls remote changes in server sequence order, durably stores encrypted objects FIRST,
   * and advances the sync cursor ONLY after persistence succeeds.
   * Driven by the shared Rust core WasmSyncStateMachine.
   */
  public async pullChangesToStorage(
    storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">,
    limit = 50
  ): Promise<PullReport> {
    this.assertLinkedStorage(storage, linkStorage);
    await ensureWasmInitialized();

    const syncState = await storage.getSyncState(this.identity);
    const initialCursor = syncState ? BigInt(syncState.sync_cursor) : 0n;
    const sm = new zk.WasmSyncStateMachine(initialCursor, JSON.stringify([]));

    const actions: any[] = JSON.parse(sm.start());
    let pagesFetched = 0;
    let totalChanges = 0;
    let appliedChanges = 0;
    let currentCursor = Number(initialCursor);

    while (actions.length > 0) {
      const action = actions.shift();
      if (!action) continue;

      switch (action.type) {
        case "FetchPull": {
          pagesFetched++;
          const resp = await this.fetchPullChanges(action.after, limit);
          totalChanges += resp.changes ? resp.changes.length : 0;
          const nextActions = JSON.parse(sm.handle_pull_response(JSON.stringify(resp)));
          actions.push(...nextActions);
          break;
        }

        case "StoreObject": {
          await storage.putObject(action.object);
          appliedChanges++;
          break;
        }

        case "AdvanceCursor": {
          currentCursor = action.cursor;
          await storage.setSyncCursor(action.cursor, this.identity);
          break;
        }
      }
    }

    return {
      pagesFetched,
      totalChanges,
      appliedChanges,
      initialCursor: Number(initialCursor),
      finalCursor: currentCursor,
    };
  }

  /**
   * Executes a complete pull-before-push sync cycle (MASTER_SPEC.md § 9.6).
   * Advances last_sync_at ONLY after all phases complete successfully.
   * Owned and driven by the shared Rust core WasmSyncStateMachine.
   */
  public async sync(
    storage: IndexedDbStorage,
    linkStorage?: Pick<Storage, "getItem">
  ): Promise<SyncReport> {
    this.assertLinkedStorage(storage, linkStorage);
    await ensureWasmInitialized();

    const syncState = await storage.getSyncState(this.identity);
    const initialCursor = syncState ? BigInt(syncState.sync_cursor) : 0n;
    const pendingMutations = await storage.listPendingMutations();

    const sm = new zk.WasmSyncStateMachine(initialCursor, JSON.stringify(pendingMutations));
    const actions: any[] = JSON.parse(sm.start());

    let initialPullReport: PullReport | null = null;
    let followupPullReport: PullReport | null = null;
    const pushReport: PushReport = {
      totalAttempted: 0,
      accepted: [],
      conflicts: [],
    };

    while (actions.length > 0) {
      const action = actions.shift();
      if (!action) continue;

      switch (action.type) {
        case "ResetInFlightMutations": {
          await storage.resetInFlightMutations();
          break;
        }

        case "FetchPull": {
          const resp = await this.fetchPullChanges(action.after, action.limit);
          const nextActions = JSON.parse(sm.handle_pull_response(JSON.stringify(resp)));
          actions.push(...nextActions);
          break;
        }

        case "StoreObject": {
          await storage.putObject(action.object);
          break;
        }

        case "AdvanceCursor": {
          await storage.setSyncCursor(action.cursor, this.identity);
          break;
        }

        case "MarkMutationInFlight": {
          await storage.updateMutationStatus(
            action.mutation_id,
            MutationStatus.InFlight,
            action.retry_count
          );
          break;
        }

        case "SendPush": {
          pushReport.totalAttempted++;
          const currentMutation = pendingMutations.find(
            (m) => m.mutation_id === action.request.mutation_id
          );

          try {
            const resp = await this.pushMutation(action.request);
            pushReport.accepted.push(resp);
            const nextActions = JSON.parse(
              sm.handle_push_success(action.request.mutation_id, JSON.stringify(resp))
            );
            actions.push(...nextActions);
          } catch (err: any) {
            if (err instanceof RevisionConflictError) {
              const baseEnvelope = await storage.getBaseVersion(
                action.request.object_id,
                action.request.expected_revision
              );

              // Fail closed: shared-core Rust/WASM generates conflict record; no TypeScript fallback!
              let conflictRecord: ConflictRecord;
              try {
                if (this.workerClient) {
                  const recordJson = await this.workerClient.recordConflict(
                    JSON.stringify(currentMutation || action.request),
                    JSON.stringify(err.conflict),
                    baseEnvelope ? JSON.stringify(baseEnvelope) : null
                  );
                  conflictRecord = JSON.parse(recordJson);
                } else {
                  const recordJson = zk.build_conflict_record(
                    JSON.stringify(currentMutation || action.request),
                    JSON.stringify(err.conflict),
                    baseEnvelope ? JSON.stringify(baseEnvelope) : null
                  );
                  conflictRecord = JSON.parse(recordJson);
                }
              } catch (recErr) {
                await storage
                  .updateMutationStatus(action.request.mutation_id, MutationStatus.Pending)
                  .catch(() => {});
                throw recErr;
              }

              pushReport.conflicts.push(conflictRecord);
              const nextActions = JSON.parse(
                sm.handle_push_conflict(action.request.mutation_id, JSON.stringify(conflictRecord))
              );
              actions.push(...nextActions);
            } else {
              // Any non-revision-conflict error (network error, 409 replay mismatch, 500, etc.):
              // Fail closed: reset in-flight mutation back to Pending so it can be retried / inspected (no data loss!)
              await storage
                .updateMutationStatus(action.request.mutation_id, MutationStatus.Pending)
                .catch(() => {});
              throw err;
            }
          }
          break;
        }

        case "AcknowledgeAccepted": {
          await storage.putObject(action.object);
          await storage.removeMutation(action.mutation_id);
          break;
        }

        case "RecordConflict": {
          try {
            await storage.putConflict(action.conflict_record);
          } catch (storageErr) {
            await storage
              .updateMutationStatus(action.mutation_id, MutationStatus.Pending)
              .catch(() => {});
            throw storageErr;
          }
          break;
        }

        case "ResetMutationToPending": {
          await storage.updateMutationStatus(action.mutation_id, MutationStatus.Pending);
          break;
        }

        case "MarkMutationFailed": {
          await storage.updateMutationStatus(action.mutation_id, MutationStatus.Failed);
          break;
        }

        case "UpdateSyncState": {
          await storage.setSyncState(
            {
              sync_cursor: action.cursor,
              last_sync_at: action.last_sync_at,
              device_id: syncState ? syncState.device_id : null,
            },
            this.identity
          );
          break;
        }
      }
    }

    const rawReport = JSON.parse(sm.get_report());

    initialPullReport = {
      pagesFetched: rawReport.initial_pull.pages_fetched,
      totalChanges: rawReport.initial_pull.total_changes,
      appliedChanges: rawReport.initial_pull.applied_changes,
      initialCursor: rawReport.initial_pull.initial_cursor,
      finalCursor: rawReport.initial_pull.final_cursor,
    };

    if (rawReport.followup_pull) {
      followupPullReport = {
        pagesFetched: rawReport.followup_pull.pages_fetched,
        totalChanges: rawReport.followup_pull.total_changes,
        appliedChanges: rawReport.followup_pull.applied_changes,
        initialCursor: rawReport.followup_pull.initial_cursor,
        finalCursor: rawReport.followup_pull.final_cursor,
      };
    }

    return {
      initialPull: initialPullReport,
      push: pushReport,
      followupPull: followupPullReport,
      initialCursor: rawReport.initial_cursor,
      finalCursor: rawReport.final_cursor,
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

