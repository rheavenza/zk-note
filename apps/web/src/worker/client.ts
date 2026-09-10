/**
 * Typed Web Worker Client (ZK-062).
 *
 * Provides a strongly typed Promise-based interface for React components and
 * application state services to communicate with the cryptographic Web Worker.
 *
 * In accordance with MASTER_SPEC.md § 18:
 * - React components NEVER hold or receive the VaultKey or WasmVaultSession.
 * - All cryptographic operations (KDF derivation, envelope encryption/decryption,
 *   search index maintenance and search querying) are offloaded to the worker thread.
 */

import {
  WorkerTypedRequest,
  WorkerResponse,
  WorkerRequestType,
  WorkerErrorCode,
  isWorkerBroadcastEvent,
  PlaintextNoteDto,
  SearchResultDto,
  VaultInitResultDto,
  VaultRewrapResultDto,
  VaultStatusDto,
  DecryptBatchItem,
  DecryptBatchResultDto,
} from "./protocol.js";

export class WorkerError extends Error {
  public readonly code: WorkerErrorCode;

  constructor(code: WorkerErrorCode, message: string) {
    super(message);
    this.name = "WorkerError";
    this.code = code;
  }
}

export interface WorkerLike {
  postMessage(message: any): void;
  addEventListener?(type: string, listener: (event: any) => void): void;
  removeEventListener?(type: string, listener: (event: any) => void): void;
  on?(event: string, listener: (...args: any[]) => void): void;
  off?(event: string, listener: (...args: any[]) => void): void;
}

export type LockListener = () => void;

export class VaultWorkerClient {
  private worker: WorkerLike;
  private pendingRequests = new Map<
    string,
    {
      resolve: (data: any) => void;
      reject: (err: Error) => void;
      timer: NodeJS.Timeout | number;
    }
  >();
  private lockListeners = new Set<LockListener>();
  private nextId = 1;

  constructor(worker: WorkerLike) {
    this.worker = worker;
    this.setupMessageListener();
  }

  private setupMessageListener(): void {
    const handleIncoming = (msg: unknown) => {
      if (isWorkerBroadcastEvent(msg)) {
        if (msg.event === "VAULT_LOCKED") {
          for (const listener of this.lockListeners) {
            listener();
          }
        }
        return;
      }

      const response = msg as WorkerResponse;
      if (!response || !response.id) {
        return;
      }

      const pending = this.pendingRequests.get(response.id);
      if (!pending) {
        return;
      }

      this.pendingRequests.delete(response.id);
      clearTimeout(pending.timer);

      if (response.ok) {
        pending.resolve(response.data);
      } else {
        pending.reject(new WorkerError(response.error.code, response.error.message));
      }
    };

    if (typeof (this.worker as any).addEventListener === "function") {
      (this.worker as any).addEventListener("message", (event: MessageEvent) => {
        handleIncoming(event.data);
      });
    } else if (typeof (this.worker as any).on === "function") {
      (this.worker as any).on("message", (data: any) => {
        handleIncoming(data);
      });
    }
  }

  /**
   * Sends a typed request to the Web Worker and awaits its response.
   */
  public sendRequest<T extends WorkerRequestType>(
    type: T,
    payload: any,
    timeoutMs = 30000
  ): Promise<any> {
    const id = `req-${this.nextId++}-${Date.now()}`;
    const request: WorkerTypedRequest<T> = { id, type, payload };

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(
          new WorkerError(
            WorkerErrorCode.INTERNAL_ERROR,
            `Worker request timed out after ${timeoutMs}ms (type: ${type})`
          )
        );
      }, timeoutMs);

      this.pendingRequests.set(id, { resolve, reject, timer });
      this.worker.postMessage(request);
    });
  }

  /**
   * Registers a listener callback invoked whenever the vault is locked.
   */
  public onLock(listener: LockListener): () => void {
    this.lockListeners.add(listener);
    return () => this.lockListeners.delete(listener);
  }

  // --------------------------------------------------------------------------
  // High-Level Cryptographic APIs
  // --------------------------------------------------------------------------

  public async getStatus(): Promise<VaultStatusDto> {
    return this.sendRequest("GET_STATUS", undefined);
  }

  public async initVault(
    passphrase: string,
    kdfParamsJson?: string
  ): Promise<VaultInitResultDto> {
    return this.sendRequest("INIT_VAULT", { passphrase, kdfParamsJson });
  }

  public async unlockVault(
    passphrase: string,
    wrappedVaultKeyJson: string,
    kdfParamsJson: string
  ): Promise<{ success: true }> {
    return this.sendRequest("UNLOCK_VAULT", {
      passphrase,
      wrappedVaultKeyJson,
      kdfParamsJson,
    });
  }

  public async unlockWithRecoveryKey(
    recoveryPhrase: string,
    wrappedRecoveryKeyJson: string
  ): Promise<{ success: true }> {
    return this.sendRequest("UNLOCK_WITH_RECOVERY_KEY", {
      recoveryPhrase,
      wrappedRecoveryKeyJson,
    });
  }

  public async lockVault(): Promise<{ success: true }> {
    return this.sendRequest("LOCK_VAULT", undefined);
  }

  public async rewrapPassphrase(
    newPassphrase: string,
    kdfParamsJson?: string
  ): Promise<VaultRewrapResultDto> {
    return this.sendRequest("REWRAP_PASSPHRASE", {
      newPassphrase,
      kdfParamsJson,
    });
  }

  public async encryptNote(
    noteId: string,
    title: string,
    body: string,
    tags: string[]
  ): Promise<{ envelopeJson: string }> {
    return this.sendRequest("ENCRYPT_NOTE", { noteId, title, body, tags });
  }

  public async decryptNote(envelopeJson: string): Promise<PlaintextNoteDto> {
    return this.sendRequest("DECRYPT_NOTE", { envelopeJson });
  }

  public async decryptNotesBatch(
    envelopes: DecryptBatchItem[]
  ): Promise<DecryptBatchResultDto> {
    return this.sendRequest("DECRYPT_NOTES_BATCH", { envelopes });
  }

  public async indexNote(
    noteId: string,
    title: string,
    body: string,
    tags: string[],
    updatedAt: string
  ): Promise<{ success: true }> {
    return this.sendRequest("INDEX_NOTE", {
      noteId,
      title,
      body,
      tags,
      updatedAt,
    });
  }

  public async removeFromIndex(noteId: string): Promise<{ success: true }> {
    return this.sendRequest("REMOVE_FROM_INDEX", { noteId });
  }

  public async search(query: string): Promise<SearchResultDto[]> {
    return this.sendRequest("SEARCH", { query });
  }

  /**
   * Terminates or cancels any pending requests.
   */
  public dispose(): void {
    for (const pending of this.pendingRequests.values()) {
      clearTimeout(pending.timer);
      pending.reject(
        new WorkerError(
          WorkerErrorCode.INTERNAL_ERROR,
          "VaultWorkerClient disposed"
        )
      );
    }
    this.pendingRequests.clear();
    this.lockListeners.clear();
  }
}
