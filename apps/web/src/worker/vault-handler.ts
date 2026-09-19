/**
 * Vault Message Handler (ZK-062).
 *
 * Implements the core Web Worker cryptographic logic. Owns the active
 * `WasmVaultSession` exclusively in private worker memory.
 *
 * Security Invariants:
 * - SEC-001 / SEC-002: Raw Vault Key bytes NEVER cross to JavaScript.
 * - SEC-003: No secrets in logs.
 * - SEC-009: Persistent local cache stores ciphertext only.
 * - SEC-010: Cryptographic errors fail closed with typed WorkerErrorCode.
 */

import * as zk from "zk-wasm";
import {
  WorkerErrorCode,
  WorkerRequest,
  WorkerResponse,
  WorkerResponseError,
  PlaintextNoteDto,
  AttachmentManifestDto,
  SearchResultDto,
  VaultInitResultDto,
  VaultRewrapResultDto,
  VaultStatusDto,
  DecryptBatchResultDto,
} from "./protocol.js";

export class VaultHandler {
  private session: zk.WasmVaultSession | null = null;
  private isWasmInitialized = false;

  /**
   * Initializes the underlying WASM module if not already initialized.
   */
  public async initWasm(wasmModuleOrBytes?: Uint8Array | ArrayBuffer | WebAssembly.Module): Promise<void> {
    if (this.isWasmInitialized) {
      return;
    }
    if (wasmModuleOrBytes) {
      zk.initSync({ module: wasmModuleOrBytes });
    }
    zk.init_panic_hook();
    this.isWasmInitialized = true;
  }

  /**
   * Processes a single RPC request message and produces a response.
   */
  public handleMessage(
    request: WorkerRequest,
    postMessage: (response: WorkerResponse) => void,
    broadcast?: (event: { event: "VAULT_LOCKED" }) => void
  ): void {
    try {
      const result = this.processRequest(request);

      // If action was LOCK_VAULT, broadcast notification
      if (request.type === "LOCK_VAULT" && broadcast) {
        broadcast({ event: "VAULT_LOCKED" });
      }

      postMessage({
        id: request.id,
        ok: true,
        data: result,
      });
    } catch (err) {
      const errorResponse = this.mapErrorToResponse(request.id, err);
      postMessage(errorResponse);
    }
  }

  private processRequest(request: WorkerRequest): any {
    switch (request.type) {
      case "GET_STATUS": {
        const isUnlocked = this.session !== null && this.session.is_unlocked();
        return { isUnlocked } as VaultStatusDto;
      }

      case "INIT_VAULT": {
        const payload = request.payload;
        let initRes: zk.WasmVaultInitResult;
        if (payload.kdfParamsJson) {
          initRes = zk.init_vault_with_params(payload.passphrase, payload.kdfParamsJson);
        } else {
          initRes = zk.init_vault(payload.passphrase);
        }

        const dto: VaultInitResultDto = {
          wrappedVaultKey: initRes.wrapped_vault_key,
          kdfParamsJson: initRes.kdf_params_json,
          wrappedRecoveryKey: initRes.wrapped_recovery_key,
          recoveryPhrase: initRes.recovery_phrase,
        };

        // Take active session and store strictly within worker scope
        if (this.session) {
          this.session.lock();
        }
        this.session = initRes.take_session();

        return dto;
      }

      case "UNLOCK_VAULT": {
        const payload = request.payload;
        if (this.session) {
          this.session.lock();
          this.session = null;
        }

        const session = zk.unlock_vault(
          payload.passphrase,
          payload.wrappedVaultKeyJson,
          payload.kdfParamsJson
        );
        this.session = session;
        return { success: true };
      }

      case "UNLOCK_WITH_RECOVERY_KEY": {
        const payload = request.payload;
        if (this.session) {
          this.session.lock();
          this.session = null;
        }

        const session = zk.unlock_with_recovery_key(
          payload.recoveryPhrase,
          payload.wrappedRecoveryKeyJson
        );
        this.session = session;
        return { success: true };
      }

      case "LOCK_VAULT": {
        if (this.session) {
          this.session.lock();
          this.session = null;
        }
        return { success: true };
      }

      case "REWRAP_PASSPHRASE": {
        const session = this.ensureUnlocked();
        const payload = request.payload;

        // If current passphrase verification is requested, verify it against the current envelope
        if (
          payload.oldPassphrase &&
          payload.currentWrappedVaultKeyJson &&
          payload.currentKdfParamsJson
        ) {
          try {
            const verificationSession = zk.unlock_vault(
              payload.oldPassphrase,
              payload.currentWrappedVaultKeyJson,
              payload.currentKdfParamsJson
            );
            verificationSession.lock();
          } catch (_e) {
            const err = new Error("Current master passphrase is incorrect.");
            (err as any).code = WorkerErrorCode.DECRYPTION_FAILED;
            throw err;
          }
        }

        let rewrapRes: zk.WasmRewrapResult;
        if (payload.kdfParamsJson) {
          rewrapRes = session.rewrap_passphrase_with_params(
            payload.newPassphrase,
            payload.kdfParamsJson
          );
        } else {
          rewrapRes = session.rewrap_passphrase(payload.newPassphrase);
        }

        return {
          newWrappedVaultKey: rewrapRes.new_wrapped_vault_key,
          newKdfParamsJson: rewrapRes.new_kdf_params_json,
        } as VaultRewrapResultDto;
      }

      case "ENCRYPT_NOTE": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        let envelopeJson: string;
        if (payload.attachments && payload.attachments.length > 0) {
          envelopeJson = session.encrypt_note_with_attachments(
            payload.noteId,
            payload.title,
            payload.body,
            payload.tags,
            payload.attachments
          );
        } else {
          envelopeJson = session.encrypt_note(
            payload.noteId,
            payload.title,
            payload.body,
            payload.tags
          );
        }
        return { envelopeJson };
      }

      case "DECRYPT_NOTE": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        const note = session.decrypt_note(payload.envelopeJson);
        return this.mapNoteToDto(note);
      }

      case "DECRYPT_NOTES_BATCH": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        const notes: PlaintextNoteDto[] = [];
        const failed: Array<{ id: string; error: string }> = [];

        for (const item of payload.envelopes) {
          try {
            const note = session.decrypt_note(item.envelopeJson);
            notes.push(this.mapNoteToDto(note));
          } catch (e: any) {
            failed.push({
              id: item.id,
              error: e?.message || String(e),
            });
          }
        }

        return { notes, failed } as DecryptBatchResultDto;
      }

      case "INDEX_NOTE": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        session.index_note(
          payload.noteId,
          payload.title,
          payload.body,
          payload.tags,
          payload.updatedAt
        );
        return { success: true };
      }

      case "REMOVE_FROM_INDEX": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        session.remove_from_index(payload.noteId);
        return { success: true };
      }

      case "SEARCH": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        const results = session.search(payload.query);
        return results.map(
          (r: zk.WasmSearchResult): SearchResultDto => ({
            noteId: r.note_id,
            score: r.score,
            matchedTitle: r.matched_title,
            snippet: r.snippet,
          })
        );
      }

      case "ENCRYPT_ATTACHMENT_CHUNK": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        const chunkBinary = session.encrypt_attachment_chunk(
          payload.chunkBytes,
          payload.attachmentId,
          payload.chunkIndex,
          payload.totalChunks,
          payload.attachmentKeyBase64
        );
        return { chunkBinary };
      }

      case "DECRYPT_ATTACHMENT_CHUNK": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        const plaintextBytes = session.decrypt_attachment_chunk(
          payload.chunkBinary,
          payload.attachmentKeyBase64
        );
        return { plaintextBytes };
      }

      case "ENCRYPT_ATTACHMENT_MANIFEST": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        const envelopeJson = session.encrypt_attachment_manifest(
          JSON.stringify(payload.manifest),
          payload.attachmentKeyBase64
        );
        return { envelopeJson };
      }

      case "DECRYPT_ATTACHMENT_MANIFEST": {
        const session = this.ensureUnlocked();
        const payload = request.payload;
        const decResult = session.decrypt_attachment_manifest(payload.envelopeJson);
        const manifestObj = decResult.manifest;
        const manifest: AttachmentManifestDto = {
          attachment_id: manifestObj.attachment_id,
          name: manifestObj.name,
          mime: manifestObj.mime,
          size: manifestObj.size,
          chunk_count: manifestObj.chunk_count,
          chunk_size: manifestObj.chunk_size,
          content_hash: manifestObj.content_hash,
        };
        return {
          manifest,
          attachmentKeyBase64: decResult.attachment_key_base64,
        };
      }

      case "GENERATE_ATTACHMENT_KEY": {
        const attachmentKeyBase64 = zk.wasm_generate_attachment_key();
        return { attachmentKeyBase64 };
      }

      case "COMPUTE_CONTENT_HASH": {
        const payload = request.payload;
        const hash = zk.wasm_compute_content_hash(payload.bytes);
        return { hash };
      }

      default: {
        throw new Error(`Unknown request type: ${(request as any).type}`);
      }
    }
  }

  private ensureUnlocked(): zk.WasmVaultSession {
    if (!this.session || !this.session.is_unlocked()) {
      const err = new Error("Vault is locked. Unlock the vault to perform this operation.");
      (err as any).code = WorkerErrorCode.VAULT_LOCKED;
      throw err;
    }
    return this.session;
  }

  private mapNoteToDto(note: zk.WasmPlaintextNote): PlaintextNoteDto {
    return {
      id: note.id,
      title: note.title,
      body: note.body,
      tags: note.tags,
      attachments: note.attachments || [],
      createdAt: note.created_at,
      updatedAt: note.updated_at,
    };
  }

  private mapErrorToResponse(id: string, err: unknown): WorkerResponseError {
    const rawMsg = err instanceof Error ? err.message : String(err);
    let code = WorkerErrorCode.INTERNAL_ERROR;

    if ((err as any)?.code) {
      code = (err as any).code;
    } else if (rawMsg.includes("vault is locked") || rawMsg.includes("locked")) {
      code = WorkerErrorCode.VAULT_LOCKED;
    } else if (
      rawMsg.includes("decryption failed") ||
      rawMsg.includes("decrypt failed") ||
      rawMsg.includes("unlock failed")
    ) {
      code = WorkerErrorCode.DECRYPTION_FAILED;
    } else if (rawMsg.includes("recovery phrase") || rawMsg.includes("recovery unwrap failed")) {
      code = WorkerErrorCode.INVALID_RECOVERY_KEY;
    } else if (rawMsg.includes("invalid payload") || rawMsg.includes("invalid envelope")) {
      code = WorkerErrorCode.INVALID_PAYLOAD;
    }

    return {
      id,
      ok: false,
      error: {
        code,
        message: rawMsg,
      },
    };
  }
}
