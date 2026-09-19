/**
 * Web Encrypted Attachment Manager (ZK-084).
 *
 * Implements chunked client-side encryption and decryption of file attachments
 * for the web client, offloaded to the dedicated Web Worker.
 *
 * Security Invariants:
 * - SEC-001: Plaintext note attachments, filenames, and MIME types NEVER cross to the server.
 * - SEC-002: Server only stores opaque blob IDs and ciphertext chunks; cannot decrypt.
 * - SEC-003: No attachment keys or plaintext content in logs or network headers.
 * - SEC-004 / SEC-005: Authenticated encryption via XChaCha20-Poly1305 with random nonces and AAD binding.
 * - SEC-009: Local persistence (IndexedDB) stores ciphertext blobs and encrypted envelopes only.
 * - SEC-010: Tampered chunks or integrity mismatch fails closed immediately.
 */

import { VaultWorkerClient } from "../worker/client.js";
import { IndexedDbStorage } from "../storage/indexeddb.js";
import { AttachmentManifestDto } from "../worker/protocol.js";
import {
  EncryptedEnvelopeDto,
  MutationType,
  MutationStatus,
  StoredEncryptedObject,
} from "../storage/models.js";

export const DEFAULT_ATTACHMENT_CHUNK_SIZE = 4 * 1024 * 1024; // 4 MiB
export const MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024; // 100 MiB (from MASTER_SPEC § 14)
export const OBJECT_KIND_ATTACHMENT_MANIFEST = 4;

export interface AttachmentProgress {
  attachmentId: string;
  chunkIndex: number;
  totalChunks: number;
  percent: number;
  phase: "encrypting" | "uploading" | "downloading" | "decrypting" | "complete";
  message?: string;
}

export type ProgressCallback = (progress: AttachmentProgress) => void;

export interface AttachmentFileSource {
  name: string;
  type: string;
  size: number;
  arrayBuffer: () => Promise<ArrayBuffer>;
  slice?: (start: number, end: number) => { arrayBuffer: () => Promise<ArrayBuffer> };
}

export interface DownloadedAttachment {
  blob: Blob;
  name: string;
  mime: string;
  size: number;
}

export interface AttachmentManagerConfig {
  serverUrl?: string;
  authToken?: string;
  chunkSize?: number;
}

export class AttachmentManager {
  private client: VaultWorkerClient;
  private storage: IndexedDbStorage;
  private config: AttachmentManagerConfig;

  constructor(
    client: VaultWorkerClient,
    storage: IndexedDbStorage,
    config: AttachmentManagerConfig = {}
  ) {
    this.client = client;
    this.storage = storage;
    this.config = config;
  }

  public setConfig(config: Partial<AttachmentManagerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Encrypts and stores a file attachment, returning its canonical attachment ID.
   *
   * Flow:
   * 1. Validates size <= 100 MiB.
   * 2. Generates random 256-bit AttachmentKey and attachment UUID.
   * 3. Chunks file and encrypts each chunk in Web Worker with unique nonce and AAD.
   * 4. Persists ciphertext chunks locally and uploads to /v1/blobs/{blob_id} if online.
   * 5. Encrypts AttachmentManifest envelope (kind 4) under active VaultKey in Web Worker.
   * 6. Persists manifest object in IndexedDB and enqueues upsert mutation for sync.
   */
  public async uploadAttachment(
    file: AttachmentFileSource,
    onProgress?: ProgressCallback
  ): Promise<AttachmentManifestDto> {
    if (file.size > MAX_ATTACHMENT_SIZE) {
      throw new Error(
        `Attachment size (${(file.size / (1024 * 1024)).toFixed(1)} MiB) exceeds maximum allowed size (100 MiB)`
      );
    }

    const chunkSize = this.config.chunkSize || DEFAULT_ATTACHMENT_CHUNK_SIZE;
    const totalChunks = file.size === 0 ? 1 : Math.ceil(file.size / chunkSize);

    const attachmentId =
      typeof crypto !== "undefined" && crypto.randomUUID
        ? crypto.randomUUID()
        : `att-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    // 1. Generate fresh random AttachmentKey in Web Worker
    const attachmentKeyBase64 = await this.client.generateAttachmentKey();

    // 2. Read file bytes and compute BLAKE2b content hash
    const fullBuffer = new Uint8Array(await file.arrayBuffer());
    const contentHash = await this.client.computeContentHash(fullBuffer);

    // 3. Encrypt and upload chunks
    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
      const start = chunkIndex * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      const chunkBytes = file.size === 0 ? new Uint8Array(0) : fullBuffer.slice(start, end);

      const percent = Math.round(((chunkIndex) / totalChunks) * 100);
      onProgress?.({
        attachmentId,
        chunkIndex,
        totalChunks,
        percent,
        phase: "encrypting",
        message: `Encrypting chunk ${chunkIndex + 1} of ${totalChunks}...`,
      });

      // Encrypt chunk in Web Worker
      const chunkBinary = await this.client.encryptAttachmentChunk(
        chunkBytes,
        attachmentId,
        chunkIndex,
        totalChunks,
        attachmentKeyBase64
      );

      const blobId = `${attachmentId}_${chunkIndex}`;

      onProgress?.({
        attachmentId,
        chunkIndex,
        totalChunks,
        percent,
        phase: "uploading",
        message: `Storing chunk ${chunkIndex + 1} of ${totalChunks}...`,
      });

      // Persist ciphertext chunk to local encrypted IndexedDB store
      await this.storage.putBlob(blobId, chunkBinary);

      // Upload ciphertext chunk to server if online and configured
      if (this.config.serverUrl && this.config.authToken) {
        await this.uploadCiphertextBlobToServer(blobId, chunkBinary);
      }
    }

    // 4. Create and encrypt AttachmentManifest
    const manifest: AttachmentManifestDto = {
      attachment_id: attachmentId,
      name: file.name || "attachment",
      mime: file.type || "application/octet-stream",
      size: file.size,
      chunk_count: totalChunks,
      chunk_size: chunkSize,
      content_hash: contentHash,
    };

    const envelopeJson = await this.client.encryptAttachmentManifest(
      manifest,
      attachmentKeyBase64
    );
    const envelope: EncryptedEnvelopeDto = JSON.parse(envelopeJson);

    // 5. Store manifest object in local IndexedDB
    const now = new Date().toISOString();
    const storedObject: StoredEncryptedObject = {
      object_id: attachmentId,
      object_kind: OBJECT_KIND_ATTACHMENT_MANIFEST,
      revision: 1,
      server_seq: 0,
      is_deleted: false,
      envelope,
      updated_at: now,
    };
    await this.storage.putObject(storedObject);

    // 6. Queue mutation for sync
    const mutationId =
      typeof crypto !== "undefined" && crypto.randomUUID
        ? crypto.randomUUID()
        : `mut-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    await this.storage.enqueueMutation({
      mutation_id: mutationId,
      object_id: attachmentId,
      expected_revision: 0,
      object_kind: OBJECT_KIND_ATTACHMENT_MANIFEST,
      mutation_type: MutationType.Upsert,
      envelope,
      created_at: now,
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    onProgress?.({
      attachmentId,
      chunkIndex: totalChunks - 1,
      totalChunks,
      percent: 100,
      phase: "complete",
      message: "Attachment upload complete.",
    });

    return manifest;
  }

  /**
   * Retrieves and decrypts an attachment by its canonical ID.
   *
   * Flow:
   * 1. Loads encrypted manifest from IndexedDB and decrypts in Web Worker.
   * 2. Fetches each ciphertext chunk (from IndexedDB or server).
   * 3. Decrypts chunk in Web Worker using AttachmentKey and verifies AAD.
   * 4. Validates sequential ordering and content hash.
   * 5. Returns a reconstructed browser Blob.
   */
  public async downloadAttachment(
    attachmentId: string,
    onProgress?: ProgressCallback
  ): Promise<DownloadedAttachment> {
    // 1. Retrieve manifest envelope from local storage
    const storedManifestObj = await this.storage.getObject(attachmentId);
    if (!storedManifestObj || storedManifestObj.is_deleted) {
      throw new Error(`Attachment manifest '${attachmentId}' not found.`);
    }

    // 2. Decrypt manifest in Web Worker
    const { manifest, attachmentKeyBase64 } =
      await this.client.decryptAttachmentManifest(
        JSON.stringify(storedManifestObj.envelope)
      );

    const decryptedChunks: Uint8Array[] = [];

    // 3. Download and decrypt each chunk
    for (let chunkIndex = 0; chunkIndex < manifest.chunk_count; chunkIndex++) {
      const blobId = `${manifest.attachment_id}_${chunkIndex}`;

      const percent = Math.round(((chunkIndex) / manifest.chunk_count) * 100);
      onProgress?.({
        attachmentId,
        chunkIndex,
        totalChunks: manifest.chunk_count,
        percent,
        phase: "downloading",
        message: `Downloading chunk ${chunkIndex + 1} of ${manifest.chunk_count}...`,
      });

      // Fetch ciphertext chunk: try local IndexedDB first, fallback to server
      let chunkBinary = await this.storage.getBlob(blobId);
      if (!chunkBinary) {
        if (this.config.serverUrl && this.config.authToken) {
          chunkBinary = await this.downloadCiphertextBlobFromServer(blobId);
          // Cache locally
          await this.storage.putBlob(blobId, chunkBinary);
        } else {
          throw new Error(
            `Ciphertext blob '${blobId}' not available locally or offline.`
          );
        }
      }

      onProgress?.({
        attachmentId,
        chunkIndex,
        totalChunks: manifest.chunk_count,
        percent,
        phase: "decrypting",
        message: `Decrypting chunk ${chunkIndex + 1} of ${manifest.chunk_count}...`,
      });

      // Decrypt chunk in Web Worker (fails closed on tampered ciphertext or AAD)
      const plaintextChunk = await this.client.decryptAttachmentChunk(
        chunkBinary,
        attachmentKeyBase64
      );

      decryptedChunks.push(plaintextChunk);
    }

    // 4. Combine decrypted chunks into contiguous byte array
    const totalBytes = decryptedChunks.reduce((acc, c) => acc + c.length, 0);
    const fullDecrypted = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of decryptedChunks) {
      fullDecrypted.set(chunk, offset);
      offset += chunk.length;
    }

    // 5. Verify BLAKE2b content integrity hash if manifest specified one
    if (manifest.content_hash) {
      const actualHash = await this.client.computeContentHash(fullDecrypted);
      if (actualHash !== manifest.content_hash) {
        throw new Error(
          `Attachment integrity verification failed: hash mismatch.`
        );
      }
    }

    onProgress?.({
      attachmentId,
      chunkIndex: manifest.chunk_count - 1,
      totalChunks: manifest.chunk_count,
      percent: 100,
      phase: "complete",
      message: "Decryption complete.",
    });

    const blob = new Blob([fullDecrypted], { type: manifest.mime });

    return {
      blob,
      name: manifest.name,
      mime: manifest.mime,
      size: manifest.size,
    };
  }

  /**
   * Retrieves the decrypted manifest for an attachment ID without downloading all chunks.
   */
  public async getManifest(attachmentId: string): Promise<AttachmentManifestDto | null> {
    const stored = await this.storage.getObject(attachmentId);
    if (!stored || stored.is_deleted) {
      return null;
    }
    try {
      const { manifest } = await this.client.decryptAttachmentManifest(
        JSON.stringify(stored.envelope)
      );
      return manifest;
    } catch (_err) {
      return null;
    }
  }

  /**
   * Detaches an attachment: writes a tombstone for the manifest object and queues delete mutation.
   */
  public async deleteAttachment(attachmentId: string): Promise<void> {
    const existing = await this.storage.getObject(attachmentId);
    if (!existing) {
      return;
    }

    const now = new Date().toISOString();
    const nextRevision = existing.revision + 1;

    // 1. Mark manifest deleted in local storage
    await this.storage.markDeleted(attachmentId, nextRevision, existing.envelope, now);

    // 2. Queue delete mutation for sync
    const mutationId =
      typeof crypto !== "undefined" && crypto.randomUUID
        ? crypto.randomUUID()
        : `mut-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    await this.storage.enqueueMutation({
      mutation_id: mutationId,
      object_id: attachmentId,
      expected_revision: existing.revision,
      object_kind: OBJECT_KIND_ATTACHMENT_MANIFEST,
      mutation_type: MutationType.Delete,
      envelope: existing.envelope,
      created_at: now,
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // 3. Clean up cached local chunks
    for (let i = 0; i < 256; i++) {
      const blobId = `${attachmentId}_${i}`;
      const deleted = await this.storage.deleteBlob(blobId);
      if (!deleted) break;
    }
  }

  /**
   * Uploads opaque ciphertext bytes to server PUT /v1/blobs/{blob_id}.
   * SEC-001/SEC-002: Sends ONLY ciphertext and authorization header.
   * Zero filename, MIME, or note plaintext headers.
   */
  private async uploadCiphertextBlobToServer(
    blobId: string,
    chunkBinary: Uint8Array
  ): Promise<void> {
    const cleanUrl = (this.config.serverUrl || "").replace(/\/+$/, "");
    const res = await fetch(`${cleanUrl}/v1/blobs/${blobId}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${this.config.authToken}`,
        "Content-Type": "application/octet-stream",
      },
      body: chunkBinary as any,
    });

    if (!res.ok && res.status !== 201) {
      const errText = await res.text().catch(() => "");
      throw new Error(`Blob upload failed (${res.status}): ${errText}`);
    }
  }

  /**
   * Fetches opaque ciphertext bytes from server GET /v1/blobs/{blob_id}.
   */
  private async downloadCiphertextBlobFromServer(blobId: string): Promise<Uint8Array> {
    const cleanUrl = (this.config.serverUrl || "").replace(/\/+$/, "");
    const res = await fetch(`${cleanUrl}/v1/blobs/${blobId}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${this.config.authToken}`,
      },
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch blob '${blobId}' from server (${res.status})`);
    }

    const buffer = await res.arrayBuffer();
    return new Uint8Array(buffer);
  }
}
