/**
 * Web Encrypted Attachment Support Tests (ZK-084).
 *
 * Acceptance criteria:
 * - encrypt before upload;
 * - decrypt after download;
 * - progress shown;
 * - network sees ciphertext only.
 *
 * Security Invariants:
 * - SEC-001: Plaintext note attachments, filenames, and MIME types NEVER cross to the server.
 * - SEC-002: Server only stores opaque blob IDs and ciphertext chunks; cannot decrypt.
 * - SEC-003: No secrets or plaintext content in logs or network headers.
 * - SEC-004 / SEC-005: Authenticated encryption via XChaCha20-Poly1305 with random nonces and AAD binding.
 * - SEC-009: Local persistence (IndexedDB) stores ciphertext blobs and encrypted envelopes only.
 * - SEC-010: Cryptographic failures and tampered chunks fail closed.
 */

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import { indexedDB as fakeIDB } from "fake-indexeddb";

import { VaultWorkerClient } from "../src/worker/client.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import {
  AttachmentManager,
  AttachmentProgress,
  AttachmentFileSource,
  MAX_ATTACHMENT_SIZE,
  OBJECT_KIND_ATTACHMENT_MANIFEST,
} from "../src/attachments/manager.js";
import { MutationType } from "../src/storage/models.js";
import { threeWayMergeNotes } from "../src/utils/diff3.js";
import { PlaintextNoteDto } from "../src/worker/protocol.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = fs.existsSync(path.resolve(__dirname, "../src/worker/worker.js"))
  ? path.resolve(__dirname, "../src/worker/worker.js")
  : path.resolve(__dirname, "../dist/src/worker/worker.js");

// Fast test KDF parameters JSON
const TEST_KDF_PARAMS_JSON = JSON.stringify({
  algorithm: "argon2id",
  memory_kib: 1024,
  iterations: 1,
  parallelism: 1,
  salt: "AQIDBAUGBwgJCgsMDQ4PEA==",
});

function createTestClient(): { client: VaultWorkerClient; worker: Worker } {
  const worker = new Worker(WORKER_PATH);
  const client = new VaultWorkerClient(worker);
  return { client, worker };
}

function createMockFileSource(
  name: string,
  type: string,
  data: Uint8Array
): AttachmentFileSource {
  return {
    name,
    type,
    size: data.length,
    arrayBuffer: async () => {
      const copy = new Uint8Array(data.byteLength);
      copy.set(data);
      return copy.buffer as ArrayBuffer;
    },
  };
}

test("Worker: Direct attachment chunk encryption, decryption, and tampered fail-closed (SEC-010)", async () => {
  const { client, worker } = createTestClient();
  try {
    await client.initVault("test-passphrase-att", TEST_KDF_PARAMS_JSON);

    // 1. Generate fresh random 256-bit AttachmentKey
    const attachmentKeyBase64 = await client.generateAttachmentKey();
    assert.ok(attachmentKeyBase64.length > 0);
    const keyBytes = Buffer.from(attachmentKeyBase64, "base64");
    assert.equal(keyBytes.length, 32);

    // 2. Encrypt chunk
    const plaintext = new TextEncoder().encode("Hello, encrypted chunked attachment world!");
    const attachmentId = "11111111-2222-3333-4444-555555555555";
    const chunkBinary = await client.encryptAttachmentChunk(
      plaintext,
      attachmentId,
      0,
      1,
      attachmentKeyBase64
    );

    // 3. Verify ZKCK wire format header
    // Magic: 0x5A 0x4B 0x43 0x4B ("ZKCK")
    assert.equal(chunkBinary[0], 0x5a);
    assert.equal(chunkBinary[1], 0x4b);
    assert.equal(chunkBinary[2], 0x43);
    assert.equal(chunkBinary[3], 0x4b);
    // Version: 1 (4-byte big-endian u32)
    const version = new DataView(chunkBinary.buffer, chunkBinary.byteOffset).getUint32(4);
    assert.equal(version, 1);

    // 4. Decrypt chunk round trip
    const decrypted = await client.decryptAttachmentChunk(
      chunkBinary,
      attachmentKeyBase64
    );
    assert.deepEqual(decrypted, plaintext);

    // 5. Wrong attachment key fails closed (SEC-010)
    const wrongKey = Buffer.alloc(32, 0xff).toString("base64");
    await assert.rejects(async () => {
      await client.decryptAttachmentChunk(chunkBinary, wrongKey);
    });

    // 6. Tampered ciphertext fails closed (SEC-010)
    const tampered = new Uint8Array(chunkBinary);
    const lastByte = tampered[tampered.length - 1];
    if (lastByte !== undefined) {
      tampered[tampered.length - 1] = lastByte ^ 0x01; // flip 1 bit in tag
    }
    await assert.rejects(async () => {
      await client.decryptAttachmentChunk(tampered, attachmentKeyBase64);
    });

    // 7. Tampered header/AAD fails closed (SEC-010)
    const tamperedHeader = new Uint8Array(chunkBinary);
    const versionByte = tamperedHeader[7];
    if (versionByte !== undefined) {
      tamperedHeader[7] = versionByte ^ 0x02; // tamper with version field
    }
    await assert.rejects(async () => {
      await client.decryptAttachmentChunk(tamperedHeader, attachmentKeyBase64);
    });
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Worker: Attachment manifest encryption and decryption under VaultKey", async () => {
  const { client, worker } = createTestClient();
  try {
    await client.initVault("test-passphrase-manifest", TEST_KDF_PARAMS_JSON);

    const attachmentKeyBase64 = await client.generateAttachmentKey();
    const manifest = {
      attachment_id: "att-manifest-001",
      name: "financial-report.pdf",
      mime: "application/pdf",
      size: 1048576,
      chunk_count: 1,
      chunk_size: 4194304,
      content_hash: "blake2b-dummy-hash",
    };

    const envelopeJson = await client.encryptAttachmentManifest(
      manifest,
      attachmentKeyBase64
    );
    const env = JSON.parse(envelopeJson);
    assert.equal(env.envelope_version, 1);
    assert.equal(env.object_id, "att-manifest-001");
    assert.equal(env.object_kind, 4); // ObjectKind::AttachmentManifest

    // Decrypt manifest
    const decrypted = await client.decryptAttachmentManifest(envelopeJson);
    assert.deepEqual(decrypted.manifest, manifest);
    assert.equal(decrypted.attachmentKeyBase64, attachmentKeyBase64);
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("AttachmentManager: Chunked upload, download, and progress reporting", async () => {
  const { client, worker } = createTestClient();
  const dbName = `test-att-manager-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    await client.initVault("test-passphrase-att-mgr", TEST_KDF_PARAMS_JSON);

    // Create 180-byte test file and set chunk size to 64 bytes -> exactly 3 chunks (64, 64, 52)
    const testData = new Uint8Array(180);
    for (let i = 0; i < testData.length; i++) {
      testData[i] = (i * 7 + 13) % 256;
    }

    const file = createMockFileSource("secret-document.bin", "application/octet-stream", testData);

    const manager = new AttachmentManager(client, storage, {
      chunkSize: 64, // force multi-chunk
    });

    // Track upload progress
    const uploadProgressEvents: AttachmentProgress[] = [];
    const manifest = await manager.uploadAttachment(file, (p) => {
      uploadProgressEvents.push({ ...p });
    });

    assert.equal(manifest.name, "secret-document.bin");
    assert.equal(manifest.mime, "application/octet-stream");
    assert.equal(manifest.size, 180);
    assert.equal(manifest.chunk_count, 3);
    assert.equal(manifest.chunk_size, 64);
    assert.ok(manifest.content_hash && manifest.content_hash.length > 0);

    // Verify upload progress sequence
    assert.ok(uploadProgressEvents.length >= 3);
    const phases = uploadProgressEvents.map((e) => e.phase);
    assert.ok(phases.includes("encrypting"));
    assert.ok(phases.includes("uploading"));
    assert.equal(phases[phases.length - 1], "complete");
    const lastUploadEvent = uploadProgressEvents[uploadProgressEvents.length - 1];
    assert.ok(lastUploadEvent);
    assert.equal(lastUploadEvent.percent, 100);

    // Verify local IndexedDB persistence (SEC-009)
    // 1. Chunks are stored in 'blobs' store with ZKCK magic
    for (let i = 0; i < 3; i++) {
      const blobId = `${manifest.attachment_id}_${i}`;
      const blobData = await storage.getBlob(blobId);
      assert.ok(blobData, `Blob chunk ${blobId} should be present in IndexedDB`);
      assert.equal(blobData[0], 0x5a); // 'Z'
      assert.equal(blobData[1], 0x4b); // 'K'
      assert.equal(blobData[2], 0x43); // 'C'
      assert.equal(blobData[3], 0x4b); // 'K'
    }

    // 2. Manifest is stored in 'objects' store as encrypted envelope kind 4
    const manifestObj = await storage.getObject(manifest.attachment_id);
    assert.ok(manifestObj);
    assert.equal(manifestObj.object_kind, OBJECT_KIND_ATTACHMENT_MANIFEST);
    assert.equal(manifestObj.is_deleted, false);
    assert.equal(manifestObj.revision, 1);

    // 3. Upsert mutation queued
    const mutations = await storage.listPendingMutations();
    assert.equal(mutations.length, 1);
    const mut = mutations[0];
    assert.ok(mut);
    assert.equal(mut.object_id, manifest.attachment_id);
    assert.equal(mut.mutation_type, MutationType.Upsert);
    assert.equal(mut.expected_revision, 0);

    // 4. Download and verify round-trip byte identity
    const downloadProgressEvents: AttachmentProgress[] = [];
    const downloaded = await manager.downloadAttachment(manifest.attachment_id, (p) => {
      downloadProgressEvents.push({ ...p });
    });

    assert.equal(downloaded.name, "secret-document.bin");
    assert.equal(downloaded.mime, "application/octet-stream");
    assert.equal(downloaded.size, 180);

    const downloadedBytes = new Uint8Array(await downloaded.blob.arrayBuffer());
    assert.deepEqual(downloadedBytes, testData);

    // Verify download progress sequence
    const dlPhases = downloadProgressEvents.map((e) => e.phase);
    assert.ok(dlPhases.includes("downloading"));
    assert.ok(dlPhases.includes("decrypting"));
    assert.equal(dlPhases[dlPhases.length - 1], "complete");

    // 5. Manifest inspection without downloading all chunks
    const inspected = await manager.getManifest(manifest.attachment_id);
    assert.ok(inspected);
    assert.deepEqual(inspected, manifest);

    // 6. Delete attachment -> marks tombstone and deletes cached chunks
    await manager.deleteAttachment(manifest.attachment_id);

    const deletedObj = await storage.getObject(manifest.attachment_id);
    assert.ok(deletedObj);
    assert.equal(deletedObj.is_deleted, true);
    assert.equal(deletedObj.revision, 2);

    // Cached blobs deleted
    for (let i = 0; i < 3; i++) {
      const blob = await storage.getBlob(`${manifest.attachment_id}_${i}`);
      assert.equal(blob, null);
    }
  } finally {
    client.dispose();
    await worker.terminate();
    await storage.deleteDatabase();
  }
});

test("AttachmentManager: Network sees CIPHERTEXT ONLY with zero plaintext headers (SEC-001, SEC-002)", async () => {
  const { client, worker } = createTestClient();
  const dbName = `test-att-net-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  // Intercept globalThis.fetch to audit network traffic
  const capturedRequests: {
    url: string;
    method: string;
    headers: Record<string, string>;
    bodyBytes: Uint8Array;
  }[] = [];

  const originalFetch = globalThis.fetch;
  const mockServerBlobs = new Map<string, Uint8Array>();

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof input === "string" ? input : input.toString();
    const method = init?.method || "GET";
    const headers: Record<string, string> = {};
    if (init?.headers) {
      const h = new Headers(init.headers as any);
      h.forEach((val, key) => {
        headers[key.toLowerCase()] = val;
      });
    }

    let bodyBytes: Uint8Array = new Uint8Array(0);
    if (init && init.body) {
      if (init.body instanceof Uint8Array) {
        bodyBytes = new Uint8Array(init.body.buffer, init.body.byteOffset, init.body.byteLength);
      } else if (init.body instanceof ArrayBuffer) {
        bodyBytes = new Uint8Array(init.body);
      }
    }

    capturedRequests.push({
      url: urlStr,
      method,
      headers,
      bodyBytes,
    });

    if (method === "PUT" && urlStr.includes("/v1/blobs/")) {
      const parts = urlStr.split("/v1/blobs/");
      const blobId = parts[1] || "";
      mockServerBlobs.set(blobId, bodyBytes);
      return new Response(null, { status: 201 });
    }

    if (method === "GET" && urlStr.includes("/v1/blobs/")) {
      const parts = urlStr.split("/v1/blobs/");
      const blobId = parts[1] || "";
      const data = mockServerBlobs.get(blobId);
      if (data) {
        const copy = new Uint8Array(data.byteLength);
        copy.set(data);
        return new Response(copy.buffer as ArrayBuffer, {
          status: 200,
          headers: { "Content-Type": "application/octet-stream" },
        });
      }
      return new Response("Not found", { status: 404 });
    }

    return new Response("Not handled", { status: 500 });
  };

  try {
    await client.initVault("test-passphrase-network", TEST_KDF_PARAMS_JSON);

    const secretPlaintextString = "TOP_SECRET_FINANCIAL_PASSWORDS_DO_NOT_REVEAL";
    const secretFileName = "confidential_bank_export.csv";
    const secretMimeType = "text/csv";

    const secretData = new TextEncoder().encode(secretPlaintextString);
    const file = createMockFileSource(secretFileName, secretMimeType, secretData);

    const manager = new AttachmentManager(client, storage, {
      serverUrl: "https://sync.example.com",
      authToken: "bearer-token-sec-test",
      chunkSize: 1024,
    });

    const manifest = await manager.uploadAttachment(file);

    // Audit captured network requests
    assert.equal(capturedRequests.length, 1);
    const uploadReq = capturedRequests[0];
    assert.ok(uploadReq);
    assert.equal(uploadReq.method, "PUT");
    assert.equal(uploadReq.url, `https://sync.example.com/v1/blobs/${manifest.attachment_id}_0`);
    assert.equal(uploadReq.headers["authorization"], "Bearer bearer-token-sec-test");
    assert.equal(uploadReq.headers["content-type"], "application/octet-stream");

    // SEC-001 Invariant: Assert no plaintext filenames, mime types, or note bodies in headers or url
    for (const [headerKey, headerVal] of Object.entries(uploadReq.headers)) {
      assert.ok(
        !headerVal.includes(secretFileName),
        `Header '${headerKey}' leaked plaintext filename: ${headerVal}`
      );
      assert.ok(
        !headerVal.includes(secretMimeType),
        `Header '${headerKey}' leaked plaintext MIME: ${headerVal}`
      );
      assert.ok(
        !headerVal.includes(secretPlaintextString),
        `Header '${headerKey}' leaked plaintext body: ${headerVal}`
      );
    }

    // Assert body starts with ZKCK wire format magic and does NOT contain plaintext
    assert.equal(uploadReq.bodyBytes[0], 0x5a); // 'Z'
    assert.equal(uploadReq.bodyBytes[1], 0x4b); // 'K'
    assert.equal(uploadReq.bodyBytes[2], 0x43); // 'C'
    assert.equal(uploadReq.bodyBytes[3], 0x4b); // 'K'

    const bodyAsText = new TextDecoder("utf-8", { fatal: false }).decode(uploadReq.bodyBytes);
    assert.ok(
      !bodyAsText.includes(secretPlaintextString),
      "Server request body leaked plaintext payload!"
    );
    assert.ok(
      !bodyAsText.includes(secretFileName),
      "Server request body leaked plaintext filename!"
    );

    // Now test downloading from server when local cache is deleted:
    // Delete local blob chunk
    await storage.deleteBlob(`${manifest.attachment_id}_0`);
    assert.equal(await storage.getBlob(`${manifest.attachment_id}_0`), null);

    // Download attachment -> must fetch blob from server and decrypt cleanly
    const downloaded = await manager.downloadAttachment(manifest.attachment_id);
    assert.equal(downloaded.name, secretFileName);
    assert.equal(downloaded.mime, secretMimeType);
    const downloadedText = new TextDecoder().decode(await downloaded.blob.arrayBuffer());
    assert.equal(downloadedText, secretPlaintextString);

    // Verify GET request was made to server
    const getReqs = capturedRequests.filter((r) => r.method === "GET");
    assert.equal(getReqs.length, 1);
    const getReq = getReqs[0];
    assert.ok(getReq);
    assert.equal(getReq.url, `https://sync.example.com/v1/blobs/${manifest.attachment_id}_0`);
  } finally {
    globalThis.fetch = originalFetch;
    client.dispose();
    await worker.terminate();
    await storage.deleteDatabase();
  }
});

test("AttachmentManager: Oversized file (>100 MiB) rejected immediately", async () => {
  const { client, worker } = createTestClient();
  const dbName = `test-att-oversized-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    await client.initVault("test-passphrase-oversized", TEST_KDF_PARAMS_JSON);
    const manager = new AttachmentManager(client, storage);

    const oversizedFile: AttachmentFileSource = {
      name: "huge-archive.iso",
      type: "application/x-iso9660-image",
      size: MAX_ATTACHMENT_SIZE + 1024,
      arrayBuffer: async () => new ArrayBuffer(0),
    };

    await assert.rejects(
      async () => {
        await manager.uploadAttachment(oversizedFile);
      },
      (err: any) => {
        return err.message && err.message.includes("exceeds maximum allowed size");
      }
    );
  } finally {
    client.dispose();
    await worker.terminate();
    await storage.deleteDatabase();
  }
});

test("AttachmentManager: Tampered chunk data fails closed on download (SEC-010)", async () => {
  const { client, worker } = createTestClient();
  const dbName = `test-att-tamper-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    await client.initVault("test-passphrase-tamper", TEST_KDF_PARAMS_JSON);
    const manager = new AttachmentManager(client, storage);

    const file = createMockFileSource("data.bin", "application/octet-stream", new Uint8Array([1, 2, 3, 4]));
    const manifest = await manager.uploadAttachment(file);

    // Tamper with local blob chunk
    const blobId = `${manifest.attachment_id}_0`;
    const originalBlob = await storage.getBlob(blobId);
    assert.ok(originalBlob);
    const tamperedBlob = new Uint8Array(originalBlob);
    const blobLastByte = tamperedBlob[tamperedBlob.length - 1];
    if (blobLastByte !== undefined) {
      tamperedBlob[tamperedBlob.length - 1] = blobLastByte ^ 0x55; // corrupt authentication tag
    }
    await storage.putBlob(blobId, tamperedBlob);

    // Attempting download must fail closed
    await assert.rejects(async () => {
      await manager.downloadAttachment(manifest.attachment_id);
    });
  } finally {
    client.dispose();
    await worker.terminate();
    await storage.deleteDatabase();
  }
});

test("threeWayMergeNotes: 3-way merging handles concurrent attachment additions", () => {
  const base: PlaintextNoteDto = {
    id: "note-att-1",
    title: "Title",
    body: "Body",
    tags: ["work"],
    attachments: ["att-base-1"],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };

  // Local adds att-local-2
  const local: PlaintextNoteDto = {
    ...base,
    attachments: ["att-base-1", "att-local-2"],
  };

  // Remote adds att-remote-3 and removes att-base-1
  const remote: PlaintextNoteDto = {
    ...base,
    attachments: ["att-remote-3"],
  };

  const res = threeWayMergeNotes(base, local, remote);
  assert.equal(res.isClean, true);
  // att-base-1 was deleted by remote -> absent
  // att-local-2 was added by local -> present
  // att-remote-3 was added by remote -> present
  assert.deepEqual(res.candidate.attachments, ["att-local-2", "att-remote-3"]);
});
