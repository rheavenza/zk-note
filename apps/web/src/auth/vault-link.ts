/**
 * Safe Authenticated Vault Linking and Restoration (ZK-105).
 *
 * Security Invariants:
 * - SEC-001 / SEC-002: Server receives only encrypted bootstrap envelope and allowed metadata.
 *   Passphrases, plaintext content, Vault Keys, and Recovery Keys are NEVER transmitted.
 * - SEC-003: No secrets in logs.
 * - SEC-006 / SEC-008: Non-destructive conflict safety: mismatched local/remote bootstrap,
 *   wrong-account state, or existing local vault stops with an explicit error.
 *   Automatic replacement or reinitialization NEVER occurs.
 * - SEC-007 / SEC-009: Idempotent retry safety and persistent local encryption.
 */

import { normalizeServerOrigin } from "./session.js";

export interface KdfParamsDto {
  algorithm: string;
  salt: string;
  memory_kib: number;
  iterations: number;
  parallelism: number;
}

export interface WrappedVaultKeyDto {
  cipher_suite: string;
  nonce: string;
  ciphertext: string;
}

export interface VaultBootstrapDto {
  crypto_version: number;
  kdf: KdfParamsDto;
  wrapped_vault_key: WrappedVaultKeyDto;
  recovery_wrapped_vault_key: WrappedVaultKeyDto;
}

export interface VaultBootstrapData {
  wrappedVaultKey: string;
  kdfParamsJson: string;
  wrappedRecoveryKey: string;
}

export interface VaultLinkRecord {
  accountId: string;
  serverOrigin: string;
  linkedAt: string;
}

export const VAULT_LINK_STORAGE_KEY = "zk_vault_link";

export class VaultLinkError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = "VaultLinkError";
  }
}

export class WrongAccountError extends VaultLinkError {
  constructor(public readonly linkedAccountId: string, public readonly currentAccountId: string) {
    super(
      `This vault is already linked to account '${linkedAccountId}'. Current account is '${currentAccountId}'. Sign in to the linked account to access this vault.`,
      "WRONG_ACCOUNT"
    );
    this.name = "WrongAccountError";
  }
}

export class OriginMismatchError extends VaultLinkError {
  constructor(public readonly linkedOrigin: string, public readonly currentOrigin: string) {
    super(
      `This vault is already linked to server '${linkedOrigin}'. Current server is '${currentOrigin}'. Switch to the linked server to access this vault.`,
      "ORIGIN_MISMATCH"
    );
    this.name = "OriginMismatchError";
  }
}

export class MismatchedVaultError extends VaultLinkError {
  constructor(message?: string) {
    super(
      message ||
        "The server account already contains a different vault bootstrap. Linking blocked to prevent overwriting existing notes.",
      "MISMATCHED_VAULT"
    );
    this.name = "MismatchedVaultError";
  }
}

export class ExistingLocalVaultError extends VaultLinkError {
  constructor(message?: string) {
    super(
      message ||
        "A local vault already exists on this browser and differs from the remote vault. Restoring is blocked to prevent data loss. Export your local data or clear locally before restoring.",
      "EXISTING_LOCAL_VAULT"
    );
    this.name = "ExistingLocalVaultError";
  }
}

export class VaultAlreadyExistsError extends VaultLinkError {
  constructor(message?: string) {
    super(message || "Vault has already been initialized for this account.", "VAULT_ALREADY_EXISTS");
    this.name = "VaultAlreadyExistsError";
  }
}

/**
 * Recursively scans payload to guarantee SEC-001/SEC-002 compliance before transmission.
 */
export function assertNoPlaintextSecrets(value: unknown, path = ""): void {
  if (value === null || value === undefined) return;
  if (typeof value === "object") {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        assertNoPlaintextSecrets(value[i], `${path}[${i}]`);
      }
    } else {
      for (const [k, v] of Object.entries(value)) {
        const lower = k.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (
          lower === "passphrase" ||
          lower === "password" ||
          lower === "vaultpassphrase" ||
          lower === "vaultkey" ||
          lower === "masterkey" ||
          lower === "secret" ||
          lower === "plaintext" ||
          lower === "recoveryphrase" ||
          lower === "recoverykey"
        ) {
          throw new Error(
            `SEC-001/SEC-002 violation: forbidden key '${k}' at '${path}' must not be transmitted to the server.`
          );
        }
        assertNoPlaintextSecrets(v, `${path}.${k}`);
      }
    }
  }
}

/**
 * Converts local VaultBootstrapData into strongly typed VaultBootstrapDto.
 */
export function toVaultBootstrapDto(data: VaultBootstrapData): VaultBootstrapDto {
  const kdf =
    typeof data.kdfParamsJson === "string" ? JSON.parse(data.kdfParamsJson) : data.kdfParamsJson;
  const wrappedVault =
    typeof data.wrappedVaultKey === "string"
      ? JSON.parse(data.wrappedVaultKey)
      : data.wrappedVaultKey;
  const wrappedRec =
    typeof data.wrappedRecoveryKey === "string"
      ? JSON.parse(data.wrappedRecoveryKey)
      : data.wrappedRecoveryKey;

  const dto: VaultBootstrapDto = {
    crypto_version: 1,
    kdf: {
      algorithm: String(kdf.algorithm || "argon2id"),
      salt: String(kdf.salt),
      memory_kib: Number(kdf.memory_kib || kdf.memoryKib),
      iterations: Number(kdf.iterations),
      parallelism: Number(kdf.parallelism),
    },
    wrapped_vault_key: {
      cipher_suite: String(wrappedVault.cipher_suite || wrappedVault.cipherSuite || "xchacha20poly1305"),
      nonce: String(wrappedVault.nonce),
      ciphertext: String(wrappedVault.ciphertext),
    },
    recovery_wrapped_vault_key: {
      cipher_suite: String(wrappedRec.cipher_suite || wrappedRec.cipherSuite || "xchacha20poly1305"),
      nonce: String(wrappedRec.nonce),
      ciphertext: String(wrappedRec.ciphertext),
    },
  };

  assertNoPlaintextSecrets(dto);
  return dto;
}

/**
 * Converts VaultBootstrapDto into VaultBootstrapData format for local worker/storage.
 */
export function fromVaultBootstrapDto(dto: VaultBootstrapDto): VaultBootstrapData {
  if (!dto || typeof dto !== "object") {
    throw new Error("Invalid vault bootstrap response from server.");
  }
  if (dto.crypto_version !== 1) {
    throw new Error(`Unsupported crypto_version '${dto.crypto_version}', expected 1.`);
  }
  if (!dto.kdf || !dto.wrapped_vault_key || !dto.recovery_wrapped_vault_key) {
    throw new Error("Malformed vault bootstrap structure.");
  }

  assertNoPlaintextSecrets(dto);

  return {
    wrappedVaultKey: JSON.stringify(dto.wrapped_vault_key),
    kdfParamsJson: JSON.stringify(dto.kdf),
    wrappedRecoveryKey: JSON.stringify(dto.recovery_wrapped_vault_key),
  };
}

/**
 * Field-by-field equality comparison between two bootstrap records.
 */
export function areBootstrapsEqual(
  a: VaultBootstrapData | VaultBootstrapDto,
  b: VaultBootstrapData | VaultBootstrapDto
): boolean {
  try {
    const dtoA = "crypto_version" in a ? a : toVaultBootstrapDto(a);
    const dtoB = "crypto_version" in b ? b : toVaultBootstrapDto(b);

    return (
      dtoA.crypto_version === dtoB.crypto_version &&
      dtoA.kdf.algorithm === dtoB.kdf.algorithm &&
      dtoA.kdf.salt === dtoB.kdf.salt &&
      dtoA.kdf.memory_kib === dtoB.kdf.memory_kib &&
      dtoA.kdf.iterations === dtoB.kdf.iterations &&
      dtoA.kdf.parallelism === dtoB.kdf.parallelism &&
      dtoA.wrapped_vault_key.cipher_suite === dtoB.wrapped_vault_key.cipher_suite &&
      dtoA.wrapped_vault_key.nonce === dtoB.wrapped_vault_key.nonce &&
      dtoA.wrapped_vault_key.ciphertext === dtoB.wrapped_vault_key.ciphertext &&
      dtoA.recovery_wrapped_vault_key.cipher_suite === dtoB.recovery_wrapped_vault_key.cipher_suite &&
      dtoA.recovery_wrapped_vault_key.nonce === dtoB.recovery_wrapped_vault_key.nonce &&
      dtoA.recovery_wrapped_vault_key.ciphertext === dtoB.recovery_wrapped_vault_key.ciphertext
    );
  } catch {
    return false;
  }
}

/**
 * Reads the vault link association from local storage.
 */
export function readVaultLink(storage: Pick<Storage, "getItem">): VaultLinkRecord | null {
  try {
    const raw = storage.getItem(VAULT_LINK_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.accountId === "string" && typeof parsed.serverOrigin === "string") {
      return {
        accountId: parsed.accountId,
        serverOrigin: normalizeServerOrigin(parsed.serverOrigin),
        linkedAt: typeof parsed.linkedAt === "string" ? parsed.linkedAt : new Date().toISOString(),
      };
    }
  } catch {
    // Ignore storage parse errors
  }
  return null;
}

/**
 * Persists the vault link association in local storage without any plaintext secrets.
 */
export function writeVaultLink(
  storage: Pick<Storage, "setItem" | "removeItem">,
  link: VaultLinkRecord | null
): void {
  try {
    if (link) {
      assertNoPlaintextSecrets(link);
      storage.setItem(
        VAULT_LINK_STORAGE_KEY,
        JSON.stringify({
          accountId: link.accountId,
          serverOrigin: normalizeServerOrigin(link.serverOrigin),
          linkedAt: link.linkedAt || new Date().toISOString(),
        })
      );
    } else {
      storage.removeItem(VAULT_LINK_STORAGE_KEY);
    }
  } catch (err) {
    if (err instanceof VaultLinkError) throw err;
    throw new VaultLinkError(
      "Failed to persist vault link association to storage.",
      "STORAGE_ERROR"
    );
  }
}

/**
 * Clears the vault link association. Local encrypted vault remains untouched.
 */
export function clearVaultLink(storage: Pick<Storage, "removeItem">): void {
  try {
    storage.removeItem(VAULT_LINK_STORAGE_KEY);
  } catch (err) {
    if (err instanceof VaultLinkError) throw err;
    throw new VaultLinkError(
      "Failed to clear vault link association from storage.",
      "STORAGE_ERROR"
    );
  }
}

/**
 * Fetches vault bootstrap from GET /v1/vault/bootstrap.
 */
export async function fetchRemoteBootstrap(
  serverOrigin: string,
  token: string
): Promise<VaultBootstrapDto | null> {
  const origin = normalizeServerOrigin(serverOrigin);
  const res = await fetch(`${origin}/v1/vault/bootstrap`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (res.status === 404) {
    return null;
  }

  if (res.status === 401 || res.status === 403) {
    const err = await res.json().catch(() => ({}));
    throw new VaultLinkError(
      err.message || "Authentication expired or invalid. Please sign in again.",
      "UNAUTHORIZED"
    );
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new VaultLinkError(
      err.message || `Failed to fetch remote vault bootstrap (HTTP ${res.status}).`,
      err.code || "SERVER_ERROR"
    );
  }

  const data = await res.json();
  assertNoPlaintextSecrets(data);
  return data as VaultBootstrapDto;
}

/**
 * Uploads vault bootstrap via POST /v1/vault/bootstrap.
 */
export async function uploadRemoteBootstrap(
  serverOrigin: string,
  token: string,
  bootstrap: VaultBootstrapDto
): Promise<VaultBootstrapDto> {
  assertNoPlaintextSecrets(bootstrap);
  const origin = normalizeServerOrigin(serverOrigin);

  const res = await fetch(`${origin}/v1/vault/bootstrap`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(bootstrap),
  });

  if (res.status === 409) {
    const err = await res.json().catch(() => ({}));
    throw new VaultAlreadyExistsError(err.message || "Vault already exists on the server.");
  }

  if (res.status === 401 || res.status === 403) {
    const err = await res.json().catch(() => ({}));
    throw new VaultLinkError(
      err.message || "Authentication expired or invalid. Please sign in again.",
      "UNAUTHORIZED"
    );
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new VaultLinkError(
      err.message || `Failed to upload vault bootstrap (HTTP ${res.status}).`,
      err.code || "SERVER_ERROR"
    );
  }

  const created = await res.json();
  assertNoPlaintextSecrets(created);
  return created as VaultBootstrapDto;
}

export interface LinkVaultOptions {
  serverOrigin: string;
  token: string;
  accountId: string;
  localBootstrap: VaultBootstrapData;
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">;
}

/**
 * Safely links the existing local vault to the authenticated server account.
 * Honors idempotency on duplicate retry and stops non-destructively on mismatch or wrong account.
 */
export async function linkLocalVaultToAccount(
  options: LinkVaultOptions
): Promise<{ status: "linked"; link: VaultLinkRecord }> {
  const { serverOrigin, token, accountId, localBootstrap } = options;
  const storage =
    options.storage || (typeof window !== "undefined" ? window.localStorage : null);

  if (!storage) {
    throw new VaultLinkError("Storage is not available for vault linking.", "STORAGE_UNAVAILABLE");
  }

  const origin = normalizeServerOrigin(serverOrigin);

  // 1. Wrong-account and server origin mismatch checks
  const existingLink = readVaultLink(storage);
  if (existingLink) {
    if (normalizeServerOrigin(existingLink.serverOrigin) !== origin) {
      throw new OriginMismatchError(existingLink.serverOrigin, origin);
    }
    if (existingLink.accountId !== accountId) {
      throw new WrongAccountError(existingLink.accountId, accountId);
    }
  }

  // 2. Fetch remote bootstrap to inspect existing state
  const remote = await fetchRemoteBootstrap(origin, token);

  if (remote !== null) {
    // Remote already has a bootstrap. Check if identical.
    if (areBootstrapsEqual(localBootstrap, remote)) {
      const linkRecord: VaultLinkRecord = {
        accountId,
        serverOrigin: origin,
        linkedAt: new Date().toISOString(),
      };
      writeVaultLink(storage, linkRecord);
      return { status: "linked", link: linkRecord };
    } else {
      // Mismatch! Do not overwrite either side.
      throw new MismatchedVaultError();
    }
  }

  // 3. Remote has no bootstrap. Upload local bootstrap.
  const dto = toVaultBootstrapDto(localBootstrap);
  try {
    await uploadRemoteBootstrap(origin, token, dto);
    const linkRecord: VaultLinkRecord = {
      accountId,
      serverOrigin: origin,
      linkedAt: new Date().toISOString(),
    };
    writeVaultLink(storage, linkRecord);
    return { status: "linked", link: linkRecord };
  } catch (err) {
    if (err instanceof VaultAlreadyExistsError) {
      // Race condition or retry after lost response:
      // Re-fetch and check if remote matches local.
      const recheckedRemote = await fetchRemoteBootstrap(origin, token);
      if (recheckedRemote && areBootstrapsEqual(localBootstrap, recheckedRemote)) {
        const linkRecord: VaultLinkRecord = {
          accountId,
          serverOrigin: origin,
          linkedAt: new Date().toISOString(),
        };
        writeVaultLink(storage, linkRecord);
        return { status: "linked", link: linkRecord };
      } else {
        throw new MismatchedVaultError();
      }
    }
    throw err;
  }
}

export interface RestoreVaultOptions {
  serverOrigin: string;
  token: string;
  accountId: string;
  localBootstrap: VaultBootstrapData | null;
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">;
}

/**
 * Restores the remote encrypted vault bootstrap to the browser.
 * Fails closed and non-destructively if a differing local vault already exists,
 * or if the browser is already associated with a different account or server.
 */
export async function restoreVaultFromAccount(
  options: RestoreVaultOptions
): Promise<{ bootstrap: VaultBootstrapData; link: VaultLinkRecord }> {
  const { serverOrigin, token, accountId, localBootstrap } = options;
  const storage =
    options.storage ||
    (typeof window !== "undefined" ? window.localStorage : (typeof localStorage !== "undefined" ? localStorage : null));

  if (!storage) {
    throw new VaultLinkError("Storage is not available for vault restoration.", "STORAGE_UNAVAILABLE");
  }

  const origin = normalizeServerOrigin(serverOrigin);

  // 1. Wrong-account and origin-mismatch check on existing persisted link
  const existingLink = readVaultLink(storage);
  if (existingLink) {
    if (normalizeServerOrigin(existingLink.serverOrigin) !== origin) {
      throw new OriginMismatchError(existingLink.serverOrigin, origin);
    }
    if (existingLink.accountId !== accountId) {
      throw new WrongAccountError(existingLink.accountId, accountId);
    }
  }

  // 2. If local vault exists, check non-destructive rules
  if (localBootstrap) {
    const remote = await fetchRemoteBootstrap(origin, token);
    if (!remote) {
      throw new VaultLinkError(
        `No vault found on the server for account '${accountId}'.`,
        "OBJECT_NOT_FOUND"
      );
    }
    if (areBootstrapsEqual(localBootstrap, remote)) {
      const linkRecord: VaultLinkRecord = {
        accountId,
        serverOrigin: origin,
        linkedAt: new Date().toISOString(),
      };
      writeVaultLink(storage, linkRecord);
      return { bootstrap: localBootstrap, link: linkRecord };
    }
    // Differs! Refuse to overwrite local vault.
    throw new ExistingLocalVaultError();
  }

  // 3. Local vault is null (UNINITIALIZED). Fetch remote bootstrap.
  const remote = await fetchRemoteBootstrap(origin, token);
  if (!remote) {
    throw new VaultLinkError(
      `No vault found on the server for account '${accountId}'. Create a new vault locally instead.`,
      "OBJECT_NOT_FOUND"
    );
  }

  const restoredBootstrap = fromVaultBootstrapDto(remote);
  const linkRecord: VaultLinkRecord = {
    accountId,
    serverOrigin: origin,
    linkedAt: new Date().toISOString(),
  };

  writeVaultLink(storage, linkRecord);

  return { bootstrap: restoredBootstrap, link: linkRecord };
}
