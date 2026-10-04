/**
 * Browser-driving helpers for the ZK-107 acceptance suite.
 *
 * Everything here interacts through real user-visible controls. The only
 * low-level escape hatches are (a) Chromium's WebAuthn virtual authenticator
 * (a platform passkey stand-in) and (b) read-only IndexedDB inspection used to
 * prove that only ciphertext is persisted.
 */

import { expect, type Browser, type BrowserContext, type CDPSession, type Page } from "@playwright/test";

export const PASSKEY_USER = "e2e-owner";
export const VAULT_PASSPHRASE = "correct horse battery staple e2e";

// ---------------------------------------------------------------------------
// Virtual WebAuthn authenticator (two "devices" share one passkey, like a
// passkey synced through a platform keychain).
// ---------------------------------------------------------------------------

export interface ExportedCredential {
  credentialId: string;
  isResidentCredential: boolean;
  rpId: string;
  privateKey: string;
  userHandle: string;
  signCount: number;
}

export class VirtualAuthenticator {
  constructor(
    private readonly client: CDPSession,
    public readonly authenticatorId: string
  ) {}

  async exportCredentials(): Promise<ExportedCredential[]> {
    const { credentials } = (await this.client.send("WebAuthn.getCredentials", {
      authenticatorId: this.authenticatorId,
    })) as { credentials: ExportedCredential[] };
    return credentials;
  }

  async importCredentials(credentials: ExportedCredential[]): Promise<void> {
    for (const credential of credentials) {
      await this.client.send("WebAuthn.addCredential", {
        authenticatorId: this.authenticatorId,
        credential: {
          credentialId: credential.credentialId,
          isResidentCredential: true,
          rpId: credential.rpId,
          privateKey: credential.privateKey,
          userHandle: credential.userHandle,
          signCount: credential.signCount,
        },
      });
    }
  }
}

export interface BrowserHandle {
  context: BrowserContext;
  page: Page;
  authenticator: VirtualAuthenticator;
}

/**
 * Opens an isolated browser context (its own IndexedDB + localStorage) with a
 * virtual platform authenticator attached. Pass another handle's credentials to
 * model "the same passkey available on a second device".
 */
export async function openBrowser(
  browser: Browser,
  sharedCredentials?: ExportedCredential[]
): Promise<BrowserHandle> {
  const context = await browser.newContext({
    // Matches playwright.config.ts: only needed in the opt-in HTTPS mode, where
    // the origin is served with a throwaway self-signed certificate.
    ignoreHTTPSErrors: process.env.ZK_E2E_HTTPS === "1",
  });
  const page = await context.newPage();
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = (await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })) as { authenticatorId: string };
  const authenticator = new VirtualAuthenticator(client, authenticatorId);
  if (sharedCredentials) await authenticator.importCredentials(sharedCredentials);
  return { context, page, authenticator };
}

// ---------------------------------------------------------------------------
// Account controls
// ---------------------------------------------------------------------------

const ACCOUNT_TRIGGER = 'button[aria-label="Account and server authentication"]';

export function accountTrigger(page: Page) {
  return page.locator(ACCOUNT_TRIGGER);
}

export async function openAccountPanel(page: Page): Promise<void> {
  const panel = page.getByRole("group", { name: "Account authentication" });
  if (!(await panel.isVisible().catch(() => false))) {
    await accountTrigger(page).click();
  }
  await expect(panel).toBeVisible();
}

export async function closeAccountPanel(page: Page): Promise<void> {
  const panel = page.getByRole("group", { name: "Account authentication" });
  if (await panel.isVisible().catch(() => false)) {
    await accountTrigger(page).click();
  }
}

/** Registers a brand-new account with a passkey and returns its account id. */
export async function createAccount(page: Page, username = PASSKEY_USER): Promise<string> {
  await openAccountPanel(page);
  await page.locator('input[autocomplete="username"]').fill(username);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(accountTrigger(page)).toContainText("Signed in", { timeout: 45_000 });
  return readAccountId(page);
}

/** Signs in with the discoverable credential already on this authenticator. */
export async function signInWithPasskey(page: Page): Promise<string> {
  await openAccountPanel(page);
  await page.getByRole("button", { name: "Sign in with passkey" }).click();
  await expect(accountTrigger(page)).toContainText("Signed in", { timeout: 45_000 });
  return readAccountId(page);
}

export async function signOut(page: Page): Promise<void> {
  await openAccountPanel(page);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(accountTrigger(page)).toContainText("not signed in", { timeout: 30_000 });
}

export async function readAccountId(page: Page): Promise<string> {
  const text = await accountTrigger(page).innerText();
  const match = text.match(/\(([^)]+)\)/);
  if (!match) throw new Error(`Could not read account id from "${text}"`);
  return match[1]!;
}

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

export async function createVault(page: Page, passphrase = VAULT_PASSPHRASE): Promise<void> {
  await closeAccountPanel(page);
  await page.locator("#create-passphrase").fill(passphrase);
  await page.locator("#confirm-passphrase").fill(passphrase);
  await page.getByRole("button", { name: "Create Vault" }).click();
  await expect(page.getByText("Save Your Recovery Key")).toBeVisible({ timeout: 60_000 });
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Enter Vault" }).click();
  await expect(page.getByRole("button", { name: "+ New Note" })).toBeVisible({ timeout: 60_000 });
}

export async function unlockVault(page: Page, passphrase = VAULT_PASSPHRASE): Promise<void> {
  await page.locator("#unlock-passphrase").fill(passphrase);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.getByRole("button", { name: "+ New Note" })).toBeVisible({ timeout: 60_000 });
}

/** Unlocks only if the vault is currently locked (identity switches re-lock it). */
export async function ensureUnlocked(page: Page, passphrase = VAULT_PASSPHRASE): Promise<void> {
  if (await page.locator("#unlock-passphrase").isVisible().catch(() => false)) {
    await unlockVault(page, passphrase);
  }
}

export async function lockVault(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Lock vault" }).click();
  await expect(page.locator("#unlock-passphrase")).toBeVisible({ timeout: 30_000 });
}

/**
 * Links the local vault to the signed-in account (explicit user action).
 *
 * Persisting the link switches the app to the account-scoped database, which
 * remounts the vault provider and re-locks the vault, so we wait for that
 * observable transition instead of the transient confirmation message.
 */
export async function linkVault(page: Page): Promise<void> {
  await openAccountPanel(page);
  await page.locator(".zk-link-vault-button").click();
  await expect(
    page.locator("#unlock-passphrase").or(page.getByText("Vault successfully linked to this account."))
  ).toBeVisible({ timeout: 60_000 });
}

/** Restores the encrypted remote vault bootstrap into a fresh browser. */
export async function restoreVault(page: Page): Promise<void> {
  const button = page.locator(".zk-restore-vault-button").first();
  await expect(button).toBeVisible({ timeout: 30_000 });
  await button.click();
  // A successful restore persists the bootstrap and moves the app to LOCKED.
  await expect(page.locator("#unlock-passphrase")).toBeVisible({ timeout: 60_000 });
}

// ---------------------------------------------------------------------------
// Sync status + notes
// ---------------------------------------------------------------------------

export function statusBadge(page: Page) {
  return page.getByTestId("sync-status-badge");
}

export async function statusLabel(page: Page): Promise<string> {
  return (await page.locator(".zk-sync-label").innerText()).trim();
}

export async function expectStatus(page: Page, expected: string): Promise<void> {
  await expect(page.locator(".zk-sync-label")).toHaveText(expected, { timeout: 60_000 });
}

/** Opens the sync popover. */
export async function openSyncPopover(page: Page): Promise<void> {
  const popover = page.getByTestId("sync-popover");
  if (!(await popover.isVisible().catch(() => false))) {
    await statusBadge(page).click();
  }
  await expect(popover).toBeVisible();
}

export async function closeSyncPopover(page: Page): Promise<void> {
  const popover = page.getByTestId("sync-popover");
  if (await popover.isVisible().catch(() => false)) {
    await popover.getByRole("button", { name: "Close" }).click();
  }
}

/** Clicks Sync Now and waits for the round trip to leave the "syncing" state. */
export async function triggerSync(page: Page): Promise<void> {
  await openSyncPopover(page);
  await page.locator(".zk-sync-now-button").click();
  await expect(page.locator(".zk-sync-label")).not.toHaveText("syncing", { timeout: 90_000 });
  await closeSyncPopover(page);
}

/**
 * Opens the conflict resolver from the sync popover. The conflict store is
 * poll-based, so this retries until the freshly recorded conflict is visible.
 */
export async function openConflictResolverFromSync(page: Page): Promise<void> {
  await expect(async () => {
    await openSyncPopover(page);
    await page.getByTestId("resolve-conflicts-popover-button").click();
    await expect(page.getByText(/Resolve Synchronization Conflict/)).toBeVisible({
      timeout: 1_500,
    });
  }).toPass({ timeout: 30_000 });
}

export async function createNote(page: Page, title: string, body: string): Promise<void> {
  await page.getByRole("button", { name: "+ New Note" }).click();
  await fillNote(page, title, body);
}

/** Fills the currently selected note's title/body and waits for the local save. */
export async function fillNote(page: Page, title: string, body: string): Promise<void> {
  await page.locator('input[aria-label="Note title"]').fill(title);
  await page.locator('textarea[aria-label="Markdown source content"]').fill(body);
  await expect(page.locator(".zk-save-status")).toContainText("Saved locally", { timeout: 30_000 });
}

/** Edits only the body, producing exactly one queued mutation. */
export async function fillBody(page: Page, body: string): Promise<void> {
  await page.locator('textarea[aria-label="Markdown source content"]').fill(body);
  await expect(page.locator(".zk-save-status")).toContainText("Saved locally", { timeout: 30_000 });
}

export function noteItems(page: Page) {
  return page.locator(".zk-note-item");
}

/** Note row whose visible title matches exactly (avoids "X" also matching "X (Local Copy)"). */
export function noteItem(page: Page, title: string) {
  const escaped = title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return page
    .locator(".zk-note-item")
    .filter({ has: page.locator("h4", { hasText: new RegExp(`^${escaped}$`) }) });
}

export async function openNote(page: Page, title: string): Promise<void> {
  await page.locator(".zk-note-item", { hasText: title }).first().click();
  await expect(page.locator('input[aria-label="Note title"]')).toHaveValue(title);
}

export async function deleteCurrentNote(page: Page, title: string): Promise<void> {
  await page.locator(".zk-delete-note-btn").click();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.locator(".zk-note-item", { hasText: title })).toHaveCount(0, { timeout: 30_000 });
}

export async function noteTitles(page: Page): Promise<string[]> {
  return page
    .locator(".zk-note-item")
    .evaluateAll((nodes) => nodes.map((n) => (n.querySelector("h4")?.textContent || "").trim()));
}

// ---------------------------------------------------------------------------
// IndexedDB inspection (read-only; used to prove ciphertext-only persistence)
// ---------------------------------------------------------------------------

export async function listDatabases(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    const entries = await indexedDB.databases();
    return entries.map((entry) => entry.name).filter((name): name is string => Boolean(name));
  });
}

/** The account-scoped database created once a vault is linked. */
export async function scopedDatabaseName(page: Page): Promise<string | undefined> {
  const names = await listDatabases(page);
  return names.find((name) => name.startsWith("zk_notes_db_"));
}

export async function readStore(page: Page, dbName: string, store: string): Promise<any[]> {
  return page.evaluate(
    ([db, storeName]) =>
      new Promise<any[]>((resolve, reject) => {
        const open = indexedDB.open(db as string);
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const database = open.result;
          if (!database.objectStoreNames.contains(storeName as string)) {
            database.close();
            resolve([]);
            return;
          }
          const tx = database.transaction(storeName as string, "readonly");
          const all = tx.objectStore(storeName as string).getAll();
          all.onsuccess = () => {
            const result = all.result;
            database.close();
            resolve(result);
          };
          all.onerror = () => {
            const error = all.error;
            database.close();
            reject(error);
          };
        };
      }),
    [dbName, store] as const
  );
}

/** The durable `last_sync_at` recorded for the account-scoped database. */
export async function lastSyncAt(page: Page, scoped: string): Promise<string | null> {
  const rows = await readStore(page, scoped, "sync_state");
  return (rows[0]?.state?.last_sync_at as string | undefined) ?? null;
}

/** Sorted ids of the durable pending mutation queue. */
export async function mutationIds(page: Page, scoped: string): Promise<string[]> {
  const rows = await readStore(page, scoped, "mutations");
  return rows.map((row) => row.mutation_id as string).sort();
}

/** Revisions of every non-deleted stored object. */
export async function liveRevisions(page: Page, scoped: string): Promise<number[]> {
  const rows = await readStore(page, scoped, "objects");
  return rows.filter((row) => !row.is_deleted).map((row) => row.revision as number);
}

/**
 * Collects the raw bodies of every request the page sends to `/v1`, so tests can
 * assert that no plaintext ever left the browser (SEC-001).
 */
export function recordApiPayloads(page: Page): string[] {
  const payloads: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/v1/") && request.method() !== "GET") {
      payloads.push(request.postData() ?? "");
    }
  });
  return payloads;
}

/**
 * Asserts that none of the given secrets appear anywhere in the serialized
 * records (SEC-001/SEC-009: persistent local storage stays ciphertext).
 */
export function assertNoPlaintext(records: unknown[], secrets: string[]): void {
  const serialized = JSON.stringify(records);
  for (const secret of secrets) {
    expect(serialized, `plaintext leak of "${secret.slice(0, 24)}..." into local storage`).not.toContain(
      secret
    );
  }
}
