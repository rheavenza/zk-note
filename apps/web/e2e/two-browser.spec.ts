/**
 * ZK-107 acceptance B & C — link / restore and the real two-browser journey.
 *
 * Two isolated browser contexts (separate IndexedDB + localStorage) share one
 * account through the same virtual passkey, exactly like a passkey synced to a
 * second device. All assertions go through the real UI; storage is inspected
 * read-only to prove ciphertext-only persistence.
 */

import { expect, test } from "@playwright/test";
import {
  assertNoPlaintext,
  createAccount,
  createNote,
  createVault,
  deleteCurrentNote,
  ensureUnlocked,
  expectStatus,
  fillNote,
  linkVault,
  openAccountPanel,
  openBrowser,
  openNote,
  readStore,
  restoreVault,
  scopedDatabaseName,
  signInWithPasskey,
  triggerSync,
  unlockVault,
} from "./helpers";

const BODY_FROM_A = "body from browser A";
const BODY_FROM_B = "edited on browser B";
const BODY_FROM_A_AGAIN = "edited on browser A afterwards";
const NOTE_TITLE = "Shared Note";

test.describe("ZK-107 two-browser synchronization", () => {
  test("restore on a second browser, then edits and deletions converge", async ({ browser }) => {
    // ---- Browser A: local-only note, then link + first upload ----
    const a = await openBrowser(browser);
    await a.page.goto("/");
    await createVault(a.page);
    await createNote(a.page, NOTE_TITLE, BODY_FROM_A);
    await createAccount(a.page, "owner-a");
    await linkVault(a.page);
    await ensureUnlocked(a.page);
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");

    const credentials = await a.authenticator.exportCredentials();
    expect(credentials.length).toBe(1);

    // ---- Browser B: fresh storage, same account, restore from account ----
    const b = await openBrowser(browser, credentials);
    await b.page.goto("/");
    await signInWithPasskey(b.page);
    await restoreVault(b.page);
    await unlockVault(b.page);
    await triggerSync(b.page);
    await expectStatus(b.page, "synced");

    // The note is readable only after local decryption of the pulled ciphertext.
    await expect(b.page.locator(".zk-note-item", { hasText: NOTE_TITLE })).toBeVisible({
      timeout: 30_000,
    });
    await openNote(b.page, NOTE_TITLE);
    await expect(b.page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      BODY_FROM_A
    );

    // ---- B edits -> sync -> A sync -> converges ----
    await fillNote(b.page, NOTE_TITLE, BODY_FROM_B);
    await triggerSync(b.page);
    await expectStatus(b.page, "synced");

    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await expect(a.page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      BODY_FROM_B,
      { timeout: 30_000 }
    );

    // ---- A edits -> sync -> B sync -> converges ----
    await fillNote(a.page, NOTE_TITLE, BODY_FROM_A_AGAIN);
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");

    await triggerSync(b.page);
    await expectStatus(b.page, "synced");
    await expect(b.page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      BODY_FROM_A_AGAIN,
      { timeout: 30_000 }
    );

    // ---- Deletion converges as a tombstone and is not resurrected ----
    await deleteCurrentNote(b.page, NOTE_TITLE);
    await triggerSync(b.page);
    await expectStatus(b.page, "synced");

    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await expect(a.page.locator(".zk-note-item", { hasText: NOTE_TITLE })).toHaveCount(0, {
      timeout: 30_000,
    });

    // A subsequent round trip on the browser that deleted it must not bring it back.
    await triggerSync(b.page);
    await triggerSync(a.page);
    await expect(a.page.locator(".zk-note-item", { hasText: NOTE_TITLE })).toHaveCount(0);
    await expect(b.page.locator(".zk-note-item", { hasText: NOTE_TITLE })).toHaveCount(0);

    // Server-side state (via A's local ciphertext cache) never contains plaintext.
    const scoped = await scopedDatabaseName(a.page);
    expect(scoped).toBeTruthy();
    const objects = await readStore(a.page, scoped!, "objects");
    assertNoPlaintext(objects, [NOTE_TITLE, BODY_FROM_A, BODY_FROM_B, BODY_FROM_A_AGAIN]);

    await a.context.close();
    await b.context.close();
  });

  test("a differing local vault is never silently overwritten by the account vault", async ({
    browser,
  }) => {
    // Browser A establishes the account vault.
    const a = await openBrowser(browser);
    await a.page.goto("/");
    await createVault(a.page);
    await createAccount(a.page, "owner-a");
    await linkVault(a.page);
    await ensureUnlocked(a.page);
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    const credentials = await a.authenticator.exportCredentials();

    // Browser B has its own, unrelated local vault with real local content.
    const b = await openBrowser(browser, credentials);
    await b.page.goto("/");
    await createVault(b.page, "an entirely different local passphrase");
    await createNote(b.page, "B Only Note", "belongs to browser B");

    await signInWithPasskey(b.page);
    await openAccountPanel(b.page);
    await b.page.locator(".zk-link-vault-button").click();

    // Explicit, non-destructive refusal: B's vault is preserved.
    await expect(b.page.getByText(/different vault bootstrap/i)).toBeVisible({ timeout: 30_000 });
    await expect(b.page.locator(".zk-note-item", { hasText: "B Only Note" })).toBeVisible();

    await a.context.close();
    await b.context.close();
  });
});
