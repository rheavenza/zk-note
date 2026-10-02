/**
 * ZK-107 acceptance F & G — lock/unlock and authentication expiry.
 *
 * The vault lock is a local key-material boundary, not an account boundary: the
 * persisted link keeps selecting the account-scoped encrypted database while a
 * session is expired, revoked, or replaced by a different account. Sync is only
 * enabled for the account that actually owns the link.
 *
 * Locked-pull mechanics (ciphertext persisted without decryption) are covered by
 * the shared-core suite in `test/sync-engine.test.tsx` ("locked-vault pull");
 * this file covers the browser-observable behavior around them.
 */

import { expect, test } from "@playwright/test";
import {
  accountTrigger,
  assertNoPlaintext,
  closeSyncPopover,
  createAccount,
  createNote,
  createVault,
  ensureUnlocked,
  expectStatus,
  linkVault,
  lockVault,
  mutationIds,
  openBrowser,
  openNote,
  openSyncPopover,
  readStore,
  scopedDatabaseName,
  signInWithPasskey,
  signOut,
  triggerSync,
  unlockVault,
} from "./helpers";

const NOTE_TITLE = "Locked Note";
const NOTE_BODY = "secret body text that must never persist in the clear";

test.describe("ZK-107 lock and authentication acceptance", () => {
  test("locking removes plaintext from the app and keeps ciphertext-only storage", async ({
    browser,
  }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");
    await createVault(page);
    await createNote(page, NOTE_TITLE, NOTE_BODY);
    await createAccount(page, "owner-lock");
    await linkVault(page);
    await ensureUnlocked(page);
    await triggerSync(page);
    await expectStatus(page, "synced");

    const scoped = (await scopedDatabaseName(page))!;
    await lockVault(page);

    // No decrypted note content remains in the rendered application.
    const renderedText = await page.locator("body").innerText();
    expect(renderedText).not.toContain(NOTE_TITLE);
    expect(renderedText).not.toContain(NOTE_BODY);

    // Persistent storage holds ciphertext only.
    const objects = await readStore(page, scoped, "objects");
    expect(objects.length).toBeGreaterThan(0);
    assertNoPlaintext(objects, [NOTE_TITLE, NOTE_BODY]);

    // Unlocking re-derives the key and decrypts the same notes again.
    await unlockVault(page);
    await expect(page.locator(".zk-note-item", { hasText: NOTE_TITLE })).toBeVisible();
    await openNote(page, NOTE_TITLE);
    await expect(page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      NOTE_BODY
    );

    await context.close();
  });

  test("signing in to a different account keeps the linked vault but disables sync", async ({
    browser,
  }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");
    await createVault(page);
    await createNote(page, "Owner One Note", "belongs to account one");
    const accountOne = await createAccount(page, "owner-one");
    await linkVault(page);
    await ensureUnlocked(page);
    await triggerSync(page);
    await expectStatus(page, "synced");
    const scoped = (await scopedDatabaseName(page))!;

    // Replace the session with a different account in the same browser.
    await signOut(page);
    const accountTwo = await createAccount(page, "owner-two");
    expect(accountTwo).not.toBe(accountOne);

    // The persisted vault link still owns the local vault and its database.
    await expectStatus(page, "sign in to sync");
    expect(await scopedDatabaseName(page)).toBe(scoped);
    await expect(page.locator(".zk-note-item", { hasText: "Owner One Note" })).toBeVisible();

    // A manual sync must fail closed rather than upload to the wrong account.
    await openSyncPopover(page);
    await page.locator(".zk-sync-now-button").click();
    await expectStatus(page, "error");
    await expect(page.getByTestId("sync-popover").getByRole("alert")).toContainText(
      "linked to"
    );
    await closeSyncPopover(page);

    // Nothing was uploaded under the wrong account: the local object set is intact.
    const objects = await readStore(page, scoped, "objects");
    expect(objects.filter((object) => !object.is_deleted).length).toBe(1);
    expect(await scopedDatabaseName(page)).toBe(scoped);

    await context.close();
  });

  test("an expired session keeps the linked vault and queued work; re-auth syncs it", async ({
    browser,
  }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");
    await createVault(page);
    await createAccount(page, "owner-expiry");
    await linkVault(page);
    await ensureUnlocked(page);
    await triggerSync(page);
    await expectStatus(page, "synced");

    const scoped = (await scopedDatabaseName(page))!;
    await createNote(page, "Pending Across Expiry", "queued before expiry");
    const queuedIds = await mutationIds(page, scoped);
    expect(queuedIds.length).toBeGreaterThan(0);

    // Expire the client session, then reload: the vault link is untouched.
    await page.evaluate(() => {
      const raw = sessionStorage.getItem("zk_auth_session_v2");
      if (!raw) throw new Error("expected a persisted session to expire");
      const parsed = JSON.parse(raw);
      parsed.session.expiresAt = new Date(Date.now() - 60_000).toISOString();
      sessionStorage.setItem("zk_auth_session_v2", JSON.stringify(parsed));
    });
    await page.reload();
    await ensureUnlocked(page);

    await expect(accountTrigger(page)).toContainText("Session expired");
    // The account-scoped database is still selected, and no work was lost.
    expect(await scopedDatabaseName(page)).toBe(scoped);
    await expectStatus(page, "sign in to sync");
    expect(await mutationIds(page, scoped)).toEqual(queuedIds);
    // Notes stay usable locally while the session is expired.
    await expect(page.locator(".zk-note-item", { hasText: "Pending Across Expiry" })).toBeVisible();

    // Re-authenticate: sync becomes possible again and drains the same queue.
    await signInWithPasskey(page);
    await expectStatus(page, "pending changes");
    await triggerSync(page);
    await expectStatus(page, "synced");
    expect(await mutationIds(page, scoped)).toEqual([]);

    await context.close();
  });
});
