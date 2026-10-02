/**
 * ZK-107 acceptance A — truthful sync UX.
 *
 * Proves that the browser never reports "synced" for local-only persistence or
 * for a merely-linked vault, and reaches "synced" only after a real
 * authenticated server round trip.
 */

import { expect, test } from "@playwright/test";
import {
  assertNoPlaintext,
  createAccount,
  createNote,
  createVault,
  ensureUnlocked,
  expectStatus,
  linkVault,
  openBrowser,
  openSyncPopover,
  readStore,
  scopedDatabaseName,
  signOut,
  triggerSync,
} from "./helpers";

const NOTE_TITLE = "Offline Note";
const NOTE_BODY = "written before any account existed";

test.describe("ZK-107 truthful synchronization state", () => {
  test("a local-only vault reports 'local only' and stores notes as ciphertext", async ({ browser }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");

    await createVault(page);
    await expectStatus(page, "local only");

    await createNote(page, NOTE_TITLE, NOTE_BODY);
    // Local persistence must NOT be presented as server synchronization.
    await expectStatus(page, "local only");

    const localObjects = await readStore(page, "zk_notes_db", "objects");
    expect(localObjects.length).toBeGreaterThan(0);
    assertNoPlaintext(localObjects, [NOTE_TITLE, NOTE_BODY]);

    await context.close();
  });

  test("linked vault progresses not-synced-yet -> pending changes -> synced", async ({ browser }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");

    // Link BEFORE creating notes so the "no round trip yet" state is observable.
    await createVault(page);
    await createAccount(page);
    await linkVault(page);
    await ensureUnlocked(page);

    // Linked + authenticated with no pending work: truthful "not synced yet".
    await expectStatus(page, "not synced yet");

    await createNote(page, NOTE_TITLE, NOTE_BODY);
    await expectStatus(page, "pending changes");

    await triggerSync(page);
    await expectStatus(page, "synced");

    // The note now lives in the account-scoped database, still ciphertext-only.
    const scoped = await scopedDatabaseName(page);
    expect(scoped, "account-scoped database should exist after linking").toBeTruthy();
    const scopedObjects = await readStore(page, scoped!, "objects");
    expect(scopedObjects.length).toBeGreaterThan(0);
    assertNoPlaintext(scopedObjects, [NOTE_TITLE, NOTE_BODY]);

    await context.close();
  });

  test("signing out keeps linked local notes but disables sync", async ({ browser }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");

    await createVault(page);
    const accountId = await createAccount(page);
    expect(accountId).toMatch(/^[0-9a-f-]{36}$/);

    await linkVault(page);
    await ensureUnlocked(page);
    await triggerSync(page);
    await expectStatus(page, "synced");

    await createNote(page, "Pending While Signed Out", "queued while still signed in");

    // Signing out must not hide or delete local encrypted notes, and must not
    // pretend synchronization is still possible.
    await signOut(page);
    await expectStatus(page, "sign in to sync");

    await openSyncPopover(page);
    const explanation = page.getByTestId("sync-status-explanation");
    await expect(explanation).toContainText("waiting to upload");

    // Notes remain readable locally while signed out.
    await expect(page.locator(".zk-note-item", { hasText: "Pending While Signed Out" })).toBeVisible();

    await context.close();
  });
});
