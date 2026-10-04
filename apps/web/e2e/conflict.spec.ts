/**
 * ZK-107 acceptance E — conflict preservation and recovery.
 *
 * Two isolated browser contexts share one account. Edits are made offline on
 * both sides and then synchronized in a conflicting order. The losing side must
 * receive an actionable, persisted conflict — never a silent overwrite and never
 * a resurrected tombstone.
 */

import { expect, test } from "@playwright/test";
import {
  createAccount,
  createNote,
  createVault,
  deleteCurrentNote,
  ensureUnlocked,
  expectStatus,
  fillBody,
  linkVault,
  lockVault,
  noteItem,
  openBrowser,
  openConflictResolverFromSync,
  openNote,
  openSyncPopover,
  readStore,
  recordApiPayloads,
  restoreVault,
  scopedDatabaseName,
  signInWithPasskey,
  triggerSync,
  unlockVault,
} from "./helpers";

const TITLE = "Conflict Note";
const BASE_BODY = "shared base body";
const LOCAL_BODY_B = "local edit made on browser B";

async function seedTwoBrowsers(browser: import("@playwright/test").Browser) {
  const a = await openBrowser(browser);
  await a.page.goto("/");
  await createVault(a.page);
  await createNote(a.page, TITLE, BASE_BODY);
  await createAccount(a.page, "owner-conflict");
  await linkVault(a.page);
  await ensureUnlocked(a.page);
  await triggerSync(a.page);
  await expectStatus(a.page, "synced");

  const credentials = await a.authenticator.exportCredentials();
  const b = await openBrowser(browser, credentials);
  await b.page.goto("/");
  await signInWithPasskey(b.page);
  await restoreVault(b.page);
  await unlockVault(b.page);
  await triggerSync(b.page);
  await expectStatus(b.page, "synced");
  await expect(b.page.locator(".zk-note-item", { hasText: TITLE })).toBeVisible({ timeout: 30_000 });

  return { a, b };
}

test.describe("ZK-107 conflict acceptance", () => {
  test("a stale offline edit surfaces an actionable conflict that survives reload and relock", async ({
    browser,
  }) => {
    const { a, b } = await seedTwoBrowsers(browser);
    // Capture everything B sends to the server to prove nothing plaintext leaves.
    const bPayloads = recordApiPayloads(b.page);

    await a.context.setOffline(true);
    await b.context.setOffline(true);
    await expectStatus(a.page, "offline");
    await expectStatus(b.page, "offline");

    // Both sides edit the same revision while disconnected.
    await openNote(a.page, TITLE);
    await fillBody(a.page, "A local edit");
    await openNote(b.page, TITLE);
    await fillBody(b.page, LOCAL_BODY_B);

    // A reconnects and wins the race.
    await a.context.setOffline(false);
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");

    // B reconnects, pushes against a stale revision, and must be told.
    await b.context.setOffline(false);
    await triggerSync(b.page);
    await expectStatus(b.page, "conflict");
    await expect(b.page.getByTestId("note-conflict-badge").first()).toBeVisible();

    // The conflict is actionable and B's own edit is recoverable.
    await b.page.locator(".zk-note-item", { hasText: TITLE }).click();
    await b.page.getByTestId("resolve-conflict-banner-button").click();
    await expect(b.page.getByText(/Resolve Synchronization Conflict/)).toBeVisible();
    await expect(b.page.getByText("Local Version (Your edits)")).toBeVisible();
    await expect(b.page.locator("body")).toContainText(LOCAL_BODY_B);

    // Close without resolving: the conflict must remain until explicitly resolved.
    await b.page.getByRole("button", { name: "Cancel" }).click();
    await expectStatus(b.page, "conflict");

    // Survives a full reload.
    await b.page.reload();
    await ensureUnlocked(b.page);
    await expectStatus(b.page, "conflict");

    // Survives lock / unlock.
    await lockVault(b.page);
    await unlockVault(b.page);
    await expectStatus(b.page, "conflict");

    // SEC-001: nothing plaintext was ever sent to the server for this conflict.
    const leaked = bPayloads.filter(
      (payload) => payload.includes(LOCAL_BODY_B) || payload.includes(TITLE) || payload.includes(BASE_BODY)
    );
    expect(leaked).toEqual([]);

    await a.context.close();
    await b.context.close();
  });

  test("delete-versus-edit is not silently resurrected and stays recoverable", async ({ browser }) => {
    const { a, b } = await seedTwoBrowsers(browser);

    await a.context.setOffline(true);
    await b.context.setOffline(true);

    // A deletes while disconnected; B edits the same revision.
    await openNote(a.page, TITLE);
    await deleteCurrentNote(a.page, TITLE);
    await openNote(b.page, TITLE);
    await fillBody(b.page, LOCAL_BODY_B);

    // A's deletion is synchronized first and becomes a tombstone.
    await a.context.setOffline(false);
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await expect(a.page.locator(".zk-note-item", { hasText: TITLE })).toHaveCount(0);

    // B's stale edit must conflict rather than resurrect the note. The tombstone
    // wins locally, so the conflict is surfaced through the sync status control.
    await b.context.setOffline(false);
    await triggerSync(b.page);
    await expectStatus(b.page, "conflict");
    await expect(b.page.locator(".zk-note-item", { hasText: TITLE })).toHaveCount(0);

    // B's local edit is still recoverable from the conflict record.
    await openConflictResolverFromSync(b.page);
    await expect(b.page.getByText("Local Version (Your edits)")).toBeVisible();
    await expect(b.page.locator("body")).toContainText(LOCAL_BODY_B);
    await b.page.getByRole("button", { name: "Cancel" }).click();

    // A subsequent round trip from B must not resurrect the deleted note anywhere.
    await triggerSync(b.page);
    await expectStatus(b.page, "conflict");
    await triggerSync(a.page);
    await expect(a.page.locator(".zk-note-item", { hasText: TITLE })).toHaveCount(0);
    await triggerSync(b.page);
    await expect(a.page.locator(".zk-note-item", { hasText: TITLE })).toHaveCount(0);

    await a.context.close();
    await b.context.close();
  });

  test("an edit that races an incoming pull conflicts instead of overwriting it", async ({
    browser,
  }) => {
    const { a, b } = await seedTwoBrowsers(browser);
    const scoped = (await scopedDatabaseName(b.page))!;

    // A edits and synchronizes first, advancing the server past B's local base.
    await openNote(a.page, TITLE);
    await fillBody(a.page, "A wins the race");
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");

    const before = await readStore(b.page, scoped, "objects");
    const baseRevision = before.find((object) => !object.is_deleted)?.revision as number;
    expect(baseRevision).toBeGreaterThanOrEqual(1);

    // Freeze B's page timers so the 600 ms autosave cannot fire on its own. This
    // makes the race exact: the edit is made first and stays dirty across the
    // whole sync, then the autosave flushes after the pull has stored revision 2.
    await b.page.clock.install();
    await openNote(b.page, TITLE);
    // Edit first: with timers frozen the debounce cannot fire, so the edit stays
    // dirty across the whole sync that follows.
    await b.page
      .locator('textarea[aria-label="Markdown source content"]')
      .fill("B edit racing the pull");
    await openSyncPopover(b.page);

    const pullCompleted = b.page.waitForResponse(
      (response) => response.url().includes("/v1/sync/pull") && response.status() === 200
    );
    await b.page.locator(".zk-sync-now-button").click();
    await pullCompleted;
    // Real time (Playwright-side) so the round trip and its post-sync reload
    // settle; the frozen debounce still cannot have fired.
    await b.page.waitForTimeout(1_500);

    const dirty = await readStore(b.page, scoped, "objects");
    expect(
      dirty.find((object) => !object.is_deleted)?.revision,
      "the pull must have landed while the edit was still unsaved"
    ).toBe(baseRevision + 1);

    // Now let the autosave flush.
    await b.page.clock.fastForward(1_000);
    await expect(b.page.locator(".zk-save-status")).toContainText("Saved locally", {
      timeout: 20_000,
    });

    // The queued mutation must keep the pre-pull base, so its push conflicts
    // rather than silently overwriting A's edit (SEC-006).
    const queued = await readStore(b.page, scoped, "mutations");
    const upsert = queued.filter((m) => m.object_id === before[0]?.object_id).at(-1);
    expect(upsert, "the racing edit must be queued").toBeTruthy();
    expect(upsert!.expected_revision).toBe(baseRevision);

    await triggerSync(b.page);
    await expectStatus(b.page, "conflict");

    // A's remote edit survives: a later pull from A still shows A's text.
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await openNote(a.page, TITLE);
    await expect(a.page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      "A wins the race"
    );

    await a.context.close();
    await b.context.close();
  });

  test("resolving with Keep Local pushes the local edit and converges", async ({ browser }) => {
    const { a, b } = await seedTwoBrowsers(browser);

    await a.context.setOffline(true);
    await b.context.setOffline(true);
    await openNote(a.page, TITLE);
    await fillBody(a.page, "A edit");
    await openNote(b.page, TITLE);
    await fillBody(b.page, LOCAL_BODY_B);

    await a.context.setOffline(false);
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await b.context.setOffline(false);
    await triggerSync(b.page);
    await expectStatus(b.page, "conflict");

    // Explicitly resolve in favour of B's local edit.
    await openConflictResolverFromSync(b.page);
    await b.page.getByRole("button", { name: "Keep Local Version" }).click();

    // Resolution queues a mutation; the badge must not claim synced yet.
    await expectStatus(b.page, "pending changes");
    await expect(b.page.getByTestId("note-conflict-badge")).toHaveCount(0);

    await triggerSync(b.page);
    await expectStatus(b.page, "synced");

    // The resolution converges onto A.
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await expect(a.page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      LOCAL_BODY_B,
      { timeout: 30_000 }
    );

    await a.context.close();
    await b.context.close();
  });

  test("resolving with Preserve Both keeps the remote note and duplicates the local edit", async ({
    browser,
  }) => {
    const { a, b } = await seedTwoBrowsers(browser);

    await a.context.setOffline(true);
    await b.context.setOffline(true);
    await openNote(a.page, TITLE);
    await fillBody(a.page, "A edit");
    await openNote(b.page, TITLE);
    await fillBody(b.page, LOCAL_BODY_B);

    await a.context.setOffline(false);
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await b.context.setOffline(false);
    await triggerSync(b.page);
    await expectStatus(b.page, "conflict");

    await openConflictResolverFromSync(b.page);
    await b.page.getByRole("button", { name: /Preserve Both/ }).click();
    await expectStatus(b.page, "pending changes");

    await triggerSync(b.page);
    await expectStatus(b.page, "synced");
    await expect(noteItem(b.page, `${TITLE} (Local Copy)`)).toBeVisible();

    // The duplicate converges onto A, and the original keeps A's remote version.
    await triggerSync(a.page);
    await expectStatus(a.page, "synced");
    await expect(noteItem(a.page, `${TITLE} (Local Copy)`)).toBeVisible({ timeout: 30_000 });
    await noteItem(a.page, TITLE).click();
    await expect(a.page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      "A edit"
    );
    await noteItem(a.page, `${TITLE} (Local Copy)`).click();
    await expect(a.page.locator('textarea[aria-label="Markdown source content"]')).toHaveValue(
      LOCAL_BODY_B
    );

    await a.context.close();
    await b.context.close();
  });
});
