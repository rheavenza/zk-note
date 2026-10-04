/**
 * ZK-107 acceptance D — offline, durability, and retry behavior.
 *
 * Note on the "reload while offline" step: this app ships no service worker, so
 * the app shell itself cannot be re-fetched with the network fully down. The
 * test therefore exercises the durable-storage guarantee exactly as it matters —
 * the browser is reloaded with every `/v1` request failing (server unreachable),
 * which is the state the app is actually in while offline.
 */

import { expect, test } from "@playwright/test";
import {
  assertNoPlaintext,
  closeSyncPopover,
  createAccount,
  createNote,
  createVault,
  ensureUnlocked,
  expectStatus,
  fillBody,
  lastSyncAt,
  linkVault,
  liveRevisions,
  mutationIds,
  openBrowser,
  openSyncPopover,
  readStore,
  scopedDatabaseName,
  statusBadge,
  triggerSync,
} from "./helpers";

test.describe("ZK-107 offline and retry acceptance", () => {
  test("offline edits queue locally, survive a reload, and sync after reconnect", async ({ browser }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");
    await createVault(page);
    await createAccount(page, "owner-offline");
    await linkVault(page);
    await ensureUnlocked(page);
    await triggerSync(page);
    await expectStatus(page, "synced");

    const scoped = await scopedDatabaseName(page);
    expect(scoped).toBeTruthy();
    const syncedAt = await lastSyncAt(page, scoped!);
    expect(syncedAt).toBeTruthy();

    // ---- Disconnect and work locally ----
    await context.setOffline(true);
    await expectStatus(page, "offline");

    await createNote(page, "Offline One", "created while offline");
    await expectStatus(page, "offline");
    // The badge must show that work is waiting, not that it is synchronized.
    await expect(statusBadge(page)).toContainText("(");

    const queuedIds = await mutationIds(page, scoped!);
    expect(queuedIds.length).toBeGreaterThan(0);

    const queuedRows = await readStore(page, scoped!, "mutations");
    assertNoPlaintext(queuedRows, ["Offline One", "created while offline"]);

    // A blocked operation must never advance the sync timestamp.
    expect(await lastSyncAt(page, scoped!)).toBe(syncedAt);

    // ---- Reload with the server unreachable: queued work must be durable ----
    await context.setOffline(false);
    await page.route("**/v1/**", (route) => route.abort());
    await page.reload();
    await ensureUnlocked(page);

    expect(await mutationIds(page, scoped!)).toEqual(queuedIds);
    await expectStatus(page, "pending changes");
    expect(await lastSyncAt(page, scoped!)).toBe(syncedAt);

    // ---- Reconnect and retry: same stable mutation ids, drained queue ----
    await page.unroute("**/v1/**");
    await triggerSync(page);
    await expectStatus(page, "synced");
    expect(await mutationIds(page, scoped!)).toEqual([]);
    expect(await lastSyncAt(page, scoped!)).not.toBe(syncedAt);
    await expect(page.locator(".zk-note-item", { hasText: "Offline One" })).toBeVisible();

    await context.close();
  });

  test("a push accepted by the server but lost in transit is not applied twice on retry", async ({
    browser,
  }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");
    await createVault(page);
    await createAccount(page, "owner-lost-response");
    await linkVault(page);
    await ensureUnlocked(page);
    await triggerSync(page);
    await expectStatus(page, "synced");

    const scoped = (await scopedDatabaseName(page))!;

    // Seed and synchronize the note so the queue is empty and the baseline
    // revision is known.
    await createNote(page, "Lost Response", "body that must exist exactly once");
    await triggerSync(page);
    await expectStatus(page, "synced");
    const [baselineRevision] = await liveRevisions(page, scoped);
    expect(baselineRevision).toBeTruthy();

    // A single body edit queues exactly one mutation.
    await fillBody(page, "edited exactly once");
    const queued = await mutationIds(page, scoped);
    expect(queued.length).toBe(1);
    const mutationId = queued[0]!;

    // Simulate "server committed, response never arrived".
    let dropped = false;
    await page.route("**/v1/sync/push", async (route) => {
      if (!dropped) {
        dropped = true;
        await route.fetch(); // the server durably accepts the mutation
        await route.abort("failed"); // ...but the client never sees the response
        return;
      }
      await route.continue();
    });

    await triggerSync(page);
    await expectStatus(page, "error");

    // The mutation is retained with the same idempotency id.
    expect(await mutationIds(page, scoped)).toEqual([mutationId]);

    await page.unroute("**/v1/sync/push");
    await triggerSync(page);
    await expectStatus(page, "synced");
    expect(await mutationIds(page, scoped)).toEqual([]);

    // The replayed mutation was applied exactly once: exactly one new revision.
    const [afterRevision] = await liveRevisions(page, scoped);
    expect(afterRevision).toBe(baselineRevision! + 1);

    await context.close();
  });

  test("401, 429, and 5xx are retryable and the retry preserves mutation ids", async ({ browser }) => {
    const { context, page } = await openBrowser(browser);
    await page.goto("/");
    await createVault(page);
    await createAccount(page, "owner-transient");
    await linkVault(page);
    await ensureUnlocked(page);
    await triggerSync(page);
    await expectStatus(page, "synced");

    const scoped = (await scopedDatabaseName(page))!;

    await createNote(page, "Transient Retry", "seed body");
    await triggerSync(page);
    await expectStatus(page, "synced");
    const [baselineRevision] = await liveRevisions(page, scoped);
    // Captured after the last successful round trip, so any advance below would
    // mean a failed attempt was falsely recorded as synchronized.
    const syncedAt = await lastSyncAt(page, scoped);
    expect(syncedAt).toBeTruthy();

    await fillBody(page, "survives transient failures");
    const queued = await mutationIds(page, scoped);
    expect(queued.length).toBe(1);
    const mutationId = queued[0]!;

    const cases: Array<{ status: number; code: string }> = [
      { status: 401, code: "UNAUTHORIZED" },
      { status: 429, code: "RATE_LIMITED" },
      { status: 503, code: "SERVER_UNAVAILABLE" },
    ];

    let checkedSanitizedMessage = false;
    for (const failure of cases) {
      await page.route("**/v1/sync/push", (route) =>
        route.fulfill({
          status: failure.status,
          contentType: "application/json",
          body: JSON.stringify({ code: failure.code, message: `injected ${failure.status}` }),
        })
      );

      await triggerSync(page);

      // Never "synced", never a fabricated timestamp, mutation still queued with
      // the exact same idempotency id.
      await expectStatus(page, "error");
      expect(await mutationIds(page, scoped)).toEqual([mutationId]);
      expect(await lastSyncAt(page, scoped)).toBe(syncedAt);

      if (!checkedSanitizedMessage) {
        checkedSanitizedMessage = true;
        // The surfaced error must not contain local note content (SEC-001/SEC-003).
        await openSyncPopover(page);
        const popoverText = await page.getByTestId("sync-popover").innerText();
        expect(popoverText).not.toContain("survives transient failures");
        await closeSyncPopover(page);
      }

      await page.unroute("**/v1/sync/push");
    }

    // Retry with a healthy server succeeds using the same mutation id, applied once.
    await triggerSync(page);
    await expectStatus(page, "synced");
    expect(await mutationIds(page, scoped)).toEqual([]);
    const [afterRevision] = await liveRevisions(page, scoped);
    expect(afterRevision).toBe(baselineRevision! + 1);

    await context.close();
  });
});
