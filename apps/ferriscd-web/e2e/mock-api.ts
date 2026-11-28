import { readFileSync } from "node:fs";
import type { Page } from "@playwright/test";

/**
 * Frozen API responses captured from the demo server. Routing every `/api/v1`
 * call through this fixture makes the suite hermetic: no FerrisCD server,
 * cluster, token or seed data is required to run it.
 */
const responses: Record<string, unknown> = JSON.parse(
  readFileSync(new URL("./fixtures/api.json", import.meta.url), "utf8"),
);

export async function mockApi(page: Page): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const { pathname } = new URL(route.request().url());
    const body = responses[pathname];
    if (body === undefined) {
      // Only the SSE stream is optional: a 404 makes the UI poll instead.
      if (pathname.endsWith("/applications/stream")) {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ detail: "stream disabled in tests" }),
        });
        return;
      }
      console.error(`[mock-api] unmocked endpoint: ${pathname}`);
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ detail: "unmocked endpoint" }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  });
}
