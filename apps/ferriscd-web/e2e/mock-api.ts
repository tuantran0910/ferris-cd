import { readFileSync } from "node:fs";
import type { Page } from "@playwright/test";

/**
 * Frozen API responses captured from the demo server. Routing every `/api/v1`
 * call through this fixture makes the suite hermetic: no FerrisCD server,
 * cluster, token or seed data is required to run it.
 */
const responses: Record<string, unknown> = JSON.parse(
  readFileSync("e2e/fixtures/api.json", "utf8"),
);

export async function mockApi(page: Page): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const { pathname } = new URL(route.request().url());
    const body = responses[pathname];
    if (body === undefined) {
      // The SSE stream is optional; a 404 makes the UI fall back to polling.
      await route.fulfill({
        status: 404,
        contentType: "application/json",
        body: JSON.stringify({ detail: "not mocked" }),
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
