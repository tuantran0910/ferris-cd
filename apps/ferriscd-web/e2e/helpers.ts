import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";
import { mockApi } from "./mock-api";

export const APP = {
  namespace: "ferriscd-system",
  name: "payments-api",
};

export async function signIn(page: Page): Promise<void> {
  await mockApi(page);
  await page.goto("/");
  const token = page.locator('input[name="token"]');
  if (await token.count()) {
    await token.fill("dev");
    await page.getByRole("button", { name: /sign in/i }).click();
  }
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
}

export async function openApplication(page: Page): Promise<void> {
  await signIn(page);
  await page
    .getByRole("link", { name: new RegExp(`${APP.name}`, "i") })
    .first()
    .click();
  await expect(
    page.getByRole("heading", { name: APP.name, level: 1 }),
  ).toBeVisible();
}

export async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, "page must not scroll horizontally").toBeLessThanOrEqual(1);
}

export async function expectAccessible(page: Page): Promise<void> {
  // Let entrance animations settle so opacity mid-flight is not measured.
  await page
    .waitForFunction(
      () =>
        document.getAnimations().every((animation) => animation.playState !== "running"),
      undefined,
      { timeout: 1000 },
    )
    .catch(() => undefined);
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag22aa"])
    .analyze();
  if (results.violations.length > 0) {
    console.log(
      JSON.stringify(
        results.violations.map((violation) => ({
          id: violation.id,
          nodes: violation.nodes.map((node) => ({
            target: node.target,
            summary: node.failureSummary,
          })),
        })),
        null,
        2,
      ),
    );
  }
  expect(results.violations.map((violation) => violation.id)).toEqual([]);
}

/** Volatile values (sync times, revisions, generated IDs) masked in snapshots. */
export function frozenMasks(page: Page) {
  // The API is mocked, so only locale-rendered times vary between machines.
  return [page.locator("time")];
}
