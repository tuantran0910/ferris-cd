import { expect, test } from "@playwright/test";
import { mockApi } from "./mock-api";
import {
  APP,
  expectAccessible,
  expectNoHorizontalOverflow,
  openApplication,
  signIn,
} from "./helpers";

test.describe("login", () => {
  test("renders the token form accessibly in every theme", async ({ page }) => {
    await mockApi(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.locator('input[name="token"]')).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expectAccessible(page);
  });

  test("paints the persisted theme before the app bundle runs", async ({
    page,
  }) => {
    await page.addInitScript(() =>
      localStorage.setItem("ferriscd-theme", "light"),
    );
    // Block the React entry so only the inline boot script can set the theme.
    await page.route("**/src/app/main.tsx*", (route) => route.abort());
    await page.goto("/");
    const boot = await page.evaluate(() => ({
      theme: document.documentElement.dataset.theme,
      meta: document
        .querySelector('meta[name="theme-color"]')
        ?.getAttribute("content"),
    }));
    expect(boot.theme).toBe("light");
    expect(boot.meta).toBe("#f1f5f9");
  });
});

test.describe("applications", () => {
  test("lists applications, filters them and keeps the layout intact", async ({
    page,
  }) => {
    await signIn(page);
    await expect(page.getByRole("heading", { name: "Applications" })).toBeVisible();

    const search = page.getByPlaceholder(/search by name, namespace/i);
    // The focused control must expose a visible ring that is not just a 1.5:1 wash.
    const blurred = await search.evaluate((element) => {
      const style = getComputedStyle(element);
      return { border: style.borderTopColor, shadow: style.boxShadow };
    });
    await search.focus();
    await expect
      .poll(
        () =>
          search.evaluate(
            (element) => getComputedStyle(element).borderTopColor,
          ),
        { timeout: 2000 },
      )
      .not.toBe(blurred.border);
    const focused = await search.evaluate((element) => {
      const style = getComputedStyle(element);
      return { border: style.borderTopColor, shadow: style.boxShadow };
    });
    expect(focused.border).not.toBe(blurred.border);
    expect(focused.shadow).not.toBe("none");

    await search.fill("payments");
    await expect(
      page.getByRole("link", { name: new RegExp(APP.name, "i") }).first(),
    ).toBeVisible();
    await search.fill("no-such-application");
    await expect(page.getByText(/no applications match/i)).toBeVisible();
    await search.fill("");

    await expectNoHorizontalOverflow(page);
    await expectAccessible(page);
  });

  test("opens the detail page and every tab renders", async ({ page }) => {
    await openApplication(page);

    // Source / destination / sync cards.
    await expect(page.getByTestId("source-card")).toBeVisible();
    await expect(page.getByText("Destination", { exact: false })).toBeVisible();

    // Narrow viewports default to the table; exercise both modes explicitly.
    await page.getByRole("button", { name: /Graph View/i }).click();
    await expect(page.getByTestId("resource-graph-canvas")).toBeVisible();
    await page.getByRole("button", { name: /Resource Table View/i }).click();
    await expect(page.getByTestId("resource-table-view")).toBeVisible();

    await page.getByRole("tab", { name: /Live Diff/i }).click();
    await expect(page.getByText(/Revision:/i)).toBeVisible();

    await page.getByRole("tab", { name: /Events/i }).click();
    await expect(page.getByRole("tab", { name: /Events/i })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    await page.getByRole("tab", { name: /Conditions/i }).click();
    await page.getByRole("tab", { name: /History/i }).click();
    await expect(page.getByTestId("history-table")).toBeVisible();

    await expectNoHorizontalOverflow(page);
    await expectAccessible(page);
  });

  test("sync and rollback dialogs open and close without layout shift", async ({
    page,
  }) => {
    await openApplication(page);

    await page.getByRole("button", { name: /^Sync$/i }).click();
    const syncDialog = page.getByRole("dialog");
    await expect(syncDialog.getByText("Sync Application")).toBeVisible();
    await expect(syncDialog.getByText("Dry-run preview")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(syncDialog).toBeHidden();

    await page.getByRole("button", { name: /^Rollback$/i }).click();
    const rollbackDialog = page.getByRole("dialog");
    await expect(rollbackDialog).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(rollbackDialog).toBeHidden();
    await expectNoHorizontalOverflow(page);
  });

  test("copies a revision and confirms it with a toast", async ({ page }) => {
    await openApplication(page);
    await page.getByRole("button", { name: "Copy rendered revision" }).click();
    await expect(page.getByText("Copied", { exact: true })).toBeVisible();
    await expect(page.getByText("Copied", { exact: true })).toBeHidden({
      timeout: 4000,
    });
  });
});

test.describe("navigation", () => {
  test("projects and clusters pages render", async ({ page }) => {
    await signIn(page);

    await page.getByRole("link", { name: "Projects" }).click();
    await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expectAccessible(page);

    await page.getByRole("link", { name: "Clusters" }).click();
    await expect(page.getByRole("heading", { name: "Clusters" })).toBeVisible();
    await expect(
      page.getByTestId("cluster-card-in-cluster"),
    ).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expectAccessible(page);
  });

  test("cluster query filters the list and a missing query has a way back", async ({
    page,
  }) => {
    await signIn(page);
    await page.goto("/clusters?q=in-cluster");
    await expect(page.getByTestId("cluster-card-in-cluster")).toBeVisible();

    await page.goto("/clusters?q=does-not-exist");
    await expect(page.getByText(/No cluster matches/i)).toBeVisible();
    await page.getByRole("link", { name: /clear the filter/i }).click();
    await expect(page.getByTestId("cluster-card-in-cluster")).toBeVisible();
  });

  test("the command palette searches, navigates and closes with Escape", async ({
    page,
  }) => {
    await signIn(page);

    await page.keyboard.press(
      process.platform === "darwin" ? "Meta+k" : "Control+k",
    );
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    const input = dialog.getByRole("combobox");
    await expect(input).toBeFocused();

    // One focus indicator: the border is the indicator, not border + outline.
    const focusStyle = await input.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        outline: style.outlineStyle,
        border: style.borderTopColor,
        shadow: style.boxShadow,
      };
    });
    expect(focusStyle.outline).toBe("none");
    expect(focusStyle.shadow).not.toBe("none");
    expect(focusStyle.border).toMatch(/rgb\(/);

    await input.fill("Projects");
    await dialog
      .getByRole("option", { name: /Projects/i })
      .first()
      .click();
    await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

    await page.keyboard.press(
      process.platform === "darwin" ? "Meta+k" : "Control+k",
    );
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("theme toggle persists without a flash", async ({ page }) => {
    await signIn(page);
    const before = await page.evaluate(
      () => document.documentElement.dataset.theme,
    );
    let after = before;
    for (let click = 0; click < 3 && after === before; click += 1) {
      await page.getByTestId("theme-toggle").click();
      after = await page.evaluate(
        () => document.documentElement.dataset.theme,
      );
    }
    expect(after).not.toBe(before);

    await page.reload();
    const reloaded = await page.evaluate(
      () => document.documentElement.dataset.theme,
    );
    expect(reloaded).toBe(after);
    const meta = await page
      .locator('meta[name="theme-color"]')
      .getAttribute("content");
    expect(meta).toBe(after === "light" ? "#f1f5f9" : "#020617");
  });
});

test.describe("responsive", () => {
  test("the header collapses without hiding navigation labels from AT", async ({
    page,
  }) => {
    await signIn(page);
    await expect(
      page.getByRole("link", { name: "Applications" }),
    ).toBeVisible();
    await expect(page.getByRole("link", { name: "Projects" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Clusters" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });
});
