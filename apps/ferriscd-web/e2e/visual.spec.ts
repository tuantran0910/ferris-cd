import { expect, test } from "@playwright/test";
import { frozenMasks, openApplication, signIn } from "./helpers";

test.describe("visual snapshots", () => {
  test("applications list", async ({ page }) => {
    await signIn(page);
    await expect(page.getByRole("heading", { name: "Applications" })).toBeVisible();
    await expect(page).toHaveScreenshot("applications.png", {
      fullPage: true,
      animations: "disabled",
      caret: "hide",
      mask: frozenMasks(page),
      maxDiffPixelRatio: 0.03,
    });
  });

  test("application detail", async ({ page }) => {
    await openApplication(page);
    await expect(
      page.getByTestId("resource-graph-canvas").or(
        page.getByTestId("resource-table-view"),
      ),
    ).toBeVisible();
    await expect(page).toHaveScreenshot("application-detail.png", {
      fullPage: true,
      animations: "disabled",
      caret: "hide",
      mask: frozenMasks(page),
      maxDiffPixelRatio: 0.03,
    });
  });

  test("projects and clusters", async ({ page }) => {
    await signIn(page);
    await page.getByRole("link", { name: "Projects" }).click();
    await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
    await expect(page).toHaveScreenshot("projects.png", {
      fullPage: true,
      animations: "disabled",
      caret: "hide",
      mask: frozenMasks(page),
      maxDiffPixelRatio: 0.03,
    });

    await page.getByRole("link", { name: "Clusters" }).click();
    await expect(page.getByRole("heading", { name: "Clusters" })).toBeVisible();
    await expect(page).toHaveScreenshot("clusters.png", {
      fullPage: true,
      animations: "disabled",
      caret: "hide",
      mask: frozenMasks(page),
      maxDiffPixelRatio: 0.03,
    });
  });

  test("command palette", async ({ page }) => {
    await signIn(page);
    await page.keyboard.press(
      process.platform === "darwin" ? "Meta+k" : "Control+k",
    );
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page).toHaveScreenshot("command-palette.png", {
      animations: "disabled",
      caret: "hide",
      maxDiffPixelRatio: 0.03,
    });
  });
});
