import axe from "axe-core";

/**
 * Automated WCAG 2.2 AA check for a rendered container (`T17.3`).
 *
 * Runs axe-core's WCAG 2.0/2.1/2.2 A+AA rules against the container and fails on any
 * **critical** or **serious** violation — the roadmap's acceptance criterion. Lower-impact findings
 * are reported in the failure message of the assertion that follows, but do not fail the suite:
 * "moderate" findings in axe are frequently stylistic (e.g. `region`) rather than barriers.
 *
 * Two honest limitations, documented so the suite never over-claims:
 *
 * 1. **Colour contrast is checked separately.** jsdom has no layout engine, so axe cannot resolve
 *    computed colours and returns `color-contrast` as *incomplete* rather than passing it. The
 *    contrast requirement (>= 4.5:1) is therefore proven arithmetically in `contrast.test.ts`
 *    against the exact palette the components use.
 * 2. **Keyboard behaviour is checked directly.** axe cannot press `Tab`/`Escape`; the focus-trap,
 *    skip-link and shortcut behaviour is asserted with `userEvent` in the component tests.
 */
export interface A11yResult {
  critical: axe.Result[];
  serious: axe.Result[];
  other: axe.Result[];
}

/** Runs axe over `container` and returns the violations grouped by impact. */
export async function a11yViolations(container: HTMLElement): Promise<A11yResult> {
  const results = await axe.run(container, {
    runOnly: {
      type: "tag",
      values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
    },
  });
  const byImpact = (impact: string) =>
    results.violations.filter((violation) => violation.impact === impact);
  return {
    critical: byImpact("critical"),
    serious: byImpact("serious"),
    other: results.violations.filter(
      (violation) => violation.impact !== "critical" && violation.impact !== "serious",
    ),
  };
}

function describe(violations: axe.Result[]): string {
  return violations
    .map(
      (violation) =>
        `${violation.impact ?? "unknown"} ${violation.id}: ${violation.help} (${violation.nodes
          .map((node) => node.target.join(" "))
          .join(", ")})`,
    )
    .join("\n");
}

/** Throws with a readable report when `container` has any critical/serious violation. */
export async function expectNoA11yViolations(container: HTMLElement): Promise<A11yResult> {
  const result = await a11yViolations(container);
  if (result.critical.length > 0 || result.serious.length > 0) {
    throw new Error(
      `axe-core found ${result.critical.length} critical and ${result.serious.length} serious WCAG 2.2 AA violations:\n${describe(
        [...result.critical, ...result.serious],
      )}`,
    );
  }
  return result;
}
