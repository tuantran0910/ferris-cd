import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { DiffViewer } from "../components/DiffViewer";
import { sampleDiffPayload } from "./fixtures";

describe("DiffViewer (T16.4)", () => {
  it("highlights OutOfSync, Missing, Orphaned, FieldConflict managers, and ***REDACTED(...)*** secret badges", async () => {
    const user = userEvent.setup();
    render(<DiffViewer diff={sampleDiffPayload} />);

    // Deployment with OutOfSync + SSA FieldConflict manager
    const deployCard = screen.getByTestId(
      "diff-resource-apps/Deployment/payments/payments-api",
    );
    expect(deployCard).toHaveTextContent("OutOfSync");
    expect(
      within(deployCard).getByTestId("field-conflict-badge"),
    ).toHaveTextContent("FieldConflict (1)");
    expect(
      within(deployCard).getByTestId("field-conflict-list"),
    ).toHaveTextContent("manager: kube-controller-manager");
    expect(
      within(deployCard).getByTestId("field-conflict-list"),
    ).toHaveTextContent(".spec.replicas");

    // Secret diff renders ***REDACTED(sha256:...)*** badges clearly
    const secretCard = screen.getByTestId(
      "diff-resource-/Secret/payments/payments-db-creds",
    );
    const redactedBadges = within(secretCard).getAllByTestId(
      "redacted-secret-badge",
    );
    expect(redactedBadges).toHaveLength(2);
    expect(redactedBadges[0]).toHaveTextContent(
      "***REDACTED(sha256:9f86d081)***",
    );
    expect(redactedBadges[1]).toHaveTextContent(
      "***REDACTED(sha256:4b227777)***",
    );

    // Missing and Orphaned resources highlighted
    expect(
      screen.getByTestId(
        "diff-resource-policy/PodDisruptionBudget/payments/payments-pdb",
      ),
    ).toHaveTextContent("Missing");
    expect(
      screen.getByTestId("diff-resource-/ConfigMap/payments/legacy-flags"),
    ).toHaveTextContent("Orphaned");

    // Defaults to side-by-side and switches to unified view
    expect(screen.getAllByTestId("diff-side-by-side").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: /Unified/i }));
    expect(screen.getAllByTestId("diff-unified").length).toBeGreaterThan(0);
    expect(screen.queryByTestId("diff-side-by-side")).not.toBeInTheDocument();

    // Filter to FieldConflict only
    await user.selectOptions(
      screen.getByLabelText(/Filter diff status/i),
      "FieldConflict",
    );
    expect(
      screen.getByTestId("diff-resource-apps/Deployment/payments/payments-api"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("diff-resource-/Service/payments/payments-svc"),
    ).not.toBeInTheDocument();
  });

  it("distinguishes an empty diff from an over-narrow filter and tolerates a missing resources array (M9)", () => {
    const emptyDiff = {
      revision: "deadbeef",
      desired: 0,
      wouldSync: false,
      summary: {
        total: 0,
        synced: 0,
        outOfSync: 0,
        missing: 0,
        orphaned: 0,
        ownershipConflicts: 0,
        fieldConflicts: 0,
      },
      resources: [],
    };
    const { unmount } = render(<DiffViewer diff={emptyDiff} />);
    expect(screen.getByTestId("diff-empty-state")).toHaveTextContent(
      /both empty/i,
    );
    unmount();

    // `resources` is optional in the OpenAPI schema: an absent array must not
    // crash the page.
    const { resources: _omit, ...withoutResources } = emptyDiff;
    render(<DiffViewer diff={withoutResources} />);
    expect(screen.getByTestId("diff-empty-state")).toBeInTheDocument();
  });
});
