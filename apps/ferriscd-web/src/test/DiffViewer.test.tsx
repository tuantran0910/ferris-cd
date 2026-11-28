import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { DiffViewer } from "../features/diff/DiffViewer";
import { isBlockingEnforcement } from "../api/types";
import {
  sampleDiffPayload,
  sampleDiffPayloadWithPolicyViolations,
} from "./fixtures";

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
    await user.click(
      screen.getByRole("combobox", { name: /Filter diff status/i }),
    );
    await user.click(screen.getByRole("option", { name: "FieldConflict" }));
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

  it("shows a blocking policy violation banner above the diff (T20.2)", () => {
    render(<DiffViewer diff={sampleDiffPayloadWithPolicyViolations} />);

    const banner = screen.getByTestId("policy-violations-banner");
    expect(banner).toHaveTextContent(/policy violations/i);
    expect(banner).toHaveTextContent(/1 blocking/i);
    expect(banner).toHaveTextContent(/refused until these manifests comply/i);

    const violations = within(banner).getAllByTestId("policy-violation");
    expect(violations).toHaveLength(2);
    // The guard the components branch on agrees with the server's wire value.
    expect(
      (
        sampleDiffPayloadWithPolicyViolations.policyViolations ?? []
      ).filter((violation) => isBlockingEnforcement(violation.enforcement)),
    ).toHaveLength(1);
    expect(violations[0]).toHaveTextContent("Enforce");
    expect(violations[0]).toHaveTextContent("no-privileged");
    expect(violations[0]).toHaveTextContent(
      "apps/Deployment/payments/payments-api",
    );
    expect(violations[1]).toHaveTextContent("Warn");
    expect(violations[1]).toHaveTextContent("prefer-approved-registry");

    // The banner explains the refusal; the resource cards still render so the
    // operator can see *what* would have been applied.
    expect(
      screen.getByTestId("diff-resource-apps/Deployment/payments/payments-api"),
    ).toBeInTheDocument();
  });

  it("renders advisories without claiming the sync is blocked (T20.2)", () => {
    const advisoryOnly = {
      ...sampleDiffPayloadWithPolicyViolations,
      wouldSync: true,
      policyViolations: (
        sampleDiffPayloadWithPolicyViolations.policyViolations ?? []
      ).filter((violation) => !isBlockingEnforcement(violation.enforcement)),
    };
    render(<DiffViewer diff={advisoryOnly} />);

    const banner = screen.getByTestId("policy-violations-banner");
    expect(banner).toHaveTextContent(/1 advisory/i);
    expect(banner).toHaveTextContent(/sync proceeds/i);
    expect(banner).not.toHaveTextContent(/blocking/i);
  });

  it("renders no policy banner when no rule fired (T20.2)", () => {
    render(<DiffViewer diff={sampleDiffPayload} />);
    expect(
      screen.queryByTestId("policy-violations-banner"),
    ).not.toBeInTheDocument();
  });
});
