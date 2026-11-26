import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiClientError } from "../api/client";
import { RollbackModal } from "../components/RollbackModal";
import { SyncModal } from "../components/SyncModal";
import { sampleAppDetail } from "./fixtures";

describe("SyncModal & RollbackModal (T16.4 & Trap Guard T16.4)", () => {
  it("submits manual sync request and handles RBAC 403 Forbidden gracefully without crashing", async () => {
    const user = userEvent.setup();
    const onForbidden = vi.fn();
    const onConfirm = vi.fn().mockRejectedValue(
      new ApiClientError(
        403,
        "Forbidden",
        "read-only user cannot sync project payments",
      ),
    );

    render(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        onClose={vi.fn()}
        onConfirm={onConfirm}
        onForbidden={onForbidden}
      />,
    );

    const confirmBtn = screen.getByRole("button", { name: /Confirm Sync/i });
    await user.click(confirmBtn);

    expect(onConfirm).toHaveBeenCalledWith({});
    expect(onForbidden).toHaveBeenCalledTimes(1);
    expect(await screen.findByTestId("sync-rbac-forbidden")).toHaveTextContent(
      "read-only user cannot sync project payments",
    );
    expect(confirmBtn).toBeDisabled();
  });

  it("enforces v1.0 contract: disables prune, routes dryRun to onPreviewDiff without POSTing, and submits {} on Confirm Sync", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onPreviewDiff = vi.fn();
    const onConfirm = vi.fn().mockResolvedValue({
      status: "accepted",
      operation: "sync",
      namespace: "ferriscd-system",
      name: "payments-api",
      request: '{"sync":{}}',
    });

    const { rerender } = render(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        onClose={onClose}
        onConfirm={onConfirm}
        onPreviewDiff={onPreviewDiff}
      />,
    );

    // Prune is disabled in v1.0 with clear spec.syncPolicy indicator
    const pruneCheckbox = screen.getByLabelText(/Prune orphaned resources/i);
    expect(pruneCheckbox).toBeDisabled();
    expect(pruneCheckbox).not.toBeChecked();
    expect(
      screen.getByText(/Configured via/i).closest("span"),
    ).toHaveTextContent(
      "Configured via spec.syncPolicy.automated.prune (v1.0).",
    );

    // Checking dryRun routes directly to onPreviewDiff without invoking onConfirm
    await user.click(screen.getByLabelText(/Dry-run preview/i));
    const previewBtn = screen.getByRole("button", {
      name: /Preview Dry-Run Diff/i,
    });
    await user.click(previewBtn);

    expect(onConfirm).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onPreviewDiff).toHaveBeenCalledTimes(1);

    // Reopen modal and submit normal Confirm Sync -> posts {} and displays 202 confirmation
    rerender(
      <SyncModal
        open={false}
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        onClose={onClose}
        onConfirm={onConfirm}
        onPreviewDiff={onPreviewDiff}
      />,
    );
    rerender(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        onClose={onClose}
        onConfirm={onConfirm}
        onPreviewDiff={onPreviewDiff}
      />,
    );

    await user.click(screen.getByRole("button", { name: /Confirm Sync/i }));

    expect(onConfirm).toHaveBeenCalledWith({});
    expect(await screen.findByTestId("sync-success-banner")).toHaveTextContent(
      "accepted",
    );
  });

  it("displays automated-sync-pause warning in RollbackModal, selects history entry, and handles 403 Forbidden gracefully", async () => {
    const user = userEvent.setup();
    const onForbidden = vi.fn();
    const onConfirm = vi.fn().mockRejectedValue(
      new ApiClientError(
        403,
        "Forbidden",
        "read-only user cannot roll back project payments",
      ),
    );

    render(
      <RollbackModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        history={sampleAppDetail.history ?? []}
        onClose={vi.fn()}
        onConfirm={onConfirm}
        onForbidden={onForbidden}
      />,
    );

    // Explicit automated sync pause warning
    expect(
      screen.getByTestId("rollback-auto-sync-warning"),
    ).toHaveTextContent(/Automated sync will be paused/i);
    expect(
      screen.getByTestId("rollback-auto-sync-warning"),
    ).toHaveTextContent("spec.syncPolicy.automated");

    // Choose Deployment #1
    await user.click(screen.getByLabelText(/Deployment #1/i));

    const confirmBtn = screen.getByRole("button", {
      name: /Confirm Rollback/i,
    });
    await user.click(confirmBtn);

    expect(onConfirm).toHaveBeenCalledWith({ id: 1 });
    expect(onForbidden).toHaveBeenCalledTimes(1);
    expect(
      await screen.findByTestId("rollback-rbac-forbidden"),
    ).toHaveTextContent("read-only user cannot roll back project payments");
    expect(confirmBtn).toBeDisabled();
  });
});
