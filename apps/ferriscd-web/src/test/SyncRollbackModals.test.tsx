import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { ApiClientError } from "../api/client";
import type { OperationResponse } from "../api/types";
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

  it("reports a 409 conflict for sync as a pending rollback instead of a bare status code (M6)", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn().mockRejectedValue(
      new ApiClientError(
        409,
        "Conflict",
        "a rollback is pending for this Application",
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
      />,
    );

    await user.click(screen.getByRole("button", { name: /Confirm Sync/i }));

    const errorBox = await screen.findByTestId("sync-error");
    expect(errorBox).toHaveTextContent("Operation already pending (409 Conflict)");
    expect(errorBox).toHaveTextContent(/rollback is still pending/i);
    expect(errorBox).toHaveTextContent(
      "a rollback is pending for this Application",
    );
    // A conflict is not an RBAC denial: the action stays available for a retry.
    expect(
      screen.getByRole("button", { name: /Confirm Sync/i }),
    ).toBeEnabled();
  });

  it("shows readable success feedback, never the raw operation JSON (M7)", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn().mockResolvedValue({
      status: "accepted",
      operation: "sync",
      namespace: "ferriscd-system",
      name: "payments-api",
      request: '{"sync":{}}',
      resourceVersion: "42",
    });

    render(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        onClose={vi.fn()}
        onConfirm={onConfirm}
      />,
    );

    await user.click(screen.getByRole("button", { name: /Confirm Sync/i }));

    const banner = await screen.findByTestId("sync-success-banner");
    expect(banner).toHaveTextContent("accepted");
    expect(banner).not.toHaveTextContent("{");
    expect(banner).not.toHaveTextContent('"sync"');
  });

  it("behaves like a modal dialog: focus moves inside, Escape closes, background scroll is locked (M1)", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();

    const { unmount } = render(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        onClose={onClose}
        onConfirm={vi.fn()}
      />,
    );

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.body.style.overflow).toBe("hidden");

    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);

    unmount();
    expect(document.body.style.overflow).toBe("");
  });

  it("restores focus to the trigger and keeps Escape from closing an in-flight request (M1)", async () => {
    let resolveConfirm: ((value: OperationResponse) => void) | undefined;
    const onConfirm = vi.fn(
      () =>
        new Promise<OperationResponse>((resolve) => {
          resolveConfirm = resolve;
        }),
    );

    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Open Sync
          </button>
          <SyncModal
            open={open}
            namespace="ferriscd-system"
            name="payments-api"
            targetRevision="main"
            onClose={() => setOpen(false)}
            onConfirm={onConfirm}
          />
        </>
      );
    }

    const user = userEvent.setup();
    render(<Harness />);

    const trigger = screen.getByRole("button", { name: /Open Sync/i });
    await user.click(trigger);
    await user.click(screen.getByRole("button", { name: /Confirm Sync/i }));

    // Request in flight: Escape must not silently dismiss the dialog.
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    resolveConfirm?.({
      status: "accepted",
      operation: "sync",
      namespace: "ferriscd-system",
      name: "payments-api",
      request: "{}",
    });
    await screen.findByTestId("sync-success-banner");
    await user.click(screen.getByRole("button", { name: /Done/i }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(document.activeElement).toBe(trigger);
  });
});
