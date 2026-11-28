import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SyncModal } from "../features/sync/SyncModal";
import {
  SyncWindowBadge,
  SyncWindowNotice,
  SyncWindowRow,
  SyncWindowsPanel,
} from "../features/sync/SyncWindows";
import { blockedSyncWindow, overridableSyncWindow, sampleProjects } from "./fixtures";

const paymentsProject = sampleProjects.items[0]!;
const windows = paymentsProject.syncWindows ?? [];

describe("Sync windows (T17.4)", () => {
  it("renders each window with its live state, schedule, time zone, and scope", () => {
    render(
      <ul>
        <SyncWindowRow window={windows[0]!} testId="window-block" />
        <SyncWindowRow window={windows[1]!} testId="window-release" />
      </ul>,
    );

    const blocked = screen.getByTestId("window-block");
    expect(blocked).toHaveAttribute("data-window-kind", "deny");
    expect(blocked).toHaveAttribute("data-window-state", "active");
    expect(blocked).toHaveTextContent("deny");
    expect(blocked).toHaveTextContent("Open now");
    expect(blocked).toHaveTextContent("0 9-17 * * MON-FRI");
    expect(blocked).toHaveTextContent("for 8h in America/New_York");
    expect(blocked).toHaveTextContent("Open until 2026-11-25 22:00:00 UTC");
    // The scope globs are stated, never implied.
    expect(blocked).toHaveTextContent(
      "Scope: applications=payments-* · clusters=prod-*.",
    );

    const release = screen.getByTestId("window-release");
    expect(release).toHaveAttribute("data-window-state", "scheduled");
    expect(release).toHaveTextContent("Closed now");
    expect(release).toHaveTextContent("Next opens 2026-11-28 02:00:00 UTC");
    expect(release).toHaveTextContent("manual override");
  });

  it("reports an unparseable window instead of hiding it (fail closed)", () => {
    render(
      <ul>
        <SyncWindowRow
          window={{
            ...windows[0]!,
            schedule: "every weekday",
            active: false,
            startsAt: null,
            endsAt: null,
            nextStart: null,
            error: "must have exactly 5 fields",
          }}
        />
      </ul>,
    );
    const row = screen.getByRole("listitem");
    expect(row).toHaveAttribute("data-window-state", "invalid");
    expect(row).toHaveTextContent("Cannot be evaluated");
    expect(row).toHaveTextContent("every sync of this project is denied");
    // Finding N2: no open/closed claim for a schedule the server could not evaluate.
    expect(row).not.toHaveTextContent("Closed now");
    expect(row).not.toHaveTextContent("Open now");
  });

  it("renders nothing for a project without windows", () => {
    const { container } = render(<SyncWindowsPanel windows={[]} />);
    expect(container).toBeEmptyDOMElement();
    render(<SyncWindowsPanel windows={undefined} />);
    expect(screen.queryByText(/Sync windows/)).not.toBeInTheDocument();
  });

  it("lists every window plus the next transition", () => {
    render(
      <SyncWindowsPanel
        windows={windows}
        nextTransition={paymentsProject.nextSyncWindowTransition}
        testId="project-sync-windows-payments"
      />,
    );
    expect(screen.getByText("Sync windows (2)")).toBeInTheDocument();
    expect(
      screen.getByTestId("project-sync-windows-payments-0"),
    ).toHaveAttribute("data-window-kind", "deny");
    expect(screen.getByText(/Next transition/)).toHaveTextContent(
      "2026-11-25 22:00:00 UTC",
    );
  });

  it("explains a block that has no manual override, warning about it only when it does", () => {
    const { rerender } = render(
      <SyncWindowNotice syncWindow={blockedSyncWindow} />,
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveAttribute("data-sync-window-reason", "denyWindowActive");
    expect(alert).toHaveTextContent("Blocked by an AppProject sync window");
    expect(alert).toHaveTextContent("deny sync window is active");
    expect(alert).toHaveTextContent("Drift is still detected and reported");
    expect(alert).toHaveTextContent("manualSync: true");

    // With `manualSync: true` the same window says so — and it is a `status`, not an `alert`,
    // because nothing is wrong: the click will be honoured.
    rerender(<SyncWindowNotice syncWindow={overridableSyncWindow} />);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByTestId("sync-window-override")).toHaveTextContent(
      "Manual override applies",
    );

    // An allowed sync window renders no notice at all.
    rerender(
      <SyncWindowNotice
        syncWindow={{ ...blockedSyncWindow, blocked: false, reason: undefined }}
      />,
    );
    expect(screen.queryByTestId("sync-window-override")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    rerender(<SyncWindowNotice syncWindow={null} />);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("badges the application header only while a window blocks automation", () => {
    const { rerender } = render(
      <SyncWindowBadge syncWindow={blockedSyncWindow} />,
    );
    expect(screen.getByTestId("sync-window-badge")).toHaveTextContent(
      "Sync window blocked",
    );
    rerender(<SyncWindowBadge syncWindow={overridableSyncWindow} />);
    expect(screen.getByTestId("sync-window-badge")).toHaveTextContent(
      "Sync window (override)",
    );
    rerender(<SyncWindowBadge syncWindow={{ ...blockedSyncWindow, blocked: false }} />);
    expect(screen.queryByTestId("sync-window-badge")).not.toBeInTheDocument();
  });

  it("disables Confirm Sync when the window blocks it, and keeps the dry-run preview available", () => {
    render(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        syncWindow={blockedSyncWindow}
        onClose={() => undefined}
        onConfirm={() => Promise.reject(new Error("must not be called"))}
        onPreviewDiff={() => undefined}
      />,
    );
    expect(screen.getByTestId("sync-window-blocked")).toHaveTextContent(
      "Blocked by an AppProject sync window",
    );
    expect(screen.getByRole("button", { name: /Confirm Sync/i })).toBeDisabled();
    // Drift preview stays available: a window never suppresses diffing.
    expect(
      screen.getByRole("button", { name: /Open Live Diff/i }),
    ).toBeEnabled();
  });

  it("allows Confirm Sync when every blocking window sets manualSync", () => {
    render(
      <SyncModal
        open
        namespace="ferriscd-system"
        name="payments-api"
        targetRevision="main"
        syncWindow={overridableSyncWindow}
        onClose={() => undefined}
        onConfirm={() => Promise.reject(new Error("not submitted"))}
      />,
    );
    expect(screen.getByTestId("sync-window-override")).toHaveTextContent(
      "Manual override applies",
    );
    expect(screen.getByRole("button", { name: /Confirm Sync/i })).toBeEnabled();
  });
});
