import { Ban, CalendarClock, Clock, ShieldAlert, ShieldCheck } from "lucide-react";
import type { ProjectSyncWindowView, SyncWindowGateView } from "../../api/types";
import { Badge } from "../../ui/Badge";
import { formatTimestamp } from "../../utils/format";

/**
 * Sync-window surfaces (`T17.4`).
 *
 * A deployment-governance window is a *time* policy, so the two things an operator must be able to
 * see are: which windows a project configures (and whether each one is open **now**), and — before
 * clicking Sync — whether the controller will actually apply the pass. `GET /api/v1/projects`
 * evaluates the windows server-side, so these components never parse a cron expression: the engine
 * that blocks the sync is the engine that produced these facts.
 */

/** The `allow`/`deny` + open/closed state of one window, as a compact row. */
export function SyncWindowRow({
  window,
  testId,
}: {
  window: ProjectSyncWindowView;
  testId?: string;
}) {
  const deny = window.kind === "deny";
  const state = window.error
    ? "invalid"
    : window.active
      ? "active"
      : window.nextStart
        ? "scheduled"
        : "never";
  const tone = window.error
    ? "danger"
    : window.active
      ? deny
        ? "danger"
        : "success"
      : "info";

  return (
    <li
      className="rounded-lg border border-line bg-canvas p-2.5"
      data-testid={testId}
      data-window-kind={window.kind}
      data-window-state={state}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone={tone} size="sm">
          {window.kind}
        </Badge>
        {/* Finding N2: an unparseable window has no open/closed state at all — that is the whole
            point of the error — so "Closed now" would be a claim the server never made. */}
        {!window.error &&
          (window.active ? (
            <Badge tone={deny ? "danger" : "success"} size="sm">
              Open now
            </Badge>
          ) : (
            <Badge tone="neutral" size="sm">
              Closed now
            </Badge>
          ))}
        {window.manualSync && (
          <Badge tone="warning" size="sm">
            manual override
          </Badge>
        )}
        <code className="break-all rounded border border-control bg-surface px-1.5 py-0.5 font-mono text-[11px] text-ink">
          {window.schedule}
        </code>
        <span className="text-[11px] text-ink-muted">
          for {window.duration} in {window.timeZone}
        </span>
      </div>

      <p className="mt-1 text-[11px] text-ink-body">
        {window.error ? (
          <span className="text-danger">
            Cannot be evaluated ({window.error}) — every sync of this project is denied until the
            schedule is fixed.
          </span>
        ) : window.active ? (
          <>
            Open until{" "}
            <time dateTime={window.endsAt ?? undefined}>
              {formatTimestamp(window.endsAt)}
            </time>
            , since {formatTimestamp(window.startsAt)}.
          </>
        ) : window.nextStart ? (
          <>
            Next opens{" "}
            <time dateTime={window.nextStart}>
              {formatTimestamp(window.nextStart)}
            </time>
            .
          </>
        ) : (
          <>This schedule does not fire within the next year.</>
        )}
        {scopeLabel(window) && (
          <span className="text-ink-muted"> Scope: {scopeLabel(window)}.</span>
        )}
      </p>
    </li>
  );
}

/** `applications=payments-* · namespaces=payments · clusters=prod-*`, or the empty (all) case. */
function scopeLabel(window: ProjectSyncWindowView): string {
  const parts: string[] = [];
  if (window.applications?.length) {
    parts.push(`applications=${window.applications.join(",")}`);
  }
  if (window.namespaces?.length) {
    parts.push(`namespaces=${window.namespaces.join(",")}`);
  }
  if (window.clusters?.length) {
    parts.push(`clusters=${window.clusters.join(",")}`);
  }
  return parts.join(" · ");
}

/**
 * The project-card panel: every window with its live state, plus the next transition.
 *
 * A project with no windows renders nothing at all: "no change freeze" is the absence of a policy,
 * not an empty box.
 */
export function SyncWindowsPanel({
  windows,
  nextTransition,
  testId,
}: {
  windows?: ProjectSyncWindowView[] | null;
  nextTransition?: string | null;
  testId?: string;
}) {
  if (!windows || windows.length === 0) {
    return null;
  }
  return (
    <div data-testid={testId}>
      <dt className="flex items-center gap-1.5 font-medium text-ink">
        <CalendarClock aria-hidden="true" className="h-3.5 w-3.5 text-warning" />
        Sync windows ({windows.length})
      </dt>
      <dd className="mt-1 space-y-1.5">
        <ul className="space-y-1.5">
          {windows.map((window, index) => (
            <SyncWindowRow
              key={`${window.kind}-${window.schedule}-${index}`}
              window={window}
              testId={testId ? `${testId}-${index}` : undefined}
            />
          ))}
        </ul>
        {nextTransition && (
          <p className="text-[11px] text-ink-muted">
            Next transition{" "}
            <time dateTime={nextTransition}>{formatTimestamp(nextTransition)}</time>.
          </p>
        )}
      </dd>
    </div>
  );
}

/**
 * The verdict banner the Sync dialog shows before submitting (`T17.4`).
 *
 * - blocked and not overridable → an `alert` and a disabled confirm button: requesting a sync the
 *   controller will skip only teaches the operator that "nothing happens";
 * - blocked but `manualSync: true` → a warning *with* the override: the click is honoured, and the
 *   operator is told they are breaking glass;
 * - not blocked → nothing (the dialog's normal content is the whole message).
 */
export function SyncWindowNotice({
  syncWindow,
  testId,
}: {
  syncWindow?: SyncWindowGateView | null;
  /** Overrides the default `sync-window-blocked`/`sync-window-override` test id (a page and its
   * dialog both render this notice, and each must stay addressable). */
  testId?: string;
}) {
  if (!syncWindow || !syncWindow.blocked) {
    return null;
  }
  const override = syncWindow.manualOverride;
  return (
    <div
      role={override ? "status" : "alert"}
      data-testid={
        testId ?? (override ? "sync-window-override" : "sync-window-blocked")
      }
      data-sync-window-reason={syncWindow.reason ?? "unknown"}
      className={`flex items-start gap-2.5 rounded-lg border p-3 text-xs motion-fade-in ${
        override
          ? "border-amber-500/40 bg-warning-tint text-warning"
          : "border-rose-500/40 bg-danger-tint text-danger"
      }`}
    >
      {override ? (
        <ShieldCheck aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
      ) : (
        <Ban aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
      )}
      <div>
        <p className="font-semibold">
          {override
            ? "Manual override applies"
            : "Blocked by an AppProject sync window"}
        </p>
        <p className="mt-0.5 break-words">{syncWindow.message}</p>
        {syncWindow.nextTransition && (
          <p className="mt-1 flex items-center gap-1.5 text-[11px] opacity-90">
            <Clock aria-hidden="true" className="h-3 w-3" />
            Next transition{" "}
            <time dateTime={syncWindow.nextTransition}>
              {formatTimestamp(syncWindow.nextTransition)}
            </time>
          </p>
        )}
        {!override && (
          <p className="mt-1 text-[11px] opacity-90">
            Drift is still detected and reported. Add{" "}
            <code className="font-mono">manualSync: true</code> to the window in{" "}
            <code className="font-mono">spec.syncWindows</code> if a manual sync should be
            allowed.
          </p>
        )}
        {/* Finding N4: this verdict is a snapshot, not a reservation — the window can close (or
            open) between the page load and the reconcile that submits. */}
        <p className="mt-1 text-[11px] opacity-75">
          Evaluated when this page was loaded; the controller re-evaluates the window on
          every pass, so a verdict can still change before the sync runs.
        </p>
      </div>
    </div>
  );
}

/** A one-line status badge for the application header, so "blocked" is visible before opening the dialog. */
export function SyncWindowBadge({
  syncWindow,
}: {
  syncWindow?: SyncWindowGateView | null;
}) {
  if (!syncWindow?.blocked) {
    return null;
  }
  return (
    <Badge
      tone={syncWindow.manualOverride ? "warning" : "danger"}
      size="sm"
      data-testid="sync-window-badge"
      title={syncWindow.message}
    >
      <ShieldAlert aria-hidden="true" className="mr-1 h-3 w-3" />
      {syncWindow.manualOverride ? "Sync window (override)" : "Sync window blocked"}
    </Badge>
  );
}
