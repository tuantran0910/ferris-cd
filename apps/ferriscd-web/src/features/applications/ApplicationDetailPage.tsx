import {
  ArrowLeft,
  Clock,
  FileDiff,
  GitFork,
  History,
  RefreshCw,
  RotateCcw,
  ShieldOff,
  TriangleAlert,
} from "lucide-react";
import { useCallback, useState, type ReactNode } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import { ApiErrorAlert } from "../../ui/ApiErrorBoundary";
import { Button } from "../../ui/Button";
import { LiveRegion } from "../../ui/LiveRegion";
import { Skeleton } from "../../ui/Skeleton";
import { HealthStatusBadge, SyncStatusBadge } from "../../ui/StatusBadges";
import { DiffViewer } from "../diff/DiffViewer";
import { ResourceGraph } from "../resources/ResourceGraph";
import { RollbackModal } from "../sync/RollbackModal";
import { SyncModal } from "../sync/SyncModal";
import { ConditionsList } from "./components/ConditionsList";
import { EventsTimeline } from "./components/EventsTimeline";
import { HistoryTable } from "./components/HistoryTable";
import { OperationBanner } from "./components/OperationBanner";
import { SourcePanel } from "./components/SourcePanel";
import {
  useApplicationDetail,
  useApplicationEvents,
  useDiff,
  useInvalidateAfterOperation,
  useResources,
} from "./hooks";

const DETAIL_TABS = [
  "resources",
  "diff",
  "events",
  "conditions",
  "history",
] as const;

type DetailTab = (typeof DETAIL_TABS)[number];

/** The `?tab=` value, or the default tab for anything unrecognised (a stale bookmark). */
function detailTabFromParam(value: string | null): DetailTab {
  return DETAIL_TABS.find((tab) => tab === value) ?? "resources";
}

export function ApplicationDetailPage() {
  const { namespace = "", name = "" } = useParams<{
    namespace: string;
    name: string;
  }>();

  return (
    <ApplicationDetailContent
      key={`${namespace}/${name}`}
      namespace={namespace}
      name={name}
    />
  );
}

/**
 * Composition root for the detail screen: owns the URL/route wiring, the tab
 * state and the two mutation dialogs. Every panel below it is presentational
 * and gets its data from `./hooks`, so a poll re-render only touches the DOM of
 * the sections whose data actually changed.
 */
function ApplicationDetailContent({
  namespace,
  name,
}: {
  namespace: string;
  name: string;
}) {
  const { apiClient } = useAuth();
  const location = useLocation();
  // The list hands its filter/search state over so "Back to Applications"
  // restores the exact view the operator left.
  const listSearch = (
    location.state as { listSearch?: string } | null
  )?.listSearch ?? "";

  // The active tab lives in the URL (`?tab=events`) so the command palette, a
  // bookmark, or a link pasted into an incident channel can open a specific
  // section of a specific application.
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = detailTabFromParam(searchParams.get("tab"));
  const selectTab = useCallback(
    (tab: DetailTab) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          if (tab === "resources") {
            next.delete("tab");
          } else {
            next.set("tab", tab);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const [diffFilterKey, setDiffFilterKey] = useState("");
  const [syncModalOpen, setSyncModalOpen] = useState(false);
  const [rollbackModalOpen, setRollbackModalOpen] = useState(false);
  const [rollbackInitialId, setRollbackInitialId] = useState<number | null>(
    null,
  );
  const [syncForbidden, setSyncForbidden] = useState(false);
  const [rollbackForbidden, setRollbackForbidden] = useState(false);

  const detailQuery = useApplicationDetail(namespace, name);
  // Tabs drive fetching: the graph polls only while its tab is visible, the
  // diff is fetched on demand.
  const resourcesQuery = useResources(
    namespace,
    name,
    activeTab === "resources",
  );
  const diffQuery = useDiff(namespace, name, activeTab === "diff");
  // The events timeline is one namespaced `list` against the cluster, so it is fetched only while
  // its tab is open (like the resource graph).
  const eventsQuery = useApplicationEvents(
    namespace,
    name,
    activeTab === "events",
  );
  const invalidateAfterOperation = useInvalidateAfterOperation(namespace, name);

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (detailQuery.error || !detailQuery.data) {
    return (
      <div className="space-y-4">
        <Link
          to={{ pathname: "/", search: listSearch }}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-indigo-400 transition-colors hover:text-indigo-300"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Applications
        </Link>
        <ApiErrorAlert
          error={detailQuery.error}
          onRetry={() => void detailQuery.refetch()}
        />
      </div>
    );
  }

  const detail = detailQuery.data;
  const app = detail.application;
  const conditions = app.conditions ?? [];
  const history = detail.history ?? [];
  const operation = detail.operation ?? null;

  return (
    <div className="space-y-6">
      {/* The badges below change on every poll without any user action: the live region is what
          tells a screen reader operator that the sync or health verdict moved (`T17.3`). */}
      <LiveRegion
        message={`${app.name}: sync ${app.sync?.status ?? "Unknown"}, health ${
          app.health?.status ?? "Unknown"
        }${operation ? `, operation ${operation.phase}` : ""}.`}
        data-testid="application-status-live-region"
      />

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-2">
          <Link
            to={{ pathname: "/", search: listSearch }}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 transition-colors hover:text-indigo-300"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Applications
          </Link>

          <div className="flex flex-wrap items-center gap-3">
            <h1
              className="max-w-full break-all text-2xl font-bold tracking-tight text-slate-100"
              title={app.name}
            >
              {app.name}
            </h1>
            <span className="max-w-full truncate rounded-md border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-xs text-slate-300">
              {app.namespace}
            </span>
            <span className="max-w-full truncate rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2 py-0.5 font-mono text-xs text-indigo-300">
              project: {app.project}
            </span>
          </div>

          {/* Trap Guard T16.2: Strictly separate Sync Status & Health Status badges */}
          <div className="flex flex-wrap items-center gap-2.5 pt-1">
            <SyncStatusBadge status={app.sync?.status} />
            <HealthStatusBadge status={app.health?.status} />
            {app.health?.message && (
              <span className="text-xs text-slate-400">
                — {app.health.message}
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="primary"
            size="md"
            disabled={syncForbidden}
            title={
              syncForbidden
                ? "Disabled: RBAC 403 Forbidden for sync action"
                : "Request manual sync"
            }
            onClick={() => setSyncModalOpen(true)}
            icon={<RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />}
          >
            Sync
          </Button>

          <Button
            variant="warning"
            size="md"
            disabled={rollbackForbidden || history.length === 0}
            title={
              rollbackForbidden
                ? "Disabled: RBAC 403 Forbidden for rollback action"
                : history.length === 0
                  ? "No history available for rollback"
                  : "Roll back to a previous revision"
            }
            onClick={() => {
              setRollbackInitialId(null);
              setRollbackModalOpen(true);
            }}
            icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />}
          >
            Rollback
          </Button>
        </div>
      </div>

      {(syncForbidden || rollbackForbidden) && (
        <div
          role="status"
          data-testid="detail-rbac-readonly-notice"
          className="flex items-center gap-2 rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-2.5 text-xs text-rose-200 motion-fade-in"
        >
          <ShieldOff className="h-4 w-4 shrink-0 text-rose-400" />
          <span>
            Read-only RBAC mode: one or more mutation actions were denied (HTTP
            403 Forbidden) and have been disabled.
          </span>
        </div>
      )}

      {operation && (
        <OperationBanner operation={operation} repoUrl={app.source.repoUrl} />
      )}

      <SourcePanel app={app} />

      <div
        role="tablist"
        aria-label="Application detail sections"
        className="flex flex-wrap gap-1 border-b border-slate-800"
      >
        <TabButton
          active={activeTab === "resources"}
          tabKey="resources"
          onClick={() => selectTab("resources")}
          icon={<GitFork className="h-4 w-4" />}
          label={`Resources (${app.resourceCount})`}
        />
        <TabButton
          active={activeTab === "diff"}
          tabKey="diff"
          onClick={() => {
            setDiffFilterKey("");
            selectTab("diff");
          }}
          icon={<FileDiff className="h-4 w-4" />}
          label="Live Diff"
        />
        <TabButton
          active={activeTab === "events"}
          tabKey="events"
          onClick={() => selectTab("events")}
          icon={<TriangleAlert className="h-4 w-4" />}
          label="Events"
        />
        <TabButton
          active={activeTab === "conditions"}
          tabKey="conditions"
          onClick={() => selectTab("conditions")}
          icon={<Clock className="h-4 w-4" />}
          label={`Conditions (${conditions.length})`}
        />
        <TabButton
          active={activeTab === "history"}
          tabKey="history"
          onClick={() => selectTab("history")}
          icon={<History className="h-4 w-4" />}
          label={`History (${history.length})`}
        />
      </div>

      {/* The panel is keyed by tab so switching sections replays the fade
          instead of hard-cutting the content. */}
      <div
        role="tabpanel"
        id="app-tabpanel"
        aria-labelledby={`app-tab-${activeTab}`}
        key={activeTab}
        className="motion-fade-in"
      >
        {activeTab === "resources" && (
          <div>
            {resourcesQuery.isLoading ? (
              <Skeleton className="h-80" />
            ) : resourcesQuery.error ? (
              <ApiErrorAlert
                error={resourcesQuery.error}
                onRetry={() => void resourcesQuery.refetch()}
              />
            ) : resourcesQuery.data ? (
              <ResourceGraph
                appNamespace={app.namespace}
                appName={app.name}
                graph={resourcesQuery.data}
                onInspectDiff={(resourceKey) => {
                  setDiffFilterKey(resourceKey);
                  selectTab("diff");
                }}
              />
            ) : null}
          </div>
        )}

        {activeTab === "diff" && (
          <div>
            {diffQuery.isLoading ? (
              <Skeleton className="h-72" />
            ) : diffQuery.error ? (
              <ApiErrorAlert
                error={diffQuery.error}
                onRetry={() => void diffQuery.refetch()}
              />
            ) : diffQuery.data ? (
              <DiffViewer
                key={diffFilterKey}
                diff={diffQuery.data}
                initialSearch={diffFilterKey}
              />
            ) : null}
          </div>
        )}

        {activeTab === "events" && (
          <div>
            {eventsQuery.isLoading ? (
              <Skeleton className="h-64" />
            ) : eventsQuery.error ? (
              <ApiErrorAlert
                error={eventsQuery.error}
                onRetry={() => void eventsQuery.refetch()}
              />
            ) : eventsQuery.data ? (
              <EventsTimeline
                events={eventsQuery.data.items ?? []}
                truncated={eventsQuery.data.truncated}
              />
            ) : null}
          </div>
        )}

        {activeTab === "conditions" && (
          <ConditionsList conditions={conditions} />
        )}

        {activeTab === "history" && (
          <HistoryTable
            history={history}
            repoUrl={app.source.repoUrl}
            rollbackForbidden={rollbackForbidden}
            onRollback={(historyId) => {
              setRollbackInitialId(historyId);
              setRollbackModalOpen(true);
            }}
          />
        )}
      </div>

      <SyncModal
        open={syncModalOpen}
        namespace={app.namespace}
        name={app.name}
        targetRevision={app.source.targetRevision}
        disabledByRbac={syncForbidden}
        onClose={() => setSyncModalOpen(false)}
        onForbidden={() => setSyncForbidden(true)}
        onPreviewDiff={() => {
          setDiffFilterKey("");
          selectTab("diff");
        }}
        onConfirm={async (body) => {
          const res = await apiClient.syncApplication(
            app.namespace,
            app.name,
            body,
          );
          invalidateAfterOperation();
          return res;
        }}
      />

      <RollbackModal
        open={rollbackModalOpen}
        namespace={app.namespace}
        name={app.name}
        history={history}
        initialHistoryId={rollbackInitialId}
        disabledByRbac={rollbackForbidden}
        onClose={() => setRollbackModalOpen(false)}
        onForbidden={() => setRollbackForbidden(true)}
        onConfirm={async (body) => {
          const res = await apiClient.rollbackApplication(
            app.namespace,
            app.name,
            body,
          );
          invalidateAfterOperation();
          return res;
        }}
      />
    </div>
  );
}

function TabButton({
  active,
  tabKey,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  tabKey: string;
  onClick: () => void;
  icon: ReactNode;
  label: string;
}) {
  const onKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    const keys = ["ArrowRight", "ArrowLeft", "Home", "End"];
    if (!keys.includes(event.key)) {
      return;
    }
    event.preventDefault();
    const tabs = Array.from(
      event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]') ?? [],
    );
    const index = tabs.indexOf(event.currentTarget);
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? tabs.length - 1
          : event.key === "ArrowRight"
            ? (index + 1) % tabs.length
            : (index - 1 + tabs.length) % tabs.length;
    tabs[next]?.focus();
    tabs[next]?.click();
  };

  return (
    <button
      type="button"
      role="tab"
      id={`app-tab-${tabKey}`}
      aria-controls="app-tabpanel"
      aria-selected={active}
      tabIndex={active ? 0 : -1}
      onKeyDown={onKeyDown}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 border-b-2 px-4 py-2.5 text-xs font-semibold transition-colors ${
        active
          ? "border-indigo-500 text-indigo-300"
          : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
      }`}
    >
      {icon}
      {label}
    </button>
  );
}
