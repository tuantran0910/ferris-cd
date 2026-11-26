import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  Clock,
  FileDiff,
  FolderGit2,
  GitBranch,
  GitFork,
  History,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldOff,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiClientError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ApiErrorAlert } from "../components/ApiErrorBoundary";
import { DiffViewer } from "../components/DiffViewer";
import { ResourceGraph } from "../components/ResourceGraph";
import { RollbackModal } from "../components/RollbackModal";
import { HealthStatusBadge, SyncStatusBadge } from "../components/StatusBadges";
import { SyncModal } from "../components/SyncModal";

type DetailTab = "resources" | "diff" | "conditions" | "history";

const DETAIL_POLL_INTERVAL_MS = 10_000;

function pollUnlessTerminalError(query: {
  state: { error: unknown };
}): number | false {
  const err = query.state.error;
  if (err instanceof ApiClientError && (err.isForbidden || err.isNotFound)) {
    return false;
  }
  return DETAIL_POLL_INTERVAL_MS;
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

function ApplicationDetailContent({
  namespace,
  name,
}: {
  namespace: string;
  name: string;
}) {
  const { apiClient } = useAuth();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<DetailTab>("resources");
  const [diffFilterKey, setDiffFilterKey] = useState("");
  const [syncModalOpen, setSyncModalOpen] = useState(false);
  const [rollbackModalOpen, setRollbackModalOpen] = useState(false);
  const [rollbackInitialId, setRollbackInitialId] = useState<number | null>(
    null,
  );
  const [syncForbidden, setSyncForbidden] = useState(false);
  const [rollbackForbidden, setRollbackForbidden] = useState(false);

  const detailQuery = useQuery({
    queryKey: ["application", namespace, name],
    queryFn: () => apiClient.getApplication(namespace, name),
    enabled: Boolean(namespace && name),
    refetchInterval: pollUnlessTerminalError,
  });

  const resourcesQuery = useQuery({
    queryKey: ["application-resources", namespace, name],
    queryFn: () => apiClient.getResources(namespace, name),
    enabled: Boolean(namespace && name && activeTab === "resources"),
    refetchInterval: pollUnlessTerminalError,
  });

  const diffQuery = useQuery({
    queryKey: ["application-diff", namespace, name],
    queryFn: () => apiClient.getDiff(namespace, name),
    enabled: Boolean(namespace && name && activeTab === "diff"),
  });

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-24 animate-pulse rounded-xl border border-slate-800 bg-slate-900/60" />
        <div className="h-96 animate-pulse rounded-xl border border-slate-800 bg-slate-900/60" />
      </div>
    );
  }

  if (detailQuery.error || !detailQuery.data) {
    return (
      <div className="space-y-4">
        <Link
          to="/"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-indigo-400 hover:text-indigo-300"
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

  const invalidateAfterOperation = () => {
    void queryClient.invalidateQueries({
      queryKey: ["application", namespace, name],
    });
    void queryClient.invalidateQueries({
      queryKey: ["application-resources", namespace, name],
    });
    void queryClient.invalidateQueries({
      queryKey: ["application-diff", namespace, name],
    });
    void queryClient.invalidateQueries({ queryKey: ["applications"] });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-2">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-indigo-300"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Applications
          </Link>

          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">
              {app.name}
            </h1>
            <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-xs text-slate-300">
              {app.namespace}
            </span>
            <span className="rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2 py-0.5 font-mono text-xs text-indigo-300">
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
          <button
            type="button"
            disabled={syncForbidden}
            title={
              syncForbidden
                ? "Disabled: RBAC 403 Forbidden for sync action"
                : "Request manual sync"
            }
            onClick={() => setSyncModalOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Sync
          </button>

          <button
            type="button"
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
            className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/15 px-3.5 py-2 text-xs font-semibold text-amber-200 transition hover:bg-amber-500/25 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Rollback
          </button>
        </div>
      </div>

      {(syncForbidden || rollbackForbidden) && (
        <div
          role="status"
          data-testid="detail-rbac-readonly-notice"
          className="flex items-center gap-2 rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-2.5 text-xs text-rose-200"
        >
          <ShieldOff className="h-4 w-4 shrink-0 text-rose-400" />
          <span>
            Read-only RBAC mode: one or more mutation actions were denied (HTTP
            403 Forbidden) and have been disabled.
          </span>
        </div>
      )}

      {operation && (
        <section
          aria-label="Active operation state"
          className="rounded-xl border border-indigo-500/40 bg-indigo-950/30 px-4 py-3 text-xs text-indigo-100"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-indigo-400" />
              <span className="font-semibold">
                Operation: {operation.phase}
              </span>
              <span className="rounded bg-indigo-500/20 px-1.5 py-0.5 font-mono text-[11px]">
                wave {operation.currentWave}
              </span>
              {operation.revision && (
                <code className="font-mono text-indigo-200">
                  {operation.revision.slice(0, 12)}
                </code>
              )}
            </div>
            <span className="font-mono text-[11px] text-indigo-300">
              Started: {operation.startedAt}
              {operation.finishedAt ? ` • Finished: ${operation.finishedAt}` : ""}
            </span>
          </div>
          {operation.message && (
            <p className="mt-1.5 text-indigo-200/90">{operation.message}</p>
          )}
        </section>
      )}

      <section
        aria-label="Source and destination summary"
        className="grid grid-cols-1 gap-4 md:grid-cols-3"
      >
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-400">
            <FolderGit2 className="h-3.5 w-3.5 text-indigo-400" />
            Source
          </p>
          <dl className="mt-3 space-y-1.5">
            <div>
              <dt className="text-slate-500">Repository</dt>
              <dd className="break-all font-mono text-slate-200">
                {app.source.repoUrl}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Path</dt>
              <dd className="font-mono text-slate-200">{app.source.path}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Target Revision</dt>
              <dd className="font-mono text-slate-200">
                {app.source.targetRevision}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Renderer</dt>
              <dd className="font-mono text-slate-200">{app.source.renderer}</dd>
            </div>
          </dl>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-400">
            <Server className="h-3.5 w-3.5 text-emerald-400" />
            Destination
          </p>
          <dl className="mt-3 space-y-1.5">
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Cluster</dt>
              <dd className="font-mono text-slate-200">
                {app.destination.cluster}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Namespace</dt>
              <dd className="font-mono text-slate-200">
                {app.destination.namespace}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Tracked Resources</dt>
              <dd className="font-mono text-slate-200">{app.resourceCount}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Observed Generation</dt>
              <dd className="font-mono text-slate-200">
                {app.observedGeneration ?? "—"}
              </dd>
            </div>
          </dl>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-400">
            <GitBranch className="h-3.5 w-3.5 text-amber-400" />
            Sync Metadata
          </p>
          <dl className="mt-3 space-y-1.5">
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Rendered Revision</dt>
              <dd className="font-mono text-slate-200">
                {app.sync?.revision ? app.sync.revision.slice(0, 12) : "—"}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Last Synced Revision</dt>
              <dd className="font-mono text-slate-200">
                {app.sync?.lastSyncedRevision
                  ? app.sync.lastSyncedRevision.slice(0, 12)
                  : "—"}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-500">Last Synced At</dt>
              <dd className="font-mono text-slate-200">
                {app.sync?.lastSyncedAt ?? "—"}
              </dd>
            </div>
          </dl>
        </div>
      </section>

      <div
        role="tablist"
        aria-label="Application detail sections"
        className="flex flex-wrap gap-1 border-b border-slate-800"
      >
        <TabButton
          active={activeTab === "resources"}
          onClick={() => setActiveTab("resources")}
          icon={<GitFork className="h-4 w-4" />}
          label={`Resources (${app.resourceCount})`}
        />
        <TabButton
          active={activeTab === "diff"}
          onClick={() => {
            setDiffFilterKey("");
            setActiveTab("diff");
          }}
          icon={<FileDiff className="h-4 w-4" />}
          label="Live Diff"
        />
        <TabButton
          active={activeTab === "conditions"}
          onClick={() => setActiveTab("conditions")}
          icon={<Clock className="h-4 w-4" />}
          label={`Conditions (${conditions.length})`}
        />
        <TabButton
          active={activeTab === "history"}
          onClick={() => setActiveTab("history")}
          icon={<History className="h-4 w-4" />}
          label={`History (${history.length})`}
        />
      </div>

      <div role="tabpanel">
        {activeTab === "resources" && (
          <div>
            {resourcesQuery.isLoading ? (
              <div className="h-80 animate-pulse rounded-xl border border-slate-800 bg-slate-900/60" />
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
                  setActiveTab("diff");
                }}
              />
            ) : null}
          </div>
        )}

        {activeTab === "diff" && (
          <div>
            {diffQuery.isLoading ? (
              <div className="h-72 animate-pulse rounded-xl border border-slate-800 bg-slate-900/60" />
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

        {activeTab === "conditions" && (
          <section
            aria-label="Conditions timeline"
            data-testid="conditions-timeline"
            className="space-y-3"
          >
            {conditions.length === 0 ? (
              <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-8 text-center text-sm text-slate-400">
                No status conditions recorded yet.
              </div>
            ) : (
              <ol className="relative space-y-3 border-l border-slate-800 pl-6">
                {conditions.map((cond, idx) => {
                  const isTrue = cond.status === "True";
                  return (
                    <li
                      key={`${cond.type}-${cond.lastTransitionTime}-${idx}`}
                      className="relative rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs"
                    >
                      <span
                        className={`absolute -left-[33px] top-4 flex h-5 w-5 items-center justify-center rounded-full border ${
                          isTrue
                            ? "border-emerald-500/50 bg-emerald-950 text-emerald-400"
                            : "border-rose-500/50 bg-rose-950 text-rose-400"
                        }`}
                      >
                        {isTrue ? (
                          <CheckCircle2 className="h-3 w-3" />
                        ) : (
                          <XCircle className="h-3 w-3" />
                        )}
                      </span>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-100">
                            {cond.type}
                          </span>
                          <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">
                            status={cond.status}
                          </span>
                          <span className="rounded bg-indigo-500/15 px-1.5 py-0.5 font-mono text-[11px] text-indigo-300">
                            {cond.reason}
                          </span>
                        </div>
                        <time className="font-mono text-[11px] text-slate-400">
                          {cond.lastTransitionTime}
                        </time>
                      </div>
                      <p className="mt-2 leading-relaxed text-slate-300">
                        {cond.message}
                      </p>
                    </li>
                  );
                })}
              </ol>
            )}
          </section>
        )}

        {activeTab === "history" && (
          <section
            aria-label="Deployment history"
            data-testid="history-table"
            className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/70"
          >
            {history.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-400">
                No deployment history recorded yet.
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 bg-slate-900 text-[11px] uppercase tracking-wider text-slate-400">
                  <tr>
                    <th className="px-4 py-3">ID</th>
                    <th className="px-4 py-3">Revision</th>
                    <th className="px-4 py-3">Deployed At</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {[...history]
                    .sort((a, b) => b.id - a.id)
                    .map((entry) => (
                      <tr key={entry.id} className="hover:bg-slate-800/50">
                        <td className="px-4 py-3 font-mono font-semibold text-slate-100">
                          #{entry.id}
                        </td>
                        <td className="px-4 py-3 font-mono text-indigo-300">
                          {entry.revision ?? "—"}
                        </td>
                        <td className="px-4 py-3 font-mono text-slate-400">
                          {entry.deployedAt}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            type="button"
                            disabled={rollbackForbidden}
                            onClick={() => {
                              setRollbackInitialId(entry.id);
                              setRollbackModalOpen(true);
                            }}
                            className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[11px] font-medium text-amber-200 hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            <RotateCcw className="h-3 w-3" />
                            Rollback
                          </button>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </section>
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
          setActiveTab("diff");
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
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 border-b-2 px-4 py-2.5 text-xs font-semibold transition ${
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
