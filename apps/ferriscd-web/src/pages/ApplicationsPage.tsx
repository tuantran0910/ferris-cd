import { useQuery } from "@tanstack/react-query";
import {
  Box,
  FolderGit2,
  GitBranch,
  LayoutGrid,
  List,
  RefreshCw,
  Search,
  Server,
} from "lucide-react";
import { useCallback, useMemo } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import type { ApplicationSummary } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ApiErrorAlert } from "../components/ApiErrorBoundary";
import {
  HealthStatusBadge,
  normalizeHealthStatus,
  normalizeSyncStatus,
  SyncStatusBadge,
} from "../components/StatusBadges";
import { shortRevision } from "../utils/format";

export const APPLICATIONS_POLL_INTERVAL_MS = 10_000;

const CANONICAL_SYNC_STATUSES = ["Synced", "OutOfSync", "Unknown"] as const;
const CANONICAL_HEALTH_STATUSES = [
  "Healthy",
  "Progressing",
  "Degraded",
  "Suspended",
  "Missing",
  "Unknown",
] as const;

const ALL = "ALL";

/**
 * Filter/view state lives in the URL (not component state) so a filtered view
 * survives drilling into an Application and coming back, and so it can be
 * bookmarked or pasted into an incident channel.
 */
const FILTER_PARAMS = {
  view: "view",
  search: "q",
  project: "project",
  sync: "sync",
  health: "health",
} as const;

export function ApplicationsPage() {
  const { apiClient } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  // Carried into the detail route so "Back to Applications" returns to the
  // same filtered view instead of a pristine list.
  const listState = useMemo(
    () => ({ listSearch: location.search }),
    [location.search],
  );

  const viewMode = searchParams.get(FILTER_PARAMS.view) === "table" ? "table" : "grid";
  const search = searchParams.get(FILTER_PARAMS.search) ?? "";
  const projectFilter = searchParams.get(FILTER_PARAMS.project) ?? ALL;
  const syncFilter = searchParams.get(FILTER_PARAMS.sync) ?? ALL;
  const healthFilter = searchParams.get(FILTER_PARAMS.health) ?? ALL;

  const setParam = useCallback(
    (key: string, value: string, defaultValue = "") => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          if (!value || value === defaultValue) {
            next.delete(key);
          } else {
            next.set(key, value);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const clearFilters = useCallback(() => {
    setSearchParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        for (const key of Object.values(FILTER_PARAMS)) {
          next.delete(key);
        }
        return next;
      },
      { replace: true },
    );
  }, [setSearchParams]);

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ["applications"],
    queryFn: () => apiClient.listApplications(),
    refetchInterval: APPLICATIONS_POLL_INTERVAL_MS,
  });

  const apps: ApplicationSummary[] = useMemo(() => data?.items ?? [], [data]);

  const projects = useMemo(() => {
    const set = new Set(apps.map((a) => a.project));
    if (projectFilter !== ALL) {
      set.add(projectFilter);
    }
    return Array.from(set).sort();
  }, [apps, projectFilter]);

  const syncStatuses = useMemo(() => {
    const set = new Set<string>(CANONICAL_SYNC_STATUSES);
    for (const a of apps) {
      set.add(normalizeSyncStatus(a.sync?.status));
    }
    if (syncFilter !== ALL) {
      set.add(syncFilter);
    }
    return Array.from(set);
  }, [apps, syncFilter]);

  const healthStatuses = useMemo(() => {
    const set = new Set<string>(CANONICAL_HEALTH_STATUSES);
    for (const a of apps) {
      set.add(normalizeHealthStatus(a.health?.status));
    }
    if (healthFilter !== ALL) {
      set.add(healthFilter);
    }
    return Array.from(set);
  }, [apps, healthFilter]);

  const filteredApps = useMemo(() => {
    const q = search.trim().toLowerCase();
    return apps.filter((app) => {
      if (projectFilter !== ALL && app.project !== projectFilter) {
        return false;
      }
      if (
        syncFilter !== ALL &&
        normalizeSyncStatus(app.sync?.status) !== syncFilter
      ) {
        return false;
      }
      if (
        healthFilter !== ALL &&
        normalizeHealthStatus(app.health?.status) !== healthFilter
      ) {
        return false;
      }
      if (!q) {
        return true;
      }
      return (
        app.name.toLowerCase().includes(q) ||
        app.namespace.toLowerCase().includes(q) ||
        app.project.toLowerCase().includes(q) ||
        app.source.repoUrl.toLowerCase().includes(q) ||
        app.destination.cluster.toLowerCase().includes(q) ||
        app.destination.namespace.toLowerCase().includes(q)
      );
    });
  }, [apps, projectFilter, syncFilter, healthFilter, search]);

  const filtersActive =
    search.trim().length > 0 ||
    projectFilter !== ALL ||
    syncFilter !== ALL ||
    healthFilter !== ALL;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Applications
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Showing {filteredApps.length} of {apps.length} watched applications
            • Live polling every {APPLICATIONS_POLL_INTERVAL_MS / 1000}s
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void refetch()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${isFetching ? "animate-spin text-indigo-400" : ""}`}
              aria-hidden="true"
            />
            Refresh
          </button>

          <div
            role="group"
            aria-label="Applications layout"
            className="inline-flex rounded-lg border border-slate-700 bg-slate-900 p-0.5"
          >
            <button
              type="button"
              aria-label="Grid view"
              aria-pressed={viewMode === "grid"}
              onClick={() => setParam(FILTER_PARAMS.view, "grid", "grid")}
              className={`rounded-md p-1.5 ${
                viewMode === "grid"
                  ? "bg-indigo-600 text-white"
                  : "text-slate-400 hover:text-slate-100"
              }`}
            >
              <LayoutGrid className="h-4 w-4" />
            </button>
            <button
              type="button"
              aria-label="Table view"
              aria-pressed={viewMode === "table"}
              onClick={() => setParam(FILTER_PARAMS.view, "table", "grid")}
              className={`rounded-md p-1.5 ${
                viewMode === "table"
                  ? "bg-indigo-600 text-white"
                  : "text-slate-400 hover:text-slate-100"
              }`}
            >
              <List className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      <section
        aria-label="Application filters"
        className="grid grid-cols-1 gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:grid-cols-2 lg:grid-cols-5"
      >
        <div className="relative lg:col-span-2">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="search"
            aria-label="Search applications"
            value={search}
            onChange={(e) => setParam(FILTER_PARAMS.search, e.target.value)}
            placeholder="Search by name, namespace, repo, or cluster..."
            className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-xs text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <select
          aria-label="Filter by project"
          value={projectFilter}
          onChange={(e) => setParam(FILTER_PARAMS.project, e.target.value, ALL)}
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
        >
          <option value="ALL">All Projects</option>
          {projects.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by sync status"
          value={syncFilter}
          onChange={(e) => setParam(FILTER_PARAMS.sync, e.target.value, ALL)}
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
        >
          <option value="ALL">All Sync Statuses</option>
          {syncStatuses.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by health status"
          value={healthFilter}
          onChange={(e) => setParam(FILTER_PARAMS.health, e.target.value, ALL)}
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
        >
          <option value="ALL">All Health Statuses</option>
          {healthStatuses.map((h) => (
            <option key={h} value={h}>
              {h}
            </option>
          ))}
        </select>
      </section>

      {error && <ApiErrorAlert error={error} onRetry={() => void refetch()} />}

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-44 animate-pulse rounded-xl border border-slate-800 bg-slate-900/50"
            />
          ))}
        </div>
      ) : !data ? (
        // Failed initial load: the alert above is the whole story. Claiming
        // "No Applications visible to your identity" here would blame RBAC for
        // an API/network failure.
        null
      ) : filteredApps.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-12 text-center text-sm text-slate-400">
          <p>
            {apps.length === 0
              ? "No Applications visible to your identity."
              : "No Applications match the current filters."}
          </p>
          {apps.length > 0 && filtersActive && (
            <button
              type="button"
              onClick={clearFilters}
              className="mt-3 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : viewMode === "grid" ? (
        <div
          data-testid="applications-grid"
          className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3"
        >
          {filteredApps.map((app) => (
            <Link
              key={`${app.namespace}/${app.name}`}
              to={`/applications/${encodeURIComponent(app.namespace)}/${encodeURIComponent(app.name)}`}
              state={listState}
              data-testid={`app-card-${app.namespace}-${app.name}`}
              className="group flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/70 p-4 transition hover:border-indigo-500/60 hover:bg-slate-900"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p
                      className="truncate font-mono text-[11px] text-slate-400"
                      title={app.namespace}
                    >
                      {app.namespace}
                    </p>
                    <h2
                      className="truncate text-base font-semibold text-slate-100 group-hover:text-indigo-300"
                      title={app.name}
                    >
                      {app.name}
                    </h2>
                  </div>
                  <span
                    className="max-w-[45%] shrink-0 truncate rounded-md border border-slate-700 bg-slate-950 px-2 py-0.5 font-mono text-[11px] text-slate-300"
                    title={app.project}
                  >
                    {app.project}
                  </span>
                </div>

                {/* Trap Guard T16.2: Always render separate Sync & Health badges */}
                <div className="mt-3 flex flex-wrap gap-2">
                  <SyncStatusBadge status={app.sync?.status} />
                  <HealthStatusBadge status={app.health?.status} />
                </div>

                <dl className="mt-4 space-y-1.5 text-xs text-slate-400">
                  <div className="flex items-center gap-2">
                    <FolderGit2 className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                    <span
                      className="min-w-0 truncate font-mono text-slate-300"
                      title={app.source.repoUrl}
                    >
                      {app.source.repoUrl}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <GitBranch className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                    <span
                      className="min-w-0 truncate font-mono"
                      title={`${app.source.targetRevision} @ ${app.sync?.revision ?? "unknown revision"}`}
                    >
                      {app.source.targetRevision} (
                      {shortRevision(app.sync?.revision)})
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Server className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                    <span className="min-w-0 truncate font-mono">
                      {app.destination.cluster} / {app.destination.namespace}
                    </span>
                  </div>
                </dl>
              </div>

              <div className="mt-4 flex items-center justify-between border-t border-slate-800/80 pt-3 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1">
                  <Box className="h-3.5 w-3.5 text-slate-500" />
                  {app.resourceCount} resources
                </span>
                <span className="font-mono text-slate-500">
                  {app.source.renderer}
                </span>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <div
          data-testid="applications-table"
          className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/70"
        >
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-900 text-[11px] uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-4 py-3">Application</th>
                <th className="px-4 py-3">Project</th>
                <th className="px-4 py-3">Sync Status</th>
                <th className="px-4 py-3">Health Status</th>
                <th className="px-4 py-3">Revision</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3 text-right">Resources</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredApps.map((app) => (
                <tr
                  key={`${app.namespace}/${app.name}`}
                  className="hover:bg-slate-800/50"
                >
                  <td className="max-w-[280px] px-4 py-3">
                    <Link
                      to={`/applications/${encodeURIComponent(app.namespace)}/${encodeURIComponent(app.name)}`}
                      state={listState}
                      className="block truncate font-semibold text-indigo-300 hover:underline"
                      title={`${app.namespace}/${app.name}`}
                    >
                      {app.namespace}/{app.name}
                    </Link>
                  </td>
                  <td className="max-w-[160px] truncate px-4 py-3 font-mono text-slate-300">
                    {app.project}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    <SyncStatusBadge status={app.sync?.status} compact />
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    <HealthStatusBadge status={app.health?.status} compact />
                  </td>
                  <td
                    className="px-4 py-3 font-mono text-slate-300"
                    title={app.sync?.revision ?? undefined}
                  >
                    {shortRevision(app.sync?.revision, 12)}
                  </td>
                  <td className="max-w-[200px] truncate px-4 py-3 font-mono text-slate-400">
                    {app.destination.cluster}/{app.destination.namespace}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-slate-300">
                    {app.resourceCount}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
