import { Layers, Server } from "lucide-react";
import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { ClusterView } from "../../api/types";
import { ApiErrorAlert } from "../../ui/ApiErrorBoundary";
import { Badge } from "../../ui/Badge";
import { Card } from "../../ui/Card";
import { EmptyState } from "../../ui/EmptyState";
import { LiveRegion } from "../../ui/LiveRegion";
import { Skeleton } from "../../ui/Skeleton";
import {
  HealthStatusBadge,
  normalizeHealthStatus,
  normalizeSyncStatus,
  SyncStatusBadge,
} from "../../ui/StatusBadges";
import { useApplications } from "../applications/hooks";
import { useClusters } from "./hooks";

interface ClusterRollup {
  total: number;
  outOfSync: number;
  healthy: number;
  degraded: number;
  progressing: number;
  missing: number;
  unknown: number;
}

const EMPTY_ROLLUP: ClusterRollup = {
  total: 0,
  outOfSync: 0,
  healthy: 0,
  degraded: 0,
  progressing: 0,
  missing: 0,
  unknown: 0,
};

/**
 * `/clusters` — the cluster registry this identity may deploy to (`T17.3`).
 *
 * `GET /api/v1/clusters` is already **project-scoped** (`T17.1`): the server answers `in-cluster`
 * plus only the remote clusters permitted by an `AppProject` the caller can see, so this page must
 * not (and cannot) reveal a cluster that belongs to another tenant. It adds the part the API does
 * not know: a health/sync rollup computed from the caller's own visible applications, so an operator
 * can tell a healthy cluster from a degraded one at a glance.
 */
export function ClustersPage() {
  const clustersQuery = useClusters();
  const applicationsQuery = useApplications();
  const [params] = useSearchParams();
  const filter = (params.get("q") ?? "").trim().toLowerCase();

  const allClusters = useMemo(
    () => clustersQuery.data?.items ?? [],
    [clustersQuery.data],
  );
  const clusters = useMemo(
    () =>
      filter
        ? allClusters.filter((cluster) =>
            cluster.name.toLowerCase().includes(filter),
          )
        : allClusters,
    [allClusters, filter],
  );
  const applications = useMemo(
    () => applicationsQuery.data?.items ?? [],
    [applicationsQuery.data],
  );

  const rollups = useMemo(() => {
    const byCluster = new Map<string, ClusterRollup>();
    for (const app of applications) {
      const cluster = app.destination?.cluster ?? "in-cluster";
      const rollup = byCluster.get(cluster) ?? { ...EMPTY_ROLLUP };
      rollup.total += 1;
      if (normalizeSyncStatus(app.sync?.status) === "OutOfSync") {
        rollup.outOfSync += 1;
      }
      switch (normalizeHealthStatus(app.health?.status)) {
        case "Healthy":
          rollup.healthy += 1;
          break;
        case "Degraded":
          rollup.degraded += 1;
          break;
        case "Progressing":
          rollup.progressing += 1;
          break;
        case "Missing":
          rollup.missing += 1;
          break;
        default:
          rollup.unknown += 1;
          break;
      }
      byCluster.set(cluster, rollup);
    }
    return byCluster;
  }, [applications]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-ink-strong">
          Clusters
        </h1>
        <p className="mt-1 text-xs text-ink-body">
          {!clustersQuery.data
            ? "Loading destination clusters…"
            : filter
              ? `${clusters.length} of ${allClusters.length} ${
                  allClusters.length === 1 ? "cluster" : "clusters"
                } ${clusters.length === 1 ? "matches" : "match"} “${filter}”`
              : clusters.length === 1
                ? "1 destination cluster visible to your identity"
                : `${clusters.length} destination clusters visible to your identity`}
          {" — "}
          filtered to the destinations your AppProjects allow.
        </p>
      </div>

      <LiveRegion
        message={
          clustersQuery.isSuccess
            ? `Showing ${clusters.length} clusters with ${applications.length} visible applications.`
            : ""
        }
        data-testid="clusters-live-region"
      />

      {clustersQuery.error && (
        <ApiErrorAlert
          error={clustersQuery.error}
          onRetry={() => void clustersQuery.refetch()}
        />
      )}

      {clustersQuery.isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {Array.from({ length: 2 }).map((_, index) => (
            <Skeleton key={index} className="h-40" />
          ))}
        </div>
      ) : !clustersQuery.data ? null : allClusters.length === 0 ? (
        <EmptyState size="lg">
          <p>
            No destination clusters are visible to your identity. A cluster appears here once one of
            your AppProjects lists it in <code className="font-mono">spec.destinations</code>.
          </p>
        </EmptyState>
      ) : clusters.length === 0 ? (
        <EmptyState size="lg">
          <p>
            No cluster matches <code className="font-mono">{filter}</code>.
          </p>
          <Link to="/clusters" className="text-accent hover:underline">
            Clear the filter
          </Link>
        </EmptyState>
      ) : (
        <ul className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {clusters.map((cluster) => (
            <li key={cluster.name}>
              <ClusterCard
                cluster={cluster}
                rollup={rollups.get(cluster.name) ?? EMPTY_ROLLUP}
              />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ClusterCard({
  cluster,
  rollup,
}: {
  cluster: ClusterView;
  rollup: ClusterRollup;
}) {
  const filterLink = {
    pathname: "/",
    search: `?${new URLSearchParams({ q: cluster.name }).toString()}`,
  };
  const worstSync: string | undefined =
    rollup.total === 0 ? undefined : rollup.outOfSync > 0 ? "OutOfSync" : "Synced";
  const worstHealth: string | undefined =
    rollup.total === 0
      ? undefined
      : rollup.degraded > 0
        ? "Degraded"
        : rollup.missing > 0
          ? "Missing"
          : rollup.progressing > 0
            ? "Progressing"
            : rollup.healthy > 0
              ? "Healthy"
              : "Unknown";

  return (
    <Card className="flex h-full flex-col gap-4" data-testid={`cluster-card-${cluster.name}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h2 className="flex min-w-0 items-center gap-2 text-base font-semibold text-ink-strong">
          <Server aria-hidden="true" className="h-4 w-4 text-success" />
          <Link
            to={filterLink}
            className="truncate rounded hover:underline"
            title={`Applications deployed to ${cluster.name}`}
          >
            {cluster.name}
          </Link>
        </h2>
        <Badge tone={cluster.inCluster ? "violet" : "info"} size="sm">
          {cluster.inCluster ? "in-cluster" : "remote"}
        </Badge>
      </div>

      <dl className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
        <Metric testId="applications" label="Applications" value={rollup.total} />
        <Metric
          testId="out-of-sync"
          label="Out of sync"
          value={rollup.outOfSync}
          emphasize={rollup.outOfSync > 0}
        />
        <Metric
          testId="degraded"
          label="Degraded"
          value={rollup.degraded}
          emphasize={rollup.degraded > 0}
        />
        <Metric testId="progressing" label="Progressing" value={rollup.progressing} />
      </dl>

      <div className="mt-auto flex flex-wrap items-center gap-2 text-xs">
        <span className="text-ink-body">Rollup:</span>
        {rollup.total === 0 ? (
          <span className="text-ink-body">no visible applications</span>
        ) : (
          <>
            <SyncStatusBadge status={worstSync} compact />
            <HealthStatusBadge status={worstHealth} compact />
          </>
        )}
      </div>

      {/* The per-application breakdown stays textual: a colour alone is never the only signal. */}
      <ul className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-ink-body">
        {healthBreakdown(rollup).map(({ status, count }) => (
          <li key={status} data-testid={`cluster-health-${status.toLowerCase()}`}>
            {status}:{" "}
            <span className="font-mono text-ink" data-testid="count">
              {count}
            </span>
          </li>
        ))}
      </ul>

      <p className="text-xs">
        <Link to={filterLink} className="font-medium text-accent hover:underline">
          View applications on this cluster
        </Link>
      </p>
    </Card>
  );
}

function healthBreakdown(rollup: ClusterRollup): { status: string; count: number }[] {
  return [
    { status: "Healthy", count: rollup.healthy },
    { status: "Progressing", count: rollup.progressing },
    { status: "Degraded", count: rollup.degraded },
    { status: "Missing", count: rollup.missing },
    { status: "Unknown", count: rollup.unknown },
  ];
}

function Metric({
  testId,
  label,
  value,
  emphasize = false,
}: {
  testId: string;
  label: string;
  value: number;
  emphasize?: boolean;
}) {
  return (
    <div>
      <dt className="text-ink-body">{label}</dt>
      <dd
        data-testid={`cluster-metric-${testId}`}
        className={`mt-0.5 flex items-center gap-1 font-mono text-sm ${
          emphasize ? "text-warning" : "text-ink-strong"
        }`}
      >
        <Layers aria-hidden="true" className="h-3.5 w-3.5 text-ink-muted" />
        {value}
      </dd>
    </div>
  );
}
