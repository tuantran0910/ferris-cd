import {
  Activity,
  AlertTriangle,
  Gauge,
  Layers,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import { useMemo, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ApiErrorAlert } from "../../ui/ApiErrorBoundary";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { EmptyState } from "../../ui/EmptyState";
import { LiveRegion } from "../../ui/LiveRegion";
import { Skeleton } from "../../ui/Skeleton";
import {
  HealthStatusBadge,
  SyncStatusBadge,
  normalizeHealthStatus,
  normalizeSyncStatus,
} from "../../ui/StatusBadges";
import { useApplications } from "../applications/hooks";
import { useClusters } from "../clusters/hooks";
import { useProjects } from "../projects/hooks";
import {
  buildFleetRollup,
  percentOf,
  type FleetBucket,
  type RollupCounts,
} from "./rollup";

/** How many applications the triage queue lists before it links to the filtered list. */
export const TRIAGE_LIMIT = 8;

/**
 * `/overview` — the fleet-wide executive dashboard (`T20.5`).
 *
 * # What it aggregates, and from where
 *
 * Three endpoints, all of them already **project-scoped by the server** (`T14.4`, `T17.1`):
 * `GET /api/v1/applications` (filtered to the caller's projects), `GET /api/v1/clusters` (only the
 * destinations a visible `AppProject` allows) and `GET /api/v1/projects` (the caller's catalogue).
 * Every figure on the page is a rollup over that payload — see `rollup.ts` for the Trap Guard that
 * keeps a restricted tenant from ever seeing a cluster-wide total.
 *
 * The page never fetches a per-application diff: counting `Warn` advisories would cost one diff
 * computation per application, which is not a dashboard's job. A **blocking** `Enforce` violation
 * does surface here, because the controller already writes it into `Ready=False,
 * reason=PolicyGateViolation` (`PolicyViolation` is the different `AppProject` allow-list
 * verdict; both are counted).
 *
 * Accessibility (`WCAG 2.2 AA`): every figure is textual (a number plus its label, never a colour or
 * a bar alone), the two tables have captions and scoped headers, the KPIs are a description list,
 * and the live region announces the whole rollup on each poll so a screen-reader user is told when
 * the fleet changes.
 */
export function FleetOverviewPage() {
  const applicationsQuery = useApplications();
  const clustersQuery = useClusters();
  const projectsQuery = useProjects();

  const applications = useMemo(
    () => applicationsQuery.data?.items ?? [],
    [applicationsQuery.data],
  );
  const clusters = useMemo(
    () => (clustersQuery.data?.items ?? []).map((cluster) => cluster.name),
    [clustersQuery.data],
  );
  const projects = useMemo(
    () => (projectsQuery.data?.items ?? []).map((project) => project.name),
    [projectsQuery.data],
  );

  const rollup = useMemo(
    () => buildFleetRollup(applications, clusters, projects),
    [applications, clusters, projects],
  );

  const { totals } = rollup;
  // The KPI must agree with the queue rendered below it: `triage` is the one place
  // that decides what "needs attention" means, so reuse its count instead of
  // re-deriving a narrower sum (which silently dropped policy-blocked and
  // never-reconciled applications).
  const attention = rollup.triage.length;
  const isLoading = applicationsQuery.isLoading;
  const error =
    applicationsQuery.error ?? clustersQuery.error ?? projectsQuery.error;

  return (
    <div className="space-y-6">
      <LiveRegion
        message={
          applicationsQuery.data
            ? `Fleet overview: ${totals.total} applications visible, ${totals.outOfSync} out of sync, ${totals.degraded} degraded, ${totals.policyViolations} with a blocking policy violation.`
            : ""
        }
        data-testid="overview-live-region"
      />

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink-strong">
            Fleet overview
          </h1>
          <p className="mt-1 text-xs text-ink-body">
            {applicationsQuery.data
              ? `${totals.total} ${
                  totals.total === 1 ? "application" : "applications"
                } visible to your identity across ${rollup.byCluster.length} ${
                  rollup.byCluster.length === 1 ? "cluster" : "clusters"
                } and ${rollup.byProject.length} ${
                  rollup.byProject.length === 1 ? "project" : "projects"
                } — every figure is scoped to the projects your RBAC policy grants.`
              : "Loading the fleet rollup…"}
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => {
            void applicationsQuery.refetch();
            void clustersQuery.refetch();
            void projectsQuery.refetch();
          }}
          icon={
            <RefreshCw
              className={`h-3.5 w-3.5 ${
                applicationsQuery.isFetching ? "animate-spin text-accent" : ""
              }`}
              aria-hidden="true"
            />
          }
          className="px-3 py-1.5"
        >
          Refresh
        </Button>
      </div>

      {error && (
        <ApiErrorAlert
          error={error}
          onRetry={() => {
            // `error` covers all three queries, so retrying only the application list
            // would leave a clusters/projects failure on screen forever.
            void applicationsQuery.refetch();
            void clustersQuery.refetch();
            void projectsQuery.refetch();
          }}
        />
      )}

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
          {Array.from({ length: 5 }).map((_, index) => (
            <Skeleton key={index} className="h-28" />
          ))}
        </div>
      ) : !applicationsQuery.data ? null : totals.total === 0 ? (
        <EmptyState size="lg">
          <p>No Applications are visible to your identity.</p>
          <p className="mt-2 text-xs text-ink-muted">
            The fleet rollup counts only what your RBAC grants can read, so an empty
            overview means every application belongs to a project you cannot see.
          </p>
        </EmptyState>
      ) : (
        <>
          <section aria-label="Fleet key figures">
            <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
              <Kpi
                testId="total"
                label="Applications"
                value={totals.total}
                detail={`${rollup.resources} tracked resources`}
                icon={<Layers aria-hidden="true" className="h-4 w-4" />}
              />
              <Kpi
                testId="synced"
                label="In sync"
                value={totals.synced}
                detail={`${percentOf(totals.synced, totals.total)}% of the fleet`}
                icon={<Activity aria-hidden="true" className="h-4 w-4" />}
              />
              <Kpi
                testId="out-of-sync"
                label="Out of sync"
                value={totals.outOfSync}
                detail={`${percentOf(totals.outOfSync, totals.total)}% of the fleet`}
                emphasize={totals.outOfSync > 0}
                icon={<Gauge aria-hidden="true" className="h-4 w-4" />}
              />
              <Kpi
                testId="degraded"
                label="Degraded or missing"
                value={totals.degraded + totals.missing}
                detail={`${totals.degraded} degraded · ${totals.missing} missing`}
                emphasize={totals.degraded + totals.missing > 0}
                icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
              />
              <Kpi
                testId="policy-violations"
                label="Policy violations"
                value={totals.policyViolations}
                detail={
                  totals.policyViolations > 0
                    ? "blocked by an Enforce rule"
                    : "no blocking rule is failing"
                }
                emphasize={totals.policyViolations > 0}
                icon={<ShieldAlert aria-hidden="true" className="h-4 w-4" />}
              />
            </dl>
          </section>

          <section aria-label="Health distribution">
            <Card className="flex flex-wrap items-center gap-x-6 gap-y-2">
              <h2 className="text-sm font-semibold text-ink-strong">
                Health distribution
              </h2>
              <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-body">
                {healthDistribution(totals).map(({ status, count }) => (
                  <li
                    key={status}
                    data-testid={`overview-health-${status.toLowerCase()}`}
                    className="flex items-center gap-1.5"
                  >
                    <span>{status}:</span>
                    <span className="font-mono text-ink">{count}</span>
                  </li>
                ))}
              </ul>
              <span className="text-xs text-ink-body">
                {attention > 0
                  ? `${attention} of ${totals.total} applications need attention`
                  : "no visible application needs attention"}
              </span>
            </Card>
          </section>

          <BreakdownTable
            testId="overview-clusters"
            title="Cluster breakdown"
            caption="Applications, sync state and blocking policy violations per destination cluster, computed only from the applications your identity can see."
            keyHeader="Cluster"
            linkFor={(bucket) => ({
              pathname: "/",
              // Exact cluster filter: `q` is a substring search, so a cluster named
              // `prod` would also list `prod-us` applications.
              search: `?${new URLSearchParams({ cluster: bucket.key }).toString()}`,
            })}
            buckets={rollup.byCluster}
            emptyMessage="No destination clusters are visible to your identity."
          />

          <BreakdownTable
            testId="overview-projects"
            title="Project breakdown"
            caption="Applications, sync state and blocking policy violations per project, restricted to the projects your RBAC policy grants."
            keyHeader="Project"
            linkFor={(bucket) => ({
              pathname: "/",
              search: `?${new URLSearchParams({ project: bucket.key }).toString()}`,
            })}
            buckets={rollup.byProject}
            emptyMessage="No projects are visible to your identity."
          />

          <section aria-label="Degraded application triage">
            <Card disablePadding className="overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
                <h2 className="text-sm font-semibold text-ink-strong">
                  Triage queue
                </h2>
                <p className="text-xs text-ink-body">
                  {rollup.triage.length === 0
                    ? "nothing to triage"
                    : `${rollup.triage.length} ${
                        rollup.triage.length === 1
                          ? "application needs"
                          : "applications need"
                      } attention`}
                </p>
              </div>
              {rollup.triage.length === 0 ? (
                <EmptyState bordered={false} size="sm">
                  <p>
                    Every application visible to your identity is synced, healthy,
                    and passing its policy rules.
                  </p>
                </EmptyState>
              ) : (
                <>
                  <ul
                    data-testid="overview-triage"
                    className="divide-y divide-line"
                  >
                    {rollup.triage.slice(0, TRIAGE_LIMIT).map((entry) => (
                      <li
                        key={`${entry.app.namespace}/${entry.app.name}`}
                        data-testid={`overview-triage-${entry.app.namespace}-${entry.app.name}`}
                        className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                      >
                        <div className="min-w-0">
                          <Link
                            to={`/applications/${encodeURIComponent(
                              entry.app.namespace,
                            )}/${encodeURIComponent(entry.app.name)}`}
                            className="block truncate font-semibold text-accent hover:underline"
                            title={`${entry.app.namespace}/${entry.app.name}`}
                          >
                            {entry.app.namespace}/{entry.app.name}
                          </Link>
                          <p className="mt-0.5 truncate text-xs text-ink-body">
                            {entry.app.project} · {entry.app.destination.cluster}/
                            {entry.app.destination.namespace} ·{" "}
                            {entry.reasons.join("; ")}
                          </p>
                        </div>
                        <div className="flex shrink-0 flex-wrap items-center gap-2">
                          <SyncStatusBadge
                            status={normalizeSyncStatus(entry.app.sync?.status)}
                            compact
                          />
                          <HealthStatusBadge
                            status={normalizeHealthStatus(
                              entry.app.health?.status,
                            )}
                            compact
                          />
                        </div>
                      </li>
                    ))}
                  </ul>
                  {rollup.triage.length > TRIAGE_LIMIT && (
                    <p className="border-t border-line px-4 py-3 text-xs text-ink-body">
                      Showing the {TRIAGE_LIMIT} most urgent of{" "}
                      {rollup.triage.length}.{" "}
                      <Link
                        to="/"
                        className="font-medium text-accent hover:underline"
                      >
                        Review every application
                      </Link>
                    </p>
                  )}
                </>
              )}
            </Card>
          </section>
        </>
      )}
    </div>
  );
}

function healthDistribution(
  totals: RollupCounts,
): { status: string; count: number }[] {
  return [
    { status: "Healthy", count: totals.healthy },
    { status: "Progressing", count: totals.progressing },
    { status: "Degraded", count: totals.degraded },
    { status: "Suspended", count: totals.suspended },
    { status: "Missing", count: totals.missing },
    { status: "Unknown", count: totals.unknownHealth },
  ];
}

function Kpi({
  testId,
  label,
  value,
  detail,
  emphasize = false,
  icon,
}: {
  testId: string;
  label: string;
  value: number;
  detail: string;
  emphasize?: boolean;
  icon: ReactNode;
}) {
  return (
    <Card className="flex flex-col gap-1" data-testid={`overview-kpi-${testId}`}>
      <dt className="flex items-center gap-1.5 text-xs text-ink-body">
        <span className="text-ink-muted">{icon}</span>
        {label}
      </dt>
      {/* The description list holds exactly one `dt`/`dd` pair per card: axe's `definition-list`
          rule rejects anything else directly inside a `dl` group, so the sub-label lives inside the
          `dd` rather than beside it. */}
      <dd className="flex flex-col gap-1">
        <span
          data-testid={`overview-kpi-${testId}-value`}
          className={`font-mono text-2xl tracking-tight ${
            emphasize ? "text-warning" : "text-ink-strong"
          }`}
        >
          {value}
        </span>
        <span className="text-[11px] text-ink-muted">{detail}</span>
      </dd>
    </Card>
  );
}

function BreakdownTable({
  testId,
  title,
  caption,
  keyHeader,
  linkFor,
  buckets,
  emptyMessage,
}: {
  testId: string;
  title: string;
  caption: string;
  keyHeader: string;
  linkFor: (bucket: FleetBucket) => { pathname: string; search: string };
  buckets: readonly FleetBucket[];
  emptyMessage: string;
}) {
  return (
    <section aria-label={title}>
      <Card disablePadding className="overflow-hidden">
        <h2 className="border-b border-line px-4 py-3 text-sm font-semibold text-ink-strong">
          {title}
        </h2>
        {buckets.length === 0 ? (
          <EmptyState bordered={false} size="sm">
            <p>{emptyMessage}</p>
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table data-testid={testId} className="w-full text-left text-xs">
              <caption className="sr-only">{caption}</caption>
              <thead className="bg-surface text-[11px] uppercase tracking-wider text-ink-muted">
                <tr>
                  <th scope="col" className="px-4 py-2.5">
                    {keyHeader}
                  </th>
                  <th scope="col" className="px-4 py-2.5 text-right">
                    Applications
                  </th>
                  <th scope="col" className="px-4 py-2.5 text-right">
                    Out of sync
                  </th>
                  <th scope="col" className="px-4 py-2.5 text-right">
                    Degraded
                  </th>
                  <th scope="col" className="px-4 py-2.5 text-right">
                    Missing
                  </th>
                  <th scope="col" className="px-4 py-2.5 text-right">
                    Policy violations
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {buckets.map((bucket) => (
                  <tr
                    key={bucket.key}
                    data-testid={`${testId}-${bucket.key}`}
                    className="transition-colors hover:bg-elevated"
                  >
                    <th
                      scope="row"
                      className="max-w-[220px] truncate px-4 py-2.5 text-left font-mono font-medium text-ink-body"
                    >
                      <Link
                        to={linkFor(bucket)}
                        className="rounded text-accent hover:underline"
                        title={`Filter applications by ${bucket.key}`}
                      >
                        {bucket.key}
                      </Link>
                    </th>
                    <Cell value={bucket.counts.total} />
                    <Cell value={bucket.counts.outOfSync} />
                    <Cell value={bucket.counts.degraded} />
                    <Cell value={bucket.counts.missing} />
                    <Cell value={bucket.counts.policyViolations} />
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </section>
  );
}

function Cell({ value }: { value: number }) {
  return (
    <td
      className={`px-4 py-2.5 text-right font-mono ${
        value > 0 ? "text-ink-strong" : "text-ink-muted"
      }`}
    >
      {value}
    </td>
  );
}
