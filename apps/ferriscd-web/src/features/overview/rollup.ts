import type { ApplicationSummary } from "../../api/types";
import {
  normalizeHealthStatus,
  normalizeSyncStatus,
} from "../../ui/StatusBadges";

/**
 * Pure fleet-wide rollups for the Fleet Overview dashboard (`T20.5`).
 *
 * # The Trap Guard this module exists to keep
 *
 * `GET /api/v1/applications` is **already filtered by the server** to the projects the caller may
 * see (`T14.4`): an application in a project the caller has no grant on is absent from the payload,
 * and the response never reports how many were filtered out. A fleet-wide dashboard is exactly the
 * surface that can undo that guarantee — one `SUM` over "everything in the cluster" and a restricted
 * tenant learns another tenant's application count.
 *
 * So every number the overview renders is derived from the `ApplicationSummary[]` the server
 * returned, and from nothing else: there is no cluster-wide constant, no second (unscoped) source,
 * and no "expected total" to compare against. The functions here are pure and take the list as
 * their only input, which is what makes the RBAC-scoping property testable — feed them one tenant's
 * slice and every bucket can only ever contain that slice.
 *
 * # Shard ownership is not in this data
 *
 * `T13.3` shard assignment (`sha256(namespace, name) % totalShards`) is a control-plane capacity
 * decision computed inside each controller replica from the object's own identity; it is not part of
 * the application payload, and a single API replica cannot report which shard owns a *different*
 * replica's work. The overview therefore breaks the fleet down by the two dimensions the API does
 * expose — destination **cluster** and **project** (the tenant partition RBAC scopes on) — and the
 * per-shard numbers live in the benchmark (`docs/benchmarks/v2.0.md`), sampled per shard from each
 * replica's `/metrics` listener.
 */

/** `status.conditions[].reason` the controller writes when a `T20.2` `Enforce` rule blocks a sync. */
export const POLICY_VIOLATION_REASON = "PolicyViolation";

/** Counts of one slice of the fleet (the whole visible set, one cluster, or one project). */
export interface RollupCounts {
  /** Applications in the slice. */
  total: number;
  /** `sync.status: Synced`. */
  synced: number;
  /** `sync.status: OutOfSync`. */
  outOfSync: number;
  /** No sync verdict at all (never reconciled). */
  unknownSync: number;
  /** `health.status: Healthy`. */
  healthy: number;
  /** `health.status: Progressing`. */
  progressing: number;
  /** `health.status: Degraded`. */
  degraded: number;
  /** `health.status: Suspended`. */
  suspended: number;
  /** `health.status: Missing`. */
  missing: number;
  /** No health verdict at all. */
  unknownHealth: number;
  /** Applications whose latest `Ready` condition blames a blocking policy rule. */
  policyViolations: number;
}

/** A zeroed count set; spreads into a fresh object at every slice. */
export const EMPTY_COUNTS: RollupCounts = {
  total: 0,
  synced: 0,
  outOfSync: 0,
  unknownSync: 0,
  healthy: 0,
  progressing: 0,
  degraded: 0,
  suspended: 0,
  missing: 0,
  unknownHealth: 0,
  policyViolations: 0,
};

/** One named slice of the fleet (a cluster, or a project). */
export interface FleetBucket {
  /** Cluster name or project name. */
  key: string;
  /** Counts over the applications in this slice only. */
  counts: RollupCounts;
}

/** One application the operator has to look at, with why and how urgently. */
export interface TriageEntry {
  /** The application as the list endpoint returned it. */
  app: ApplicationSummary;
  /** Lower is more urgent (`0` = a blocking policy violation). */
  severity: number;
  /** Short, human-readable reasons, most urgent first. */
  reasons: string[];
}

/** The whole dashboard's data, computed in one pass. */
export interface FleetRollup {
  /** Counts over every visible application. */
  totals: RollupCounts;
  /** Per destination cluster, sorted by key (`in-cluster` first). */
  byCluster: FleetBucket[];
  /** Per project, sorted by key. */
  byProject: FleetBucket[];
  /** Applications needing attention, most urgent first (ties broken by `namespace/name`). */
  triage: TriageEntry[];
  /** Resources tracked across the visible applications. */
  resources: number;
}

/**
 * Whether the application's latest `Ready` condition reports a blocking policy violation.
 *
 * The controller patches `Ready=False, reason=PolicyViolation` when the `T20.2` gate refuses a
 * bundle, so this is the only policy signal a *list* response carries: `Warn` (advisory) rules do
 * not fail a sync and therefore produce no condition. Advisory violations are shown per application
 * in the diff view, which is where the rule-level detail already lives — the dashboard deliberately
 * does not fetch a diff per application to count them.
 */
export function hasBlockingPolicyViolation(app: ApplicationSummary): boolean {
  const conditions = app.conditions ?? [];
  // `conditions` are newest last, so the last `Ready` is the current verdict.
  for (let index = conditions.length - 1; index >= 0; index -= 1) {
    const condition = conditions[index];
    if (condition && condition.type === "Ready") {
      return condition.reason === POLICY_VIOLATION_REASON;
    }
  }
  return false;
}

/** Adds one application to a count set (mutates and returns `counts` for caller convenience). */
export function addApplicationCounts(
  counts: RollupCounts,
  app: ApplicationSummary,
): RollupCounts {
  counts.total += 1;
  switch (normalizeSyncStatus(app.sync?.status)) {
    case "Synced":
      counts.synced += 1;
      break;
    case "OutOfSync":
      counts.outOfSync += 1;
      break;
    default:
      counts.unknownSync += 1;
      break;
  }
  switch (normalizeHealthStatus(app.health?.status)) {
    case "Healthy":
      counts.healthy += 1;
      break;
    case "Progressing":
      counts.progressing += 1;
      break;
    case "Degraded":
      counts.degraded += 1;
      break;
    case "Suspended":
      counts.suspended += 1;
      break;
    case "Missing":
      counts.missing += 1;
      break;
    default:
      counts.unknownHealth += 1;
      break;
  }
  if (hasBlockingPolicyViolation(app)) {
    counts.policyViolations += 1;
  }
  return counts;
}

/**
 * Classifies one application for the triage queue, or `null` when it needs no attention.
 *
 * A `Progressing` application is *not* triaged: a rollout in flight is the system working, and a
 * queue filled with healthy rollouts is a queue operators learn to ignore.
 */
export function triageEntry(app: ApplicationSummary): TriageEntry | null {
  const reasons: string[] = [];
  let severity = Number.POSITIVE_INFINITY;

  if (hasBlockingPolicyViolation(app)) {
    reasons.push("blocked by an Enforce policy rule");
    severity = 0;
  }
  switch (normalizeHealthStatus(app.health?.status)) {
    case "Degraded":
      reasons.push(app.health?.message?.trim() || "health is Degraded");
      severity = Math.min(severity, 1);
      break;
    case "Missing":
      reasons.push(app.health?.message?.trim() || "health is Missing");
      severity = Math.min(severity, 2);
      break;
    default:
      break;
  }
  if (normalizeSyncStatus(app.sync?.status) === "OutOfSync") {
    reasons.push("out of sync with Git");
    severity = Math.min(severity, 3);
  }
  if (normalizeHealthStatus(app.health?.status) === "Unknown") {
    reasons.push("no health verdict yet");
    severity = Math.min(severity, 4);
  }

  if (severity === Number.POSITIVE_INFINITY) {
    return null;
  }
  return { app, severity, reasons };
}

function compareTriage(left: TriageEntry, right: TriageEntry): number {
  if (left.severity !== right.severity) {
    return left.severity - right.severity;
  }
  return (
    `${left.app.namespace}/${left.app.name}`.localeCompare(
      `${right.app.namespace}/${right.app.name}`,
    )
  );
}

function compareBuckets(left: FleetBucket, right: FleetBucket): number {
  // `in-cluster` is the control plane's own client: it sorts first, like `/api/v1/clusters` does.
  if (left.key === "in-cluster") {
    return right.key === "in-cluster" ? 0 : -1;
  }
  if (right.key === "in-cluster") {
    return 1;
  }
  return left.key.localeCompare(right.key);
}

/**
 * Builds the dashboard rollup from the applications the server returned.
 *
 * `clusters` and `projects` are the project-scoped catalogues the API also scopes (`T17.1`); they
 * are used **only** to give a registered-but-empty cluster/project a zero row, never to add a total.
 * A name that appears in neither catalogue still gets a row when an application targets it, so a
 * rollup can never silently drop an application whose cluster is no longer registered.
 */
export function buildFleetRollup(
  applications: readonly ApplicationSummary[],
  clusters: readonly string[] = [],
  projects: readonly string[] = [],
): FleetRollup {
  const totals: RollupCounts = { ...EMPTY_COUNTS };
  const clusterBuckets = new Map<string, RollupCounts>();
  const projectBuckets = new Map<string, RollupCounts>();
  const triage: TriageEntry[] = [];
  let resources = 0;

  for (const name of clusters) {
    clusterBuckets.set(name, { ...EMPTY_COUNTS });
  }
  for (const name of projects) {
    projectBuckets.set(name, { ...EMPTY_COUNTS });
  }

  for (const app of applications) {
    addApplicationCounts(totals, app);

    const cluster = app.destination?.cluster ?? "in-cluster";
    const clusterCounts = clusterBuckets.get(cluster) ?? { ...EMPTY_COUNTS };
    addApplicationCounts(clusterCounts, app);
    clusterBuckets.set(cluster, clusterCounts);

    const project = app.project;
    const projectCounts = projectBuckets.get(project) ?? { ...EMPTY_COUNTS };
    addApplicationCounts(projectCounts, app);
    projectBuckets.set(project, projectCounts);

    resources += app.resourceCount;
    const entry = triageEntry(app);
    if (entry) {
      triage.push(entry);
    }
  }

  return {
    totals,
    byCluster: Array.from(clusterBuckets, ([key, counts]) => ({ key, counts })).sort(
      compareBuckets,
    ),
    byProject: Array.from(projectBuckets, ([key, counts]) => ({ key, counts })).sort(
      compareBuckets,
    ),
    triage: triage.sort(compareTriage),
    resources,
  };
}

/** `part / total` as a percentage rounded to one decimal (`0` when the slice is empty). */
export function percentOf(part: number, total: number): number {
  if (total <= 0) {
    return 0;
  }
  return Math.round((part / total) * 1000) / 10;
}
