import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Columns2,
  FileWarning,
  Lock,
  Rows3,
  Search,
  ShieldAlert,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type {
  DiffChange,
  DiffPayload,
  DiffResource,
  PolicyViolation,
} from "../../api/types";
import { isBlockingEnforcement } from "../../api/types";
import { parseResourceKey } from "../../utils/format";
import { Badge } from "../../ui/Badge";
import { CopyText } from "../../ui/CopyText";
import { EmptyState } from "../../ui/EmptyState";
import { kindTone } from "../../ui/kindTone";
import {
  containsRedactedMarker,
  formatDiffValue,
  isRedactedToken,
  isSecretResourceKey,
} from "./diffFormat";
import { Select } from "../../ui/Select";

type DiffStatusFilter =
  | "ALL"
  | "DRIFTED"
  | "OutOfSync"
  | "Missing"
  | "Orphaned"
  | "OwnershipConflict"
  | "FieldConflict"
  | "Synced";

function getDiffStatusBadge(status: string): string {
  switch (status.toLowerCase()) {
    case "synced":
      return "border-emerald-500/40 bg-emerald-500/15 text-success";
    case "outofsync":
      return "border-amber-500/40 bg-amber-500/15 text-warning";
    case "missing":
      return "border-sky-500/40 bg-sky-500/15 text-info";
    case "orphaned":
      return "border-rose-500/40 bg-rose-500/15 text-danger";
    case "ownershipconflict":
      return "border-fuchsia-500/40 bg-fuchsia-500/15 text-accent-alt";
    default:
      return "border-line-emphasis bg-elevated text-ink-body";
  }
}

function RenderedDiffValue({
  value,
  tone,
}: {
  value: unknown;
  tone: "live" | "predicted" | "neutral";
}) {
  if (isRedactedToken(value)) {
    return (
      <span
        data-testid="redacted-secret-badge"
        className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/50 bg-amber-500/15 px-2 py-0.5 font-mono text-xs font-semibold text-warning"
      >
        <Lock className="h-3 w-3 shrink-0 text-warning" aria-hidden="true" />
        {value}
      </span>
    );
  }

  const formatted = formatDiffValue(value);
  const hasInlineRedacted = containsRedactedMarker(value);
  const toneClass =
    tone === "live"
      ? "text-danger"
      : tone === "predicted"
        ? "text-success"
        : "text-ink";

  return (
    <div className="space-y-1">
      {hasInlineRedacted && (
        <span
          data-testid="redacted-secret-badge"
          className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-warning"
        >
          <Lock className="h-2.5 w-2.5" aria-hidden="true" />
          Secret Redacted
        </span>
      )}
      <pre
        className={`overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs leading-relaxed ${toneClass}`}
      >
        {formatted}
      </pre>
    </div>
  );
}

function SideBySideChanges({ changes }: { changes: DiffChange[] }) {
  return (
    <div
      data-testid="diff-side-by-side"
      className="overflow-x-auto rounded-lg border border-line"
    >
      <table className="w-full table-fixed text-left text-xs">
        <thead className="border-b border-line bg-canvas text-[11px] uppercase tracking-wider text-ink-muted">
          <tr>
            <th className="w-1/4 px-3 py-2">Field Path</th>
            <th className="w-[37.5%] border-l border-line px-3 py-2 text-danger">
              Live (Cluster)
            </th>
            <th className="w-[37.5%] border-l border-line px-3 py-2 text-success">
              Predicted (Git / SSA Dry-Run)
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {changes.map((change, idx) => (
            <tr key={`${change.path}-${idx}`} className="align-top">
              <td className="px-3 py-2.5">
                <div className="break-all font-mono text-xs text-ink">
                  {change.path}
                </div>
                <span className="mt-1 inline-block rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] uppercase text-ink-muted">
                  {change.kind}
                </span>
              </td>
              <td className="border-l border-line bg-danger-tint px-3 py-2.5">
                {change.kind === "added" ? (
                  <span className="font-mono text-xs italic text-ink-subtle">
                    (absent)
                  </span>
                ) : (
                  <RenderedDiffValue value={change.live} tone="live" />
                )}
              </td>
              <td className="border-l border-line bg-success-tint px-3 py-2.5">
                {change.kind === "removed" ? (
                  <span className="font-mono text-xs italic text-ink-subtle">
                    (removed)
                  </span>
                ) : (
                  <RenderedDiffValue value={change.predicted} tone="predicted" />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UnifiedChanges({ changes }: { changes: DiffChange[] }) {
  return (
    <div
      data-testid="diff-unified"
      className="divide-y divide-line rounded-lg border border-line bg-canvas font-mono text-xs"
    >
      {changes.map((change, idx) => (
        <div key={`${change.path}-${idx}`} className="p-3">
          <div className="mb-1.5 flex items-center gap-2 text-ink-muted">
            <span className="font-semibold text-accent">
              @@ {change.path} @@
            </span>
            <span className="rounded bg-elevated px-1.5 py-0.5 text-[10px] uppercase">
              {change.kind}
            </span>
          </div>
          {change.kind !== "added" && (
            <div className="flex items-start gap-2 rounded bg-danger-tint px-2.5 py-1.5 text-danger">
              <span className="select-none font-bold text-danger">-</span>
              <div className="min-w-0 flex-1">
                <RenderedDiffValue value={change.live} tone="live" />
              </div>
            </div>
          )}
          {change.kind !== "removed" && (
            <div className="mt-1 flex items-start gap-2 rounded bg-success-tint px-2.5 py-1.5 text-success">
              <span className="select-none font-bold text-success">+</span>
              <div className="min-w-0 flex-1">
                <RenderedDiffValue value={change.predicted} tone="predicted" />
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ResourceDiffCard({
  resource,
  mode,
}: {
  resource: DiffResource;
  mode: "side-by-side" | "unified";
}) {
  const changes = resource.changes ?? [];
  const conflicts = resource.conflicts ?? [];
  const isSecret = isSecretResourceKey(resource.key);
  const hasRedactedValues =
    isSecret ||
    changes.some(
      (c) =>
        containsRedactedMarker(c.live) || containsRedactedMarker(c.predicted),
    );

  const identity = parseResourceKey(resource.key);

  return (
    <article
      data-testid={`diff-resource-${resource.key}`}
      title={resource.key}
      className="rounded-xl border border-line bg-surface p-4 motion-fade-in"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              tone={kindTone(identity.kind)}
              size="sm"
              className="font-mono uppercase tracking-wide"
            >
              {identity.kind}
            </Badge>
            <span className="truncate text-sm font-semibold text-ink-strong">
              {identity.name}
            </span>
          </div>
          <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-muted">
            {identity.namespace ? (
              <span>
                <span className="text-ink-subtle">Namespace:</span>{" "}
                <Link
                  to={`/?q=${encodeURIComponent(identity.namespace)}`}
                  title={`Show applications in namespace ${identity.namespace}`}
                  className="font-mono hover:text-accent hover:underline"
                >
                  {identity.namespace}
                </Link>
              </span>
            ) : (
              <span>
                <span className="text-ink-subtle">Scope:</span> cluster
              </span>
            )}
            {identity.group ? (
              <span>
                <span className="text-ink-subtle">Group:</span>{" "}
                <span className="font-mono">{identity.group}</span>
              </span>
            ) : null}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${getDiffStatusBadge(
              resource.status,
            )}`}
          >
            {resource.status.charAt(0).toUpperCase() + resource.status.slice(1)}
          </span>
          {conflicts.length > 0 && (
            <span
              data-testid="field-conflict-badge"
              className="inline-flex items-center gap-1 rounded-full border border-rose-500/50 bg-rose-500/20 px-2 py-0.5 text-[11px] font-medium text-danger"
            >
              <ShieldAlert className="h-3 w-3" />
              FieldConflict ({conflicts.length})
            </span>
          )}
          {hasRedactedValues && (
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-warning">
              <Lock className="h-3 w-3" />
              Secret Redacted
            </span>
          )}
          {resource.truncated && (
            <span className="inline-flex items-center gap-1 rounded-full border border-line-emphasis bg-elevated px-2 py-0.5 text-[11px] text-ink-body">
              <FileWarning className="h-3 w-3" />
              Diff Truncated
            </span>
          )}
        </div>
      </div>

      {resource.status === "OwnershipConflict" && resource.owner && (
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-fuchsia-500/40 bg-fuchsia-500/10 px-3 py-2 text-xs text-accent-alt">
          <AlertOctagon className="h-4 w-4 shrink-0 text-accent-alt" />
          <span>
            Owned by another FerrisCD application:{" "}
            <code className="font-mono font-semibold">{resource.owner}</code>
          </span>
        </div>
      )}

      {conflicts.length > 0 && (
        <div
          data-testid="field-conflict-list"
          className="mt-3 rounded-lg border border-rose-500/40 bg-danger-tint p-3 text-xs"
        >
          <p className="flex items-center gap-1.5 font-semibold text-danger">
            <AlertTriangle className="h-4 w-4 text-danger" />
            Server-Side Apply Field-Ownership Conflicts
          </p>
          <ul className="mt-2 space-y-1.5">
            {conflicts.map((conflict, idx) => (
              <li
                key={`${conflict.field ?? "field"}-${conflict.manager ?? "mgr"}-${idx}`}
                className="flex flex-wrap items-center gap-2 font-mono text-danger"
              >
                <span className="rounded bg-rose-500/25 px-1.5 py-0.5 text-[11px] font-semibold text-danger">
                  manager: {conflict.manager ?? "unknown"}
                </span>
                <span className="break-all text-ink">
                  {conflict.field ?? "(unspecified field)"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {changes.length > 0 ? (
        <div className="mt-3">
          {mode === "side-by-side" ? (
            <SideBySideChanges changes={changes} />
          ) : (
            <UnifiedChanges changes={changes} />
          )}
        </div>
      ) : resource.status === "Synced" ? (
        <p className="mt-2 flex items-center gap-1.5 text-xs text-success">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Live cluster state matches SSA dry-run prediction.
        </p>
      ) : resource.status === "Missing" ? (
        <p className="mt-2 text-xs text-info">
          Resource does not exist in the destination cluster yet and will be
          created on sync.
        </p>
      ) : resource.status === "Orphaned" ? (
        <p className="mt-2 text-xs text-danger">
          Tracked in inventory but no longer rendered from Git. Will be pruned
          if <code className="font-mono">syncPolicy.automated.prune</code> is
          enabled.
        </p>
      ) : null}
    </article>
  );
}

/**
 * `T20.2` pre-sync policy gate banner.
 *
 * A blocking violation means the next sync will be refused, so it is rendered above every other
 * affordance on the page; an advisory only says the bundle would deploy with a warning. Both come
 * from the server's `DiffView.policyViolations`, which never carries a `Secret` value.
 */
function PolicyViolationsBanner({
  violations,
}: {
  violations: PolicyViolation[];
}) {
  if (violations.length === 0) return null;
  const blocking = violations.filter((v) =>
    isBlockingEnforcement(v.enforcement),
  );
  const advisories = violations.filter(
    (v) => !isBlockingEnforcement(v.enforcement),
  );
  const isBlocking = blocking.length > 0;
  return (
    <section
      data-testid="policy-violations-banner"
      aria-labelledby="policy-violations-heading"
      className={`rounded-xl border px-4 py-3 ${
        isBlocking
          ? "border-rose-500/50 bg-danger-tint"
          : "border-amber-500/40 bg-warning-tint"
      }`}
    >
      <h2
        id="policy-violations-heading"
        className="flex items-center gap-2 text-sm font-semibold"
      >
        {isBlocking ? (
          <ShieldAlert
            className="h-4 w-4 shrink-0 text-danger"
            aria-hidden="true"
          />
        ) : (
          <AlertTriangle
            className="h-4 w-4 shrink-0 text-warning"
            aria-hidden="true"
          />
        )}
        <span className={isBlocking ? "text-danger" : "text-warning"}>
          Policy Violations
        </span>
        <span className="rounded-full border border-control bg-canvas px-2 py-0.5 text-[11px] font-medium text-ink-body">
          {isBlocking
            ? `${blocking.length} blocking`
            : `${advisories.length} advisory`}
        </span>
      </h2>
      <p className="mt-1 text-xs text-ink-body">
        {isBlocking
          ? "The sync is refused until these manifests comply: nothing is applied and nothing is pruned."
          : "The sync proceeds; these rules only advise."}
      </p>
      <ul className="mt-2 space-y-1.5">
        {violations.map((violation) => (
          <li
            key={`${violation.rule}-${violation.resourceKey}-${violation.message}`}
            data-testid="policy-violation"
            className="flex flex-wrap items-baseline gap-2 rounded-lg border border-line bg-canvas px-2.5 py-1.5 text-xs"
          >
            <span
              className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                isBlockingEnforcement(violation.enforcement)
                  ? "bg-rose-500/20 text-danger"
                  : "bg-amber-500/20 text-warning"
              }`}
            >
              {violation.enforcement}
            </span>
            <code className="font-mono text-accent">{violation.rule}</code>
            <code className="break-all font-mono text-ink-muted">
              {violation.resourceKey}
            </code>
            <span className="text-ink">{violation.message}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export interface DiffViewerProps {
  diff: DiffPayload;
  initialSearch?: string;
}

export function DiffViewer({ diff, initialSearch = "" }: DiffViewerProps) {
  const [viewMode, setViewMode] = useState<"side-by-side" | "unified">(
    "side-by-side",
  );
  const [statusFilter, setStatusFilter] = useState<DiffStatusFilter>("ALL");
  const [search, setSearch] = useState(initialSearch);

  const resources = diff.resources ?? [];

  const filteredResources = useMemo(() => {
    const q = search.trim().toLowerCase();
    return resources.filter((res) => {
      if (statusFilter === "DRIFTED") {
        const drifted =
          res.status !== "Synced" || (res.conflicts?.length ?? 0) > 0;
        if (!drifted) return false;
      } else if (statusFilter === "FieldConflict") {
        if ((res.conflicts?.length ?? 0) === 0) return false;
      } else if (statusFilter !== "ALL" && res.status !== statusFilter) {
        return false;
      }
      if (!q) return true;
      return res.key.toLowerCase().includes(q);
    });
  }, [resources, search, statusFilter]);

  const { summary } = diff;

  return (
    <div className="space-y-4">
      <PolicyViolationsBanner violations={diff.policyViolations ?? []} />
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4 lg:grid-cols-7">
        <SummaryStat label="Total" value={summary.total} tone="slate" />
        <SummaryStat label="Synced" value={summary.synced} tone="emerald" />
        <SummaryStat
          label="OutOfSync"
          value={summary.outOfSync}
          tone="amber"
        />
        <SummaryStat label="Missing" value={summary.missing} tone="sky" />
        <SummaryStat label="Orphaned" value={summary.orphaned} tone="rose" />
        <SummaryStat
          label="FieldConflict"
          value={summary.fieldConflicts}
          tone="rose"
        />
        <SummaryStat
          label="OwnershipConflict"
          value={summary.ownershipConflicts}
          tone="fuchsia"
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface px-4 py-3 text-xs">
        <div className="flex flex-wrap items-center gap-3 text-ink-body">
          <span className="min-w-0">
            Revision:{" "}
            <CopyText
              value={diff.revision}
              label="revision"
              className="break-all rounded bg-canvas px-1.5 py-0.5 text-accent"
            />
          </span>
          <span>
            Desired resources:{" "}
            <strong className="text-ink-strong">{diff.desired}</strong>
          </span>
          <span>
            Would sync:{" "}
            <strong
              className={diff.wouldSync ? "text-warning" : "text-success"}
            >
              {diff.wouldSync ? "Yes" : "No"}
            </strong>
          </span>
        </div>

        <div
          role="group"
          aria-label="Diff display mode"
          className="inline-flex rounded-lg border border-control bg-canvas p-0.5"
        >
          <button
            type="button"
            onClick={() => setViewMode("side-by-side")}
            aria-pressed={viewMode === "side-by-side"}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              viewMode === "side-by-side"
                ? "bg-indigo-600 text-white"
                : "text-ink-body hover:text-ink-strong"
            }`}
          >
            <Columns2 className="h-3.5 w-3.5" />
            Side-by-Side
          </button>
          <button
            type="button"
            onClick={() => setViewMode("unified")}
            aria-pressed={viewMode === "unified"}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              viewMode === "unified"
                ? "bg-indigo-600 text-white"
                : "text-ink-body hover:text-ink-strong"
            }`}
          >
            <Rows3 className="h-3.5 w-3.5" />
            Unified
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-subtle" />
          <input
            type="search"
            aria-label="Filter diff resources"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by kind, name or namespace..."
            className="w-full rounded-lg border border-control bg-surface py-2 pl-9 pr-3 text-xs text-ink-strong transition-colors placeholder-hint "
          />
        </div>
        <Select
          aria-label="Filter diff status"
          value={statusFilter}
          onChange={(value) => setStatusFilter(value as DiffStatusFilter)}
          options={[
            { value: "ALL", label: `All Statuses (${resources.length})` },
            { value: "DRIFTED", label: "Drifted & Conflicts Only" },
            { value: "OutOfSync", label: "OutOfSync" },
            { value: "Missing", label: "Missing" },
            { value: "Orphaned", label: "Orphaned" },
            { value: "FieldConflict", label: "FieldConflict" },
            { value: "OwnershipConflict", label: "OwnershipConflict" },
            { value: "Synced", label: "Synced" },
          ]}
        />
      </div>

      {filteredResources.length === 0 ? (
        <EmptyState data-testid="diff-empty-state">
          {resources.length === 0
            ? "No resources were diffed: the rendered bundle and the tracked inventory are both empty."
            : "No diff entries match the selected filter."}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          {filteredResources.map((res) => (
            <ResourceDiffCard key={res.key} resource={res} mode={viewMode} />
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "slate" | "emerald" | "amber" | "sky" | "rose" | "fuchsia";
}) {
  const colorMap: Record<typeof tone, string> = {
    slate: "text-ink-strong",
    emerald: "text-success",
    amber: "text-warning",
    sky: "text-info",
    rose: "text-danger",
    fuchsia: "text-accent-alt",
  };
  return (
    <div className="rounded-lg border border-line bg-surface px-3 py-2">
      <p className="text-[11px] text-ink-muted">{label}</p>
      <p className={`mt-0.5 text-lg font-semibold ${colorMap[tone]}`}>
        {value}
      </p>
    </div>
  );
}
