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
import type { DiffChange, DiffPayload, DiffResource } from "../../api/types";
import { EmptyState } from "../../ui/EmptyState";
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
  switch (status) {
    case "Synced":
      return "border-emerald-500/40 bg-emerald-500/15 text-emerald-300";
    case "OutOfSync":
      return "border-amber-500/40 bg-amber-500/15 text-amber-300";
    case "Missing":
      return "border-sky-500/40 bg-sky-500/15 text-sky-300";
    case "Orphaned":
      return "border-rose-500/40 bg-rose-500/15 text-rose-300";
    case "OwnershipConflict":
      return "border-fuchsia-500/40 bg-fuchsia-500/15 text-fuchsia-300";
    default:
      return "border-slate-600 bg-slate-800 text-slate-300";
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
        className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/50 bg-amber-500/15 px-2 py-0.5 font-mono text-xs font-semibold text-amber-200"
      >
        <Lock className="h-3 w-3 shrink-0 text-amber-400" aria-hidden="true" />
        {value}
      </span>
    );
  }

  const formatted = formatDiffValue(value);
  const hasInlineRedacted = containsRedactedMarker(value);
  const toneClass =
    tone === "live"
      ? "text-rose-200"
      : tone === "predicted"
        ? "text-emerald-200"
        : "text-slate-200";

  return (
    <div className="space-y-1">
      {hasInlineRedacted && (
        <span
          data-testid="redacted-secret-badge"
          className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-200"
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
      className="overflow-x-auto rounded-lg border border-slate-800"
    >
      <table className="w-full table-fixed text-left text-xs">
        <thead className="border-b border-slate-800 bg-slate-950/90 text-[11px] uppercase tracking-wider text-slate-400">
          <tr>
            <th className="w-1/4 px-3 py-2">Field Path</th>
            <th className="w-[37.5%] border-l border-slate-800 px-3 py-2 text-rose-300">
              Live (Cluster)
            </th>
            <th className="w-[37.5%] border-l border-slate-800 px-3 py-2 text-emerald-300">
              Predicted (Git / SSA Dry-Run)
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/80">
          {changes.map((change, idx) => (
            <tr key={`${change.path}-${idx}`} className="align-top">
              <td className="px-3 py-2.5">
                <div className="break-all font-mono text-xs text-slate-200">
                  {change.path}
                </div>
                <span className="mt-1 inline-block rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-400">
                  {change.kind}
                </span>
              </td>
              <td className="border-l border-slate-800 bg-rose-950/15 px-3 py-2.5">
                {change.kind === "added" ? (
                  <span className="font-mono text-xs italic text-slate-500">
                    (absent)
                  </span>
                ) : (
                  <RenderedDiffValue value={change.live} tone="live" />
                )}
              </td>
              <td className="border-l border-slate-800 bg-emerald-950/15 px-3 py-2.5">
                {change.kind === "removed" ? (
                  <span className="font-mono text-xs italic text-slate-500">
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
      className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-slate-950 font-mono text-xs"
    >
      {changes.map((change, idx) => (
        <div key={`${change.path}-${idx}`} className="p-3">
          <div className="mb-1.5 flex items-center gap-2 text-slate-400">
            <span className="font-semibold text-indigo-300">
              @@ {change.path} @@
            </span>
            <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase">
              {change.kind}
            </span>
          </div>
          {change.kind !== "added" && (
            <div className="flex items-start gap-2 rounded bg-rose-950/35 px-2.5 py-1.5 text-rose-200">
              <span className="select-none font-bold text-rose-400">-</span>
              <div className="min-w-0 flex-1">
                <RenderedDiffValue value={change.live} tone="live" />
              </div>
            </div>
          )}
          {change.kind !== "removed" && (
            <div className="mt-1 flex items-start gap-2 rounded bg-emerald-950/35 px-2.5 py-1.5 text-emerald-200">
              <span className="select-none font-bold text-emerald-400">+</span>
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

  return (
    <article
      data-testid={`diff-resource-${resource.key}`}
      className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 motion-fade-in"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <code className="break-all font-mono text-xs font-semibold text-slate-100">
            {resource.key}
          </code>
          <span
            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${getDiffStatusBadge(
              resource.status,
            )}`}
          >
            {resource.status}
          </span>
          {conflicts.length > 0 && (
            <span
              data-testid="field-conflict-badge"
              className="inline-flex items-center gap-1 rounded-full border border-rose-500/50 bg-rose-500/20 px-2 py-0.5 text-[11px] font-medium text-rose-200"
            >
              <ShieldAlert className="h-3 w-3" />
              FieldConflict ({conflicts.length})
            </span>
          )}
          {hasRedactedValues && (
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-200">
              <Lock className="h-3 w-3" />
              Secret Redacted
            </span>
          )}
          {resource.truncated && (
            <span className="inline-flex items-center gap-1 rounded-full border border-slate-600 bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300">
              <FileWarning className="h-3 w-3" />
              Diff Truncated
            </span>
          )}
        </div>
      </div>

      {resource.status === "OwnershipConflict" && resource.owner && (
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-fuchsia-500/40 bg-fuchsia-500/10 px-3 py-2 text-xs text-fuchsia-200">
          <AlertOctagon className="h-4 w-4 shrink-0 text-fuchsia-400" />
          <span>
            Owned by another FerrisCD application:{" "}
            <code className="font-mono font-semibold">{resource.owner}</code>
          </span>
        </div>
      )}

      {conflicts.length > 0 && (
        <div
          data-testid="field-conflict-list"
          className="mt-3 rounded-lg border border-rose-500/40 bg-rose-950/30 p-3 text-xs"
        >
          <p className="flex items-center gap-1.5 font-semibold text-rose-200">
            <AlertTriangle className="h-4 w-4 text-rose-400" />
            Server-Side Apply Field-Ownership Conflicts
          </p>
          <ul className="mt-2 space-y-1.5">
            {conflicts.map((conflict, idx) => (
              <li
                key={`${conflict.field ?? "field"}-${conflict.manager ?? "mgr"}-${idx}`}
                className="flex flex-wrap items-center gap-2 font-mono text-rose-100"
              >
                <span className="rounded bg-rose-500/25 px-1.5 py-0.5 text-[11px] font-semibold text-rose-200">
                  manager: {conflict.manager ?? "unknown"}
                </span>
                <span className="break-all text-slate-200">
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
        <p className="mt-2 flex items-center gap-1.5 text-xs text-emerald-300/90">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Live cluster state matches SSA dry-run prediction.
        </p>
      ) : resource.status === "Missing" ? (
        <p className="mt-2 text-xs text-sky-300/90">
          Resource does not exist in the destination cluster yet and will be
          created on sync.
        </p>
      ) : resource.status === "Orphaned" ? (
        <p className="mt-2 text-xs text-rose-300/90">
          Tracked in inventory but no longer rendered from Git. Will be pruned
          if <code className="font-mono">syncPolicy.automated.prune</code> is
          enabled.
        </p>
      ) : null}
    </article>
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

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3 text-xs">
        <div className="flex flex-wrap items-center gap-3 text-slate-300">
          <span className="min-w-0">
            Revision:{" "}
            <code
              className="break-all rounded bg-slate-950 px-1.5 py-0.5 font-mono text-indigo-300"
              title={diff.revision}
            >
              {diff.revision}
            </code>
          </span>
          <span>
            Desired resources:{" "}
            <strong className="text-slate-100">{diff.desired}</strong>
          </span>
          <span>
            Would sync:{" "}
            <strong
              className={diff.wouldSync ? "text-amber-300" : "text-emerald-300"}
            >
              {diff.wouldSync ? "Yes" : "No"}
            </strong>
          </span>
        </div>

        <div
          role="group"
          aria-label="Diff display mode"
          className="inline-flex rounded-lg border border-slate-700 bg-slate-950 p-0.5"
        >
          <button
            type="button"
            onClick={() => setViewMode("side-by-side")}
            aria-pressed={viewMode === "side-by-side"}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              viewMode === "side-by-side"
                ? "bg-indigo-600 text-white"
                : "text-slate-300 hover:text-white"
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
                : "text-slate-300 hover:text-white"
            }`}
          >
            <Rows3 className="h-3.5 w-3.5" />
            Unified
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="search"
            aria-label="Filter diff resources"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter resources by GKNN key..."
            className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-xs text-slate-100 transition-colors placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
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
    slate: "text-slate-100",
    emerald: "text-emerald-300",
    amber: "text-amber-300",
    sky: "text-sky-300",
    rose: "text-rose-300",
    fuchsia: "text-fuchsia-300",
  };
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-2">
      <p className="text-[11px] text-slate-400">{label}</p>
      <p className={`mt-0.5 text-lg font-semibold ${colorMap[tone]}`}>
        {value}
      </p>
    </div>
  );
}
