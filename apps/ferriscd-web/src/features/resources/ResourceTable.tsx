import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import type { ResourceGraphView, ResourceNodeView } from "../../api/types";
import { HealthStatusBadge, SyncStatusBadge } from "../../ui/StatusBadges";
import { Badge } from "../../ui/Badge";
import { kindTone } from "../../ui/kindTone";
import { Select } from "../../ui/Select";

export interface ResourceTableProps {
  /** Nodes to display (already the whole inventory of the application). */
  nodes: ResourceNodeView[];
  graph: ResourceGraphView;
  /** Opens the inspector for a resource key. */
  onSelect: (key: string) => void;
}

/**
 * Searchable resource inventory table.
 *
 * This is the fallback for large applications (and a user choice for small
 * ones). Search and kind filter are local to the table — they are view state,
 * not URL state, and must not survive oddly if the component unmounts.
 */
export function ResourceTable({ nodes, graph, onSelect }: ResourceTableProps) {
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState<string>("ALL");

  const uniqueKinds = useMemo(() => {
    const kinds = new Set(nodes.map((n) => n.kind));
    return Array.from(kinds).sort();
  }, [nodes]);

  // A poll can remove every node of the filtered kind. Without this guard the
  // <select> would silently fall back to its first option while the state stayed
  // on the vanished kind, leaving a permanently empty table.
  const effectiveKindFilter =
    kindFilter === "ALL" || uniqueKinds.includes(kindFilter) ? kindFilter : "ALL";

  const filteredNodes = useMemo(() => {
    const q = search.trim().toLowerCase();
    return nodes.filter((n) => {
      if (effectiveKindFilter !== "ALL" && n.kind !== effectiveKindFilter) {
        return false;
      }
      if (!q) {
        return true;
      }
      return (
        n.name.toLowerCase().includes(q) ||
        n.kind.toLowerCase().includes(q) ||
        n.key.toLowerCase().includes(q) ||
        (n.namespace ?? "").toLowerCase().includes(q) ||
        (n.health ?? "").toLowerCase().includes(q)
      );
    });
  }, [nodes, effectiveKindFilter, search]);

  return (
    <div data-testid="resource-table-view" className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[240px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-subtle" />
          <input
            type="search"
            aria-label="Search resources"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search resources by name, kind, namespace, or GKNN..."
            className="w-full rounded-lg border border-control bg-surface py-2 pl-9 pr-3 text-xs text-ink-strong transition-colors placeholder-hint focus-visible:border-accent "
          />
        </div>
        <Select
          aria-label="Filter by resource kind"
          value={effectiveKindFilter}
          onChange={setKindFilter}
          options={[
            { value: "ALL", label: `All Kinds (${nodes.length})` },
            ...uniqueKinds.map((kind) => ({ value: kind, label: kind })),
          ]}
        />
        <span className="text-xs text-ink-muted">
          Showing {filteredNodes.length} of {nodes.length}
        </span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-line bg-surface">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-line bg-surface text-[11px] uppercase tracking-wider text-ink-muted">
            <tr>
              <th className="px-4 py-2.5">Kind</th>
              <th className="px-4 py-2.5">Name</th>
              <th className="px-4 py-2.5">Namespace</th>
              <th className="px-4 py-2.5">Sync</th>
              <th className="px-4 py-2.5">Health</th>
              <th className="px-4 py-2.5">Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {filteredNodes.map((node) => {
              const syncStatus = node.present ? graph.syncStatus : "OutOfSync";
              const healthStatus = !node.present
                ? "Missing"
                : node.health ?? "Unknown";
              return (
                <tr
                  key={node.key}
                  tabIndex={0}
                  aria-label={`Inspect ${node.kind} ${node.name}`}
                  onClick={() => onSelect(node.key)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelect(node.key);
                    }
                  }}
                  className="cursor-pointer transition-colors hover:bg-elevated focus-visible:bg-elevated"
                >
                  <td className="whitespace-nowrap px-4 py-2.5">
                    <Badge tone={kindTone(node.kind)} size="sm" className="font-mono">
                      {node.kind}
                    </Badge>
                  </td>
                  <td
                    className="max-w-[220px] truncate px-4 py-2.5 font-mono text-ink-strong"
                    title={node.name}
                  >
                    {node.name}
                  </td>
                  <td
                    className="max-w-[160px] truncate px-4 py-2.5 font-mono text-ink-muted"
                    title={node.namespace ?? undefined}
                  >
                    {node.namespace ?? "—"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5">
                    <SyncStatusBadge status={syncStatus} compact />
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5">
                    <HealthStatusBadge status={healthStatus} compact />
                  </td>
                  <td
                    className="max-w-xs truncate px-4 py-2.5 text-ink-muted"
                    title={node.healthMessage ?? undefined}
                  >
                    {node.healthMessage ?? "—"}
                  </td>
                </tr>
              );
            })}
            {filteredNodes.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-ink-muted">
                  No resources match your search filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
