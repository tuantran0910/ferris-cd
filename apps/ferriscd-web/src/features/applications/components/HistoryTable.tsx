import { RotateCcw } from "lucide-react";
import type { HistoryView } from "../../../api/types";
import { Button } from "../../../ui/Button";
import { EmptyState } from "../../../ui/EmptyState";
import { CopyText } from "../../../ui/CopyText";
import { formatTimestamp, shortRevision } from "../../../utils/format";

export interface HistoryTableProps {
  history: HistoryView[];
  /** True once a 403 proved this identity cannot roll back. */
  rollbackForbidden: boolean;
  /** Opens the rollback modal pre-selected on this entry. */
  onRollback: (historyId: number) => void;
}

/**
 * Deployment history, newest first.
 *
 * The API returns history in its own order, so the sort is client-side and
 * descending by id: the row an operator wants after an incident is the last
 * deployment, not the first.
 */
export function HistoryTable({
  history,
  rollbackForbidden,
  onRollback,
}: HistoryTableProps) {
  return (
    <section
      aria-label="Deployment history"
      data-testid="history-table"
      className="overflow-x-auto rounded-xl border border-line bg-surface"
    >
      {history.length === 0 ? (
        <EmptyState bordered={false}>No deployment history recorded yet.</EmptyState>
      ) : (
        <table className="w-full text-left text-xs">
          <thead className="border-b border-line bg-surface text-[11px] uppercase tracking-wider text-ink-muted">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Revision</th>
              <th className="px-4 py-3">Deployed At</th>
              <th className="px-4 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {[...history]
              .sort((a, b) => b.id - a.id)
              .map((entry) => {
                return (
                  <tr key={entry.id} className="hover:bg-elevated">
                    <td className="px-4 py-3 font-mono font-semibold text-ink-strong">
                      #{entry.id}
                    </td>
                    <td
                      className="max-w-[280px] truncate px-4 py-3 font-mono text-accent"
                      title={entry.revision ?? undefined}
                    >
                      {entry.revision ? (
                        <CopyText
                          value={entry.revision}
                          display={shortRevision(entry.revision, 12)}
                          label="revision"
                        />
                      ) : (
                        shortRevision(entry.revision, 12)
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-ink-muted">
                      <time dateTime={entry.deployedAt} title={entry.deployedAt}>
                        {formatTimestamp(entry.deployedAt)}
                      </time>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        variant="warning"
                        size="sm"
                        disabled={rollbackForbidden}
                        onClick={() => onRollback(entry.id)}
                        icon={<RotateCcw className="h-3 w-3" />}
                      >
                        Rollback
                      </Button>
                    </td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      )}
    </section>
  );
}
