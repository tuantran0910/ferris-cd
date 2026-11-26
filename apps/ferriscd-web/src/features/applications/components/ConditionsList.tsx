import { CheckCircle2, XCircle } from "lucide-react";
import type { ConditionView } from "../../../api/types";
import { EmptyState } from "../../../ui/EmptyState";
import { formatTimestamp } from "../../../utils/format";

/**
 * Conditions timeline.
 *
 * `True` conditions are emerald, everything else rose — that is the Kubernetes
 * convention operators already read. The list keeps the DOM order the API sent
 * (a condition timeline is chronological by `lastTransitionTime`), so it is not
 * sorted client-side.
 */
export function ConditionsList({ conditions }: { conditions: ConditionView[] }) {
  return (
    <section
      aria-label="Conditions timeline"
      data-testid="conditions-timeline"
      className="space-y-3"
    >
      {conditions.length === 0 ? (
        <EmptyState bordered={false}>No status conditions recorded yet.</EmptyState>
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
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-slate-100">
                      {cond.type}
                    </span>
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">
                      status={cond.status}
                    </span>
                    <span className="max-w-full truncate rounded bg-indigo-500/15 px-1.5 py-0.5 font-mono text-[11px] text-indigo-300">
                      {cond.reason}
                    </span>
                  </div>
                  <time
                    dateTime={cond.lastTransitionTime}
                    title={cond.lastTransitionTime}
                    className="font-mono text-[11px] text-slate-400"
                  >
                    {formatTimestamp(cond.lastTransitionTime)}
                  </time>
                </div>
                <p className="mt-2 break-words leading-relaxed text-slate-300">
                  {cond.message}
                </p>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
