import { Activity } from "lucide-react";
import type { OperationView } from "../../../api/types";
import { commitWebUrl, formatTimestamp, shortRevision } from "../../../utils/format";

export interface OperationBannerProps {
  operation: OperationView;
  /** Repository the operation's revision belongs to (for commit links). */
  repoUrl: string;
}

/**
 * The in-flight / last-completed reconciliation banner.
 *
 * Failure states get the rose treatment; a successful operation is emerald; a
 * running one is indigo. The banner fades in so a poll that flips the phase is
 * noticeable without any looping animation.
 */
export function OperationBanner({ operation, repoUrl }: OperationBannerProps) {
  const tone =
    operation.phase === "Failed" || operation.phase === "Error"
      ? "border-rose-500/40 bg-rose-950/30 text-rose-100"
      : operation.phase === "Succeeded"
        ? "border-emerald-500/40 bg-emerald-950/25 text-emerald-100"
        : "border-indigo-500/40 bg-indigo-950/30 text-indigo-100";
  const revisionUrl = commitWebUrl(repoUrl, operation.revision);

  return (
    <section
      aria-label="Active operation state"
      data-testid="operation-banner"
      className={`rounded-xl border px-4 py-3 text-xs motion-fade-in ${tone}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Activity className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span className="font-semibold">Operation: {operation.phase}</span>
          <span className="rounded bg-black/20 px-1.5 py-0.5 font-mono text-[11px]">
            wave {operation.currentWave}
          </span>
          {operation.revision &&
            (revisionUrl ? (
              <a
                href={revisionUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono underline decoration-slate-500/60 decoration-dotted underline-offset-2 hover:text-indigo-200"
                title={`${operation.revision} — open commit`}
              >
                {shortRevision(operation.revision, 12)}
              </a>
            ) : (
              <code className="font-mono" title={operation.revision}>
                {shortRevision(operation.revision, 12)}
              </code>
            ))}
        </div>
        <span className="font-mono text-[11px] opacity-80">
          Started: {formatTimestamp(operation.startedAt)}
          {operation.finishedAt
            ? ` • Finished: ${formatTimestamp(operation.finishedAt)}`
            : ""}
        </span>
      </div>
      {operation.message && (
        <p className="mt-1.5 break-words opacity-90">{operation.message}</p>
      )}
    </section>
  );
}
