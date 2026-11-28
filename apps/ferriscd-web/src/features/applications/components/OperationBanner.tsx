import { Activity } from "lucide-react";
import type { OperationView } from "../../../api/types";
import { CopyText } from "../../../ui/CopyText";
import { formatTimestamp, shortRevision } from "../../../utils/format";

export interface OperationBannerProps {
  operation: OperationView;
}

/**
 * The in-flight / last-completed reconciliation banner.
 *
 * Failure states get the rose treatment; a successful operation is emerald; a
 * running one is indigo. The banner fades in so a poll that flips the phase is
 * noticeable without any looping animation.
 */
export function OperationBanner({ operation }: OperationBannerProps) {
  const tone =
    operation.phase === "Failed" || operation.phase === "Error"
      ? "border-rose-500/40 bg-danger-tint text-danger"
      : operation.phase === "Succeeded"
        ? "border-emerald-500/40 bg-success-tint text-success"
        : "border-indigo-500/40 bg-accent-tint text-accent";

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
          <span className="rounded bg-canvas px-1.5 py-0.5 font-mono text-[11px]">
            wave {operation.currentWave}
          </span>
          {operation.revision && (
            <CopyText
              value={operation.revision}
              display={shortRevision(operation.revision, 12)}
              label="operation revision"
            />
          )}
        </div>
        <span className="font-mono text-[11px]">
          Started: {formatTimestamp(operation.startedAt)}
          {operation.finishedAt
            ? ` • Finished: ${formatTimestamp(operation.finishedAt)}`
            : ""}
        </span>
      </div>
      {operation.message && (
        <p className="mt-1.5 break-words">{operation.message}</p>
      )}
    </section>
  );
}
