import { GitBranch } from "lucide-react";
import type { ApplicationSummary } from "../../../api/types";
import { Card } from "../../../ui/Card";
import {
  commitWebUrl,
  formatTimestamp,
  shortRevision,
} from "../../../utils/format";

/**
 * Third card of the source/destination summary: what the controller actually
 * rendered and applied, as opposed to what Git asks for.
 *
 * Revisions that resolve to a browsable commit are links; when the repo is not
 * HTTP(S) (SSH / local path) the same value renders as plain mono text, so a
 * missing link never hides data.
 */
export function SyncMetadata({ app }: { app: ApplicationSummary }) {
  const renderedRevision = commitWebUrl(
    app.source.repoUrl,
    app.sync?.revision,
  );
  const lastSyncedRevision = commitWebUrl(
    app.source.repoUrl,
    app.sync?.lastSyncedRevision,
  );

  return (
    <Card className="text-xs">
      <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-400">
        <GitBranch className="h-3.5 w-3.5 text-amber-400" />
        Sync Metadata
      </p>
      <dl className="mt-3 space-y-1.5">
        <div className="flex justify-between gap-3">
          <dt className="shrink-0 text-slate-500">Rendered Revision</dt>
          <dd
            className="min-w-0 break-all text-right font-mono text-slate-200"
            title={app.sync?.revision ?? undefined}
          >
            {renderedRevision ? (
              <a
                href={renderedRevision}
                target="_blank"
                rel="noopener noreferrer"
                className="underline decoration-slate-500/60 decoration-dotted underline-offset-2 hover:text-indigo-300 hover:decoration-indigo-400"
              >
                {shortRevision(app.sync?.revision, 12)}
              </a>
            ) : (
              shortRevision(app.sync?.revision, 12)
            )}
          </dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="shrink-0 text-slate-500">Last Synced Revision</dt>
          <dd
            className="min-w-0 break-all text-right font-mono text-slate-200"
            title={app.sync?.lastSyncedRevision ?? undefined}
          >
            {lastSyncedRevision ? (
              <a
                href={lastSyncedRevision}
                target="_blank"
                rel="noopener noreferrer"
                className="underline decoration-slate-500/60 decoration-dotted underline-offset-2 hover:text-indigo-300 hover:decoration-indigo-400"
              >
                {shortRevision(app.sync?.lastSyncedRevision, 12)}
              </a>
            ) : (
              shortRevision(app.sync?.lastSyncedRevision, 12)
            )}
          </dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="shrink-0 text-slate-500">Last Synced At</dt>
          <dd
            className="text-right font-mono text-slate-200"
            title={app.sync?.lastSyncedAt ?? undefined}
          >
            {formatTimestamp(app.sync?.lastSyncedAt)}
          </dd>
        </div>
      </dl>
    </Card>
  );
}
