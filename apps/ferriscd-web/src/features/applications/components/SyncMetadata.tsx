import { GitBranch } from "lucide-react";
import type { ApplicationSummary } from "../../../api/types";
import { Card } from "../../../ui/Card";
import { CopyText } from "../../../ui/CopyText";
import { formatTimestamp, shortRevision } from "../../../utils/format";

/**
 * Third card of the source/destination summary: what the controller actually
 * rendered and applied, as opposed to what Git asks for.
 *
 * Revisions that resolve to a browsable commit are links; when the repo is not
 * HTTP(S) (SSH / local path) the same value renders as plain mono text, so a
 * missing link never hides data.
 */
export function SyncMetadata({ app }: { app: ApplicationSummary }) {
  // `T20.1`: a multi-source pass reports one revision per declared source.
  // They are shown next to the composite revision above, because the whole
  // point of the list is answering "did the values repository move?" — a
  // question the composite digest alone cannot answer.
  const sources = app.source.sources ?? [];
  const perSource = app.sync?.revisions ?? [];
  // The block is gated on the *data*, not on the badge: a multi-source
  // application that has never synced (or whose spec has not been reconciled
  // yet) has no revisions to show, and rendering an empty `Source Revisions`
  // heading would look like a controller bug (finding N2).
  const showPerSource = perSource.length > 0;

  return (
    <Card className="text-xs">
      <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-ink-muted">
        <GitBranch className="h-3.5 w-3.5 text-warning" />
        Sync Metadata
      </p>
      <dl className="mt-3 space-y-1.5">
        <div className="flex justify-between gap-3">
          <dt className="shrink-0 text-ink-subtle">Rendered Revision</dt>
          <dd
            className="min-w-0 break-all text-right font-mono text-ink"
            title={app.sync?.revision ?? undefined}
          >
            {app.sync?.revision ? (
              <CopyText
                value={app.sync.revision}
                display={shortRevision(app.sync.revision, 12)}
                label="rendered revision"
                className="justify-end font-mono"
              />
            ) : (
              shortRevision(app.sync?.revision, 12)
            )}
          </dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="shrink-0 text-ink-subtle">Last Synced Revision</dt>
          <dd
            className="min-w-0 break-all text-right font-mono text-ink"
            title={app.sync?.lastSyncedRevision ?? undefined}
          >
            {app.sync?.lastSyncedRevision ? (
              <CopyText
                value={app.sync.lastSyncedRevision}
                display={shortRevision(app.sync.lastSyncedRevision, 12)}
                label="last synced revision"
                className="justify-end font-mono"
              />
            ) : (
              shortRevision(app.sync?.lastSyncedRevision, 12)
            )}
          </dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="shrink-0 text-ink-subtle">Last Synced At</dt>
          <dd
            className="text-right font-mono text-ink"
            title={app.sync?.lastSyncedAt ?? undefined}
          >
            {formatTimestamp(app.sync?.lastSyncedAt)}
          </dd>
        </div>
        {showPerSource ? (
          <div
            data-testid="per-source-revisions"
            className="border-t border-line-strong pt-1.5"
          >
            <p className="text-ink-subtle">Source Revisions</p>
            <ul aria-label="Source revisions" className="mt-1 space-y-1">
              {perSource.map((revision, index) => {
                // The API reports the revisions in `spec.sources` declaration
                // order, so the alias comes from the same index. A missing
                // entry (an older payload, or a source added since the last
                // pass) is labelled by position rather than dropped.
                const alias = sources[index]?.ref?.trim();
                return (
                  <li
                    key={`${alias ?? "source"}-${index}`}
                    data-testid={`source-revision-${index}`}
                    className="flex justify-between gap-3"
                  >
                    <span className="shrink-0 font-mono text-ink-muted">
                      {alias ?? `source ${index + 1}`}
                    </span>
                    <span
                      className="min-w-0 break-all text-right font-mono text-ink"
                      title={revision}
                    >
                      <CopyText
                        value={revision}
                        display={shortRevision(revision, 12)}
                        label={`source ${alias ?? index + 1} revision`}
                        className="justify-end font-mono"
                      />
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null}
      </dl>
    </Card>
  );
}
