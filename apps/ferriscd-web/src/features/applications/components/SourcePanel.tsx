import { FolderGit2, Server } from "lucide-react";
import type { ApplicationSummary } from "../../../api/types";
import { Card } from "../../../ui/Card";
import { repoWebUrl } from "../../../utils/format";
import { SyncMetadata } from "./SyncMetadata";

/**
 * Source / Destination / Sync Metadata summary.
 *
 * Kept as one section (`aria-label="Source and destination summary"`) because
 * the three cards answer a single question — "where does this application come
 * from and where did it land" — and the accessible grouping is what tests and
 * screen-reader users navigate by.
 */
export function SourcePanel({ app }: { app: ApplicationSummary }) {
  return (
    <section
      aria-label="Source and destination summary"
      className="grid grid-cols-1 gap-4 md:grid-cols-3"
    >
      <Card className="text-xs">
        <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-400">
          <FolderGit2 className="h-3.5 w-3.5 text-indigo-400" />
          Source
        </p>
        <dl className="mt-3 space-y-1.5">
          <div>
            <dt className="text-slate-500">Repository</dt>
            <dd
              className="break-all font-mono text-slate-200"
              title={app.source.repoUrl}
            >
              {repoWebUrl(app.source.repoUrl) ? (
                <a
                  href={repoWebUrl(app.source.repoUrl)!}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline decoration-slate-500/60 decoration-dotted underline-offset-2 hover:text-indigo-300 hover:decoration-indigo-400"
                >
                  {app.source.repoUrl}
                </a>
              ) : (
                app.source.repoUrl
              )}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">Path</dt>
            <dd
              className="min-w-0 break-all text-right font-mono text-slate-200"
              title={app.source.path}
            >
              {app.source.path}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">Target Revision</dt>
            <dd
              className="min-w-0 break-all text-right font-mono text-slate-200"
              title={app.source.targetRevision}
            >
              {app.source.targetRevision}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">Renderer</dt>
            <dd className="min-w-0 break-all text-right font-mono text-slate-200">
              {app.source.renderer}
            </dd>
          </div>
        </dl>
      </Card>

      <Card className="text-xs">
        <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-400">
          <Server className="h-3.5 w-3.5 text-emerald-400" />
          Destination
        </p>
        <dl className="mt-3 space-y-1.5">
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">Cluster</dt>
            <dd className="min-w-0 break-all text-right font-mono text-slate-200">
              {app.destination.cluster}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">Namespace</dt>
            <dd className="min-w-0 break-all text-right font-mono text-slate-200">
              {app.destination.namespace}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">Tracked Resources</dt>
            <dd className="font-mono text-slate-200">{app.resourceCount}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-slate-500">Observed Generation</dt>
            <dd className="font-mono text-slate-200">
              {app.observedGeneration ?? "—"}
            </dd>
          </div>
        </dl>
      </Card>

      <SyncMetadata app={app} />
    </section>
  );
}
