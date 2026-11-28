import { Boxes, FolderGit2, Layers, Server } from "lucide-react";
import type { ApplicationSummary, SourceEntryView } from "../../../api/types";
import { Badge } from "../../../ui/Badge";
import { Card } from "../../../ui/Card";
import { repoWebUrl } from "../../../utils/format";
import { SyncMetadata } from "./SyncMetadata";

/** The two source kinds the API reports (`SourceView.sourceType`, `T18.4`). */
function isOciSource(app: ApplicationSummary): boolean {
  return app.source.sourceType === "oci";
}

/** Every declared source of a multi-source `Application` (`source.sources`, `T20.1`). */
function declaredSources(app: ApplicationSummary): SourceEntryView[] {
  return app.source.sources ?? [];
}

/**
 * One row of the declared-source list: `ref: chart` — the alias a sibling
 * addresses with `$chart/...`.
 *
 * A source without an alias is labelled by its position instead, so the list
 * never shows a blank label an operator cannot act on.
 */
function sourceAlias(source: SourceEntryView, index: number): string {
  const alias = source.ref?.trim();
  return alias ? `ref: ${alias}` : `source ${index + 1}`;
}

/**
 * What one declared source contributes: a renderer means it produces
 * manifests, no renderer means it is a values-only support source (`T20.1`).
 */
function sourceRole(source: SourceEntryView): string {
  return source.renderer ? source.renderer : "values";
}

/** A count with its noun, pluralized (`1 source`, `2 sources`). */
function sourceCount(count: number): string {
  return `${count} ${count === 1 ? "source" : "sources"}`;
}

/**
 * Source / Destination / Sync Metadata summary.
 *
 * Kept as one section (`aria-label="Source and destination summary"`) because
 * the three cards answer a single question — "where does this application come
 * from and where did it land" — and the accessible grouping is what tests and
 * screen-reader users navigate by.
 */
export function SourcePanel({ app }: { app: ApplicationSummary }) {
  const oci = isOciSource(app);
  const sources = declaredSources(app);
  const multiSource = app.source.multiSource === true || sources.length > 1;
  return (
    <section
      aria-label="Source and destination summary"
      className="grid grid-cols-1 gap-4 md:grid-cols-3"
    >
      <Card className="text-xs" data-testid="source-card">
        <p className="flex flex-wrap items-center gap-1.5 font-semibold uppercase tracking-wider text-ink-muted">
          {oci ? (
            <Boxes className="h-3.5 w-3.5 text-accent-alt" />
          ) : (
            <FolderGit2 className="h-3.5 w-3.5 text-accent" />
          )}
          Source
          <Badge
            data-testid="source-kind"
            tone={oci ? "fuchsia" : "neutral"}
            size="sm"
            className="ml-1 tracking-normal"
          >
            {oci ? "OCI" : "Git"}
          </Badge>
          {/*
            `T20.1`: a split chart + values layout has more than one repository.
            The badge states the count in words (never colour alone) and the
            rows below name each one, so "where do these values come from?" is
            answerable from this card.
          */}
          {multiSource ? (
            <Badge
              data-testid="multi-source-badge"
              tone="violet"
              size="sm"
              className="tracking-normal"
            >
              <Layers className="h-3 w-3" aria-hidden="true" />
              {sources.length > 0 ? sourceCount(sources.length) : "multi-source"}
            </Badge>
          ) : null}
        </p>
        <dl className="mt-3 space-y-1.5">
          <div>
            <dt className="text-ink-subtle">
              {oci ? "Registry" : "Repository"}
            </dt>
            <dd
              className="break-all font-mono text-ink"
              title={app.source.repoUrl}
            >
              {repoWebUrl(app.source.repoUrl) ? (
                <a
                  href={repoWebUrl(app.source.repoUrl)!}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline decoration-slate-500/60 decoration-dotted underline-offset-2 hover:text-accent hover:decoration-indigo-400"
                >
                  {app.source.repoUrl}
                </a>
              ) : (
                app.source.repoUrl
              )}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-ink-subtle">Path</dt>
            <dd
              className="min-w-0 break-all text-right font-mono text-ink"
              title={app.source.path}
            >
              {app.source.path}
            </dd>
          </div>
          {/*
            `T18.4`: an OCI source reports the *tag it resolves* and the
            *digest it pinned* separately — those are different facts, and
            "Target Revision" (which collapses them into one string) would hide
            the pin. A Git source keeps the row it always had.
          */}
          {oci ? (
            <>
              {app.source.tag ? (
                <div className="flex justify-between gap-3">
                  <dt className="shrink-0 text-ink-subtle">Tag</dt>
                  <dd
                    data-testid="source-tag"
                    className="min-w-0 break-all text-right font-mono text-ink"
                    title={app.source.tag}
                  >
                    {app.source.tag}
                  </dd>
                </div>
              ) : null}
              {app.source.digest ? (
                <div className="flex justify-between gap-3">
                  <dt className="shrink-0 text-ink-subtle">Digest</dt>
                  <dd
                    data-testid="source-digest"
                    className="min-w-0 break-all text-right font-mono text-ink"
                    title={app.source.digest}
                  >
                    {app.source.digest}
                  </dd>
                </div>
              ) : null}
              {!app.source.tag && !app.source.digest ? (
                <div className="flex justify-between gap-3">
                  <dt className="shrink-0 text-ink-subtle">Target Revision</dt>
                  <dd
                    className="min-w-0 break-all text-right font-mono text-ink"
                    title={app.source.targetRevision}
                  >
                    {app.source.targetRevision}
                  </dd>
                </div>
              ) : null}
            </>
          ) : (
            <div className="flex justify-between gap-3">
              <dt className="shrink-0 text-ink-subtle">Target Revision</dt>
              <dd
                className="min-w-0 break-all text-right font-mono text-ink"
                title={app.source.targetRevision}
              >
                {app.source.targetRevision}
              </dd>
            </div>
          )}
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-ink-subtle">Renderer</dt>
            <dd className="min-w-0 break-all text-right font-mono text-ink">
              {app.source.renderer}
            </dd>
          </div>
        </dl>
        {sources.length > 0 ? (
          <div
            data-testid="declared-sources"
            className="mt-3 border-t border-line-strong pt-3"
          >
            <p className="font-semibold uppercase tracking-wider text-ink-muted">
              Declared sources
            </p>
            <ul aria-label="Declared sources" className="mt-2 space-y-2">
              {sources.map((source, index) => (
                <li
                  // Two sources may legitimately share no alias, so the index
                  // is part of the key: the list is declaration-ordered and
                  // never reorders.
                  key={`${source.ref ?? "source"}-${index}`}
                  data-testid={`declared-source-${index}`}
                  className="space-y-1"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-ink-body">
                      {sourceAlias(source, index)}
                    </span>
                    <span className="flex items-center gap-1">
                      <Badge
                        tone={source.sourceType === "oci" ? "fuchsia" : "neutral"}
                        size="sm"
                        className="tracking-normal"
                      >
                        {source.sourceType === "oci" ? "OCI" : "Git"}
                      </Badge>
                      <Badge
                        tone={source.renderer ? "info" : "warning"}
                        size="sm"
                        className="tracking-normal"
                      >
                        {sourceRole(source)}
                      </Badge>
                    </span>
                  </div>
                  <p
                    className="break-all font-mono text-ink"
                    title={source.repoUrl}
                  >
                    {source.repoUrl}
                  </p>
                  <p className="flex justify-between gap-3 text-ink-muted">
                    <span className="min-w-0 break-all font-mono">
                      {source.path || "/"}
                    </span>
                    <span
                      className="shrink-0 font-mono"
                      title={source.targetRevision}
                    >
                      @{source.targetRevision}
                    </span>
                  </p>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </Card>

      <Card className="text-xs">
        <p className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-ink-muted">
          <Server className="h-3.5 w-3.5 text-success" />
          Destination
        </p>
        <dl className="mt-3 space-y-1.5">
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-ink-subtle">Cluster</dt>
            <dd className="min-w-0 break-all text-right font-mono text-ink">
              {app.destination.cluster}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-ink-subtle">Namespace</dt>
            <dd className="min-w-0 break-all text-right font-mono text-ink">
              {app.destination.namespace}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-ink-subtle">Tracked Resources</dt>
            <dd className="font-mono text-ink">{app.resourceCount}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="shrink-0 text-ink-subtle">Observed Generation</dt>
            <dd className="font-mono text-ink">
              {app.observedGeneration ?? "—"}
            </dd>
          </div>
        </dl>
      </Card>

      <SyncMetadata app={app} />
    </section>
  );
}
