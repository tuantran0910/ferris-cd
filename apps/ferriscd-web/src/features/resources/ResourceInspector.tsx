import { FileDiff, Layers, Shield, X } from "lucide-react";
import { useEffect } from "react";
import { createPortal } from "react-dom";
import type { ResourceNodeView } from "../../api/types";
import { Badge } from "../../ui/Badge";
import { Button } from "../../ui/Button";
import { CopyText } from "../../ui/CopyText";
import { kindTone } from "../../ui/kindTone";
import { HealthStatusBadge, SyncStatusBadge } from "../../ui/StatusBadges";

export interface ResourceInspectorProps {
  resource: ResourceNodeView | null;
  appSyncStatus: string;
  onClose: () => void;
  onInspectDiff?: (resourceKey: string) => void;
}

export function ResourceInspector({
  resource,
  appSyncStatus,
  onClose,
  onInspectDiff,
}: ResourceInspectorProps) {
  useEffect(() => {
    if (!resource) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [resource, onClose]);

  if (!resource) {
    return null;
  }

  const syncStatus = resource.present ? appSyncStatus : "OutOfSync";
  const healthStatus = !resource.present
    ? "Missing"
    : resource.health ?? "Unknown";

  return createPortal(
    <>
      <div
        data-testid="resource-inspector-backdrop"
        aria-hidden="true"
        onClick={onClose}
        className="motion-fade-in fixed inset-0 z-30 bg-black/40 backdrop-blur-[1px]"
      />
      <aside
        aria-label="Resource Inspector"
        data-testid="resource-inspector"
        className="motion-slide-in-right fixed inset-y-0 right-0 z-40 flex w-full max-w-md flex-col border-l border-line bg-surface shadow-2xl"
      >
      <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
        <div className="min-w-0">
          <Badge tone={kindTone(resource.kind)} size="sm" className="font-mono uppercase tracking-wider">
            {resource.kind}
          </Badge>
          <h3 className="truncate text-lg font-semibold text-ink-strong">
            {resource.name}
          </h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close resource inspector"
          className="rounded-lg p-1.5 text-ink-muted transition-colors hover:bg-elevated hover:text-ink-strong"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
        <div className="flex flex-wrap gap-2">
          <SyncStatusBadge status={syncStatus} />
          <HealthStatusBadge status={healthStatus} />
        </div>

        <section className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Version-Agnostic GKNN Key
          </h4>
          <div className="rounded-lg border border-line bg-canvas px-3 py-2">
            <span data-testid="inspector-gknn">
              <CopyText
                value={resource.key}
                label="GKNN key"
                className="break-all text-xs text-ink"
              />
            </span>
          </div>
        </section>

        <section className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Metadata
          </h4>
          <dl className="divide-y divide-line rounded-lg border border-line bg-canvas text-xs">
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-ink-muted">API Group</dt>
              <dd className="min-w-0 break-all text-right font-mono text-ink">
                {resource.group || "core (v1)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-ink-muted">Kind</dt>
              <dd className="min-w-0 break-all text-right font-mono text-ink">
                {resource.kind}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-ink-muted">Namespace</dt>
              <dd className="min-w-0 break-all text-right font-mono text-ink">
                {resource.namespace ?? "(cluster-scoped)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-ink-muted">Name</dt>
              <dd className="min-w-0 break-all text-right font-mono text-ink">
                {resource.name}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-ink-muted">Sync Wave</dt>
              <dd
                data-testid="inspector-sync-wave"
                className="font-mono text-ink-muted"
              >
                — (not reported by API)
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-ink-muted">Present in Cluster</dt>
              <dd className="font-mono text-ink">
                {resource.present ? "Yes" : "No (Missing)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="flex shrink-0 items-center gap-1 text-ink-muted">
                <Shield className="h-3.5 w-3.5" />
                Ownership
              </dt>
              <dd className="min-w-0 break-all text-right font-mono text-ink">
                {resource.ownership ?? "Owned / Inherited"}
              </dd>
            </div>
            {resource.parent && (
              <div className="flex flex-col gap-1 px-3 py-2">
                <dt className="flex items-center gap-1 text-ink-muted">
                  <Layers className="h-3.5 w-3.5" />
                  Owner Reference (Parent)
                </dt>
                <dd className="break-all font-mono text-ink">
                  {resource.parent}
                </dd>
              </div>
            )}
          </dl>
        </section>

        <section className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Health Message
          </h4>
          <div
            data-testid="inspector-health-message"
            className="rounded-lg border border-line bg-canvas p-3 text-xs leading-relaxed text-ink-body"
          >
            {resource.healthMessage
              ? resource.healthMessage
              : resource.present
                ? "No health issues reported from last reconcile."
                : "Resource is not currently present in the destination cluster."}
          </div>
        </section>
      </div>

      {onInspectDiff && (
        <div className="border-t border-line px-5 py-3">
          <Button
            variant="secondary"
            size="md"
            onClick={() => onInspectDiff(resource.key)}
            icon={<FileDiff className="h-4 w-4" aria-hidden="true" />}
            className="w-full border-indigo-500/40 bg-indigo-500/15 text-accent hover:bg-indigo-500/25"
          >
            View Resource in Diff
          </Button>
        </div>
      )}
    </aside>
    </>,
    document.body,
  );
}
