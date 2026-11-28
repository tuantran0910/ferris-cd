import { Copy, Check, FileDiff, Layers, Shield, X } from "lucide-react";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import type { ResourceNodeView } from "../../api/types";
import { Button } from "../../ui/Button";
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
  const [copied, setCopied] = useState(false);

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

  const handleCopyKey = async () => {
    try {
      if (!navigator.clipboard?.writeText) {
        // No clipboard API (insecure context): report nothing rather than
        // claiming a copy that never happened.
        return;
      }
      await navigator.clipboard.writeText(resource.key);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be denied by permissions policy.
    }
  };

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
        className="motion-slide-in-right fixed inset-y-0 right-0 z-40 flex w-full max-w-md flex-col border-l border-default bg-surface shadow-2xl"
      >
      <div className="flex items-start justify-between gap-3 border-b border-default px-5 py-4">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider text-accent">
            {resource.kind}
          </p>
          <h3 className="truncate text-lg font-semibold text-strong">
            {resource.name}
          </h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close resource inspector"
          className="rounded-lg p-1.5 text-muted transition-colors hover:bg-elevated hover:text-strong"
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
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">
            Version-Agnostic GKNN Key
          </h4>
          <div className="flex items-center justify-between gap-2 rounded-lg border border-default bg-canvas px-3 py-2">
            <code
              data-testid="inspector-gknn"
              className="break-all font-mono text-xs text-primary"
            >
              {resource.key}
            </code>
            <button
              type="button"
              onClick={handleCopyKey}
              aria-label="Copy GKNN key"
              className="shrink-0 rounded p-1 text-muted transition-colors hover:bg-elevated hover:text-strong"
            >
              {copied ? (
                <Check className="h-3.5 w-3.5 text-success" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              <span aria-live="polite" className="sr-only">
                {copied ? "Copied" : ""}
              </span>
            </button>
          </div>
        </section>

        <section className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">
            Metadata
          </h4>
          <dl className="divide-y divide-default/80 rounded-lg border border-default bg-canvas/60 text-xs">
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-muted">API Group</dt>
              <dd className="min-w-0 break-all text-right font-mono text-primary">
                {resource.group || "core (v1)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-muted">Kind</dt>
              <dd className="min-w-0 break-all text-right font-mono text-primary">
                {resource.kind}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-muted">Namespace</dt>
              <dd className="min-w-0 break-all text-right font-mono text-primary">
                {resource.namespace ?? "(cluster-scoped)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-muted">Name</dt>
              <dd className="min-w-0 break-all text-right font-mono text-primary">
                {resource.name}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-muted">Sync Wave</dt>
              <dd
                data-testid="inspector-sync-wave"
                className="font-mono text-muted"
              >
                — (not reported by API)
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="shrink-0 text-muted">Present in Cluster</dt>
              <dd className="font-mono text-primary">
                {resource.present ? "Yes" : "No (Missing)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="flex shrink-0 items-center gap-1 text-muted">
                <Shield className="h-3.5 w-3.5" />
                Ownership
              </dt>
              <dd className="min-w-0 break-all text-right font-mono text-primary">
                {resource.ownership ?? "Owned / Inherited"}
              </dd>
            </div>
            {resource.parent && (
              <div className="flex flex-col gap-1 px-3 py-2">
                <dt className="flex items-center gap-1 text-muted">
                  <Layers className="h-3.5 w-3.5" />
                  Owner Reference (Parent)
                </dt>
                <dd className="break-all font-mono text-primary">
                  {resource.parent}
                </dd>
              </div>
            )}
          </dl>
        </section>

        <section className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">
            Health Message
          </h4>
          <div
            data-testid="inspector-health-message"
            className="rounded-lg border border-default bg-canvas/60 p-3 text-xs leading-relaxed text-body"
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
        <div className="border-t border-default px-5 py-3">
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
