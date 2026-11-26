import { Copy, Check, FileDiff, Layers, Shield, X } from "lucide-react";
import { useState } from "react";
import type { ResourceNodeView } from "../api/types";
import { HealthStatusBadge, SyncStatusBadge } from "./StatusBadges";

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

  if (!resource) {
    return null;
  }

  const syncStatus = resource.present ? appSyncStatus : "OutOfSync";
  const healthStatus = !resource.present
    ? "Missing"
    : resource.health ?? "Unknown";

  const handleCopyKey = async () => {
    try {
      await navigator.clipboard?.writeText(resource.key);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be unavailable in non-secure contexts.
    }
  };

  return (
    <aside
      aria-label="Resource Inspector"
      data-testid="resource-inspector"
      className="fixed inset-y-0 right-0 z-40 flex w-full max-w-md flex-col border-l border-slate-800 bg-slate-900 shadow-2xl"
    >
      <div className="flex items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider text-indigo-400">
            {resource.kind}
          </p>
          <h3 className="truncate text-lg font-semibold text-slate-100">
            {resource.name}
          </h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close resource inspector"
          className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
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
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Version-Agnostic GKNN Key
          </h4>
          <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">
            <code
              data-testid="inspector-gknn"
              className="break-all font-mono text-xs text-slate-200"
            >
              {resource.key}
            </code>
            <button
              type="button"
              onClick={handleCopyKey}
              aria-label="Copy GKNN key"
              className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            >
              {copied ? (
                <Check className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
        </section>

        <section className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Metadata
          </h4>
          <dl className="divide-y divide-slate-800/80 rounded-lg border border-slate-800 bg-slate-950/60 text-xs">
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="text-slate-400">API Group</dt>
              <dd className="font-mono text-slate-200">
                {resource.group || "core (v1)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="text-slate-400">Kind</dt>
              <dd className="font-mono text-slate-200">{resource.kind}</dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="text-slate-400">Namespace</dt>
              <dd className="font-mono text-slate-200">
                {resource.namespace ?? "(cluster-scoped)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="text-slate-400">Name</dt>
              <dd className="font-mono text-slate-200">{resource.name}</dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="text-slate-400">Sync Wave</dt>
              <dd
                data-testid="inspector-sync-wave"
                className="font-mono text-slate-400"
              >
                — (not reported by API)
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="text-slate-400">Present in Cluster</dt>
              <dd className="font-mono text-slate-200">
                {resource.present ? "Yes" : "No (Missing)"}
              </dd>
            </div>
            <div className="flex justify-between gap-4 px-3 py-2">
              <dt className="flex items-center gap-1 text-slate-400">
                <Shield className="h-3.5 w-3.5" />
                Ownership
              </dt>
              <dd className="font-mono text-slate-200">
                {resource.ownership ?? "Owned / Inherited"}
              </dd>
            </div>
            {resource.parent && (
              <div className="flex flex-col gap-1 px-3 py-2">
                <dt className="flex items-center gap-1 text-slate-400">
                  <Layers className="h-3.5 w-3.5" />
                  Owner Reference (Parent)
                </dt>
                <dd className="break-all font-mono text-slate-200">
                  {resource.parent}
                </dd>
              </div>
            )}
          </dl>
        </section>

        <section className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Health Message
          </h4>
          <div
            data-testid="inspector-health-message"
            className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs leading-relaxed text-slate-300"
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
        <div className="border-t border-slate-800 px-5 py-3">
          <button
            type="button"
            onClick={() => onInspectDiff(resource.key)}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-indigo-500/40 bg-indigo-500/15 px-4 py-2 text-xs font-semibold text-indigo-200 hover:bg-indigo-500/25"
          >
            <FileDiff className="h-4 w-4" />
            View Resource in Diff
          </button>
        </div>
      )}
    </aside>
  );
}
