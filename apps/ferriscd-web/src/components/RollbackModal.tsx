import { AlertTriangle, History, RotateCcw, ShieldOff, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ApiClientError } from "../api/client";
import type {
  HistoryView,
  OperationResponse,
  RollbackRequestBody,
} from "../api/types";

export interface RollbackModalProps {
  open: boolean;
  namespace: string;
  name: string;
  history: HistoryView[];
  initialHistoryId?: number | null;
  disabledByRbac?: boolean;
  onClose: () => void;
  onConfirm: (body: RollbackRequestBody) => Promise<OperationResponse>;
  onForbidden?: () => void;
}

export function RollbackModal({
  open,
  namespace,
  name,
  history,
  initialHistoryId = null,
  disabledByRbac = false,
  onClose,
  onConfirm,
  onForbidden,
}: RollbackModalProps) {
  const sortedHistory = useMemo(
    () => [...history].sort((a, b) => b.id - a.id),
    [history],
  );

  const [selectedId, setSelectedId] = useState<number | null>(
    () => initialHistoryId ?? sortedHistory[0]?.id ?? null,
  );
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(disabledByRbac);
  const [successResponse, setSuccessResponse] =
    useState<OperationResponse | null>(null);

  useEffect(() => {
    if (open) {
      setSelectedId(initialHistoryId ?? sortedHistory[0]?.id ?? null);
      setErrorMessage(null);
      setSuccessResponse(null);
      setForbidden(disabledByRbac);
    }
    // Only reset transient modal state when the dialog opens, not when
    // disabledByRbac flips true in response to a 403 inside the open modal.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initialHistoryId]);

  if (!open) {
    return null;
  }

  const isForbidden = forbidden || disabledByRbac;

  const handleSubmit = async () => {
    if (isForbidden || submitting || selectedId === null) return;
    setSubmitting(true);
    setErrorMessage(null);
    try {
      const result = await onConfirm({ id: selectedId });
      setSuccessResponse(result);
    } catch (err) {
      if (err instanceof ApiClientError && err.isForbidden) {
        setForbidden(true);
        setErrorMessage(
          err.message ||
            "Permission denied (403 Forbidden): your role cannot roll back this application.",
        );
        onForbidden?.();
      } else if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage("Failed to request rollback.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="rollback-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm"
    >
      <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-2">
            <RotateCcw className="h-4 w-4 text-amber-400" />
            <h2
              id="rollback-modal-title"
              className="text-base font-semibold text-slate-100"
            >
              Rollback Application
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close rollback modal"
            className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 px-5 py-5 text-sm">
          <p className="text-slate-300">
            Select a previous deployment from{" "}
            <code className="rounded bg-slate-950 px-1.5 py-0.5 font-mono text-xs text-indigo-300">
              {namespace}/{name}
            </code>{" "}
            history to redeploy.
          </p>

          <div
            role="note"
            data-testid="rollback-auto-sync-warning"
            className="flex items-start gap-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs text-amber-200"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
            <div>
              <p className="font-semibold text-amber-100">
                Automated sync will be paused
              </p>
              <p className="mt-0.5 leading-relaxed text-amber-200/90">
                Rolling back pins this application to the chosen commit and
                disables{" "}
                <code className="font-mono text-amber-100">
                  spec.syncPolicy.automated
                </code>{" "}
                so the controller does not immediately overwrite the rollback.
              </p>
            </div>
          </div>

          {sortedHistory.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center text-xs text-slate-400">
              <History className="mx-auto mb-2 h-5 w-5 text-slate-500" />
              No deployment history entries are available to roll back to.
            </div>
          ) : (
            <fieldset
              disabled={isForbidden || submitting}
              className="max-h-56 space-y-2 overflow-y-auto pr-1"
            >
              <legend className="sr-only">Select revision history entry</legend>
              {sortedHistory.map((entry) => {
                const checked = selectedId === entry.id;
                return (
                  <label
                    key={entry.id}
                    className={`flex cursor-pointer items-center justify-between gap-3 rounded-xl border px-3.5 py-2.5 text-xs transition ${
                      checked
                        ? "border-indigo-500 bg-indigo-500/10 text-slate-100"
                        : "border-slate-800 bg-slate-950/60 text-slate-300 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <input
                        type="radio"
                        name="rollback-history-id"
                        value={entry.id}
                        checked={checked}
                        onChange={() => setSelectedId(entry.id)}
                        className="border-slate-600 bg-slate-900 text-indigo-500"
                      />
                      <div>
                        <p className="font-semibold text-slate-100">
                          Deployment #{entry.id}
                        </p>
                        <p className="font-mono text-[11px] text-indigo-300">
                          {entry.revision ?? "(unknown revision)"}
                        </p>
                      </div>
                    </div>
                    <time className="font-mono text-[11px] text-slate-400">
                      {entry.deployedAt}
                    </time>
                  </label>
                );
              })}
            </fieldset>
          )}

          {isForbidden && (
            <div
              role="alert"
              data-testid="rollback-rbac-forbidden"
              className="flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 text-xs text-rose-200"
            >
              <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
              <div>
                <p className="font-semibold text-rose-100">
                  RBAC Permission Required (403 Forbidden)
                </p>
                <p className="mt-0.5">
                  {errorMessage ??
                    "Your current Kubernetes identity is not permitted to roll back this application."}
                </p>
              </div>
            </div>
          )}

          {!isForbidden && errorMessage && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 text-xs text-rose-200"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successResponse && (
            <div
              role="status"
              data-testid="rollback-success-banner"
              className="rounded-lg border border-emerald-500/40 bg-emerald-950/40 p-3 text-xs text-emerald-200"
            >
              Rollback request <strong>{successResponse.status}</strong> (
              <code className="font-mono">{successResponse.request}</code>).
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2.5 border-t border-slate-800 px-5 py-3.5">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700"
          >
            {successResponse ? "Done" : "Cancel"}
          </button>
          {!successResponse && (
            <button
              type="button"
              onClick={handleSubmit}
              disabled={isForbidden || submitting || selectedId === null}
              className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-amber-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              {submitting ? "Rolling back..." : "Confirm Rollback"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
