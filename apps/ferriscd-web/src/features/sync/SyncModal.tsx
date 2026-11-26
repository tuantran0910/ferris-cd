import { AlertTriangle, Info, RefreshCw, ShieldOff } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { OperationResponse, SyncRequestBody } from "../../api/types";
import { Button } from "../../ui/Button";
import { Modal, ModalBody, ModalFooter, ModalHeader } from "../../ui/Modal";
import { describeOperationError } from "../../utils/apiErrorText";
import { useModalBehavior } from "./useModalBehavior";

export interface SyncModalProps {
  open: boolean;
  namespace: string;
  name: string;
  targetRevision: string;
  disabledByRbac?: boolean;
  onClose: () => void;
  onConfirm: (body: SyncRequestBody) => Promise<OperationResponse>;
  onForbidden?: () => void;
  onPreviewDiff?: () => void;
}

export function SyncModal({
  open,
  namespace,
  name,
  targetRevision,
  disabledByRbac = false,
  onClose,
  onConfirm,
  onForbidden,
  onPreviewDiff,
}: SyncModalProps) {
  const [dryRun, setDryRun] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<{ title: string; detail: string } | null>(
    null,
  );
  const [forbidden, setForbidden] = useState(disabledByRbac);
  const [successResponse, setSuccessResponse] =
    useState<OperationResponse | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (open) {
      setDryRun(false);
      setError(null);
      setSuccessResponse(null);
      setForbidden(disabledByRbac);
    }
    // Only reset transient modal state when the dialog opens, not when
    // disabledByRbac flips true in response to a 403 inside the open modal.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useModalBehavior(open, dialogRef, onClose, { dismissible: !submitting });

  if (!open) {
    return null;
  }

  const isForbidden = forbidden || disabledByRbac;

  const handleSubmit = async () => {
    if (dryRun) {
      onClose();
      onPreviewDiff?.();
      return;
    }
    if (isForbidden || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const body: SyncRequestBody = {};
      const result = await onConfirm(body);
      setSuccessResponse(result);
    } catch (err) {
      const described = describeOperationError(err, "sync");
      if (described.forbidden) {
        setForbidden(true);
        onForbidden?.();
      }
      setError({ title: described.title, detail: described.detail });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      labelledBy="sync-modal-title"
      describedBy="sync-modal-description"
      dialogRef={dialogRef}
    >
      <ModalHeader
        titleId="sync-modal-title"
        title="Sync Application"
        icon={<RefreshCw className="h-4 w-4 text-indigo-400" />}
        onClose={onClose}
        closeLabel="Close sync modal"
      />

      <ModalBody>
        <p id="sync-modal-description" className="break-words text-slate-300">
          Request a manual reconcile for{" "}
          <code className="break-all rounded bg-slate-950 px-1.5 py-0.5 font-mono text-xs text-indigo-300">
            {namespace}/{name}
          </code>{" "}
          at revision{" "}
          <code className="break-all rounded bg-slate-950 px-1.5 py-0.5 font-mono text-xs text-slate-200">
            {targetRevision}
          </code>
          .
        </p>

        <div className="space-y-2.5 rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 text-xs">
          <label className="flex items-start gap-2.5 text-slate-400">
            <input
              type="checkbox"
              checked={false}
              disabled
              className="mt-0.5 cursor-not-allowed rounded border-slate-700 bg-slate-900 text-indigo-500 opacity-60"
            />
            <span>
              <strong className="block font-medium text-slate-300">
                Prune orphaned resources
              </strong>
              <span className="text-slate-400">
                Configured via{" "}
                <code className="font-mono">spec.syncPolicy.automated.prune</code>{" "}
                (v1.0).
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2.5 text-slate-200">
            <input
              type="checkbox"
              checked={dryRun}
              disabled={submitting}
              onChange={(e) => setDryRun(e.target.checked)}
              className="mt-0.5 rounded border-slate-600 bg-slate-900 text-indigo-500"
            />
            <span>
              <strong className="block font-medium">Dry-run preview</strong>
              <span className="text-slate-400">
                Opens the live SSA dry-run Diff tab powered by{" "}
                <code className="font-mono">GET .../diff</code> without
                triggering a sync.
              </span>
            </span>
          </label>

          {onPreviewDiff && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 pt-2.5 text-slate-400">
              <span className="flex items-center gap-1.5">
                <Info className="h-3.5 w-3.5 text-sky-400" />
                Want to preview SSA dry-run changes first?
              </span>
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onPreviewDiff();
                }}
                className="font-medium text-indigo-400 transition-colors hover:text-indigo-300"
              >
                Open Live Diff
              </button>
            </div>
          )}
        </div>

        {isForbidden && (
          <div
            role="alert"
            data-testid="sync-rbac-forbidden"
            className="flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 text-xs text-rose-200 motion-fade-in"
          >
            <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            <div>
              <p className="font-semibold text-rose-100">
                RBAC Permission Required (403 Forbidden)
              </p>
              <p className="mt-0.5 break-words">
                {error?.detail ??
                  "Your current Kubernetes identity has read-only access and is not permitted to trigger a sync on this project."}
              </p>
            </div>
          </div>
        )}

        {!isForbidden && error && (
          <div
            role="alert"
            data-testid="sync-error"
            className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-950/40 p-3 text-xs text-amber-200 motion-fade-in"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
            <div>
              <p className="font-semibold text-amber-100">{error.title}</p>
              <p className="mt-0.5 break-words text-amber-200/90">
                {error.detail}
              </p>
            </div>
          </div>
        )}

        {successResponse && (
          <div
            role="status"
            data-testid="sync-success-banner"
            className="rounded-lg border border-emerald-500/40 bg-emerald-950/40 p-3 text-xs text-emerald-200 motion-fade-in"
          >
            <p>
              Sync request <strong>{successResponse.status}</strong> — the
              controller has been notified and will reconcile{" "}
              <code className="break-all font-mono">
                {successResponse.namespace}/{successResponse.name}
              </code>
              .
            </p>
            <p className="mt-1 text-emerald-200/80">
              Polling for the Sync badge and diff to update; this dialog can be
              closed.
            </p>
          </div>
        )}
      </ModalBody>

      <ModalFooter>
        <Button variant="secondary" size="md" onClick={onClose}>
          {successResponse ? "Done" : "Cancel"}
        </Button>
        {!successResponse && (
          <Button
            variant="primary"
            size="md"
            onClick={() => void handleSubmit()}
            disabled={dryRun ? submitting : isForbidden || submitting}
            isLoading={submitting}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            {dryRun
              ? "Preview Dry-Run Diff"
              : submitting
                ? "Syncing..."
                : "Confirm Sync"}
          </Button>
        )}
      </ModalFooter>
    </Modal>
  );
}
