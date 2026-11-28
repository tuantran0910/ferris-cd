import { AlertTriangle, Info, RefreshCw, ShieldOff } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type {
  OperationResponse,
  SyncRequestBody,
  SyncWindowGateView,
} from "../../api/types";
import { Button } from "../../ui/Button";
import { Modal, ModalBody, ModalFooter, ModalHeader } from "../../ui/Modal";
import { describeOperationError } from "../../utils/apiErrorText";
import { SyncWindowNotice } from "./SyncWindows";
import { useModalBehavior } from "./useModalBehavior";

export interface SyncModalProps {
  open: boolean;
  namespace: string;
  name: string;
  targetRevision: string;
  disabledByRbac?: boolean;
  /**
   * The `AppProject` sync-window verdict for this application (`T17.4`).
   *
   * The server evaluated it at request time, so the dialog explains exactly what the controller
   * will do: a blocked window with `manualOverride: false` disables Confirm (the pass would be
   * skipped), and a blocked window with `manualOverride: true` says so before the operator clicks.
   */
  syncWindow?: SyncWindowGateView | null;
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
  syncWindow = null,
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
  // `T17.4`: a deny window the project did not opt out of makes a manual sync a no-op. Blocking
  // the button is honest; the dry-run preview stays available, because a window never suppresses
  // drift detection.
  const blockedByWindow = Boolean(syncWindow?.blocked && !syncWindow.manualOverride);

  const handleSubmit = async () => {
    if (dryRun) {
      onClose();
      onPreviewDiff?.();
      return;
    }
    if (isForbidden || blockedByWindow || submitting) return;
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
        icon={<RefreshCw className="h-4 w-4 text-accent" />}
        onClose={onClose}
        closeLabel="Close sync modal"
      />

      <ModalBody>
        <p id="sync-modal-description" className="break-words text-ink-body">
          Request a manual reconcile for{" "}
          <code className="break-all rounded bg-canvas px-1.5 py-0.5 font-mono text-xs text-accent">
            {namespace}/{name}
          </code>{" "}
          at revision{" "}
          <code className="break-all rounded bg-canvas px-1.5 py-0.5 font-mono text-xs text-ink">
            {targetRevision}
          </code>
          .
        </p>

        <SyncWindowNotice syncWindow={syncWindow} />

        <div className="space-y-2.5 rounded-xl border border-line bg-canvas p-3.5 text-xs">
          <label className="flex items-start gap-2.5 text-ink-muted">
            <input
              type="checkbox"
              checked={false}
              disabled
              className="mt-0.5 cursor-not-allowed rounded border-line-strong bg-surface text-accent opacity-60"
            />
            <span>
              <strong className="block font-medium text-ink-body">
                Prune orphaned resources
              </strong>
              <span className="text-ink-muted">
                Configured via{" "}
                <code className="font-mono">spec.syncPolicy.automated.prune</code>{" "}
                (v1.0).
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2.5 text-ink">
            <input
              type="checkbox"
              checked={dryRun}
              disabled={submitting}
              onChange={(e) => setDryRun(e.target.checked)}
              className="mt-0.5 rounded border-line-emphasis bg-surface text-accent"
            />
            <span>
              <strong className="block font-medium">Dry-run preview</strong>
              <span className="text-ink-muted">
                Opens the live SSA dry-run Diff tab powered by{" "}
                <code className="font-mono">GET .../diff</code> without
                triggering a sync.
              </span>
            </span>
          </label>

          {onPreviewDiff && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-2.5 text-ink-muted">
              <span className="flex items-center gap-1.5">
                <Info className="h-3.5 w-3.5 text-info" />
                Want to preview SSA dry-run changes first?
              </span>
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onPreviewDiff();
                }}
                className="font-medium text-accent transition-colors hover:text-accent"
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
            className="flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-danger-tint p-3 text-xs text-danger motion-fade-in"
          >
            <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <div>
              <p className="font-semibold text-danger">
                RBAC Permission Required (403 Forbidden)
              </p>
              <p className="mt-0.5 break-words">
                {error?.detail ??
                  "Your current Kubernetes identity has read-only access and is not permitted to trigger a sync on this project."}
              </p>
            </div>
          </div>
        )}

        {!isForbidden && !blockedByWindow && error && (
          <div
            role="alert"
            data-testid="sync-error"
            className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-warning-tint p-3 text-xs text-warning motion-fade-in"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
            <div>
              <p className="font-semibold text-warning">{error.title}</p>
              <p className="mt-0.5 break-words text-warning">
                {error.detail}
              </p>
            </div>
          </div>
        )}

        {successResponse && (
          <div
            role="status"
            data-testid="sync-success-banner"
            className="rounded-lg border border-emerald-500/40 bg-success-tint p-3 text-xs text-success motion-fade-in"
          >
            <p>
              Sync request <strong>{successResponse.status}</strong> — the
              controller has been notified and will reconcile{" "}
              <code className="break-all font-mono">
                {successResponse.namespace}/{successResponse.name}
              </code>
              .
            </p>
            <p className="mt-1 text-success">
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
            disabled={
              dryRun ? submitting : isForbidden || blockedByWindow || submitting
            }
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
