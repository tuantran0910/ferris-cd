import { AlertTriangle, History, RotateCcw, ShieldOff } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type {
  HistoryView,
  OperationResponse,
  RollbackRequestBody,
} from "../../api/types";
import { Button } from "../../ui/Button";
import { CopyText } from "../../ui/CopyText";
import { EmptyState } from "../../ui/EmptyState";
import { Modal, ModalBody, ModalFooter, ModalHeader } from "../../ui/Modal";
import { describeOperationError } from "../../utils/apiErrorText";
import { shortRevision } from "../../utils/format";
import { useModalBehavior } from "./useModalBehavior";

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
  const [error, setError] = useState<{ title: string; detail: string } | null>(
    null,
  );
  const [forbidden, setForbidden] = useState(disabledByRbac);
  const [successResponse, setSuccessResponse] =
    useState<OperationResponse | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (open) {
      setSelectedId(initialHistoryId ?? sortedHistory[0]?.id ?? null);
      setError(null);
      setSuccessResponse(null);
      setForbidden(disabledByRbac);
    }
    // Only reset transient modal state when the dialog opens, not when
    // disabledByRbac flips true in response to a 403 inside the open modal.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initialHistoryId]);

  useModalBehavior(open, dialogRef, onClose, { dismissible: !submitting });

  if (!open) {
    return null;
  }

  const isForbidden = forbidden || disabledByRbac;
  const selectionExists =
    selectedId !== null && sortedHistory.some((entry) => entry.id === selectedId);

  const handleSubmit = async () => {
    if (isForbidden || submitting || !selectionExists || selectedId === null) {
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await onConfirm({ id: selectedId });
      setSuccessResponse(result);
    } catch (err) {
      const described = describeOperationError(err, "rollback");
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
      labelledBy="rollback-modal-title"
      describedBy="rollback-modal-description"
      dialogRef={dialogRef}
    >
      <ModalHeader
        titleId="rollback-modal-title"
        title="Rollback Application"
        icon={<RotateCcw className="h-4 w-4 text-warning" />}
        onClose={onClose}
        closeLabel="Close rollback modal"
      />

      <ModalBody>
        <p
          id="rollback-modal-description"
          className="break-words text-ink-body"
        >
          Select a previous deployment from{" "}
          <code className="break-all rounded bg-canvas px-1.5 py-0.5 font-mono text-xs text-accent">
            {namespace}/{name}
          </code>{" "}
          history to redeploy.
        </p>

        <div
          role="note"
          data-testid="rollback-auto-sync-warning"
          className="flex items-start gap-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs text-warning"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          <div>
            <p className="font-semibold text-warning">
              Automated sync will be paused
            </p>
            <p className="mt-0.5 leading-relaxed text-warning">
              Rolling back pins this application to the chosen commit and
              disables{" "}
              <code className="font-mono text-warning">
                spec.syncPolicy.automated
              </code>{" "}
              so the controller does not immediately overwrite the rollback.
            </p>
          </div>
        </div>

        {sortedHistory.length === 0 ? (
          <EmptyState>
            <History className="mx-auto mb-2 h-5 w-5 text-ink-subtle" />
            No deployment history entries are available to roll back to.
          </EmptyState>
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
                  className={`flex cursor-pointer items-center justify-between gap-3 rounded-xl border px-3.5 py-2.5 text-xs transition-colors ${
                    checked
                      ? "border-indigo-500 bg-indigo-500/10 text-ink-strong"
                      : "border-line bg-canvas text-ink-body hover:border-line-strong"
                  }`}
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <input
                      type="radio"
                      name="rollback-history-id"
                      value={entry.id}
                      checked={checked}
                      onChange={() => setSelectedId(entry.id)}
                      className="border-line-emphasis bg-surface text-accent"
                    />
                    <div className="min-w-0">
                      <p className="font-semibold text-ink-strong">
                        Deployment #{entry.id}
                      </p>
                      <p
                        className="break-all font-mono text-[11px] text-accent"
                        title={entry.revision ?? undefined}
                      >
                        {entry.revision ? (
                          <CopyText
                            value={entry.revision}
                            display={shortRevision(entry.revision, 12)}
                            label="rollback revision"
                          />
                        ) : (
                          shortRevision(entry.revision, 12)
                        )}
                      </p>
                    </div>
                  </div>
                  <time
                    dateTime={entry.deployedAt}
                    title={entry.deployedAt}
                    className="shrink-0 font-mono text-[11px] text-ink-muted"
                  >
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
            className="flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-danger-tint p-3 text-xs text-danger motion-fade-in"
          >
            <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <div>
              <p className="font-semibold text-danger">
                RBAC Permission Required (403 Forbidden)
              </p>
              <p className="mt-0.5 break-words">
                {error?.detail ??
                  "Your current Kubernetes identity is not permitted to roll back this application."}
              </p>
            </div>
          </div>
        )}

        {!isForbidden && error && (
          <div
            role="alert"
            data-testid="rollback-error"
            className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-danger-tint p-3 text-xs text-danger motion-fade-in"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <div>
              <p className="font-semibold text-danger">{error.title}</p>
              <p className="mt-0.5 break-words text-danger">
                {error.detail}
              </p>
            </div>
          </div>
        )}

        {successResponse && (
          <div
            role="status"
            data-testid="rollback-success-banner"
            className="rounded-lg border border-emerald-500/40 bg-success-tint p-3 text-xs text-success motion-fade-in"
          >
            <p>
              Rollback request <strong>{successResponse.status}</strong> — the
              controller will redeploy deployment <strong>#{selectedId}</strong>{" "}
              and pause automated sync.
            </p>
            <p className="mt-1 text-success">
              Polling for the Sync badge and history to update; this dialog can
              be closed.
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
            disabled={isForbidden || submitting || !selectionExists}
            isLoading={submitting}
            icon={<RotateCcw className="h-3.5 w-3.5" />}
            className="bg-amber-600 hover:bg-amber-500"
          >
            {submitting ? "Rolling back..." : "Confirm Rollback"}
          </Button>
        )}
      </ModalFooter>
    </Modal>
  );
}
