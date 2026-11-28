import { X } from "lucide-react";
import type { ReactNode, RefObject } from "react";
import { createPortal } from "react-dom";
import { cx } from "../utils/cx";

export interface ModalProps {
  open: boolean;
  /** id of the element holding the dialog title. */
  labelledBy: string;
  /** id of the element describing the dialog. */
  describedBy?: string;
  /** Ref to the panel: the focus trap and initial focus target. */
  dialogRef?: RefObject<HTMLDivElement | null>;
  /** Panel width utility, e.g. "max-w-lg" (default) or "max-w-2xl". */
  panelClassName?: string;
  /** Close when the dimmed backdrop is clicked (opt-in per modal). */
  onBackdropClick?: () => void;
  children: ReactNode;
}

/**
 * Dialog shell: backdrop + centred panel.
 *
 * Rendering is unchanged from the previous per-modal markup (`role="dialog"`,
 * `aria-modal`, `aria-labelledby`, `aria-describedby`, panel at `z-50`); only
 * the entrance motion is new:
 * - the backdrop fades (`motion-fade-in`),
 * - the panel scales in from 96% (`motion-scale-in`).
 *
 * Both animate `opacity`/`transform` only, run at 120–180ms, and are disabled
 * under `prefers-reduced-motion: reduce`. The backdrop is a separate layer so
 * fading it does not fade the panel with it.
 *
 * Backdrop clicks are opt-in: the command palette closes on outside clicks,
 * while the Sync/Rollback modals keep their explicit close paths.
 */
export function Modal({
  open,
  labelledBy,
  describedBy,
  dialogRef,
  panelClassName,
  onBackdropClick,
  children,
}: ModalProps) {
  if (!open) {
    return null;
  }

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      className="fixed inset-0 z-50 overflow-y-auto"
    >
      <div
        aria-hidden="true"
        data-testid="modal-backdrop"
        onClick={onBackdropClick}
        className="motion-fade-in fixed inset-0 bg-black/70 backdrop-blur-sm"
      />
      <div
        data-testid="modal-outside"
        className="relative flex min-h-full items-center justify-center p-4"
        onClick={(event) => {
          if (event.target === event.currentTarget) {
            onBackdropClick?.();
          }
        }}
      >
        <div
          ref={dialogRef}
          tabIndex={-1}
          className={cx(
            "motion-scale-in w-full rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl focus:outline-none",
            panelClassName ?? "max-w-lg",
          )}
        >
          {children}
        </div>
      </div>
    </div>,
    document.body,
  );
}

export interface ModalHeaderProps {
  titleId: string;
  title: string;
  icon?: ReactNode;
  onClose: () => void;
  /** Accessible name of the close button, e.g. "Close sync modal". */
  closeLabel: string;
}

export function ModalHeader({
  titleId,
  title,
  icon,
  onClose,
  closeLabel,
}: ModalHeaderProps) {
  return (
    <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
      <div className="flex items-center gap-2">
        {icon}
        <h2 id={titleId} className="text-base font-semibold text-slate-100">
          {title}
        </h2>
      </div>
      <button
        type="button"
        onClick={onClose}
        aria-label={closeLabel}
        className="rounded-lg p-1 text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

export function ModalBody({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx("space-y-4 px-5 py-5 text-sm", className)}>{children}</div>
  );
}

export function ModalFooter({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center justify-end gap-2.5 border-t border-slate-800 px-5 py-3.5">
      {children}
    </div>
  );
}
