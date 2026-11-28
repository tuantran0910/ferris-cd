import { Check } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { cx } from "../utils/cx";

export const COPY_EVENT = "ferriscd:copied";

interface ToastState {
  label: string;
  value: string;
  visible: boolean;
}

/**
 * Single global confirmation toast for every click-to-copy value. Living at the
 * viewport edge keeps the animation out of scroll containers (tables and diff
 * cards clip absolutely-positioned chips).
 */
export function CopyToast() {
  const [toast, setToast] = useState<ToastState>({
    label: "",
    value: "",
    visible: false,
  });
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    const onCopied = (event: Event) => {
      const detail = (
        event as CustomEvent<{ label?: string; value?: string }>
      ).detail;
      setToast({
        label: detail?.label ?? "Value",
        value: detail?.value ?? "",
        visible: true,
      });
      clearTimeout(timer.current);
      timer.current = setTimeout(
        () => setToast((current) => ({ ...current, visible: false })),
        1800,
      );
    };
    window.addEventListener(COPY_EVENT, onCopied);
    return () => {
      window.removeEventListener(COPY_EVENT, onCopied);
      clearTimeout(timer.current);
    };
  }, []);

  return createPortal(
    <div
      aria-live="polite"
      aria-atomic="true"
      className="pointer-events-none fixed inset-x-0 bottom-6 z-[60] flex justify-center px-4"
    >
      <div
        className={cx(
          "flex items-center gap-2.5 rounded-xl border border-line-strong bg-surface px-3.5 py-2.5 shadow-2xl transition-all duration-200 ease-out",
          toast.visible
            ? "translate-y-0 scale-100 opacity-100"
            : "translate-y-2 scale-95 opacity-0",
        )}
      >
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-success/15 text-success">
          <Check aria-hidden="true" className="h-3.5 w-3.5" />
        </span>
        <span className="min-w-0">
          <span className="block text-xs font-semibold text-ink-strong">
            Copied
          </span>
          <span className="block max-w-[260px] truncate font-mono text-[10px] text-ink-muted">
            {toast.value || toast.label}
          </span>
        </span>
        <span className="sr-only">{toast.label} copied</span>
      </div>
    </div>,
    document.body,
  );
}
