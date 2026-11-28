import { Check } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { cx } from "../utils/cx";

export const COPY_EVENT = "ferriscd:copied";

interface ToastState {
  label: string;
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
    visible: false,
  });
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    const onCopied = (event: Event) => {
      const label = (event as CustomEvent<{ label?: string }>).detail?.label;
      setToast({ label: label ?? "Value", visible: true });
      clearTimeout(timer.current);
      timer.current = setTimeout(
        () => setToast((current) => ({ ...current, visible: false })),
        1600,
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
          "flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface px-3 py-2 text-xs font-medium text-ink-strong shadow-lg transition-all duration-200 ease-out",
          toast.visible
            ? "translate-y-0 scale-100 opacity-100"
            : "translate-y-2 scale-95 opacity-0",
        )}
      >
        <Check aria-hidden="true" className="h-3.5 w-3.5 text-success" />
        <span>Copied</span>
        <span className="sr-only">{toast.label} copied</span>
      </div>
    </div>,
    document.body,
  );
}
