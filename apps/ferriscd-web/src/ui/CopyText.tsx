import { useEffect, useRef, useState } from "react";
import { cx } from "../utils/cx";

export interface CopyTextProps {
  value: string;
  /** Text shown for long values; the full value is copied. */
  display?: string;
  label: string;
  className?: string;
}

/**
 * Inline click-to-copy value. The value keeps its natural text styling; hover
 * changes the cursor and colour, a click copies, and a short "Copied" chip
 * confirms the action without shifting the layout.
 */
export function CopyText({ value, display, label, className }: CopyTextProps) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const area = document.createElement("textarea");
      area.value = value;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    setCopied(true);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 1200);
  };

  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation();
        void copy();
      }}
      title={`Click to copy ${label}`}
      aria-label={`Copy ${label}`}
      className={cx(
        "relative inline-flex max-w-full cursor-pointer items-center text-left align-baseline hover:text-accent hover:underline",
        className,
      )}
    >
      <span className="truncate">{display ?? value}</span>
      {copied && (
        <span
          role="status"
          className="motion-fade-in pointer-events-none absolute -top-6 left-0 z-20 whitespace-nowrap rounded border border-line-strong bg-surface px-1.5 py-0.5 text-[10px] font-medium text-success shadow-lg"
        >
          Copied
        </span>
      )}
    </button>
  );
}
