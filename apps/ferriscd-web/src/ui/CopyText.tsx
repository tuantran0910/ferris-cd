import { Check } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { cx } from "../utils/cx";

export interface CopyTextProps {
  value: string;
  /** Text shown for long values; the full value is copied. */
  display?: string;
  label: string;
  className?: string;
  /** Brief check-mark feedback after a successful copy. */
  feedback?: boolean;
}

/**
 * Inline click-to-copy value. The value keeps its natural text styling; hover
 * only changes the cursor and colour, and a click copies the full value.
 */
export function CopyText({
  value,
  display,
  label,
  className,
  feedback = false,
}: CopyTextProps) {
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
    if (feedback) {
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1200);
    }
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
        "inline max-w-full truncate text-left align-baseline [cursor:copy] hover:text-accent",
        className,
      )}
    >
      {display ?? value}
      {feedback && copied && (
        <Check
          aria-hidden="true"
          className="motion-scale-in ml-1 inline h-3 w-3 text-success"
        />
      )}
      {feedback && (
        <span aria-live="polite" className="sr-only">
          {copied ? "Copied" : ""}
        </span>
      )}
    </button>
  );
}
