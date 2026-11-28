import { cx } from "../utils/cx";
import { COPY_EVENT } from "./CopyToast";

export interface CopyTextProps {
  value: string;
  /** Text shown for long values; the full value is copied. */
  display?: string;
  label: string;
  className?: string;
}

/**
 * Inline click-to-copy value. Hover changes the cursor and colour; a click
 * copies and raises the shared confirmation toast.
 */
export function CopyText({ value, display, label, className }: CopyTextProps) {
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
    window.dispatchEvent(
      new CustomEvent(COPY_EVENT, { detail: { label, value } }),
    );
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
        "inline max-w-full cursor-pointer truncate text-left align-baseline hover:text-accent hover:underline",
        className,
      )}
    >
      {display ?? value}
    </button>
  );
}
