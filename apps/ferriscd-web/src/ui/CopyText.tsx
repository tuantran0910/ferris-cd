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
 * only changes the cursor and colour, and a click copies the full value.
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
        "inline max-w-full truncate text-left align-baseline [cursor:copy] hover:text-accent hover:underline",
        className,
      )}
    >
      {display ?? value}
    </button>
  );
}
