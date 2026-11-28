import { copyToClipboard } from "../utils/clipboard";
import { cx } from "../utils/cx";

export interface CopyTextProps {
  value: string;
  /** Text shown for long values; the full value is copied. */
  display?: string;
  label: string;
  className?: string;
  /** Allow long values (e.g. GKNN keys) to wrap; revisions stay on one line. */
  wrap?: boolean;
}

/**
 * Inline click-to-copy value. Hover changes the cursor and colour; a click
 * copies and raises the shared confirmation toast.
 */
export function CopyText({
  value,
  display,
  label,
  className,
  wrap = false,
}: CopyTextProps) {
  const copy = () => {
    void copyToClipboard(value, label);
  };

  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation();
        copy();
      }}
      title={`Click to copy ${label}`}
      aria-label={`Copy ${label}`}
      className={cx(
        "relative inline-flex min-h-6 max-w-full cursor-pointer items-center text-left align-baseline hover:text-accent hover:underline",
        className,
      )}
    >
      <span className={wrap ? "min-w-0 break-all" : "min-w-0 whitespace-nowrap"}>
        {display ?? value}
      </span>
    </button>
  );
}
