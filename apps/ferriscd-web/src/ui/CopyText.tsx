import { cx } from "../utils/cx";
import { COPY_EVENT } from "./CopyToast";

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
  const copy = async () => {
    let copied = true;
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const area = document.createElement("textarea");
      area.value = value;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      copied =
        typeof document.execCommand === "function" &&
        document.execCommand("copy");
      area.remove();
    }
    if (!copied) {
      return;
    }
    window.dispatchEvent(new CustomEvent(COPY_EVENT, { detail: { label } }));
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
        "relative -mx-0.5 inline-flex min-h-7 min-w-6 max-w-full cursor-pointer items-center px-0.5 py-1 text-left align-baseline hover:text-accent hover:underline",
        className,
      )}
    >
      <span className={wrap ? "min-w-0 break-all" : "min-w-0 whitespace-nowrap"}>
        {display ?? value}
      </span>
    </button>
  );
}
