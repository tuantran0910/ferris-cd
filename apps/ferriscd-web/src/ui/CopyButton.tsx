import { Check, Copy } from "lucide-react";
import { useState } from "react";

/**
 * Copies a value that is useful outside the UI (a local repo path, a registry
 * URL, a namespace). The value stays visible next to the button, so the control
 * is an enhancement rather than the only way to read it.
 */
export function CopyButton({
  value,
  label,
}: {
  value: string;
  label: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={copied ? "Copied" : `Copy ${label}`}
      aria-label={copied ? "Copied" : `Copy ${label}`}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          },
          () => undefined,
        );
      }}
      className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-ink-subtle transition-colors hover:bg-elevated hover:text-ink-strong"
    >
      {copied ? (
        <Check aria-hidden="true" className="h-3 w-3" />
      ) : (
        <Copy aria-hidden="true" className="h-3 w-3" />
      )}
    </button>
  );
}
