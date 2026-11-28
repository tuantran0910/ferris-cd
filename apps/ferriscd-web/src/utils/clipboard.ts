export const COPY_EVENT = "ferriscd:copied";

/**
 * Copies a value with the async Clipboard API and falls back to the legacy
 * textarea command. Returns false when both paths fail so callers never claim a
 * copy that did not happen.
 */
export async function copyToClipboard(
  value: string,
  label: string,
): Promise<boolean> {
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
      typeof document.execCommand === "function" && document.execCommand("copy");
    area.remove();
  }
  if (!copied) {
    return false;
  }
  window.dispatchEvent(new CustomEvent(COPY_EVENT, { detail: { label } }));
  return true;
}
