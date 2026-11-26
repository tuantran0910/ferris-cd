/**
 * Joins class names, dropping falsy entries.
 *
 * Small and dependency-free on purpose: the UI is built from Tailwind utility
 * strings, and a full `classnames`/`clsx` runtime is not worth a new dependency.
 */
export function cx(
  ...values: Array<string | false | null | undefined>
): string {
  return values.filter(Boolean).join(" ");
}
