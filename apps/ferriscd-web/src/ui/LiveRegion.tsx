import { cx } from "../utils/cx";

export interface LiveRegionProps {
  /** The sentence to announce. Changing it is what triggers the announcement. */
  message: string;
  /**
   * `polite` (default) queues the message behind whatever the screen reader is saying;
   * `assertive` interrupts. Status updates use `polite` — nothing here is an emergency.
   */
  politeness?: "polite" | "assertive";
  className?: string;
  "data-testid"?: string;
}

/**
 * Visually hidden ARIA live region (WCAG 2.2 AA, SC 4.1.3 "Status Messages").
 *
 * The dashboard updates itself every poll, so state changes (an application recovering, the events
 * timeline refreshing, the palette result count changing) would otherwise be invisible to a screen
 * reader user: nothing they did caused the change, and no focus moves. Announcing a short sentence
 * is the accessible equivalent of the badge turning green.
 *
 * `aria-atomic="true"` makes the *whole* sentence readable rather than just the changed word, and
 * `sr-only` keeps it out of the visual design (it is never `display: none`, which would remove it
 * from the accessibility tree entirely).
 */
export function LiveRegion({
  message,
  politeness = "polite",
  className,
  "data-testid": testId = "live-region",
}: LiveRegionProps) {
  return (
    <div
      role="status"
      aria-live={politeness}
      aria-atomic="true"
      data-testid={testId}
      className={cx("sr-only", className)}
    >
      {message}
    </div>
  );
}
