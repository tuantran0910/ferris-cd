import type { HTMLAttributes } from "react";
import { cx } from "../utils/cx";

/** Surface shared by every card in the UI. Exported for card-shaped callers
 *  that must render a different element (e.g. a router `Link`). */
export const CARD_SURFACE_CLASS =
  "rounded-xl border border-line bg-surface";

/** Hover treatment for cards that are themselves clickable. The 2px lift is
 *  CSS-only and is neutralised under `prefers-reduced-motion`. */
export const CARD_INTERACTIVE_CLASS =
  "motion-interactive motion-lift hover:-translate-y-0.5 hover:border-indigo-500/60 hover:bg-surface";

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  /** Adds the hover lift + border/background transition. */
  interactive?: boolean;
  /** Removes the default `p-4` when the caller manages its own padding. */
  disablePadding?: boolean;
}

export function Card({
  interactive = false,
  disablePadding = false,
  className,
  children,
  ...rest
}: CardProps) {
  return (
    <div
      {...rest}
      className={cx(
        CARD_SURFACE_CLASS,
        !disablePadding && "p-4",
        interactive && CARD_INTERACTIVE_CLASS,
        className,
      )}
    >
      {children}
    </div>
  );
}
