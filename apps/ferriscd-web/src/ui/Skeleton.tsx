import { cx } from "../utils/cx";

export type SkeletonRadius = "sm" | "md" | "lg" | "xl" | "full";

const RADIUS_CLASSES: Record<SkeletonRadius, string> = {
  sm: "rounded-sm",
  md: "rounded-md",
  lg: "rounded-lg",
  xl: "rounded-xl",
  full: "rounded-full",
};

export interface SkeletonProps {
  className?: string;
  radius?: SkeletonRadius;
}

/**
 * Loading placeholder.
 *
 * Replaces the old `animate-pulse` blocks: a pulsing block (opacity 1 → 0.5)
 * reads as "flickering broken UI", whereas a slow horizontal shimmer reads as
 * "content is on its way". The sweep is painted by `.motion-shimmer::after`
 * (a translated pseudo-element) so no layout property is ever animated, and it
 * disappears entirely under `prefers-reduced-motion: reduce`.
 *
 * Always `aria-hidden`: the surrounding region owns the accessible
 * "loading" state, and a placeholder has nothing to announce.
 */
export function Skeleton({ className, radius = "xl" }: SkeletonProps) {
  return (
    <div
      aria-hidden="true"
      data-skeleton="true"
      className={cx(
        "motion-shimmer border border-line bg-surface",
        RADIUS_CLASSES[radius],
        className,
      )}
    />
  );
}
