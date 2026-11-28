import type { HTMLAttributes } from "react";
import { cx } from "../utils/cx";

export type BadgeTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "orange"
  | "danger"
  | "violet"
  | "fuchsia";

export type BadgeSize = "sm" | "md";

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: "border-line-emphasis bg-elevated text-ink-body",
  info: "border-sky-500/40 bg-sky-500/15 text-info",
  success: "border-emerald-500/40 bg-emerald-500/15 text-success",
  warning: "border-amber-500/40 bg-amber-500/15 text-warning",
  orange: "border-orange-500/40 bg-orange-500/15 text-kind-job",
  danger: "border-rose-500/40 bg-rose-500/15 text-danger",
  violet: "border-violet-500/40 bg-violet-500/15 text-kind-namespace",
  fuchsia: "border-fuchsia-500/40 bg-fuchsia-500/15 text-kind-workload",
};

const SIZE_CLASSES: Record<BadgeSize, string> = {
  sm: "gap-1 px-2 py-0.5 text-[11px]",
  md: "gap-1.5 px-2.5 py-1 text-xs",
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  size?: BadgeSize;
}

/**
 * Pill used for status/conflict/inspection labels.
 *
 * It is presentational only: the caller supplies the icon and the text (e.g.
 * "Sync: OutOfSync"), which keeps every badge self-describing — a colour alone
 * must never be the only signal, and colour does not animate.
 */
export function Badge({
  tone = "neutral",
  size = "md",
  className,
  children,
  ...rest
}: BadgeProps) {
  return (
    <span
      {...rest}
      className={cx(
        "inline-flex items-center rounded-full border font-medium",
        SIZE_CLASSES[size],
        TONE_CLASSES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
