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
  neutral: "border-slate-600/60 bg-slate-800 text-slate-300",
  info: "border-sky-500/40 bg-sky-500/15 text-sky-300",
  success: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
  warning: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  orange: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  danger: "border-rose-500/40 bg-rose-500/15 text-rose-300",
  violet: "border-violet-500/40 bg-violet-500/15 text-violet-300",
  fuchsia: "border-fuchsia-500/40 bg-fuchsia-500/15 text-fuchsia-300",
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
