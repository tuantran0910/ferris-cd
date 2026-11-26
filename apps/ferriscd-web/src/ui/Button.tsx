import { Loader2 } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cx } from "../utils/cx";

export type ButtonVariant =
  | "primary"
  | "secondary"
  | "ghost"
  | "danger"
  | "warning";

export type ButtonSize = "sm" | "md" | "lg" | "icon";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Shows a spinner and marks the button busy; does not change its label. */
  isLoading?: boolean;
  /** Optional leading icon (rendered before the label). */
  icon?: ReactNode;
}

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    "bg-indigo-600 text-white font-semibold hover:bg-indigo-500 border border-transparent",
  secondary:
    "border border-slate-700 bg-slate-900 text-slate-200 font-medium hover:border-slate-600 hover:bg-slate-800",
  ghost:
    "border border-transparent text-slate-300 font-medium hover:bg-slate-800/80 hover:text-white",
  danger:
    "border border-rose-500/40 bg-rose-500/15 text-rose-100 font-medium hover:bg-rose-500/25",
  warning:
    "border border-amber-500/40 bg-amber-500/15 text-amber-200 font-semibold hover:bg-amber-500/25",
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  sm: "gap-1 rounded-md px-2.5 py-1 text-[11px]",
  md: "gap-1.5 rounded-lg px-3.5 py-2 text-xs",
  lg: "gap-2 rounded-lg px-4 py-2.5 text-sm",
  icon: "rounded-lg p-1.5",
};

/**
 * The single button primitive for the app.
 *
 * `variant` covers the four roles used across the UI (primary action,
 * secondary action, low-emphasis/ghost, destructive) plus `warning` for the
 * amber rollback family, so button styling is decided in one place instead of
 * being re-typed per call site. Labels, `data-testid`s and `disabled` semantics
 * stay with the caller — this component only owns appearance and the busy flag.
 *
 * Interaction motion (fast transform, colour transitions, 0.98 active press)
 * comes from `index.css`, so every button — including the ones that are not
 * using this component yet — behaves identically and respects reduced motion.
 */
export function Button({
  variant = "primary",
  size = "md",
  isLoading = false,
  icon,
  type = "button",
  className,
  children,
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      type={type}
      disabled={disabled}
      aria-busy={isLoading || undefined}
      data-loading={isLoading || undefined}
      className={cx(
        "inline-flex items-center justify-center",
        SIZE_CLASSES[size],
        VARIANT_CLASSES[variant],
        "disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
    >
      {isLoading ? (
        <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" aria-hidden="true" />
      ) : (
        icon
      )}
      {children}
    </button>
  );
}
