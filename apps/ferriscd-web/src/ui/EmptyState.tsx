import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../utils/cx";

export type EmptyStateSize = "sm" | "md" | "lg";

const PADDING_CLASSES: Record<EmptyStateSize, string> = {
  sm: "p-8",
  md: "p-10",
  lg: "p-12",
};

export interface EmptyStateProps
  extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  /** Optional action rendered under the message (e.g. "Clear filters"). */
  action?: ReactNode;
  /** Draws the surrounding card surface. Off when already nested in a card. */
  bordered?: boolean;
  size?: EmptyStateSize;
}

/**
 * The "there is nothing here" block.
 *
 * Callers own the copy: the difference between "no applications visible to your
 * identity" (RBAC) and "no applications match the current filters" (user input)
 * is meaningful, so this component never invents a message.
 */
export function EmptyState({
  children,
  action,
  bordered = true,
  size = "sm",
  className,
  ...rest
}: EmptyStateProps) {
  return (
    <div
      {...rest}
      className={cx(
        "text-center text-sm text-ink-muted",
        PADDING_CLASSES[size],
        bordered && "rounded-xl border border-line bg-surface",
        className,
      )}
    >
      {children}
      {action}
    </div>
  );
}
