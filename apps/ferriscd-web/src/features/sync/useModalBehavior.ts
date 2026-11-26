import { useEffect, useRef, type RefObject } from "react";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

export interface ModalBehaviorOptions {
  /** Blocks `Escape` (e.g. while a request is in flight). */
  dismissible?: boolean;
}

/**
 * Dialog keyboard/scroll behaviour shared by the Sync and Rollback modals.
 *
 * A `role="dialog" aria-modal="true"` declaration is only honest if the dialog
 * actually behaves modally, so this hook:
 * - moves focus into the dialog when it opens,
 * - traps `Tab`/`Shift+Tab` inside it (the page behind stays unreachable),
 * - closes on `Escape` unless `dismissible` is `false`,
 * - locks background scrolling,
 * - restores focus to the element that opened the dialog on close.
 *
 * The effect deliberately depends only on `open`/`dismissible`: callbacks and
 * parents re-render on every poll, and re-running this effect would yank focus
 * back to the first field every ten seconds.
 */
export function useModalBehavior(
  open: boolean,
  dialogRef: RefObject<HTMLElement | null>,
  onClose: () => void,
  { dismissible = true }: ModalBehaviorOptions = {},
): void {
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const previouslyFocused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;

    const dialog = dialogRef.current;
    const initialFocus =
      dialog?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR) ?? dialog;
    initialFocus?.focus();

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (dismissible) {
          event.preventDefault();
          onCloseRef.current();
        }
        return;
      }
      if (event.key !== "Tab") {
        return;
      }
      const container = dialogRef.current;
      if (!container) {
        return;
      }
      const focusable = Array.from(
        container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      ).filter(
        (element) => element.offsetParent !== null || element === container,
      );
      if (focusable.length === 0) {
        event.preventDefault();
        container.focus();
        return;
      }
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !container.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (
        !event.shiftKey &&
        (active === last || !container.contains(active))
      ) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previouslyFocused?.focus();
    };
  }, [open, dismissible, dialogRef]);
}
