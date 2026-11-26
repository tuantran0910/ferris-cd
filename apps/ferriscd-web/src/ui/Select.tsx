import { Check, ChevronDown } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { cx } from "../utils/cx";

export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps {
  "aria-label": string;
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  className?: string;
  disabled?: boolean;
}

/**
 * Themed listbox replacing a native `<select>`.
 *
 * A native `<option>` popup is painted by the operating system, so it always
 * breaks the dark theme. This implements the ARIA combobox/listbox pattern
 * instead: the trigger keeps focus and drives the active option through
 * `aria-activedescendant`, while Arrow keys / Home / End / Enter / Space /
 * Escape and click-outside are handled explicitly. Chevron and menu use the
 * shared motion tokens, so `prefers-reduced-motion` removes them.
 */
export function Select({
  "aria-label": ariaLabel,
  value,
  onChange,
  options,
  className,
  disabled = false,
}: SelectProps) {
  const id = useId();
  const listId = `${id}-listbox`;
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);

  const selectedIndex = options.findIndex((option) => option.value === value);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : undefined;

  const openMenu = () => {
    if (disabled) return;
    setActiveIndex(selectedIndex >= 0 ? selectedIndex : 0);
    setOpen(true);
  };

  const closeMenu = (restoreFocus: boolean) => {
    setOpen(false);
    setActiveIndex(-1);
    if (restoreFocus) {
      triggerRef.current?.focus();
    }
  };

  const commit = (index: number) => {
    const option = options[index];
    if (!option) return;
    onChange(option.value);
    closeMenu(true);
  };

  useEffect(() => {
    if (!open) {
      return;
    }
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        closeMenu(false);
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  useEffect(() => {
    if (!open || activeIndex < 0) {
      return;
    }
    const active = listRef.current?.querySelector<HTMLElement>(
      `[data-index="${activeIndex}"]`,
    );
    // jsdom (tests) does not implement scrollIntoView.
    active?.scrollIntoView?.({ block: "nearest" });
  }, [activeIndex, open]);

  const onTriggerKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    switch (event.key) {
      case "ArrowDown":
      case "ArrowUp": {
        event.preventDefault();
        if (!open) {
          openMenu();
          return;
        }
        const delta = event.key === "ArrowDown" ? 1 : -1;
        setActiveIndex((index) =>
          Math.min(options.length - 1, Math.max(0, index + delta)),
        );
        return;
      }
      case "Home":
        if (open) {
          event.preventDefault();
          setActiveIndex(0);
        }
        return;
      case "End":
        if (open) {
          event.preventDefault();
          setActiveIndex(options.length - 1);
        }
        return;
      case "Enter":
      case " ":
        event.preventDefault();
        if (open) {
          commit(activeIndex);
        } else {
          openMenu();
        }
        return;
      case "Escape":
        if (open) {
          event.preventDefault();
          closeMenu(true);
        }
        return;
      case "Tab":
        if (open) {
          closeMenu(false);
        }
        return;
      default:
        return;
    }
  };

  return (
    <div ref={rootRef} className={cx("relative", className)}>
      <button
        ref={triggerRef}
        type="button"
        role="combobox"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-activedescendant={
          open && activeIndex >= 0 ? `${id}-option-${activeIndex}` : undefined
        }
        disabled={disabled}
        onClick={() => (open ? closeMenu(true) : openMenu())}
        onKeyDown={onTriggerKeyDown}
        className={cx(
          "flex w-full items-center justify-between gap-2 rounded-lg border border-slate-700 bg-slate-950 py-2 pl-3 pr-3 text-left text-xs text-slate-200 transition-colors focus:border-indigo-500 focus:outline-none",
          disabled ? "cursor-not-allowed opacity-60" : "hover:border-slate-600",
        )}
      >
        <span className="truncate">{selected?.label ?? value}</span>
        <ChevronDown
          aria-hidden="true"
          className={cx(
            "h-3.5 w-3.5 shrink-0 text-slate-400 transition-transform duration-150",
            open && "rotate-180",
          )}
        />
      </button>

      {open && (
        <ul
          ref={listRef}
          id={listId}
          role="listbox"
          aria-label={ariaLabel}
          className="motion-scale-in absolute z-50 mt-1 max-h-64 w-full origin-top overflow-auto rounded-lg border border-slate-700 bg-slate-900 p-1 shadow-2xl"
        >
          {options.map((option, index) => {
            const isSelected = option.value === value;
            return (
              <li
                key={option.value}
                id={`${id}-option-${index}`}
                data-index={index}
                role="option"
                aria-selected={isSelected}
                tabIndex={-1}
                onMouseEnter={() => setActiveIndex(index)}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => commit(index)}
                className={cx(
                  "flex cursor-pointer items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-xs",
                  index === activeIndex
                    ? "bg-slate-800 text-white"
                    : "text-slate-300",
                  isSelected && "text-indigo-200",
                )}
              >
                <span className="truncate">{option.label}</span>
                {isSelected && (
                  <Check
                    aria-hidden="true"
                    className="h-3.5 w-3.5 shrink-0 text-indigo-300"
                  />
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
