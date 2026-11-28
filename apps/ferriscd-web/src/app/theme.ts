export type Theme = "light" | "dark";
export type ThemeMode = Theme | "system";

const STORAGE_KEY = "ferriscd-theme";

function systemTheme(): Theme {
  const prefersLight =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: light)").matches;
  return prefersLight ? "light" : "dark";
}

/** The explicit choice (or `system` when the operator never chose). */
export function readMode(): ThemeMode {
  const painted = document.documentElement.dataset.themeMode;
  if (painted === "light" || painted === "dark" || painted === "system") {
    return painted;
  }
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") {
      return stored;
    }
  } catch {
    // Storage blocked: fall back to the OS preference.
  }
  return "system";
}

export function resolveMode(mode: ThemeMode): Theme {
  return mode === "system" ? systemTheme() : mode;
}

/** Keeps the browser chrome colour in step with the painted theme. */
export function syncThemeColor(theme: Theme): void {
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", theme === "light" ? "#f1f5f9" : "#020617");
}

/** Applies a mode, remembers it, and returns the resolved theme. */
export function applyMode(mode: ThemeMode): Theme {
  const resolved = resolveMode(mode);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themeMode = mode;
  syncThemeColor(resolved);
  try {
    window.localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // The theme still applies for this page.
  }
  return resolved;
}

export function nextMode(mode: ThemeMode): ThemeMode {
  if (mode === "light") return "dark";
  if (mode === "dark") return "system";
  return "light";
}

/**
 * Switches the theme with one short cross-fade when the browser supports the
 * View Transitions API. Per-element colour transitions would fire at different
 * times and read as a flicker, so the switch is one composited snapshot instead.
 */
export function applyThemeTransition(commit: () => void): void {
  const reduceMotion =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const transition = document.startViewTransition?.bind(document);
  if (!transition || reduceMotion) {
    commit();
    return;
  }
  transition(commit);
}
