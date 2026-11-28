export type Theme = "light" | "dark";

const STORAGE_KEY = "ferriscd-theme";

/** The theme the page was painted with, falling back to the OS preference. */
export function currentTheme(): Theme {
  const applied = document.documentElement.dataset.theme;
  if (applied === "light" || applied === "dark") {
    return applied;
  }
  const prefersLight =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: light)").matches;
  return prefersLight ? "light" : "dark";
}

/** Applies a theme and remembers the explicit choice for the next visit. */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Private mode / blocked storage: the theme still applies for this page.
  }
}

export function nextTheme(theme: Theme): Theme {
  return theme === "light" ? "dark" : "light";
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
