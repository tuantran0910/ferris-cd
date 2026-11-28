import { FolderGit2, Layers, LogOut, Monitor, Moon, Search, Server, Sun } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { flushSync } from "react-dom";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Button } from "../ui/Button";
import {
  CommandPalette,
  COMMAND_PALETTE_HINT,
  useCommandPaletteShortcut,
} from "./CommandPalette";
import {
  applyMode,
  applyThemeTransition,
  nextMode,
  readMode,
  resolveMode,
  type Theme,
  type ThemeMode,
} from "./theme";

const NAV_ITEMS = [
  { to: "/", label: "Applications", icon: Layers, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2, end: false },
  { to: "/clusters", label: "Clusters", icon: Server, end: false },
] as const;

/**
 * Application shell: skip link, header, primary nav, command palette and the routed content area.
 *
 * Page transitions: the routed content is keyed by `location.pathname`, so a
 * navigation remounts it with a 180ms fade + 2px rise (`motion-slide-up`).
 * Query-only changes (filters, view mode) keep the same pathname and therefore
 * the same element instance — the list must not animate, scroll or remount every
 * time an operator types in the search box.
 *
 * Accessibility (`T17.3`, WCAG 2.2 AA):
 * - the **first** focusable element is a "Skip to main content" link, visible on focus, pointing at
 *   `<main id="main-content">`, so keyboard users never have to tab through the header to reach a
 *   dashboard;
 * - `<main>` is a focus target (`tabIndex={-1}`) so following the skip link actually moves focus;
 * - the nav marks the current page with `aria-current="page"`, not just a colour;
 * - the palette is reachable with `Cmd+K`/`Ctrl+K` and from a real button, so the shortcut is
 *   discoverable rather than folklore.
 */
export function Layout() {
  const { baseUrl, logout, sessionStatus, beginSsoLogin, ssoAvailable } = useAuth();
  const { pathname } = useLocation();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mode, setMode] = useState<ThemeMode>(readMode);
  const [theme, setTheme] = useState<Theme>(() => resolveMode(readMode()));

  const togglePalette = useCallback(() => setPaletteOpen((open) => !open), []);
  const toggleTheme = useCallback(() => {
    const next = nextMode(mode);
    applyThemeTransition(() => {
      const resolved = applyMode(next);
      flushSync(() => {
        setMode(next);
        setTheme(resolved);
      });
    });
  }, [mode]);

  // `system` must follow the OS live, not just at first paint.
  useEffect(() => {
    if (mode !== "system" || typeof window.matchMedia !== "function") {
      return;
    }
    const query = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      const resolved = resolveMode("system");
      document.documentElement.dataset.theme = resolved;
      setTheme(resolved);
    };
    query.addEventListener?.("change", onChange);
    return () => query.removeEventListener?.("change", onChange);
  }, [mode]);
  useCommandPaletteShortcut(togglePalette);

  // A new route starts at the top of the page. Assigning `scrollTop` (rather
  // than `scrollTo`/`scrollIntoView`) keeps this a no-op in environments without
  // a layout engine, and it is instant by design: `scroll-behavior: smooth` is
  // for in-page anchors, not for a route change that already animates.
  useEffect(() => {
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [pathname]);

  return (
    <div className="flex min-h-screen flex-col bg-canvas text-strong">
      <a
        href="#main-content"
        data-testid="skip-to-content"
        className="sr-only rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white focus:not-sr-only focus:absolute focus:left-4 focus:top-3 focus:z-50"
      >
        Skip to main content
      </a>

      <header className="sticky top-0 z-30 border-b border-default bg-canvas/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="flex items-center gap-2.5 font-semibold tracking-tight text-strong transition-colors hover:text-strong"
            >
              <img
                src="/ferriscd-mark.svg"
                alt=""
                width={28}
                height={28}
                className="h-7 w-7"
              />
              <span>FerrisCD</span>
            </Link>
            <nav aria-label="Primary" className="flex items-center gap-1">
              {NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                      isActive
                        ? "bg-elevated text-strong"
                        : "text-primary hover:bg-elevated/80 hover:text-strong"
                    }`
                  }
                >
                  <item.icon className="h-4 w-4 text-accent" aria-hidden="true" />
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={`Theme: ${mode}. Switch to ${nextMode(mode)}.`}
              title={`Theme: ${mode}. Switch to ${nextMode(mode)}.`}
              data-testid="theme-toggle"
              className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-strong bg-surface text-body transition-colors hover:border-emphasis hover:bg-elevated hover:text-strong"
            >
              {mode === "system" ? (
                <Monitor aria-hidden="true" className="h-4 w-4" />
              ) : theme === "light" ? (
                <Moon aria-hidden="true" className="h-4 w-4" />
              ) : (
                <Sun aria-hidden="true" className="h-4 w-4" />
              )}
            </button>
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              aria-keyshortcuts="Meta+K Control+K"
              title={`Search everything (${COMMAND_PALETTE_HINT})`}
              className="hidden items-center gap-2 rounded-lg border border-strong bg-surface px-2.5 py-1.5 text-xs text-primary transition-colors hover:border-emphasis hover:bg-elevated sm:inline-flex"
            >
              <Search aria-hidden="true" className="h-3.5 w-3.5 text-body" />
              <span>Search</span>
              <kbd className="rounded border border-emphasis bg-canvas px-1 py-0.5 font-mono text-[10px] text-primary">
                ⌘K
              </kbd>
            </button>
            <span
              className="hidden max-w-[22rem] items-center gap-1.5 truncate rounded-md border border-default bg-surface px-2.5 py-1 font-mono text-xs text-body sm:inline-flex"
              title={`Connected FerrisCD API endpoint: ${baseUrl || "same-origin"}`}
            >
              <Server className="h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
              <span className="truncate">{baseUrl || "same-origin"}</span>
            </span>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => logout()}
              icon={<LogOut className="h-3.5 w-3.5" />}
              className="px-3 py-1.5"
            >
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      {/* `T19.2`: a warning *before* the token expires, while the operator still has a session — the
          one-click re-authenticate keeps the current route, so nothing in progress is lost. */}
      {sessionStatus === "expiring" && (
        <div
          role="status"
          className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-warning sm:px-6"
        >
          <div className="mx-auto flex max-w-7xl items-center justify-between gap-3">
            <span>
              Your SSO session expires in less than a minute. Re-authenticate now to
              stay signed in.
            </span>
            {ssoAvailable && (
              <button
                type="button"
                onClick={() => void beginSsoLogin()}
                className="shrink-0 rounded-md border border-amber-400/50 bg-amber-500/20 px-2.5 py-1 font-semibold text-warning transition-colors hover:bg-amber-500/30"
              >
                Re-authenticate
              </button>
            )}
          </div>
        </div>
      )}

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 focus:outline-none sm:px-6"
      >
        <div key={pathname} className="motion-slide-up">
          <Outlet />
        </div>
      </main>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
