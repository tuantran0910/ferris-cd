import { Layers, LogOut, Server } from "lucide-react";
import { useEffect } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Button } from "../ui/Button";

/**
 * Application shell: header, primary nav and the routed content area.
 *
 * Page transitions: the routed content is keyed by `location.pathname`, so a
 * navigation remounts it with a 180ms fade + 2px rise (`motion-slide-up`).
 * Query-only changes (filters, view mode) keep the same pathname and therefore
 * the same element instance — the list must not animate, scroll or remount every
 * time an operator types in the search box.
 */
export function Layout() {
  const { baseUrl, logout } = useAuth();
  const { pathname } = useLocation();

  // A new route starts at the top of the page. Assigning `scrollTop` (rather
  // than `scrollTo`/`scrollIntoView`) keeps this a no-op in environments without
  // a layout engine, and it is instant by design: `scroll-behavior: smooth` is
  // for in-page anchors, not for a route change that already animates.
  useEffect(() => {
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [pathname]);

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="flex items-center gap-2.5 font-semibold tracking-tight text-slate-100 transition-colors hover:text-white"
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
              <Link
                to="/"
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-800/80 hover:text-white"
              >
                <Layers className="h-4 w-4 text-indigo-400" />
                Applications
              </Link>
            </nav>
          </div>

          <div className="flex items-center gap-3">
            <span
              className="hidden max-w-[22rem] items-center gap-1.5 truncate rounded-md border border-slate-800 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-400 sm:inline-flex"
              title={`Connected FerrisCD API endpoint: ${baseUrl || "same-origin"}`}
            >
              <Server className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
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

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6">
        <div key={pathname} className="motion-slide-up">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
