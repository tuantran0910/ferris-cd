import { Layers, LogOut, Server } from "lucide-react";
import { Link, Outlet } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function Layout() {
  const { baseUrl, logout } = useAuth();

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="flex items-center gap-2.5 font-semibold tracking-tight text-slate-100 hover:text-white"
            >
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-orange-500 to-rose-600 text-xs font-bold text-white">
                F
              </span>
              <span>FerrisCD</span>
            </Link>
            <nav aria-label="Primary" className="flex items-center gap-1">
              <Link
                to="/"
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium text-slate-300 hover:bg-slate-800/80 hover:text-white"
              >
                <Layers className="h-4 w-4 text-indigo-400" />
                Applications
              </Link>
            </nav>
          </div>

          <div className="flex items-center gap-3">
            <span
              className="hidden items-center gap-1.5 rounded-md border border-slate-800 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-400 sm:inline-flex"
              title="Connected FerrisCD API endpoint"
            >
              <Server className="h-3.5 w-3.5 text-emerald-400" />
              {baseUrl || "same-origin"}
            </span>
            <button
              type="button"
              onClick={() => logout()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-800"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6">
        <Outlet />
      </main>
    </div>
  );
}
