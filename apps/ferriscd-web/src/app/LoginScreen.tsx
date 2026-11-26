import { useState, type FormEvent } from "react";
import { KeyRound, Lock, Server, ShieldCheck } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { normalizeBaseUrl } from "../auth/tokenStorage";
import { Button } from "../ui/Button";

export function LoginScreen() {
  const { baseUrl, authNotice, login } = useAuth();
  const [tokenInput, setTokenInput] = useState("");
  const [serverInput, setServerInput] = useState(baseUrl);
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = tokenInput.trim();
    if (!trimmed) {
      setValidationError("Please enter a Kubernetes ServiceAccount bearer token.");
      return;
    }
    const trimmedUrl = serverInput.trim();
    if (trimmedUrl && normalizeBaseUrl(trimmedUrl) === "") {
      // Silently falling back to same-origin here would send the operator's
      // bearer token somewhere they did not point at, and the failure would
      // only show up as a confusing 401 later.
      setValidationError(
        "API Server URL must be an http(s) URL or a path prefix such as /ferriscd.",
      );
      return;
    }
    setValidationError(null);
    login(trimmed, serverInput);
    setTokenInput("");
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-12">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl motion-scale-in">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-orange-500 to-rose-600 font-bold text-white shadow-lg">
            F
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-slate-100">
              FerrisCD
            </h1>
            <p className="text-xs text-slate-400">
              Kubernetes-Native GitOps Control Plane
            </p>
          </div>
        </div>

        {authNotice && (
          <div
            role="alert"
            className="mt-5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 motion-fade-in"
          >
            {authNotice}
          </div>
        )}

        {validationError && (
          <div
            role="alert"
            className="mt-5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200 motion-fade-in"
          >
            {validationError}
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label
              htmlFor="ferriscd-token"
              className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-slate-300"
            >
              <KeyRound className="h-3.5 w-3.5 text-slate-400" />
              Kubernetes Bearer Token
            </label>
            <input
              id="ferriscd-token"
              name="token"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="Paste TokenReview-valid bearer token"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 font-mono text-sm text-slate-100 transition-colors placeholder-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/30"
            />
          </div>

          <div>
            <label
              htmlFor="ferriscd-api-url"
              className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-slate-300"
            >
              <Server className="h-3.5 w-3.5 text-slate-400" />
              API Server URL{" "}
              <span className="font-normal text-slate-500">
                (optional — leave blank for same-origin)
              </span>
            </label>
            <input
              id="ferriscd-api-url"
              name="serverUrl"
              type="text"
              value={serverInput}
              onChange={(e) => setServerInput(e.target.value)}
              placeholder="http://127.0.0.1:8080"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 font-mono text-xs text-slate-200 transition-colors placeholder-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/30"
            />
          </div>

          <Button
            type="submit"
            variant="primary"
            size="lg"
            icon={<Lock className="h-4 w-4" aria-hidden="true" />}
            className="w-full focus:ring-2 focus:ring-indigo-500/50"
          >
            Sign In
          </Button>
        </form>

        <div className="mt-6 flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-[11px] leading-relaxed text-slate-400">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
          <p>
            Tokens are validated via Kubernetes{" "}
            <code className="text-slate-300">TokenReview</code> and stored only
            in memory and <code className="text-slate-300">sessionStorage</code>{" "}
            for this browser tab—never in{" "}
            <code className="text-slate-300">localStorage</code> or URL
            parameters.
          </p>
        </div>
      </div>
    </div>
  );
}
