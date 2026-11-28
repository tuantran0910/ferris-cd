import { useState, type FormEvent } from "react";
import { KeyRound, Lock, Server, ShieldCheck, UserRoundCheck } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { normalizeBaseUrl } from "../auth/tokenStorage";
import { Button } from "../ui/Button";

/**
 * The sign-in screen (`T19.2`).
 *
 * Three shapes, decided by `GET /api/v1/auth/config`:
 *
 * - `token-review`: the existing bearer-token form (unchanged behaviour, no SSO button);
 * - `oidc`: a single **Sign in with SSO** button — there is no token form to fall back to;
 * - `token-review-or-oidc`: the SSO button, with the token form inside a collapsible disclosure so a
 *   `ServiceAccount` token remains usable (CI-style automation, an IdP outage).
 *
 * Nothing here ever renders a token: the field is a password input, the value is handed to
 * `AuthContext` (memory + `sessionStorage` for the token mode; memory only for SSO) and cleared.
 */
export function LoginScreen() {
  const {
    baseUrl,
    authNotice,
    login,
    ssoAvailable,
    tokenLoginAvailable,
    tokenFormCollapsed,
    bffEnabled,
    beginSsoLogin,
    ssoBusy,
    ssoError,
    dismissSsoError,
  } = useAuth();
  const [tokenInput, setTokenInput] = useState("");
  const [serverInput, setServerInput] = useState(baseUrl);
  const [validationError, setValidationError] = useState<string | null>(null);
  // `null` = "follow the server's recommendation", which is only known after discovery resolves; an
  // explicit click wins from then on.
  const [tokenFormOpen, setTokenFormOpen] = useState<boolean | null>(null);
  const tokenFormExpanded = tokenFormOpen ?? !tokenFormCollapsed;

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

  const handleSso = () => {
    setValidationError(null);
    void beginSsoLogin();
  };

  // The token form is the sign-in method in `token-review`; in the mixed mode it lives behind a
  // disclosure, which starts closed.
  const showTokenForm = tokenLoginAvailable && tokenFormExpanded;
  const showSsoButton = ssoAvailable;

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-12">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl motion-scale-in">
        <div className="flex items-center gap-3">
          <img
            src="/ferriscd-mark.svg"
            alt=""
            width={44}
            height={44}
            className="h-11 w-11 drop-shadow-lg"
          />
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

        {ssoError && (
          <div
            role="alert"
            className="mt-5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200 motion-fade-in"
          >
            <p>{ssoError}</p>
            <button
              type="button"
              onClick={dismissSsoError}
              className="mt-1.5 underline decoration-rose-300/60 underline-offset-2 hover:text-rose-100"
            >
              Dismiss
            </button>
          </div>
        )}

        {showSsoButton && (
          <div className="mt-6 space-y-3">
            <Button
              type="button"
              variant="primary"
              size="lg"
              icon={<UserRoundCheck className="h-4 w-4" aria-hidden="true" />}
              className="w-full focus:ring-2 focus:ring-indigo-500/50"
              onClick={handleSso}
              disabled={ssoBusy}
            >
              {ssoBusy ? "Redirecting to your identity provider…" : "Sign in with SSO"}
            </Button>
            <p className="text-center text-[11px] text-slate-500">
              Authorization Code + PKCE (S256) — no client secret is stored in
              this app.
            </p>
          </div>
        )}

        {tokenLoginAvailable && tokenFormCollapsed && (
          <div className="mt-5">
            <button
              type="button"
              aria-expanded={tokenFormExpanded}
              aria-controls="ferriscd-token-fallback"
              onClick={() => setTokenFormOpen(!tokenFormExpanded)}
              className="flex w-full items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3.5 py-2.5 text-xs font-medium text-slate-300 transition-colors hover:border-slate-700 hover:text-slate-100"
            >
              <span>Use a ServiceAccount token instead</span>
              <span aria-hidden="true">{tokenFormExpanded ? "−" : "+"}</span>
            </button>
          </div>
        )}

        {showTokenForm && (
          <form
            id="ferriscd-token-fallback"
            onSubmit={handleSubmit}
            className="mt-5 space-y-4"
          >
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
        )}

        <div className="mt-6 flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-[11px] leading-relaxed text-slate-400">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
          {bffEnabled ? (
            <p>
              This server keeps your SSO session in an{" "}
              <code className="text-slate-300">HttpOnly</code>,{" "}
              <code className="text-slate-300">Secure</code> cookie sealed with
              the server&apos;s own key: no token ever reaches this page, and
              signing out expires the cookie. A Kubernetes{" "}
              <code className="text-slate-300">TokenReview</code> token is
              validated by the API server and stored only in memory and{" "}
              <code className="text-slate-300">sessionStorage</code> for this
              browser tab.
            </p>
          ) : ssoAvailable ? (
            <p>
              SSO tokens are kept in this tab&apos;s memory only — never in{" "}
              <code className="text-slate-300">localStorage</code>,{" "}
              <code className="text-slate-300">sessionStorage</code> or the URL —
              so closing the tab ends the session. A Kubernetes{" "}
              <code className="text-slate-300">TokenReview</code> token is
              validated by the API server and stored only in memory and{" "}
              <code className="text-slate-300">sessionStorage</code> for this
              browser tab.
            </p>
          ) : (
            <p>
              Tokens are validated via Kubernetes{" "}
              <code className="text-slate-300">TokenReview</code> and stored
              only in memory and{" "}
              <code className="text-slate-300">sessionStorage</code> for this
              browser tab—never in{" "}
              <code className="text-slate-300">localStorage</code> or URL
              parameters.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
