import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, LogOut, RotateCcw } from "lucide-react";
import { ApiClientError } from "../api/client";

interface ApiErrorBoundaryProps {
  children: ReactNode;
  onReset?: () => void;
  onLogout?: () => void;
}

interface ApiErrorBoundaryState {
  error: Error | null;
}

export class ApiErrorBoundary extends Component<
  ApiErrorBoundaryProps,
  ApiErrorBoundaryState
> {
  override state: ApiErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ApiErrorBoundaryState {
    return { error };
  }

  override componentDidCatch(_error: Error, _info: ErrorInfo): void {
    // Error details are rendered in the fallback UI without logging bearer tokens.
  }

  private handleReset = () => {
    this.setState({ error: null });
    this.props.onReset?.();
  };

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) {
      return this.props.children;
    }

    const isApiError = error instanceof ApiClientError;
    const statusLabel = isApiError
      ? `${error.status} ${error.code}`
      : "Unexpected UI Error";

    return (
      <div
        role="alert"
        className="mx-auto my-12 max-w-xl rounded-xl border border-rose-500/40 bg-slate-900 p-6 shadow-xl"
      >
        <div className="flex items-start gap-3">
          <div className="rounded-lg bg-rose-500/15 p-2 text-rose-400">
            <AlertTriangle className="h-5 w-5" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-base font-semibold text-slate-100">
                Something went wrong
              </h2>
              <span className="rounded bg-rose-500/20 px-2 py-0.5 font-mono text-xs text-rose-300">
                {statusLabel}
              </span>
            </div>
            <p className="mt-2 break-words text-sm text-slate-300">
              {error.message || "An unexpected error occurred while rendering."}
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={this.handleReset}
                className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-indigo-500"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                Try Again
              </button>
              {this.props.onLogout && (
                <button
                  type="button"
                  onClick={() => {
                    this.setState({ error: null });
                    this.props.onLogout?.();
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  Sign Out
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export function ApiErrorAlert({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  const apiError = error instanceof ApiClientError ? error : null;
  const message =
    error instanceof Error ? error.message : "Failed to load data from API.";
  // `status === 0` means the request never reached the server: showing
  // "HTTP_0 (HTTP 0)" would send the operator looking for an HTTP problem.
  const networkError = apiError !== null && apiError.status === 0;
  const heading = networkError
    ? "API Server Unreachable"
    : apiError
      ? `${apiError.code} (HTTP ${apiError.status})`
      : "API Request Failed";

  return (
    <div
      role="alert"
      className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-4 text-sm text-rose-200"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-2.5">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <div className="min-w-0">
            <p className="font-medium text-rose-100">{heading}</p>
            <p className="mt-0.5 break-words text-rose-200/90">
              {networkError
                ? "The FerrisCD API server could not be reached. Check the API Server URL and your connection, then retry."
                : message}
            </p>
          </div>
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="shrink-0 rounded-md border border-rose-500/40 bg-rose-500/15 px-3 py-1 text-xs font-medium text-rose-100 hover:bg-rose-500/25"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  );
}
