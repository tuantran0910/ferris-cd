import { ApiClientError } from "../api/client";

export interface OperationErrorInfo {
  /** Short, human-readable heading (never raw JSON/HTTP plumbing as the only text). */
  title: string;
  /** Explanation, preferring the server's own (secret-free) message. */
  detail: string;
  /** True when the failure is an RBAC denial and the action must stay disabled. */
  forbidden: boolean;
}

function actionNoun(action: "sync" | "rollback"): string {
  return action === "sync" ? "sync" : "rollback";
}

/**
 * Turns an API failure from `POST .../sync|rollback` into text an operator can
 * act on. Every status the server documents for those two endpoints
 * (`400/401/403/404/409/413/422`, plus `0` for a network failure) gets its own
 * wording instead of leaking a bare stack/JSON payload into the dialog.
 */
export function describeOperationError(
  error: unknown,
  action: "sync" | "rollback",
): OperationErrorInfo {
  const noun = actionNoun(action);
  const fallback = `Failed to request ${noun}.`;

  if (!(error instanceof ApiClientError)) {
    return {
      title: `${action === "sync" ? "Sync" : "Rollback"} request failed`,
      detail: error instanceof Error && error.message ? error.message : fallback,
      forbidden: false,
    };
  }

  const detail = error.message?.trim() ? error.message : fallback;

  if (error.isForbidden) {
    return {
      title: "RBAC Permission Required (403 Forbidden)",
      detail:
        error.message?.trim() ||
        `Your current Kubernetes identity is not permitted to ${noun} this application.`,
      forbidden: true,
    };
  }
  if (error.isUnauthorized) {
    return {
      title: "Session expired (401 Unauthorized)",
      detail:
        "Your bearer token is no longer accepted. Sign in again with a fresh token.",
      forbidden: false,
    };
  }
  if (error.isConflict) {
    return {
      title: "Operation already pending (409 Conflict)",
      detail:
        action === "sync"
          ? `A rollback is still pending for this application and has not been consumed by the controller yet. Wait for it to be applied, then sync. (${detail})`
          : `The Application changed while the request was recorded. Reload and try again. (${detail})`,
      forbidden: false,
    };
  }
  if (error.isUnprocessable) {
    return {
      title:
        action === "rollback"
          ? "Rollback entry no longer valid (422)"
          : "Request cannot be honoured (422)",
      detail:
        action === "rollback"
          ? `This deployment id is no longer in the Application's history. Refresh the page and pick another entry. (${detail})`
          : detail,
      forbidden: false,
    };
  }
  if (error.isNotFound) {
    return {
      title: "Application not found (404 NotFound)",
      detail:
        "It does not exist, or it is not visible to your identity. (Identical answers by design.)",
      forbidden: false,
    };
  }
  if (error.status === 413) {
    return {
      title: "Request rejected: payload too large (413)",
      detail,
      forbidden: false,
    };
  }
  if (error.status === 0) {
    return {
      title: "Network error",
      detail:
        "The FerrisCD API server could not be reached. Check the API Server URL and your connection, then retry.",
      forbidden: false,
    };
  }
  return {
    title: `${action === "sync" ? "Sync" : "Rollback"} request failed (${error.code})`,
    detail,
    forbidden: false,
  };
}
