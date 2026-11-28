import createClient, { type Client, type Middleware } from "openapi-fetch";
import type { paths } from "./schema";
import type {
  ApiErrorBody,
  ApplicationDetailView,
  AuthConfigView,
  ApplicationEventListView,
  ApplicationListView,
  ClusterListView,
  DiffView,
  OperationResponse,
  ProjectListView,
  ResourceGraphView,
  RollbackRequestBody,
  SyncRequestBody,
} from "./types";

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = code;
  }

  get isUnauthorized(): boolean {
    return this.status === 401 || this.code === "Unauthorized";
  }

  get isForbidden(): boolean {
    return this.status === 403 || this.code === "Forbidden";
  }

  get isNotFound(): boolean {
    return this.status === 404 || this.code === "NotFound";
  }

  get isConflict(): boolean {
    return this.status === 409 || this.code === "Conflict";
  }

  get isUnprocessable(): boolean {
    return this.status === 422 || this.code === "Unprocessable";
  }
}

export interface FerrisClientOptions {
  baseUrl: string;
  getToken: () => string | null;
  onUnauthorized?: () => void;
  fetchImpl?: typeof fetch;
}

export interface FerrisApiClient {
  raw: Client<paths>;
  listApplications: () => Promise<ApplicationListView>;
  getApplication: (namespace: string, name: string) => Promise<ApplicationDetailView>;
  getResources: (namespace: string, name: string) => Promise<ResourceGraphView>;
  getDiff: (namespace: string, name: string) => Promise<DiffView>;
  /** `GET .../events`: the bounded, redacted Kubernetes events timeline (`T17.3`). */
  getApplicationEvents: (
    namespace: string,
    name: string,
  ) => Promise<ApplicationEventListView>;
  syncApplication: (
    namespace: string,
    name: string,
    body?: SyncRequestBody,
  ) => Promise<OperationResponse>;
  rollbackApplication: (
    namespace: string,
    name: string,
    body: RollbackRequestBody,
  ) => Promise<OperationResponse>;
  listProjects: () => Promise<ProjectListView>;
  listClusters: () => Promise<ClusterListView>;
  /** `GET /api/v1/auth/config`: the public sign-in discovery document (`T19.1`, used by `T19.2`). */
  getAuthConfig: () => Promise<AuthConfigView>;
  /** `POST /api/v1/auth/logout`: expires the optional BFF session cookie (`T19.2`). */
  logoutSession: () => Promise<void>;
}

/**
 * Name of the readable, non-`HttpOnly` double-submit CSRF cookie the BFF flow sets (`T19.2`).
 *
 * `__Host-` prefixed, matching the server: the browser only stores it when it is `Secure`, `Path=/`
 * and carries no `Domain`, so a sibling subdomain cannot plant or overwrite the value.
 */
export const CSRF_COOKIE_NAME = "__Host-ferriscd_csrf";

/** Header name the server compares against that cookie (and against the sealed session). */
export const CSRF_HEADER = "x-ferriscd-csrf";

/** Reads one cookie from `document.cookie`, or `null`. */
function readCookie(name: string): string | null {
  if (typeof document === "undefined") {
    return null;
  }
  for (const part of document.cookie.split(";")) {
    const [key, ...rest] = part.split("=");
    if (key?.trim() === name) {
      const value = rest.join("=").trim();
      return value.length > 0 ? value : null;
    }
  }
  return null;
}

function extractApiError(
  error: unknown,
  response: Response | undefined,
): ApiClientError {
  const status = response?.status ?? 0;
  const body = error as Partial<ApiErrorBody> | undefined;
  if (body?.error && typeof body.error.message === "string") {
    return new ApiClientError(
      status,
      typeof body.error.code === "string" ? body.error.code : "ApiError",
      body.error.message,
    );
  }
  const fallbackMessage =
    status === 401
      ? "Authentication required. Please sign in with a valid Kubernetes bearer token."
      : status === 403
        ? "Forbidden: your identity does not have permission to perform this action."
        : status === 404
          ? "Resource not found or not visible to your identity."
          : status > 0
            ? `Request failed with HTTP ${status}.`
            : "Network error communicating with FerrisCD API server.";
  return new ApiClientError(status, `HTTP_${status}`, fallbackMessage);
}

export function createFerrisApiClient(options: FerrisClientOptions): FerrisApiClient {
  const raw = createClient<paths>({
    baseUrl: options.baseUrl,
    fetch: options.fetchImpl,
  });

  const authMiddleware: Middleware = {
    onRequest({ request }) {
      const token = options.getToken();
      if (token) {
        request.headers.set("Authorization", `Bearer ${token}`);
      }
      // `T19.2`: in the optional BFF cookie mode the server requires a double-submit CSRF header on
      // every mutating request. It is only present when the BFF flow is enabled (the cookie is set by
      // the callback), so a token-mode deployment sends nothing extra.
      const method = request.method.toUpperCase();
      if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
        const csrf = readCookie(CSRF_COOKIE_NAME);
        if (csrf) {
          request.headers.set(CSRF_HEADER, csrf);
        }
      }
      return request;
    },
    onResponse({ response }) {
      if (response.status === 401 && options.onUnauthorized) {
        options.onUnauthorized();
      }
      return response;
    },
  };

  raw.use(authMiddleware);

  return {
    raw,

    async listApplications() {
      const { data, error, response } = await raw.GET("/api/v1/applications");
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async getApplication(namespace, name) {
      const { data, error, response } = await raw.GET(
        "/api/v1/applications/{namespace}/{name}",
        {
          params: { path: { namespace, name } },
        },
      );
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async getResources(namespace, name) {
      const { data, error, response } = await raw.GET(
        "/api/v1/applications/{namespace}/{name}/resources",
        {
          params: { path: { namespace, name } },
        },
      );
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async getDiff(namespace, name) {
      const { data, error, response } = await raw.GET(
        "/api/v1/applications/{namespace}/{name}/diff",
        {
          params: { path: { namespace, name } },
        },
      );
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async getApplicationEvents(namespace, name) {
      const { data, error, response } = await raw.GET(
        "/api/v1/applications/{namespace}/{name}/events",
        {
          params: { path: { namespace, name } },
        },
      );
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async syncApplication(namespace, name, body = {}) {
      const { data, error, response } = await raw.POST(
        "/api/v1/applications/{namespace}/{name}/sync",
        {
          params: { path: { namespace, name } },
          body,
        },
      );
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async rollbackApplication(namespace, name, body) {
      const { data, error, response } = await raw.POST(
        "/api/v1/applications/{namespace}/{name}/rollback",
        {
          params: { path: { namespace, name } },
          body,
        },
      );
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async listProjects() {
      const { data, error, response } = await raw.GET("/api/v1/projects");
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async listClusters() {
      const { data, error, response } = await raw.GET("/api/v1/clusters");
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async getAuthConfig() {
      const { data, error, response } = await raw.GET("/api/v1/auth/config");
      if (error || !data) {
        throw extractApiError(error, response);
      }
      return data;
    },

    async logoutSession() {
      // 404 means the server was started without `--oidc-bff-enabled`: there is no cookie to clear.
      const { error, response } = await raw.POST("/api/v1/auth/logout");
      if (error && response?.status !== 404) {
        throw extractApiError(error, response);
      }
    },
  };
}
