import createClient, { type Client, type Middleware } from "openapi-fetch";
import type { paths } from "./schema";
import type {
  ApiErrorBody,
  ApplicationDetailView,
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
  };
}
