import type { components } from "./schema";

export type ApiErrorBody = components["schemas"]["ApiErrorBody"];
export type ApiErrorDetail = components["schemas"]["ApiErrorDetail"];
export type ApplicationListView = components["schemas"]["ApplicationListView"];
export type ApplicationDetailView = components["schemas"]["ApplicationDetailView"];
export type ApplicationSummary = components["schemas"]["ApplicationSummary"];
export type ConditionView = components["schemas"]["ConditionView"];
export type DestinationView = components["schemas"]["DestinationView"];
export type SourceView = components["schemas"]["SourceView"];
export type SyncView = components["schemas"]["SyncView"];
export type HealthView = components["schemas"]["HealthView"];
export type HistoryView = components["schemas"]["HistoryView"];
export type OperationView = components["schemas"]["OperationView"];
export type OperationResponse = components["schemas"]["OperationResponse"];
export type ResourceGraphView = components["schemas"]["ResourceGraphView"];
export type ResourceNodeView = components["schemas"]["ResourceNodeView"];
export type DiffView = components["schemas"]["DiffView"];
export type DiffSummaryView = components["schemas"]["DiffSummaryView"];
export type DiffResourceView = components["schemas"]["DiffResourceView"];
export type DiffChangeView = components["schemas"]["DiffChangeView"];
export type DiffConflictView = components["schemas"]["DiffConflictView"];
export type SyncRequestBody = components["schemas"]["SyncRequestBody"];
export type RollbackRequestBody = components["schemas"]["RollbackRequestBody"];
export type ProjectListView = components["schemas"]["ProjectListView"];
export type ProjectView = components["schemas"]["ProjectView"];
export type ClusterListView = components["schemas"]["ClusterListView"];
export type ClusterView = components["schemas"]["ClusterView"];
export type ApplicationEventListView =
  components["schemas"]["ApplicationEventListView"];
export type ApplicationEventView = components["schemas"]["ApplicationEventView"];
export type AuthConfigView = components["schemas"]["AuthConfigView"];
export type HealthResponse = components["schemas"]["HealthResponse"];
export type ReadyResponse = components["schemas"]["ReadyResponse"];

/**
 * Runtime-safe diff view aliases: `utoipa` emits `serde_json::Value` as
 * `type: ["object", "null"]`, which `openapi-typescript` types as
 * `Record<string, never> | null`. At runtime `live` and `predicted` can hold
 * any JSON value (strings like `***REDACTED(sha256:...)***`, numbers, arrays,
 * objects, or null). `DiffView` is structurally assignable to `DiffPayload`.
 */
export type DiffChange = Omit<DiffChangeView, "live" | "predicted"> & {
  live?: unknown;
  predicted?: unknown;
};

export type DiffResource = Omit<DiffResourceView, "changes"> & {
  changes?: DiffChange[];
};

export type DiffPayload = Omit<DiffView, "resources"> & {
  resources?: DiffResource[];
};
