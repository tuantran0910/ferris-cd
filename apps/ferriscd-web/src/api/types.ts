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
export type PolicyViolationView = components["schemas"]["PolicyViolationView"];
export type SyncRequestBody = components["schemas"]["SyncRequestBody"];
export type RollbackRequestBody = components["schemas"]["RollbackRequestBody"];
export type ProjectListView = components["schemas"]["ProjectListView"];
export type ProjectView = components["schemas"]["ProjectView"];
export type ProjectSyncWindowView =
  components["schemas"]["ProjectSyncWindowView"];
export type SyncWindowGateView = components["schemas"]["SyncWindowGateView"];
export type ClusterListView = components["schemas"]["ClusterListView"];
export type ClusterView = components["schemas"]["ClusterView"];
export type ApplicationSetListView =
  components["schemas"]["ApplicationSetListView"];
export type ApplicationSetView = components["schemas"]["ApplicationSetView"];
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

/**
 * What a policy rule does when its expression rejects a resource (`T20.2`).
 *
 * The wire values are the server's own enum serialization (a plain string in the OpenAPI schema:
 * the CRD-side enum is authoritative, and the server serializes it verbatim), so this is the *only*
 * place the two literals appear: every comparison goes through {@link isBlockingEnforcement}, which
 * is what keeps a typo from silently rendering a blocking violation as an advisory.
 */
export const PolicyEnforcement = {
  Enforce: "Enforce",
  Warn: "Warn",
} as const;

export type PolicyEnforcement =
  (typeof PolicyEnforcement)[keyof typeof PolicyEnforcement];

/**
 * Whether `enforcement` refuses the sync (an `Enforce` rule).
 *
 * Takes the raw wire `string` rather than the narrow union: `DiffView` comes straight from the
 * generated schema (`enforcement: string`), and narrowing it by hand at the boundary would only
 * move the same comparison into a cast.
 */
export function isBlockingEnforcement(enforcement: string): boolean {
  return enforcement === PolicyEnforcement.Enforce;
}

export type PolicyViolation = PolicyViolationView;

/** `DiffView` with the engine's raw JSON values left un-narrowed for rendering. */
export type DiffPayload = Omit<DiffView, "resources"> & {
  resources?: DiffResource[];
};
