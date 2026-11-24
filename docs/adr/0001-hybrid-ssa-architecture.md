# ADR-0001: Hybrid Engine (Argo CD UX + Flux SSA Core)

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

GitOps Continuous Delivery platforms must bridge two distinct layers:

1. **The Operator & Developer Experience (UX):** Declarative `Application` and `AppProject` APIs, orthogonal Sync and Health states, ordered sync waves and lifecycle hooks, diff previews with `ignoreDifferences`, and clear CLI/Web workflows.
2. **The Kubernetes Reconciliation Core:** Computing live-vs-desired diffs, applying manifests idempotently, tracking managed resource ownership, and persisting state safely across controller restarts.

Historically, Argo CD implemented its reconciliation core around client-side 3-way strategic-merge patch diffing in Go (`k8s.io/apimachinery`), OpenAPI schema defaulting on the controller, and a Redis cache/state layer. Re-implementing Go's strategic-merge patch and Kubernetes OpenAPI defaulting logic in Rust would take months, drift subtly across Kubernetes versions, and introduce a mandatory external state dependency (Redis). Conversely, Flux CD demonstrated that Kubernetes **Server-Side Apply (SSA)** (`Patch::Apply` + `dryRun=All` + `managedFields`) delegates schema defaulting, structural merge, and field ownership directly to the Kubernetes API server while storing compact inventory in `etcd` on the custom resource's `/status` subresource.

## Decision

FerrisCD adopts a **Hybrid GitOps Engine** combining Argo CD's operator UX with a Flux-inspired SSA core:

1. **Argo CD-Grade UX (`ferriscd.io/v1alpha1`):**
   - `Application` and `AppProject` CRDs with separate **Sync** (`Synced | OutOfSync | Unknown`) and **Health** (`Healthy | Progressing | Degraded | Suspended | Missing | Unknown`) statuses.
   - Deterministic dependency tiers, sync waves (`i32`, default `0`), lifecycle hooks (`PreSync`, `Sync`, `PostSync`, `SyncFail`), RFC 6901 JSON Pointer `ignoreDifferences`, and Secret-redacted diff previews.
2. **Flux-Inspired SSA Reconciliation Core:**
   - **SSA First (`Patch::Apply`):** All declarative resources are applied with `field_manager: "ferriscd"`.
   - **Safe Force Default (`serverSideForce: false`):** FerrisCD never enables `force: true` by default so it cannot silently clobber fields owned by HPA, VPA, or other cluster controllers. `409 Conflict` responses are surfaced as structured `FieldConflict` diagnostics listing the conflicting manager and fields, with explicit opt-in `syncOptions.takeoverFieldManagers` for brownfield adoption.
   - **API-Driven Diffing (`dryRun=All`):** Existing live objects are diffed by running `Patch::Apply` with `dry_run: true`, then comparing canonicalized live vs. dry-run server responses (applying `ignoreDifferences` on clones without mutating desired payloads).
   - **Deferred Dry-Run Guard:** Resources whose CRD or target Namespace does not yet exist (`Missing`, `DeferredPendingCrd`, `DeferredPendingNamespace`) skip dry-run diffing and are classified `OutOfSync`/`Missing` until sync creates the prerequisite CRD/Namespace and refreshes `Discovery`.
   - **Two-Stage Normalization:** Stage 1 (offline) strips `.status` and server-owned metadata and converts `Secret.stringData` into base64 `.data`; Stage 2 (cluster-aware) resolves cluster vs. namespaced scope via `DiscoveryCache` before diff/apply.
3. **Zero External Database or Redis:**
   - All durable reconciliation state—compact GKNN `status.inventory`, re-entrant `status.operationState`, and `status.history` (hard-capped at 20 metadata-only entries)—is persisted in Kubernetes `etcd` via the `Application/status` subresource.
   - Caches (`RepoCache`, `DiscoveryCache`, render cache) are strictly ephemeral in-process or local scratch state.

## Consequences

### Positive
- Eliminates re-implementing Go strategic-merge patch and Kubernetes version-specific defaulting in Rust; the target API server is the single source of truth for schema defaulting and `managedFields` ownership.
- Zero Redis or external SQL database to deploy, secure, back up, or keep consistent with `etcd`.
- Crash-safe by construction: killing the controller mid-sync leaves accurate `status.inventory` and `status.operationState` in `etcd`.
- Protects multi-controller fields (e.g., HPA `spec.replicas`) by default via `serverSideForce: false`.

### Trade-offs & Mitigations
- **API server round-trips for `dryRun=All` diffs:** Computing diffs requires server-side dry-run requests for existing resources. *Mitigation:* Scoped on-demand fetching (`desired ∪ prev_inventory`), `applyOutOfSyncOnly: true` by default, and skipping dry-run for `Missing`/`DeferredPendingCrd`/`DeferredPendingNamespace` resources.
- **Brownfield adoption conflicts:** Resources previously applied by `kubectl apply` (`kubectl-client-side-apply`) or Helm can trigger `409 Conflict` under `force: false`. *Mitigation:* Report actionable `FieldConflict` manager/field details and support scoped `syncOptions.takeoverFieldManagers`.
- **`etcd` 1.5 MiB object size limit:** Storing full rendered YAML or diffs in `Application.status` would risk `etcd` write failures. *Mitigation:* Store only compact GKNN entries in `status.inventory` and cap `status.history` at 20 metadata-only entries (<100 KB even at 500 resources); compute diffs on demand in memory.

## References

- [MASTER_PLAN.md](../MASTER_PLAN.md) — Sections 1.2, 3 (ADR-001), 4.3, and 5
- [REVIEW_LOG.md](../REVIEW_LOG.md) — Findings P1-02, C3, and H6
- [ADR-0002: Modular Monolith Workspace](./0002-modular-monolith-workspace.md)
- [ADR-0003: Version-Agnostic GKNN Inventory & `tracking-id`](./0003-gknn-inventory-and-tracking-id.md)
