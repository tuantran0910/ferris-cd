# Track B: Intelligent GitOps Engine (Phases 07–10)

> **Milestone:** `v0.3` Intelligent Continuous Delivery Engine (Phase 10)  
> **Back to:** [ROADMAP.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/ROADMAP.md) · [MASTER_PLAN.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/MASTER_PLAN.md)

---

## Phase 07: SSA Dry-Run Diff Engine

**Phase Goal:** Detect real configuration drift with near-zero false positives using Kubernetes Server-Side Apply `dryRun=All`, RFC 6901 `ignoreDifferences`, Secret redaction, and accurate `automated`/`selfHeal` decision logic.  
**Knowledge Base Lesson (`docs/lessons/07-ssa-dry-run-diffing-and-field-ownership.md`):** How SSA `dryRun=All` evaluates mutating webhooks and defaults, handling HPA `managedFields` conflicts, and Secret redaction hygiene.

### `T07.1` — Implement SSA Dry-Run Evaluator with Deferred CRD/Namespace Handling
- **Why:** Submitting desired manifests with `dryRun=All` lets the Kubernetes API server compute the exact post-default, post-webhook predicted object without hand-rolling `apimachinery` strategic merges—while skipping dry-run for brand-new CRDs/namespaces that don't exist yet.
- **Detailed Requirements:**
  - For each desired resource:
    - If `LiveState` is `Missing`, `DeferredPendingCrd`, or `DeferredPendingNamespace`: classify directly as `DiffStatus::Missing` without calling dry-run (so brand-new CRD+CR or `createNamespace: true` commits never fail in the diff phase!).
    - If `LiveState` is `Present(_, OwnedByForeign(other))`: classify as `DiffStatus::OwnershipConflict { owner: other }`.
    - Otherwise, execute `Api::patch(name, &PatchParams::apply("ferriscd").dry_run(), &Patch::Apply(&desired))` (applying `force` only if `serverSideForce: true`).
    - Catch `409 Conflict` API responses and parse Kubernetes `StatusDetails.causes` into structured `FieldConflict { field, manager }` items rather than returning an opaque error.
- **Outputs:** `crates/ferriscd-controller/src/dry_run.rs`, `crates/ferriscd-engine/src/diff/types.rs`.
- **Verification:** Live `kind` test proving: (1) API-defaulted fields (`terminationMessagePath`, `clusterIP`) produce **zero** diff, (2) a field modified by another manager produces a structured `FieldConflict` naming that manager, (3) a brand-new CRD+CR commit does not error during dry-run.
- **Trap Guard:** Fixes Finding C3 (dry-run failing before CRD/namespace creation) and Finding H6 (actionable conflict manager reporting).

### `T07.2` — Implement Canonical JSON Diff & RFC 6901 `ignoreDifferences`
- **Why:** Even with SSA dry-run, volatile metadata (`resourceVersion`, `managedFields`, `status`) and user-configured exemptions (e.g., mutating webhook mutations or HPA-managed `/spec/replicas`) must be stripped before comparing `live` vs `predicted`.
- **Detailed Requirements:**
  - Canonicalize clones of `live` and `predicted` (never mutating the original desired payload!): strip `metadata.resourceVersion`, `metadata.uid`, `metadata.generation`, `metadata.creationTimestamp`, `metadata.managedFields`, and top-level `.status`.
  - Apply matching `spec.ignoreDifferences` rules (by `group`, `kind`, optional `name`/`namespace`) removing configured RFC 6901 JSON Pointers (`jsonptr`) from both `live` and `predicted` clones.
  - Compute structured field-level diffs (`Added`, `Removed`, `Modified`) and classify each resource as `Synced` or `OutOfSync`, plus classify inventory-only resources as `Orphaned`.
- **Outputs:** `crates/ferriscd-engine/src/diff/compare.rs`, `crates/ferriscd-engine/src/diff/ignore.rs`.
- **Verification:** Unit tests for nested objects, arrays, missing JSON Pointer paths (must not error!), and live `kind` test with HPA-style `replicas` ignored cleanly.
- **Trap Guard:** Never fail reconciliation if an `ignoreDifferences` JSON Pointer doesn't exist on an object; always clone before stripping.

### `T07.3` — Implement Secret Redaction Layer
- **Why:** SSA dry-run returns full live `Secret` objects from the API server; without mandatory redaction, plaintext credentials will leak into diff previews, controller logs, and API responses.
- **Detailed Requirements:**
  - Implement `redact_secret(obj: &mut serde_json::Value)` for `v1/Secret`: replace every value in `.data` and `.stringData` with `"***REDACTED(sha256:<first-8-hex>)***"`.
  - Keep hash-based redaction so diffs still accurately show *whether* a Secret key changed (`old_hash != new_hash`) without ever exposing the plaintext or base64 secret!
  - Enforce redaction automatically inside `ResourceDiff` construction before any diff leaves `ferriscd-engine`.
- **Outputs:** `crates/ferriscd-engine/src/diff/redact.rs`.
- **Verification:** Unit test proving (1) changed Secret key still marks `OutOfSync`, (2) unchanged Secret key marks `Synced`, (3) raw secret value and base64 encoding never appear in `Debug`, `Display`, or JSON serialization of `ResourceDiff`.
- **Trap Guard:** Fixes Secret leakage via SSA dry-run diff (Trap T4 / Security).

### `T07.4` — Implement Sync Decision Gate (`automated`, `selfHeal`, `source_spec_hash`)
- **Why:** Accurately distinguish manual-only apps, revision-only auto-sync (`selfHeal: false`), and continuous self-healing (`selfHeal: true`), including when `Application.spec` changes without a new Git commit.
- **Detailed Requirements:**
  - Compute deterministic `source_spec_hash = sha256(canonical_json(spec.source, spec.destination))`.
  - Implement pure `should_sync(app, resolved_sha, source_spec_hash, &diff_summary, manual_op) -> SyncDecision { Skip(reason), Execute(trigger_reason) }`:
    - Manual operation requested -> `Execute(Manual)`.
    - `automated == None` -> `Skip(AutomatedDisabled)`.
    - `self_heal == false` -> `Execute(SourceChanged)` iff `(resolved_sha, source_spec_hash) != (last_synced_revision, last_synced_spec_hash)`; otherwise `Skip(SelfHealDisabled)`.
    - `self_heal == true` -> `Execute` if source changed OR any `OutOfSync`/`Missing` resource OR (`prune == true` and any `Orphaned` resource).
- **Outputs:** `crates/ferriscd-engine/src/diff/decision.rs`.
- **Verification:** Exhaustive truth-table unit tests covering all combinations, specifically verifying `spec.source.git.path` edit with unchanged `commit_sha` triggers sync even when `selfHeal: false`.
- **Trap Guard:** Fixes Finding H7 (`selfHeal: false` ignoring `Application.spec` edits).

### `T07.5` — Integrate Diff Engine into Controller & Write Phase 07 Lesson
- **Why:** Switch the controller from naive "apply every pass" (`v0.2`) to true diff-gated, idempotent reconciliation (`applyOutOfSyncOnly`).
- **Detailed Requirements:**
  - Wire `T07.1`–`T07.4` into `ferriscd-controller`; update `Application.status.sync.status` (`Synced`/`OutOfSync`) and `lastSyncedSpecHash`.
  - Write `docs/lessons/07-ssa-dry-run-diffing-and-field-ownership.md` with a `kind` experiment demonstrating drift detection with `automated: None`, `selfHeal: false`, and `selfHeal: true`.
- **Outputs:** Updated `crates/ferriscd-controller/src/reconcile.rs`, `docs/lessons/07-ssa-dry-run-diffing-and-field-ownership.md`.
- **Verification:** Live `kind` test proving an already-synced app performs **0** mutating `Patch` calls on subsequent reconciles.
- **Trap Guard:** Verify `applyOutOfSyncOnly: true` skips synced resources cleanly.

---

## Phase 08: Sync Engine, Dependency Ordering & Safe Lifecycle

**Phase Goal:** Execute deterministic, ordered synchronization plans that safely handle CRD+CR single-sync, brownfield adoption conflicts, immutable fields, and ownership-verified reverse-order pruning without risking CRD/Namespace catastrophes.  
**Knowledge Base Lesson (`docs/lessons/08-ordered-sync-crd-refresh-and-safe-pruning.md`):** Resource dependency graphs, CRD establishment & discovery invalidation, immutable fields, and safe pruning invariants.

### `T08.1` — Expand Deterministic Resource Priority Ordering
- **Why:** Workloads depend on Namespaces, CRDs, RBAC, ConfigMaps/Secrets, and PVCs existing first; pruning must unwind in the exact reverse order.
- **Detailed Requirements:**
  - Expand `ferriscd-engine/src/graph/order.rs` with full Kubernetes priority tiers:
    `Namespace (0)` -> `ResourceQuota/LimitRange (1)` -> `CustomResourceDefinition (2)` -> `ServiceAccount (3)` -> `ClusterRole/Role (4)` -> `ClusterRoleBinding/RoleBinding (5)` -> `ConfigMap/Secret (6)` -> `StorageClass/PVC (7)` -> `Service (8)` -> `Deployment/StatefulSet/DaemonSet/Job/CronJob (9)` -> `Ingress/NetworkPolicy/HPA/PDB (10)` -> `Custom Resources & Webhooks (11)`.
  - Tie-break deterministically by `ResourceKey`; expose `sort_apply_order` and `sort_prune_order` (exact reverse).
- **Outputs:** `crates/ferriscd-engine/src/graph/order.rs`.
- **Verification:** Unit tests verifying determinism and exact symmetry between apply order and prune order.
- **Trap Guard:** Custom resources must sort *after* CRDs so CRD establishment always precedes CR creation.

### `T08.2` — Implement `SyncPlan` Builder with CRD/Namespace Prune Safety Rails
- **Why:** Translating a `DiffSummary` into an explicit `SyncPlan` makes sync behavior auditable, testable without a cluster, and enforces safety guardrails before any API write occurs.
- **Detailed Requirements:**
  - Build `SyncPlan { pre_create_namespace: Option<String>, steps: Vec<SyncAction> }` where `SyncAction` is `Apply`, `Replace`, `Prune`, `Skip`, or `FailConflict`.
  - Honor `applyOutOfSyncOnly`, `createNamespace`, `pruneLast`, and per-resource `ferriscd.io/prune=false`.
  - **Hard safety rails:** Never plan `Prune` for `OwnedByForeign` or `Unmanaged` resources; never plan `Prune` for `CustomResourceDefinition` unless `syncOptions.pruneCRDs == true` (or resource annotation); never plan `Prune` for `Namespace` unless `syncOptions.pruneNamespaces == true`.
- **Outputs:** `crates/ferriscd-engine/src/sync/plan.rs`.
- **Verification:** Unit tests verifying every safety rail (foreign resource skipped, CRD orphan preserved when `pruneCRDs: false`, `PruneLast` schedules prunes after applies).
- **Trap Guard:** Fixes Finding H3 (catastrophic CRD/Namespace auto-pruning) and Trap T10.

### `T08.3` — Implement SSA Sync Executor with CRD `Established` Wait & Discovery Refresh
- **Why:** Applying a new CRD and its Custom Resource in the same Git commit fails unless the controller waits for the CRD to register and refreshes its `DiscoveryCache`.
- **Detailed Requirements:**
  - Implement `SyncExecutor` executing `SyncPlan` actions in order.
  - When `pre_create_namespace` is set, SSA-apply the target `Namespace` first (without stamping prune ownership unless managed in Git).
  - After applying any `CustomResourceDefinition` in a batch, poll CRD `status.conditions[type=Established, status=True]` (bounded short timeout, e.g. 15s, or requeue if not ready) and call `DiscoveryCache::invalidate_and_refresh()` before resolving/applying subsequent CRs.
  - Track `applied_ok` and `failed` sets cleanly so partial failures still update `status.inventory` safely via `T06.2`.
- **Outputs:** `crates/ferriscd-controller/src/sync_executor.rs`.
- **Verification:** Live `kind` integration test applying `examples/crd-and-cr/` (brand-new CRD + its CR in one commit) and succeeding on the **first** sync!
- **Trap Guard:** Fixes Trap T6 & Finding C3 end-to-end.

### `T08.4` — Handle Immutable Fields (`Replace=true`) & Brownfield Field-Manager Takeover
- **Why:** Two real-world SSA pain points block teams immediately: editing immutable fields (`Job`, `immutable: true` ConfigMap) and adopting existing resources originally applied by `kubectl apply` or `helm`.
- **Detailed Requirements:**
  - Detect Kubernetes immutable-field `422 Invalid` errors: surface a clear `SyncError` suggesting `ferriscd.io/sync-options: Replace=true` by default; when `Replace=true` is set, issue `Api::delete`, verify/requeue until `404 NotFound` (avoiding delete-recreate race!), then SSA-apply cleanly.
  - For `409 Conflict` when `syncOptions.takeoverFieldManagers` contains **all** conflicting managers (e.g., `["kubectl-client-side-apply"]`), retry that single resource with `force: true` and emit a `Normal` log/event; if an unlisted manager (like `kube-controller-manager` / HPA) conflicts, **do not force**—fail cleanly with the conflicting manager name.
- **Outputs:** `crates/ferriscd-controller/src/sync_recovery.rs`.
- **Verification:** Live `kind` integration tests: (1) modifying an `immutable: true` ConfigMap fails safely without `Replace=true` and recreates cleanly with `Replace=true`; (2) adopting a `kubectl apply`-created ConfigMap fails clearly by default and succeeds when `takeoverFieldManagers: ["kubectl-client-side-apply"]` is set.
- **Trap Guard:** Fixes Trap T7, Finding H6 (brownfield adoption), and Finding M3 (async delete-then-recreate `409 AlreadyExists` race).

### `T08.5` — Implement Ownership-Verified Safe Pruning & Phase 08 Lesson
- **Why:** Pruning is the highest-blast-radius operation in any GitOps platform and must verify ownership immediately before deletion.
- **Detailed Requirements:**
  - Before issuing `Api::delete(name, &DeleteParams::background())`, re-verify `tracking-id == expected` on the fetched live object (refuse delete on mismatch).
  - Treat `404 NotFound` / `410 Gone` as `pruned_ok`; keep failed deletes in `next_inventory` for retry on next reconcile.
  - Wire the same safe pruner into `T05.3` cascade finalizer cleanup.
  - Write `docs/lessons/08-ordered-sync-crd-refresh-and-safe-pruning.md`.
- **Outputs:** `crates/ferriscd-controller/src/prune.rs`, `docs/lessons/08-ordered-sync-crd-refresh-and-safe-pruning.md`.
- **Verification:** Live `kind` test proving: (1) removed Git resource pruned when `prune: true`, kept when `prune: false`, (2) foreign-tracked resource never pruned, (3) CRD orphan preserved by default.
- **Trap Guard:** Fixes Trap T10, Finding C1, and Finding H3.

---

## Phase 09: Health Assessment Engine

**Phase Goal:** Evaluate resource and application health accurately across core Kubernetes workloads and CRDs, accounting for real-world rollout edge cases (`paused`, `replicas: 0`, `OnDelete` StatefulSets, `Job` retries).  
**Knowledge Base Lesson (`docs/lessons/09-kubernetes-workload-health-machines.md`):** Why `observedGeneration` is mandatory for health checks, workload rollout state machines, and why Sync Status != Health Status.

### `T09.1` — Define `HealthStatus` Lattice & `HealthEvaluator` Trait
- **Why:** Provide a single, deterministic aggregation model so an Application's overall health accurately reflects its worst child resource.
- **Detailed Requirements:**
  - Define `HealthStatus` (`Healthy`, `Progressing`, `Degraded`, `Suspended`, `Missing`, `Unknown`) and `ResourceHealth { status, message }`.
  - Implement strict aggregation precedence: `Degraded > Missing > Progressing > Suspended > Unknown > Healthy` (empty resource list -> `Healthy`).
  - Define `HealthEvaluator` trait + registry dispatching by `(group, kind)` with passive built-ins (`ConfigMap`, `Secret`, `ServiceAccount`, `Namespace`, `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`, `CRD`) returning `Healthy` when present (or checking `Established` for CRDs).
- **Outputs:** `crates/ferriscd-engine/src/health/mod.rs`.
- **Verification:** Unit tests for aggregation lattice across all combinations and passive-resource defaults.
- **Trap Guard:** Never report passive config resources (`ConfigMap`, `Secret`) as `Unknown`.

### `T09.2` — Implement Core Workload Health Evaluators (Deployment, StatefulSet, DaemonSet, ReplicaSet)
- **Why:** Workloads are the most complex health state machines in Kubernetes and have well-known traps (`paused`, `replicas: 0`, `OnDelete` STS) that hang sync waves if coded naively.
- **Detailed Requirements:**
  - **Every** workload evaluator must first check `status.observedGeneration < metadata.generation` -> `Progressing("Waiting for controller to observe generation")`.
  - `Deployment`: `spec.paused == true` -> `Suspended`; `spec.replicas == 0` -> `Healthy` once `status.replicas == 0`; condition `Progressing=False` with `ProgressDeadlineExceeded` -> `Degraded`; all `updatedReplicas == availableReplicas == desired` -> `Healthy`; else `Progressing`.
  - `StatefulSet`: handle `updateStrategy.type == "OnDelete"` (don't hang waiting for `updatedReplicas`!) and `rollingUpdate.partition > 0` (`updatedReplicas >= replicas - partition`); handle `replicas == 0`.
  - `DaemonSet`: check `desiredNumberScheduled`, `updatedNumberScheduled`, `numberAvailable`.
  - `ReplicaSet`: check `observedGeneration`, `availableReplicas == spec.replicas`.
- **Outputs:** `crates/ferriscd-engine/src/health/workloads.rs`.
- **Verification:** Snapshot unit tests using real K8s JSON fixtures covering every edge case: healthy rollout, stale `observedGeneration`, `ProgressDeadlineExceeded`, `paused: true`, `replicas: 0`, `OnDelete` StatefulSet, partitioned StatefulSet.
- **Trap Guard:** Fixes Finding M2 workload edge cases and split from oversized epic (Finding H9).

### `T09.3` — Implement Pod, Job, Service, Ingress & PVC Health Evaluators
- **Why:** Hooks rely heavily on `Job` health, while apps depend on `Pod`, `Service`, `Ingress`, and `PVC` readiness.
- **Detailed Requirements:**
  - `Pod`: `Succeeded` -> `Healthy`; `Failed` -> `Degraded`; container waiting in `CrashLoopBackOff`/`ImagePullBackOff`/`ErrImagePull`/`CreateContainerConfigError` -> `Degraded`; `Running` + `Ready=True` -> `Healthy`; else `Progressing`.
  - `Job`: `spec.suspend == true` -> `Suspended`; `conditions[type=Complete, status=True]` -> `Healthy`; `conditions[type=Failed, status=True]` -> `Degraded` (do **not** mark `Degraded` on transient `status.failed > 0` during normal backoff retries!); else `Progressing`.
  - `Service`: `ClusterIP`/`NodePort`/`ExternalName` -> `Healthy`; `LoadBalancer` -> `Healthy` when `status.loadBalancer.ingress` is non-empty, else `Progressing` (with configurable option/annotation for local clusters without LB controller).
  - `Ingress` & `PVC`: `PVC` `Bound` -> `Healthy`, `Lost` -> `Degraded`, `Pending` -> `Progressing`.
- **Outputs:** `crates/ferriscd-engine/src/health/runtime.rs`.
- **Verification:** Snapshot unit tests for all 5 kinds, specifically verifying a `Job` with `status.failed: 1` and no `Failed` condition remains `Progressing`, not `Degraded`.
- **Trap Guard:** Fixes Finding M2 (`Job` retry trap & `LoadBalancer` on `kind`).

### `T09.4` — Implement Generic CRD Condition Heuristic
- **Why:** Real clusters deploy dozens of third-party CRDs (`Certificate`, `Database`, `VirtualService`) that follow standard Kubernetes `status.conditions` conventions.
- **Detailed Requirements:**
  - For any unrecognized GVK, inspect `status.conditions` if present: look for `type` in `["Ready", "Available", "Healthy", "Synced"]` (in priority order); check `observedGeneration` if present on `status` or condition.
  - Map `status: "True"` -> `Healthy`, `status: "False"` with transient reason (`Progressing`/`Reconciling`) -> `Progressing`, other `"False"` -> `Degraded`, missing `status.conditions` -> `Healthy` (if spec-only CRD) or `Unknown` (configurable).
- **Outputs:** `crates/ferriscd-engine/src/health/crd.rs`.
- **Verification:** Unit tests using cert-manager `Certificate`, Crossplane, and spec-only CRD JSON fixtures.
- **Trap Guard:** Respect `observedGeneration` on CRD status when present so stale `Ready=True` doesn't mask a failing update.

### `T09.5` — Wire Health Engine into Controller & Adaptive Requeue + Phase 09 Lesson
- **Why:** Continuously track workload health after sync and poll faster while a rollout is `Progressing` without overloading the API server once `Healthy`.
- **Detailed Requirements:**
  - Evaluate health of all desired/live resources in every reconcile pass; populate `Application.status.health` and per-resource health summary.
  - Adaptive requeue: when `Application` health is `Progressing`, requeue after `10s` (capped minimum); when settled (`Healthy`/`Degraded`/`Suspended`), requeue after `spec.requeueAfterSeconds`.
  - Write `docs/lessons/09-kubernetes-workload-health-machines.md`.
- **Outputs:** Updated `crates/ferriscd-controller/src/reconcile.rs`, `docs/lessons/09-kubernetes-workload-health-machines.md`.
- **Verification:** Live `kind` test: deploy bad image tag -> `Synced` + `Degraded`; push fixed image -> transitions `Progressing` -> `Healthy` within ~15s.
- **Trap Guard:** Never conflate `Synced` with `Healthy`.

---

## Phase 10: Sync Waves, Lifecycle Hooks & Rollback — *Milestone `v0.3` Complete*

**Phase Goal:** Implement crash-safe, re-entrant multi-wave rollouts, `PreSync`/`PostSync`/`SyncFail` hooks (with `generateName` support), bounded deployment history, and GitOps-safe rollbacks.  
**Knowledge Base Lesson (`docs/lessons/10-sync-waves-hooks-and-gitops-rollback.md`):** Designing non-blocking re-entrant controller state machines in `status.operationState`, hook lifecycles, and why naive rollbacks fight `selfHeal`.

### `T10.1` — Design & Implement Re-Entrant `OperationState` State Machine
- **Why:** Waiting for a Wave `-1` DB-migration Job to finish can take minutes—blocking a controller worker task would starve other apps and lose state on pod restart. A persisted state machine makes multi-wave syncs crash-safe and non-blocking.
- **Detailed Requirements:**
  - Model `SyncPhase` (`PreSync` -> `Sync(wave)` -> `PostSync` -> `Succeeded` | `SyncFail` -> `Failed`) inside `status.operationState`.
  - On each reconcile while `operationState.phase == Running`: resume at `(current_phase, current_wave)`, check health of already-applied resources in that wave, advance to the next wave only when all are `Healthy` (or transition to `SyncFail` on `Degraded` / wave timeout), persist updated `operationState`, and return `Action::requeue(5s)`.
  - Enforce a per-operation timeout (default 10m) so stuck waves terminate cleanly.
- **Outputs:** `crates/ferriscd-engine/src/sync/state_machine.rs`.
- **Verification:** Pure unit/contract tests stepping through a 3-wave sync across simulated controller restarts, wave `Progressing` -> `Healthy` transitions, and wave failure -> `SyncFail`.
- **Trap Guard:** Split from oversized epic (Finding H9); never sleep/block a Tokio reconcile worker waiting for a Job!

### `T10.2` — Implement Sync Wave Partitioning & Wave Gating
- **Why:** Let application authors order migrations, CRDs, backends, and frontends using `ferriscd.io/sync-wave: "-1" | "0" | "1"`.
- **Detailed Requirements:**
  - Parse `ferriscd.io/sync-wave` annotation as signed `i32` (default `0`; invalid integer returns a clear terminal manifest error).
  - Group non-hook resources by wave (sorted ascending) and apply `T08.1` priority tier ordering within each wave.
  - Wire wave stepping into `T10.1` `OperationState` machine in `ferriscd-controller`.
- **Outputs:** `crates/ferriscd-engine/src/graph/waves.rs`, controller wave runner integration.
- **Verification:** Live `kind` test: Wave `-1` `ConfigMap` + `Job` completes `Healthy` before Wave `0` `Deployment` is created.
- **Trap Guard:** If Wave `-1` contains a CRD, still run `DiscoveryCache::invalidate_and_refresh()` before Wave `0`.

### `T10.3` — Implement Lifecycle Hooks (`PreSync`, `Sync`, `PostSync`, `SyncFail`) & `generateName`
- **Why:** Enable pre-deployment DB migrations, post-deployment smoke tests, and failure notifications without polluting permanent resource inventory.
- **Detailed Requirements:**
  - Parse `ferriscd.io/hook` (comma-separated phases: `PreSync`, `Sync`, `PostSync`, `SyncFail`, `Skip`) and partition hooks out of regular desired resources so they **never** enter `status.inventory`.
  - Support `metadata.generateName` on hook resources by creating via `Api::create` (recording the generated live name in `status.operationState.activeHooks` so subsequent requeues track the exact Job instead of creating duplicates!).
  - Execute `PreSync` hooks (sorted by wave) before `Sync`, `PostSync` after all `Sync` waves are `Healthy`, and `SyncFail` if any phase fails.
- **Outputs:** `crates/ferriscd-engine/src/graph/hooks.rs`, `crates/ferriscd-controller/src/hooks.rs`.
- **Verification:** Live `kind` test: `PreSync` Job with `generateName: migrate-` runs exactly once, succeeds, then `Sync` Deployment applies; failing `PreSync` Job triggers `SyncFail` hook and aborts `Sync`.
- **Trap Guard:** Fixes Finding H2 (`generateName` + `Api::create`) and ensures hooks are tracked in `operationState`, never in permanent prune `inventory`.

### `T10.4` — Implement Hook Deletion Policies
- **Why:** Repeated syncs would leave behind piles of completed `PreSync`/`PostSync` Jobs or fail with `AlreadyExists` for named hooks unless hook cleanup policies are enforced.
- **Detailed Requirements:**
  - Parse `ferriscd.io/hook-delete-policy` (`HookSucceeded`, `HookFailed`, `BeforeHookCreation`; default `BeforeHookCreation` for named hooks).
  - Delete existing named hook (waiting/requeuing until `404`) on `BeforeHookCreation`, and delete active hook upon reaching `Healthy` (`HookSucceeded`) or `Degraded` (`HookFailed`).
- **Outputs:** Hook cleanup logic in `crates/ferriscd-controller/src/hooks.rs`.
- **Verification:** Live `kind` test proving named hook with `BeforeHookCreation` re-runs cleanly on second sync, and `HookSucceeded` deletes the Job upon completion.
- **Trap Guard:** Handle async deletion cleanly (requeue until `404` before recreating named hook — Finding M3).

### `T10.5` — Implement Bounded Revision History & GitOps-Safe Rollback
- **Why:** Operators need an auditable history of deployed revisions and a fast emergency rollback that doesn't immediately get overwritten by `selfHeal`.
- **Detailed Requirements:**
  - On sync completion (`Succeeded`), append `RevisionHistoryEntry { id, revision, deployed_at, source_summary }` to `status.history`, trimming oldest entries to `min(revisionHistoryLimit, 20)`.
  - Implement rollback operation (`ferriscd.io/operation: {"rollback":{"id": N}}`): look up target `revision` in `status.history`, disable `spec.syncPolicy.automated` (recording a clear `Warning` condition `AutomatedSyncDisabledByRollback` so the operator knows to revert in Git and re-enable!), and sync to the pinned historical `commit_sha`.
- **Outputs:** `crates/ferriscd-engine/src/sync/history.rs`, rollback handler in `ferriscd-controller`.
- **Verification:** Live `kind` test: deploy commit v1 -> commit v2 -> trigger rollback to history ID 1 -> workloads revert to v1 and **stay** on v1 across subsequent requeues (not overwritten by `HEAD`).
- **Trap Guard:** Prevents the classic GitOps rollback-vs-`selfHeal` fight loop.

### `T10.6` — Execute Full `v0.3` E2E Verification Suite & Phase 10 Lesson
- **Why:** Lock in all core GitOps invariants with a comprehensive automated live `kind` test suite before moving on to renderers and multi-tenancy.
- **Detailed Requirements:**
  - Build `tests/integration/v0_3_e2e.rs` exercising: (1) drift self-heal on/off, (2) safe orphan prune & foreign non-prune, (3) CRD+CR single-sync, (4) `Secret.stringData` zero-drift + redaction, (5) `PreSync` hook + multi-wave rollout, (6) bad-image `Degraded` -> fix `Healthy`, (7) rollback stability.
  - Write `docs/lessons/10-sync-waves-hooks-and-gitops-rollback.md`.
- **Outputs:** `tests/integration/v0_3_e2e.rs`, `examples/crd-and-cr/`, `examples/waves-hooks/`, `docs/lessons/10-sync-waves-hooks-and-gitops-rollback.md`.
- **Verification:** Entire `v0.3` E2E suite passes green against `kind`. **Milestone `v0.3` Complete.**
- **Trap Guard:** Run suite twice back-to-back to ensure zero flaky timing assumptions.
