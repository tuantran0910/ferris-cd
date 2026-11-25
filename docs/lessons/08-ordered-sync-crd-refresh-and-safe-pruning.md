# Lesson 08 — Ordered Sync, CRD Establishment, and Safe Pruning

> Phase 08 turns the diff result into an explicit, auditable plan and executes it in dependency
> order. The two catastrophic failure classes in GitOps live here: **applying a custom resource
> before its CRD exists**, and **pruning something we do not own** (or auto-pruning a CRD or a
> Namespace). Both are prevented structurally, not by careful coding at the call site.
>
> Code: `crates/ferriscd-engine/src/{graph/order.rs,sync/plan.rs}`,
> `crates/ferriscd-controller/src/{sync_executor.rs,sync_recovery.rs,prune.rs}`.
> The live `kind` checks are manual and marked **pending**; `make gate` is hermetic.

---

## 1. Plan first, execute second

A diff says *what* changed. A sync plan says *what FerrisCD will do about it, in what order, and
what it refuses to do*. `SyncPlan` is built by a pure function from `DiffSummary` + policy:

```text
SyncPlan {
  pre_create_namespace: Option<String>,
  steps: Vec<SyncAction>,
}

SyncAction = Apply | Replace | Prune | Skip(reason) | FailConflict(owner)
```

Why this matters:

- **Auditable.** Every mutation and every refusal is a typed step. A bug in policy is a wrong
  plan, visible in a unit test, not an API call that already happened.
- **Deterministic.** The same inputs produce byte-identical ordering (priority tier, then
  `ResourceKey`), so tests and dry-runs are stable.
- **Safe by construction.** The safety rails are branches in the plan builder, not conventions
  spread across the executor.

`Skip` is not an error: it means "this orphan is retained" (foreign, opted out, prune disabled)
or "this resource is already synced". The reason travels with the step.

---

## 2. Dependency tiers and reverse-order pruning

Kubernetes has an implicit dependency graph: a `Deployment` needs its `ConfigMap`/`Secret`, a
custom resource needs its CRD, a namespaced object needs its `Namespace`. Phase 08 encodes a
12-tier priority order:

```text
0  Namespace
1  ResourceQuota / LimitRange
2  CustomResourceDefinition
3  ServiceAccount
4  ClusterRole / Role
5  ClusterRoleBinding / RoleBinding
6  ConfigMap / Secret
7  StorageClass / PersistentVolumeClaim
8  Service
9  Deployment / StatefulSet / DaemonSet / Job / CronJob
10 Ingress / NetworkPolicy / HorizontalPodAutoscaler / PodDisruptionBudget
11 Custom Resources / admission webhooks
```

Ties are broken by the version-agnostic `ResourceKey`, so two runs never disagree. Pruning uses
**the exact reverse** order (`sort_prune_order`): delete the consumer before the thing it
consumes, and never leave a CR pointing at a deleted CRD.

`syncOptions.pruneLast` (default `true`) schedules all prunes after all applies; setting it to
`false` runs prunes first, which is occasionally useful to free quota or a name in the same pass.

---

## 3. The safety rails

The planner refuses to emit a dangerous `Prune`, regardless of what the diff says:

| Condition | Result |
|---|---|
| orphan is `OwnedByForeign` / `Unmanaged` | `Skip` — never deleted (trap T10) |
| orphan is a `CustomResourceDefinition` | `Skip` unless `syncOptions.pruneCRDs: true` |
| orphan is a `Namespace` | `Skip` unless `syncOptions.pruneNamespaces: true` |
| resource has `ferriscd.io/prune: "false"` | `Skip` — per-resource opt-out |
| `automated.prune: false` | no `Prune` at all |
| decision gate says `Skip` | no apply/replace/prune anywhere |

`pruneCRDs` does **not** imply `pruneNamespaces`, and neither is on by default: deleting a CRD
deletes every custom resource of that kind cluster-wide, and deleting a namespace deletes
everything inside it. Both are opt-in.

There is no per-resource annotation that turns CRD pruning *on*: `syncOptions.pruneCRDs` is the
only enabling switch (T08.2). `ferriscd.io/prune: "false"` is a retain-only opt-out — it is
honoured on any resource, a CRD included, but it can only ever narrow what the switch allows.

A desired resource whose live object carries another `Application`'s `tracking-id` becomes
`FailConflict(owner)` — never `Apply`. The object is not adopted, and the conflict is visible.

---

## 4. CRD + CR in one commit

This is the classic first-sync failure:

1. Git adds `widgets.example.com` CRD and a `Widget` that uses it.
2. The API server has not established the CRD yet.
3. Applying the `Widget` answers `404 NoMatchesForKind`.
4. Discovery still has the old resource map, so even a retry may resolve the wrong thing.

The executor handles it explicitly:

```text
apply CRD
  -> poll CRD.status.conditions[type=Established].status == "True"  (bounded ~15s)
  -> DiscoveryCache::invalidate_and_refresh()
  -> only then apply the CR
```

If the CRD is not established inside the window, the pass is **not** an error: it reports the
remaining steps as pending and requeues on the short interval. A slow cluster converges.

One condition is *not* "slow": `NamesAccepted=False` means the API server rejected the definition
(invalid `spec.names`/versions), so waiting can never help. The executor fails the pass with the
condition's reason and message instead of requeueing forever behind a `PendingDependencies`
condition — a permanent error must look permanent. This closes trap T6 / finding C3 (and finding
H5) end-to-end.

The plan is built *before* the CRD is established, and the two cases are handled very differently —
that difference is the whole of T08.3:

- A custom resource whose kind a CRD in this bundle defines is **not deferred at all**: it is
  planned as a normal `Apply` at tier 11. The plan never needs the kind: the executor applies the
  CRD, waits for `Established`, calls `DiscoveryCache::invalidate_and_refresh()`, and only then
  applies the CR — in the **same** pass. If the CRD is not established inside the window, the
  executor stops the pass right there (`RequeuePending`: the remaining steps become pending, the
  pass is not an error); a `NamesAccepted=False` rejection fails the pass instead.
- A resource targeting a **`Namespace` in this bundle** (`DeferredPendingNamespace`) is the only
  kind of key that enters `PlanRequest::deferred`, and therefore the only `Skip(Deferred)` step.
  The executor never resolves such a step in-pass, unconditionally — even a discovery refresh it
  just performed does not promote it. The resource waits for exactly one extra reconcile: the
  namespace can only exist after the pass that applies it. So the cost of a namespace deferral is
  one extra pass, always, and nothing is ever applied into a namespace that does not exist yet.

`pre_create_namespace` is applied before the first step, as a bare `Namespace` **without** a
prune ownership marker unless the namespace is also managed in Git. That keeps "create the
destination namespace" from silently making the namespace prunable.

---

## 5. Immutable fields and brownfield adoption

Two SSA realities break naive controllers:

### Immutable fields (`422 Invalid`)

`Job`, many `StatefulSet` fields, and `immutable: true` `ConfigMap`/`Secret` cannot be patched.
The safe default is a clear failure, not a silent delete:

```yaml
metadata:
  annotations:
    ferriscd.io/sync-options: Replace=true
```

With the opt-in, the plan emits `Replace` and recovery performs the only race-free sequence:

```text
DELETE -> poll GET until 404 NotFound -> SSA apply
```

The `404` wait matters: deletion is asynchronous (finalizers), and an immediate re-apply answers
`409 AlreadyExists`. The wait is bounded; on expiry the pass returns a **retryable** error and the
next reconcile continues from live state.

### Brownfield field managers (`409 Conflict`)

An object previously written by `kubectl apply` or Helm has another field manager. FerrisCD never
force-adopts by default. When the conflict's managers are **all** listed in
`syncOptions.takeoverFieldManagers`, it retries that one resource with `force: true` and logs a
`Normal` event. If an unlisted manager (for example `kube-controller-manager` or HPA) is involved,
the sync fails cleanly with the manager name — forcing would fight the controller that owns that
field.

---

## 6. Pruning is a security operation

`prune.rs` re-verifies everything immediately before `Delete`:

1. **Re-GET** the object. The pass-level live map can be minutes old; a takeover may have
   happened while dozens of applies ran.
2. **Re-check `ferriscd.io/tracking-id`** against this `Application`. A mismatch (or a missing
   annotation) retains the object and records why.
3. **Re-check the rails** on the fresh object (`prune: "false"`, CRD/Namespace opt-ins).
4. **Delete with `DeleteParams::background()`** so finalizers never block a reconcile worker.

`404`/`410` at any point is a confirmed absence and counts as pruned. A real delete failure keeps
the key out of `next_inventory` so it is retried next pass instead of leaking. The same pruner is
used by the cascade finalizer path, so deleting an `Application` cannot delete more than a normal
prune would.

---

## 7. Partial failure still advances inventory correctly

`SyncExecutor` returns `applied_ok`, `synced_ok` and `pruned_ok` sets. The crash-safe formula from
Phase 06 applies unchanged:

```text
next_inventory = (prev_inventory \ pruned_ok) ∪ (applied_ok ∪ synced_ok)
```

A successful apply before a later failure is still recorded; a failed delete stays in inventory.
Nothing depends on the reconcile finishing.

The failure class decides what `/status` says about it, and both paths carry the confirmed
inventory: a retryable failure becomes `PartialSync`, a terminal policy failure (immutable field
without `Replace=true`, an unlisted field manager, a foreign owner) becomes `SyncConflict`. A
terminal failure that dropped its inventory would turn every object it already created into an
untracked orphan.

---

## 8. Manual `kind` acceptance — **PENDING (not executed)**

The harness for every item below is `tests/integration/v0_8_ordered_sync.rs` (compiled by
`crates/ferriscd-cli/tests/v0_8_ordered_sync.rs`), one `#[ignore]`d, `kind`-guarded test per
behaviour. Run it with `make kind-up && make test-integration`.

Do not copy expected output into docs. Run on a `kind` cluster and record what you observe:

1. **CRD+CR single sync** — apply an `Application` pointing at `examples/crd-and-cr/`; the CR must
   be created on the *first* sync, with a discovery refresh between CRD and CR.
2. **Pruning** — remove a resource from Git with `prune: true`; it is deleted. With
   `prune: false` it is retained. A resource carrying another app's `tracking-id` is never
   deleted.
3. **CRD/Namespace rails** — delete a CRD's manifest from Git with `pruneCRDs: false`; the CRD
   survives. Same for a `Namespace` with `pruneNamespaces: false`.
4. **Immutable fields** — edit an `immutable: true` ConfigMap; without `Replace=true` the sync
   fails with an actionable message and does not delete the object. With `Replace=true` it is
   deleted, waits for `404`, and is recreated.
5. **Takeover** — adopt a `kubectl apply`-created ConfigMap; default fails with the manager name,
   and succeeds only when that manager is listed in `takeoverFieldManagers`.

Run the suite twice back-to-back to catch timing assumptions.

---

## 9. Limitations at the end of Phase 08

- No sync waves or hooks yet (Phase 10): the plan is a single ordered batch.
- Prunes are ordered by tier + key, not by wave (waves do not exist yet).
- No background garbage-collection of failed prune retries beyond the normal reconcile loop.
- `takeoverFieldManagers` is opt-in per Application; there is no global policy yet.
- The live `kind` verification above is pending (the tests exist and compile, but were not run in
  this environment); the hermetic gate covers the plan/executor branches with fakes.
- `createNamespace` creates the destination namespace but nothing cleans it up when the
  `Application` is deleted: an unstamped namespace is never prunable, by design.

---

## Further reading

- Kubernetes API conventions: resource deletion, finalizers, and background vs foreground
  propagation.
- CRD establishment and aggregated discovery (`Established` condition, discovery refresh).
- Server-Side Apply field ownership and conflict managers (`managedFields`).
