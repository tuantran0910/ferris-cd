# Lesson 10 — Sync Waves, Lifecycle Hooks, and GitOps-Safe Rollback

> Phase 10 turns FerrisCD from *"apply the diff"* into *"run an ordered, observable rollout"*. Three
> things make that hard, and none of them is about YAML:
>
> 1. **Waiting is not allowed.** A wave `-1` database migration can take minutes. A reconcile worker
>    that sleeps on it starves every other `Application`, and a pod restart loses all progress. The
>    progress of a multi-wave sync therefore lives in `Application.status.operationState` and every
>    pass *re-derives* the next step from `(persisted state, wave schedule, observed health)`.
> 2. **A hook is not desired state.** A `PreSync` `Job` must be created imperatively (so
>    `metadata.generateName` works), tracked outside `status.inventory`, and reaped by its own
>    deletion policy — otherwise a requeue runs the migration twice or the pruner deletes a Job that
>    is still running.
> 3. **A rollback fights `selfHeal`.** Deploying an old commit while `spec.syncPolicy.automated`
>    still compares live state against `HEAD` is not a rollback: the next reconcile reverts it. The
>    only honest implementation is "pin the commit **and** turn automation off, loudly".
>
> Code references: `crates/ferriscd-engine/src/sync/{state_machine,history}.rs`,
> `crates/ferriscd-engine/src/graph/{waves,hooks}.rs` (the pure engine) and
> `crates/ferriscd-controller/src/{waves,hooks,sync}.rs` (the impure half: `Api::create`, deletes,
> `/status` patches). The live `kind` experiment at the end is **not** executed by `make gate`; it is
> marked *pending* and must be run by hand.
>
> **`v0.3` is not declared complete until the `#[ignore]`d live suite (`tests/integration/
> v0_3_e2e.rs`) has run green on `kind-ferriscd-dev`** — the hermetic tests pin the state machine,
> the hook lifecycle and the rollback decision, but only a real cluster proves that the API server
> generates the hook names, that the `Established` wait is fast enough between waves, and that a
> pinned revision really survives a `selfHeal` pass.

---

## 1. The phase graph

```text
PreSync ──> Sync(wave -1) ──> Sync(wave 0) ──> … ──> PostSync ──> Succeeded
                  │
                  └──────────────> SyncFail ──> Failed
```

| persisted | observed | next |
|---|---|---|
| any running step | every expected resource `Healthy` | the next step (`Execute`) |
| any running step | some resource `Progressing`/`Missing`/`Unknown` | same step (`Wait`, 5 s requeue) |
| any running step | nothing observed yet | same step (`Execute`, re-apply is idempotent) |
| any running step | any resource `Degraded` | `SyncFail` (runs the failure hooks), then `Failed` |
| any running step | step or operation elapsed ≥ timeout (10 min) | `SyncFail`, then `Failed` |
| `SyncFail` | its hooks finished (or failed, or there are none) | `Failed` |
| any running step | the resolved revision moved | `PreSync` of the new revision |

Two rows deserve a comment.

**"Nothing observed" must re-execute, not wait.** A pass reads live state *before* it writes, so on
the pass that dispatches a wave nothing of that wave exists yet. Treating "no observation" as
"converging" deadlocks the very first wave; treating it as "execute" is safe (Server-Side Apply and
`Api::create` are idempotent) and crash-safe (a worker killed after persisting `operationState` but
before writing simply writes on the next pass). Care is needed on the other side too: re-dispatching
the *same* step must not move `phaseStartedAt`, or a wave that legitimately takes minutes could never
time out.

**`SyncFail` is not terminal.** It is the phase that runs the failure hooks, so it must be
enterable — and a *failing* `SyncFail` hook must never hang the operation. The machine therefore maps
"`SyncFail` hooks did not complete" straight to the terminal `Failed` phase.

### Which bundles enter the machine at all

A bundle with **one wave and no hooks** is applied in a single pass, exactly like Phase 08. There is
nothing to order and nothing to wait for, so a persisted phase would only add a requeue — and it
would change the observable behaviour of every application that already worked (`status.sync.status`
would flap through `SyncInProgress`, and orphan pruning would slip from "this pass" to "after
`PostSync`"). Everything else — several waves, any lifecycle hook, or an operation that is already
running — is driven by the machine across requeues (`BundleWaves::needs_operation`).

---

## 2. Waves: ordering that the cluster never validates

`ferriscd.io/sync-wave` is a signed `i32` that only FerrisCD reads, so a typo is invisible until the
migration runs *after* the workload it was supposed to prepare. Parsing is therefore strict and
terminal (`ManifestError::InvalidAnnotation`, naming the file, the resource and the value);
`sync-wave: ""` is an error rather than wave `0`.

Inside a wave the Phase 08 tier order still applies, so a wave can never apply a `Deployment` before
the `ConfigMap` it mounts:

```text
migration.yaml   ferriscd.io/sync-wave: "-1"   Job/migrate        -> wave -1
config.yaml      (no annotation)               ConfigMap/settings -> wave  0
deployment.yaml  (no annotation)               Deployment/api     -> wave  0
smoke.yaml       ferriscd.io/sync-wave: "1"    Job/smoke          -> wave  1
```

Two consequences the wiring must respect:

* **The wave is the unit of the health gate.** A `Sync(wave 0)` step is satisfied only when *every*
  resource of that wave is `Healthy` — including a `ferriscd.io/hook: Sync` `Job` that shares the
  wave number. Reporting a wave `Healthy` as soon as its `ConfigMap` converges would start an inline
  migration's dependants while the migration is still running.
* **A wave that carries a `CustomResourceDefinition` must refresh discovery before the next wave.**
  This is `T08.3`'s rule lifted to the wave boundary: the CRD registers its kinds only once the API
  server establishes it, so the discovery snapshot taken at the start of the pass does not serve
  them. `WavePlan::contains_crd(wave)` is the pure predicate the controller asks;
  `DiscoveryCache::invalidate_and_refresh()` is the side effect it performs.

### Ownership stamping must precede the wave plan

A `WavePlan` owns **clones** of the permanent resources. A plan built *before*
`ferriscd.io/tracking-id` was stamped would apply every wave member without the marker: the pruner
would classify the live object as unmanaged (never prunable, never re-confirmed) and every wave's
dry-run diff would report the missing annotation as permanent drift. This was found by the hermetic
"two waves, one pass each" test and is now pinned by `BundleWaves::replan` plus a unit test.

---

## 3. Hooks: desired state that must not be desired

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  generateName: migrate-
  annotations:
    ferriscd.io/hook: PreSync
    ferriscd.io/hook-delete-policy: BeforeHookCreation
```

* **Partition first.** `graph::hooks::partition` removes every annotated resource from the permanent
  set, so it can never reach `status.inventory`, the pruner, the drift diff or the wave planner. The
  inventory is built from the partition (`permanent_inventory`), which is the seam that makes the
  invariant structural rather than a convention.
* **`generateName` needs `Api::create`.** A Server-Side Apply needs a name, so a `generateName` hook
  cannot be applied — it must be created. The API server picks the suffix, and that name is recorded
  in `status.operationState.activeHooks` (keyed by the hook's stable `<source file>#<ordinal>` id)
  so the next requeue observes *that* `Job` instead of starting a second migration. The alternative
  — keying by GKNN — cannot work: a `generateName` hook has no name before it exists.
* **`metadata.generateName` is only legal on a hook.** For a permanent resource the name *is* the
  identity (inventory, prune, diff), so the loader rejects it; the controller keeps a second,
  explicit check with an actionable message.
* **Hooks are never stamped** with `ferriscd.io/tracking-id` (another reason the partition must come
  before `stamp_ownership`).

### Delete policies

| policy | when the object is deleted |
|---|---|
| `BeforeHookCreation` (default for named hooks) | a previous run is deleted **before** the hook is (re)created, and the create waits for `404` |
| `HookSucceeded` | as soon as the hook is observed `Healthy` |
| `HookFailed` | as soon as the hook is observed `Degraded` |

`BeforeHookCreation` never deletes and creates in one pass. `Delete` is asynchronous in Kubernetes,
so re-creating immediately answers `409 AlreadyExists`; the pass that deleted reports
`pending_delete`, and the next pass sees `404` and creates. A hook that already reached `Healthy` is
never read or created again: after `HookSucceeded` has reaped the object a health read would answer
`404`, and re-running a migration is far worse than a stale record.

A `generateName` hook that has **neither** `HookSucceeded` nor `HookFailed` is never reaped: it leaks
one completed `Job` per sync, because `BeforeHookCreation` only pre-deletes hooks that have an
explicit `metadata.name` (there is no prefix to delete safely). Pair `generateName` with
`HookSucceeded` whenever the finished object is no longer wanted.

---

## 4. Rollback: pin the commit, then take Git back out of the loop

`ferriscd.io/operation: {"rollback":{"id":1}}` is parsed **before** the diff gate, because it decides
*which commit the pass sees*. Applying `HEAD` and then "rolling back" would have mutated the cluster
towards the wrong commit first — and with `selfHeal` it would fight itself forever.

```text
status.history: [ {id:2, revision:"sha-v2"}, {id:1, revision:"sha-v1"} ]
request:        {"rollback":{"id":1}}
                -> resolve "sha-v1"        (status.history, never HEAD)
                -> patch spec.syncPolicy.automated = null
                -> condition Warning/AutomatedSyncDisabledByRollback
                -> sync, and record the rollback as a new deployment (id 3)
                -> consume the annotation once it succeeded
```

* **Disabling automation is the whole point.** `selfHeal: true` compares live state against `HEAD`
  on every pass; leaving it on means the rollback is reverted within one requeue. Removing
  `spec.syncPolicy.automated` (a narrow merge patch — `prune`/`syncOptions` survive) is what makes
  the rollback stick, and it is what the operator must undo deliberately after fixing Git.
* **The warning is the only explanation the operator gets**, so it is a `Warning` condition (with
  `status: True`; `metav1.Condition` has no polarity field) named
  `AutomatedSyncDisabledByRollback`. It is cleared automatically on the first pass that sees
  `spec.syncPolicy.automated` back on — a warning that outlives its cause trains operators to ignore
  warnings.
* **Stability comes from `/status`, not from the annotation.** Once the request has been honoured the
  annotation is consumed (it must not keep forcing a manual sync), and the pin becomes
  `operationState.revision` **while the warning stands**: that is what keeps `status.sync.revision`
  on `sha-v1` instead of flipping back to `HEAD` on the next pass.
* **History is bounded and idempotent.** `min(spec.revisionHistoryLimit, 20)` entries, appended once
  per *deployment* (a repeated `Finished` pass or a drift-healing pass of the same commit must not
  append a duplicate).

> The engine's `record_operation_success` is idempotent per `(revision, finishedAt)`; because a
> drift-healing pass starts a *new* operation (and therefore a new `finishedAt`), the controller
> gates the call on "the resulting revision differs from `status.sync.lastSyncedRevision`". One
> history entry per deployed revision, not per pass.

---

## 5. Where each decision lives

```text
controller/src/sync.rs
  plan_rollback()        parse + pin + disable automated + warn      (impure: one spec patch)
  fetch_desired(pinned)  render the pinned commit, never HEAD
  BundleWaves::partition hooks out, permanent set into waves          (pure engine)
  stamp_ownership()      tracking-id on the permanent half only
  BundleWaves::replan()  re-derive the plan from the stamped half
  run_single_pass()      Phase 08 path: one wave, no hooks, one pass
  run_operation()        Phase 10 path: hooks -> machine step -> execute one wave
  execute_plan()         the single place that turns a plan into cluster calls
controller/src/hooks.rs  create / observe / reap, tracking in operationState.activeHooks
controller/src/waves.rs  step_health(), needs_operation(), merge_hook_records(), replan()
engine/src/sync/state_machine.rs   the pure phase graph, timeouts, requeue hints as data
engine/src/sync/history.rs         bounded history, rollback target, warning condition
```

`SyncMachine::step` takes `(persisted state, schedule, observed health, revision, now)` and returns
`StepOutcome { state, action }` — **data**, never a side effect. That is what makes "restart" a
round-trip through `serde_json` and "a stuck wave" a test that passes a later `now`.

---

## 6. Known limitations (documented, not hidden)

* **A crash between `Api::create` and the `/status` patch can duplicate a hook run.** The window is
  one API call wide and unavoidable without pre-generating names; the recorded generated name closes
  the *requeue* window (finding H2), which is the one that happens on every sync.
* **`BeforeHookCreation` deletes by name inside the destination namespace.** A hook whose rendered
  name collides with an object managed by something else would be deleted. Named hooks are the only
  case that can collide, and the policy is exactly the documented GitOps semantic; use
  `generateName` when that risk matters.
* **`WaveGate::HealthyOnly` treats `Suspended` as not-done.** A `Deployment` with `spec.paused: true`
  never becomes `Healthy`, so its wave fails on the wave timeout. `v1alpha1` exposes no spec field to
  relax this (`WaveGate::HealthyOrSuspended` exists for a future opt-in).
* **Pruning runs on `PostSync`, not per wave.** An orphan is reaped once the whole rollout converged,
  so a resource an earlier wave depended on cannot be deleted mid-rollout. In a hook-only commit (no
  permanent resources) `PostSync` is what still lets a prune happen.
* **An apply failure ends the pass, not the operation.** The `Ready` condition reports the error and
  the operation stays `Running` until the wave timeout turns it into `SyncFail` → `Failed` (10 min).
  The alternative — synthesizing a `Degraded` observation for the failed key — was rejected as
  second-guessing the API server.
* **A rollback pins a commit, not a manifest.** If the historical commit's `spec.source.git.path` no
  longer exists in the repository, the rollback fails like any other render error.

---

## 7. Manual `kind` walkthrough — **PENDING (not yet executed)**

Everything below is a **script**, not a recorded result. The real output must be pasted in after the
run; nothing in this section is a measurement yet.

```bash
# 0. cluster + CRDs
make kind-up
kubectl apply -f deploy/crds
kubectl create namespace ferriscd-system --dry-run=client -o yaml | kubectl apply -f -

# 1. the waves + hooks example (wave -1 PreSync migration, wave 0 workloads, wave 1 PostSync smoke)
#    NOTE: `repoURL` must be the absolute path of the checkout below.
git init -b main /tmp/waves-demo && cp examples/waves-hooks/*.yaml /tmp/waves-demo/
git -C /tmp/waves-demo add . && git -C /tmp/waves-demo -c user.email=demo@example.com \
  -c user.name=demo commit -m "seed"
kubectl -n ferriscd-system apply -f /tmp/waves-demo/application.yaml

# 2. run the controller
cargo run -p ferriscd-cli -- controller --namespace ferriscd-system --allow-local-repos

# 3. in a second shell: watch the phases
kubectl -n ferriscd-system get application waves-hooks -o \
  jsonpath='{.status.operationState.syncPhase}/{.status.operationState.currentWave}{"\n"}' -w
kubectl -n ferriscd-waves-hooks get jobs,deployments -w
```

Expected, to be confirmed and pasted:

| step | observation to record |
|---|---|
| wave `-1` | `PreSync` `Job` created with a generated name; `status.operationState.activeHooks[].generatedName` equals it |
| wave `0` | the `Deployment` does **not** exist while the `PreSync` Job runs |
| `PostSync` | the smoke `Job` exists only after both waves are `Healthy`, and is reaped by `HookSucceeded` |
| inventory | `status.inventory` contains no `Job` at any point |
| rollback | after `{"rollback":{"id":1}}`: `status.sync.revision` = the older SHA, `spec.syncPolicy.automated` gone, warning condition present, and the revision stays put for ≥ 3 requeues |

Record here (paste raw output):

```text
PENDING — no live run has been performed for this lesson yet.
```

---

## 8. What is verified automatically

* **State machine** (`engine/src/sync/state_machine.rs`): the three-wave happy path with a restart
  between *every* pass, `Progressing` → `Healthy`, `Degraded` → `SyncFail` → `Failed`, the wave
  timeout, the operation timeout, `SyncFail` hooks that fail (never hang), `Suspended` under both
  gates, a legacy state without `syncPhase`, a wave that disappeared from the schedule, purity (no
  clock, no mutation of the persisted state), terminal normalization (`Running` + `Succeeded` is
  repaired), `Unobserved` re-dispatch that keeps `phaseStartedAt`, the `SyncFail` reason surviving
  into `/status`, a revision change restarting at `PreSync`, and `current_step` agreeing with the
  step the machine resumes at.
* **History & rollback** (`engine/src/sync/history.rs`): `min(limit, 20)` bound, monotonic ids,
  idempotent recording per `(revision, deployedAt)`, the `AutomatedSyncDisabledByRollback`
  condition, every `RollbackError` variant, and the warning-clearing rule.
* **Waves** (`engine/src/graph/waves.rs`): signed `i32` range, blank/overflowing values rejected,
  tier order inside a wave, permutation determinism, `contains_crd`/`crd_waves`/`last_wave`.
* **Hooks** (`engine/src/graph/hooks.rs`, `controller/src/hooks.rs`): phase and policy parsing
  (aliases, blanks, unknown tokens), partition out of the inventory and the wave plan, `Skip`,
  stable `<file>#<ordinal>` ids, "created once, then observed", `generateName` never pre-deleted,
  `BeforeHookCreation` → delete → wait `404` → create, `HookSucceeded`/`HookFailed` reaping, a
  degraded hook reported as data (never an error), and a vanished hook failing the step instead of
  waiting for the timeout.
* **Wiring** (`controller/src/sync.rs`): a two-wave bundle applied one wave per pass with the
  `operationState` persisted at every step and history recorded once; a CRD in wave `-1` forcing a
  discovery refresh before wave `0`; a rollback that renders the historical commit, patches only
  `spec.syncPolicy.automated`, warns, consumes the annotation, records the deployment, and then
  keeps the pinned revision across three further passes with zero mutating applies; an unknown
  history id and a non-rollback operation annotation.

Live coverage (`tests/integration/v0_3_e2e.rs`, `#[ignore]`d, `kind-` context guarded, compiled
through `crates/ferriscd-cli/tests/v0_3_e2e.rs`): the seven `v0.3` invariants of §7 —
self-heal on/off, safe prune vs a foreign owner, CRD+CR in one sync, `Secret.stringData` zero drift
plus plaintext-free `/status`, a `PreSync` hook with a real multi-wave rollout, `Degraded` →
`Healthy`, and rollback stability.
