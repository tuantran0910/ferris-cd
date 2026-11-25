# Lesson 09 — Kubernetes Workload Health Machines, `observedGeneration`, and Why Sync ≠ Health

> Phase 09 adds the **health** axis to FerrisCD. Phase 07 taught the controller to answer *"does
> live state match Git?"*; this phase answers a different question: *"is the thing actually
> working?"* The two answers are stored in different fields (`status.sync.status` vs
> `status.health.status`), computed from different inputs (diff vs the live objects' `status`
> blocks), and they routinely disagree in both directions.
>
> Code references: `crates/ferriscd-engine/src/health/{mod,workloads,runtime,crd,values}.rs` (the
> pure engine: lattice, registry, evaluators, generic CR heuristic) and
> `crates/ferriscd-controller/src/{sync.rs,reconcile.rs}` (where health is assessed, merged into
> `/status`, and turned into a requeue interval). The live `kind` experiment at the end is **not**
> executed by `make gate`; it is marked *pending* and must be run by hand.
>
> **`v0.3` is not declared complete until the `#[ignore]`d live test (`tests/integration/
> v0_3_health.rs`) has run on `kind-ferriscd-dev`** — hermetic snapshot tests pin the *state
> machine*, but only a real cluster proves that the kubelet and the workload controllers write the
> status fields the way the fixtures assume.

---

## 1. Two orthogonal axes

| Question | Field | Input | Wrong answer looks like |
|---|---|---|---|
| does live state match Git? | `status.sync.status` | canonicalized live vs SSA `dryRun=All` prediction | `Synced` while every pod crashes |
| are the managed workloads serving? | `status.health.status` | the live objects' `.status` | `Degraded` for a `Deployment` an HPA is legitimately scaling |

Concrete pairs that occur in production:

* **`Synced` + `Degraded`** — a `Deployment` whose `image` Git says is `api:2.1` and the cluster
  agrees, but the tag does not exist in the registry. Nothing is out of sync; nothing works.
* **`OutOfSync` + `Healthy`** — a `Deployment` whose `spec.replicas` is owned by an HPA. The diff
  reports `OutOfSync` on every pass (the field is not ours), while all pods serve traffic.
* **`Synced` + `Progressing`** — a fresh apply. Git matches; the new pods have not started yet.

`T09.5`'s trap guard is therefore structural, not a convention: `build_outcome` derives
`status.sync.status` from `DiffSummary` only, and `health.status` from `HealthSummary` only. No code
path can set one from the other. A hermetically-proven example lives in
`sync.rs::a_skipped_pass_still_reports_health_and_never_claims_healthy`: the gate applies **zero**
objects (`Synced`), and health is still `Progressing` because the `Deployment`'s
`status.observedGeneration` lags its `metadata.generation`.

---

## 2. The lattice

```text
Degraded > Missing > Progressing > Suspended > Unknown > Healthy      (empty set -> Healthy)
```

Why this order:

* `Degraded` outranks everything: a failure is the most actionable signal an operator can get, and
  it must not be hidden by another resource that is merely slow.
* `Missing` outranks `Progressing`: "the object does not exist" is a stronger statement than "the
  object is converging". A resource that vanished is exactly what `selfHeal` exists for, and it
  should not look like a rollout in flight.
* `Suspended` outranks `Unknown`: an intentionally paused workload is *known* to be idle;
  `Unknown` means we could not read the status at all.
* An empty resource set is `Healthy`: an `Application` that manages nothing has nothing broken.
  Reporting `Unknown` there (the `v0.2`-era behaviour) made every `Application` whose bundle is
  empty or not yet applied look unreadable.

`precedence()` is the single implementation, `PRECEDENCE_ORDER` is the same order spelled out for
the tests, and the tests prove the lattice is a **strict total order** (every pair aggregates to the
same winner in both input orders) and that **all 64 subsets** aggregate to their maximum.

The wire type is `ferriscd_crd::status::HealthStatus`, re-exported by the engine — one type, so the
lattice cannot drift from the CRD schema (`MASTER_PLAN` FR-08 listed the order slightly differently
once; the code and the roadmap `T09.1` agree on the order above, and that is what tests pin).

---

## 3. `observedGeneration` is not optional

Every workload evaluator starts with:

```text
metadata.generation (desired)  >  status.observedGeneration (processed)  =>  Progressing
                                                             "Waiting for controller to observe generation"
```

Without it, health is computed from the **previous** rollout's counters. `availableReplicas ==
desired == updatedReplicas` stays true for one or more reconciles after a `spec` edit, so a
just-edited `Deployment` reports `Healthy` *before a single new pod exists* — the classic
false-green, and the reason `observedGeneration` exists in the first place.

A `status` that has not been written at all (a freshly created object) is treated the same way:
`metadata.generation` present + no `status.observedGeneration` ⇒ `Progressing`.

### …except when the controller is paused

A paused `Deployment` stops reconciling, so a `spec` edit made while paused **never** advances
`observedGeneration`. Gating on it first would report `Progressing` forever and (from Phase 10) hang
every sync wave behind it. `Deployment` therefore checks `spec.paused` **before** the generation
gate:

```text
Deployment:  spec.paused == true            -> Suspended      (before everything else)
             observedGeneration < generation -> Progressing
             Progressing=False, reason=ProgressDeadlineExceeded -> Degraded
             spec.replicas == 0, status.replicas == 0 -> Healthy
             updatedReplicas == availableReplicas == desired -> Healthy
             else                            -> Progressing
```

That ordering is a deliberate, tested deviation from "the generation check is always first": it is
the only way `Suspended` is ever reachable for a paused-and-edited `Deployment`. Anything else in
the evaluators keeps the generation check first.

---

## 4. The workload state machines (`T09.2`)

| Kind | `Healthy` when | Traps handled |
|---|---|---|
| `Deployment` | `updatedReplicas == availableReplicas == spec.replicas` | `paused` (§3), `replicas: 0` (Healthy only once `status.replicas == 0`, `Progressing` while pods terminate), `ProgressDeadlineExceeded` |
| `StatefulSet` (`RollingUpdate`) | `updatedReplicas >= replicas - partition` **and** `readyReplicas >= replicas` | `partition > 0` (canary): waiting for `updatedReplicas == replicas` hangs forever |
| `StatefulSet` (`OnDelete`) | `readyReplicas >= replicas` | `updatedReplicas` never advances by itself under `OnDelete`; waiting on it hangs forever |
| `DaemonSet` | `updatedNumberScheduled == desiredNumberScheduled == numberAvailable` | `desiredNumberScheduled == 0` (a selector matching no node) is `Healthy`, not an endless rollout |
| `ReplicaSet` | `availableReplicas >= spec.replicas` | `replicas: 0`; a `ReplicaSet` declared in Git is assessed even though a `Deployment` normally owns it |

Notes worth keeping:

* **`replicas: 0` is a first-class state.** A deliberately scaled-down workload that reports
  `Progressing` forever blocks every wave behind it and trains operators to ignore the health field.
  The condition is `spec.replicas == 0 && status.replicas == 0`; while pods are still terminating it
  stays `Progressing` with a message that says so.
* **An undocumented `Progressing=False` reason stays `Progressing`.** Only
  `ProgressDeadlineExceeded` is documented as terminal, and turning a novel reason into `Degraded`
  would be inventing a failure. The reason is always carried in the message.
* **`Deployment`-level health is coarse.** FerrisCD assesses the resources *in Git*; the pods a
  `Deployment` creates are not in the bundle, so an `ImagePullBackOff` is observed through the
  `Deployment`'s own `Progressing` condition — which only turns `False` after
  `spec.progressDeadlineSeconds` (default **600 s**). The live walkthrough (§9) therefore sets a
  short `progressDeadlineSeconds`; that is the honest, documented lever, not a workaround.

---

## 5. Pods, Jobs, Services, Ingresses, PVCs (`T09.3`)

* **`Pod`**: `Succeeded` → `Healthy`, `Failed` → `Degraded` (terminal phases decide first, because a
  completed pod may legitimately carry an `Error`/`OOMKilled` terminated container). A container
  waiting in `CrashLoopBackOff`, `ImagePullBackOff`, `ErrImagePull` or `CreateContainerConfigError`
  → `Degraded`, in `initContainerStatuses` too. Otherwise `Running` + `Ready=True` → `Healthy`,
  anything else → `Progressing`. A waiting reason that is *not* in that list (e.g.
  `ContainerCreating`) is normal and stays `Progressing`.
* **`Job`**: `spec.suspend` → `Suspended`; `conditions[type=Complete, status=True]` → `Healthy`;
  `conditions[type=Failed, status=True]` → `Degraded`.
  **`status.failed > 0` without a `Failed` condition is `Progressing`, never `Degraded`.** Kubernetes
  increments `status.failed` for every failed pod attempt while `backoffLimit` (default 6) still
  allows another try, so treating it as a failure fails a `PreSync` migration that would have
  succeeded on its second attempt seconds later. The retry count is still reported in the message.
* **`Service`**: `ClusterIP`/`NodePort`/`ExternalName` → `Healthy` (they have no provisioning step;
  an absent `spec.type` means `ClusterIP`). `LoadBalancer` → `Healthy` only once
  `status.loadBalancer.ingress` is non-empty, else `Progressing`. Two overrides exist because a
  local cluster (`kind`) has **no** load-balancer controller: the
  `ferriscd.io/load-balancer-health: Ignore` annotation on the `Service`, and
  `HealthConfig::load_balancer` (`InventorySyncPipeline::with_health_config`) for the whole
  controller. An unparseable annotation value falls back to the default — a typo must never silently
  disable the check.
* **`Ingress`**: `Healthy` when it exists. An `Ingress` has no condition surface FerrisCD can trust
  (`status.loadBalancer` is controller-specific, and an `Ingress` pointing at a dead `Service` is
  still `Accepted`); the backends that *do* have a status (`Service`, `Pod`) carry the real signal.
* **`PersistentVolumeClaim`**: `Bound` → `Healthy`, `Lost` → `Degraded`, `Pending` (or no phase yet)
  → `Progressing`.

---

## 6. Generic custom resources (`T09.4`)

Any `(group, kind)` without a built-in evaluator is judged from `status.conditions`:

1. **Priority**: `Ready` > `Available` > `Healthy` > `Synced` — the first type that exists wins.
   `Ready` is preferred because it is the type the ecosystem standardized on; `Synced` is the
   *weakest* signal (a Crossplane resource can be `Synced=True` — GitOps is happy — and `Ready=False`
   because the cloud API rejected it). If the priority list wins on `Synced`, a broken database is
   reported `Healthy`.
2. **Staleness**: if `status.observedGeneration < metadata.generation` → `Progressing`, and if the
   chosen *condition's* `observedGeneration` is stale → `Progressing`. A stale `Ready=True` must not
   mask a failing update. Unlike the workload evaluators, an **absent** `observedGeneration` is not
   stale (writing it is optional; treating it as stale would report `Progressing` forever).
3. `status: "True"` → `Healthy`; `"False"` with a transient reason (`Progressing`, `Reconciling`,
   `Pending`, `InProgress`, `Creating`, `Updating`, `Installing`, case-insensitive) →
   `Progressing`; any other `"False"` → `Degraded`; `"Unknown"`/unset → `Progressing`.
4. **No `status.conditions` at all** → `Healthy` by default (a spec-only CRD is a configuration
   object), or `Unknown` with `HealthConfig::cr_without_conditions = NoConditionPolicy::Unknown`.
   Conditions present but none of the four known types → `Unknown` (we cannot interpret them, and
   guessing `Healthy` would be a false-green).

Passive built-ins (`ConfigMap`, `Secret`, `ServiceAccount`, `Namespace`, `Role`, `ClusterRole`,
`RoleBinding`, `ClusterRoleBinding`) are `Healthy` whenever they exist — **never** `Unknown`
(`T09.1` trap guard). A `CustomResourceDefinition` is `Healthy` once `Established=True` and
`Progressing` before that (never `Unknown`: the API server is actively registering it).

Secret hygiene: no evaluator reads `data`/`stringData` of a `Secret`; the passive evaluator only
names the kind. Health messages are derived from `status` counters and condition
reason/message text, which Kubernetes never fills with secret values. A test
(`passive_secret_health_never_echoes_its_payload`) pins that.

---

## 7. Where health is computed, and how it reaches `/status`

```text
sync_apply:
  … Phase 07/08 pipeline unchanged …
  → assess_health(desired set, pass-level live read, applied_ok)
      health_inputs():  Present  → the live object (real evaluator)
                        Missing + applied this pass → Progressing("applied in this pass; …")
                        Missing (not applied)      → Missing
                        DeferredPending*           → Progressing(waiting for …)
  → health::assess(inputs, HealthRegistry::builtin(), HealthConfig)
      per-resource verdicts, sorted by ResourceKey (byte-stable /status)
      aggregate via the lattice, bounded message naming the worst resource
  → ApplyOutcome { health: Some(HealthState), resources: Some(Vec<ResourceStatus>) }
  → plan_requeue(execute, pending, health.status, spec.requeueAfterSeconds)
```

Decisions that matter:

* **Health is assessed on every pass, including a `Skip`.** `automated: None` (manual-only)
  `Application`s would otherwise never report health at all.
* **No extra API calls.** The inputs are the objects the pass already fetched for the diff
  (`desired ∪ prev_inventory`, model 1 drift detection). Health never adds a cluster-wide informer.
* **A `Present` object is used even if this pass re-applied it** — its `status` is one reconcile
  stale and self-corrects, whereas reporting `Missing` for an object that demonstrably exists is a
  lie. A `Missing` object that this pass *created* is `Progressing`, not `Missing`.
* **`status.resources` is replaced, not merged** (`apply_outcome_status`): it is this pass's
  assessment of exactly the desired set, so a resource removed from Git cannot keep a stale summary
  forever. The list is bounded (`MAX_RESOURCE_STATUSES = 100`, overflow counted in
  `resourcesOmitted`, messages truncated to 200 chars) exactly like the rest of `/status` (trap T9).
* **A pipeline that reports no health leaves `status.health` untouched** (`None` ⇒ no write), so an
  `ApplyOutcome` from another phase can never clear it.
* **Adaptive requeue** (`plan_requeue`):
  `pending` on a CRD/namespace → `PENDING_REQUEUE` (10 s);
  `Progressing` → `min(PROGRESSING_REQUEUE = 10 s, spec.requeueAfterSeconds)`;
  settled (`Healthy`/`Degraded`/`Suspended`/`Missing`/`Unknown`) → `spec.requeueAfterSeconds`.
  Only `Progressing` shortens the interval: a rollout converges in seconds, whereas `Degraded` and
  `Missing` are observations a faster poll cannot change, and polling hard because a workload is
  broken helps nobody. The interval is never *lengthened*: an operator who configured 3 s keeps 3 s.

---

## 8. Known limitations (documented, not hidden)

* **Only resources in Git are assessed.** A `Deployment`'s pods, a `Job`'s pods, and a
  `LoadBalancer`'s backends are not in the bundle, so workload failure surfaces through the
  owner's own conditions. For a bad image that means waiting for
  `spec.progressDeadlineSeconds` (600 s by default) unless the manifest shortens it. Pod-level
  aggregation is inbound with hook/wave health (Phase 10) and would still be scoped to the bundle.
* **Orphans are not health-assessed.** A resource still tracked in `status.inventory` but removed
  from Git is pruned (or deliberately retained) without contributing to `status.health`: it is no
  longer part of what the `Application` *declares*, and letting a resource on its way out pin
  `Missing`/`Degraded` would make the aggregate meaningless.
* **An empty assessment needs the explicit patch field.** `ApplicationStatus::resources` is
  `skip_serializing_if = "Vec::is_empty"`, and a JSON merge patch treats an absent field as
  "unchanged", so `status_patch_body` always emits `resources` (and `resourcesOmitted`) — otherwise
  a pass that assesses nothing would leave the previous summaries on the CR forever.
* **`Ingress` health is "exists".** No ingress controller publishes a portable, trustworthy
  condition for it.
* **`ReplicaFailure=True` is not treated as failure.** Kubernetes sets it transiently during normal
  rollouts (quota, scheduling), so acting on it produces false `Degraded` verdicts. Only
  `ProgressDeadlineExceeded` is terminal.
* **`Unknown` is not "the API server is unreachable".** Health is computed from a live read that
  already succeeded; a failed read fails the whole reconcile (retry with backoff) and leaves the
  previous `status.health` in place rather than flapping it to `Unknown`.
* **`status.health` is aggregate-only.** There is no per-condition health detail on the
  `Application` beyond `status.resources[].message`, which is deliberately bounded.
* **Health does not gate anything yet.** Waves and hooks that wait for `Healthy` are `T10.x`; this
  phase only *reports* health and polls faster while it converges.

---

## 9. Manual `kind` walkthrough — **PENDING (not yet executed)**

Everything below must be run by hand against `kind-ferriscd-dev`. **No output is recorded in this
repository yet**, and nothing here is asserted by CI. The values below are the assertions to
*check*, not measurements.

```bash
# 0. cluster + CRDs + control-plane namespace
make kind-up
kubectl apply -f deploy/crds
kubectl create namespace ferriscd-system --dry-run=client -o yaml | kubectl apply -f -

# 1. a fixture repo: Namespace + a Deployment with a tag that does not exist.
#    progressDeadlineSeconds is shortened to 45 s — with the default 600 s the Deployment
#    legitimately stays Progressing for ten minutes (§4).
export DEMO=$(mktemp -d); mkdir -p "$DEMO/repo" && cd "$DEMO/repo"
cat > namespace.yaml <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: ferriscd-health-demo
EOF
cat > deployment.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  progressDeadlineSeconds: 45
  selector:
    matchLabels: { app: web }
  template:
    metadata:
      labels: { app: web }
    spec:
      containers:
        - name: web
          image: nginx:definitely-not-a-real-tag
          ports: [{ containerPort: 80 }]
EOF
git init --initial-branch=main . && git add . \
  && git -c user.name=demo -c user.email=demo@example.com commit -m "bad image"
cd -

# 2. run the controller
cargo run -p ferriscd-cli -- controller --allow-local-repos --namespace ferriscd-system

# 3. create the Application
kubectl apply -f - <<EOF
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata: { name: health-demo, namespace: ferriscd-system }
spec:
  source: { git: { repoURL: $DEMO/repo, targetRevision: main, path: . } }
  destination: { cluster: in-cluster, namespace: ferriscd-health-demo }
  syncPolicy: { automated: { prune: false, selfHeal: true } }
  requeueAfterSeconds: 15
EOF
```

### 9.1 bad image → `Synced` + `Progressing` → `Degraded`

```bash
watch -n 2 'kubectl get application health-demo -n ferriscd-system \
  -o jsonpath="{.status.sync.status}{\" \"}{.status.health.status}{\" \"}{.status.health.message}{\"\\n\"}"'
```

Expected (verify, do not assume):

* immediately after the first apply: `Synced Progressing` — the `Deployment` was created by that
  pass, so the live read that fed the health assessment predates the write.
* within ~45 s: `Synced Degraded`, message naming `apps/Deployment/ferriscd-health-demo/web is
  Degraded(` and `progress deadline`.
* `kubectl get pods -n ferriscd-health-demo` → `ImagePullBackOff`.
* `kubectl get application health-demo -n ferriscd-system -o jsonpath='{.status.resources}'` → one
  entry for the `Deployment` (and one for the `Namespace`) with `"health":"Degraded"`.

This is the `T09.5` assertion: the *sync* status never left `Synced` — Git and the cluster agree —
while health went `Progressing` → `Degraded`.

### 9.2 fixed image → `Progressing` → `Healthy`

```bash
cd "$DEMO/repo"
sed -i.bak 's/nginx:definitely-not-a-real-tag/nginx:1.27-alpine/' deployment.yaml
git add . && git -c user.name=demo -c user.email=demo@example.com commit -m "fix image"
cd -
```

Expected:

* the commit is picked up on the next reconcile (`status.sync.revision` advances);
* health goes `Progressing` while the new pod pulls and starts (the message names the
  `updated/available/ready` counters), then `Healthy` with `all N resource(s) are healthy`;
* while `Progressing` the controller requeues every 10 s (watch the controller log:
  `assessed application health … requeue_seconds=10`), and once `Healthy` it goes back to
  `requeueAfterSeconds` (`15`).

### 9.3 the lattice, by hand

Leave a second `Deployment` in the repo with `spec.paused: true` and commit it: the aggregate must be
`Suspended` (not `Progressing`), and the namespace-level `status.health.message` must name the paused
`Deployment`. Scale a `Deployment` to `0` replicas: it must report `Healthy` once its pods are gone.

### 9.4 cleanup

```bash
kubectl delete application health-demo -n ferriscd-system
kubectl delete namespace ferriscd-health-demo
make kind-down
```

**Status:** pending manual execution. Replace this paragraph with the observed `status.health`
transitions and `status.resources` output — and with every *surprise* — once the walkthrough has
actually run on `kind-ferriscd-dev`.

---

## 10. What is verified automatically

```bash
make gate                # fmt + clippy + unit/integration tests (no cluster)
make test-integration    # the #[ignore]d live tests (requires kind-up + kind-* context)
```

Hermetic coverage (no cluster, no network):

* **Lattice** (`health/mod.rs`): strict total order over every pair (both input orders), all 64
  subsets aggregate to their maximum, empty set is `Healthy`, `PRECEDENCE_ORDER` matches
  `precedence()`, wire labels are stable.
* **Registry** (`health/mod.rs`): every passive kind is registered and `Healthy` (never `Unknown`),
  a `Secret`'s payload never appears in its health message, `CustomResourceDefinition` is
  `Progressing` → `Healthy` on `Established`, unknown kinds fall back to the generic heuristic,
  custom evaluators can be registered per `(group, kind)`.
* **Observations & aggregation** (`health/mod.rs`): `Live`/`Missing`/`Applied`/`Pending` map onto
  `Healthy`/`Missing`/`Progressing`/`Progressing`, per-resource assessments are sorted by
  `ResourceKey`, the summary message is deterministic, bounded and names the worst resource.
* **Workloads** (`health/workloads.rs`): settled rollout, stale `observedGeneration`, no status at
  all, `paused` (including paused *and* stale), `ProgressDeadlineExceeded`, an undocumented
  `Progressing=False`, `replicas: 0` (settled and still terminating), partially rolled,
  `OnDelete` StatefulSet (stuck `updatedReplicas` is `Healthy`, not-ready is `Progressing`),
  partitioned StatefulSet (2-of-5 required, full partition, unpartitioned equivalent, partially
  rolled), `DaemonSet` desired/updated/available and the no-matching-node case, `ReplicaSet`
  availability and observation.
* **Runtime** (`health/runtime.rs`): `Pod` terminal phases before container state, every fatal
  waiting reason, a benign waiting reason, a fatal *init* container, `Job` suspend/complete/failed,
  **the retry trap** (`status.failed: 1` without a `Failed` condition is `Progressing`), every
  addressable `Service` type, `LoadBalancer` pending/provisioned, the annotation and global
  overrides (including a typo falling back), `Ingress`, and all four `PVC` phases.
* **Generic CRs** (`health/crd.rs`): a cert-manager `Certificate` (`Ready` True/False/transient), a
  Crossplane resource where `Synced=True` must not mask `Ready=False`, a `Synced`-only CR, a
  spec-only CR in both policy modes, a stale status *and* a stale condition generation, an absent
  `observedGeneration`, and unrecognized condition types.
* **Values** (`health/values.rs`): absent/mistyped fields never panic, negative counts clamp,
  conditions without a `type` are skipped, `describe()` covers every reason/message combination.
* **Wiring** (`sync.rs`): `Synced` + `Progressing` on a skipped pass with zero applies and a 10 s
  requeue; `Synced` + `Degraded` with the configured interval; `Healthy` + the configured interval;
  the full `plan_requeue` table; `health_inputs` covering every `LiveState` (an applied resource is
  never `Missing`, a desired key is never an orphan).
* **Status merge** (`reconcile.rs`): a successful outcome persists `status.health`, **replaces**
  `status.resources` (stale entries dropped, `resourcesOmitted` reset), leaves the `Ready`
  condition alone, and an outcome without health leaves the previous health untouched.

Live coverage (`tests/integration/v0_3_health.rs`, `#[ignore]`d, `kind-` context guarded, compiled
through `crates/ferriscd-cli/tests/v0_3_health.rs`): the §9 legs — bad image ⇒ `Synced` +
`Progressing` (fresh create) ⇒ `Degraded` after a 45 s progress deadline, the per-resource
`status.resources` entry, then a fixed image ⇒ `Progressing` ⇒ `Healthy` within ~15 s of the
rollout completing.
