# Lesson 20 — Multi-Source, Policy Gates, Progressive Delivery, Disaster Recovery & Fleet Scale

**Phase 20 (`v2.0`) knowledge base.** This chapter covers the five `v2.0` milestones end to end:
multi-source `Application`s (`T20.1`), the declarative policy gate (`T20.2`), metric-gated
progressive delivery (`T20.3`), disaster recovery and upgrade safety (`T20.4`), and fleet-scale
operation with a federated overview (`T20.5`).

The theme of the phase is **one control plane, many failure modes** — and, for each of them, a rule
that fails *closed* and says so in the object's own status.

---

## 1. Multi-source applications (`T20.1`)

### 1.1 What the spec looks like

```yaml
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: storefront
  namespace: ferriscd-system
spec:
  sources:
    - ref: chart
      git:
        repoURL: https://git.example.com/charts.git
        targetRevision: main
        path: charts/storefront
    - ref: values
      git:
        repoURL: https://git.example.com/config.git
        targetRevision: main
        path: values
  renderer:
    helm:
      valueFiles:
        - $ref/values/values.yaml
```

* `spec.source` (single) and `spec.sources[]` (multi) are **mutually exclusive** — a CEL rule on the
  CRD rejects an object that declares both, and one that declares neither.
* At most **16** sources (`MAX_SOURCES`), each `ref` unique. A `ref` is an *alias*, not a path: it
  names the source for `$ref/<alias>/…` lookups inside a renderer.
* `renderer` on a source entry wins over a fleet-level `renderer`; with no explicit renderer, the
  **first** entry renders and the others only contribute files.

### 1.2 The three things that break first

| Trap | What FerrisCD does |
|---|---|
| A `$ref` escaping the checked-out worktree | `SourceRoots` jails every lookup to the materialised checkout root; a symlink or `../` escape is refused before any file is read |
| The composite revision no longer identifies one commit | `status.sync.revision` stays the raw SHA for a single source and becomes a `sha256:` **composite digest** over the ordered per-source revisions for several sources |
| Rollback pointing at a composite digest | `status.history[].revisions` records one revision per source; a rollback re-pins **each** source. A composite pin that no history entry decomposes is a **terminal** error, never a fetch of a `sha256:` string |

### 1.3 Policy follows every source

`AppProjectPolicy::check_application` validates **every** declared source URL against
`sourceRepos` (redacted per source kind). An unauthorized second source is refused *before the
first clone* — the trap guard asserts zero resolve calls.

---

## 2. The policy gate (`T20.2`)

Two engines, one contract:

* **CEL** (`crates/ferriscd-engine/src/policy/cel.rs`) — embedded, no sidecar, evaluated against the
  rendered bundle.
* **Rego/OPA** (`crates/ferriscd-engine/src/policy/rego.rs`) — optional, for organisations that
  already have a policy library.

Both produce the same verdict shape, and both are configured by cluster admins in
`ferriscd-system` (`ferriscd-policies-cm`), never by the tenant whose bundle is judged.

| Rule level | Effect |
|---|---|
| `Enforce` | The sync is refused. The `Application` goes `Ready=False, reason=PolicyViolation`, the inventory is untouched, and nothing is applied or pruned. |
| `Warn` | The sync proceeds; the violation is recorded and surfaced in the UI diff. |

The gate runs **before** any apply, so a refused policy never leaves a half-applied fleet behind.
An evaluation error is a refusal, not a pass: the gate fails closed.

---

## 3. Metric-gated progressive delivery (`T20.3`)

```yaml
spec:
  syncPolicy:
    syncOptions: ["applyOutOfSyncOnly=true"]
    metricGates:
      - afterWave: 1
        provider: prod-prometheus
        query: sum(rate(http_requests_total{job="storefront"}[1m]))
        successCondition: result[0] > 0
        intervalSeconds: 15
        count: 3
        failureAction: Rollback
```

### 3.1 Why the field is `provider` and not a URL

A tenant-supplied URL in `ApplicationSpec` is an SSRF primitive: it would let a tenant point the
control plane at `169.254.169.254` or an internal admin endpoint. So the spec names an
**allowlisted provider**; the URL lives in `ConfigMap/ferriscd-metrics-providers-cm` in
`ferriscd-system`, which only a cluster admin writes. `ApplicationSpec::validate` additionally
*rejects* URL-shaped `provider` values, so a misconfiguration fails at admission, not at query time.

### 3.2 The gate is re-entrant, never blocking

A gate samples a metric every `intervalSeconds` and needs `count` consecutive successes before the
next wave is promoted. Sampling happens **across reconciles**: the pass persists the gate's progress
(`status.operationState.metricGate`) and requeues, it never sleeps a reconcile worker. A restarted
pass drops the gate progress — samples belong to a revision, not to the object.

A gate **breach** is terminal for that pass:

* `failureAction: Pause` — the operation stops and the `Application` waits for an operator.
* `failureAction: Rollback` — the controller re-enters the `T10.5` rollback path (pin the previous
  history revision, strip `automated`, record the rollback), so there is exactly one rollback
  implementation in the product.

A provider that is unreachable, or a query that fails to parse, is **fail-closed**: the gate does
not pass, and the error is never formatted into a log line (a `reqwest` `Display` contains the URL).

### 3.3 Health evaluators for the traffic managers that gate on

`HTTPRoute` (`gateway.networking.k8s.io`), Argo `Rollout` and Flagger `Canary` get first-class
evaluators, each mapping its conditions onto the FerrisCD health lattice and refusing a stale
`observedGeneration` as "not yet known" rather than "healthy".

---

## 4. Disaster recovery & upgrade safety (`T20.4`)

```bash
ferriscd backup export --output ferriscd-dr-$(date +%F).json --control-plane-namespace ferriscd-system
ferriscd backup restore ferriscd-dr-2026-11-28.json --dry-run
ferriscd backup restore ferriscd-dr-2026-11-28.json --on-conflict abort
```

| Property | Implementation |
|---|---|
| The bundle contains **no secret material** | Credentials are listed as an *inventory* (names, kinds, namespaces); the values never leave the cluster |
| The bundle is reproducible | `--exported-at` makes two exports of an unchanged control plane byte-identical, so `git diff --exit-code` answers "did anything change?" |
| A restore cannot silently steal fields | Every apply is Server-Side Apply with `force: false`; a `409` is reported (`--on-conflict abort|takeover`) |
| A restore can be staged before the credentials exist | `--allow-missing-secrets`; the affected applications report `Ready=False` until the credential is copied over |
| The export is private | `--output` writes the file with mode `0600` |

The upgrade path is the same discipline applied to the product itself: Helm values are additive,
CRDs are regenerated and vendored (`make crd-check`), and the release pipeline publishes signed
images plus a CycloneDX SBOM (see Lesson 17).

---

## 5. Fleet scale & federation (`T20.5`)

### 5.1 The sharded benchmark

`benchmarks/scale_250_sharded.sh` runs **250 applications / 2,500 resources** across **three
control-plane shards** (`--shard-id N --total-shards 3`, each with its own leader-election `Lease`),
generates the fleet with `ApplicationSet`s, enables the drift watcher, and soaks while committing to
Git and editing the cluster out-of-band. The measured numbers and the SLO table live in
[`docs/benchmarks/v2.0.md`](../benchmarks/v2.0.md).

The harness refuses to touch anything but a `kind-*` context, and it cleans up the fleet, the
namespaces and the controller processes on exit — including on `SIGINT`.

### 5.2 The fleet overview must not leak

`GET /api/v1/applications` is **already** filtered by the server to the projects the caller may see.
A dashboard is the classic place where that guarantee is undone — one `SUM` over "everything in the
cluster" and a restricted tenant learns another tenant's size. So the overview
(`apps/ferriscd-web/src/features/overview/`) computes **every** figure from the payload the server
returned, and nothing else: no cluster-wide constant, no second unscoped source, no "expected
total". The rollup functions are pure, which makes the property testable — feed them one tenant's
slice and every bucket can only contain that slice.

Sharding is a capacity decision computed inside each replica from the object's own identity, so the
overview breaks the fleet down by the two dimensions the API *does* expose — destination cluster and
project — and leaves the per-shard numbers to the benchmark.

---

## 6. The through-line

Every `v2.0` feature follows the same three rules:

1. **Fail closed, and say why.** A refused policy, an unreachable provider, a composite rollback
   that cannot be decomposed — each is a terminal error with a message, never a silent pass.
2. **Never widen a tenant's view.** Multi-source adds repositories (each one policy-checked), the
   overview aggregates (only over what the caller may see), and the backup inventory lists names,
   never values.
3. **Keep the object the source of truth.** Gate progress, per-source revisions, drift decisions and
   audit records all live in `status`, so a restart, a requeue or a shard migration never loses or
   duplicates work.
