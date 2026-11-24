# Lesson 01: OpenGitOps, Server-Side Apply, and the Walking Skeleton

> **Phase:** 01 — Workspace Scaffold, CI, ADRs & Walking Skeleton (Milestone M0)  
> **Related ADRs:** [ADR-0001: Hybrid SSA Architecture](../adr/0001-hybrid-ssa-architecture.md) · [ADR-0002: Modular Monolith Workspace](../adr/0002-modular-monolith-workspace.md) · [ADR-0003: GKNN Inventory & `tracking-id`](../adr/0003-gknn-inventory-and-tracking-id.md)  
> **Code Walkthrough:** [`apply_file.rs`](../../crates/ferriscd-cli/src/commands/apply_file.rs) · [`ferriscd-engine/src/lib.rs`](../../crates/ferriscd-engine/src/lib.rs)

---

## 1. OpenGitOps Principles and How FerrisCD Maps Onto Them

The CNCF [OpenGitOps](https://opengitops.dev/) specification defines four foundational principles for GitOps Continuous Delivery. Every architectural decision in FerrisCD maps directly onto these four invariants:

| # | OpenGitOps Principle | Meaning | How FerrisCD Implements It |
|---|---|---|---|
| 1 | **Declarative** | A system managed by GitOps must have its desired state expressed declaratively. | Workloads live as declarative Kubernetes manifests (Plain YAML, Helm, Kustomize) referenced by declarative `Application` and `AppProject` CRDs (`ferriscd.io/v1alpha1`). No imperative `kubectl` scripts in pipelines. |
| 2 | **Versioned & Immutable** | Desired state is stored in a way that enforces immutability and versioning and retains a complete version history. | Git serves as the single source of truth; FerrisCD resolves branch/tag refs to immutable 40-character commit SHAs (`ResolvedRevision`) and records compact deployment metadata in `status.history` (capped at 20 entries). |
| 3 | **Pulled Automatically** | Software agents automatically pull the desired state declarations from the source. | Instead of CI pipelines pushing cluster credentials outward, the in-cluster `ferriscd-controller` pulls manifests from Git via pure-Rust `gix` into an isolated, symlink-sanitized `RepoCache` ([ADR-0002](../adr/0002-modular-monolith-workspace.md)). |
| 4 | **Continuously Reconciled** | Software agents continuously observe actual system state and attempt to apply the desired state. | FerrisCD computes live-vs-desired state via API-server `dryRun=All` Server-Side Apply, tracks managed objects with version-agnostic GKNN `status.inventory` ([ADR-0003](../adr/0003-gknn-inventory-and-tracking-id.md)), and reconciles drift using `Patch::Apply` ([ADR-0001](../adr/0001-hybrid-ssa-architecture.md)). |

In **Phase 01**, the `ferriscd apply-file` walking skeleton exercises the lowest layer of principle #1 and #4—taking a declarative YAML file and converging it onto the Kubernetes API server via **Server-Side Apply (SSA)**—before introducing Git acquisition, GKNN inventory, and the continuous controller loop in later phases.

---

## 2. Client-Side Apply (CSA) vs. Server-Side Apply (SSA)

### Why Legacy Client-Side Apply Breaks Down

Classic `kubectl apply` (Client-Side Apply, or CSA) stores a full JSON snapshot of the last applied manifest inside an annotation on the live object:

```text
metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]
```

When `kubectl apply` runs again, the *client* fetches the live object, reads `last-applied-configuration`, and computes a **client-side 3-way strategic merge patch** against the new manifest. This design breaks down in multi-controller GitOps environments for four reasons:

1. **Multi-controller ownership collisions:** Kubernetes clusters routinely have multiple actors editing the same resource—for example, a HorizontalPodAutoscaler (HPA) updating `spec.replicas`, a mutating admission webhook injecting sidecar containers or default security contexts, or an operator running an emergency `kubectl edit`. Because CSA only has a single `last-applied-configuration` blob and no per-field owner map, two controllers fighting over a field silently overwrite each other or leave orphaned patches behind.
2. **Client-side OpenAPI schema drift:** CSA requires the client (not the API server) to understand strategic-merge-patch list keys (`mergeKey`) and Kubernetes version-specific schema defaulting. Re-implementing Go's `k8s.io/apimachinery` strategic merge and OpenAPI defaulting in Rust would be fragile and lag behind cluster upgrades ([ADR-0001](../adr/0001-hybrid-ssa-architecture.md)).
3. **CRD blind spots:** Custom Resources lack Go strategic-merge struct tags, forcing CSA to fall back to coarse JSON merge semantics on nested arrays and maps.
4. **`etcd` annotation bloat:** Duplicating the entire manifest inside `last-applied-configuration` doubles metadata payload size and fails outright on large manifests approaching Kubernetes annotation limits.

### How Server-Side Apply Solves This

Kubernetes **Server-Side Apply** moves merge, defaulting, validation, and field ownership tracking directly into `kube-apiserver`:

- **`fieldManager`:** Every SSA request identifies the actor via a `fieldManager` query parameter (FerrisCD uses `"ferriscd"` from [`default_field_manager()`](../../crates/ferriscd-engine/src/lib.rs#L6-L8)).
- **`metadata.managedFields` (`FieldsV1` trie):** The API server maintains a compact per-field ownership trie in `metadata.managedFields`. Each entry records the `manager`, `operation` (`Apply` or `Update`), `apiVersion`, timestamp, and exact field paths owned by that manager (`f:data`, `f:metadata`, `f:labels`, etc.).
- **Explicit conflict semantics (`force: false`):** When a manager attempts to `Apply` a field currently owned by a *different* manager with a conflicting value, and `force=false`, the API server rejects the request with **HTTP `409 Conflict`** (`FieldManagerConflict`) rather than silently overwriting the other controller's state.
- **Zero-write idempotency:** If the submitted SSA payload matches the current server state and field ownership, `kube-apiserver` detects no effective change and leaves `metadata.resourceVersion` untouched—avoiding spurious `etcd` writes and informer watch storms.

---

## 3. Walking Skeleton Pipeline Walkthrough (`ferriscd apply-file`)

The Phase 01 walking skeleton lives in [`crates/ferriscd-cli/src/commands/apply_file.rs`](../../crates/ferriscd-cli/src/commands/apply_file.rs) and connects YAML parsing, dynamic API discovery, scope resolution, normalization, and SSA into a single end-to-end pipeline:

```text
YAML file
  │
  ▼  parse_and_prepare_manifest()
YAML 1.2 (serde_saphyr::from_str) ──► DynamicObject
  │   • validates apiVersion, kind, metadata.name
  │   • derives GroupVersionKind
  │   • strips top-level `.status` (object.data.as_object_mut().remove("status"))
  ▼
kube::Discovery::new(client).run()
  │   • resolves (ApiResource, ApiCapabilities) via discovery.resolve_gvk(&gvk)
  ▼  resolve_target_namespace()
Scope routing (ApiCapabilities.scope)
  ├── Scope::Namespaced ──► resolves --namespace / metadata.namespace / "default"
  │                         Api::<DynamicObject>::namespaced_with(client, ns, &ar)
  └── Scope::Cluster    ──► rejects any namespace; clears metadata.namespace
                            Api::<DynamicObject>::all_with(client, &ar)
  ▼  apply_patch_params()
PatchParams::apply("ferriscd")   // force defaults to false
  │
  ▼  api.patch(&name, &params, &Patch::Apply(&object))
Kubernetes API Server (SSA)
  └── prints GKNN, resourceVersion, and deduplicated managedFields managers
```

Key implementation details in [`apply_file.rs`](../../crates/ferriscd-cli/src/commands/apply_file.rs):

1. **YAML 1.2 parsing (`serde-saphyr`):** [`parse_and_prepare_manifest`](../../crates/ferriscd-cli/src/commands/apply_file.rs#L98-L132) parses manifests into `kube::api::DynamicObject` without needing compile-time Rust structs per Kubernetes resource type, keeping `ferriscd-crd` and `ferriscd-engine` free of `k8s-openapi` version lock-in ([ADR-0002](../adr/0002-modular-monolith-workspace.md)).
2. **`.status` stripping before apply:** Before sending any payload, [`parse_and_prepare_manifest`](../../crates/ferriscd-cli/src/commands/apply_file.rs#L127-L129) removes any top-level `status` map so declarative manifests exported from a cluster never pollute the desired SSA fieldset.
3. **Discovery-driven scope routing:** [`resolve_target_namespace`](../../crates/ferriscd-cli/src/commands/apply_file.rs#L136-L194) inspects `caps.scope` returned by `kube::Discovery`. Namespaced resources default to `"default"` if neither `--namespace` nor `metadata.namespace` is set (and error on mismatch); cluster-scoped resources (`Namespace`, `ClusterRole`, `CustomResourceDefinition`) automatically use `Api::all_with` and reject accidental `--namespace` flags.
4. **Safe `force: false` default:** [`apply_patch_params`](../../crates/ferriscd-cli/src/commands/apply_file.rs#L198-L200) calls `PatchParams::apply(ferriscd_engine::default_field_manager())`, whose default `force` flag is `false`.

---

## 4. Step-by-Step Reproducible `kind` Experiment

All outputs below were captured directly against the local **`kind-ferriscd-dev`** cluster running **Kubernetes `v1.35.8`**.

### Step 0: Create/Verify `kind-ferriscd-dev` and Enforce the Context Guard

First, ensure the local `kind-ferriscd-dev` cluster is up and verify that `kubectl` is pointed exclusively at a `kind-*` context before running any mutating command:

```bash
make kind-up
kubectl config current-context | grep -q '^kind-' || { echo "ABORT: non-kind context!"; exit 1; }
```

> **Safety Invariant:** Never run test or experiment `apply`/`patch`/`delete` commands unless `kubectl config current-context` begins with `kind-`.

---

### Step 1: First SSA Apply (Namespaced `ConfigMap`)

Apply [`examples/basic/configmap.yaml`](../../examples/basic/configmap.yaml) to the `default` namespace:

```bash
cargo run -p ferriscd-cli -- apply-file examples/basic/configmap.yaml --namespace default
```

**Observed output (`kind-ferriscd-dev`, v1.35.8):**

```text
applied: /ConfigMap/default/demo-config
resourceVersion: 859
managedFields managers: ferriscd
```

Notice the canonical GKNN format `/ConfigMap/default/demo-config` (empty `<group>` for core `v1` resources, followed by `Kind/Namespace/Name` as standardized in [ADR-0003](../adr/0003-gknn-inventory-and-tracking-id.md)), the initial `resourceVersion: 859`, and the single field manager `ferriscd`.

---

### Step 2: Second Idempotent Apply & `managedFields` Inspection

Re-run the exact same command without changing the manifest:

```bash
cargo run -p ferriscd-cli -- apply-file examples/basic/configmap.yaml --namespace default
```

**Observed output (`kind-ferriscd-dev`, v1.35.8):**

```text
applied: /ConfigMap/default/demo-config
resourceVersion: 859
managedFields managers: ferriscd
```

Look closely at `resourceVersion`: **`859` -> `859`**. Even though we issued a full HTTP `PATCH` request, Kubernetes recognized that the desired fields and field ownership were completely unchanged and performed **zero spurious `etcd` writes**.

Now inspect the live `ConfigMap` including its `managedFields` trie:

```bash
kubectl get cm demo-config -n default -o yaml --show-managed-fields
```

**Observed YAML (`kind-ferriscd-dev`, v1.35.8):**

```yaml
apiVersion: v1
data:
  APP_ENV: demo
  LOG_LEVEL: info
kind: ConfigMap
metadata:
  creationTimestamp: "2026-11-24T06:05:50Z"
  labels:
    app.kubernetes.io/name: demo-app
    app.kubernetes.io/part-of: ferriscd-demo
  managedFields:
  - apiVersion: v1
    fieldsType: FieldsV1
    fieldsV1:
      f:data:
        f:APP_ENV: {}
        f:LOG_LEVEL: {}
      f:metadata:
        f:labels:
          f:app.kubernetes.io/name: {}
          f:app.kubernetes.io/part-of: {}
    manager: ferriscd
    operation: Apply
    time: "2026-11-24T06:05:50Z"
  name: demo-config
  namespace: default
  resourceVersion: "859"
  uid: 3b63a636-ba7c-4047-a32a-252d3aff82ec
```

Inside `metadata.managedFields`, `kube-apiserver` recorded a `FieldsV1` entry for `manager: ferriscd` (`operation: Apply`) claiming ownership of `f:data.f:APP_ENV`, `f:data.f:LOG_LEVEL`, and the two `f:metadata.f:labels` keys.

---

### Step 3: Cluster-Scoped Apply (`Namespace` via `Discovery`)

Next, apply [`examples/basic/namespace.yaml`](../../examples/basic/namespace.yaml) without passing `--namespace`:

```bash
cargo run -p ferriscd-cli -- apply-file examples/basic/namespace.yaml
```

**Observed output (`kind-ferriscd-dev`, v1.35.8):**

```text
applied: /Namespace//ferriscd-demo
resourceVersion: 861
managedFields managers: ferriscd
```

`kube::Discovery` automatically identifies `v1/Namespace` as `Scope::Cluster`, routes the request through `Api::<DynamicObject>::all_with`, and formats the GKNN with an empty namespace segment (`/Namespace//ferriscd-demo`).

---

### Step 4: Triggering a Real SSA Field Conflict

Now simulate an out-of-band human edit on `demo-config` that changes `data.LOG_LEVEL` from `"info"` to `"debug"` using the `kubectl-edit` field manager:

```bash
kubectl patch cm demo-config -n default --field-manager=kubectl-edit --type=merge -p '{"data":{"LOG_LEVEL":"debug"}}'
```

*(Note: Running `kubectl edit cm demo-config -n default` interactively and changing `LOG_LEVEL: info` to `LOG_LEVEL: debug` creates the exact same `manager: kubectl-edit` + `operation: Update` ownership entry on the API server; `--field-manager=kubectl-edit` reproduces it deterministically in scripts.)*

Inspect `managedFields` again to see how Kubernetes splits field ownership between the two actors:

```bash
kubectl get cm demo-config -n default -o yaml --show-managed-fields
```

**Observed `metadata` YAML (`kind-ferriscd-dev`, v1.35.8):**

```yaml
metadata:
  managedFields:
  - apiVersion: v1
    fieldsType: FieldsV1
    fieldsV1:
      f:data:
        f:APP_ENV: {}
      f:metadata:
        f:labels:
          f:app.kubernetes.io/name: {}
          f:app.kubernetes.io/part-of: {}
    manager: ferriscd
    operation: Apply
    time: "2026-11-24T06:05:50Z"
  - apiVersion: v1
    fieldsType: FieldsV1
    fieldsV1:
      f:data:
        f:LOG_LEVEL: {}
    manager: kubectl-edit
    operation: Update
    time: "2026-11-24T06:05:50Z"
  resourceVersion: "864"
```

Notice the ownership split:
- **`ferriscd` (`operation: Apply`)** still owns `f:data.f:APP_ENV` and `f:metadata.f:labels`.
- **`kubectl-edit` (`operation: Update`)** now owns `f:data.f:LOG_LEVEL`, and `resourceVersion` bumped to `"864"`.

Now re-run `ferriscd apply-file` to reconcile Git state back onto the `ConfigMap`:

```bash
cargo run -p ferriscd-cli -- apply-file examples/basic/configmap.yaml --namespace default
```

**Observed error output (`kind-ferriscd-dev`, v1.35.8):**

```text
Error: server-side apply failed for /ConfigMap/default/demo-config

Caused by:
    0: ApiError: Apply failed with 1 conflict: conflict with "kubectl-edit" using v1: .data.LOG_LEVEL: Conflict (Status { status: Some(Failure), code: 409, message: "Apply failed with 1 conflict: conflict with \"kubectl-edit\" using v1: .data.LOG_LEVEL", ..., reason: "Conflict", details: Some(StatusDetails { ..., causes: [StatusCause { reason: "FieldManagerConflict", message: "conflict with \"kubectl-edit\" using v1", field: ".data.LOG_LEVEL" }], retry_after_seconds: 0 }) })
    1: Apply failed with 1 conflict: conflict with "kubectl-edit" using v1: .data.LOG_LEVEL: Conflict
```

Because `force` is `false`, `kube-apiserver` refuses to let `ferriscd` overwrite `.data.LOG_LEVEL` while `kubectl-edit` owns it and returns **HTTP `409 Conflict`** with structured `StatusCause { reason: "FieldManagerConflict", field: ".data.LOG_LEVEL" }`.

---

### Step 5: Why `serverSideForce: false` Is FerrisCD's Safe Default

If FerrisCD blindly passed `force: true` on every `Patch::Apply`, the conflict in Step 4 would vanish—but at a dangerous cost:
- **HPA / VPA thrashing:** If a `Deployment` in Git sets `spec.replicas: 2` while an HPA scales the workload to `10` (`manager: kube-controller-manager` / `horizontal-pod-autoscaler`), `force: true` would repeatedly scale production traffic down to `2` on every sync.
- **Admission webhook & operator overrides:** Mutating webhooks and operators that legitimately manage injected fields or annotations would have their changes silently clobbered.

Instead, as designed in [ADR-0001](../adr/0001-hybrid-ssa-architecture.md):
1. **Default safety (`serverSideForce: false`):** Never silently steal field ownership from other managers.
2. **Structured conflict reporting (Phase 07/08):** The `SsaDiffEngine` and `SyncEngine` parse `409 Conflict` (`FieldManagerConflict`) responses into structured `FieldConflict` diagnostics surfaced on `Application.status`, showing operators the exact conflicting manager (e.g., `"kubectl-edit"` or `"kubectl-client-side-apply"`) and field path (`.data.LOG_LEVEL`).
3. **Scoped brownfield adoption (`syncOptions.takeoverFieldManagers`):** For brownfield migrations (such as adopting resources previously applied by `kubectl-client-side-apply` or Helm), operators can explicitly opt into taking over specific named field managers rather than turning on a blanket `force: true`.

---

### Step 6: Cleanup

Remove the experiment resources from `kind-ferriscd-dev`:

```bash
kubectl delete cm demo-config -n default --ignore-not-found && kubectl delete ns ferriscd-demo --ignore-not-found
```
