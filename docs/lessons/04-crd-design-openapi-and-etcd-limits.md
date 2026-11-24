# Lesson 04 — Designing CRDs in Rust: OpenAPI Schemas, `/status`, and the `etcd` Budget

> **Phase:** 04 · **Tasks:** `T04.1`–`T04.4` · **Artifacts:** `crates/ferriscd-crd/`,
> `deploy/crds/*.yaml`, `deploy/manifests/default-project.yaml`

FerrisCD stores all of its control state in Kubernetes itself: an `Application` custom
resource carries the desired state (`spec`), the observed state (`status`), the resource
inventory, and re-entrant operation progress. That makes the CRD schema a *safety
boundary*, not just a data definition. This lesson covers how the schemas are generated
from Rust, why the shape matters, and how `etcd` limits the status layout.

---

## 1. From Rust types to a structural OpenAPI schema

`kube::CustomResource` derives a `CustomResourceDefinition` from a plain Rust struct:

```rust
#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[kube(
    group = "ferriscd.io",
    version = "v1alpha1",
    kind = "Application",
    namespaced,
    status = "ApplicationStatus",
    printcolumn(name = "SYNC", type_ = "string", json_path = ".status.sync.status")
)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSpec { /* ... */ }
```

Two crates do the work:

1. `schemars` 1 derives a JSON Schema from the spec/status types (honouring `serde`
   attributes such as `rename`, `default`, `skip_serializing_if` and
   `#[schemars(range(min = 1, max = 20))]`).
2. `kube` rewrites that JSON Schema with `StructuralSchemaRewriter` so it satisfies
   Kubernetes' *structural schema* rules: tagged enums (`oneOf`) get their properties
   hoisted into a shared `properties` map with `oneOf: [{required: [...]}]`, `anyOf`
   variants of plain enums collapse into a single `enum`, `Option<T>` becomes
   `nullable: true` instead of `anyOf: [T, null]`, and `additionalProperties` from a
   flattened map becomes `x-kubernetes-preserve-unknown-fields`.

**Consequence for API design:** every Rust type must map cleanly onto OpenAPI.
`schemars` gives you `oneOf` from a Rust enum — Kubernetes accepts that only because
`kube` hoists it. A hand-written schema that nests `properties` *inside* `oneOf` branches
is rejected by the API server. This is why the renderer selection in FerrisCD is a Rust
enum (`RendererSpec::{Auto, PlainYaml, Kustomize, Helm}`) and not four independent
optional fields.

### `k8s-openapi` version features

`k8s-openapi` refuses to compile without a `v1_*` feature. The feature must be enabled by
the **final binary** (`ferriscd-cli`), never by a library crate: if both
`ferriscd-crd` and `ferriscd-cli` pinned versions, two features could be enabled at once,
which `k8s-openapi` does not support. Building `ferriscd-crd` on its own therefore needs
`K8S_OPENAPI_ENABLED_VERSION=1.35` — the workspace gate builds everything together, so the
binary's feature selection wins.

---

## 2. Making invalid states unrepresentable

The original design used flat booleans:

```yaml
syncPolicy:
  automated: false
  selfHeal: true   # ← contradictory, but perfectly valid YAML
```

FerrisCD models automation as an *optional struct* instead:

```rust
pub struct SyncPolicy {
    pub automated: Option<AutomatedSyncPolicy>, // { prune, selfHeal }
}
```

Now `automated: false` is a **type error**, so `selfHeal` can only exist when automation
does. There is no validation code to forget, no "invalid combination" branch to test, and
the generated schema documents the intent. The same idea governs:

- `revisionHistoryLimit` — bounded in the schema (`minimum: 1`, `maximum: 20`) *and* in
  `ApplicationSpec::validate()`, so the CLI/controller rejects out-of-range values offline
  with the exact error the API server would return online.
- `SyncOptions` — `pruneCRDs`, `pruneNamespaces`, and `serverSideForce` default to `false`
  in both `Default` and the serialized schema, so a partially written `syncOptions` block
  can never silently arm destructive behaviour.
- `InventoryEntry` — the key is a version-agnostic GKNN string
  (`<group>/<kind>/<namespace>/<name>`) and the API version is stored beside it as a
  non-key hint, so `v1beta1 → v1` upgrades never turn a live object into a "missing"
  orphan that gets self-pruned.

---

## 3. The `/status` subresource (Trap T2)

`#[kube(status = "ApplicationStatus")]` emits:

```yaml
subresources:
  status: {}
```

Without it, `kubectl apply`/`patch` on `Application` rewrites `spec`, and — more
importantly — the controller's `patch_status` call would be a **full-object update**. That
bumps `metadata.generation` on every reconcile, which trips generation-based watch
predicates into an infinite reconcile loop. `deploy/crds/applications.ferriscd.io.yaml`
is asserted to contain that stanza by a test, and `AppProject` gets the same treatment so
policy errors can be surfaced as conditions.

Printer columns make `kubectl get apps` readable:

```yaml
additionalPrinterColumns:
  - { name: SYNC,     type: string, jsonPath: .status.sync.status }
  - { name: HEALTH,   type: string, jsonPath: .status.health.status }
  - { name: REVISION, type: string, jsonPath: .status.sync.revision }
  - { name: AGE,      type: date,   jsonPath: .metadata.creationTimestamp }
```

`AGE` is computed by `kubectl` from a `type: date` column, so `metadata.creationTimestamp`
is the correct path — there is no "age" field on the object.

---

## 4. The `etcd` budget: 1.5 MiB, and why we aim much lower

The API server's hard limit per object is **1.5 MiB** (after which writes fail with
`etcdserver: request is too large`). Worse than the hard failure is the slow death: a
status blob that grows with the cluster makes every watch event, list call, and SSA patch
expensive, and an `Application` managing 500 resources would otherwise serialise a large
document on every reconcile.

FerrisCD's rules, all enforced by tests in `crates/ferriscd-crd/src/status.rs`:

| Budget | Limit | Why |
|---|---|---|
| `status.inventory` | one `{key, version}` per resource | A GKNN key is ~40–70 bytes; 500 resources ≈ 30 KiB |
| `status.history` | **hard cap 20** entries | Metadata only (`id`, `revision`, `deployedAt`) — never manifest content |
| `status.resources` | **cap 100** summaries, messages ≤ 200 chars | Overflow is counted in `resourcesOmitted` instead of silently truncated |
| Everything else | no rendered YAML, no diffs, no per-resource manifests | Diffs are recomputed on demand; the CR is a control object, not a cache |

The test `large_status_stays_under_etcd_budget` builds a status with 500 inventory
entries, 20 history entries, 100 resource summaries, and full sync/health blocks, then
asserts the serialized JSON is **< 100 KB** — 6 % of the hard limit, with room for a
~10× larger cluster before the design needs revisiting.

Two smaller but load-bearing details:

- `set_inventory` sorts by key and de-duplicates before storing, so an unchanged inventory
  produces a **byte-identical** status patch. Watch predicates and the API server both
  thank you.
- `set_condition` preserves `lastTransitionTime` whenever the condition `status` does not
  change. Refreshing the message on every reconcile must not look like a state transition
  (`kubectl wait --for=condition=Ready` and every alerting rule depend on this).

---

## 5. Hands-on experiment (`kind`, manual)

> **Status: pending manual verification.** These commands were not executed in CI because
> this task is hermetic-only. Before running them, assert the active context is a `kind`
> cluster — never touch a shared/non-`kind` cluster.

```bash
# 0. Safety gate: refuse to continue on a non-kind context.
kubectl config current-context | grep -q '^kind-' || { echo "ABORT: not a kind context"; exit 1; }

# 1. Install both CRDs (server-side apply so the CRD schema is authoritative).
make kind-up
kubectl apply --server-side -f deploy/crds/
kubectl get crd applications.ferriscd.io -o jsonpath='{.spec.versions[0].subresources}'; echo
# expect: {"status":{}}

# 2. The default AppProject is required before any Application can reconcile.
kubectl apply -f deploy/manifests/default-project.yaml
kubectl -n ferriscd-system get appprojects

# 3. Printer columns are registered on the CRD.
kubectl get crd applications.ferriscd.io \
  -o jsonpath='{range .spec.versions[0].additionalPrinterColumns[*]}{.name}={.jsonPath}{"\n"}{end}'
# SYNC=.status.sync.status
# HEALTH=.status.health.status
# REVISION=.status.sync.revision
# AGE=.metadata.creationTimestamp

# 4. OpenAPI validation rejects malformed specs with 422 (see §2 and §4).
kubectl apply -f - <<'YAML'
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata: { name: bad-limit, namespace: ferriscd-system }
spec:
  source:
    git: { repoURL: https://github.com/example/repo.git }
  destination: { namespace: payments }
  revisionHistoryLimit: 21        # schema maximum is 20
YAML
# expect: Error from server (Invalid): ... spec.revisionHistoryLimit: Invalid value: 21 ...
#         (reason: must be less than or equal to 20)

kubectl apply -f - <<'YAML'
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata: { name: bad-automation, namespace: ferriscd-system }
spec:
  source:
    git: { repoURL: https://github.com/example/repo.git }
  destination: { namespace: payments }
  syncPolicy:
    automated: false              # must be an object, not a boolean
    selfHeal: true
YAML
# expect: Error from server (Invalid): ... automated: Invalid value: "boolean": ...
```

```bash
# 5. Prove /status writes never bump metadata.generation.
kubectl apply -f - <<'YAML'
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata: { name: demo, namespace: ferriscd-system }
spec:
  source:
    git: { repoURL: https://github.com/example/repo.git }
  destination: { namespace: payments }
YAML

gen_before=$(kubectl -n ferriscd-system get app demo -o jsonpath='{.metadata.generation}')
# Patch ONLY the status subresource (what the controller does every reconcile).
kubectl -n ferriscd-system patch application demo --subresource=status --type=merge \
  -p '{"status":{"sync":{"status":"Synced","revision":"8f3a1c2"}}}'
gen_after=$(kubectl -n ferriscd-system get app demo -o jsonpath='{.metadata.generation}')

test "$gen_before" = "$gen_after" && echo "PASS: status subresource left generation at $gen_before"

# 6. Printer columns render.
kubectl -n ferriscd-system get apps
# NAME   SYNC     HEALTH   REVISION   AGE
# demo   Synced            8f3a1c2    5s
```

### What to look for

- `subresources: {"status":{}}` proves the schema is not silently a full-object patch.
- A `422` (not `400`) means the CRD **schema** rejected the object, i.e. the OpenAPI
  bounds are live, not just documentation.
- `generation` unchanged after a `/status` patch is the property that keeps Phase 05's
  watch predicate loop-free.
- If the status patch instead fails with `request is too large`, revisit §4: something
  manifest-sized has leaked into `status`.

---

## 6. Takeaways

1. Design the Rust types so the invalid YAML is unrepresentable — then the schema,
   the client, and the controller all agree by construction.
2. Never let the API server infer structure: `kube`'s structural rewriter needs Rust
   enums and plain structs, not hand-written `oneOf`/`properties` nesting.
3. `subresources.status: {}` + printer columns are not cosmetics; they decouple status
   writes from spec generation and make the CR operable with plain `kubectl`.
4. `etcd` gives you 1.5 MiB and no warnings; budget the status at 5–10 % of it and assert
   the budget in a test so the next feature cannot quietly blow it.
5. Generate CRD YAML from the Rust types (`ferriscd crd generate`) and **commit it**, with
   a drift test: a hand-edited manifest instantly diverges from the schema the controller
   compiles against.
