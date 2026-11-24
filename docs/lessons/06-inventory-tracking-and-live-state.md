# Lesson 06 — Inventory, `tracking-id`, and Union Live State

> Phase 06 turns FerrisCD from a one-shot applier into a controller: an `Application` CR is
> watched, its Git source is re-read on every reconcile, and the result is applied with
> Server-Side Apply while a **crash-safe inventory** lives in `status.inventory`.
>
> All code references below are to `crates/ferriscd-controller/src/` (`live_state.rs`,
> `sync.rs`, `reconcile.rs`) and `crates/ferriscd-engine/src/inventory/`. The live `kind`
> walkthrough at the end is **not** executed by `make gate`; it is marked *pending* and must be
> run manually. **`v0.2` is not declared complete until the `#[ignore]`d live test has run on
> `kind`** (see §8) — hermetic tests cannot prove the union fetch against a real API server.

---

## 1. Why a `desired`-only reconcile is a trap

The naive loop is: read Git, apply everything. It has three fatal holes.

| Hole | Symptom | FerrisCD fix |
|---|---|---|
| **Trap T1** — a resource deleted from Git is invisible | the live object is never pruned and leaks forever | fetch `desired ∪ prev_inventory`, not `desired` |
| **Finding C1** — a partial apply drops state | a create that succeeded but was not recorded becomes an untracked orphan | `next_inventory = (prev \ pruned_ok) ∪ applied_ok`, persisted even on failure |
| **Finding C2** — API upgrades self-prune | `v1beta1` → `v1` looks like a different object | identity is GKNN, never GVKNN |
| **Trap T10** — two apps fight over one object | infinite apply/prune war | `ferriscd.io/tracking-id` ownership verification |

Everything in this phase exists to close those four holes with a *state machine that is safe
to kill at any instruction*: the only durable state is the `Application` status in `etcd`.

---

## 2. Identity: GKNN, never GVKNN

`ferriscd_engine::manifest::ResourceKey` is `Group + Kind + Namespace + Name`. The API
`version` is stored **only** as a non-key hint (`InventoryEntry::version`), so:

```text
key      = networking.k8s.io/Ingress/payments/web     # stable forever
version  = v1beta1 → v1                               # just a hint
```

Consequences that the fetcher relies on:

* `to_fetch`/`orphans` never see an upgrade as a change, so an upgrade produces **zero**
  orphans (unit-tested in `inventory::tests::version_upgrade_updates_the_hint_with_zero_orphans`).
* Serialized `/status` keys are byte-stable, so a no-op reconcile produces no diff and the
  composite watch predicate sees no change (`controller::predicate`).
* When only a key is available (e.g. deleting an orphan), the reader resolves the *kind* and
  reads the object through whatever version the cluster serves
  (`DiscoveryCache::resolve_kind`).

---

## 3. Ownership: the `tracking-id` marker

```text
<app-ns>/<app-name>:<group>/<kind>:<res-ns>/<res-name>
ferriscd-system/payments:apps/Deployment:payments/api
ferriscd-system/platform:rbac.authorization.k8s.io/ClusterRole:/ferriscd-admin
```

`inventory::tracking::classify_ownership` returns exactly three states:

| State | Meaning | FerrisCD behaviour |
|---|---|---|
| `OwnedBySelf` | the marker equals the expected value | apply, and (with `prune: true`) delete |
| `Unmanaged` | no/blank marker | apply; real field conflicts surface as SSA `409` |
| `OwnedByForeign(id)` | a different marker, **including malformed values** | never apply, never delete |

The comparison is a byte comparison. A value that merely *looks* like ours (extra whitespace,
version segment) is foreign, never adopted. `stamp_tracking_id` runs **after** scope
normalization because the marker is rendered from the final GKNN key, and it skips lifecycle
hooks so nothing created imperatively can ever look prunable.

The whole bundle is checked before the first `Patch`: `sync::reject_foreign_ownership` fails the
reconcile with the offending keys listed, so a half-applied sync can never start a fight.

---

## 4. Union live fetch (`live_state.rs`)

```text
to_fetch = desired_keys ∪ prev_inventory_keys          # inventory::to_fetch, sorted
```

`ClusterStateReader::fetch_live` reads them with `futures::stream::iter(..).buffer_unordered(16)`
(`LIVE_FETCH_CONCURRENCY`), de-duplicates by `ResourceKey`, and returns a `BTreeMap` so two
passes over the same cluster are byte-identical. Every fetch is a plain async `kube` GET, so
**no blocking I/O ever runs on a Tokio worker**: the only `spawn_blocking` in the wired pipeline
wraps manifest file I/O and YAML parsing, and the repo/git layer does its own `spawn_blocking`
internally. The invariant is "no blocking I/O on Tokio workers", not "one `spawn_blocking`".

Classification (`LiveState`):

| Variant | Trigger | Sync consequence |
|---|---|---|
| `Present(obj, ownership)` | `200` | diff/apply; ownership decides |
| `Missing` | `404`/`410` on a namespaced/all GET | create it; for an orphan it counts as a confirmed prune |
| `DeferredPendingCrd` | GVK absent from discovery **and** a `CustomResourceDefinition` in `desired` defines it | requeue (never fail) |
| `DeferredPendingNamespace` | `404` **and** the object's namespace is absent **and** a `Namespace` manifest in the bundle declares it | requeue (never fail) |
| `OrphanGvkGone` | an orphan whose kind no longer exists (its CRD was deleted) | treat as already pruned |

Two details that matter more than they look:

* **`410 Gone` is `404`.** A CRD-driven kind can start answering `410` after deletion; treating
  it as an error would wedge a reconcile on a resource that is definitionally gone.
* **The namespace is probed before deferring.** Deferring on "the bundle declares this
  Namespace" alone would be a self-heal bug: a ConfigMap deleted by hand *inside an existing*
  namespace would be classified "pending namespace" and never re-created. `fetch_live`
  therefore checks `namespace_exists` and only defers when the namespace is genuinely absent.
  The verdict is **memoized for the pass** (`NamespaceVerdicts`), so N keys that `404` in the
  same fresh namespace cost exactly one `Namespace` GET instead of N; the cache is dropped at
  the end of the pass, so a namespace created by this very sync is re-probed next time.

`syncOptions.createNamespace` is **not** honoured: `v0.2` has no namespace creator, so the
option is rejected outright by the pipeline (see §5). A namespace is "ours to wait for" only
when a `Namespace` manifest is part of the same bundle; on-demand creation is `T08.3`.

Nothing else is swallowed: `5xx`, `403`, transport failures and discovery outages become a
typed `LiveStateError` with an `is_retryable()` verdict, and any `404`/`410` surfaced by the
source is normalised to absence defensively.

---

## 5. The wired `v0.2` pipeline (`sync.rs`)

`InventorySyncPipeline` implements the Phase 05 `SyncPipeline` seam:

```text
validate spec (destination.cluster == in-cluster; spec.validate())
  → reject syncOptions.createNamespace (v0.2 never creates a namespace ⇒ T08.3)
  → resolve revision (RepoCache/GixGitClient, url policy enforced)
  → checkout + load/parse/normalize manifests            [spawn_blocking]
  → tier sort (Namespace → CRD → RBAC/ConfigMap → rest)
  → reject generateName / lifecycle hooks (unsupported)
  → collect in-bundle CRDs + Namespace names
  → DiscoveryCache::ensure_fresh()                       (trap T6)
  → normalize_scopes(...) + duplicate-GKNN check
  → stamp_tracking_id(...)
  → reject an empty desired set over a non-empty inventory (unless opted in)
  → plan_fetch(desired, prev_inventory) → ClusterStateReader::fetch_live
  → reject OwnedByForeign                                (trap guard, before any mutation)
  → ordered SSA apply (Patch::Apply, field manager "ferriscd", force=false)
  → minimal prune (only with automated.prune, only OwnedBySelf, re-checked before delete)
  → next_inventory(prev, applied_ok, pruned_ok) + status.sync
```

Safety decisions worth calling out:

* **`force: false` always.** A `409` field conflict is information, not noise: it tells the
  operator another manager owns a field (trap T5). `serverSideForce` is honoured in Phase 07; in
  v0.2 it is logged and ignored rather than silently weakening the guarantee. `PatchParams` is
  built by one helper (`sync::apply_patch_params`) whose `force`/`field_manager` are unit-tested
  against `ferriscd_engine::default_field_manager()`.
* **`createNamespace: true` is rejected, not ignored.** `v0.2` has no namespace creator, so
  honouring the flag would classify every key of the missing namespace as
  `DeferredPendingNamespace` and requeue every 10 s forever — a livelock with no error surface.
  The pipeline therefore fails the pass with `Invalid` on the *first* pass and an actionable
  message ("declare the Namespace in Git or create it manually"); on-demand creation lands with
  `pre_create_namespace` in `T08.2`/`T08.3`.
* **An empty desired set cannot erase the inventory by accident.** If `desired` is empty while
  `status.inventory` still has entries (a wrong `spec.source.git.path`, an emptied repository),
  the pass fails terminally instead of pruning everything. `FERRISCD_ALLOW_EMPTY_DESIRED=1` is
  the explicit opt-in for the (rare) intentional "delete everything" commit.
* **Deferred ≠ error.** A resource pending on a CRD or namespace keeps `Ready=True` with reason
  `PendingDependencies` and requeues after `PENDING_REQUEUE` (10 s) instead of `Ready=False`.
  `sync.status` is `OutOfSync` and `lastSyncedRevision` is *not* advanced, so "synced" always
  means "the whole desired set is applied".
* **Prune is opt-in and narrow.** Only `spec.syncPolicy.automated.prune`, only objects whose
  live `tracking-id` is ours, never `CustomResourceDefinition`/`Namespace` unless
  `pruneCRDs`/`pruneNamespaces` opt in, and `ferriscd.io/prune: "false"` opts a single resource
  out. Deletion order is reverse key order — the wave-ordered planner is `T08.1`/`T08.2`, and
  the dedicated ownership-verified pruner is `T08.5`.
* **Ownership is re-checked immediately before `Delete`.** The pass-level live read can be stale
  (another `Application` may adopt the object, or it may vanish). The pruner re-`GET`s the object,
  re-runs `classify_ownership`, and skips the delete on anything that is no longer
  `OwnedBySelf`; a `404`/`410` in that window still counts as a confirmed prune.
* **Stuck orphans are visible.** The `Ready=True` message ends with
  `; N orphan(s) retained (not owned, not prunable, or still pending)` whenever a prune pass left
  orphans behind, so "prune did nothing" is distinguishable from "there was nothing to prune".
* **`in-cluster` only.** A non-`in-cluster` `spec.destination.cluster` is rejected instead of
  silently applying to the wrong cluster; remote destinations need credentials (Phase 12).

### Crash-safe status (`reconcile.rs`)

`ApplyOutcome` now carries `inventory` and `sync`, and `apply_once` writes them **only when the
pipeline reported them** (so `UnwiredSyncPipeline` and any future partial pass cannot clear
state owned by another phase). `merge_sync_state` preserves `lastSyncedRevision`,
`lastSyncedSpecHash` and `lastSyncedAt` when the pass did not refresh them.

A mid-sync failure returns `ReconcileError::PartialSync { inventory, revision, .. }`. That is
the whole point of Finding C1: the reconcile still fails (`Ready=False`, retryable backoff), but
`apply_once` persists the inventory that is already true, so the created resource is never
forgotten and a later `prune: true` pass can still clean it up.

---

## 6. Local repositories are an explicit, opt-in policy

`RepoUrlPolicy::Production` (the default) accepts only `https://`, `ssh://` and SCP-style SSH.
`file://` URLs and bare local paths are accepted **only** under
`RepoUrlPolicy::AllowLocal`, which must be requested on purpose:

```bash
# local demo / integration test only
cargo run -p ferriscd-cli -- controller --allow-local-repos
```

`ferriscd_controller::RunOptions { allow_local_repos: false, .. }` is the production default,
`InventorySyncPipeline::with_url_policy(..)` defaults to `Production`, and the controller logs a
warning when local repositories are enabled. A misconfigured `Application` can therefore never
read the controller pod's filesystem by accident.

---

## 7. Deliberate `v0.2` limits (read before filing a bug)

| Concern | `v0.2` behaviour | Arrives |
|---|---|---|
| Dry-run diff / `ignoreDifferences` | not implemented: every reconcile re-applies the full set | `T07.x` |
| `serverSideForce` | logged and ignored (`force=false` always) | `T07.x` |
| Manual-only sync (`automated: None`) | not treated as "report drift only" yet | `T07.x` |
| `lastSyncedSpecHash` | not written (needs the sync-decision gate, finding H7) | `T07.x` |
| `syncOptions.createNamespace: true` | **rejected** with `Invalid` on the first pass: nothing creates namespaces yet, so honouring it would requeue forever | `T08.2`/`T08.3` (`pre_create_namespace`) |
| Waves / hooks | `generateName` and `ferriscd.io/hook` manifests are rejected with an actionable message | `T10.x` |
| CRD + CR in one bundle | CRD applies now, CR is `DeferredPendingCrd` and lands one requeue later (no `Established` wait yet) | `T08.3` |
| Prune ordering | reverse key order, no hook teardown | `T08.1` (reverse prune order), `T08.2` (`SyncPlan`) |
| Prune execution | inline in `sync.rs`, re-verified before each delete | `T08.5` (dedicated safe pruner) |
| Destination clusters / credentials | `in-cluster` + anonymous Git only | `T12.x` |
| Health aggregation | `status.health` untouched by the pipeline | Phase 09 |

---

## 8. Manual `kind` walkthrough — **PENDING (not yet executed)**

Everything below must be run by hand against `kind-ferriscd-dev`. There is no recorded output
in this repository yet, and nothing here is asserted by CI.

**`v0.2` is therefore not declared complete.** The milestone closes only when
`make test-integration` (the `#[ignore]`d live test in `tests/integration/v0_2_controller.rs`)
has actually run on `kind` and passed; it is the only proof that the union fetch classifies a
Git-removed object as `OwnedBySelf` against a real API server. Expected assertions of that test
(no invented output — check the run for exactly these):

1. `status.sync.revision` and `status.inventory` are populated for the seeded resources, and
   `spec.requeueAfterSeconds` reconciles a second commit without touching the `Application`.
2. The ConfigMap that was removed from Git is still live and still carries
   `ferriscd-system/payments:/ConfigMap:<ns>/removed-later`, and it is still listed in
   `status.inventory` while prune is off.
3. After `spec.syncPolicy.automated.prune` is enabled, that ConfigMap disappears (and leaves
   `status.inventory`), while the still-desired ConfigMap stays live and tracked, and the
   `Application` stays `Ready=True`.

```bash
# 0. cluster + CRDs
make kind-up
kubectl apply -f deploy/crds
kubectl create namespace ferriscd-system --dry-run=client -o yaml | kubectl apply -f -

# 1. a local Git fixture with two ConfigMaps and a Namespace
export DEMO=$(mktemp -d)
mkdir -p "$DEMO/repo" && cd "$DEMO/repo"
cat > namespace.yaml <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: ferriscd-demo
EOF
cat > one.yaml <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: one
data: { key: value }
EOF
cat > two.yaml <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: two
data: { key: value }
EOF
git init --initial-branch=main . && git add . \
  && git -c user.name=demo -c user.email=demo@example.com commit -m "seed"
git rev-parse HEAD

# 2. run the controller (local repos must be enabled explicitly)
cd -
cargo run -p ferriscd-cli -- controller --allow-local-repos --namespace ferriscd-system

# 3. in a second shell, create the Application
kubectl apply -f - <<EOF
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: demo
  namespace: ferriscd-system
spec:
  source:
    git:
      repoURL: $DEMO/repo
      targetRevision: main
      path: .
  destination:
    cluster: in-cluster
    namespace: ferriscd-demo
  requeueAfterSeconds: 15
EOF

# 4. observe the first sync
kubectl get cm -n ferriscd-demo
kubectl get application demo -n ferriscd-system -o jsonpath='{.status.sync.revision}{"\n"}'
kubectl get application demo -n ferriscd-system -o jsonpath='{range .status.inventory[*]}{.key}{"\n"}{end}'
kubectl get cm two -n ferriscd-demo -o jsonpath='{.metadata.annotations.ferriscd\.io/tracking-id}{"\n"}'
#   expect: /ConfigMap/ferriscd-demo/one, /ConfigMap/ferriscd-demo/two,
#           /Namespace//ferriscd-demo and
#           ferriscd-system/demo:/ConfigMap:ferriscd-demo/two

# 5. remove `two` from Git and confirm the union fetch keeps it
cd "$DEMO/repo" && rm two.yaml && git add --all \
  && git -c user.name=demo -c user.email=demo@example.com commit -m "remove two" \
  && git rev-parse HEAD
cd -
kubectl get application demo -n ferriscd-system -o jsonpath='{.status.sync.revision}{"\n"}'   # new SHA
kubectl get cm two -n ferriscd-demo          # still present: prune is off
kubectl get application demo -n ferriscd-system -o jsonpath='{range .status.inventory[*]}{.key}{"\n"}{end}'
#   expect: /ConfigMap/ferriscd-demo/two is STILL listed (trap T1)

# 6. (optional) prove the ownership guard
kubectl annotate cm two -n ferriscd-demo ferriscd.io/tracking-id='other/repo:/ConfigMap:ferriscd-demo/two' --overwrite
#   restore `two.yaml` in Git and commit: the reconcile must now fail with
#   Ready=False / InvalidSpec and list the foreign owner, without patching anything.

# 7. cleanup
kubectl delete application demo -n ferriscd-system
kubectl delete namespace ferriscd-demo
make kind-down
```

**Status:** pending manual execution. Update this section with the observed `managedFields`,
inventory output and any surprises once the walkthrough has been run on `kind-ferriscd-dev`.

---

## 9. What is verified automatically

```bash
make gate                       # fmt + clippy + unit/integration tests (no cluster)
make test-integration           # the #[ignore]d live tests (requires kind-up)
```

Hermetic coverage (no cluster, no network, no `git`):

* every `LiveState` classification, including `410`, foreign ownership, a namespace that exists
  vs. one that does not, and `OrphanGvkGone`;
* bounded concurrency (exactly 16 in flight on a large set, never more) and de-duplication by
  `ResourceKey`;
* one namespace-existence probe per distinct namespace per pass (three keys in one fresh
  namespace ⇒ exactly one `Namespace` GET, and a fresh probe on the next pass);
* `ClusterStateReader::recheck` seeing a takeover that happened after the pass-level fetch;
* the wired pipeline end to end over `FakeGitClient` + scripted discovery/live cluster: tier
  ordering, tracking-id stamping, foreign-owner rejection **before** any mutation, partial
  inventory on failure, deferred CRD/namespace requeue, `createNamespace` rejection, the
  empty-desired guard, prune rails, the pre-delete ownership re-check, retained-orphan counts,
  cascade cleanup;
* `apply_once` persisting inventory/sync on both paths while preserving unrelated status fields.

Live coverage (`tests/integration/v0_2_controller.rs`, `#[ignore]`d, `kind-` context guarded):
apply two ConfigMaps from a local repository, remove one from Git, assert the removed object is
still live, still stamped and still in `status.inventory`, then enable
`syncPolicy.automated.prune` and assert that object is deleted (and drops out of the inventory)
while the still-desired ConfigMap survives. That deletion is the live proof of the union fetch
and the `OwnedBySelf` classification, because the object is no longer in Git at all.
