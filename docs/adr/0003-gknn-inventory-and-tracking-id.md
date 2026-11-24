# ADR-0003: Version-Agnostic GKNN Inventory & `tracking-id` Ownership Safety

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Because FerrisCD avoids external databases (ADR-0001), each `Application` records its managed resources in `status.inventory` to detect objects removed from Git (orphans) and clean them up during pruning or cascading deletion. Two classes of production failures arise if resource identity, inventory updates, and pruning rules are naive:

1. **API / CRD Version Upgrade Self-Pruning:** If `apiVersion` (e.g., `networking.k8s.io/v1beta1` vs. `v1`) is part of the `ResourceKey` equality/hash, upgrading a manifest's API version or a CRD's served version causes the controller to treat the existing object as an unreferenced `v1beta1` orphan and **delete the live production resource**.
2. **Crash-Unsafe Inventory & Over-Broad Pruning:**
   - Updating inventory with `applied_ok ∪ failed_prune_orphans` silently drops previously managed resources whose apply failed during a transient error, leaking permanent orphans.
   - Fetching only `desired` live objects makes resources deleted from Git invisible and unprunable.
   - Pruning without checking live ownership risks deleting pre-existing cluster objects or resources owned by another `Application`.
   - Auto-pruning `CustomResourceDefinition` or `Namespace` objects can cascade-delete all custom resources or an entire namespace from a single accidental commit.

## Decision

FerrisCD standardizes resource identity, inventory set arithmetic, and prune guards as follows:

1. **Version-Agnostic GKNN Identity (`ResourceKey`):**
   - Key `ResourceKey` (`Eq`, `Hash`, `Ord`) and `status.inventory` strictly on **Group + Kind + Namespace + Name (GKNN)**, formatted canonically as `<group>/<kind>/<ns>/<name>` (e.g., `apps/Deployment/payments/payment-api`, `/Service/payments/payment-api`, or `apiextensions.k8s.io/CustomResourceDefinition//widgets.example.io`).
   - Store `version` (e.g., `"v1"`) only as a **non-key hint** in `InventoryEntry { key, version }`.
2. **Union Live-State Discovery:**
   - Every reconcile computes `to_fetch = desired_gknn ∪ prev_inventory_gknn` so both desired objects and previously tracked orphans are inspected on the target cluster.
3. **Crash-Safe Inventory Formula:**
   - Compute the next persisted inventory strictly as:
     $$\text{next\_inventory} = (\text{prev\_inventory} \setminus \text{pruned\_ok}) \cup \text{applied\_ok}$$
   - Confirmed `404 NotFound` / `410 Gone` responses during prune count as `pruned_ok`. Failed applies remain in `prev_inventory` if previously tracked (never leaked); failed prunes remain in `prev_inventory` for retry on the next reconcile. Lifecycle hooks (e.g., `PreSync`/`PostSync` jobs) never enter permanent `status.inventory`.
4. **Live Ownership Verification (`ferriscd.io/tracking-id`):**
   - Stamp every applied resource with `metadata.annotations["ferriscd.io/tracking-id"]` binding it to the owning `Application` and GKNN.
   - Immediately before pruning (or cascading finalizer deletion), verify the live object's `tracking-id` (`OwnedBySelf`, `Unmanaged`, `OwnedByForeign`). Never prune `Unmanaged` or `OwnedByForeign` resources, nor any resource annotated `ferriscd.io/prune: "false"`.
5. **CRD & Namespace Prune Safety Rails:**
   - Never auto-prune `CustomResourceDefinition` or `Namespace` objects by default—even when `automated.prune: true`—unless explicitly opted in via `syncOptions.pruneCRDs: true` / `syncOptions.pruneNamespaces: true` (or explicit prune opt-in controls). Prune in reverse dependency tier order.

## Consequences

### Positive
- API version migrations (`v1beta1` -> `v1`) and CRD version graduations preserve resource identity seamlessly with zero self-pruning.
- Crash-safe across `SIGKILL`, partial apply failures, and partial prune failures without external transactions.
- Strong defense-in-depth against accidental deletion of unmanaged brownfield resources, foreign `Application` resources, CRDs, and Namespaces.
- Compact `InventoryEntry` representation keeps `Application.status` well below Kubernetes's 1.5 MiB `etcd` limit.

### Trade-offs & Mitigations
- **Stale `version` hints in inventory:** If a resource's preferred API version changes while it is orphaned, the stored `version` hint may lag behind the cluster. *Mitigation:* Resolve live objects through `DiscoveryCache` by GK rather than trusting the hint blindly.
- **Orphaned resources stay tracked on partial failure:** Until a failed apply or failed prune succeeds, the resource remains in `status.inventory`. *Mitigation:* Surface clear `OutOfSync`/`Degraded` conditions and retryable vs. terminal error classification so operators see exact status immediately.
- **Brownfield ownership adoption:** Pre-existing resources without `ferriscd.io/tracking-id` will not be pruned automatically. *Mitigation:* First successful SSA apply stamps `ferriscd.io/tracking-id` (and `syncOptions.takeoverFieldManagers` assists brownfield field migration).

## References

- [MASTER_PLAN.md](../MASTER_PLAN.md) — Sections 2.1, 2.2, 3 (ADR-003), 4.3, and 5
- [REVIEW_LOG.md](../REVIEW_LOG.md) — Findings P1-01, C1, C2, and H3
- [ADR-0001: Hybrid SSA Architecture](./0001-hybrid-ssa-architecture.md)
