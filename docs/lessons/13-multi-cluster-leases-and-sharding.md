# Lesson 13 — Multi-Cluster, Leases, and Deterministic Sharding

> Phase 13 is where a FerrisCD control plane stops being a single process talking to a single
> cluster. Two things change at once, and they pull in opposite directions: the controller now
> reaches **other people's clusters** (so every credential and every CA on that path becomes part of
> the trust boundary), and it now runs as **more than one replica** (so "who is allowed to write
> right now?" stops being a configuration question and becomes a distributed-systems one). Nothing
> here makes either problem disappear; it makes the set of things that can go wrong small, explicit,
> and observable.
>
> Code: `crates/ferriscd-controller/src/{cluster_manager,leader_election,sharding,controller}.rs`.
> Hermetic coverage: `cargo test -p ferriscd-controller --lib -- cluster_manager leader_election
> sharding controller` (kubeconfig and `Secret` parsing, TLS policy, handle invalidation,
> acquire/renew/lose/release, the monotonic-clock expiry rule, the 1,000-application shard
> partition, the stream-level shard filter).
> Live coverage: `tests/integration/v0_5_ha.rs` and `tests/integration/v0_5_enterprise.rs`
> (`#[ignore]`d, `kind-` guarded) — **not executed here** (see §7).

---

## 1. Kubeconfig trust boundaries

A `ferriscd.io/secret-type=cluster` `Secret` in the control-plane namespace is a **complete
credential for another cluster**, plus the CA that credential must be checked against. That makes it
the highest-value object in the namespace: whoever can write it can make the controller send every
manifest (and every impersonation header) to an API server of their choosing, or make it accept a
certificate they minted. Four rules follow, and all four are enforced in code rather than documented
as advice:

| Rule | Why it is not optional |
|---|---|
| A `Secret` is read by a **namespaced** `Api<Secret>` in the control-plane namespace only | otherwise a tenant could register a cluster from a namespace it owns, and the controller would trust it |
| `insecureSkipTLSVerify` / plaintext `http://` is refused unless `--allow-insecure-cluster-tls` | without verification, anything on the control-plane→workload path can read *and rewrite* every manifest FerrisCD applies, including the `Secret`s it creates |
| A `kubeconfig` in the `Secret` may not use `exec`, `auth-provider`, `proxy-url`, `tokenFile`, or certificate **paths** | those turn "the controller reads a credential" into "the controller runs a binary / reads a pod file" — a privilege escalation through a `Secret`, not a configuration convenience |
| `in-cluster` is reserved and cannot be re-registered | a `Secret` named `in-cluster` would silently shadow the controller's own identity, which is the one credential the operator never had to hand over |

The CA bundle is parsed strictly at seed time, so a placeholder fails immediately and loudly instead
of at the first reconcile. Changing a `Secret` rebuilds that cluster's client — connector, discovery
cache and every cached impersonated client — and deleting it removes the registration: a rotated
credential with a typo **invalidates** the previous one instead of leaving the revoked credential
alive.

The trust boundary has a second half that is easy to miss: the remote credential is only ever asked
to satisfy the *remote* request. `Application.status` and `ferriscd.io/finalizer` stay on the
control plane, so the remote cluster needs no FerrisCD CRDs at all — which is what makes it possible
to manage a cluster that does not run (and never will run) FerrisCD.

## 2. `Lease` internals: `resourceVersion`, renew, expiry, and skew

`coordination.k8s.io/v1` gives us exactly one primitive we need — a *compare-and-swap register with a
timestamp* — and writing the elector by hand (~300 lines, no third-party crate, finding H4) is worth
it only if the failure modes are understood:

**`spec.holderIdentity` + `metadata.resourceVersion` = mutual exclusion.** Acquisition and renewal are
`PUT`s carrying the `resourceVersion` that was just read. If anybody else wrote in between, the API
server answers `409 Conflict` and the write does **not** happen. That is the whole safety argument:
two replicas cannot both hold the lease, because the second write is rejected rather than merged. The
elector's response to a `409` is never "retry blindly" — it re-reads and *decides*: still me ⇒ adopt
the new `resourceVersion`; somebody else ⇒ leadership lost ([`HoldOutcome::Lost`]).

**`renewTime` = liveness, and expiry is judged from the reader's clock.** A standby sees
`renewTime + leaseDurationSeconds` in the past and takes over. Two traps live here:

* *`renew_interval` must be strictly less than `lease_duration / 3`.* A renewal that is merely
  "inside" the duration oscillates: one slow API call, and a *healthy* leader loses the lease. The
  configuration refuses to start otherwise (a third of 15 s is exactly 5 s, which is why the default
  renewal is 4 s).
* *Never compare another process's timestamp to your own wall clock to decide "how long ago".*
  Replicas' clocks drift; a leader whose clock runs *ahead* writes a `renewTime` in the future, a
  wall-clock comparison computes a **negative age**, and a dead leader can then never be replaced —
  the lease looks alive for the whole skew. FerrisCD therefore measures elapsed **local monotonic**
  time from the moment it observed the lease, and clamps a future `renewTime` to "renewed just now".
  The cost of the clamp is at most one lease duration of extra waiting; the cost of the naive
  comparison is an unrecoverable split brain.

**The leader also gives up before the standby can take over.** `lost_deadline = lease_duration -
renew_interval`: after that long without a successful renewal, the leader stops reconciling on its
own. Otherwise a leader whose API access is broken but whose process is healthy would keep applying
manifests right through the takeover window.

**`Lease` expiry is a *timeout*, not a membership protocol.** There is no gossip and no quorum: a
`SIGKILL`ed leader is replaced after `leaseDurationSeconds`, and the cluster needs NTP (or a cloud
time service) on the control-plane nodes. Raise the duration above the skew you are prepared to
tolerate; that is the trade — a longer lease is a slower failover, a shorter one is a failover that
can happen while the old leader still believes it leads.

**Graceful stop is not failure.** On `SIGTERM` the leader *releases*: `holderIdentity` cleared and
`leaseDurationSeconds: 1`. A standby then takes over on its next attempt instead of waiting out the
full duration. This is why the rolling update of a single-replica controller is a sub-second gap and
not a 15-second one — and why `SIGTERM` handling is part of the HA design, not an operational
afterthought.

## 3. Active/standby vs. sharding

| | Active/standby (`--leader-election`) | Sharding (`--shard-id` + `--total-shards`) |
|---|---|---|
| Reconciles per `Application` | exactly one leader, always | exactly one replica, by hash |
| Failover | lease expiry (`leaseDurationSeconds` + retry) | that **shard's** lease expiry; other shards are unaffected |
| Work distribution | 1 leader, N−1 idle | N leaders, each with a slice |
| Bottleneck | one process's CPU/IO at any fleet size | per-shard; add shards to add capacity |
| Failure blast radius | the whole fleet pauses until a standby takes over | one shard pauses; the rest keep reconciling |

They are not alternatives in FerrisCD — **sharding is per-shard leader election**. The reasons are
the two ways to get it wrong:

* Sharding alone (no lease): two replicas configured with the same `--shard-id` both reconcile that
  shard, which is the double-apply/racing-prune the `T13.2` lease exists to prevent. Nothing in the
  system can stop an operator from reusing an index — no membership list, no coordinator — so the
  only safe design is to make the lease mandatory.
* Sharding with *one* shared lease: exactly one replica leads, so replicas of the other shards stand
  by forever and **their `Application`s are never reconciled**. The controller looks healthy. This is
  the worst failure mode in the whole phase, which is why the combination is *refused* rather than
  warned about: sharding always derives `ferriscd-leader-shard-<id>`, and any other lease name is a
  startup error ([`ShardingConfigError::LeaseNameConflict`]).

So the deployable shape is `N` replicas × `--total-shards N` × distinct `--shard-id`, each holding its
own lease. Replicas of the *same* shard still compete for that shard's lease, so a duplicate index
costs an idle standby (wasteful, safe) rather than a double apply.

> **Migration is stop-then-start.** A mixed fleet — an unsharded replica holding
> `ferriscd-controller-leader` next to sharded replicas holding `ferriscd-leader-shard-<id>` — has
> **two independent leaders** over the same objects, because the leases do not exclude each other.
> Scale the old shape to zero (or release its lease) before starting the new one. A rolling update
> between the two shapes double-applies and races prunes; this is the failure the lease exists to
> prevent, and it cannot be detected from inside one process.

## 4. Deterministic sharding: the hash, and what it must never do

```text
shard = sha256("ferriscd/shard/v1" NUL namespace NUL name) % total_shards
```

* **Deterministic and stateless on purpose.** Every replica computes the same answer from the
  object's own identity, with no coordinator, no membership list, no rebalancing protocol. A restart,
  a rolling update or a rescheduled pod cannot change ownership, and there is no "who owns what"
  state to get out of sync.
* **The key layout is versioned and pinned.** The domain tag (`ferriscd/shard/v1`) and the NUL
  separators (Kubernetes names cannot contain a NUL, so `("a","b\0c")` cannot collide with
  `("a\0b","c")`) are part of the on-disk contract: changing them reshuffles every `Application` in a
  running fleet. A known-answer test pins the layout against an independently computed SHA-256, so a
  silent change fails in CI instead of in production.
* **The whole digest is reduced** (Horner's rule over all 64 hex digits), not a truncated prefix:
  modulo on a prefix is still uniform, but "one shard gets 8 bits and another gets 4" is the kind of
  detail that only shows up at 100 k `Application`s. The partition test asserts 1,000 synthetic
  `(namespace, name)` pairs are 100 % disjoint, cover every `Application` exactly once, and leave no
  shard empty for `N = 1, 3, 5` — and that the mapping is unchanged when the pairs are observed in a
  different order.
* **The filter runs on the watch stream, before the queue.** A shard filter inside the reconciler
  would still schedule the work (and back off, and requeue) for `Application`s this replica must never
  touch. The filter sits between `reflect` and the composite predicate, so a foreign `Application`
  costs one hash comparison. Watch *errors* always pass through: an `Err` item is not an
  `Application`, and swallowing it would hide a broken watch. The store keeps every object it listed
  — only the queue is sharded — so readiness and inventory reads do not depend on the shard count.
* **Sharding is a capacity decision, not rebalancing.** Changing `--total-shards` re-partitions every
  `Application` on the next watch event of every replica. That is *safe* (each object still has
  exactly one owner, and `ferriscd.io/tracking-id` ownership is untouched), but it is a fleet-wide
  restart, so the value belongs next to the replica count, templated once.
* **No dependency, no new crate.** The digest comes from the workspace's existing dependency-free
  FIPS 180-4 implementation (`ferriscd_engine::manifest::cache::sha256_hex`), already pinned by
  published known-answer vectors and already used for diff fingerprints. Sharding uses it as a
  *spreader*, never as a security primitive.

## 5. Remote impersonation RBAC

Impersonation composes badly with multi-cluster if the RBAC is assumed rather than stated, because
there are two API servers and two `ServiceAccount` namespaces in play:

| Where | What is needed | Why |
|---|---|---|
| Control plane | `users`, `groups`, `serviceaccounts` **`impersonate`** on the controller's `ClusterRole` | Kubernetes checks the impersonated `system:serviceaccount:<ns>:<name>` against `serviceaccounts`, and `Impersonate-Group` is a *separate* grant from `Impersonate-User` (finding H5: a group-only `RoleBinding` cannot be satisfied without it) |
| Control plane | the tenant `ServiceAccount`'s own RBAC in its destination namespace | impersonation only *narrows* the request; it never grants anything |
| Remote (`Secret` credential) | the same three `impersonate` verbs on the **remote** API server | the controller impersonates there with the remote connector, not the control-plane one |
| Remote | the remote destination namespace's `ServiceAccount` must exist, with its own RBAC | a tenant `Application` on a remote cluster is deployed as that identity there, never as the `Secret`'s credential |
| Remote | **no** FerrisCD permissions | `status` and the finalizer never leave the control plane |

A control-plane-owned `Application` (`spec.serviceAccountName` unset, in the control-plane namespace)
is deployed as the `Secret`'s credential and needs no impersonation at all — that is the case the
`v0_5_enterprise.rs` remote test pins. A *tenant* `Application` on a remote cluster needs every row of
the table above, and the project must list the remote `(cluster, namespace)` pair in
`spec.destinations` before the registry is even consulted, so a tenant cannot probe which clusters
exist.

`system:masters` is never impersonated, and a `ServiceAccount` that does not exist is a terminal
`InvalidSpec` — never a silent fallback to the controller's own identity (finding C8).

## 6. Verification performed

Run in this phase (`make gate`, no cluster required):

```text
cargo test -p ferriscd-controller --lib sharding      # 10 tests
cargo test -p ferriscd-controller --lib leader_election
cargo test -p ferriscd-controller --lib cluster_manager
cargo test -p ferriscd-controller --lib controller    # incl. the stream-level shard filter
cargo test -p ferriscd-cli                            # the sharding flags and their refusals
```

What they prove, specifically:

* **Shards.** 1,000 synthetic `(namespace, name)` pairs for `N = 1, 3, 5`: 100 % disjoint, every
  `Application` owned exactly once, no empty shard, and the mapping identical when the pairs are
  observed in a different order or computed twice. Known-answer vectors pin the key layout against an
  independently computed SHA-256. Invalid configurations (`--shard-id` without `--total-shards`, and
  vice versa, `--total-shards 0`, `--shard-id >= --total-shards`, non-numeric environment values) are
  rejected, and blank environment values mean "unset", never shard `0`.
* **Shard wiring.** A scripted watch delivers one owned and one foreign `Application`; the stream
  yields only the owned one, and the private store still reflects both. The assertion is
  ordering-based, not timeout-based: a filter placed after the queue would surface the foreign object
  first.
* **Per-shard leases.** `Sharding::new(i, n).lease_name()` is `ferriscd-leader-shard-<i>` and is a
  valid DNS subdomain for every index; `RunOptions::ha_plan` derives it, refuses sharding without
  leader election, and refuses the single-leader default (`ferriscd-controller-leader`) or any other
  name. The CLI rejects `--shard-id` together with `--leader-election-lease-name`, and its help text
  states the RBAC/lease rules.
* **Leases.** Acquire/renew/lose/release, `409` handling that re-reads instead of forcing a write, a
  live lease that is never stolen, takeover of an expired one (incrementing `leaseTransitions`), a
  graceful release that clears the holder and shortens the duration, a future `renewTime` that cannot
  block takeover, and the token that is cancelled the moment leadership ends.
* **Registry.** `Secret` parsing (bearer token / client certificate / kubeconfig), the strict TLS
  policy, the reserved `in-cluster` name, handle rebuild on change and removal on delete.

## 7. Live `kind` acceptance — **PENDING (not executed)**

None of the suites below has been executed for this phase. The commands are recorded so the run is
reproducible and so the pending state is auditable; no results are claimed.

```bash
# 1. Two clusters: a control plane and a workload cluster.
make kind-up                                     # kind-ferriscd-dev
kind create cluster --name ferriscd-workload     # kind-ferriscd-workload
kubectl config use-context kind-ferriscd-dev

# 2. CRDs, control-plane namespaces and the default project.
kubectl apply -f deploy/crds
kubectl create namespace ferriscd-system --dry-run=client -o yaml | kubectl apply -f -

# 3. The enterprise acceptance suite (T13.4): project namespace/kind rejection,
#    ServiceAccount impersonation through a group RoleBinding + a 403, remote
#    deploy/prune, and a 2-replica per-shard Lease failover.
cargo test -p ferriscd-controller --test v0_5_enterprise -- --ignored --test-threads=1

# 4. The focused suites (T12.2/T12.3/T12.4/T13.1/T13.2).
cargo test -p ferriscd-controller --test v0_5_ha -- --ignored --test-threads=1
cargo test -p ferriscd-controller --test v0_5_multi_tenancy -- --ignored
cargo test -p ferriscd-controller --test v0_5_repo_credentials -- --ignored

# 5. HA by hand: two controller processes on ONE shard, then a kill -9.
kubectl apply -f deploy/crds
ferriscd controller --leader-election --shard-id 0 --total-shards 2 & leader=$!
ferriscd controller --leader-election --shard-id 0 --total-shards 2 & standby=$!
kubectl -n ferriscd-system get lease ferriscd-leader-shard-0 \
  -o jsonpath='{.spec.holderIdentity}'                                   # exactly one holder
kill -9 "$leader"                                                        # the leader is gone
kubectl -n ferriscd-system get lease ferriscd-leader-shard-0 \
  -o jsonpath='{.spec.holderIdentity}'                                   # holder changes
kubectl -n ferriscd-system get lease ferriscd-leader-shard-0 \
  -o jsonpath='{.spec.leaseTransitions}'                                 # must have incremented
kill "$standby"

# 6. Sharding by hand: one replica per shard, one lease per shard.
for shard in 0 1; do
  ferriscd controller --leader-election --shard-id "$shard" --total-shards 2 &
done
kubectl -n ferriscd-system get leases | grep ferriscd-leader-shard   # one per shard
```

What the run must show, in the order the suite asserts it:

1. `Ready=False, reason=PolicyViolation` naming `spec.destinations` (and separately
   `spec.namespaceResourceWhitelist`), with nothing applied; the same project still authorizes a
   whitelisted kind into a listed namespace.
2. A tenant `Application` syncing **as** `system:serviceaccount:enterprise-app:deployer` through a
   group `RoleBinding`, and a `403` from the API server naming that identity for a destination the
   project permits but the tenant's RBAC does not.
3. The `ConfigMap` present on `kind-ferriscd-workload`, absent on the control plane, `/status` patched
   on the control plane, and the object pruned from the remote cluster on the next commit.
4. Exactly one leader on `ferriscd-leader-shard-0`, a takeover within `lease_duration + 2s` of the
   leader's last renewal, and an immediate hand-over on graceful release.

## 8. Limitations at the end of Phase 13

* **No rebalancing, no coordinator.** Sharding is a static hash partition: the fleet cannot grow or
  shrink shard counts without a restart, and a hot shard (an unlucky cluster of names) is not split
  further. Consistent hashing or a membership protocol would fix both, at the cost of the property
  that makes this design easy to trust — no shared state.
* **Two replicas of the same shard are indistinguishable from one intended standby.** Duplicate
  `--shard-id` is safe (the lease serialises them) but wasteful, and nothing warns about it.
* **A shard count change is a fleet-wide restart**, and during it some `Application`s are briefly
  owned by nobody. Ownership hand-off is safe because `ferriscd.io/tracking-id` is re-verified before
  every prune, but convergence is not instantaneous.
* **Lease timing assumptions are real assumptions.** Sub-second failover needs a lease duration close
  to the API server's write latency, which is exactly where clock skew and API-server hiccups start to
  matter. The shipped default (15 s lease, 4 s renewal) is deliberately boring.
* **The remote credential is only as narrow as the operator made it.** FerrisCD never *grants* it
  anything, but it also cannot shrink a `cluster-admin` kubeconfig pasted into a `Secret`. The
  impersonation path is the mechanism that bounds a *tenant*; the `Secret` still bounds the
  control-plane owner.
* **Repository credentials and cluster registrations are control-plane-wide** (one namespace, one
  set). Per-tenant registries are a Phase 14+ question, and the namespaced-`Api` design means the
  answer will be "a second store", never "a cluster-wide watch".

## Further reading

* Kubernetes, [Leases](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/lease-v1/)
  and the [coordinated leader election KEP](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/5000-coordinated-leader-election).
* `client-go`'s `leaderelection` package — the reference implementation of the renew/expiry/skew
  rules in §2.
* FIPS 180-4 §6.2 (SHA-256 padding and compression), which the workspace's dependency-free
  implementation follows, together with the NIST known-answer vectors its tests pin.
* Lesson 05 (watch predicates and finalizers) for why the shard filter belongs on the stream, and
  lesson 12 (impersonation and the confused deputy) for the identity half of §5.
