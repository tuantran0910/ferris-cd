# Lesson 05 — Controller Runtime: Discovery, Predicates, Finalizers, and Scope

> Phase 05 builds the Kubernetes-native runtime around the pure logic from Phases 02–04:
> a refreshable discovery cache, a composite watch predicate, a finalizer gate with escape
> hatches, an always-update-status wrapper, cluster-aware scope normalization, and a
> drain-on-SIGTERM shutdown path.
>
> All code references below are to `crates/ferriscd-controller/src/`. The live `kind`
> checks are documented at the end and are **not** executed by `make gate`; treat them as
> manual acceptance steps.

---

## 1. What a controller actually is

A controller is a level-triggered loop:

```text
watch desired object -> enqueue key -> reconcile(key) -> write status/observed state
        ^                                                        |
        +------------------- watch event <-----------------------+
```

Two properties matter more than throughput:

1. **Level-triggered, not edge-triggered.** A reconcile must converge from whatever state
   it observes; it may run twice, or not at all, and the system still has to end up correct.
   This is why we reconcile an object identity, not an event.
2. **Every failure is visible.** A controller that returns an error and patches nothing
   leaves `kubectl describe` showing a stale, healthy-looking status. Phase 05 closes that
   hole (`reconcile::apply_once`, `reconcile::cleanup_once`).

The kube-rs `Controller` gives us a queue, bounded concurrency, requeue actions, and a
predicate hook. The rest is FerrisCD policy.

---

## 2. Discovery is a cache with an invalidation contract

Resolving `apiVersion`/`kind` on every reconcile hammers the API server; caching forever
breaks the moment a new CRD is installed. `discovery::DiscoveryCache` therefore keeps a
snapshot with:

| Concern | Implementation |
|---|---|
| Snapshot storage | `Arc<tokio::sync::RwLock<CachedDiscovery>>` |
| Freshness | TTL, default `DEFAULT_TTL` = 5 min |
| Forced refresh | `invalidate_and_refresh()` |
| Coalescing | `tokio::sync::Mutex` + generation counter: N concurrent misses cost **one** round trip |
| Server identity | `kube_version()` returns `gitVersion` (used later for Helm `--kube-version`) |
| Sync scope lookups | `ScopeLookup::scope_of(&GroupVersionKind)` indexes the snapshot, so scope normalization never `.await`s |

The generation counter is the subtle part. Every refresh publishes a new generation *after*
the snapshot is installed. `invalidate_and_refresh` captures the generation it observed,
then calls `refresh_since(seen)`:

```text
two concurrent invalidations, both observe generation G
  first  -> acquires gate, fetches, publishes G+1
  second -> acquires gate, sees generation G+1 != G, returns without fetching
```

This is why the unit test drives both calls with `tokio::join!` and a source that yields:
without the yield, the calls are sequential and both legitimately refresh.

**CRD + CR in one sync.** A bundle may install a `CustomResourceDefinition` and then apply
a custom resource of that kind. The discovery snapshot predates the CRD, so the controller
must call `invalidate_and_refresh()` after applying the CRD and before resolving the CR.
That is trap T6; the cache API exists to make the correct sequence cheap.

---

## 3. Why `predicates::generation` is a trap

`kube_runtime::predicates::generation` hashes only `metadata.generation`. The API server
does **not** bump generation for:

- adding or removing a finalizer,
- setting `metadata.deletionTimestamp`,
- changing an annotation such as `ferriscd.io/refresh`.

A generation-only predicate silently drops those events. The failure modes are exactly the
dangerous ones: a deleted `Application` never runs cleanup, and a manual refresh never
reconciles.

`predicate::composite_hash` hashes the fields FerrisCD reacts to:

```rust
// (metadata.generation, deletion_timestamp, finalizers,
//  annotations{refresh, operation, cascade-delete, force-delete})
```

Status-only writes are deliberately absent, so the always-update-status wrapper cannot
re-trigger itself. Labels and unrelated annotations are ignored as well.

The predicate is applied **before** the controller sees the stream
(`Controller::for_stream`, enabled by kube's `unstable-runtime` feature). Filtering after
enqueue would still spend a queue slot and a status-write comparison per status patch.

### The status-loop test

The unit test is the contract:

```text
patch only status                          -> false
bump generation                            -> true
add/remove a finalizer                     -> true
set/clear deletionTimestamp                -> true
change each control annotation             -> true
change an unrelated annotation/label       -> false
```

If someone later replaces the predicate with `predicates::generation`, the finalizer and
deletion tests fail immediately.

---

## 4. Retry classification, not blanket backoff

`controller::FailureClass` splits errors into:

- **Retryable** — network blips, API timeouts, 429/5xx. Exponential backoff from
  `RETRY_BASE_DELAY` (5 s), capped at `RETRY_MAX_DELAY` (180 s).
- **Terminal** — invalid spec, unknown kind, malformed revision. A long fixed
  `TERMINAL_DELAY` (600 s), so a broken `Application` cannot spin the queue.

The distinction is a policy decision, not an error-string hack: adapters convert their
errors to `ReconcileError`/`ControllerError`, and the controller asks
`FailureClass::of(..)`. New integrations must classify rather than default to retryable.
When in doubt, retryable is safer for availability but noisier; terminal is safer for the
queue but hides transient fixes behind a 10-minute wait.

---

## 5. Finalizers: crash-safe cleanup without wedging

A finalizer turns deletion into a two-step operation:

1. The API server sets `deletionTimestamp` and keeps the object while finalizers exist.
2. The controller runs cleanup, then removes the finalizer; the object disappears.

The dangerous failure is a finalizer that is never released. `reconcile.rs` encodes four
release rules:

| Situation | Decision |
|---|---|
| Target returns `404` / `410` / `NoMatchesForKind` | Already gone — release |
| Destination-cluster secret is missing | Nothing can be cleaned — release with a warning |
| `ferriscd.io/force-delete: "true"` | Operator escape hatch — release with a warning |
| `ferriscd.io/cascade-delete` absent/false | Orphan children (non-cascading default) |
| Any other cleanup error | Keep the finalizer; retry |

`cleanup_disposition` is a pure function over the error + annotations, which is what makes
the deadlock-prevention testable without a cluster.

### Always update status

Both branches patch `/status` before returning:

```text
Ok(outcome)  -> observedGeneration = generation, Ready=True,  reason = outcome.reason
Err(err)     -> observedGeneration = generation, Ready=False, reason = ...
```

Fields owned by other phases (`inventory`, `operationState`, history) are preserved: the
patch is a merge patch built from the current status, not a replacement. On the success
path a failed *status write* is itself an error — otherwise `observedGeneration` would
silently stop advancing while the controller reports success. On the apply-error path the
apply error is what drives the retry, so a failed status write is logged and the apply
error is returned.

Status messages are bounded with `bounded()` at `MAX_STATUS_MESSAGE_CHARS` **on a char
boundary** and end with `…`; a multi-byte codepoint is never split.

---

## 6. Scope normalization: the offline/online boundary

The manifest normalizer from Phase 03 deliberately refuses to guess whether a custom
resource is namespaced. That guess can only be made with cluster knowledge, so it happens
immediately before diff/apply in `scope.rs`:

1. Ask `DiscoveryCache` (live discovery) through `ScopeLookup`.
2. If unknown, inspect a `CustomResourceDefinition` in the **same bundle** matching
   `spec.group` + `spec.names.kind` (`in_bundle_crds`).
3. If still unknown, fail the bundle with `ScopeError::UnknownScope`.

Then:

- namespaced + missing `metadata.namespace` → inject `spec.destination.namespace` and update
  `ResourceKey.namespace`;
- namespaced + explicit namespace → preserve it (never overwrite);
- cluster-scoped → never inject; a non-empty namespace is a validation error by default
  (`ClusterNamespacePolicy::Error`), or is stripped only on explicit opt-in.

All resources are validated in a first pass before any mutation, so a bad resource cannot
leave the bundle half-normalized. This is the fix for finding H1: the offline normalizer
must not guess, and the online normalizer must not inject into `ClusterRole`,
`Namespace`, `CustomResourceDefinition`, or any cluster-scoped CR.

---

## 7. Graceful shutdown

Kubernetes sends `SIGTERM` and then, after the grace period, `SIGKILL`. A controller that
drops a `/status` patch mid-flight leaves stale state; a controller that never exits makes
rollouts slow.

`lib::shutdown_signal` resolves on `SIGINT` or `SIGTERM`. `controller::run` wires it into
`Controller::graceful_shutdown_on` and keeps draining the stream for up to
`ControllerConfig::drain_timeout` (`DEFAULT_DRAIN_TIMEOUT`). If the drain window expires,
`ShutdownError::DrainTimeout` is returned and the process exits non-zero — abandoned work
must not look like a clean shutdown.

The pure helper `await_drained(run, shutdown, timeout)` is unit-tested for all three
outcomes (completed before the signal, completed during the window, timed out), so the
policy is provable without sending real signals in CI.

### Log format

`FERRISCD_LOG_FORMAT=json|pretty|text|plain` selects the subscriber; unknown values are a
startup error rather than a silent fallback. `RUST_LOG` controls filtering. JSON output is
for log aggregation; pretty is the default for local development.

---

## 8. Live `kind` acceptance (manual, not in CI)

`make gate` is hermetic. These checks require `kind` and must not run against a real
cluster. Start with the guard:

```bash
kubectl config current-context   # must start with kind-
```

Suggested sequence:

1. **Discovery refresh**
   - Resolve `v1/ConfigMap` and `apps/v1/Deployment` through `DiscoveryCache`.
   - Install a test CRD, call `invalidate_and_refresh()`, resolve the new kind.
2. **Predicate**
   - Patch only `/status` on an `Application`; assert zero new reconciles (counter/log).
   - Set `ferriscd.io/refresh`; assert an immediate reconcile.
   - `kubectl delete application ...`; assert cleanup runs.
3. **Finalizer**
   - Point an `Application` at a broken repo URL; assert `Ready=False` with a non-empty
     message in `status.conditions`.
   - Delete it; assert the finalizer is removed and the object disappears.
   - Set `ferriscd.io/force-delete: "true"` with a failing cleanup; assert release.
4. **Scope**
   - A namespaced `Deployment` without a namespace gets `spec.destination.namespace`.
   - An explicit namespace is preserved.
   - A `ClusterRole` gets no namespace.
   - An in-bundle cluster-scoped CRD + CR resolves without discovery.

Record the observed output in the PR or a follow-up note; do not present expected output as
measured.

---

## 9. Limitations at the end of Phase 05

- The diff/sync pipeline is still `reconcile::UnwiredSyncPipeline`; applications report
  `Ready=False` rather than pretending to sync. Phases 07–08 supply the real pipeline.
- There is no leader election yet (Phase 13) and no metrics endpoint (Phase 15).
- The discovery snapshot is per-process; no cross-process coordination is attempted.
- The controller watches one namespace (`ferriscd-system` by default) to preserve tenant
  isolation; cluster-wide watches are a deliberate non-goal until multi-tenancy lands.

---

## Further reading

- `kube_runtime::Controller` docs: queueing, `Action`, `graceful_shutdown_on`.
- Kubernetes finalizers: deletion timestamp semantics and orphan vs cascading deletion.
- API discovery: aggregated discovery, `gitVersion`, and why CRDs change the resource map.
- SSA field ownership (Phase 08) builds on the scope decisions made here.
