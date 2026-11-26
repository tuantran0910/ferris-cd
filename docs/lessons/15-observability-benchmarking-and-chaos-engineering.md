# Lesson 15 — Observability, Scale Benchmarking & Chaos Engineering

> A GitOps controller that silently drops reconciles, floods `etcd` with `Warning` events, leaks
> worktrees over a weekend, or wipes a production namespace during a 90-second Git outage is not
> ready for `v1.0`. Phase 15 makes FerrisCD **operationally transparent** and **fault-tested**:
> typed low-cardinality Prometheus metrics (`T15.1`), opt-in OpenTelemetry OTLP traces and
> rate-limited Kubernetes Events (`T15.2`), a repeatable 50-application / 500-resource scale & soak
> benchmark harness (`T15.3`), and an automated chaos test suite (`T15.4`).
>
> Code:
> * `crates/ferriscd-controller/src/{metrics,telemetry,events}.rs`
> * `benchmarks/scale_harness.sh` · `docs/benchmarks/v1.0.md`
> * `tests/integration/chaos_suite.rs` (`crates/ferriscd-controller/tests/chaos_suite.rs`)
>
> Verification status:
> * **Hermetic / offline:** Verified in this workspace (`cargo test -p ferriscd-controller --test chaos_suite`,
>   `./benchmarks/scale_harness.sh --self-test`, `./benchmarks/scale_harness.sh --dry-run`, plus
>   unit suites for `metrics`, `telemetry`, and `events`).
> * **Live `kind` runs:** The `#[ignore]`d live `kind` chaos tests and the 30-minute `kind` soak
>   run are automated and `kind-` safety-guarded, and are **pending execution against a live `kind`
>   cluster** (no live cluster numbers are fabricated here).

---

## 1. Prometheus Cardinality Explosions & Typed Metrics (`T15.1`)

A Prometheus time series is uniquely identified by `(metric_name, label_set)`. Every distinct
combination of label values allocates a new series in the TSDB head block. In a GitOps controller,
the classic cardinality bomb is putting the exact strings operators wish they could grep into
Prometheus labels:

* `commit_sha` — unbounded series per commit per application;
* `error_message` — unbounded series per unique API/network error string (and a secret-leak hazard);
* `resource_name` or `repo_url` — scales with every object in every cluster.

On a fleet of 200 applications pushing 50 commits a day, a single `commit_sha` label creates
300,000+ series per month and takes Prometheus down right when an incident starts.

### Making high-cardinality labels unrepresentable in Rust

In [`crates/ferriscd-controller/src/metrics.rs`](../../crates/ferriscd-controller/src/metrics.rs),
every label set is a **private `EncodeLabelSet` struct** populated only from closed `&'static str`
enums (`ReconcileResult`, `CacheOutcome`, `SyncStatus`, `HealthStatus`) — never a
`HashMap<String, String>` accepting arbitrary runtime strings:

| Metric family | Type | Labels | Bounded cardinality |
|---|---|---|---|
| `ferriscd_reconcile_duration_seconds` | Histogram (14 exp. buckets: `5ms`..`40.96s`) | `result` (`success`, `retryable`, `terminal`) | `3` |
| `ferriscd_reconcile_total` | Counter | `result` (`success`, `retryable`, `terminal`) | `3` |
| `ferriscd_app_sync_status` | Gauge (`1` active, `0` others) | `app_namespace`, `app_name`, `status` (`Synced`, `OutOfSync`, `Unknown`) | `apps × 3` |
| `ferriscd_app_health_status` | Gauge (`1` active, `0` others) | `app_namespace`, `app_name`, `status` (`Healthy`, `Progressing`, `Degraded`, `Suspended`, `Missing`, `Unknown`) | `apps × 6` |
| `ferriscd_git_fetch_duration_seconds` | Histogram (14 exp. buckets: `5ms`..`40.96s`) | *(none)* | `1` |
| `ferriscd_render_cache_total` | Counter | `outcome` (`hit`, `miss`) | `2` |
| `ferriscd_active_reconciles` | Gauge | *(none)* | `1` |

Four subtle operational details in `metrics.rs` prevent real production bugs:

1. **Pre-instantiated fixed series (`Metrics::with_fixed_series`):** `prometheus-client` omits a
   family's `# HELP`/`# TYPE` block until at least one series exists. Pre-creating the 3 `result`
   and 2 `outcome` zero-series at startup ensures alerting rules never see "missing series" on a
   freshly started replica, while per-`Application` gauges are created only when an `Application` is
   actually observed.
2. **RAII in-flight gauge (`ReconcileGuard`):** `metrics.start_reconcile()` increments
   `ferriscd_active_reconciles`, and `Drop` decrements it even if a task is cancelled during
   graceful shutdown or unwinds, so the gauge never drifts upward.
3. **Status-truth wrapping (`MetricsStatusWriter`) + deletion cleanup (`forget_app`):** The per-app
   sync/health gauges are updated by wrapping `StatusWriter`, so metrics always match the `/status`
   actually persisted to Kubernetes (on both `Ok` and `Err`). When a finalizer releases a deleted
   `Application`, `forget_app` removes its series so deleted apps do not leak gauges forever.
4. **Dedicated listener (`0.0.0.0:9090`, path `/metrics`):** The scrape endpoint runs on its own
   `axum` listener (`--metrics-addr` / `FERRISCD_METRICS_ADDR`), completely separate from
   `ferriscd-server`'s bearer-authenticated `/api/v1/*` API port. Prometheus can scrape pod IP
   `:9090` under a `NetworkPolicy` without holding a Kubernetes API bearer token or reaching the
   control-plane API.

```promql
# Steady-state p95 reconcile latency over a 5m rolling window
histogram_quantile(
  0.95,
  sum by (le) (rate(ferriscd_reconcile_duration_seconds_bucket{result="success"}[5m]))
)

# RenderCache hit ratio (%)
100 * (
  rate(ferriscd_render_cache_total{outcome="hit"}[5m])
  /
  clamp_min(sum(rate(ferriscd_render_cache_total[5m])), 1e-9)
)
```

---

## 2. OTLP Tracing Across Async Tokio Tasks & Rate-Limited K8s Events (`T15.2`)

### 2.1 Async Tokio tracing traps and `TelemetryGuard`

Wiring OpenTelemetry into an async Rust controller has two classic pitfalls:

1. **Never hold `span.enter()` across `.await`:** `tracing::Span::enter()` binds the span to the
   current OS thread. When Tokio parks a future and resumes it on a different worker thread, another
   reconcile running on the original thread inherits the wrong parent span — corrupting traces and
   mixing unrelated `Application` attributes. FerrisCD exclusively uses `.instrument(span)` (e.g.
   `reconcile_span(&app)` in `reconcile_instance` and `sync_span` in `InventorySyncPipeline`),
   attaching spans to the *future* rather than the OS thread.
2. **`BatchSpanProcessor` runs outside Tokio:** `opentelemetry_sdk`'s `BatchSpanProcessor` exports
   batches from its own dedicated background OS thread, which has no Tokio reactor. Wiring
   `opentelemetry-otlp` with `reqwest-blocking-client` + `reqwest-rustls` avoids async-reactor
   panics while sharing the process-level `ring` TLS `CryptoProvider` pinned once at startup via
   `impersonation::ensure_crypto_provider()`.

[`crates/ferriscd-controller/src/telemetry.rs`](../../crates/ferriscd-controller/src/telemetry.rs)
also enforces three production invariants:

* **Zero-overhead opt-in:** When `OTEL_EXPORTER_OTLP_ENDPOINT` is unset or blank, `init_telemetry()`
  constructs **no** `SpanExporter`, `SdkTracerProvider`, HTTP client, or background thread.
* **Non-blocking graceful flush (`TelemetryGuard::shutdown_async`):** `SdkTracerProvider::shutdown()`
  blocks waiting for the exporter thread to drain final span batches. Calling it inside
  `tokio::task::spawn_blocking` keeps Tokio worker threads unblocked during `SIGTERM` drain.
* **Endpoint credential redaction (`redact_endpoint_url`):** OTLP endpoints frequently embed auth
  userinfo (`https://user:token@collector:4318`) or query keys (`?api_key=...`). Both are stripped
  before values reach `Debug`, `TelemetryError`, or startup logs — even when the URL itself is
  malformed.

### 2.2 Why `kube::runtime::events::Recorder` alone can still spam `etcd`

Operators expect `kubectl describe application <name>` to show `Normal SyncSucceeded`,
`Normal ResourcePruned`, and `Warning SyncFailed`. However, `kube::runtime::events::Recorder`'s
built-in 6-minute `EventKey` cache only deduplicates the *Event object name*: on every cache hit it
**still issues a `Patch::Merge` against `events.k8s.io/v1`** to increment `series.count`. A fleet of
50 failing applications retrying every 30 seconds would still hammer the API server and `etcd` with
100 writes/minute.

[`crates/ferriscd-controller/src/events.rs`](../../crates/ferriscd-controller/src/events.rs) places
`EventRecorder` **in front of** `EventPublisher` (`KubeEventPublisher` in production,
`RecordingEventPublisher` in tests):

```text
apply_once_with_events
   │
   ▼
EventRecorder (in-memory gate + EventClock seam)
   ├─ identical consecutive Warning within 5m (DEFAULT_WARNING_DEDUP_WINDOW)?
   │     └─► EmitOutcome::Deduplicated (ZERO API calls!)
   ├─ Normal SyncSucceeded?
   │     └─► clears consecutive Warning state (next future failure emits immediately)
   ├─ table > DEFAULT_MAX_TRACKED_APPS (4,096)?
   │     └─► evicts expired, then oldest entry (forget_app drops deleted CRs)
   └─ sanitize_note(): redact secrets/URLs + UTF-8 truncate <= 1024 bytes
         │
         ▼
   EventPublisher::publish()  (best-effort: API/RBAC errors logged at warn!, never fail reconcile)
```

---

## 3. Repeatable Scale & Memory Soak Benchmarking (`T15.3`)

Single-application tests cannot expose watch leaks, unbounded caches, or file-descriptor exhaustion.
[`benchmarks/scale_harness.sh`](../../benchmarks/scale_harness.sh) and
[`docs/benchmarks/v1.0.md`](../benchmarks/v1.0.md) define a deterministic, self-testing 50-app /
500-resource scale & 30-minute soak benchmark:

* **Workload topology:** 1 least-privilege `AppProject` (`bench-scale`), 50 `Application` CRs
  (`bench-app-01`..`bench-app-50`), 50 auto-created namespaces, and 500 workload resources
  (`300 ConfigMap`, `50 Deployment` running `registry.k8s.io/pause:3.10`, `50 Secret` with
  synthetic `stringData`, `50 Service`, `50 ServiceAccount`).
* **Steady-state latency via Prometheus histogram deltas:** Computing `p50`/`p95` from cumulative
  buckets since process start mixes cold-start clones/applies with steady-state drift checks. The
  harness snapshots `/metrics` right after cold convergence (`t_0`) and again at soak completion
  (`t_end`), interpolating quantiles strictly over the `Δbucket` counts.
* **Flat-RSS and FD-leak gates:** After a 5-minute warm-up window, RSS and open file descriptors are
  sampled every 30 seconds for 30 minutes (~3,000 steady-state reconciles). Passing requires
  `<= 10.0%` post-warmup RSS growth, `<= +16` open FD delta, `0` restarts, and `0` panics.

### Why FerrisCD's memory curve stays bounded

Every cache and concurrency fan-out on the reconcile path has an explicit upper bound audited in
[`docs/benchmarks/v1.0.md`](../benchmarks/v1.0.md):

| Component | Bound | Source |
|---|---|---|
| `RepoCache` worktrees | `DEFAULT_MAX_ENTRIES = 64` (LRU + 1h TTL + RAII active leases) | `crates/ferriscd-engine/src/repo/cache.rs` |
| `RenderCache` entries | `DEFAULT_CACHE_CAPACITY = 128` (LRU) | `crates/ferriscd-engine/src/manifest/cache.rs` |
| Worktree sanitizer | `100,000` files / `512 MiB` | `crates/ferriscd-engine/src/repo/sanitize.rs` |
| YAML parser / subprocess | `10,000` alias replays / `20 MiB` stdout+stderr | `crates/ferriscd-engine/src/manifest/{yaml,exec}.rs` |
| Reconcile workers | `DEFAULT_CONCURRENCY = 8` per watched scope | `crates/ferriscd-controller/src/controller.rs` |
| Live GET & Dry-run fan-out | `16` concurrent calls per pass each | `crates/ferriscd-controller/src/{live_state,dry_run}.rs` |
| Impersonation pool | `MAX_CACHED_IDENTITIES = 64` (1 shared HTTP/TLS connector) | `crates/ferriscd-controller/src/impersonation.rs` |
| Event dedup table | `DEFAULT_MAX_TRACKED_APPS = 4,096` | `crates/ferriscd-controller/src/events.rs` |

In the 50-app monorepo benchmark, steady-state reconciles hold **1** `RepoCache` entry (`<= 64`) and
**50** `RenderCache` entries (`<= 128`), achieving a near-100% cache hit ratio after convergence.

---

## 4. Chaos Engineering & The #1 GitOps Safety Invariant (`T15.4`)

### The #1 GitOps safety invariant: **Never prune on fetch or render failure**

When `spec.syncPolicy.automated.prune: true` is enabled, a naive controller models reconciliation as:

```text
to_delete = live_inventory - desired_set
```

If a 90-second Git outage, a TLS hiccup, a broken Helm template, or a YAML syntax error causes the
controller to fall back to `desired_set = ∅` and continue to the prune phase, `to_delete` equals
**every single workload in production**.

FerrisCD enforces defense-in-depth across four independent barriers:

1. **Fail-fast before diff/plan/prune:** Any `RepoError` (network, timeout, HTTP 5xx/429) or
   `ManifestError` (YAML syntax, Helm/Kustomize failure) aborts the pass immediately, patches
   `Ready=False` on `/status`, preserves `status.inventory` and `lastSyncedRevision` untouched, and
   issues **zero** `Delete` calls.
2. **Empty-desired safety rail (`FERRISCD_ALLOW_EMPTY_DESIRED`):** Even when Git succeeds and no
   parser error occurs (e.g., an empty directory or misconfigured `spec.source.git.path` rendering 0
   objects), FerrisCD refuses to prune a non-empty inventory unless the operator explicitly opts in.
3. **Ownership-verified pruning + resource rails:** Before every `Delete`, the pruner re-reads the
   live object's `ferriscd.io/tracking-id` and refuses to delete foreign objects, `ferriscd.io/prune=false`
   opt-outs, `CustomResourceDefinition`s (`pruneCRDs: false`), or `Namespace`s (`pruneNamespaces: false`).
4. **Crash-safe inventory & re-entrant `operationState`:** Every pass computes
   `next_inventory = (prev \ pruned_ok) ∪ applied_ok` and persists partial progress (including
   `status.operationState` and `activeHooks`) on both `Ok` and `PartialSync`, so a `SIGKILL`
   mid-rollout never strands confirmed objects as untracked orphans.

### Dual-tier chaos suite (`tests/integration/chaos_suite.rs`)

Because live Kubernetes clusters are slow and unavailable in unit CI, FerrisCD tests every chaos
scenario at **two tiers** in [`tests/integration/chaos_suite.rs`](../../tests/integration/chaos_suite.rs):

| Scenario | Hermetic deterministic tier (runs in `cargo test`, 0 sleeps) | Live `kind` tier (`#[ignore]`, `assert_kind_context()`) |
|---|---|---|
| **1. `SIGKILL` mid-multi-wave sync** | `chaos_hermetic_sigkill_mid_multi_wave_recovers_with_exact_inventory`, `chaos_hermetic_sigkill_before_status_patch_recovers_idempotently`, `chaos_hermetic_sigkill_mid_partial_apply_preserves_inventory_and_prunes_cleanly` — drops entire `ControllerRuntime` (caches, pipeline, backoff) and boots a fresh instance against persisted `ChaosCluster` + `/status` | `live_kind_chaos_sigkill_controller_mid_multi_wave_sync` — spawns real `ferriscd controller`, sends `SIGKILL` while `operationState.phase == Running`, restarts fresh process, asserts exact 3-wave convergence & inventory |
| **2. Git outage & render failure (`prune: true`)** | `chaos_hermetic_git_outage_never_prunes_and_recovers_automatically` (6 consecutive retryable faults, backoff doubling, 1 deduplicated `Warning SyncFailed`, `delete_calls == 0`), `chaos_hermetic_renderer_failure_never_prunes_live_workloads`, `chaos_hermetic_empty_render_over_nonempty_inventory_refuses_mass_prune` | `live_kind_chaos_git_outage_never_prunes_and_recovers` — stops a loopback Git TCP server (ssh transport) for 90s (`FERRISCD_CHAOS_GIT_OUTAGE_SECONDS`), which surfaces as a retryable `RepoError::Network`; asserts `Ready=False`, zero pruned workloads, unchanged object UIDs and `status.inventory`, restarts the server, proves recovery; pinned hermetically by `chaos_local_git_tcp_server_outage_produces_retryable_network_error_and_recovers` *(plaintext `http://` is deliberately blocked by `protocol.http.allow=never`)* |
| **3. Transient K8s API faults (`429` / `503`)** | `chaos_hermetic_k8s_api_rate_limit_and_503_backoff_and_recovery` — injects `429`/`503` across live `GET`, `dryRun=All`, and SSA `Apply`, verifies exponential backoff `5s -> 10s -> 20s -> 40s -> 80s -> 160s -> 180s` cap, `delete_calls == 0`, exact Prometheus `retryable=7` & `active_reconciles=0`, and backoff reset on recovery | `live_kind_chaos_k8s_api_fault_proxy_backoff_and_recovery` — runs an L4 TCP passthrough fault proxy in front of `kind`'s `https://127.0.0.1:<port>` API server (preserving mTLS SAN validation), drops connections, asserts zero prunes, clears fault, verifies convergence |

### What chaos testing actually caught

Writing the hermetic mid-multi-wave `SIGKILL` test surfaced a real state-machine edge case in
`crates/ferriscd-engine/src/sync/state_machine.rs`: `StepHealth::is_unobserved()` currently checks
`self.observed.is_empty()` rather than checking whether *any* expected key in the current wave is
missing from `observed`. If a single wave has two or more resources and resource #1 applies cleanly
while resource #2 fails transiently (or the controller is killed between resource #1 and #2),
`observed` is non-empty (`{resource_1: Healthy}`) while `resource_2` is missing — causing
`StepHealth::verdict()` to return `Gate::Converging` (`StepAction::Wait`) instead of re-dispatching
the idempotent wave apply until `WaveTimeout` fires. Catching subtle partial-failure state-machine
traps *before* production is the entire reason chaos suites belong in the test pyramid.

---

## 5. Hands-On Experiments (`kind` & Hermetic)

### 5.1 Run the deterministic hermetic chaos suite & offline benchmark self-test (no cluster needed)

```bash
# 1. Run all 8 deterministic chaos tests (3x to confirm zero flakiness)
for i in 1 2 3; do
  echo "=== Chaos Run $i ==="
  cargo test -p ferriscd-controller --test chaos_suite
done

# 2. Verify the scale benchmark harness offline (safety guard, 50/500 counts, p50/p95, RSS/FD math)
./benchmarks/scale_harness.sh --self-test
./benchmarks/scale_harness.sh --dry-run
```

### 5.2 Inspect live `/metrics`, OTLP traces, and deduplicated K8s Events on `kind`

```bash
# Create a local kind cluster and verify context starts with `kind-`
make kind-up
kubectl config current-context   # MUST print kind-*

# Install CRDs and default AppProject
kubectl apply -f deploy/crds/
kubectl create namespace ferriscd-system --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/manifests/default-project.yaml

# Start controller with dedicated Prometheus /metrics listener (and optional OTLP endpoint)
cargo build --bin ferriscd
./target/debug/ferriscd controller \
  --namespace ferriscd-system \
  --allow-local-repos \
  --metrics-addr 127.0.0.1:9090 &
CTRL_PID=$!

# Scrape low-cardinality Prometheus metrics
curl -sS http://127.0.0.1:9090/metrics | grep '^ferriscd_'

# Inspect deduplicated Kubernetes Events on any Application
kubectl describe application <app-name> -n ferriscd-system

kill -TERM "$CTRL_PID"
```

### 5.3 Run the live `kind` chaos suite & 30-minute scale soak

```bash
# Guarded by assert_kind_context(): refuses any non-kind-* kubectl context.
# Override FERRISCD_CHAOS_GIT_OUTAGE_SECONDS=20 for faster local iteration (default: 90s).
FERRISCD_CHAOS_GIT_OUTAGE_SECONDS=90 \
  cargo test -p ferriscd-controller --test chaos_suite -- --ignored --test-threads=1

# Run the 50-Application / 500-Resource / 30-minute memory soak (see docs/benchmarks/v1.0.md)
./benchmarks/scale_harness.sh \
  --apps 50 --resources-per-app 10 --soak-minutes 30 --warmup-minutes 5 \
  --metrics-url http://127.0.0.1:9090/metrics \
  --results-dir ./benchmark-results-v1.0
```

---

## 6. Residual Limitations & Follow-Ups

* **Partial multi-resource wave re-dispatch (`StepHealth::is_unobserved`):** Fix
  `crates/ferriscd-engine/src/sync/state_machine.rs` so a wave with at least one unobserved expected
  key re-dispatches idempotent SSA instead of waiting for `WaveTimeout`.
* **Live `kind` soak & chaos execution:** Run the live 30-minute soak (`docs/benchmarks/v1.0.md`
  §7.2) and `--ignored` live chaos tests on a dedicated `kind` workstation/CI runner and populate
  observed hardware numbers.
* **Live Git outage transport:** Because FerrisCD pins `protocol.http.allow=never`, the live Git
  outage test serves the repository through a loopback `LocalGitTcpServer` behind an
  `ssh://git@127.0.0.1:<port>` URL and a test `ssh` shim. Stopping the server makes the shim fail with a
  connection refusal, which maps to `RepoError::Network` — **retryable**, so exponential backoff
  engages and the app recovers automatically once the server returns. (An earlier `file://` rename
  design was rejected: a missing repository maps to a *terminal* error with a 600s requeue.) The
  hermetic `chaos_local_git_tcp_server_outage_produces_retryable_network_error_and_recovers` test pins
  this classification without a cluster. An optional loopback HTTPS fixture (trusted via
  `SSL_CERT_FILE`) could additionally exercise the TLS transport path.
