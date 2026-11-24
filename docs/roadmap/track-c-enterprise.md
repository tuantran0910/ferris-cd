# Track C: Ecosystem Renderers, Security & Multi-Cluster (Phases 11–13)

> **Milestones:** `v0.4` Ecosystem Renderers (Phase 11) · `v0.5` Multi-Tenant & HA Control Plane (Phase 13)  
> **Back to:** [ROADMAP.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/ROADMAP.md) · [MASTER_PLAN.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/MASTER_PLAN.md)

---

## Phase 11: Manifest Renderers (Kustomize v5 & Helm v4) — *Milestone `v0.4` Complete*

**Phase Goal:** Support real-world Kustomize v5 and Helm v4 repositories safely via sandboxed subprocess execution, SSRF/remote-base blocking, and collision-free render caching—feeding all rendered output into the exact same Phase 03–08 pipeline.  
**Knowledge Base Lesson (`docs/lessons/11-safe-manifest-rendering-helm-and-kustomize.md`):** Why manifest generation is an untrusted security boundary, Kustomize remote-base SSRF, Helm capabilities/CRDs, and render cache key correctness.

### `T11.1` — Refactor Manifest Engine Around `ManifestRenderer` Trait & Auto-Detection
- **Why:** Decouple Plain YAML, Kustomize, and Helm behind one uniform trait so adding OCI or future renderers never touches the controller or sync engine.
- **Detailed Requirements:**
  - Define async `ManifestRenderer` trait returning raw YAML/JSON bytes (or `Vec<serde_json::Value>`) which always flow through the Phase 03 YAML 1.2 parser (`T03.2`) and offline normalizer (`T03.4`).
  - Wrap Phase 03 Plain YAML loader as `PlainYamlRenderer`.
  - Implement deterministic auto-detection when `spec.source.renderer` is `Auto`: `Chart.yaml` -> `Helm`, `kustomization.yaml`/`kustomization.yml`/`Kustomization` -> `Kustomize`, else `PlainYaml`; allow explicit overrides in `ApplicationSpec`.
- **Outputs:** `crates/ferriscd-engine/src/manifest/renderer.rs`.
- **Verification:** Unit tests verifying auto-detection precedence, explicit override behavior, and identical normalization across all renderers.
- **Trap Guard:** Never bypass `T03.2`/`T03.4` (`v1/List` flattening, `Secret.stringData` conversion, duplicate GKNN checks) for rendered Helm/Kustomize output.

### `T11.2` — Build Hardened Subprocess Runner for External Renderers
- **Why:** Invoking external `kustomize`/`helm` binaries on untrusted Git repos risks environment secret leakage, runaway CPU/memory, and SSRF if not strictly sandboxed.
- **Detailed Requirements:**
  - Implement `SandboxedCommand` using `tokio::process::Command`:
    - `env_clear()`, passing **only** minimal `PATH` and an isolated per-invocation scratch `HOME`/`TMPDIR` (zero controller env vars or Kubernetes env tokens inherited!).
    - Explicit proxy/network kill-vars (`HTTP_PROXY=http://127.0.0.1:0`, `HTTPS_PROXY=http://127.0.0.1:0`, `NO_PROXY=`) for offline render steps so child binaries cannot make outbound SSRF calls.
    - Hard execution timeout (default 60s, `kill_on_drop(true)`).
    - Bounded stdout/stderr streaming reader capping rendered manifest output (default 20 MiB) to prevent memory DoS.
- **Outputs:** `crates/ferriscd-engine/src/manifest/exec.rs`.
- **Verification:** Security unit tests proving: (1) sleeping child is killed on timeout, (2) oversized stdout (>cap) aborts cleanly, (3) secret env var set on parent process is invisible inside child process.
- **Trap Guard:** Fixes Finding C7 (env/token hygiene and outbound SSRF defense). Note in docs that Pod-level SA token isolation (`automountServiceAccountToken` / separate renderer pod if untrusted multi-tenant) is documented in Phase 16 `NetworkPolicy` & `SECURITY.md`.

### `T11.3` — Implement `KustomizeRenderer` (`kustomize v5`) with Remote-Base SSRF Guard
- **Why:** `--load-restrictor=LoadRestrictionsRootOnly` blocks local `../../` traversal, **not** remote `http://`/`https://`/`git::` bases—a malicious `kustomization.yaml` could otherwise bypass `AppProject.sourceRepos` or trigger SSRF.
- **Detailed Requirements:**
  - Before invoking `kustomize`, parse `kustomization.yaml` (and referenced local sub-kustomizations) and reject any `resources`, `bases`, `components`, or `patches` containing remote URLs (`http://`, `https://`, `ssh://`, `git::`, `github.com/...`) unless explicitly allowed by cluster config.
  - Invoke `kustomize build <target_path> --load-restrictor=LoadRestrictionsRootOnly` via `SandboxedCommand` (never pass `--enable-exec`, `--enable-alpha-plugins`, or `--enable-helm`).
  - Support optional `KustomizeOptions`: `namePrefix`, `nameSuffix`, `images` overrides (applied via temporary overlay dir inside scratch space without mutating cached worktree!).
- **Outputs:** `crates/ferriscd-engine/src/manifest/kustomize.rs`, `examples/kustomize/`.
- **Verification:** Live `kind` test deploying `examples/kustomize/overlays/prod`; security unit tests proving both `../../escape` and `http://169.254.169.254/latest/meta-data/` are rejected before `kustomize` executes.
- **Trap Guard:** Fixes Finding C7 (remote-base SSRF) and preserves immutable cached worktrees (`T02.3`).

### `T11.4` — Implement `HelmRenderer` (`helm v4`) with Opt-In CRDs & `--kube-version`
- **Why:** Real Helm charts inspect `.Capabilities.KubeVersion` and ship CRDs that must not be auto-managed/auto-pruned unexpectedly.
- **Detailed Requirements:**
  - Invoke `helm template <release_name> <chart_path> --namespace <dest_ns> --kube-version <cluster_kube_version>` via `SandboxedCommand` (strictly offline template mode, zero live cluster queries).
  - Pass `--include-crds` **only** when `helm.includeCRDs == true` (default `false`!).
  - Validate every `valueFiles` path canonicalizes inside `checkout.root_dir`; write inline `values` YAML to an ephemeral scratch file; pass `--set` / `--set-string` parameters safely as separate `OsStr` args (never via a shell!).
- **Outputs:** `crates/ferriscd-engine/src/manifest/helm.rs`, `examples/helm/`.
- **Verification:** Live `kind` test deploying `examples/helm/` chart with custom `valueFiles` + inline `values`; unit tests proving `../../secret.yaml` valueFile is rejected and `includeCRDs: false` omits CRDs by default.
- **Trap Guard:** Fixes Finding H3 (`--include-crds` opt-in & `--kube-version` from `DiscoveryCache`) and Trap T11 (path jail).

### `T11.5` — Implement Collision-Free Render Result Cache & Phase 11 Lesson
- **Why:** Re-running `helm`/`kustomize` subprocesses on every 180s periodic requeue wastes CPU when neither the Git commit nor Application render parameters changed—while an incomplete cache key causes dangerous cross-app contamination in monorepos!
- **Detailed Requirements:**
  - Implement bounded LRU `RenderCache` keyed by the full tuple:
    `SHA-256(repo_url, commit_sha, source_path, app_namespace, app_name, destination_namespace, cluster_kube_version, canonical_renderer_config)`.
  - Store normalized `Arc<Vec<DesiredResource>>` (already parsed & offline-normalized); expose cache hit/miss counters for Phase 15 metrics.
  - Write `docs/lessons/11-safe-manifest-rendering-helm-and-kustomize.md`.
- **Outputs:** `crates/ferriscd-engine/src/manifest/cache.rs`, `docs/lessons/11-safe-manifest-rendering-helm-and-kustomize.md`.
- **Verification:** Unit tests proving: (1) repeat render hits cache and invokes subprocess 0 times, (2) two apps on the same monorepo commit with different `path` OR different `destination.namespace` produce distinct cache keys with zero cross-contamination. **Milestone `v0.4` Complete.**
- **Trap Guard:** Fixes Finding M1 (monorepo & Helm `.Release.Namespace`/`.Release.Name` cache collision).

---

## Phase 12: Security, Impersonation & Multi-Tenancy

**Phase Goal:** Replace the Phase 05–11 `PermissivePolicy` stub with full `AppProject` allow-list enforcement, enable optional Apps-in-any-namespace (`AppProject.spec.sourceNamespaces`), implement pooled `ServiceAccount` impersonation (with `Impersonate-Group` headers), and support Secret-backed Git credentials.  
**Knowledge Base Lesson (`docs/lessons/12-multi-tenancy-impersonation-and-confused-deputy.md`):** The Kubernetes confused-deputy problem, why `Impersonate-User` without `Impersonate-Group` breaks `RoleBinding`s, and defense-in-depth with `AppProject`.

### `T12.1` — Implement `AppProjectPolicy` Enforcer (Validated Against Every Rendered Resource)
- **Why:** Checking only `spec.destination.namespace` is trivially bypassed by committing a manifest with hardcoded `metadata.namespace: kube-system` or a `ClusterRoleBinding`.
- **Detailed Requirements:**
  - Replace `PermissivePolicy` with `AppProjectPolicy` reading the referenced `AppProject` CR from `ferriscd-system` (missing project -> terminal `PolicyError::ProjectNotFound`).
  - Verify before rendering: (1) `app.namespace` is allowed by `project.spec.sourceNamespaces`, (2) `source.git.repoURL` matches `project.spec.sourceRepos`, (3) `(destination.cluster, destination.namespace)` matches `project.spec.destinations`, (4) `serviceAccountName` (if set) is permitted by `project.spec.allowedServiceAccounts`.
  - Verify **after** Stage-2 scope normalization (`T05.4`) on **every rendered resource**: (1) actual `resource.namespace` (if namespaced) is allowed by `project.spec.destinations`, (2) cluster-scoped `(group, kind)` is in `clusterResourceWhitelist`, (3) namespaced `(group, kind)` is allowed by `namespaceResourceWhitelist` (if non-empty) and not in `namespaceResourceBlacklist`.
- **Outputs:** `crates/ferriscd-engine/src/policy/app_project.rs`.
- **Verification:** Exhaustive unit tests including: manifest hardcoding `metadata.namespace: kube-system` inside a `payments`-only project is **rejected**; unauthorized `ClusterRole` is **rejected**; wildcard matching works predictably.
- **Trap Guard:** Fixes Finding C8 and Finding M6 (`namespaceResourceWhitelist` + per-resource actual-namespace check).

### `T12.2` — Enable Opt-In Apps-in-Any-Namespace Mode
- **Why:** Aligned with ADR-007: keep `ferriscd-system`-only as the safe default through `v0.4`, and allow operators to opt into tenant-namespace `Application` CRs safely when backed by `AppProject.spec.sourceNamespaces` + mandatory `serviceAccountName`.
- **Detailed Requirements:**
  - Add `--application-namespaces` flag/config (`ferriscd-system` default; comma-separated list or `*` for opt-in multi-namespace mode).
  - When an `Application` lives outside `ferriscd-system`: (1) enforce `AppProject.spec.sourceNamespaces` match, (2) **require** `spec.serviceAccountName` to be non-empty (refuse to reconcile with controller's own privileged SA!), (3) restrict `destination.namespace` unless explicitly allowed by `AppProject`.
- **Outputs:** Namespace-scope config & guard in `crates/ferriscd-controller/src/controller.rs` and `ferriscd-engine/src/policy/`.
- **Verification:** Live `kind` test: `Application` in `team-a` namespace without `serviceAccountName` is rejected; with valid `AppProject.sourceNamespaces: ["team-a"]` and `serviceAccountName`, it reconciles cleanly.
- **Trap Guard:** Prevents privilege escalation when enabling self-service tenant namespaces (Finding C8).

### `T12.3` — Implement Pooled `ServiceAccount` Impersonation (`Impersonate-User` + `Impersonate-Group`)
- **Why:** Passing `Impersonate-User` alone breaks Kubernetes group-based `RoleBinding`s, and constructing a new `kube::Client` per reconcile leaks TLS connections and file descriptors.
- **Detailed Requirements:**
  - Build a lightweight `tower::Layer` / `ImpersonationService` wrapping the cluster's shared base HTTP/TLS `hyper` connector (zero new TCP/TLS pool per reconcile!).
  - When `spec.serviceAccountName` is specified (resolved in `destination.namespace` *only after* `AppProject` authorizes `(cluster, destination.namespace)`), inject:
    - `Impersonate-User: system:serviceaccount:<dest_ns>:<sa_name>`
    - `Impersonate-Group: system:serviceaccounts`
    - `Impersonate-Group: system:serviceaccounts:<dest_ns>`
    - `Impersonate-Group: system:authenticated`
  - Document required `impersonate` RBAC (`users`, `groups`) on the controller's `ClusterRole` (and remote cluster kubeconfigs in Phase 13).
- **Outputs:** `crates/ferriscd-controller/src/impersonation.rs`.
- **Verification:** Live `kind` test: create restricted SA `tenant-deployer` in `tenant-a` bound via a **group** `RoleBinding` (testing `Impersonate-Group`!) with permissions only on `ConfigMap` in `tenant-a`. Verify deploying a `ConfigMap` succeeds, deploying to `kube-system` or creating a `ClusterRole` fails with `403 Forbidden`.
- **Trap Guard:** Fixes Finding H5 (`Impersonate-Group` + connection-pool reuse) and Trap T12.

### `T12.4` — Implement Kubernetes Secret-Backed Repository Credentials & Phase 12 Lesson
- **Why:** Git HTTPS tokens and SSH private keys must live in Kubernetes Secrets inside `ferriscd-system`, matched cleanly to `Application.spec.source.git.repoURL`.
- **Detailed Requirements:**
  - Implement `SecretCredentialStore` watching Secrets labeled `ferriscd.io/secret-type=repository` strictly inside `ferriscd-system` (never cluster-wide!).
  - Support exact URL and longest-prefix credential templates (`url`, `username`, `password`/`token`, `sshPrivateKey`, `knownHosts`).
  - Write `docs/lessons/12-multi-tenancy-impersonation-and-confused-deputy.md`.
- **Outputs:** `crates/ferriscd-controller/src/credentials.rs`, `docs/lessons/12-multi-tenancy-impersonation-and-confused-deputy.md`.
- **Verification:** Live `kind` test storing repo credentials in a `ferriscd-system` Secret and reconciling an `Application` against a token-protected local Git HTTP fixture; verify Secret values never appear in logs.
- **Trap Guard:** Scope Secret watch strictly to `ferriscd-system` so controller never requests cluster-wide Secret read RBAC.

---

## Phase 13: Multi-Cluster & High Availability — *Milestone `v0.5` Complete*

**Phase Goal:** Reconcile workloads across remote Kubernetes clusters safely and run multiple controller replicas in HA mode using a native `kube 5.x` `Lease` leader elector plus opt-in deterministic sharding.  
**Knowledge Base Lesson (`docs/lessons/13-multi-cluster-leases-and-sharding.md`):** Multi-cluster kubeconfig trust boundaries, Kubernetes `coordination.k8s.io/v1` Lease internals (optimistic concurrency via `resourceVersion`), and sharding vs. active/standby trade-offs.

### `T13.1` — Implement `ClusterManager` & Secret-Based Remote Cluster Registry
- **Why:** A single FerrisCD control plane should manage both `in-cluster` and remote workload clusters with isolated `Client` pools and per-cluster `DiscoveryCache` instances.
- **Detailed Requirements:**
  - Watch Secrets labeled `ferriscd.io/secret-type=cluster` strictly inside `ferriscd-system` containing cluster name, API server URL, CA certificate, and auth (bearer token / client cert / kubeconfig).
  - Maintain a `DashMap<ClusterName, Arc<ClusterHandle { client, discovery, base_connector }>>` invalidated automatically when the cluster Secret changes or is deleted.
  - Validate TLS CA certificates strictly by default (reject `insecure-skip-tls-verify: true` unless explicitly enabled for local dev).
- **Outputs:** `crates/ferriscd-controller/src/cluster_manager.rs`.
- **Verification:** Live multi-cluster integration test using two `kind` clusters (`kind-ferriscd-control` -> `kind-ferriscd-workload`) deploying and pruning an app remotely.
- **Trap Guard:** When a Cluster Secret is deleted while an `Application` is terminating, `T05.3`'s finalizer escape hatch prevents deadlock (Finding C5).

### `T13.2` — Implement Native `coordination.k8s.io/v1` Lease Leader Election on `kube 5.x`
- **Why:** Third-party leader-election crates frequently lag behind `kube 5.x`; a clean ~150-line native `Lease` elector has zero extra dependency risk and is hugely educational for distributed systems!
- **Detailed Requirements:**
  - Implement `LeaseElector` operating on `k8s_openapi::api::coordination::v1::Lease` (`ferriscd-controller-leader` in `ferriscd-system`) using optimistic concurrency (`resourceVersion`) to acquire, renew (`renew_interval < lease_duration / 3`), and detect lease loss.
  - Provide a `tokio_util::sync::CancellationToken` that cancels controller reconciliation immediately if lease renewal fails, and voluntarily releases the lease (setting `leaseDurationSeconds: 1` or clearing `holderIdentity`) on graceful `SIGTERM`.
- **Outputs:** `crates/ferriscd-controller/src/leader_election.rs`.
- **Verification:** Live `kind` test running 2 controller instances concurrently: verify only 1 holds the lease and reconciles; kill leader (`SIGKILL`) and verify standby acquires lease within `lease_duration + 2s` and continues reconciling cleanly.
- **Trap Guard:** Fixes Finding H4 (avoid third-party `kube-leader-election` version lag).

### `T13.3` — Implement Opt-In Deterministic Application Sharding
- **Why:** At large scale, a single active leader can become CPU/IO-bound; deterministic consistent-hash sharding allows N controller replicas to partition `Application`s cleanly.
- **Detailed Requirements:**
  - Add `--shard-id <0..N-1>` and `--total-shards <N>` flags (validated mutually exclusive with single-leader election mode, or paired with per-shard lease names `ferriscd-leader-shard-<id>`).
  - Compute `shard = blake3_or_sha256(app.namespace, app.name) % total_shards`; skip applications not belonging to this replica's shard inside the watch predicate before queueing.
- **Outputs:** `crates/ferriscd-controller/src/sharding.rs`.
- **Verification:** Unit tests verifying 100% disjoint, deterministic coverage across 1,000 synthetic `(namespace, name)` pairs for `N = 1, 3, 5`.
- **Trap Guard:** Explicitly validate CLI flags so users cannot accidentally run both single-leader and sharding in conflicting modes.

### `T13.4` — Run `v0.5` Multi-Tenant & HA Verification Suite + Phase 13 Lesson
- **Why:** Prove enterprise security boundaries, remote cluster delivery, and HA failover end-to-end before building the API and Web UI layer.
- **Detailed Requirements:**
  - Build `tests/integration/v0_5_enterprise.rs` testing: `AppProject` namespace/kind rejection, `ServiceAccount` impersonation `403` + group `RoleBinding` success, remote `kind` cluster deploy, and 2-replica Lease failover.
  - Write `docs/lessons/13-multi-cluster-leases-and-sharding.md`.
- **Outputs:** `tests/integration/v0_5_enterprise.rs`, `docs/lessons/13-multi-cluster-leases-and-sharding.md`.
- **Verification:** Full `v0.5` suite passes green. **Milestone `v0.5` Complete.**
- **Trap Guard:** Ensure remote-cluster impersonation RBAC requirements are clearly documented in the test fixture and lesson.
