# FerrisCD Knowledge Base — Curriculum Index

> **FerrisCD** is built with two equal deliverables: a memory-safe, SSA-first Kubernetes GitOps
> platform written in Rust (`v0.1` -> `v1.0`), and this **16-lesson hands-on Knowledge Base**
> paired with Architecture Decision Records (ADRs) and reproducible `kind` Kubernetes experiments.

* **Master Architecture & Specs:** [MASTER_PLAN.md](../MASTER_PLAN.md) · [ROADMAP.md](../ROADMAP.md) · [REVIEW_LOG.md](../REVIEW_LOG.md)
* **Day-2 Operations & Benchmarks:** [Operations Runbook](../operations/RUNBOOK.md) · [v1.0 Scale & Soak Benchmark](../benchmarks/v1.0.md)

---

## Prerequisites

To follow every lesson and run the hands-on `kind` experiments locally:

* **Rust:** `1.100.0` (Edition 2024, MSRV `1.99`, pinned in [`rust-toolchain.toml`](../../rust-toolchain.toml)) with `rustfmt` and `clippy`
* **Kubernetes local cluster:** Docker, `kind` (`v0.33+`), `kubectl` (`v1.35+`) — created via `make kind-up`
* **Renderers & packaging (Phases 11 & 16):** `helm` (`v4.3+`), `kustomize` (`v5.8+`)
* **Web Dashboard (Phase 16):** Node.js `22+` / `npm` (`apps/ferriscd-web`)
* **Safety habit:** Always verify `kubectl config current-context | grep -q '^kind-'` before running live cluster commands.

---

## Architecture Decision Records (ADRs)

Read these three foundational ADRs first — every lesson builds on the boundaries they establish:

| ADR | Title | Core Decision |
|---|---|---|
| [ADR-0001](../adr/0001-hybrid-ssa-architecture.md) | Hybrid Engine (Argo CD UX + Flux SSA Core) | Combine Argo CD's `Application`/`AppProject` UX, waves/hooks, and orthogonal Sync/Health model with Kubernetes Server-Side Apply (`force: false`) and zero Redis/DB state |
| [ADR-0002](../adr/0002-modular-monolith-workspace.md) | Single-Binary Modular Monolith Workspace | Keep 5 cohesive Rust crates (`ferriscd-crd`, `ferriscd-engine`, `ferriscd-controller`, `ferriscd-server`, `ferriscd-cli`) sharing in-process caches in one binary without microservice/RPC overhead |
| [ADR-0003](../adr/0003-gknn-inventory-and-tracking-id.md) | Version-Agnostic GKNN Inventory & `tracking-id` Ownership Safety | Key inventory strictly by `Group + Kind + Namespace + Name` (never `version`), update via `(prev \ pruned_ok) ∪ applied_ok`, and verify `ferriscd.io/tracking-id` immediately before pruning |

---

## Curriculum by Track & Milestone (`M0` -> `v1.0`)

### Track A — Walking Skeleton & Core Controller ([Track A Spec](../roadmap/track-a-core.md))

| Milestone | Lesson | Learning Objectives | Key Codebase Artifacts |
|---|---|---|---|
| **M0** | [Lesson 01: OpenGitOps, Server-Side Apply, and the Walking Skeleton](01-gitops-and-ssa-walking-skeleton.md) | OpenGitOps principles, Kubernetes SSA `managedFields`, `k8s-openapi` version-feature hygiene, `ferriscd apply-file` | `Cargo.toml`, `Makefile`, `crates/ferriscd-cli/src/commands/apply_file.rs` |
| **`v0.1`** | [Lesson 02: Git Internals, Protocol v2, and Concurrent Repository Caching](02-git-internals-and-repo-caching.md) | Pure-Rust `gix` cloning, `spawn_blocking` async hygiene, per-repo lock + LRU worktree cache, SSH `known_hosts`, worktree-wide symlink sanitization | `crates/ferriscd-engine/src/repo/` |
| **`v0.1`** | [Lesson 03: Kubernetes Manifests, YAML 1.2, and Offline Normalization](03-kubernetes-manifests-yaml-and-normalization.md) | `serde-saphyr` YAML 1.2 parser budgets (billion-laughs defense), `v1/List` expansion, `Secret.stringData` -> base64 `.data`, `.status` stripping, `ferriscd apply` | `crates/ferriscd-engine/src/manifest/`, `crates/ferriscd-cli/src/commands/apply.rs` |
| **`v0.2`** | [Lesson 04: Designing CRDs in Rust: OpenAPI Schemas, `/status`, and the `etcd` Budget](04-crd-design-openapi-and-etcd-limits.md) | `kube::CustomResource` + `schemars 1`, compact GKNN `status.inventory` & `operationState` within `etcd`'s 1.5 MiB object budget, deterministic `ferriscd crd generate --check` | `crates/ferriscd-crd/`, `deploy/crds/` |
| **`v0.2`** | [Lesson 05: Controller Runtime: Discovery, Predicates, Finalizers, and Scope](05-kube-controller-runtime-predicates-and-finalizers.md) | Single-flight `DiscoveryCache`, composite watch predicates (why bare `predicates::generation` breaks deletions/annotations), finalizers + `force-delete` escape hatch, cluster-aware scope injection | `crates/ferriscd-controller/src/{controller,discovery,predicate,reconcile}.rs` |
| **`v0.2`** | [Lesson 06: Inventory, `tracking-id`, and Union Live State](06-inventory-tracking-and-live-state.md) | Model 1 on-demand union fetch (`desired ∪ prev_inventory`), `ferriscd.io/tracking-id` ownership stamping, crash-safe inventory set math, always-update-status on `Ok` and `Err` | `crates/ferriscd-engine/src/inventory/`, `crates/ferriscd-controller/src/live_state.rs` |

### Track B — Intelligent GitOps Engine ([Track B Spec](../roadmap/track-b-engine.md))

| Milestone | Lesson | Learning Objectives | Key Codebase Artifacts |
|---|---|---|---|
| **`v0.3`** | [Lesson 07: SSA Dry-Run Diffing, `managedFields`, and Secret Redaction](07-ssa-dry-run-diffing-and-field-ownership.md) | Server-Side Apply `dryRun=All` diffing, `DeferredPendingCrd`/`DeferredPendingNamespace`, `409 FieldConflict` diagnostics, RFC 6901 `ignoreDifferences`, `Secret` value redaction, `source_spec_hash` | `crates/ferriscd-engine/src/diff/`, `crates/ferriscd-controller/src/dry_run.rs` |
| **`v0.3`** | [Lesson 08: Ordered Sync, CRD Establishment, and Safe Pruning](08-ordered-sync-crd-refresh-and-safe-pruning.md) | Dependency tier ordering, CRD `Established` wait + discovery cache refresh for single-sync CRD+CR, immutable-field `Replace`, `takeoverFieldManagers`, reverse-order tracking-verified pruning & CRD/NS safety rails | `crates/ferriscd-engine/src/{graph,sync}/`, `crates/ferriscd-controller/src/prune.rs` |
| **`v0.3`** | [Lesson 09: Kubernetes Workload Health Machines, `observedGeneration`, and Why Sync ≠ Health](09-kubernetes-workload-health-machines.md) | Monotonic health lattice (`Degraded` > `Missing` > `Progressing` > `Suspended` > `Healthy`), `observedGeneration` staleness trap, `Deployment`/`StatefulSet`/`DaemonSet`/`Job`/`PVC`/CRD evaluators, fast health requeue | `crates/ferriscd-engine/src/health/` |
| **`v0.3`** | [Lesson 10: Sync Waves, Lifecycle Hooks, and GitOps-Safe Rollback](10-sync-waves-hooks-and-gitops-rollback.md) | Re-entrant `OperationState` machine (never blocking a reconcile worker), sync wave gating, `PreSync`/`Sync`/`PostSync`/`SyncFail` hooks with `generateName` and cleanup policies, bounded history & auto-sync-pausing rollback | `crates/ferriscd-engine/src/sync/state_machine.rs`, `crates/ferriscd-controller/tests/` |

### Track C — Ecosystem Renderers, Security & Multi-Cluster ([Track C Spec](../roadmap/track-c-enterprise.md))

| Milestone | Lesson | Learning Objectives | Key Codebase Artifacts |
|---|---|---|---|
| **`v0.4`** | [Lesson 11: Safe Manifest Rendering (Kustomize v5 & Helm v4)](11-safe-manifest-rendering-helm-and-kustomize.md) | `ManifestRenderer` trait, `SandboxedCommand` (`env_clear()`, timeouts, 20 MiB output caps), Kustomize remote-URL SSRF blocking, Helm `--kube-version` & opt-in CRDs, collision-free `RenderCache` keys | `crates/ferriscd-engine/src/manifest/{exec,kustomize,helm,cache}.rs` |
| **`v0.5`** | [Lesson 12: Multi-Tenancy, Impersonation, and the Confused Deputy](12-multi-tenancy-impersonation-and-confused-deputy.md) | `AppProject` policy enforcement on every rendered resource's actual namespace, Apps-in-any-namespace isolation, pooled `ServiceAccount` impersonation (`Impersonate-User` + `Impersonate-Group`, refusing `system:masters`), control-plane-only repo credential Secrets | `crates/ferriscd-engine/src/policy/`, `crates/ferriscd-controller/src/{impersonation,repo_creds}.rs` |
| **`v0.5`** | [Lesson 13: Multi-Cluster, Leases, and Deterministic Sharding](13-multi-cluster-leases-and-sharding.md) | Secret-backed `ClusterManager` with strict TLS/kubeconfig validation & Finding C5 finalizer safety, native `coordination.k8s.io/v1` `Lease` active/standby HA, deterministic `sha256(ns, name) % N` sharding & stop-then-start migrations | `crates/ferriscd-controller/src/{cluster_manager,leader_election,sharding}.rs` |

### Track D — API, Observability, Modern Web UI & `v1.0` Release ([Track D Spec](../roadmap/track-d-platform.md))

| Milestone | Lesson | Learning Objectives | Key Codebase Artifacts |
|---|---|---|---|
| **`v1.0`** | [Lesson 14: Control-Plane API, Webhooks, TokenReview & Project RBAC](14-control-plane-api-webhooks-and-rbac.md) | In-process `axum` + `utoipa` OpenAPI 3.1 server sharing engine caches, hardened GitHub HMAC + `X-GitHub-Delivery` dedupe vs. GitLab token webhooks with 1 MiB body cap & fan-out debounce, `TokenReview` AuthN (30s positive cache), default-deny `ferriscd-rbac-cm` with `404` non-existence masking, full `ferriscd` CLI | `crates/ferriscd-server/`, `crates/ferriscd-cli/src/commands/{server,login,app,platform}.rs` |
| **`v1.0`** | [Lesson 15: Observability, Scale Benchmarking & Chaos Engineering](15-observability-benchmarking-and-chaos-engineering.md) | Compile-time low-cardinality Prometheus metrics (`:9090/metrics`), async Tokio `.instrument(span)` OTLP tracing, 5-minute deduplicated Kubernetes Events, 50-app / 500-resource 30m soak benchmark, dual-tier chaos suite (`SIGKILL`, Git outage with zero prunes, K8s `429`/`503` backoff) | `crates/ferriscd-controller/src/{metrics,telemetry,events}.rs`, `benchmarks/scale_harness.sh`, `tests/integration/chaos_suite.rs` |
| **`v1.0`** | [Lesson 16: Packaging, Hardening, OpenAPI Codegen & Production GitOps](16-packaging-hardening-and-production-gitops.md) | End-to-end Rust `utoipa` -> `openapi-typescript`/`openapi-fetch` React 19 + React Flow dashboard, non-root `readOnlyRootFilesystem: true` containers with `openssh-client` + UID `65532` (Finding C6) + SHA-256 pinned `helm`/`kustomize`, `NetworkPolicy` IMDS egress hardening, least-privilege Helm/Kustomize packaging, Day-2 operations & release pipeline | `apps/ferriscd-web/`, `Dockerfile`, `deploy/helm/ferriscd/`, `deploy/manifests/`, `docs/operations/RUNBOOK.md`, `.github/workflows/release.yml` |
