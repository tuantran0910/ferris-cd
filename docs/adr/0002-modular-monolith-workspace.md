# ADR-0002: Single-Binary Modular Monolith Workspace

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Two structural decisions shape FerrisCD's codebase and deployment topology:

1. **Cargo workspace granularity:** Initial drafts considered splitting the codebase into ~13 fine-grained crates on day one. In Rust, premature crate splitting introduces cyclic dependency traps, trait orphan-rule friction, and high cross-crate refactoring cost before domain interfaces stabilize.
2. **Controller vs. API Server process topology:** Because FerrisCD stores zero external Redis/DB state and never persists rendered YAML or diffs in `Application.status` (ADR-0001), an API endpoint such as `GET /api/v1/applications/{name}/diff` or `GET .../resources` must access `RepoCache`, `ClusterManager`, `DiscoveryCache`, and `DiffEngine`. Splitting the API server into a separate microservice would force either duplicating Git/cluster caches and connections across pods or introducing a new RPC/cache layer.
3. **`k8s-openapi` feature hygiene:** `k8s-openapi` requires a single Kubernetes version feature (e.g., `v1_35`) to compile types. If a library crate enables a version feature directly, it locks every downstream consumer and risks feature conflicts across tests or binaries.

## Decision

FerrisCD is organized as a **single-binary modular monolith** growing cleanly from **4 crates to 5 crates**, with strict feature isolation:

1. **Phases 01–13 (4 Crates):**
   - `ferriscd-crd` — `Application` and `AppProject` CRDs, status/conditions, compact GKNN inventory types, and canonical control annotations.
   - `ferriscd-engine` — Pure GitOps engine & mockable traits (`repo`, `manifest`, `inventory`, `diff`, `graph`, `sync`, `health`, `policy`).
   - `ferriscd-controller` — `kube-rs` controller runtime, composite watch predicates, `DiscoveryCache`, `ClusterManager`, `ServiceAccount` impersonation layer, finalizers, and native `Lease` HA.
   - `ferriscd-cli` — The `ferriscd` binary hosting standalone `apply`, `crd generate`, `controller`/`server` runner, and the full REST API CLI.
2. **Phase 14 (5th Crate Embedded In-Process):**
   - `ferriscd-server` — `axum` REST API, `utoipa` OpenAPI 3.1 schema generation, GitHub/GitLab webhooks, `TokenReview`/RBAC, and Prometheus/OTel observability.
   - Embedded alongside `ferriscd-controller` inside the single `ferriscd` process so `ferriscd-server` shares `RepoCache`, `ClusterManager`, `DiscoveryCache`, and `DiffEngine` directly in memory.
3. **`k8s-openapi` Feature Hygiene:**
   - Pin `kube = "5.1"`, `k8s-openapi = { version = "0.29", features = ["schemars"] }`, and `schemars = "1"` at the workspace root.
   - Enable the `k8s-openapi` version feature (`v1_35`) **only** in binary crates (`ferriscd-cli`, `ferriscd-controller` binary) and integration-test crates (`tests/integration`), **never** in library crates (`ferriscd-crd`, `ferriscd-engine`).
4. **Enforced Quality Boundaries:**
   - Keep `ferriscd-crd` and `ferriscd-engine` independent of `kube-rs` runtime loops and concrete `gix` types in public traits (`GitClient`, `Renderer`, `PolicyEvaluator`).
   - Deny `unwrap_used` and `expect_used` in library and controller runtime code (allowed in tests).

## Consequences

### Positive
- Fast iteration, clean Rust ownership/trait design, and zero orphan-rule friction across domains.
- Single deployable binary and container image with zero inter-service RPC latency or duplicated Git/cluster caches for live diff previews and resource DAG assembly.
- Library crates (`ferriscd-crd`, `ferriscd-engine`) remain cleanly reusable across the CLI, controller, server, and integration test suite without `k8s-openapi` version lock-in.

### Trade-offs & Mitigations
- **Coupled horizontal scaling:** Controller and REST API scale together inside one binary in `v1.0`. *Mitigation:* Phase 13 adds native `coordination.k8s.io/v1` Lease-based HA and opt-in deterministic sharding, while internal Rust crate/trait boundaries allow extracting `ferriscd-server` into a separate process post-`v1.0` if needed.
- **Shared blast radius in one process:** Untrusted repository rendering or YAML parsing shares memory with the controller. *Mitigation:* Enforce `serde-saphyr` parser budgets, worktree-wide symlink sanitization, cleared subprocess environments for `helm`/`kustomize`, SSRF remote-base blocking, and strict Secret redaction.

## References

- [MASTER_PLAN.md](../MASTER_PLAN.md) — Sections 1.3, 3 (ADR-002), 4.1–4.2, and 6
- [REVIEW_LOG.md](../REVIEW_LOG.md) — Findings P1-03, C9, and H4
- [ADR-0001: Hybrid SSA Architecture](./0001-hybrid-ssa-architecture.md)
