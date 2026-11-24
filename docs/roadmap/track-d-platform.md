# Track D: API, Observability, Modern Web UI & v1.0 Release (Phases 14–16)

> **Milestone:** `v1.0` Production-Oriented Platform & Modern Web Dashboard (Phase 16)  
> **Back to:** [ROADMAP.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/ROADMAP.md) · [MASTER_PLAN.md](file:///Users/tranngoctuan0910/Workspaces/PersonalRepo/ferris-cd/docs/MASTER_PLAN.md)

---

## Phase 14: Control Plane API, Webhooks & Full CLI

**Phase Goal:** Expose FerrisCD operations via an in-process `axum` REST API with generated OpenAPI 3.1 contracts (`utoipa`), sub-second hardened GitHub/GitLab webhooks, `TokenReview` AuthN + project RBAC, and a complete `ferriscd` CLI.  
**Knowledge Base Lesson (`docs/lessons/14-control-plane-api-webhooks-and-rbac.md`):** Modular-monolith shared-engine APIs, GitHub HMAC vs. GitLab token webhook security, Kubernetes `TokenReview` AuthN, and OpenAPI-driven typed clients.

### `T14.1` — Scaffold `ferriscd-server` (`axum` + `utoipa` OpenAPI) Sharing In-Process Engine
- **Why:** Running `ferriscd-server` in the same modular-monolith process as `ferriscd-controller` (ADR-002) lets `GET .../diff` compute live, Secret-redacted SSA dry-run diffs using the shared `RepoCache`, `ClusterManager`, and `DiffEngine` without duplicating state or adding Redis!
- **Detailed Requirements:**
  - Create `crates/ferriscd-server` with `axum` + `utoipa` OpenAPI 3.1 schema generation (`GET /api/v1/openapi.json` and CLI export command for TypeScript codegen).
  - Implement endpoints:
    - `GET /healthz`, `GET /readyz`
    - `GET /api/v1/applications`, `GET /api/v1/applications/:ns/:name`
    - `GET /api/v1/applications/:ns/:name/resources` (live health, sync status, plus on-demand `metadata.ownerReferences` traversal in `destination.namespace` to stitch `Deployment -> ReplicaSet -> Pod` nodes for the DAG without background cluster-wide informers)
    - `GET /api/v1/applications/:ns/:name/diff` (live, Secret-redacted SSA dry-run diff via shared engine)
    - `POST /api/v1/applications/:ns/:name/sync`, `POST /api/v1/applications/:ns/:name/rollback` (patches `ferriscd.io/operation` annotation on the `Application` CR)
    - `GET /api/v1/projects`, `GET /api/v1/clusters`
  - Add `ferriscd server` subcommand running controller + API server concurrently with unified graceful shutdown.
- **Outputs:** `crates/ferriscd-server/`, exported `docs/api/openapi.json`.
- **Verification:** `tower::ServiceExt::oneshot` integration tests covering all endpoints + OpenAPI JSON schema validity check.
- **Trap Guard:** Fixes Finding C9 (removes the contradictory "CR-only server computes diffs" flaw).

### `T14.2` — Implement Hardened GitHub & GitLab Webhook Verification + Endpoint
- **Why:** Enable sub-second GitOps sync on `git push` without exposing an unauthenticated DoS or thundering-herd vector.
- **Detailed Requirements:**
  - Enforce `DefaultBodyLimit::max(1024 * 1024)` (1 MiB) before parsing any webhook body.
  - Implement `POST /api/v1/webhooks/github`: verify `X-Hub-Signature-256` HMAC-SHA256 using constant-time comparison (`subtle`) AND deduplicate `X-GitHub-Delivery` UUIDs in a bounded TTL cache (e.g. 10,000 entries / 15 min) to prevent replay storms.
  - Implement `POST /api/v1/webhooks/gitlab`: verify `X-Gitlab-Token` shared secret using constant-time comparison.
  - Match affected `Application`s by normalized repo URL + branch/tag, and trigger `ferriscd.io/refresh` annotation patches with a per-repo debounce window (e.g. 2s) + jittered fan-out so a monorepo push to 50 apps doesn't stampede the API server.
- **Outputs:** `crates/ferriscd-server/src/webhooks.rs`.
- **Verification:** Unit + HTTP tests for valid, tampered, oversized (>1 MiB -> `413`), duplicate `X-GitHub-Delivery` (ignored), and multi-app fan-out debouncing; live `kind` test proving push webhook triggers reconcile in <2s.
- **Trap Guard:** Fixes Finding H8 (body cap, accurate GitHub HMAC+delivery-ID vs GitLab static token semantics, fan-out protection, moved out of Phase 12).

### `T14.3` — Implement API Authentication via Kubernetes `TokenReview`
- **Why:** Pick one rock-solid, Kubernetes-native authentication mechanism for `v1.0` instead of over-scoping both `TokenReview` and OIDC in a single task.
- **Detailed Requirements:**
  - Implement an `axum` AuthN middleware extracting `Authorization: Bearer <token>` and validating it via Kubernetes `authentication.k8s.io/v1/TokenReview` (with short-lived 30s positive cache keyed by token SHA-256 hash).
  - Attach `AuthenticatedIdentity { username, groups }` to request extensions; return `401 Unauthorized` on missing/invalid tokens.
  - Keep `/healthz`, `/readyz`, `/metrics` (separately port-bound), and `/api/v1/webhooks/*` (webhook-secret authenticated) cleanly separated from bearer-protected `/api/v1/*` routes.
- **Outputs:** `crates/ferriscd-server/src/auth.rs`.
- **Verification:** Integration tests verifying missing token -> `401`, invalid token -> `401`, valid `kind` ServiceAccount token -> `200` with resolved identity.
- **Trap Guard:** Fixes Finding H9 (focused AuthN scope; default-deny on all `/api/v1/*`).

### `T14.4` — Implement Project-Scoped RBAC Authorization Middleware
- **Why:** Authenticated users must only view or mutate `Application`s in `AppProject`s they are authorized for.
- **Detailed Requirements:**
  - Define RBAC policy loaded from a ConfigMap (`ferriscd-rbac-cm` in `ferriscd-system`) mapping `(subject: user|group, project, action: get|diff|sync|rollback|admin)` with default-deny semantics.
  - Enforce RBAC before every handler (filtering `GET /applications` list responses to permitted projects and returning `403 Forbidden` on unauthorized single-app access or sync/rollback).
- **Outputs:** `crates/ferriscd-server/src/rbac.rs`.
- **Verification:** Unit + API tests verifying read-only user can `get`/`diff` but gets `403` on `sync`/`rollback`, and tenant-A user cannot see tenant-B apps in `GET /applications`.
- **Trap Guard:** Never leak existence of unauthorized applications in `403` vs `404` or list endpoints.

### `T14.5` — Complete Full `ferriscd` Developer CLI
- **Why:** Give developers a fast, scriptable, ergonomic CLI talking to `ferriscd-server` for daily GitOps workflows.
- **Detailed Requirements:**
  - Implement subcommands: `ferriscd login <server-url> --token <...>`, `ferriscd app list`, `get <name>`, `diff <name>` (colorized, Secret-redacted), `sync <name> [--prune] [--watch]`, `rollback <name> <history-id>`, `history <name>`, `project list`, `cluster list`.
  - Support `--output table | json | yaml` across all read commands and meaningful exit codes (`0` synced, `1` error, `2` out-of-sync for CI diff checks).
- **Outputs:** `crates/ferriscd-cli/src/commands/*`, `crates/ferriscd-cli/src/client.rs`.
- **Verification:** End-to-end CLI tests against running `ferriscd-server` on `kind`.
- **Trap Guard:** Reuse server's redacted diff payload—never print raw Secrets.

### `T14.6` — Author Phase 14 Lesson
- **Why:** Document API security, webhook hardening, and OpenAPI contract generation.
- **Detailed Requirements:**
  - Write `docs/lessons/14-control-plane-api-webhooks-and-rbac.md` with a hands-on `kind` experiment firing a signed GitHub webhook payload via `curl` and watching sub-second sync.
- **Outputs:** `docs/lessons/14-control-plane-api-webhooks-and-rbac.md`.
- **Verification:** Walkthrough commands verified end-to-end on `kind`.
- **Trap Guard:** Keep curl examples using fake test tokens, never real credentials.

---

## Phase 15: Observability, Benchmarks & Chaos Testing

**Phase Goal:** Make FerrisCD operationally transparent with low-cardinality Prometheus metrics, OpenTelemetry traces, rate-limited K8s Events, and prove stability under 50-app scale and real failure chaos tests.  
**Knowledge Base Lesson (`docs/lessons/15-observability-benchmarking-and-chaos-engineering.md`):** Cardinality explosions in Prometheus, OTLP tracing across async Tokio tasks, and designing reproducible Kubernetes chaos tests.

### `T15.1` — Implement Low-Cardinality Prometheus Metrics (`/metrics`)
- **Why:** Operators need instant visibility into reconcile latency, sync failures, drift counts, Git fetch performance, and render cache efficiency.
- **Detailed Requirements:**
  - Expose `/metrics` on a dedicated internal metrics port (default `:9090`) using `prometheus-client`:
    - `ferriscd_reconcile_duration_seconds` (histogram, labels: `result`)
    - `ferriscd_reconcile_total` (counter, labels: `result`)
    - `ferriscd_app_sync_status` (gauge, labels: `app_namespace`, `app_name`, `status`)
    - `ferriscd_app_health_status` (gauge, labels: `app_namespace`, `app_name`, `status`)
    - `ferriscd_git_fetch_duration_seconds`, `ferriscd_render_cache_total{outcome="hit|miss"}`
    - `ferriscd_active_reconciles` (gauge)
- **Outputs:** `crates/ferriscd-controller/src/metrics.rs`.
- **Verification:** Integration test scraping `http://127.0.0.1:9090/metrics` and asserting expected metric families and values after a sync.
- **Trap Guard:** **Never** put `commit_sha`, `error_message`, or `resource_name` into Prometheus labels (prevents time-series cardinality explosion!).

### `T15.2` — Add OpenTelemetry OTLP Tracing & Rate-Limited Kubernetes Events
- **Why:** Distributed traces pinpoint slow steps (Git fetch vs Helm render vs K8s SSA), while K8s Events surface sync history directly in `kubectl describe application`.
- **Detailed Requirements:**
  - Wire optional `tracing-opentelemetry` OTLP exporter enabled via `OTEL_EXPORTER_OTLP_ENDPOINT`.
  - Wire `kube::runtime::events::Recorder` to emit `Normal SyncSucceeded`, `Normal ResourcePruned`, and `Warning SyncFailed` events on `Application` CRs, deduplicating identical consecutive `Warning` reasons within a 5-minute window.
- **Outputs:** `crates/ferriscd-controller/src/telemetry.rs`, `events.rs`.
- **Verification:** `kubectl describe application <name>` on `kind` displays clean sync events without flooding on repeated failures; OTLP exporter initializes cleanly when configured.
- **Trap Guard:** Unbounded `Warning` Event creation on a failing app every 30s can spam `etcd`; enforce deduplication/rate-limiting.

### `T15.3` — Run 50-Application / 500-Resource Scale & Memory Soak Benchmark
- **Why:** Quantify Rust's core value proposition (predictable low RSS memory and fast p95 reconcile latency) and catch any watch, `RepoCache`, or HTTP connection leaks before `v1.0`.
- **Detailed Requirements:**
  - Build a benchmark harness generating 50 `Application` CRs totaling 500 Kubernetes resources on `kind`.
  - Measure cold convergence time, steady-state p50/p95 reconcile latency, and RSS memory over a 30-minute soak test (confirming flat memory curve).
  - Record results and hardware profile in `docs/benchmarks/v1.0.md`.
- **Outputs:** `benchmarks/scale_harness.sh` (or Rust binary), `docs/benchmarks/v1.0.md`.
- **Verification:** Soak test completes with zero panics, zero leaked FDs, and flat RSS memory after warm-up.
- **Trap Guard:** Verify `RepoCache` LRU eviction and `RenderCache` caps keep memory strictly bounded.

### `T15.4` — Execute Chaos Test Suite & Phase 15 Lesson
- **Why:** Prove the platform holds its invariants when infrastructure breaks mid-operation.
- **Detailed Requirements:**
  - Automate 3 chaos scenarios against `kind`:
    1. `SIGKILL` controller process mid-multi-wave sync -> restart -> converges cleanly with zero orphaned/corrupted state.
    2. Take down local Git HTTP server for 90s while apps are healthy -> `Ready=False` reported, **zero** live workloads pruned or disrupted -> restore Git -> recovers automatically.
    3. Inject transient K8s API failures (simulated proxy/rate-limit) -> exponential backoff engages and converges cleanly on recovery.
  - Write `docs/lessons/15-observability-benchmarking-and-chaos-engineering.md`.
- **Outputs:** `tests/integration/chaos_suite.rs`, `docs/lessons/15-observability-benchmarking-and-chaos-engineering.md`.
- **Verification:** All 3 chaos scenarios pass cleanly.
- **Trap Guard:** Assert **zero** resources are ever pruned when Git fetch or rendering fails!

---

## Phase 16: Modern Web Dashboard, Packaging & `v1.0` Release — *Milestone `v1.0` Complete*

**Phase Goal:** Deliver a crisp, modern TypeScript Web Dashboard (`React 19 + TypeScript + Vite + Tailwind CSS + TanStack Query + React Flow`) strictly typed against `ferriscd-server`'s OpenAPI spec, harden the container image (`openssh-client` + non-root + read-only rootfs), ship a production Helm chart, and complete `v1.0`.  
**Knowledge Base Lesson (`docs/lessons/16-packaging-hardening-and-production-gitops.md`):** OpenAPI-driven Rust-to-TypeScript workflows, non-root read-only containers with `openssh-client`, Kubernetes `NetworkPolicy` hardening, and operating GitOps in production.

### `T16.1` — Scaffold Modern Web Frontend (`apps/ferriscd-web`) & OpenAPI TypeScript Codegen
- **Why:** Using a modern, strictly typed TypeScript stack (`React 19 + Vite + Tailwind CSS + TanStack Query`) decoupled via generated OpenAPI types delivers a fast, maintainable UI with zero backend/frontend schema drift.
- **Detailed Requirements:**
  - Scaffold `apps/ferriscd-web` with Vite, React 19, TypeScript (strict mode), Tailwind CSS v4, TanStack Query v5, and React Router.
  - Wire `openapi-typescript` + `openapi-fetch` script (`npm run generate-api`) reading `docs/api/openapi.json` exported from `ferriscd-server` (`T14.1`).
  - Implement token login flow (storing bearer token in memory/sessionStorage, never URL params) and API error boundary.
- **Outputs:** `apps/ferriscd-web/` scaffold, `src/api/schema.d.ts` (generated), CI frontend lint/typecheck/build job.
- **Verification:** `npm run typecheck && npm run build` passes cleanly in CI.
- **Trap Guard:** Keep frontend strictly API-driven—never couple frontend build to Cargo builds.

### `T16.2` — Build Applications Overview & Detail Views
- **Why:** Provide the core single-pane-of-glass view showing Sync Status, Health Status, current revision, conditions, and deployment history.
- **Detailed Requirements:**
  - Applications grid/table with instant filtering by `project`, `syncStatus`, `healthStatus`, and search query; live polling via TanStack Query (`refetchInterval`).
  - Application detail view showing metadata, source/destination summary, Sync & Health badges, `conditions` timeline, and `history` table.
- **Outputs:** `apps/ferriscd-web/src/pages/ApplicationsPage.tsx`, `ApplicationDetailPage.tsx`.
- **Verification:** Component unit tests (Vitest) + manual verification against live `ferriscd-server` on `kind`.
- **Trap Guard:** Clearly display Sync Status and Health Status as separate badges (never merge them into one vague "Status").

### `T16.3` — Build Interactive Resource Topology Graph (`React Flow`)
- **Why:** Visualizing the Application -> managed resources hierarchy (Deployment -> ReplicaSet/Service/ConfigMap) with per-node Sync/Health badges is the signature GitOps dashboard experience.
- **Detailed Requirements:**
  - Render `GET /api/v1/applications/:ns/:name/resources` as an interactive, auto-laid-out DAG using `React Flow` (`@xyflow/react` + `dagre` layout).
  - Color-code node borders/badges by Sync + Health status; clicking any node opens a slide-over inspector showing GKNN, sync wave, health message, and resource actions.
- **Outputs:** `apps/ferriscd-web/src/components/ResourceGraph.tsx`, `ResourceInspector.tsx`.
- **Verification:** Renders a 15-node application cleanly with zoom/pan/selection and zero layout overlap.
- **Trap Guard:** Handle large apps (100+ resources) gracefully with a toggle between Graph View and searchable Resource Table View.

### `T16.4` — Build Redacted Diff Viewer & Manual Sync / Rollback Controls
- **Why:** Allow operators to visually inspect live drift before clicking Sync or Rollback with explicit confirmation rails.
- **Detailed Requirements:**
  - Integrate a clean side-by-side / unified diff viewer consuming `GET /api/v1/applications/:ns/:name/diff` (already Secret-redacted by `ferriscd-server`), highlighting `OutOfSync`, `Missing`, `Orphaned`, and `FieldConflict` managers.
  - Add confirmation modals for **Sync** (with `prune` / `dry-run` options) and **Rollback** (selecting from `history`, explicitly warning that `automated` sync will be paused).
  - Add optional static asset embedding/serving behind `ferriscd-server` (or separate Nginx/Caddy static container).
- **Outputs:** `apps/ferriscd-web/src/components/DiffViewer.tsx`, `SyncModal.tsx`, `RollbackModal.tsx`.
- **Verification:** E2E smoke test against `kind` + `ferriscd-server`: view drift diff, click Sync, observe transition to `Synced` + `Healthy`, verify Secrets render as `***REDACTED(...)***`.
- **Trap Guard:** Confirm RBAC `403` disables/handles action buttons gracefully for read-only users.

### `T16.5` — Build Hardened Minimal Container Image (`openssh-client` + Non-Root + Read-Only Rootfs)
- **Why:** Production Kubernetes clusters require minimal, non-root, read-only images that still support `gix` SSH Git clones (`openssh-client`) and pinned `helm`/`kustomize` binaries.
- **Detailed Requirements:**
  - Multi-stage `Dockerfile`: Rust builder -> minimal **Wolfi / Debian-slim** runtime image installing **only** `ca-certificates`, `openssh-client`, pinned `helm` (v4.x), pinned `kustomize` (v5.x), and the `ferriscd` binary.
  - Run as non-root UID `65532`, set `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, drop `ALL` Linux capabilities; expect writable `emptyDir` mounted at `/tmp` for `RepoCache`, SSH ephemeral `0600` keys, and renderer scratch space.
  - Build a second minimal static image for `ferriscd-web` (or serve built static bundle from `ferriscd-server`).
- **Outputs:** `Dockerfile`, `apps/ferriscd-web/Dockerfile`, `.dockerignore`.
- **Verification:** Build image locally, load into `kind`, run Pod with `restricted` PodSecurityStandard (`readOnlyRootFilesystem: true`, `runAsNonRoot: true`), verify both HTTPS and SSH Git clones + Helm/Kustomize rendering succeed.
- **Trap Guard:** Fixes Finding C6 (bare distroless breaking `gix` SSH transport) while preserving strict PodSecurity hardening.

### `T16.6` — Author Production Helm Chart & Kustomize Install Overlays
- **Why:** Provide a single, repeatable, security-hardened installation path for FerrisCD on any Kubernetes cluster.
- **Detailed Requirements:**
  - Create `deploy/helm/ferriscd/` containing: CRDs, least-privilege RBAC (`ClusterRole`/`Role` + `leases` permission + optional `impersonate` flag), `Deployment` (with liveness/readiness probes, `emptyDir` `/tmp`, `restricted` securityContext), `Service`, `PodDisruptionBudget`, `ServiceMonitor` (optional), `NetworkPolicy` (default-deny + explicit API server/DNS/Git egress rules), and `values.yaml` supporting HA (`replicas: 2` + Lease election).
  - Provide `deploy/manifests/` Kustomize overlay for quick `kubectl apply -k` installs.
- **Outputs:** `deploy/helm/ferriscd/**`, `deploy/manifests/**`.
- **Verification:** `helm lint deploy/helm/ferriscd`, `helm template` validation, and clean `helm install ferriscd deploy/helm/ferriscd -n ferriscd-system --create-namespace` on a fresh `kind` cluster.
- **Trap Guard:** Never default `NetworkPolicy` or RBAC to overly broad wildcards without clear `values.yaml` documentation.

### `T16.7` — Finalize Knowledge Base, Operations Runbook & `v1.0` Release Pipeline
- **Why:** Complete the second core deliverable (the Knowledge Base) and ensure any engineer can install, operate, troubleshoot, and contribute to FerrisCD.
- **Detailed Requirements:**
  - Complete `docs/lessons/16-packaging-hardening-and-production-gitops.md` and `docs/lessons/README.md` curriculum index linking all 16 lessons and ADRs.
  - Write `README.md` (10-minute `kind` quickstart), `SECURITY.md` (threat model, mounted SA token note, vulnerability disclosure), `CONTRIBUTING.md`, and `docs/operations/RUNBOOK.md` (troubleshooting stuck finalizers, field conflicts, rollback recovery, HA failover).
  - Add `.github/workflows/release.yml` building tagged multi-arch binaries, container images, and Helm chart artifacts.
- **Outputs:** `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/operations/RUNBOOK.md`, `docs/lessons/README.md`, `.github/workflows/release.yml`.
- **Verification:** Follow `README.md` from scratch on a brand-new `kind` cluster to install FerrisCD and deploy an example app in <10 minutes. **Milestone `v1.0` Complete.**
- **Trap Guard:** Verify every command in `README.md` and `RUNBOOK.md` against the actual `v1.0` binary and Helm chart.

### `T16.8` — Post-`v1.0` Backlog & Extension Points (Optional Future Track)
- **Why:** Capture valuable real-world GitOps extensions explicitly outside `v1.0` so scope stays disciplined without losing architectural foresight.
- **Detailed Requirements:**
  - Document clean extension specs in `docs/design/post-v1-backlog.md` covering:
    1. Opt-in trigger-only `PartialObjectMetadata` label-scoped `DriftWatcher` (`ferriscd.io/managed-by=ferriscd` + `ferriscd.io/app-hash=<16-hex-sha256>`, respecting Kubernetes's 63-char label limit — Finding M5), wired into `Controller::reconcile_on` with debouncing, `resourceVersion` self-echo suppression for `ConfigMap`/`Secret` (which lack `metadata.generation`), and graceful `403` fallback to periodic polling.
    2. OCI artifact source (`source.oci`) for Helm charts & Kustomize bundles.
    3. OIDC / SSO login for `ferriscd-server` & `ferriscd-web`.
    4. ApplicationSet-style matrix/git-directory generators and Slack/webhook notifications.
- **Outputs:** `docs/design/post-v1-backlog.md`.
- **Verification:** Reviewed against `ApplicationSpec` to confirm zero breaking CRD changes are required to add these extensions.
- **Trap Guard:** Keep these strictly post-`v1.0` to protect `v1.0` completion velocity.
